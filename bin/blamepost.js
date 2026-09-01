#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * blamepost, the command line.
 *
 * `serve` is the default and is what the container runs. Everything
 * else is day two work: first setup, accounts, domains, DKIM keys, the
 * outbound queue, and a health check that goes and looks at DNS.
 *
 * The subcommand bodies call into `lib/`. Nothing under `lib/` calls
 * back out to this file, which is why the mail server can be driven by
 * a test without a shell.
 *
 * Exit codes follow the usual convention: 0 for success, 1 for a
 * failure at run time, 2 for a problem with the arguments.
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var b = require("../lib/vendor/blamejs");
var blamepost = require("../lib");
var auditActor = require("../lib/store/actor");
// The one derivation that decides which domain a name means, so a name
// typed at the command line and the same name typed into the browser
// console reach the same row.
var address = require("../lib/store/address");
var configModule = require("../lib/config");
var storeModule = require("../lib/store");

var TIME  = b.constants.TIME;
var BYTES = b.constants.BYTES;

// How long a drain may take before the supervisor's own patience runs
// out. Kept below the ten seconds `docker stop` allows by default so a
// stop is a drain rather than a kill.
var SHUTDOWN_GRACE_MS = TIME.seconds(8);

// Headroom between the drain budget and the watchdog that forces the
// exit. A container stop grace shorter than the sum of the two turns
// a clean shutdown back into a kill.
var SHUTDOWN_FORCE_MARGIN_MS = TIME.seconds(4);

// The audit namespace this application writes its own rows under, the
// same one the listeners record delivery events in, so a cancelled
// message and the delivery attempts that preceded it sit together.
var AUDIT_NAMESPACE = "blamepost";

// The framework's tamper-evident table. Named once because the chain
// verbs read its tip as well as walking it.
var AUDIT_TABLE = "audit_log";

// How much of the audit trail one read hands back. The default is a
// screenful; the ceiling is there because the rows are unsealed on the
// way out and a request for all of them is a request to hold the whole
// trail in memory.
var AUDIT_READ_DEFAULT_ROWS = 50;
var AUDIT_READ_MAX_ROWS     = 5000;

// The verdicts the framework files a row under. A filter naming
// anything else would narrow the answer to nothing, and an empty answer
// is what a quiet trail looks like.
var AUDIT_OUTCOMES = ["success", "failure", "denied"];

// A file holding a bundle passphrase is one line. The cap is here so a
// mistyped path pointing at a mailbox or a database cannot be read into
// memory before it is rejected.
var PASSPHRASE_FILE_MAX_BYTES = BYTES.kib(4);

// The floor a bundle passphrase has to clear. A bundle leaves this
// machine and can be attacked offline for as long as somebody cares to,
// which is a different problem from a login somebody has to make
// attempts against. Argon2id makes each guess expensive and a short
// passphrase is still short.
var MIN_BUNDLE_PASSPHRASE_CHARS = 20;

var ctx = { stdout: process.stdout, stderr: process.stderr, env: process.env };

var USAGE_ACCOUNT =
  "Usage: blamepost account <verb>\n" +
  "\n" +
  "  list [--domain <domain>]              every live account, or those on one domain\n" +
  "       [--include-archived]             archived accounts as well, which is where the\n" +
  "                                        address `resume` takes back is found\n" +
  "  show <address>                        one account and the addresses it may send as\n" +
  "  add <address> [--password <secret>] [--quota <bytes>]  create an account; a password is\n" +
  "                                        generated when omitted, and the quota is unlimited\n" +
  "  passwd <address> [--password <secret>]  set a new password\n" +
  "  suspend <address> --reason <text>     stop it authenticating and receiving, keeping everything\n" +
  "  resume <address>                      undo a suspension\n" +
  "  remove <address> --reason <text> [--destroy]  archive an account, or erase it\n" +
  "  sieve <address> --reason <text>       the account's filter scripts, active one marked\n" +
  "        [--script <name>]               the body of one script\n" +
  "  messages <address> --reason <text>    what the account holds, by id, with the ones under\n" +
  "           [--mailbox <name>]           an order marked. Senders and subjects, never bodies\n" +
  "  holds <address> [--mailbox <name>]    every message under a preservation order, and what\n" +
  "                                        each order records\n" +
  "  hold <address> --mailbox <name>       put named messages under a preservation order, so\n" +
  "       --message <id> --reason <text>   every hard delete refuses them on every protocol\n" +
  "       [--citation <ref>] [--custodian <who>]\n" +
  "  release <address> --mailbox <name>    lift an order, so the ordinary delete path reaches\n" +
  "          --message <id> --reason <text>   those messages again\n" +
  "          --approver <who> --confirm\n" +
  "\n" +
  "An order is placed on messages rather than on a mailbox, so mail arriving after it is not\n" +
  "silently covered, and it carries no expiry: nothing here sweeps one, so a date recorded\n" +
  "against it would read as an end this server never acts on. Lift it with release. Message\n" +
  "ids come from `account messages`, from `account holds`, and from what an erasure prints.";

var USAGE_DOMAIN =
  "Usage: blamepost domain <verb>\n" +
  "\n" +
  "  list                                  every hosted domain\n" +
  "  show <domain>                         one domain and its DNS expectations\n" +
  "  add <domain>                          host a new domain and mint its DKIM keys\n" +
  "  acknowledge <domain> --by <who> [--withdraw]  record that this domain's DNS is published\n" +
  "  disable <domain> --reason <text>      refuse mail for it, keeping its accounts and their mail\n" +
  "  enable <domain> --reason <text>       accept mail for it again\n" +
  "  remove <domain> --destroy --reason <text>  erase it and its DKIM selectors. It has to hold\n" +
  "                                        no accounts and no aliases first, and there is no\n" +
  "                                        undo, so disable is the reversible answer";

var USAGE_DKIM =
  "Usage: blamepost dkim <verb>\n" +
  "\n" +
  "  list [<domain>]                       selectors and their states\n" +
  "  records <domain>                      every record that must be in the zone right now\n" +
  "  generate --domain <domain>            first keys for a domain that has none\n" +
  "  rotate --domain <domain> [--selector <name>]  mint a replacement pair; both pairs sign\n" +
  "                                        meanwhile. The default name carries the month, so\n" +
  "                                        rotating twice in one month needs --selector\n" +
  "  retire --domain <domain> --selector <name>   stop signing with the outgoing pair\n" +
  "  sweep [--domain <domain>] [--immediate]   report retired selectors whose records can now be removed";

var USAGE_QUEUE =
  "Usage: blamepost queue <verb>\n" +
  "\n" +
  "  list [--account <addr>]               messages waiting for a retry, soonest first\n" +
  "       [--destination <domain>]         narrowed to one sender or one receiving domain\n" +
  "  show <id>                             one message: every attempt made on it, what the\n" +
  "                                        far side said each time, and how it ends if\n" +
  "                                        nothing changes\n" +
  "  held                                  what has stopped and what would release it,\n" +
  "                                        counted by cause rather than per recipient\n" +
  "  flush [--force]                       retry everything due now, or everything at all\n" +
  "  remove <id> --reason <text>           abandon one waiting message, or clear a message\n" +
  "                                        body that no descriptor names";

var USAGE_BLOBS =
  "Usage: blamepost blobs <verb>\n" +
  "\n" +
  "  report [--verify]                     what the message rows and the sealed bodies on\n" +
  "                                        disk disagree about. --verify also unseals every\n" +
  "                                        referenced body and hashes it back, which is the\n" +
  "                                        only way to see one that has been altered in place\n" +
  "  reclaim --confirm --reason <text>     delete the bodies no message references\n" +
  "\n" +
  "A message body is written to disk and then a row is written naming it, and nothing\n" +
  "spans the pair. report answers either way, falling back to a read-only open whose\n" +
  "rows stop at the server's last write to disk. reclaim deletes files, so it needs the\n" +
  "server stopped and is refused while another process holds the volume. A body is\n" +
  "removed only once it has been on disk for a day, and inside that window one that is\n" +
  "arriving looks exactly like one that was stranded.";

var USAGE_AUDIT =
  "Usage: blamepost audit <verb>\n" +
  "\n" +
  "  verify-chain                          walk every audit row and every signed checkpoint\n" +
  "  read [--from <when>] [--to <when>]    the rows themselves, newest first. Reading them\n" +
  "       [--action <name>] [--outcome <verdict>]   is itself recorded\n" +
  "       [--limit <n>]\n" +
  "  archive --before <when> --out <dir>   bundle the rows older than a cut, encrypted and\n" +
  "          --passphrase-file <path>      anchored. Live rows are left alone\n" +
  "  export --out <dir> --passphrase-file <path>   an auditor's copy of a range\n" +
  "         [--from <when>] [--to <when>] [--action <name>]\n" +
  "  verify-bundle --in <dir>              read a bundle back and check it end to end\n" +
  "                --passphrase-file <path>\n" +
  "  purge --archive <dir> --confirm --reason <text>   delete the live rows a verified\n" +
  "        --passphrase-file <path>        archive already holds\n" +
  "\n" +
  "A date is ISO 8601 or milliseconds since the epoch. A bundle passphrase is read from\n" +
  "a file rather than the command line, because a command line is in the shell history\n" +
  "and in the process list.";

var USAGE_BACKUP =
  "Usage: blamepost backup <verb>\n" +
  "\n" +
  "  run --storage <dir> --passphrase-file <path>   write an encrypted bundle of the whole\n" +
  "      [--keep <n>]                      data volume, keeping the newest n afterwards\n" +
  "  list --storage <dir>                  bundles in a storage directory, newest first\n" +
  "  inspect --storage <dir> --bundle <id>  what a bundle holds, without the passphrase\n" +
  "          [--fingerprint <hex>]         and refusing a signature from another key\n" +
  "  verify --storage <dir> --bundle <id>  decrypt every file and check it, restoring nothing\n" +
  "         --passphrase-file <path> [--fingerprint <hex>]\n" +
  "  purge --storage <dir> --keep <n>      drop every bundle but the newest n\n" +
  "        --confirm --reason <text> --passphrase-file <path>\n" +
  "\n" +
  "list, inspect and verify never open the database, so they still answer on a server\n" +
  "whose data volume will not open. That is the day they matter.";

var USAGE_RESTORE =
  "Usage: blamepost restore <verb>\n" +
  "\n" +
  "  apply --storage <dir> --bundle <id>   replace this data volume with a bundle, keeping\n" +
  "        --passphrase-file <path>        the directory it replaced as a rollback point.\n" +
  "        --confirm --reason <text>       The restored volume is opened and its audit chain\n" +
  "        [--fingerprint <hex>]           verified before the restore reports success\n" +
  "  rollback --confirm --reason <text>    put the most recent rollback point back\n" +
  "           [--point <path>]             or a named one\n" +
  "  list-rollbacks                        every rollback point this volume still holds\n" +
  "\n" +
  "Stop the server first. A restore renames the data directory, and a running process\n" +
  "keeps reading the directory it opened.";

// The three flags every command declares. They change where the server
// reads its state from and how the answer is printed, so every verb
// honors them and none of them belongs in the table below.
var GLOBAL_FLAGS = ["config", "data-dir", "json"];

// What each verb reads: how many arguments it takes after the verb, and
// which of its group's flags it acts on.
//
// A flag or an argument a verb does not read is refused rather than
// dropped. At a terminal, one that changed nothing and said nothing
// looks exactly like one that worked, and the first time that matters is
// an erasure an operator believes they asked for, or a second address on
// a remove line that was never touched.
var VERB_SURFACE = {
  account: {
    list:    { args: 0, flags: ["domain", "include-archived"] },
    show:    { args: 1, flags: [] },
    add:     { args: 1, flags: ["password", "quota"] },
    passwd:  { args: 1, flags: ["password"] },
    suspend: { args: 1, flags: ["reason"] },
    resume:  { args: 1, flags: [] },
    remove:  { args: 1, flags: ["destroy", "reason"] },
    sieve:   { args: 1, flags: ["reason", "script"] },
    messages: { args: 1, flags: ["mailbox", "reason"] },
    holds:   { args: 1, flags: ["mailbox"] },
    hold:    { args: 1, flags: ["mailbox", "message", "reason", "citation", "custodian"] },
    release: { args: 1, flags: ["mailbox", "message", "reason", "approver", "confirm"] },
  },
  domain: {
    list:        { args: 0, flags: [] },
    show:        { args: 1, flags: [] },
    add:         { args: 1, flags: [] },
    acknowledge: { args: 1, flags: ["by", "withdraw"] },
    disable:     { args: 1, flags: ["reason"] },
    enable:      { args: 1, flags: ["reason"] },
    remove:      { args: 1, flags: ["destroy", "reason"] },
  },
  dkim: {
    list:     { args: 1, flags: ["domain"] },
    records:  { args: 1, flags: ["domain"] },
    generate: { args: 1, flags: ["domain", "selector"] },
    rotate:   { args: 1, flags: ["domain", "selector"] },
    retire:   { args: 1, flags: ["domain", "selector"] },
    sweep:    { args: 0, flags: ["domain", "immediate"] },
  },
  queue: {
    list:   { args: 0, flags: ["account", "destination"] },
    show:   { args: 1, flags: [] },
    held:   { args: 0, flags: [] },
    flush:  { args: 0, flags: ["force"] },
    remove: { args: 1, flags: ["reason"] },
  },
  blobs: {
    report:  { args: 0, flags: ["verify"] },
    reclaim: { args: 0, flags: ["confirm", "reason"] },
  },
  audit: {
    "verify-chain":  { args: 0, flags: [] },
    read:            { args: 0, flags: ["from", "to", "action", "outcome", "limit"] },
    archive:         { args: 0, flags: ["before", "out", "passphrase-file"] },
    export:          { args: 0, flags: ["from", "to", "action", "out", "passphrase-file"] },
    "verify-bundle": { args: 0, flags: ["in", "passphrase-file"] },
    purge:           { args: 0, flags: ["archive", "confirm", "reason", "passphrase-file"] },
  },
  backup: {
    run:     { args: 0, flags: ["storage", "keep", "passphrase-file"] },
    list:    { args: 0, flags: ["storage"] },
    inspect: { args: 0, flags: ["storage", "bundle", "fingerprint"] },
    verify:  { args: 0, flags: ["storage", "bundle", "passphrase-file", "fingerprint"] },
    purge:   { args: 0, flags: ["storage", "keep", "confirm", "reason", "passphrase-file"] },
  },
  restore: {
    apply:            { args: 0, flags: ["storage", "bundle", "passphrase-file", "fingerprint",
      "confirm", "reason"] },
    rollback:         { args: 0, flags: ["point", "confirm", "reason"] },
    "list-rollbacks": { args: 0, flags: [] },
  },
};

function _reporter(verb) {
  return b.cliHelpers.makeReporter(ctx, "blamepost " + verb);
}

// Refuse anything the verb will not act on, before a store is opened or
// a key is minted. Returns 0 when the invocation is clean, and the exit
// code to hand back when it is not.
function _refuseUnread(report, group, verb, flags, positionals) {
  // Own-property only. A verb spelled `constructor` or `toString` would
  // otherwise resolve to something inherited from Object.prototype, and
  // the check would read a shape that is not a verb description at all.
  var known = VERB_SURFACE[group];
  if (!Object.prototype.hasOwnProperty.call(known, verb)) return 0;
  var surface = known[verb];

  var unread = Object.keys(flags).filter(function (name) {
    return GLOBAL_FLAGS.indexOf(name) === -1 && surface.flags.indexOf(name) === -1;
  });
  if (unread.length > 0) {
    return report.error("`" + group + " " + verb + "` does not take " +
      unread.map(function (n) { return "--" + n; }).join(" or ") + ". It takes " +
      (surface.flags.length
        ? surface.flags.map(function (n) { return "--" + n; }).join(", ")
        : "no flags of its own") + ".", 2);
  }

  var extra = positionals.slice(1 + surface.args);
  if (extra.length > 0) {
    return report.error("`" + group + " " + verb + "` takes " +
      (surface.args === 0 ? "no arguments" : surface.args + " argument") +
      ", so " + extra.join(" and ") + " would be ignored. Run it once per target.", 2);
  }
  return 0;
}

// A domain given as a scoping argument, checked for shape before it is
// used to narrow anything. A mistyped name refused here is an argument
// problem the operator sees immediately; the same name carried further
// comes back as a resolver failure, or as a clean report about a zone
// nobody asked about. Answers either `{ domain }` or `{ code }`, and the
// code is the one the caller returns.
function _readDomainArg(report, raw) {
  var verdict = address.parseDomain(raw);
  if (!verdict.ok) {
    return {
      code: report.error(JSON.stringify(String(raw)) + " is not a usable domain name (" +
        (verdict.detail || []).map(function (i) { return i.kind; }).join(", ") + ").", 2),
    };
  }
  return { domain: verdict.domain };
}

function _parser() {
  return b.argParser.create({
    programName: "blamepost",
    description: "Self-hosted mail server. SMTP, IMAP, JMAP, POP3, ManageSieve and webmail " +
      "in one process.",
    flags: [
      { name: "config", alias: "c", type: "string",
        description: "Configuration file to read. Environment values still win over it." },
      { name: "data-dir", alias: "d", type: "string",
        description: "Data directory holding the database, the spool, the keys and the certificates." },
      { name: "json", type: "boolean",
        description: "Print the result as JSON instead of as text." },
    ],
    commands: [
      { name: "serve",
        description: "Run the server. This is the default and what the container runs.",
        flags: [
          { name: "hostname", type: "string",
            description: "Public name of this server, overriding the configuration." },
        ] },
      { name: "init",
        description: "Prepare a fresh data directory and create the first administrator.",
        flags: [
          { name: "admin-email", type: "string",
            description: "Address of the first account, which is created as an administrator." },
          { name: "admin-password", type: "string",
            description: "Password for that account. One is generated and printed when omitted." },
        ] },
      { name: "account",
        description: "List, create, inspect and remove mailbox accounts, and answer a " +
          "preservation order against one.",
        flags: [
          { name: "domain", type: "string", description: "Limit the listing to one domain." },
          { name: "include-archived", type: "boolean",
            description: "Keep archived accounts in the listing. They are left out by " +
              "default because the common question is which mailboxes are live, and an " +
              "archived one is the mailbox `resume` takes back." },
          { name: "password", type: "string", description: "Password to set, rather than a generated one." },
          { name: "quota", type: "number", description: "Mailbox quota in bytes." },
          { name: "destroy", type: "boolean", description: "Erase rather than archive. Requires a reason." },
          { name: "reason", type: "string",
            description: "Why an account is being suspended or removed, why its filter " +
              "scripts or its message list are being read, or why an order is being placed " +
              "or lifted. Recorded in the audit trail, and required by each." },
          { name: "script", type: "string",
            description: "Print the body of this one filter script instead of listing them." },
          { name: "mailbox", type: "string",
            description: "Which of the account's mailboxes the messages are in, by the name " +
              "its owner sees, for example INBOX." },
          { name: "message", type: "list",
            description: "Message to place under an order or lift one from, by the object id " +
              "`account holds` and an erasure both print. Repeat it, or give one " +
              "comma-separated list, to name several." },
          { name: "citation", type: "string",
            description: "The rule or matter an order is under, for example FRCP-26 or a " +
              "case number. Recorded against the order and printed back by `account holds`." },
          { name: "custodian", type: "string",
            description: "Who is answerable for the preserved records. Recorded against the " +
              "order." },
          { name: "approver", type: "string",
            description: "Who says a preservation duty has ended. Required by release, and " +
              "recorded: an order is not lifted by whoever happens to be at the keyboard." },
          { name: "confirm", type: "boolean",
            description: "Confirm that release lifts a preservation order. The next hard " +
              "delete on those messages destroys them." },
        ] },
      { name: "domain",
        description: "List, add, inspect, acknowledge, disable and remove hosted mail domains.",
        flags: [
          { name: "destroy", type: "boolean",
            description: "Confirm that remove erases the domain. There is no archived copy, " +
              "so disable is the reversible answer." },
          { name: "reason", type: "string",
            description: "Why the domain's mail is being turned off or back on, or why the " +
              "domain is being erased. Recorded in the audit trail, and required by each." },
          { name: "by", type: "string",
            description: "Who is confirming this domain's DNS. Recorded on the row and in the audit trail." },
          { name: "withdraw", type: "boolean",
            description: "Take back a DNS acknowledgement. The MX listener stops binding until it is given again." },
        ] },
      { name: "dkim",
        description: "Mint, publish and rotate the signing keys for a domain.",
        flags: [
          { name: "domain", type: "string", description: "Domain the verb applies to." },
          { name: "selector", type: "string",
            description: "Selector name. Required by retire, optional elsewhere." },
          { name: "immediate", type: "boolean",
            description: "Withdraw a retiring selector before its overlap elapses. " +
              "Right when a key is exposed, wrong otherwise: mail signed with it and " +
              "still being retried starts failing DKIM." },
        ] },
      { name: "queue",
        description: "Inspect and drive the outbound queue.",
        flags: [
          { name: "force", type: "boolean", description: "Retry every waiting message, not only those due." },
          { name: "account", type: "string",
            description: "List only what this sender is waiting on. An address that cannot " +
              "be read is refused rather than matched against nothing." },
          { name: "destination", type: "string",
            description: "List only what is waiting for one receiving domain, which is the " +
              "shape a single receiver deferring you takes." },
          { name: "reason", type: "string",
            description: "Why a queued message is being abandoned. Recorded in the audit " +
              "trail, and required by remove." },
        ] },
      { name: "doctor",
        description: "Check this server against the DNS its domains actually publish.",
        flags: [
          { name: "domain", type: "string",
            description: "Check one hosted domain instead of every one of them. " +
              "Useful right after adding a domain, when the others are known good." },
          { name: "dane", type: "boolean", description: "Also check the TLSA record for this server." },
        ] },
      { name: "blobs",
        description: "Hold the sealed message bodies on disk against the rows naming them.",
        flags: [
          { name: "verify", type: "boolean",
            description: "Unseal every referenced body and hash it back against the digest " +
              "naming its file. Without this a body counts as present when the file is " +
              "there, which cannot see one that has been altered in place." },
          { name: "confirm", type: "boolean",
            description: "Confirm that reclaim deletes message bodies. There is no undo " +
              "and no copy." },
          { name: "reason", type: "string",
            description: "Why the bodies are being deleted. Recorded in the audit trail, " +
              "and required by reclaim: the row is the only record they were here." },
        ] },
      { name: "audit",
        description: "Prove the audit trail, and hand a range of it to an auditor.",
        flags: [
          { name: "before", type: "string",
            description: "Archive the rows recorded before this moment. ISO 8601 or " +
              "milliseconds since the epoch." },
          { name: "from", type: "string",
            description: "Earliest moment an exported row was recorded at, inclusive." },
          { name: "to", type: "string",
            description: "Latest moment an exported row was recorded at, inclusive." },
          { name: "action", type: "string",
            description: "One action name only. On export, a filter that skips rows in the " +
              "middle of the range is refused, because the chain cannot be proven across a gap." },
          { name: "outcome", type: "string",
            description: "Read only the rows that ended one way: success, failure or denied." },
          { name: "limit", type: "number",
            description: "How many rows to read, newest first." },
          { name: "out", type: "string",
            description: "Directory to write a bundle into. It must not already exist." },
          { name: "in", type: "string", description: "Bundle directory to read back and check." },
          { name: "archive", type: "string",
            description: "The verified archive bundle whose rows are being deleted from the " +
              "live table." },
          { name: "confirm", type: "boolean",
            description: "Confirm that purge deletes audit rows. The archive is the only " +
              "copy afterwards." },
          { name: "reason", type: "string",
            description: "Why audit rows are being deleted. Recorded in the audit trail, " +
              "and required by purge." },
          { name: "passphrase-file", type: "string",
            description: "File holding the passphrase a bundle is encrypted with. This " +
              "server never stores it, so losing the file loses the bundle." },
        ] },
      { name: "backup",
        description: "Write, list and verify encrypted bundles of the data volume.",
        flags: [
          { name: "storage", type: "string",
            description: "Directory bundles are written to and read from." },
          { name: "bundle", type: "string", description: "Which bundle, by the id `list` prints." },
          { name: "keep", type: "number",
            description: "How many bundles to keep, newest first. The rest are deleted." },
          { name: "fingerprint", type: "string",
            description: "Refuse a bundle whose manifest was signed by any other key. " +
              "Without it a signature proves the bundle is unmodified but not who made it." },
          { name: "confirm", type: "boolean",
            description: "Confirm that purge deletes bundles. There is no undo." },
          { name: "reason", type: "string",
            description: "Why bundles are being deleted. Recorded in the audit trail, " +
              "and required by purge." },
          { name: "passphrase-file", type: "string",
            description: "File holding the passphrase a bundle is encrypted with. It cannot " +
              "be the vault passphrase: a bundle travels off this machine and the vault does not." },
        ] },
      { name: "restore",
        description: "Put a bundle back, with the directory it replaced kept for a rollback.",
        flags: [
          { name: "storage", type: "string", description: "Directory the bundles are in." },
          { name: "bundle", type: "string", description: "Which bundle, by the id `backup list` prints." },
          { name: "point", type: "string",
            description: "Roll back to this point rather than the most recent one." },
          { name: "fingerprint", type: "string",
            description: "Refuse a bundle whose manifest was signed by any other key." },
          { name: "confirm", type: "boolean",
            description: "Confirm that this replaces the live data volume." },
          { name: "reason", type: "string",
            description: "Why the volume is being replaced. Recorded in the audit trail of " +
              "the restored volume and on the rollback point, and required by both verbs." },
          { name: "passphrase-file", type: "string",
            description: "File holding the passphrase the bundle was encrypted with." },
        ] },
    ],
  });
}

// The configuration comes from the environment and the file it names.
// The three flags that overlap with it are folded into a copy of the
// environment rather than applied afterwards, so a value given on the
// command line goes through exactly the same validation as one given
// through the environment. A path accepted from a flag but never
// checked is how a typo becomes a data directory in the wrong place.
function _configFrom(flags) {
  var env = Object.assign({}, process.env);
  if (flags.config) env.BLAMEPOST_CONFIG = flags.config;
  if (flags["data-dir"]) env.BLAMEPOST_DATA_DIR = flags["data-dir"];
  if (flags.hostname) env.BLAMEPOST_HOSTNAME = flags.hostname;
  return configModule.load({ env: env });
}

// The verbs that may answer from a read-only open of the data volume
// while the server writes it, rather than being refused until it is
// stopped.
//
// The test is not whether a verb changes anything. What disqualifies a
// read is needing to WRITE on the way to its answer, and there are two
// shapes of that.
//
// A read whose own record has to outlive the process. `audit read` is
// documented as itself being recorded and `account sieve` records that
// an administrator opened somebody's filter. A read-only handle cannot
// write that row, and a read that claims to be recorded and is not is
// worse than a read that refuses.
//
// A verb that writes before it reads. `backup run` anchors the chain so
// the bundle carries a signature over its own last row, and requires the
// volume flushed so the bundle is not older than the database it claims
// to be. `audit archive`, `audit export` and `audit purge` are the same.
// None of that is available to a handle that will not write.
//
// `blobs report` is here rather than among those. Its answer holds the
// rows against a blob directory that keeps moving. The rows carry the
// moment they were frozen and `blobs.reconcile` separates a body newer
// than that from a body nothing references, so what it reports is
// bounded by what it read.
//
// `audit verify-chain` is here because a read-only open verifies the
// checkpoint signatures rather than skipping them, which is what it
// could not get from a copy opened with the signing key left sealed. The
// chain is append-only, so what it walks is a verified prefix.
//
// `doctor` has no verb of its own, so it is listed against the empty
// one. It is the verb this exists for: an operator reaches for it
// exactly when the server is up and behaving oddly.
var NO_VERB = "";
var SNAPSHOT_ELIGIBLE = {
  account: ["list", "show"],
  domain:  ["list", "show"],
  dkim:    ["list", "records"],
  blobs:   ["report"],
  audit:   ["verify-chain"],
  doctor:  [NO_VERB],
};

function _mayReadASnapshot(group, verb) {
  if (!Object.prototype.hasOwnProperty.call(SNAPSHOT_ELIGIBLE, group)) return false;
  return SNAPSHOT_ELIGIBLE[group].indexOf(String(verb === undefined ? NO_VERB : verb)) !== -1;
}

// Open the data volume for a verb that reports, preferring a writable
// open and falling back to a read-only one.
//
// The order is what makes the answer as current as it can be: an
// operator who has stopped the server gets the volume as it stands, and
// the fall-back happens only against the refusal that says another
// process is writing it. Taking the lock is refused before anything
// decrypts, so trying costs nothing and a server that stops in between
// is picked up rather than missed.
async function _openForReporting(config, group, verb) {
  try {
    return await storeModule.open(config);
  } catch (err) {
    if (!_mayReadASnapshot(group, verb)) throw err;
    if (!err || err.code !== "store/volume-in-use") throw err;
    return await storeModule.openSnapshot(config);
  }
}

// What an operator is told before an answer that came off a private
// copy. It goes first rather than last: a long answer read in a terminal
// is read from the top, and a caveat under a screenful of output is a
// caveat nobody sees.
function _snapshotLines(snapshot) {
  var ageSeconds = Math.max(0,
    Math.round((Date.now() - snapshot.takenAt) / TIME.seconds(1)));
  return [
    "Snapshot of " + snapshot.takenAtIso + ", " + ageSeconds + " second(s) ago.",
    "  " + snapshot.reason + ", so the volume was opened read-only and these rows are as",
    "  they stood when the server last wrote them to disk. Whatever it has stored since is",
    "  not here. Stop the server and run this again for an answer that is current.",
    "",
  ];
}

// Print one verb's answer, in whichever of the two shapes was asked for.
//
// It returns 0 on every path and has no failing one: printing is all it
// does, and what the exit status should be is a question about the
// RESULT, which only the caller holding it can answer. Callers that end
// on the answer return this directly; callers that classify it print
// through this and then compute their own code. Neither shape wants a
// verdict from here, so there is nothing to test the return value for,
// and an `if` around it is a branch that can never be taken.
function _emit(report, flags, value, lines) {
  // Asked rather than passed in. One process holds one store handle, so
  // whether the answer came off a copy is a fact about the run and not
  // about this call, and threading it through every caller would make
  // the label something a new verb can be written without.
  var snapshot = storeModule.snapshotInEffect();
  if (flags.json) {
    // The envelope appears only around an answer that is old, which
    // means a reader that assumed the bare shape stops parsing at
    // exactly the moment it would otherwise have believed stale data.
    // That is the loudest signal JSON offers, and quietly handing back
    // the usual shape is the failure this exists to prevent.
    report.write(JSON.stringify(
      snapshot ? { snapshot: snapshot, result: value } : value, null, 2));
    return 0;
  }
  if (snapshot) _snapshotLines(snapshot).forEach(function (line) { report.write(line); });
  (lines || []).forEach(function (line) { report.write(line); });
  return 0;
}

// Which record one entry of an erasure report is about.
//
// An erasure destroys four different kinds of thing an account holds and
// any of them can stay behind: a message, the mailbox row itself, a
// filter script, an annotation. The adapter names each one on the entry,
// because it is the layer that knows which mailbox an opaque folder token
// was addressed by and what the owner called their script, and by the
// time a line is printed those rows may be gone. Reading the name off the
// entry is also what keeps this from inventing one: a renderer that
// assembled the description itself would print "the mailbox" over a
// filter script the moment a fifth kind of row joined the report, and it
// would print it confidently.
//
// The fallbacks are for an entry from an older shape rather than for a
// missing name. Naming the wrong thing is worse than naming it vaguely,
// so the message identifier and the mailbox are used in that order and a
// bare "a record this account held" is the floor.
function _erasureRecord(entry) {
  if (entry.record) return String(entry.record);
  if (entry.objectid) return "message " + entry.objectid + " in " + entry.mailbox;
  if (entry.mailbox) return "the mailbox " + entry.mailbox;
  return "a record this account held";
}

// What an erasure actually reached, in the order an operator has to act
// on it.
//
// An erasure is partial more often than it looks. A message under a
// preservation order stays, one inside the regulated retention window
// stays, and an alias a gate wants a second approver for stays; each of
// those is the system working, and each is something the person
// answering the request has to be able to name. Anything else that
// stayed is mail or forwarding on a volume that was asked to lose it.
//
// A single "Erased <address>" line over any of that reads as a complete
// erasure, which is the one answer that cannot be corrected later:
// nothing can be read back afterwards to find out what really happened,
// so what this prints is the whole of what the operator has.
//
// The first line therefore reports which of the two happened rather than
// always the same word. An erasure something held back leaves the
// account on the table, because the records it kept are producible only
// through the identity that owns them, and an operator told "Erased" over
// that state has been told the job is finished when there is still one
// to come back to.
function _erasureLines(address, removed) {
  var finished = removed.outcome === "destroyed";
  var lines = [
    finished
      ? "Erased " + address + "."
      : "Partly erased " + address + ", and its account was kept.",
    "  " + _plural(removed.mailErased, "message", "messages") + " destroyed across " +
      _plural(removed.mailboxesErased, "mailbox", "mailboxes") + ", " +
      _plural(removed.aliasesErased, "alias", "aliases") + " erased.",
  ];

  // Whether the record is still reachable is not the same question as
  // whether it was kept on purpose, and only the first one tells the
  // operator what they can do next. A record held back while the identity
  // that owns it is still on the table is one the same command reaches on
  // a later run; the identity having gone is what turns that into a
  // sentence nobody can act on, so it is not printed then.
  // A message names itself; a mailbox row that could not be erased names
  // only the mailbox, so the line says which of the two it is rather
  // than printing an absent identifier as though it were one.
  //
  // The messages and the account's other material are enumerated from
  // separate lists and printed in one block, because what the operator
  // does about a record held back is the same whichever kind it is and
  // the line already names which one it was. What the two lists are kept
  // apart for is the counting further down: the sentences about mail
  // still being on the volume are about messages, and reaching them over
  // an annotation would send somebody to the volume reader after an
  // erasure that left no mail at all.
  var kept = removed.mailPreserved.concat(removed.recordsPreserved || []);
  var faulted = removed.mailFailed.concat(removed.recordsFailed || []);
  kept.forEach(function (entry) {
    lines.push("  kept  " + _erasureRecord(entry) + ": " + entry.reason +
      ". It is preserved on purpose" +
      (finished ? "." : " and still resolves to this account."));
  });
  removed.aliasesPreserved.forEach(function (entry) {
    lines.push("  kept  alias " + entry.address + ": " + entry.reason +
      ". It is preserved on purpose.");
  });
  if ((kept.length > 0 || removed.aliasesPreserved.length > 0) && !finished) {
    lines.push("  Release the order or obtain the grant, then run the same command again " +
      "to erase what was held back.");
  }

  faulted.forEach(function (entry) {
    lines.push("  FAIL  " + _erasureRecord(entry) + " could not be erased: " +
      (entry.detail || entry.reason));
  });
  removed.aliasesFailed.forEach(function (entry) {
    lines.push("  FAIL  alias " + entry.address + " could not be erased: " +
      (entry.detail || entry.reason));
  });
  // Two different states arrive under `mailFailed`, and only one of them
  // is mail still sitting on the volume. A record the volume would not
  // remove is not the message: the message can already be destroyed
  // while the row binding it to a mailbox stays, which is what a
  // write-once records posture produces. Telling an operator answering
  // an erasure request that their mail is still readable when it is not
  // is as wrong as the reverse, so the entry is asked rather than the
  // reason word read for it. Absent means unknown, which is answered the
  // careful way round.
  //
  // Both sentences below are about MESSAGES, which is why they are drawn
  // from `mailFailed` alone and never from the list beside it. A filter
  // script or an annotation carries no answer about octets at all, so
  // asking one this question reads its silence as mail left on the
  // volume, and the operator is sent to the volume reader to account for
  // mail that all went.
  var octetsStillHere = removed.mailFailed.filter(function (entry) {
    return entry.octets !== "gone";
  });
  if (octetsStillHere.length > 0) {
    lines.push("Mail this server was asked to lose is still on the volume. " +
      "`blamepost blobs report --verify` reports how much, and it is listed there as " +
      "mail no account holds.");
  }
  if (octetsStillHere.length < removed.mailFailed.length) {
    lines.push("The rest is destroyed and its rows were kept: the volume would not remove " +
      "the row binding a message to a mailbox, so a record of it stays with no message " +
      "content in it. `blamepost blobs report --verify` names the mailbox those rows are " +
      "still counted against.");
  }
  if (removed.aliasesFailed.length > 0) {
    lines.push("An alias pointing at a mailbox nobody holds keeps taking mail for an " +
      "address that can no longer be read. The addresses are listed above. Remove or " +
      "repoint each one on the Aliases page of the browser interface, at " +
      "`/admin/aliases`; this command line carries no alias verb.");
  }
  // A mailbox row is kept for anything still bound to it, which is a
  // message the delete path would not destroy or an annotation the erase
  // would not take. The line says what it can stand behind in both cases:
  // naming mail over a mailbox held by an annotation would send the
  // operator looking for a message that is not there.
  if (removed.mailboxesKept > 0) {
    lines.push(_plural(removed.mailboxesKept, "mailbox", "mailboxes") + " still " +
      (removed.mailboxesKept === 1 ? "holds" : "hold") + " a record this erasure could " +
      "not destroy, so " +
      (removed.mailboxesKept === 1 ? "its row was" : "their rows were") + " kept and that " +
      "record stays addressable.");
  }
  // The identity step's own refusals, which are not the same statement as
  // the account being kept because something else still names it. One of
  // them says the row could not be erased, and the account is out of
  // service and listed as erasing exactly as it would be. The other says
  // the row could not even be MARKED, which leaves an account in service
  // whose mail has gone, and that is the line to act on first.
  (removed.identityRefused || []).forEach(function (entry) {
    lines.push((entry.preserved === true ? "  kept  " : "  FAIL  ") +
      entry.record + ": " + (entry.detail || entry.reason));
  });
  var identityFaults = (removed.identityRefused || []).filter(function (entry) {
    return entry.preserved !== true;
  });
  if (identityFaults.length > 0) {
    lines.push("The account is still in service with its mail destroyed, because the " +
      "volume would not take the write that puts it out of service. Suspend it with " +
      "`blamepost account suspend` and run this again.");
  } else if (!finished) {
    lines.push("The account row was kept too, because it is what the mail above is " +
      "addressable through. It cannot sign in, takes no delivery and cannot be resumed; " +
      "`blamepost account list` shows it as erasing until this finishes.");
  }
  return lines;
}

// ---- preservation orders ----------------------------------------------------

// The identity a verb reaching into somebody's mailbox acts under. It is
// the account's own rather than the operator's, because every mailbox
// here belongs to one account and the adapter scopes each call by the
// account it is handed; an operator identity would name no mailbox at
// all. Who ASKED is on the audit row, which reads the scope the command
// opened.
function _actorFor(account) {
  return {
    id:      account.id,
    address: account.address,
    domain:  account.domain,
    roles:   ["account"],
  };
}

// The message ids a `--message` flag named. The parser hands back an
// array for a list flag whether the operator repeated it or gave one
// comma-separated value, so the only work left is dropping the empties a
// trailing comma leaves.
//
// Nothing here checks the SHAPE of an id. The adapter holds the only map
// from an account to its messages and reports anything it does not hold
// under `notInFolder`, so a second opinion about what an id looks like
// would be a second answer to whether this account has that message,
// and the one that is wrong would be the one written here.
function _messageIds(raw) {
  if (!Array.isArray(raw)) return [];
  var out = [];
  for (var i = 0; i < raw.length; i += 1) {
    var id = String(raw[i]).trim();
    if (id.length > 0 && out.indexOf(id) === -1) out.push(id);
  }
  return out;
}

// Untrusted header text on its way to a terminal. A subject and a From
// line are written by whoever sent the message, and this prints them to
// an operator who is deciding which records an order covers. The same
// screen the browser surface puts in front of them goes here: the
// balanced profile strips bidirectional overrides, zero-width and
// control characters and leaves every script alone, so a subject
// decoding to `Invoice <RLO>gpj.exe` cannot render as `Invoice exe.jpg`
// on the line somebody reads before naming that message in a court
// filing. It is the display that is corrected, never the stored value.
var HEADER_TEXT_GUARD = Object.freeze({ profile: "balanced" });

function _headerText(value, fallback) {
  if (typeof value !== "string" || value.length === 0) return fallback;
  return b.guardText.sanitize(value, HEADER_TEXT_GUARD);
}

// One millisecond reading as the day it falls on, in UTC. An operator
// matching a court's date range against a listing is comparing days, and
// a value the volume cannot supply prints as a row of dashes rather than
// as an epoch date, which would read as a real day in January 1970.
var UNDATED_DAY = "----------";

function _day(ms) {
  if (typeof ms !== "number" || !isFinite(ms) || ms < 0) return UNDATED_DAY;
  return new Date(ms).toISOString().slice(0, 10);
}

// A column padded to a width, so a heading sits over the values it names.
// Nothing is truncated: a value wider than the column pushes the rest of
// its line along, which misaligns one row, where cutting it would lose
// the identifier an operator is copying out.
function _column(text, width) {
  var value = String(text);
  return value.length >= width ? value : value + " ".repeat(width - value.length);
}

// Which of an account's mailboxes a reporting verb walks: the one named,
// or all of them. A name the account does not have is refused with the
// ones it does, because the alternative is a clean empty report about a
// mailbox that was never read, and on a question about preservation
// orders that reads as "nothing is held here".
function _mailboxesToScan(report, store, actor, named) {
  var mine = store.mailbox.accountFolders(actor).map(function (f) { return f.name; });
  if (!named) return { names: mine };
  if (mine.indexOf(named) === -1) {
    return {
      code: report.error("this account has no mailbox named " + JSON.stringify(String(named)) +
        ". It has: " + mine.join(", ") + ".", 2),
    };
  }
  return { names: [named] };
}

// ---- serve ------------------------------------------------------------------

async function cmdServe(flags) {
  var report = _reporter("serve");
  var config = _configFrom(flags);
  var store = await storeModule.open(config);
  // Two handles over the one body of mail: the per account adapter the
  // wire listeners drive, and the substrate the mailbox access agent
  // dispatches over. The second is read off the store when it offers
  // one, so there is a single handle in the process rather than two,
  // and composed by the facade when it does not.
  var server = blamepost.create({
    config:       config,
    store:        store,
    mailStore:    store.mailbox,
    messageStore: store.messageStore,
  });

  // Ordered start. A failure here has already closed whatever bound,
  // so there is nothing to unwind beyond the store.
  try {
    await server.start();
  } catch (err) {
    await store.close();
    return report.error((err && err.message) || String(err));
  }

  // SIGTERM is the contract with the supervisor. The phases run in
  // order inside one budget: listeners drain first so no new work
  // arrives, then the trail is written down and anchored, then the store
  // closes its files. The signal path exits on its own once the phases
  // finish, and the watchdog forces the exit if a phase wedges, so
  // nothing here ever needs to be killed.
  //
  // The middle phase is the one that is easy to leave out, and leaving
  // it out costs more than the rows it drops. Two things happen there.
  //
  // Buffered events reach disk. An emit that has not been flushed lives
  // in memory, so a stop takes with it every event of the last second
  // and every event this shutdown itself produces, and those are the
  // rows an incident asks about first.
  //
  // And the chain is anchored where it now ends. The record beside the
  // volume advances only when a checkpoint is written, and the one the
  // framework writes at boot anchors the trail as it stood when the
  // server STARTED. A running server anchors again on its own interval,
  // so what is left unanchored at any moment is bounded by that interval
  // rather than by the uptime; every row past the last anchored one is a
  // row somebody who reaches the stopped volume can rewrite while the
  // record beside it still agrees. Anchoring at the stop is what closes
  // the remainder, and it has to be awaited: the framework's own close
  // launches a final checkpoint without waiting for it and then tears the database
  // handle down on the same tick, so that one almost never lands.
  //
  // The second flush is not a duplicate of the first. Writing the
  // checkpoint is itself an audited act, so it produces the last event
  // of the process, and a flush before it is a flush of everything
  // except that.
  b.appShutdown.create({
    graceMs:               SHUTDOWN_GRACE_MS,
    forceExitMarginMs:     SHUTDOWN_FORCE_MARGIN_MS,
    installSignalHandlers: true,
    signals:               ["SIGTERM", "SIGINT"],
    phases: [
      { name: "listeners", run: function () { return server.stop({ timeoutMs: SHUTDOWN_GRACE_MS / 2 }); } },
      { name: "audit",     run: async function () {
        await b.audit.flush();
        await b.audit.checkpoint({ skipIfUnchanged: true });
        await b.audit.flush();
      } },
      { name: "store",     run: function () { return store.close(); } },
    ],
  });

  // Both listener sets, in one list. An operator reading this wants to
  // see the browser surface beside the mail ports.
  //
  // A port this server decided to leave shut is named here too, with the
  // reason. Listing only what bound leaves its absence to carry the
  // answer, and an absence reads the same whether the listener was held
  // back on purpose or failed to come up. Those are the two things an
  // operator most needs to tell apart while watching a first boot.
  var shape = server.describe();
  var withheld = shape.listeners.withheld || {};
  var lines = ["blamepost " + blamepost.version + " listening as " + config.hostname];
  Object.keys(shape.listeners.bound).forEach(function (name) {
    lines.push("  " + name + " on port " + shape.listeners.bound[name]);
  });
  Object.keys(shape.web.bound).forEach(function (name) {
    lines.push("  " + name + " on port " + shape.web.bound[name]);
  });
  Object.keys(withheld).forEach(function (name) {
    lines.push("  " + name + " is not listening: " + withheld[name]);
  });
  // `--json` is offered on every command, so it is honored here too. A
  // supervisor that reads what bound and on which port wants the shape,
  // not a paragraph to parse. It gets what is being held back for the
  // same reason the lines above carry it: a supervisor deciding whether
  // this server came up correctly cannot read that off the bound set
  // alone.
  return _emit(report, flags, {
    version:   blamepost.version,
    hostname:  config.hostname,
    listeners: shape.listeners.bound,
    withheld:  withheld,
    web:       shape.web.bound,
  }, lines);
}

// ---- init -------------------------------------------------------------------

async function cmdInit(flags) {
  var report = _reporter("init");
  var config = _configFrom(flags);

  // The data directory layout, created before anything writes into it,
  // so a permission problem surfaces during setup while an operator is
  // watching rather than during the first delivery.
  configModule.ensureDataDirectories(config);

  var store = await storeModule.open(config);
  try {
    var adminEmail = flags["admin-email"] || config.adminEmail;
    if (!adminEmail) {
      return report.error("no administrator address. Pass --admin-email or set " +
        "BLAMEPOST_ADMIN_EMAIL, so the first boot leaves you with an account you can " +
        "sign in to.", 2);
    }
    var password = flags["admin-password"] || config.adminPassword || b.crypto.generateToken(18);
    var generated = !flags["admin-password"] && !config.adminPassword;

    // The domain half of the administrator's address, read through the
    // derivation the identity layer owns rather than split by hand. The
    // account this run creates is resolved through that derivation, and
    // so is the domain row it needs to belong to, so a name read any
    // other way here can look absent while it is already hosted, and
    // then be handed to the signer as a domain nothing routes to.
    var domain = address.canonical(adminEmail, "--admin-email").domain;
    var known = store.domains.get(domain) !== null;
    if (!known) await store.domains.add({ domain: domain });

    var account = await store.accounts.create({
      address:  adminEmail,
      password: password,
      isAdmin:  true,
    });

    var dkimHandle = blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store });
    var publish = dkimHandle.list(domain).length > 0
      ? dkimHandle.dnsRecords(domain)
      : (await dkimHandle.generate({ domain: domain })).publish;

    var lines = [
      "Data directory ready at " + config.dataDir,
      "Domain " + domain + " is hosted.",
      "Administrator " + account.address + " created.",
    ];
    if (generated) lines.push("Password: " + password + "   (shown once)");
    lines.push("");
    lines.push("Publish these DKIM records before sending mail:");
    publish.forEach(function (record) { lines.push("  " + record.dnsRecord); });
    lines.push("");
    lines.push("Then add the MX, SPF, DMARC, MTA-STS and TLS-RPT records from");
    lines.push("docs/operator-guide.md, set BLAMEPOST_DNS_ACKNOWLEDGED=1, and run");
    lines.push("`blamepost doctor` to confirm the zone matches what this server expects.");
    lines.push("Record the domain's own posture with");
    lines.push("`blamepost domain acknowledge " + domain + " --by <who>`; the MX listener");
    lines.push("waits on it, and on the same acknowledgement for every domain added later.");
    return _emit(report, flags, {
      dataDir: config.dataDir,
      domain:  domain,
      admin:   account.address,
      password: generated ? password : null,
      publish: publish,
    }, lines);
  } finally {
    await store.close();
  }
}

// ---- account ----------------------------------------------------------------

async function cmdAccount(flags, positionals) {
  var report = _reporter("account");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_ACCOUNT);
  var unread = _refuseUnread(report, "account", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);
  var store = await _openForReporting(config, "account", verb);
  try {
    if (verb === "list") {
      // An account can only exist on a hosted domain, so a filter naming
      // one this server does not host can only ever answer with an empty
      // list, which is exactly what a correct answer looks like when the
      // domain is hosted and simply has no accounts yet. The two are
      // different facts and the operator gets told which.
      if (flags.domain) {
        var scope = _readDomainArg(report, flags.domain);
        if (scope.code !== undefined) return scope.code;
        if (!store.domains.get(scope.domain)) {
          var hosted = store.domains.list().map(function (d) { return d.domain; });
          return report.error("this server does not host " + scope.domain +
            ", so no account can be on it. Hosted domains: " +
            (hosted.length
              ? hosted.join(", ")
              : "none. Add one with `blamepost domain add <domain>`."), 2);
        }
      }
      // Archived accounts are left out unless they are asked for, which
      // is the identity layer's own default and the right one: the common
      // question is which mailboxes are live. It was the only answer this
      // surface offered, though, and `account resume` takes an archived
      // mailbox back, so an operator was being sent to a verb over an
      // address nothing here would print. The browser console has asked
      // for those rows since it was written.
      var accounts = store.accounts.list({
        domain:          flags.domain,
        includeArchived: flags["include-archived"] === true,
      });
      return _emit(report, flags, accounts, accounts.map(function (a) {
        return a.address + "  " + a.status + (a.isAdmin ? "  administrator" : "");
      }));
    }
    if (verb === "show") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      var one = store.accounts.get(positionals[1]);
      if (!one) return report.error("no account " + positionals[1]);
      return _emit(report, flags, one, [
        one.address,
        "  status:   " + one.status + (one.statusReason ? "  (" + one.statusReason + ")" : ""),
        "  sends as: " + one.address,
        "  quota:    " + (one.quotaBytes === null ? "unlimited" : one.quotaBytes + " bytes"),
      ]);
    }
    if (verb === "add") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      var secret = flags.password || b.crypto.generateToken(18);
      var created = await store.accounts.create({
        address:    positionals[1],
        password:   secret,
        quotaBytes: flags.quota,
      });
      var addLines = ["Created " + created.address];
      if (!flags.password) addLines.push("Password: " + secret + "   (shown once)");
      return _emit(report, flags, {
        address:  created.address,
        password: flags.password ? null : secret,
      }, addLines);
    }
    if (verb === "passwd") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      var target = store.accounts.get(positionals[1]);
      if (!target) return report.error("no account " + positionals[1]);
      var newSecret = flags.password || b.crypto.generateToken(18);
      await store.accounts.setPassword({ id: target.id, password: newSecret });
      var pwLines = ["Password changed for " + target.address];
      if (!flags.password) pwLines.push("Password: " + newSecret + "   (shown once)");
      return _emit(report, flags, {
        address:  target.address,
        password: flags.password ? null : newSecret,
      }, pwLines);
    }
    if (verb === "remove") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      // A reason is required either way. Archiving is reversible and
      // erasing is not, but both change who can read the mailbox, and
      // the audit row is the only record of why.
      if (!flags.reason) {
        return report.error("give --reason. Removing an account is recorded in the audit " +
          "trail, and a row with no reason answers nothing later.", 2);
      }
      var doomed = store.accounts.get(positionals[1]);
      if (!doomed) return report.error("no account " + positionals[1]);
      var removed = await store.accounts["delete"]({
        id:      doomed.id,
        destroy: flags.destroy === true,
        reason:  flags.reason,
      });
      // What the store says it did, not what the flag asked for. A line
      // that reads the request back turns any refusal below it into a
      // confirmation the operator has no reason to doubt. There are three
      // answers rather than two, and the one this has to keep apart from
      // the others is an erasure that ran and could not finish: reporting
      // that as an archive would describe a reversible verb the operator
      // did not ask for, over mail that is already destroyed.
      if (removed.outcome === "archived") {
        return _emit(report, flags, removed, ["Archived " + doomed.address]);
      }
      _emit(report, flags, removed, _erasureLines(doomed.address, removed));
      // An erasure that could not reach everything it was asked to reach
      // is not a success, whatever it printed. The operator's next step
      // differs by which list is non-empty, and all of them are on the
      // page above; what the exit status carries is that there IS a next
      // step, so a script driving a bulk erasure stops rather than
      // recording every one of them as done. A write about the account
      // row that the volume refused counts, and is the sharpest of the
      // three: the mail is gone and the mailbox is still answering.
      var identityFaulted = (removed.identityRefused || []).filter(function (entry) {
        return entry.preserved !== true;
      });
      // Every list that can hold a fault, including the account's filter
      // scripts and annotations. An annotation storage would not take is
      // a record the subject asked to have destroyed and it is still
      // there, so a bulk run has to stop on it exactly as it stops on a
      // message that stayed.
      return (removed.mailFailed.length > 0 ||
        (removed.recordsFailed || []).length > 0 ||
        removed.aliasesFailed.length > 0 ||
        identityFaulted.length > 0) ? 1 : 0;
    }
    if (verb === "suspend") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      var offender = store.accounts.get(positionals[1]);
      if (!offender) return report.error("no account " + positionals[1]);
      // The store requires a reason and so does this. Suspension is the
      // answer to a compromised mailbox, and the row saying which
      // incident it belonged to is what makes the reinstatement
      // defensible weeks later.
      if (!flags.reason) {
        return report.error("give --reason. A suspension is recorded, and a row with no " +
          "reason cannot answer why the account was locked.", 2);
      }
      var suspended = await store.accounts.suspend({ id: offender.id, reason: flags.reason });
      return _emit(report, flags, suspended, [
        "Suspended " + suspended.address + ".",
        "  It cannot authenticate and nothing is delivered to it. Everything it holds is kept.",
        "  Reinstate with `blamepost account resume " + suspended.address + "`.",
      ]);
    }
    if (verb === "resume") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      var locked = store.accounts.get(positionals[1]);
      if (!locked) return report.error("no account " + positionals[1]);
      // Both of the states `reinstate` returns to service, not just one.
      // It takes a suspended account back AND an archived one, so reading
      // only `suspended` here told an operator who had just un-archived a
      // mailbox that it "was already active, so nothing changed" over a
      // change that had in fact just happened. The status is read before
      // the call because the call is what changes it.
      var wasHeld = locked.status === "suspended" || locked.status === "archived";
      var resumed = await store.accounts.reinstate({ id: locked.id });
      return _emit(report, flags, resumed, [
        wasHeld
          ? "Resumed " + resumed.address + ", which was " + locked.status +
            ". It can authenticate and receive again."
          : resumed.address + " was already " + resumed.status + ", so nothing changed.",
      ]);
    }
    if (verb === "sieve") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      var owner = store.accounts.get(positionals[1]);
      if (!owner) return report.error("no account " + positionals[1]);
      // A filter script is the account holder's own configuration, and
      // reading it is an administrator reading something private that
      // belongs to somebody else. `account remove` already takes this
      // position for the same reason: the audit row is the only record
      // that it happened, and a row with no reason answers nothing
      // later. The cost is a few words at a moment when an operator
      // already knows why they are looking.
      if (!flags.reason) {
        return report.error("give --reason. Reading an account's filter script is recorded " +
          "in the audit trail, and a row with no reason answers nothing later.", 2);
      }
      var reader = { id: owner.id, address: owner.address };
      await auditActor.record({
        action:   "account.sieve_read",
        outcome:  "success",
        actor:    auditActor.current(),
        // The audit row has a first-class `reason` column, so the reason
        // goes there rather than into the metadata blob. An auditor
        // filtering on it needs a column, not a string to search inside.
        reason:   flags.reason,
        resource: { kind: "account", id: owner.id },
        metadata: { address: owner.address, script: flags.script || "" },
      });

      if (flags.script) {
        var script = store.mailbox.sieveScripts.get(reader, flags.script);
        if (!script) {
          return report.error("no script named " + JSON.stringify(flags.script) +
            " for " + owner.address);
        }
        return _emit(report, flags, script, [
          script.name + (script.active ? "  (active)" : ""),
          "",
        ].concat(String(script.body).split("\n")));
      }

      var scripts = store.mailbox.sieveScripts.list(reader);
      if (scripts.length === 0) {
        return _emit(report, flags, scripts, [owner.address + " has no filter scripts."]);
      }
      // The active one is the only one that runs, so it is the one an
      // operator is looking for and it is marked rather than left to be
      // worked out from the order.
      return _emit(report, flags, scripts, scripts.map(function (s) {
        return (s.active ? "* " : "  ") + s.name;
      }).concat(["", "Read one with --script <name>. Only the marked script runs."]));
    }
    if (verb === "messages") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      // The same position `account sieve` takes, for the same reason.
      // This prints who wrote to somebody and what about, which is their
      // correspondence rather than the server's state, and the audit row
      // is the only record that an administrator read it.
      if (!flags.reason) {
        return report.error("give --reason. Listing an account's mail is recorded in the " +
          "audit trail, and a row with no reason answers nothing later.", 2);
      }
      var listedFor = store.accounts.get(positionals[1]);
      if (!listedFor) return report.error("no account " + positionals[1]);
      var listActor = _actorFor(listedFor);
      var listScope = _mailboxesToScan(report, store, listActor, flags.mailbox);
      if (listScope.code !== undefined) return listScope.code;

      await auditActor.record({
        action:   "account.messages_read",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "account", id: listedFor.id },
        metadata: { address: listedFor.address, mailbox: flags.mailbox || "" },
      });

      var held = [];
      var inventory = [];
      listScope.names.forEach(function (name) {
        var rows = store.mailbox.searchScan(listActor, name);
        if (rows.length === 0) return;
        var underOrder = Object.create(null);
        store.mailbox.legalHold.status(listActor, name, rows.map(function (m) {
          return m.objectid;
        })).forEach(function (entry) {
          if (entry.held === true) underOrder[entry.objectid] = true;
        });
        rows.forEach(function (m) {
          var record = {
            objectId: m.objectid,
            mailbox:  name,
            // Two dates, because a message carries two and they answer
            // different questions. `arrived` is the clock reading this
            // server took when it filed the message, and it is what the
            // delete path measures a retention window against.
            // `clientDate` is INTERNALDATE, which RFC 9051 section
            // 6.3.12 lets a client set on upload, so a message can be
            // made to show any date its sender's software asked for.
            //
            // This table is what a preservation answer and an erasure
            // answer are assembled from, and it carries the order marker
            // beside these columns. Built on the client's date, such an
            // answer is built on a value the account holder chose, and a
            // message can be moved out of a court's date range by
            // uploading it with a date of somebody's choosing. So the
            // arrival stamp comes first and is what the answer stands
            // on. The client's date stays because it is what the holder
            // reads off their own screen when they describe a message,
            // and an operator matching a description to a record needs
            // both on the line.
            arrived:    _day(m.createdAt),
            clientDate: _day(m.internalDate),
            from:       _headerText(m.from, ""),
            subject:    _headerText(m.subject, "(no subject)"),
            held:       underOrder[m.objectid] === true,
          };
          if (record.held) held.push(record);
          inventory.push(record);
        });
      });

      if (inventory.length === 0) {
        return _emit(report, flags, inventory, [listedFor.address + " holds no mail" +
          (flags.mailbox ? " in " + flags.mailbox : "") + "."]);
      }
      // The identifier column is as wide as the widest identifier in the
      // answer, which is known because the whole inventory is built
      // before any of it is printed. Two dates on a line with no heading
      // over them leaves the operator to work out which is which, and the
      // heading only means anything if the values line up under it.
      var idWidth = 0;
      inventory.forEach(function (record) {
        if (record.objectId.length > idWidth) idWidth = record.objectId.length;
      });
      var inventoryLines = ["  " + _column("id", idWidth) + "  " +
        _column("arrived", UNDATED_DAY.length) + "  " +
        _column("client", UNDATED_DAY.length) + "  from  subject"];
      var lastMailbox = null;
      inventory.forEach(function (record) {
        if (record.mailbox !== lastMailbox) {
          inventoryLines.push(record.mailbox);
          lastMailbox = record.mailbox;
        }
        // The order marker goes at the end of the line rather than the
        // start, so the ids stay in one column for an operator copying
        // one into `account hold`.
        inventoryLines.push("  " + _column(record.objectId, idWidth) + "  " +
          record.arrived + "  " + record.clientDate + "  " +
          record.from + "  " + record.subject + (record.held ? "  HELD" : ""));
      });
      inventoryLines.push("");
      // Said in full once, under the table rather than in the heading,
      // because the heading has to stay narrow enough to sit over a date.
      // An operator who reads only the heading has the two apart already;
      // this is for the one deciding which of them a court's date range
      // should be matched against.
      inventoryLines.push("arrived is when this server filed the message. client is the date " +
        "the message shows, which an IMAP client sets when it uploads one, so nothing that " +
        "decides whether a message may be destroyed reads it.");
      inventoryLines.push(_plural(inventory.length, "message", "messages") + " across " +
        _plural(listScope.names.length, "mailbox", "mailboxes") + ", " +
        _plural(held.length, "message", "messages") + " under a preservation order.");
      inventoryLines.push("Place one with `blamepost account hold " + listedFor.address +
        " --mailbox <name> --message <id> --reason <text>`.");
      return _emit(report, flags, inventory, inventoryLines);
    }
    if (verb === "holds") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      var custodianOf = store.accounts.get(positionals[1]);
      if (!custodianOf) return report.error("no account " + positionals[1]);
      var custodianActor = _actorFor(custodianOf);
      var scanned = _mailboxesToScan(report, store, custodianActor, flags.mailbox);
      if (scanned.code !== undefined) return scanned.code;

      var orders = [];
      scanned.names.forEach(function (name) {
        var ids = store.mailbox.searchScan(custodianActor, name).map(function (m) {
          return m.objectid;
        });
        if (ids.length === 0) return;
        store.mailbox.legalHold.status(custodianActor, name, ids).forEach(function (entry) {
          if (entry.held !== true) return;
          orders.push({
            objectId:  entry.objectid,
            mailbox:   name,
            reason:    entry.reason,
            citation:  entry.citation,
            custodian: entry.custodian,
            placedBy:  entry.placedBy,
            placedAt:  entry.placedAt,
          });
        });
      });

      if (orders.length === 0) {
        return _emit(report, flags, orders, [
          custodianOf.address + " holds no message under a preservation order" +
            (flags.mailbox ? " in " + flags.mailbox : "") + ".",
        ]);
      }
      var holdLines = [_plural(orders.length, "message", "messages") + " under a " +
        "preservation order for " + custodianOf.address + "."];
      orders.forEach(function (entry) {
        holdLines.push("  " + entry.objectId + " in " + entry.mailbox);
        // The flag is what every delete path reads and the registry is
        // what explains it, so a message held with nothing recorded
        // behind it is a half-written placement rather than a blank
        // field. It is called out rather than printed as empty columns.
        if (!entry.reason) {
          holdLines.push("    WARN  nothing is recorded behind this order, so the message " +
            "refuses every delete with no paperwork saying why. Place it again to record " +
            "one, or release it.");
          return;
        }
        holdLines.push("    reason:    " + entry.reason);
        if (entry.citation)  holdLines.push("    citation:  " + entry.citation);
        if (entry.custodian) holdLines.push("    custodian: " + entry.custodian);
        holdLines.push("    placed:    " + new Date(entry.placedAt).toISOString() +
          (entry.placedBy ? " by " + entry.placedBy : ""));
      });
      return _emit(report, flags, orders, holdLines);
    }
    if (verb === "hold") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      // The reason first, before a store lookup, because it is the column
      // an auditor filters on and an order with nothing written against
      // it is not a record of anything.
      if (!flags.reason) {
        return report.error("give --reason. It is what the order is recorded under, and the " +
          "column an auditor filters on later.", 2);
      }
      if (!flags.mailbox) {
        return report.error("give --mailbox. An order names messages in one of the " +
          "account's mailboxes; `blamepost account holds <address>` lists the mailboxes " +
          "and the ids in them.", 2);
      }
      var toHold = _messageIds(flags.message);
      if (toHold.length === 0) {
        return report.error("give --message. An order is placed on messages rather than on " +
          "a mailbox, because a mailbox-wide order would silently cover mail that arrives " +
          "after it.", 2);
      }
      var holdTarget = store.accounts.get(positionals[1]);
      if (!holdTarget) return report.error("no account " + positionals[1]);

      var placed = await store.mailbox.legalHold.place(
        _actorFor(holdTarget), flags.mailbox, toHold, {
          reason:    flags.reason,
          citation:  flags.citation  || null,
          custodian: flags.custodian || null,
          placedBy:  auditActor.current().userId,
        });
      var placedLines = [_plural(placed.held.length, "message", "messages") + " placed " +
        "under a preservation order in " + flags.mailbox + " for " + holdTarget.address + "."];
      placed.held.forEach(function (id) { placedLines.push("  " + id); });
      if (placed.held.length > 0) {
        placedLines.push("  Every hard delete refuses them now, on IMAP, POP3, JMAP and " +
          "webmail alike, and an account erasure keeps them back and says so. Lift the " +
          "order with `blamepost account release`.");
      }
      placed.alreadyHeld.forEach(function (id) {
        placedLines.push("  kept  " + id + " was already under an order, so the one on it " +
          "stands and this reason was not recorded against it.");
      });
      // The half an operator answering a court order has to see. A
      // message that is not in the mailbox they named is a message no
      // order was placed on, and reading a clean report over that is how
      // somebody comes to believe a preservation duty is met when it is
      // not.
      placed.notInFolder.forEach(function (id) {
        placedLines.push("  FAIL  " + id + " is not in " + flags.mailbox + " for this " +
          "account, so nothing was placed on it.");
      });
      _emit(report, flags, placed, placedLines);
      return placed.notInFolder.length > 0 ? 1 : 0;
    }
    if (verb === "release") {
      if (!positionals[1]) return report.usage(USAGE_ACCOUNT);
      // Lifting an order is the half of this that ends a duty, and the
      // next hard delete on those messages destroys them, so it is
      // confirmed the way every other verb that removes a protection is.
      var confirmedRelease = _requireConfirmation(report, flags,
        "Lifting a preservation order lets the ordinary delete path reach those messages " +
        "again, and the next expunge, POP3 commit, JMAP destroy or account erasure will " +
        "remove them.");
      if (confirmedRelease !== 0) return confirmedRelease;
      if (!flags.approver) {
        return report.error("give --approver. A preservation order is not lifted by whoever " +
          "happens to be at the keyboard, and the name is what the audit row carries.", 2);
      }
      if (!flags.mailbox) {
        return report.error("give --mailbox. A release names messages in one of the " +
          "account's mailboxes; `blamepost account holds <address>` lists them.", 2);
      }
      var toRelease = _messageIds(flags.message);
      if (toRelease.length === 0) {
        return report.error("give --message. A release names the messages whose duty has " +
          "ended, one order at a time, rather than clearing a mailbox at once.", 2);
      }
      var releaseTarget = store.accounts.get(positionals[1]);
      if (!releaseTarget) return report.error("no account " + positionals[1]);

      var lifted = await store.mailbox.legalHold.release(
        _actorFor(releaseTarget), flags.mailbox, toRelease, {
          reason:   flags.reason,
          approver: flags.approver,
        });
      var liftedLines = [_plural(lifted.released.length, "order", "orders") + " lifted in " +
        flags.mailbox + " for " + releaseTarget.address + "."];
      lifted.released.forEach(function (id) { liftedLines.push("  " + id); });
      if (lifted.released.length > 0) {
        liftedLines.push("  The ordinary delete path reaches them again. An account erasure " +
          "run from here on will destroy them.");
      }
      // The registry had no row and the flag came off anyway, which is
      // the state a half-written placement leaves and the one thing a
      // release has to be able to clear. It is reported rather than
      // hidden, because the message was refusing every delete with no
      // paperwork behind it and somebody should know that happened.
      lifted.notRegistered.forEach(function (id) {
        liftedLines.push("  " + id + " was refusing deletes with no order recorded behind " +
          "it. The refusal is cleared and there was no paperwork to close.");
      });
      lifted.notInFolder.forEach(function (id) {
        liftedLines.push("  FAIL  " + id + " is not in " + flags.mailbox + " for this " +
          "account, so nothing was lifted from it.");
      });
      _emit(report, flags, lifted, liftedLines);
      return lifted.notInFolder.length > 0 ? 1 : 0;
    }
    return report.usage(USAGE_ACCOUNT);
  } finally {
    await store.close();
  }
}

// ---- domain -----------------------------------------------------------------

async function cmdDomain(flags, positionals) {
  var report = _reporter("domain");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_DOMAIN);
  var unread = _refuseUnread(report, "domain", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);
  var store = await _openForReporting(config, "domain", verb);
  try {
    if (verb === "list") {
      var domains = store.domains.list();
      return _emit(report, flags, domains, domains.map(function (d) {
        return d.domain + "  " + d.status +
          (d.dnsAcknowledged ? "  dns acknowledged" : "  dns not acknowledged");
      }));
    }
    if (verb === "show") {
      if (!positionals[1]) return report.usage(USAGE_DOMAIN);
      var one = store.domains.get(positionals[1]);
      if (!one) return report.error("no hosted domain " + positionals[1]);
      var dkimShow = blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store });
      var records = dkimShow.dnsRecords(one.domain);
      return _emit(report, flags, { domain: one, dkim: records },
        [one.domain,
          "  status: " + one.status,
          "  dns:    " + (one.dnsAcknowledged
            ? "acknowledged by " + (one.dnsAcknowledgedBy || "an operator")
            : "not acknowledged, so the MX listener will not bind"),
          "  DKIM records that must be published:"]
          .concat(records.map(function (r) { return "    " + r.dnsName + "  (" + r.state + ")"; })));
    }
    if (verb === "add") {
      if (!positionals[1]) return report.usage(USAGE_DOMAIN);
      var added = await store.domains.add({ domain: positionals[1] });
      var dkimAdd = blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store });
      var minted = await dkimAdd.generate({ domain: added.domain });
      return _emit(report, flags, { domain: added, publish: minted.publish },
        ["Hosting " + added.domain, "", "Publish these DKIM records:"]
          .concat(minted.publish.map(function (r) { return "  " + r.dnsRecord; }))
          .concat(["",
            "Then run `blamepost doctor` to check the rest of the zone, and",
            "`blamepost domain acknowledge " + added.domain + " --by <who>` once it is live.",
            "Inbound mail for this domain waits on that acknowledgement."]));
    }
    // The MX listener refuses to bind while any active domain is
    // unacknowledged, so this verb is the step between publishing a new
    // domain's records and serving mail for it. It records a claim and
    // resolves nothing; `blamepost doctor` is what goes and looks.
    if (verb === "acknowledge") {
      if (!positionals[1]) return report.usage(USAGE_DOMAIN);
      if (!flags.by) {
        return report.error("give --by. The acknowledgement is one person saying the records " +
          "are published, and a row that does not name them answers nothing later.", 2);
      }
      var confirming = flags.withdraw !== true;
      var posture = await store.domains.acknowledgeDns({
        domain:         positionals[1],
        acknowledged:   confirming,
        acknowledgedBy: flags.by,
      });
      return _emit(report, flags, posture, confirming
        ? ["DNS for " + posture.domain + " acknowledged by " + flags.by + ".",
          "The MX listener binds once every hosted domain has been acknowledged.",
          "Run `blamepost doctor --domain " + posture.domain + "` to check the zone against " +
            "what this server expects."]
        : ["DNS acknowledgement for " + posture.domain + " withdrawn.",
          "The MX listener will refuse to bind until it is given again."]);
    }
    // Turning a domain off and taking it away are different operations
    // with different consequences, and only one of them can be undone.
    // A disabled domain drops out of the set the MX listener accepts
    // mail for, so inbound mail is refused at RCPT, and every account,
    // mailbox and selector stays exactly where it was.
    if (verb === "disable" || verb === "enable") {
      if (!positionals[1]) return report.usage(USAGE_DOMAIN);
      if (!flags.reason) {
        return report.error("give --reason. Turning a domain's mail off or back on changes " +
          "what this server accepts and is recorded in the audit trail, which answers " +
          "nothing later without one.", 2);
      }
      var wanted = verb === "disable" ? "disabled" : "active";
      var switched = await store.domains.setStatus({
        domain: positionals[1],
        status: wanted,
        reason: flags.reason,
      });
      return _emit(report, flags, switched, wanted === "disabled"
        ? ["Disabled " + switched.domain + ".",
          "  This server no longer accepts mail for it, so inbound mail is refused at RCPT",
          "  and senders find out. It is not a quiet hold.",
          "  Its accounts, their mail and its DKIM selectors are untouched.",
          "  Turn it back on with `blamepost domain enable " + switched.domain +
            " --reason <text>`."]
        : ["Enabled " + switched.domain + ". Mail for it is accepted again."]);
    }
    if (verb === "remove") {
      if (!positionals[1]) return report.usage(USAGE_DOMAIN);
      if (!flags.reason) {
        return report.error("give --reason. Removing a domain takes its DKIM selectors with " +
          "it and is recorded in the audit trail, which answers nothing later without one.", 2);
      }
      // There is no archived state for a domain: the row and its
      // selectors are erased outright. So the irreversible half is asked
      // for explicitly, the way erasing an account is, and the
      // reversible answer is named rather than left to be discovered.
      if (flags.destroy !== true) {
        return report.error("give --destroy. Removing a domain erases its row and its DKIM " +
          "selectors, and there is no archived copy to reinstate. To stop mail for it " +
          "without losing anything, run `blamepost domain disable " + positionals[1] +
          " --reason <text>` instead.", 2);
      }
      var removedDomain = await store.domains.remove({
        domain: positionals[1],
        reason: flags.reason,
      });
      // The private keys are named separately from the records, because
      // they are the half that cannot be republished and the half an
      // operator would otherwise have to go and look for. A selector
      // record is public and the operator still has to pull it from the
      // zone; the sealed key is gone from this volume, and saying so is
      // what tells them there is nothing left to clean up by hand.
      return _emit(report, flags, removedDomain, [
        "Erased " + removedDomain.domain +
          " along with " + removedDomain.selectorsRemoved + " DKIM selector(s)" +
          " and " + removedDomain.keysErased + " sealed private key(s)",
        "  Remove the DKIM records for " + removedDomain.domain + " from its zone: this",
        "  server never edits DNS, so they stay published until you pull them.",
      ].concat(removedDomain.keysLeftAside.length === 0 ? [] : [
        // The one outcome of a removal that leaves work on the volume.
        // A key that could not be destroyed once the rows had gone is
        // sitting under a name no row points at, so nothing here will
        // ever find it again and nothing will report it a second time.
        // Whoever holds it signs mail as this domain.
        "  " + removedDomain.keysLeftAside.length + " sealed private key(s) could not be",
        "  destroyed and are still in the keys folder under: " +
          removedDomain.keysLeftAside.join(", "),
        "  Nothing names them now, so delete them by hand. Whoever holds one of these",
        "  signs mail as " + removedDomain.domain + ", and that stays true if somebody",
        "  else hosts the name later.",
      ]));
    }
    return report.usage(USAGE_DOMAIN);
  } finally {
    await store.close();
  }
}

// ---- dkim -------------------------------------------------------------------

async function cmdDkim(flags, positionals) {
  var report = _reporter("dkim");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_DKIM);
  var unread = _refuseUnread(report, "dkim", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);
  var store = await _openForReporting(config, "dkim", verb);
  try {
    var handle = blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store });
    var domain = flags.domain || positionals[1];

    // This verb group is the one place a domain arrives from either a
    // flag or an argument, so what was assembled from the two is checked
    // here rather than several layers down. Every verb below either
    // signs for the domain or reports what its zone must carry, and
    // neither answer means anything for a name this server does not
    // host: an empty record list reads as "nothing to publish", which is
    // exactly what a correct answer looks like.
    if (domain !== undefined && domain !== null) {
      var shape = _readDomainArg(report, domain);
      if (shape.code !== undefined) return shape.code;
      domain = shape.domain;
      var hostedRow = store.domains.get(domain);
      if (!hostedRow) {
        var hosted = store.domains.list().map(function (d) { return d.domain; });
        return report.error("this server does not host " + domain + ". Hosted domains: " +
          (hosted.length
            ? hosted.join(", ")
            : "none. Add one with `blamepost domain add <domain>`."), 2);
      }
      // The name the store recorded, so every verb below reads the same
      // spelling the selector rows were written under.
      domain = hostedRow.domain;
    }

    if (verb === "list") {
      var inventory = handle.list(domain);
      return _emit(report, flags, inventory, inventory.map(function (sel) {
        return sel.domain + "  " + sel.selector + "  " + sel.algorithm + "  " + sel.state +
          (sel.retiresAt ? "  until " + new Date(sel.retiresAt).toUTCString() : "");
      }));
    }
    if (verb === "records") {
      if (!domain) return report.usage(USAGE_DKIM);
      var records = handle.dnsRecords(domain);
      return _emit(report, flags, records, records.map(function (r) { return r.dnsRecord; }));
    }
    if (verb === "generate") {
      if (!domain) return report.usage(USAGE_DKIM);
      var minted = await handle.generate({ domain: domain, selector: flags.selector });
      return _emit(report, flags, minted,
        ["Publish these records. Mail from " + domain + " is signed with them from now on, " +
          "so publish before you send."]
          .concat(minted.publish.map(function (r) { return "  " + r.dnsRecord; })));
    }
    if (verb === "rotate") {
      if (!domain) return report.usage(USAGE_DKIM);
      var rotated = await handle.rotate({ domain: domain, selector: flags.selector });
      var outgoing = rotated.previous.length > 0 ? rotated.previous[0][0] : null;
      return _emit(report, flags, rotated, [
        "A replacement pair is minted. Both pairs sign from now on, so the current",
        "signature keeps verifying while the new records propagate.",
        "",
        "Publish these records:",
      ].concat(rotated.minted.map(function (m) {
        var record = handle.dnsRecords(domain).filter(function (r) {
          return r.selector === m.selector && r.algorithm === m.algorithm;
        })[0];
        return "  " + (record ? record.dnsRecord : m.selector);
      })).concat([
        "",
        "Once they resolve, retire the outgoing pair:",
        "  blamepost dkim retire --domain " + domain +
          (outgoing ? " --selector " + outgoing : " --selector <selector>"),
      ]));
    }
    if (verb === "retire") {
      if (!domain || !flags.selector) return report.usage(USAGE_DKIM);
      var out = await handle.retire({ domain: domain, selector: flags.selector });
      var retireLines = ["Signing for " + domain + " no longer uses " +
        out.retired.map(function (r) { return r.selector; }).join(" and ") + "."];
      retireLines.push("Their private keys are erased.");
      retireLines.push("");
      retireLines.push("Leave these records published until the moment shown, so mail signed");
      retireLines.push("before the change still verifies:");
      out.retired.forEach(function (r) {
        retireLines.push("  " + r.dnsName + "  until " +
          (r.retiresAt ? new Date(r.retiresAt).toUTCString() : "the overlap elapses"));
      });
      return _emit(report, flags, out, retireLines);
    }
    if (verb === "sweep") {
      var swept = await handle.sweep({ domain: domain, immediate: flags.immediate === true });
      // A sealed private key that could not be destroyed once its row
      // had gone is sitting under a name no row points at, so nothing
      // here will report it again. It is said on both branches, because
      // a sweep that withdrew nothing can still have left one behind.
      var sweptAside = swept.keysLeftAside.length === 0 ? [] : [
        swept.keysLeftAside.length + " sealed private key(s) could not be destroyed and are",
        "still in the keys folder under: " + swept.keysLeftAside.join(", "),
        "Nothing names them now, so delete them by hand. Whoever holds one signs mail",
        "as the domain it belonged to.",
      ];
      if (swept.withdrawn.length === 0) {
        return _emit(report, flags, swept,
          ["No retired selector has finished its window yet."].concat(sweptAside));
      }
      return _emit(report, flags, swept,
        ["These records can now be removed from the zone:"]
          .concat(swept.withdrawn.map(function (s) { return "  " + s.dnsName; }))
          .concat(sweptAside));
    }
    return report.usage(USAGE_DKIM);
  } finally {
    await store.close();
  }
}

// ---- queue ------------------------------------------------------------------

async function cmdQueue(flags, positionals) {
  var report = _reporter("queue");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_QUEUE);
  var unread = _refuseUnread(report, "queue", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);
  var handle = blamepost.mail.delivery.create({
    hostname: config.hostname,
    dataDir:  config.dataDir,
    // The operator's own ceiling rather than the shipped one. Built
    // without it, this handle would report a bound the running server
    // does not hold, so `queue list` would say there is room where the
    // listeners are already refusing, or the reverse.
    spool:    config.outboundSpool,
    maxMessageBytes: config.limits === null || config.limits === undefined
      ? undefined : config.limits.maxMessageBytes,
  });

  if (verb === "list") {
    // A filter that cannot be read is refused rather than matched
    // against nothing, because an empty list is exactly what a correct
    // answer looks like and a typo would read as a settled fact about
    // that account. The refusal names what was wrong with it and comes
    // back through the dispatcher's boundary as an argument problem.
    var waiting = await handle.queue.list({
      account:     flags.account,
      destination: flags.destination,
    });
    var lines = waiting.map(function (entry) {
      if (entry.unreadable) return entry.id + "  unreadable spool entry";
      return entry.id + "  " + entry.recipient + "  attempt " + entry.attempt +
        "  due " + new Date(entry.nextAttemptAt).toUTCString() +
        _viaHost(entry) + "  " + entry.reason;
    });
    // An empty list under a filter and an empty queue are different
    // facts, and a bare blank answer reads as the second whichever one
    // is true. Say which filter produced it.
    if (waiting.length === 0 && (flags.account || flags.destination)) {
      lines = ["Nothing waiting for " +
        (flags.account ? "account " + flags.account : "destination " + flags.destination) +
        ". The queue holds " + handle.queue.count() + " message(s) in total."];
    }
    // How close the queue is to refusing. An operator reading a list of
    // waiting messages has no way to tell a queue that is filling from
    // one that is merely busy, and the difference is whether their
    // account holders are about to be told to try again.
    var room = handle.queue.capacity();
    lines = lines.concat(["",
      "Holding " + room.messages + " of " + room.maxMessages + " message(s), " +
      room.bytes + " of " + room.maxBytes + " byte(s).",
    ]);
    if (room.messages > 0) {
      lines.push("At either ceiling new mail is refused with a temporary code and stays " +
        "with its sender. `blamepost queue held` says what is waiting and why.");
    }
    // The part of that room nothing above accounts for. A message body
    // whose descriptor never landed is in no listing, because every
    // listing reads descriptors, and this is the screen an operator is
    // looking at when the queue reads as empty and mail is being refused
    // anyway. The ids are printed because clearing one takes an id.
    var unclaimed = handle.queue.orphans();
    if (unclaimed.length > 0) {
      lines.push("",
        _plural(unclaimed.length, "message body", "message bodies") +
        " here has no descriptor, holding " +
        unclaimed.reduce(function (sum, entry) { return sum + entry.sizeBytes; }, 0) +
        " byte(s) of that room. Nothing lists them and nothing sends them. Clear each " +
        "with `blamepost queue remove <id> --reason ...`: " +
        unclaimed.map(function (entry) { return entry.id; }).join(", ") + ".");
    }
    return _emit(report, flags, waiting, lines);
  }
  if (verb === "show") {
    // One entry, with the two things a listing cannot carry: what the far
    // side said on each attempt, and where the message is headed if
    // nothing changes. A row in `list` says a message is waiting and when
    // it will next be tried, which answers "is it moving" and not "why is
    // it not arriving" or "how long have I got". Those are the questions
    // an operator has when an account holder is asking after a message,
    // and the delivery handle has computed both all along.
    if (!positionals[1]) return report.usage(USAGE_QUEUE);
    var shown = await handle.queue.show(positionals[1]);

    // A well formed id with nothing behind it is an answer rather than a
    // fault: the message may have been delivered, given up on, or removed
    // since the id was read. Saying which of those is not something this
    // can know, so it says what it does know and does not guess.
    if (shown === null) {
      return _emit(report, flags, null, [
        "Nothing by that id is waiting. The message was delivered, given up on, or " +
        "taken out of the queue since the id was read. `blamepost audit read " +
        "--action blamepost.mail.queue.message_removed` says whether an operator " +
        "removed it.",
      ]);
    }

    var showLines = [
      "id         " + shown.id,
      "recipient  " + shown.recipient,
      // An empty reverse path prints as the marker rather than as a
      // blank, which reads as a field this failed to fetch. What it
      // means for the message is left to the projection below, which
      // says it in the handle's words so this surface and the browser
      // interface do not each phrase it their own way.
      "sender     " + (String(shown.from || "").trim() || "<>"),
      "queued     " + new Date(shown.queuedAt).toUTCString(),
      "size       " + shown.sizeBytes + " byte(s)",
    ];

    // The attempt record. Printed oldest first, because the question it
    // answers is what changed between attempts, and a receiver that
    // refused for one reason and then another is the shape that says the
    // fault moved rather than persisted.
    var history = Array.isArray(shown.history) ? shown.history : [];
    showLines.push("");
    if (history.length === 0) {
      showLines.push("No attempt has been made yet. The first one falls due " +
        new Date(shown.nextAttemptAt).toUTCString() + ".");
    } else {
      showLines.push(_plural(history.length, "attempt", "attempts") + ", oldest first:");
      history.forEach(function (row) {
        showLines.push("  " + new Date(row.at).toUTCString() +
          "  attempt " + row.attempt + "  " + row.outcome +
          (row.mxHost ? "  via " + row.mxHost : "") +
          (row.reasonCode ? "  " + row.reasonCode : "") +
          (row.reason ? "  " + row.reason : ""));
      });
    }

    // How it ends. The handle writes this sentence rather than the
    // terminal, so the browser interface and this command line say the
    // same thing about the same message instead of each phrasing the
    // budget in its own words.
    var projection = shown.projection || {};
    showLines.push("");
    showLines.push(projection.held
      ? "Held: this message spends no attempts while it waits."
      : "Attempt " + projection.attemptsSpent + " of " + projection.attemptsAllowed +
        " spent, " + projection.attemptsRemaining + " left. Next attempt " +
        new Date(projection.nextAttemptAt).toUTCString() + ".");
    if (projection.ifItNeverSucceeds) showLines.push(projection.ifItNeverSucceeds);

    return _emit(report, flags, shown, showLines);
  }
  if (verb === "held") {
    // Held mail is a different question from waiting mail, and `list`
    // cannot answer it: a held entry has no next attempt to sort by and
    // no budget left to report, so it reads there as a row with nothing
    // in the columns that matter. What an operator needs is the reason
    // it stopped and what would release it, counted by cause rather
    // than listed per recipient, because one fault holds every message
    // bound for the same place and a per-recipient list buries that.
    var stalled = await handle.queue.held();
    var heldLines = stalled.reasons.map(function (group) {
      return group.messages + "  " + group.reason;
    });
    if (stalled.messages === 0) {
      heldLines = ["Nothing is held. Every message in the queue still has attempts left."];
    } else {
      heldLines = heldLines.concat(["",
        stalled.messages + " message(s) held, oldest queued " +
        new Date(stalled.oldestQueuedAt).toUTCString() + ".",
        "Held mail keeps its place and spends no attempts, so nothing here is being " +
        "retried into oblivion. It leaves on its own once the cause above is gone.",
      ]);
    }
    return _emit(report, flags, stalled, heldLines);
  }
  if (verb === "flush") {
    var result = await handle.queue.runDue({ force: flags.force === true });
    // An entry another process is already attempting is reported rather
    // than passed over in silence: an operator who ran a flush and saw a
    // message stay put needs to know the server was working on it, not
    // that the flush skipped it.
    var claimed = result.results.filter(function (r) { return r.outcome === "claimed"; }).length;
    var flushLines = result.results.map(function (r) {
      return r.id + "  " + r.recipient + "  " + r.outcome + (r.error ? "  " + r.error : "");
    }).concat(["", (result.ran - claimed) + " message(s) attempted"]);
    if (claimed > 0) {
      flushLines.push(claimed + " message(s) left alone because another process is " +
        "attempting them, which is what the running server does on its own schedule.");
    }
    return _emit(report, flags, result, flushLines);
  }
  if (verb === "remove") {
    if (!positionals[1]) return report.usage(USAGE_QUEUE);
    // Abandoning a message is final: the body and the descriptor are
    // erased and the sender is never told. `account remove` already
    // takes this position for the same reason, and the incident runbook
    // reaches for this verb on mail a stolen credential sent, which is
    // exactly the moment somebody asks later what was cancelled and why.
    //
    // The rule itself belongs to the removal, which refuses without a
    // reason whoever asks. This is the argument check that names the
    // flag, in front of a volume open that unseals the vault and
    // decrypts the database: an operator who left the flag out meets a
    // usage refusal here rather than an exception several seconds later,
    // and every other destructive verb on this command line refuses the
    // same way. Both run over the same value and neither is a second
    // reading of what counts as a reason.
    if (!flags.reason) {
      return report.error("give --reason. Abandoning a queued message erases it without " +
        "telling the sender, and a row with no reason answers nothing later.", 2);
    }
    var wanted = positionals[1];
    var queued = await handle.queue.list({});
    var target = queued.filter(function (entry) { return entry.id === wanted; })[0];
    // A message body whose descriptor never landed is removable by the
    // same verb and is in none of the listings above, because every one
    // of them reads descriptors. It is what `queue list` and `doctor`
    // send an operator here to clear, so an id from either has to be one
    // this verb takes. There is no recipient to name: that was in the
    // descriptor, which is the half that is missing.
    var stranded = null;
    if (!target) {
      stranded = handle.queue.orphans().filter(function (entry) {
        return entry.id === wanted;
      })[0] || null;
    }
    // An id that is neither has to refuse. Reporting the removal of
    // something that was never there tells an operator cancelling a
    // compromised account's mail that the message is gone while it is
    // still on disk waiting for its next attempt.
    if (!target && !stranded) {
      return report.error("no queued message with id " + JSON.stringify(wanted) + ". The " +
        "queue holds " + queued.length + " message(s); `blamepost queue list` prints their " +
        "ids.", 2);
    }

    // What an operator does about a message that left on its own. It is
    // the same advice whether the reading beside the erasure found
    // nothing or the erasure itself did, so it is written once: two
    // spellings of it are two answers to disagree about what "past
    // cancelling" means.
    var pastCancelling = "A message leaves on its own when a receiver takes it or when its " +
      "attempts run out, and `blamepost queue flush` and the running server both send mail " +
      "without telling this command. Whichever of those it was, the message is past " +
      "cancelling: treat it as sent.";

    var store = await storeModule.open(config);
    try {
      // The audit namespace this application writes under. Registering
      // it here is what lets a verb that needs no mailbox state still
      // leave a row, and registration is idempotent, so a process that
      // has already composed the listeners is unaffected.
      b.audit.registerNamespace(AUDIT_NAMESPACE);
      // The reading the erasure is decided on, taken with nothing
      // suspending between it and the erasure. Everything above
      // describes the queue as it stood before the volume opened, and
      // opening the volume unseals the vault and decrypts the whole
      // database into a working copy: a `queue flush` running beside
      // this one opens no volume at all, and the running server retries
      // on a schedule of its own, so either has that entire window to
      // deliver the message and unlink the pair.
      //
      // Erasing what has already gone costs nothing, because there is
      // nothing left to erase. Reporting it is the harm: an operator
      // cancelling mail a stolen credential sent is told it was
      // stopped, and the row filed under their name says the same,
      // while the message is with the receiver.
      //
      // Both kinds of id are asked again, because either can leave. A
      // descriptor is what `show` reads; a message body whose
      // descriptor never landed is in no listing that reads
      // descriptors and is counted off the volume instead. `orphans`
      // answers without suspending, so asking and erasing stay one run.
      var current = await handle.queue.show(wanted);
      var leftBehind = current !== null ? null
        : handle.queue.orphans().filter(function (entry) {
          return entry.id === wanted;
        })[0] || null;
      if (current === null && leftBehind === null) {
        // Worth a row of its own. An operator reaching for this verb in
        // an incident needs to know the message left rather than that
        // nothing happened, and the moment they asked is what ties the
        // attempt to the rest of the incident. What it can describe is
        // the entry as the listing above saw it, which is the only
        // description of it this run ever had.
        await auditActor.record({
          action:   "blamepost.mail.queue.message_removed",
          outcome:  "failure",
          actor:    auditActor.current(),
          reason:   flags.reason,
          resource: { kind: "queued_message", id: wanted },
          metadata: {
            recipient:  target ? (target.recipient || null) : null,
            from:       target ? (target.from || null) : null,
            attempt:    target && target.attempt !== undefined ? target.attempt : null,
            descriptor: target ? "present" : "missing",
            stopped:    "left the queue before it could be erased",
            // On every row this verb files, so a trail read afterwards
            // answers "was the sender told" without the reader having to
            // know which branch wrote the row or which surface ran.
            reported:   false,
            withheld:   "message-not-cancelled",
          },
        });
        return report.error(wanted + " is no longer in the queue, so nothing was removed " +
          "and no row says otherwise. It was waiting when this run started and had gone by " +
          "the time the data volume opened. " + pastCancelling);
      }
      // Nobody is written to, and the removal is told so rather than
      // left to guess. This verb is the one an operator reaches for
      // during an incident, working through the outbound mail of an
      // account somebody else has been using: the address in the reverse
      // path is whoever has been using it, and a delivery report tells
      // them which of their messages were caught and which got out. The
      // browser console cancels routinely and makes the other choice,
      // and the queue's own verb is what holds both to stating one.
      //
      // An operator who does want the sender told sends them a message.
      // That is a decision with a person behind it, which is the right
      // shape for it, and it is not one an incident verb should make on
      // their behalf.
      var removed = await handle.queue.remove(wanted, {
        reason: flags.reason,
        notice: { withheld: "operator-withheld-notice" },
      });
      // Part of the entry destroyed and part of it kept. It is reported
      // apart from a refusal because the operator's next move is a
      // different one: a refusal cancelled nothing and is worth running
      // again, and this cancelled the message permanently while leaving
      // a file behind, so "clear the fault and run this again" would
      // send them back for a message that can never be sent either way.
      // The row is a failure because the request was not met in full.
      if (removed.outcome === "incomplete") {
        await auditActor.record({
          action:   "blamepost.mail.queue.message_removed",
          outcome:  "failure",
          actor:    auditActor.current(),
          // The sentence the removal accepted rather than the flag as it
          // was read off the command line, so this row and the console's
          // row carry one value for one act.
          reason:   removed.requestedBecause,
          resource: { kind: "queued_message", id: wanted },
          metadata: {
            recipient:  current ? (current.recipient || null) : null,
            from:       current ? (current.from || null) : null,
            attempt:    current && current.attempt !== undefined ? current.attempt : null,
            descriptor: current ? "present" : "missing",
            cause:      removed.outcome,
            destroyed:  removed.destroyed,
            stopped:    "the data volume kept its " + removed.left.join(" and ") +
              " after this server had destroyed its " + removed.destroyed.join(" and "),
            reported:   removed.reported,
            withheld:   removed.withheld,
          },
        });
        return report.error(wanted + " was destroyed in part. This server took its " +
          removed.destroyed.join(" and ") + " off the data volume and could not take its " +
          removed.left.join(" and ") + ": " + removed.reason + ". The message itself is " +
          "gone, so it can never be sent and its sender has not been told. The entry is " +
          "still listed because its descriptor is still there. Clear whatever is holding " +
          "that file open under " + config.paths.queue + " and run this again to take the " +
          "rest: the message will not come back, and until then the running server will " +
          "read the entry, find nothing to send, and abandon it on its own. That " +
          "abandonment writes to nobody either, because an entry with no message beside " +
          "it cannot tell a cancellation from a delivery, so telling this sender is yours " +
          "to do if they need to know.");
      }
      if (removed.removed !== true) {
        // The erasure's own answer, which is the last look anything takes
        // at the volume. The reading above closes the window it can
        // close; this one closes the rest of it, and it sees the state no
        // reading ever could, which is a volume that will not give the
        // message up. That one is why the refusal is worth the words: the
        // pair is still there, the running server will attempt it again,
        // and an operator told the message was cancelled stops looking
        // for it.
        await auditActor.record({
          action:   "blamepost.mail.queue.message_removed",
          outcome:  "failure",
          actor:    auditActor.current(),
          reason:   removed.requestedBecause,
          resource: { kind: "queued_message", id: wanted },
          metadata: {
            recipient:  current ? (current.recipient || null) : null,
            from:       current ? (current.from || null) : null,
            attempt:    current && current.attempt !== undefined ? current.attempt : null,
            descriptor: current ? "present" : "missing",
            cause:      removed.outcome,
            stopped:    removed.outcome === "refused"
              ? "the data volume kept its " + removed.left.join(" and ")
              : "left the queue before it could be erased",
            reported:   removed.reported,
            withheld:   removed.withheld,
          },
        });
        if (removed.outcome === "refused") {
          // A claim is the file an attempt writes while it is holding an
          // entry, and it is not part of the message. One left behind by
          // itself means the message had already gone and the file
          // outlived it, so the sentence about a message still waiting
          // would name something that is not there.
          return report.error(wanted + " is still in the queue. This server could not take " +
            "its " + removed.left.join(" and ") + " off the data volume: " + removed.reason +
            ". Nothing was cancelled, nothing was destroyed, no row says otherwise, and the " +
            "running server will attempt the message again on its own schedule. Clear " +
            "whatever is holding the file open under " + config.paths.queue +
            " and run this again: the message is still there to cancel.");
        }
        return report.error(wanted + " left the queue while it was being removed, so nothing " +
          "was removed and no row says otherwise. " + pastCancelling);
      }
      // Recorded after the message is gone, the way the store records
      // its own removals, so a row never claims something that did not
      // happen. Its metadata comes from the reading beside the erasure
      // rather than from the listing further up, because that is the
      // entry this call actually erased.
      await auditActor.record({
        action:   "blamepost.mail.queue.message_removed",
        outcome:  "success",
        actor:    auditActor.current(),
        // The audit row has a first-class `reason` column. An auditor
        // filtering on it needs a column, not a string to search inside.
        // What goes in it is the sentence the removal accepted, so this
        // row and the console's row carry one value for one act.
        reason:   removed.requestedBecause,
        resource: { kind: "queued_message", id: wanted },
        metadata: {
          recipient: current ? (current.recipient || null) : null,
          from:      current ? (current.from || null) : null,
          attempt:   current && current.attempt !== undefined ? current.attempt : null,
          // Which of the two this was. A body with no descriptor names
          // nobody, so a row that recorded it the same way as a
          // cancellation would read as a message whose recipient this
          // server failed to record rather than as one it never had.
          descriptor: current ? "present" : "missing",
          // A file the cancellation could not tidy, which is not the
          // message and does not change what happened to it. Recorded so
          // an operator finding it later can tie it to the run that left
          // it rather than to a message that never went.
          left:       removed.left.length > 0 ? removed.left.join(" and ") : null,
          // Whether this server wrote to the sender, and when it did
          // not, why. Read off the removal rather than restated here: a
          // row that recorded this verb's intent would say the same
          // thing whatever the removal actually did, and it is the
          // removal that decides.
          reported:   removed.reported,
          withheld:   removed.withheld,
        },
      });
      // The message went. What may not have is the file an attempt
      // writes while it holds an entry, which nothing reads once the
      // entry is gone and nothing else will ever clear.
      var residue = removed.left.length === 0 ? [] : [
        "  The file an attempt writes while it holds this entry could not be removed: " +
          removed.reason,
        "  Nothing reads it and nothing here will clear it. Delete " + wanted +
          " under " + config.paths.queue + " by hand once the volume lets go.",
      ];
      if (current === null) {
        return _emit(report, flags, removed, [
          "Removed " + wanted + ", a message body with no descriptor.",
          "  Nothing listed it and nothing would have sent it. It was holding " +
            leftBehind.sizeBytes + " byte(s) of the queue's room, which is now free.",
        ].concat(residue));
      }
      return _emit(report, flags, removed, [
        "Abandoned " + wanted + (current.recipient ? " for " + current.recipient : "") + ".",
        "  The sender is not told, and the audit row records that. Send them a message " +
          "yourself if they need to know. Nothing else in the queue changed.",
      ].concat(residue));
    } finally {
      await store.close();
    }
  }
  return report.usage(USAGE_QUEUE);
}

// The receiver the last attempt reached, as a clause to hang on a queue
// row, or nothing at all when no host was reached.
//
// A schedule and a peer's words do not tell an operator what to do. The
// reason is the receiver's own sentence and rarely names anybody, and a
// domain that publishes several MX hosts turns one deferral into several
// different situations: one host refusing is that receiver, or this
// server's transport security against that receiver, while all of them
// refusing is the domain. Deciding between waiting, writing to the
// receiver, and looking at the local TLS posture starts with which host
// it was.
//
// Absent rather than null is the case where the deferral happened before
// any host was reached, an MX lookup that failed, and printing "via
// null" there would name a peer that was never contacted. Both read the
// same way here: say nothing, because there is nothing to say.
//
// The value came from DNS, so it is a string from outside this server.
// It arrives already screened, because everything the queue reader hands
// back has been through the framework's text guard, which is what lets
// this write it into a terminal without screening it a second time.
function _viaHost(entry) {
  var last = entry && entry.lastAttempt;
  var host = last && typeof last.mxHost === "string" ? last.mxHost : "";
  return host.length > 0 ? "  via " + host : "";
}

// ---- blobs ------------------------------------------------------------------

// A count and the noun it counts, so a report reads as a sentence rather
// than as a form with the plural left in brackets.
function _plural(n, one, many) {
  return n + " " + (n === 1 ? one : many);
}

// One clause per way the bodies and the rows disagree, in the order an
// operator has to act on them: a body that cannot be read is an outage
// for that message, and a body nothing references is disk.
//
// Shared by `blobs report` and by the check `doctor` runs, so the two
// cannot describe the same volume differently.
function _divergenceClauses(report) {
  var clauses = [];
  if (report.missing.length > 0) {
    clauses.push(_plural(report.missing.length, "message", "messages") +
      " whose body is not on disk");
  }
  if (report.corrupt.length > 0) {
    clauses.push(_plural(report.corrupt.length, "body that no longer matches its digest",
      "bodies that no longer match their digest"));
  }
  if (report.unowned.length > 0) {
    var stranded = report.unowned.reduce(function (n, entry) { return n + entry.messages; }, 0);
    clauses.push(_plural(stranded, "message", "messages") + " in " +
      _plural(report.unowned.length, "mailbox", "mailboxes") + " no account holds");
  }
  if (report.quotaDrift.length > 0) {
    clauses.push(_plural(report.quotaDrift.length, "mailbox whose quota disagrees",
      "mailboxes whose quotas disagree") + " with the messages in " +
      (report.quotaDrift.length === 1 ? "it" : "them"));
  }
  if (report.orphans.length > 0) {
    clauses.push(_plural(report.orphans.length, "unreferenced body", "unreferenced bodies") +
      " holding " + report.orphanBytes + " bytes");
  }
  if (report.unexpected.length > 0) {
    clauses.push(_plural(report.unexpected.length, "file", "files") +
      " under the body store that " + (report.unexpected.length === 1 ? "is" : "are") +
      " not a message body");
  }
  return clauses;
}

function _blobReportLines(report) {
  var lines = [
    _plural(report.blobsOnDisk, "sealed message body", "sealed message bodies") +
      " on disk, " + report.digestsReferenced + " referenced by a row, " +
      report.bytesOnDisk + " bytes",
    report.verified
      ? "  Every referenced body was unsealed and hashed back against its digest."
      : "  Bodies were counted, not opened. Add --verify to check each one against its digest.",
  ];

  var summary = lines.length;

  report.missing.forEach(function (entry) {
    lines.push("  FAIL  message " + entry.objectid + " (uid " + entry.uid + ") has no body " +
      "on disk. It is listed by every protocol and will fail to return.");
  });
  report.corrupt.forEach(function (entry) {
    lines.push("  FAIL  " + entry.digest.slice(0, 16) + "... " + entry.reason);
  });
  report.unowned.forEach(function (entry) {
    lines.push("  FAIL  " + (entry.mailbox || "a mailbox with no row") + ": " +
      entry.detail + ". " + _plural(entry.messages, "message", "messages") + ", " +
      entry.rowBytes + " bytes, " + _plural(entry.digests.length, "body", "bodies") +
      " held on disk.");
  });
  report.quotaDrift.forEach(function (entry) {
    lines.push("  FAIL  " + (entry.account || "an account with no row") + " " +
      (entry.mailbox || "") + ": the store counts " + entry.storeCount + " message(s) and " +
      entry.storeBytes + " bytes, the mailbox lists " + entry.rowCount + " and " +
      entry.rowBytes + "." + (entry.detail ? " " + entry.detail : ""));
  });
  report.orphans.forEach(function (entry) {
    lines.push("  note  " + entry.digest.slice(0, 16) + "... " + entry.sizeBytes +
      " bytes, referenced by nothing" +
      (entry.reclaimable
        ? ", reclaimable now"
        : ", reclaimable from " + new Date(entry.reclaimableAt).toUTCString()));
  });
  report.unexpected.forEach(function (entry) {
    lines.push("  note  " + entry.path + ": " + entry.detail + ". Nothing removes it.");
  });
  // Bodies the rows had not reached, which is what mail arriving after
  // the server's last write to disk looks like from a read-only open.
  // They are counted rather than listed one by one: on a busy server
  // this is every message of the last few minutes, and a screenful of
  // notes about ordinary deliveries buries the findings above it.
  if (report.newerThanRows.length > 0) {
    lines.push("  note  " + _plural(report.newerThanRows.length, "body", "bodies") + ", " +
      report.newerThanRowsBytes + " bytes, written after " +
      new Date(report.rowsAsOf).toISOString() + ", which is where these rows stop. That is " +
      "mail the server has taken and not yet written to disk, so it is not counted either " +
      "way.");
  }

  // One blank line before the summary, and a second one above the
  // per-entry block only when there is one, so a clean volume answers in
  // four lines rather than in four lines and two gaps.
  if (lines.length > summary) lines.splice(summary, 0, "");
  lines.push("");

  if (report.ok) {
    // Scoped to what was actually weighed. Where the rows stop short of
    // the directory, "every body on disk is referenced" is a claim about
    // bodies this run deliberately did not weigh, and the closing line is
    // the one most readers take away.
    lines.push(report.newerThanRows.length > 0
      ? "Every message body written before these rows stop is referenced, and every row has " +
        "its body. The " + _plural(report.newerThanRows.length, "body", "bodies") +
        " written since is not weighed either way."
      : "Every message body on disk is referenced, and every row has its body.");
    return lines;
  }
  lines.push("Diverged: " + _divergenceClauses(report).join(", ") + ".");
  if (report.missing.length > 0 || report.corrupt.length > 0) {
    lines.push("A message with no body cannot be repaired from here. Restore the volume " +
      "from a backup taken before it was lost, or destroy the message so clients stop " +
      "listing one they cannot open.");
  }
  if (report.unowned.length > 0) {
    lines.push("Mail no account holds is what an erasure leaves when it could not " +
      "finish: the account row goes and the mailbox rows, the message rows and the " +
      "sealed bodies stay. A message a preservation order or the retention floor is " +
      "keeping leaves exactly this, and `blamepost account remove --destroy` names each " +
      "one as it runs. So does a volume restored from a copy of the identity tables " +
      "without the mailbox tables. No protocol lists any of it, and reclaiming bodies " +
      "does not free it, because the message rows still name them and a body a row " +
      "names is a body in use.");
  }
  if (report.quotaDrift.length > 0) {
    lines.push("A mailbox whose quota exceeds the messages in it is charged for mail no " +
      "protocol can list. Reclaiming bodies does not change it: the count lives in the " +
      "message store, not on disk.");
  }
  // Counted rather than measured in bytes, because a body of zero bytes
  // is still a body somebody has to decide about and a byte total of
  // zero would say nothing is waiting.
  var reclaimable = report.orphans.filter(function (o) { return o.reclaimable; });
  if (reclaimable.length > 0) {
    lines.push("Run `blamepost blobs reclaim --confirm --reason <text>` to free " +
      _plural(reclaimable.length, "body", "bodies") + ", " +
      report.reclaimableBytes + " bytes.");
  }
  if (report.nextReclaimableAt !== null) {
    lines.push(_plural(report.orphans.length - reclaimable.length, "body", "bodies") + ", " +
      report.heldBackBytes + " bytes, held back until " +
      new Date(report.nextReclaimableAt).toUTCString() + ". Inside that window an " +
      "unreferenced body and one whose row is still being written are the same thing, " +
      "so they are kept.");
  }
  return lines;
}

async function cmdBlobs(flags, positionals) {
  var report = _reporter("blobs");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_BLOBS);
  var unread = _refuseUnread(report, "blobs", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);
  // `report` reads and `reclaim` deletes, so only the first may answer
  // while the server runs. The store refuses the second on a read-only
  // handle as well, because unlinking a body is not a database write and
  // nothing below the store could stop it.
  var store = await _openForReporting(config, "blobs", verb);

  try {
    if (verb === "report") {
      var reconciled = store.blobs.reconcile({ verify: flags.verify === true });
      _emit(report, flags, reconciled, _blobReportLines(reconciled));
      // Non-zero on any divergence, so a scheduled run is not silent
      // about a mailbox that has started failing to open its mail.
      return reconciled.ok ? 0 : 1;
    }

    if (verb === "reclaim") {
      // Deleting a message body is final and there is no archived copy,
      // so it takes the same two flags every other destructive verb here
      // does rather than running off a report an operator only meant to
      // read.
      var gate = _requireConfirmation(report, flags,
        "Reclaiming deletes sealed message bodies from the data volume. Run `blamepost " +
        "blobs report` first: it removes nothing and names every body it would.");
      if (gate !== 0) return gate;

      b.audit.registerNamespace(AUDIT_NAMESPACE);
      var result = await store.blobs.reclaim({ reason: flags.reason });
      var lines = [
        "Reclaimed " + _plural(result.reclaimed.length, "message body", "message bodies") +
          ", " + result.reclaimedBytes + " bytes.",
      ];
      if (result.heldBack.length > 0) {
        lines.push("  Held back " + result.heldBack.length + " (" + result.heldBackBytes +
          " bytes) written too recently to tell from mail that is arriving. They become " +
          "reclaimable from " + new Date(result.nextReclaimableAt).toUTCString() + ".");
      }
      if (result.skipped.length > 0) {
        lines.push("  Left " + result.skipped.length + " that a message row named while " +
          "this was running.");
      }
      // Octets this server was asked to free and could not. Named one per
      // line with what the volume said, because the next step is to find
      // out why the volume refused rather than to run this again blindly.
      result.failed.forEach(function (entry) {
        lines.push("  FAIL  " + entry.digest.slice(0, 16) + "... (" + entry.sizeBytes +
          " bytes): " + entry.detail);
      });
      _emit(report, flags, result, lines);
      // Non-zero on a refusal, so a scheduled reclaim that has stopped
      // freeing anything is noticed before the volume fills.
      return result.failed.length > 0 ? 1 : 0;
    }

    return report.usage(USAGE_BLOBS);
  } finally {
    await store.close();
  }
}

// ---- doctor -----------------------------------------------------------------

// A sentence, and whatever detail there turns out to be after it.
//
// The posture answers this command reads report a reason and a list of
// particulars, and the list is allowed to be empty: a condition can be
// entirely described by its reason, and today every one of them is.
// Concatenating a fixed lead-in onto that list prints the lead-in with
// nothing after it, which reads to an operator as a line the command
// failed to finish rather than as a line that had nothing more to say.
// So the lead-in travels with the list and appears only when the list
// does.
function _sentenceWith(reason, particulars, leadIn) {
  var text = String(reason || "").replace(/\.\s*$/, "");
  var list = Array.isArray(particulars)
    ? particulars.filter(function (p) { return String(p || "").length > 0; })
    : [];
  if (list.length === 0) return text + ".";
  return text + ". " + leadIn + list.join(" and ") + ".";
}

// Checks that need nothing but the local filesystem, the loaded
// configuration, the domain rows and the data volume itself. They run
// before the DNS work because a server whose certificate is missing has
// a problem no zone edit will fix.
function _localChecks(config, activeDomains, store) {
  var findings = [];
  findings.push({
    check:  "data directory",
    ok:     b.atomicFile.exists(config.dataDir),
    detail: b.atomicFile.exists(config.dataDir)
      ? config.dataDir
      : config.dataDir + " does not exist. Run `blamepost init` to create it.",
  });
  // The certificate, read rather than counted.
  //
  // A file that is present is not a certificate that works, and every
  // way it can fail to work is invisible until mail stops. It expired
  // last night; the key beside it is from the previous issuance; it is
  // the leaf without the issuer, so browsers accept it and sending mail
  // servers do not; it is issued to a name this server does not answer
  // to. In each case the two paths point at real files, and a check that
  // confirmed only that would report the server healthy right up to the
  // morning nothing arrives. So this opens them.
  var haveTls = !!(config.tlsCert && config.tlsKey &&
    b.atomicFile.exists(config.tlsCert) && b.atomicFile.exists(config.tlsKey));
  if (!haveTls) {
    findings.push({
      check:  "certificate",
      ok:     false,
      detail: "No certificate and key on disk. Every listener requires TLS, so the server " +
        "will refuse to start. Point BLAMEPOST_TLS_CERT and BLAMEPOST_TLS_KEY at a pair " +
        "issued for " + config.hostname + ".",
    });
  } else {
    var certificate = blamepost.certificateReport({
      certFile: config.tlsCert,
      keyFile:  config.tlsKey,
      hostname: config.hostname,
    });
    findings.push({
      check:  "certificate",
      ok:     true,
      detail: config.tlsCert +
        (certificate.subject === null ? "" : " (" + certificate.subject + ")"),
    });
    certificate.findings.forEach(function (f) { findings.push(f); });
  }
  var acknowledged = config.dnsAcknowledged === true;
  findings.push({
    check:  "dns acknowledgement",
    ok:     acknowledged,
    detail: acknowledged
      ? "acknowledged"
      : "BLAMEPOST_DNS_ACKNOWLEDGED is not set to 1, so the MX listener will refuse to " +
        "bind. Set it once the records below are live.",
  });
  // The server wide acknowledgement above says nothing about a domain
  // added after it was made, so the MX listener asks each domain
  // separately. A run that reported only the first would send an
  // operator to look at a setting that is already correct.
  var pending = (activeDomains || []).filter(function (d) {
    return d.dnsAcknowledged !== true;
  }).map(function (d) { return d.domain; });
  findings.push({
    check:  "per domain acknowledgement",
    ok:     pending.length === 0,
    detail: pending.length === 0
      ? "every active domain is acknowledged"
      : pending.join(", ") + " " + (pending.length === 1 ? "has" : "have") +
        " no acknowledged DNS posture, so the MX listener will refuse to bind. Record it " +
        "with `blamepost domain acknowledge <domain> --by <who>` once the records are live.",
  });
  // Whether a message can leave this server at all. An operator whose
  // queue is growing looks here first, and without this line the only
  // available reading is that every peer on the internet is refusing at
  // once.
  var wire = blamepost.mail.delivery.wireDeliveryStatus(b.mail);
  findings.push({
    check:  "outbound delivery",
    ok:     wire.available,
    detail: wire.available
      ? "messages can reach a peer"
      : _sentenceWith(wire.reason, wire.issues, "Also: "),
  });
  // How close the outbound queue is to refusing. It belongs beside the
  // line above because the two together are the whole story: while
  // messages cannot reach a peer the queue only grows, and the moment it
  // reaches its ceiling account holders start being told to try again.
  // An operator who finds that out from a user rather than from here
  // found out too late.
  //
  // A handle built for the question and not started, so nothing arms a
  // timer inside a one shot command.
  var outbound = blamepost.mail.delivery.create({
    hostname: config.hostname,
    dataDir:  config.dataDir,
    spool:    config.outboundSpool,
    maxMessageBytes: config.limits === null || config.limits === undefined
      ? undefined : config.limits.maxMessageBytes,
  });
  var room = outbound.queue.capacity();
  // Two thirds is the point at which a queue that is filling is worth
  // saying out loud. Below it the number is reported and the check
  // passes, because a queue with mail in it is a working queue.
  var crowded = room.messages * 3 >= room.maxMessages * 2 ||
    room.bytes * 3 >= room.maxBytes * 2;
  findings.push({
    check:  "outbound queue",
    ok:     !crowded,
    detail: "holding " + _plural(room.messages, "message", "messages") + " of " +
      room.maxMessages + " and " + room.bytes + " of " + room.maxBytes + " byte(s)" +
      (crowded
        ? ". At either ceiling new mail is refused with a temporary code and stays with " +
          "its sender. Read `blamepost queue held` for what is waiting and why, and clear " +
          "what is never going to leave with `blamepost queue remove <id> --reason ...`."
        : ""),
  });
  // The spooled message bodies on disk, held against the descriptors
  // that name them.
  //
  // A waiting recipient is two files written one after the other: the
  // message, then the descriptor that names it. Nothing spans the pair,
  // so a process that stops between the two writes leaves a message
  // body with no descriptor. Every listing this server offers
  // enumerates descriptors, so that body is in no listing and has no id
  // an operator could read, while the ceiling that decides whether the
  // queue can take more mail is measured off the volume and weighs it.
  // Enough of them and mail is refused with `blamepost queue list`
  // showing nothing, which is a stall with no visible cause.
  //
  // Both files are read off one listing rather than two, so a message
  // spooled between them cannot be weighed by one and reconciled by the
  // other. A body younger than the settle window is left out: the two
  // writes are consecutive, so a fresh one is a message arriving
  // normally rather than one that was stranded.
  var stranded = outbound.queue.orphans();
  findings.push({
    check:  "outbound spool",
    ok:     stranded.length === 0,
    detail: stranded.length === 0
      ? _plural(room.messages, "message", "messages") +
        " waiting, each one with the descriptor that names it"
      : _plural(stranded.length, "spooled message body", "spooled message bodies") +
        " that no descriptor names (" +
        stranded.slice(0, 5).map(function (entry) { return entry.id; }).join(", ") +
        (stranded.length > 5 ? ", and " + (stranded.length - 5) + " more" : "") +
        "), holding " +
        stranded.reduce(function (sum, entry) { return sum + entry.sizeBytes; }, 0) +
        " byte(s) of the queue's room. Nothing lists them and nothing sends them, and the " +
        "room they hold is room this server refuses new mail over. Clear each one with " +
        "`blamepost queue remove <id> --reason ...`.",
  });
  // The sealed DKIM private keys on disk, held against the selector rows
  // that name them. A selector row's keyRef is the only handle this
  // server has on the file it points at, so the two are read together
  // here or the answer comes from nowhere.
  //
  // Both directions matter and they are different problems. A key file
  // no row names is signing material for a domain with nothing left able
  // to reach it, and it rides into every backup bundle taken afterwards;
  // whoever holds it signs mail as that domain, and that stays true
  // after somebody else takes the name on. An ACTIVE selector whose key
  // is not there is the opposite failure and it is happening now: the
  // domain cannot sign, so its mail goes out unsigned and fails DMARC
  // wherever its policy sends failures. A retiring or retired selector
  // with no key is neither, and is left out of the count: retirement
  // destroys the private half and keeps the record published through the
  // overlap, which is the whole point of the overlap.
  //
  // Read while the server runs, the rows stop at its last write to disk
  // and the keys folder is live, so the two halves are two moments. The
  // bound is where the rows stop: a key file written at or after it is
  // one the rows had not reached, and counting it as a key nothing
  // claims would send an operator to destroy signing material their
  // server is using. Held apart instead, and named as what it is.
  //
  // The other direction needs no bound. An active selector whose key is
  // not on the volume is a domain whose mail leaves unsigned, and every
  // verb that mints or destroys a key needs to write the volume, so
  // while the server holds it neither half can move underneath this at
  // all. Were it ever stale it would be stale toward reporting a fault
  // that has just been repaired, which sends an operator to look rather
  // than to delete.
  var rowsStopAt = store.snapshot ? store.snapshot.takenAt : null;
  var claimed = {};
  var missingKeys = [];
  store.domains.listSelectors({}).forEach(function (selector) {
    claimed[selector.keyRef] = true;
    if (selector.status === "active") missingKeys.push(selector);
  });
  var keyDir = config.paths.keys;
  var keyFiles = b.atomicFile.exists(keyDir)
    ? b.atomicFile.listDir(keyDir, { includeStat: true })
      .filter(function (entry) { return entry.isFile; })
    : [];
  var onDisk = keyFiles.map(function (entry) { return entry.name; });
  var unclaimed = [];
  var newerThanRows = [];
  keyFiles.forEach(function (entry) {
    if (Object.prototype.hasOwnProperty.call(claimed, entry.name)) return;
    if (rowsStopAt !== null && entry.mtimeMs >= rowsStopAt) {
      newerThanRows.push(entry.name);
      return;
    }
    unclaimed.push(entry.name);
  });
  var unsigned = missingKeys.filter(function (selector) {
    return onDisk.indexOf(selector.keyRef) === -1;
  });
  var keyTrouble = [];
  if (unclaimed.length > 0) {
    keyTrouble.push(_plural(unclaimed.length, "sealed private key", "sealed private keys") +
      " no selector record names (" + unclaimed.slice(0, 5).join(", ") +
      (unclaimed.length > 5 ? ", and " + (unclaimed.length - 5) + " more" : "") +
      "). Nothing here will ever use or remove them, and every backup taken from now on " +
      "carries them. Delete them from " + keyDir + " by hand.");
  }
  if (unsigned.length > 0) {
    keyTrouble.push(_plural(unsigned.length, "active selector", "active selectors") +
      " whose sealed private key is not on this volume (" +
      unsigned.map(function (s) { return s.domain + " " + s.selector; }).join(", ") +
      "). Mail from those domains leaves unsigned. Restore the volume from a backup taken " +
      "before the key went, or replace the pair with `blamepost dkim retire` followed by " +
      "`blamepost dkim generate`.");
  }
  findings.push({
    check:  "signing keys",
    ok:     keyTrouble.length === 0,
    // Scoped to what was actually weighed, the way the blob check above
    // scopes its own clean line. `onDisk` counts every file in the keys
    // folder, `newerThanRows` is the part this run deliberately set aside
    // as too new to judge, and counting the second inside the first made
    // the clean sentence claim a selector record for keys the next
    // sentence says were not weighed at all. The closing line is the one
    // most readers take away, so it is the one that has to be true.
    detail: (keyTrouble.length === 0
      ? (newerThanRows.length > 0
        ? _plural(onDisk.length - newerThanRows.length,
          "sealed private key", "sealed private keys") +
          " written before these rows stop, each one named by a selector record"
        : _plural(onDisk.length, "sealed private key", "sealed private keys") +
          " on disk, each one named by a selector record")
      : keyTrouble.join(" ")) +
      (newerThanRows.length > 0
        ? " " + _plural(newerThanRows.length, "key", "keys") + " written after " +
          new Date(rowsStopAt).toISOString() + ", where these rows stop, was not weighed " +
          "either way."
        : ""),
  });
  // A message body is written to disk and then a row is written naming
  // it, and nothing spans the pair. Nothing else in this server looks at
  // both, so a body written without its row is storage nobody reclaims
  // and a row without its body is a message every protocol lists and
  // then fails to open. This walks the volume and counts; it opens no
  // bodies, which is what `blobs report --verify` is for.
  //
  // It is the one check here whose two halves can come from different
  // moments. Read while the server runs, the rows stop at the last write
  // to disk and the blob directory is live, so the reconciliation is
  // given where the rows stop and holds a body written after it apart
  // from a body nothing references. What is reported is then bounded by
  // what was read, which is a verdict rather than a refusal to reach one.
  var octets = store.blobs.reconcile();
  var notYetOnDisk = octets.newerThanRows.length > 0
    ? " " + _plural(octets.newerThanRows.length, "body", "bodies") + " written after " +
      new Date(octets.rowsAsOf).toISOString() + ", where these rows stop, was not weighed " +
      "either way: that is mail the server has taken and not yet written to disk."
    : "";
  findings.push({
    check:  "message bodies",
    ok:     octets.ok,
    detail: (octets.ok
      ? _plural(octets.blobsOnDisk, "sealed message body", "sealed message bodies") +
        " on disk, each one referenced by a row"
      : _divergenceClauses(octets).join(", ") +
        ". `blamepost blobs report --verify` names each one.") + notYetOnDisk,
  });
  return findings;
}

async function cmdDoctor(flags) {
  var report = _reporter("doctor");
  var config = _configFrom(flags);
  var store = await _openForReporting(config, "doctor", NO_VERB);
  try {
    var activeDomains = store.domains.list({ status: "active" });
    var findings = _localChecks(config, activeDomains, store);
    // Carried in the spelling the row holds, which is the derived one:
    // the identity layer folds a name once on the way into the column,
    // and it is the same derivation the scoping argument below goes
    // through. Folding again here would be a second rule over the same
    // value, and a hand fold settles the case and leaves the DNS root's
    // trailing dot, so the two agree on three spellings of every name
    // and disagree on the fourth with nothing to say which is which.
    var hosted = activeDomains.map(function (d) { return d.domain; });

    // Scoping to one domain filters the hosted set rather than resolving an
    // arbitrary name, so a domain this server does not host is refused instead
    // of checked. Checking a stranger's zone would answer a question the
    // operator did not ask, and a run that silently checked nothing would print
    // the same clean summary as a run that checked everything.
    if (flags.domain) {
      var scoped = _readDomainArg(report, flags.domain);
      if (scoped.code !== undefined) return scoped.code;
      var wanted = scoped.domain;
      if (hosted.indexOf(wanted) === -1) {
        // A domain that is hosted but switched off is a different answer
        // from one this server never heard of, and sending an operator
        // to `domain add` for a name they disabled themselves is the
        // wrong instruction.
        var disabled = !!store.domains.get(wanted);
        return report.error(disabled
          ? wanted + " is disabled, so this server refuses its mail and there is nothing " +
            "in its zone to check. Turn it back on with `blamepost domain enable " + wanted +
            " --reason <text>`."
          : "this server does not host " + wanted + ". Hosted domains: " +
            (hosted.length
              ? hosted.join(", ")
              : "none. Add one with `blamepost domain add <domain>`."), 2);
      }
      hosted = [wanted];
    }

    var dnsReport = { ok: true, unresolved: false, domains: [] };
    if (hosted.length === 0) {
      findings.push({
        check:  "hosted domains",
        ok:     false,
        detail: "This server hosts no domains, so there is nothing to check. Add one with " +
          "`blamepost domain add <domain>`.",
      });
    } else {
      var checker = blamepost.mail.posture.create({
        hostname: config.hostname,
        resolver: blamepost.resolver(),
        dkim:     blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store }),
      });
      dnsReport = await checker.check({ domains: hosted, dane: flags.dane === true });
    }

    var localOk = findings.every(function (f) { return f.ok; });
    var lines = ["blamepost " + blamepost.version + " as " + config.hostname, ""];
    findings.forEach(function (f) {
      // A check that passed but wants saying reads as a note, the same
      // way an advisory record does below. Marking one "ok" would claim
      // a verdict it did not reach, and marking it "FAIL" would send an
      // operator looking for a fault that is not there.
      var mark = f.severity === "advised" ? "  note  " : (f.ok ? "  ok    " : "  FAIL  ");
      lines.push(mark + f.check + ": " + f.detail);
    });
    // How many records were checked and disagreed, and how many were
    // never checked at all. They are counted apart because they send the
    // operator to different places: one is fixed by editing a zone, the
    // other by looking at the resolver this server reads. An operator who
    // has some of each needs to know how many of each, and a single
    // number that added them together would tell them to go and edit
    // records that may well be published and correct.
    var unchecked  = 0;
    var mismatched = 0;
    findings.forEach(function (f) { if (!f.ok) mismatched += 1; });

    dnsReport.domains.forEach(function (entry) {
      lines.push("");
      lines.push(entry.domain);
      entry.findings.forEach(function (f) {
        if (f.unresolved === true) unchecked += 1;
        else if (!f.ok && f.severity !== "advised") mismatched += 1;
        // A record nobody could read gets a mark of its own, because
        // neither of the other two is true of it. It did not pass, and
        // calling it a failure of any shade says this server looked and
        // did not like what it saw. It never saw anything.
        var mark = f.unresolved === true
          ? "  ?     "
          : (f.ok ? "  ok    " : (f.severity === "advised" ? "  note  " : "  FAIL  "));
        lines.push(mark + f.record + (f.name ? " at " + f.name : ""));
        if (!f.ok && f.detail) lines.push("        " + f.detail);
        if (!f.ok && f.expected) lines.push("        expected: " + JSON.stringify(f.expected));
        if (!f.ok && f.found) lines.push("        found:    " + JSON.stringify(f.found));
      });
    });

    var ok = localOk && dnsReport.ok;
    lines.push("");
    if (ok && unchecked === 0) {
      lines.push("Everything this server expects is in place.");
    } else if (mismatched === 0 && unchecked === 0) {
      lines.push("Some records do not match what this server expects. Each FAIL above names one.");
    } else {
      if (mismatched > 0) {
        lines.push(_plural(mismatched, "check does", "checks do") + " not match what this " +
          "server expects. Each FAIL above names one, and each is answered in the zone.");
      }
      if (unchecked > 0) {
        // Said even when the run passed. An advisory record nobody could
        // read leaves `ok` true, and a closing line that then said
        // everything is in place would be making the same claim this
        // mark exists to stop.
        lines.push(_plural(unchecked, "record could", "records could") + " not be checked, " +
          "because the lookup did not complete. Each ? above names one. Nothing is known " +
          "about them, so they may well be published and correct: this is a question about " +
          "the resolver this server reads rather than about the zone.");
      }
    }

    _emit(report, flags, { ok: ok, local: findings, dns: dnsReport }, lines);
    return ok ? 0 : 1;
  } finally {
    await store.close();
  }
}

// ---- bundles, shared by audit and backup ------------------------------------

// One place a path under a directory is derived. Every filesystem call
// below takes the result rather than assembling a path in its own
// argument list, so the shape of what may be addressed is decided once.
function _under(root, relative) {
  return relative === "" ? root : nodePath.join(root, relative);
}

// A scratch directory that belongs to this run alone. Bundles are read
// back and decrypted into one of these, never into the storage the
// operator gave and never into the data volume.
function _scratchDir(purpose) {
  return nodeFs.mkdtempSync(_under(nodeOs.tmpdir(), "blamepost-" + purpose + "-"));
}

function _dropScratch(dir) {
  // Drop-silent by design: a scratch directory that outlives the run is
  // untidy, and turning that into the error the operator reads would
  // hide the answer they asked for.
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); }
  catch (_e) { /* drop-silent by design */ }
}

// The passphrase a bundle is encrypted with, read from a file rather
// than a flag. A secret on a command line is in the shell history and in
// the process list, and a backup passphrase is the one secret that has
// to survive the loss of the machine, so it lives in a file an operator
// can put on separate media.
//
// Resolved before anything is opened or created, so a run that cannot
// produce a bundle refuses without having touched the data volume.
function _passphraseFrom(report, flags, config) {
  var given = flags["passphrase-file"];
  if (typeof given !== "string" || given.length === 0) {
    return { code: report.error("give --passphrase-file. A bundle is encrypted with a " +
      "passphrase this server never stores, so the file holding it is the only way back " +
      "into the bundle.", 2) };
  }
  var raw;
  try {
    raw = b.atomicFile.fdSafeReadSync(given, {
      maxBytes: PASSPHRASE_FILE_MAX_BYTES,
      encoding: "utf8",
    });
  } catch (err) {
    return { code: report.error("could not read the passphrase file " +
      JSON.stringify(given) + ": " + ((err && err.message) || String(err)), 2) };
  }
  // One trailing newline is what an editor or a shell redirection
  // leaves behind, and an operator who put the passphrase in a file has
  // not decided that the newline is part of it.
  var passphrase = String(raw).replace(/\r?\n$/, "");
  if (passphrase.length < MIN_BUNDLE_PASSPHRASE_CHARS) {
    return { code: report.error("the passphrase file holds " + passphrase.length +
      " character(s). A bundle carries everyone's mail and can be attacked offline for as " +
      "long as somebody cares to, so this takes at least " + MIN_BUNDLE_PASSPHRASE_CHARS +
      ".", 2) };
  }
  if (b.crypto.timingSafeEqual(Buffer.from(passphrase, "utf8"),
      Buffer.from(config.vaultPassphrase, "utf8"))) {
    return { code: report.error("the passphrase file holds the vault passphrase. A bundle " +
      "travels off this machine and the vault passphrase does not, so a bundle that leaks " +
      "would take the live volume with it. Put a different passphrase in the file.", 2) };
  }
  return { passphrase: passphrase };
}

// A directory flag that has to be there, answered as either the value or
// the exit code to hand back.
function _requiredPath(report, flags, name, what) {
  var given = flags[name];
  if (typeof given !== "string" || given.length === 0) {
    return { code: report.error("give --" + name + ". " + what, 2) };
  }
  return { path: given };
}

// A moment an operator wrote on the command line. ISO 8601 or
// milliseconds since the epoch; anything else is refused here rather
// than carried into a range that silently covers nothing.
function _momentFrom(report, raw, name) {
  // Ten digits is the shortest a millisecond timestamp has been since
  // 1970 and the longest a year can be, so the boundary is what tells
  // the two apart. Without it `--from 2026` reads as a moment in 1970
  // and the range silently covers nothing.
  if (/^[0-9]{10,}$/.test(String(raw))) {
    var epoch = Number(raw);
    if (isFinite(epoch) && epoch >= 0) return { ms: epoch };
  }
  var parsed = Date.parse(String(raw));
  if (isNaN(parsed)) {
    return { code: report.error("--" + name + " " + JSON.stringify(String(raw)) +
      " is not a moment this can read. Write it as ISO 8601, for example " +
      "2026-01-01T00:00:00Z, or as milliseconds since the epoch.", 2) };
  }
  return { ms: parsed };
}

function _requireConfirmation(report, flags, what) {
  if (flags.confirm !== true) {
    return report.error("give --confirm. " + what, 2);
  }
  if (typeof flags.reason !== "string" || flags.reason.length === 0) {
    return report.error("give --reason. " + what +
      " A row with no reason answers nothing later.", 2);
  }
  return 0;
}

// Every file on the data volume, as paths relative to it.
//
// The bundle primitive takes a flat list and refuses a directory, so the
// walk is here. It is deliberately inclusive: the sealed message bodies,
// the DKIM private keys, the outbound spool and the certificates all
// live in directories whose contents nobody can enumerate in advance,
// and the framework's own state files grow between releases. A file left
// out of a backup is data that does not come back, and the way that
// shows up is not an error. One of the framework's sealed key files is
// what makes an address lookup resolve, so a bundle missing it restores
// a database that opens, an audit chain that verifies, and a server that
// answers "no such mailbox" for every account it holds.
function _walkDataFiles(root, relative, into) {
  var entries = b.atomicFile.listDir(_under(root, relative), { includeStat: true });
  for (var i = 0; i < entries.length; i += 1) {
    var childRelative = relative === "" ? entries[i].name : relative + "/" + entries[i].name;
    if (entries[i].isDirectory) _walkDataFiles(root, childRelative, into);
    else if (entries[i].isFile) into.push(childRelative);
  }
  return into;
}

// The include list a bundle is built from: the framework's own list
// first, so the four files it insists on are marked required and their
// absence refuses the backup rather than producing one that cannot be
// restored, and then everything else the walk finds.
function _backupFiles(dataDir) {
  var files = b.backup.recommendedFiles({ atRest: "encrypted", vaultMode: "wrapped" });
  var listed = {};
  files.forEach(function (entry) { listed[entry.relativePath] = true; });
  _walkDataFiles(dataDir, "", []).forEach(function (relative) {
    if (listed[relative]) return;
    listed[relative] = true;
    files.push({ relativePath: relative, kind: "raw", required: false });
  });
  return files;
}

// The reader `b.auditChain.getChainTip` asks for: one row, or null.
function _readOneRow(sqlText, params) {
  var statement = b.db.prepare(sqlText);
  var row = statement.get.apply(statement, params || []);
  return row === undefined ? null : row;
}

// The framework refuses to open a database whose audit chain does not
// verify, which is the right posture for every other verb and the wrong
// one for the verb whose whole job is to report that. These are the
// codes it refuses with, and the two the store raises from the reading
// it makes outside the database afterwards.
//
// Those last two belong here for the same reason as the rest, and it is
// the reason most easily missed: they are the refusals that catch a
// trail rewritten in full with its checkpoints deleted rather than
// forged, which is the shape every other check passes. A code left off
// this list reaches the operator as a command that crashed rather than
// as a finding, with no verdict under `--json` for a monitor to read,
// and the one failure mode that most needs to arrive as evidence is the
// one that arrives as a stack trace.
var CHAIN_REFUSAL_CODES = {
  "db/audit-chain-break":      1,
  "db/audit-checkpoint-break": 1,
  "db/audit-rollback-detected": 1,
  "db/consent-chain-break":    1,
  "store/audit-anchor-mismatch":   1,
  "store/audit-anchor-row-missing": 1,
};

function _isChainRefusal(err) {
  return !!(err && typeof err.code === "string" &&
    Object.prototype.hasOwnProperty.call(CHAIN_REFUSAL_CODES, err.code));
}

// ---- audit ------------------------------------------------------------------

// The verdict as an operator reads it.
//
// The usual door for a break is the refusal above: the framework walks
// the chain before it hands back a database and will not open one that
// does not verify, so a broken chain is reported from there. This walk
// runs afterwards on a database that did open, and it is what produces
// the counts, which the refusal does not carry. Its failing branches
// stay because the two walks are separate reads of the same rows and
// only one of them is this verb's own.
function _chainLines(config, chain, checkpoints, counter, anchor) {
  var lines = ["Audit chain at " + config.hostname, ""];
  if (chain.ok) {
    lines.push("  ok    " + chain.rowsVerified + " row(s) verified, chain stands at counter " +
      counter);
  } else {
    lines.push("  FAIL  " + chain.reason + " at row " + chain.breakAt +
      ", row id " + chain.breakRowId);
    lines.push("        expected  " + chain.expected);
    lines.push("        found     " + chain.actual);
  }
  if (!checkpoints.ok) {
    lines.push("  FAIL  signed checkpoint " + checkpoints.breakAt + ": " + checkpoints.reason);
  } else if (checkpoints.checkpointsVerified === 0) {
    lines.push("  note  no signed checkpoint yet. The chain agrees with itself and nothing");
    lines.push("        signs it, so a wholesale rewrite would look exactly like this. The");
    lines.push("        first anchor is written the next time this volume is opened, which");
    lines.push("        is any blamepost command at all.");
  } else {
    lines.push("  ok    " + checkpoints.checkpointsVerified + " signed checkpoint(s) verified");
  }

  // The third reading, and the only one made from outside the database.
  // The chain and the checkpoints are both read out of the same file
  // somebody rewriting it controls; the record beside it is not, so it
  // is the one that says whether the rows are the rows this server
  // wrote. It has to be reported in its own right, because a reading
  // that could not be made and a reading that passed are the same exit
  // code and opposite facts.
  // Three readings rather than two, and the middle one is the reason.
  // A gap where the anchored row belongs is a range this run did not
  // read, held open by a counter in a table the framework signs nothing
  // in. Reporting it beside a reading that passed would put the sentence
  // an operator carries into an incident review over rows nobody looked
  // at, and reporting it as a break would refuse a volume that may have
  // been through an ordinary retention run. It is its own line because
  // it is its own fact.
  var witnessed = !!(anchor && anchor.checked === true);
  var unproven  = !!(anchor && anchor.proven === false);
  if (unproven) {
    lines.push("  note  a gap this run did not read, trusted on an unsigned counter. " +
      anchor.reason);
  } else if (witnessed) {
    lines.push("  ok    held against the volume's own record of its last anchoring, at " +
      "counter " + anchor.counter);
  } else {
    lines.push("  note  not held against anything outside the database. " +
      ((anchor && anchor.reason) || "the volume's record of its last anchoring was " +
        "not read."));
  }

  lines.push("");
  if (!chain.ok || !checkpoints.ok) {
    lines.push("This chain does not verify. Take a copy of the data volume before anything " +
      "else: the state at this moment is the evidence and a restart overwrites some of " +
      "it. Then find out which of the two it is, because they need opposite responses. " +
      "A single row failing its own hash with everything around it intact is what " +
      "storage damage looks like; a sequence that agrees with itself while a signature " +
      "or the record beside the volume disagrees is what a rewrite looks like.");
  } else if (unproven) {
    lines.push("Every row this run READ follows the one before it and every checkpoint " +
      "signature holds, and that is not the whole trail. The rows the note above names " +
      "are gone, and what stands in for them is an unsigned counter in the database " +
      "rather than an archive anything here verified. So this run cannot say what was in " +
      "that range and is not saying it: an erasure and a retention run leave the same " +
      "bytes on this volume, and the archive bundle is the only thing that tells them " +
      "apart. Find the bundle covering that range and read it back before treating this " +
      "trail as whole.");
  } else if (!witnessed) {
    lines.push("Every row follows the one before it and every checkpoint signature holds. " +
      "That is as far as this volume can answer: both readings come out of the database " +
      "itself, and the record that would say the rows are the ones this server wrote was " +
      "not available. Treat this as a chain that has not been proven rather than one " +
      "that has.");
  } else {
    lines.push("No row has been inserted, altered or removed by anyone who did not hold " +
      "this server's vault passphrase. That passphrase unseals the audit-signing key as " +
      "well as the database, so it is the boundary this proof stands on and not a " +
      "detail: against someone holding it, every reading above is a reading of something " +
      "they could have written. Keeping a copy of the trail somewhere this server cannot " +
      "reach is what answers the rest.");
  }
  return lines;
}

async function cmdAudit(flags, positionals) {
  var report = _reporter("audit");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_AUDIT);
  var unread = _refuseUnread(report, "audit", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);

  // Every verb that writes or reads a bundle needs the passphrase, and
  // needs it before a directory is created or a database is opened.
  var passphrase = null;
  if (verb === "archive" || verb === "export" || verb === "verify-bundle" || verb === "purge") {
    var read = _passphraseFrom(report, flags, config);
    if (read.code !== undefined) return read.code;
    passphrase = read.passphrase;
  }

  // The destructive verb's own confirmation, checked before a store is
  // opened rather than after, so a line missing it changes nothing at
  // all rather than changing nothing visible.
  if (verb === "purge") {
    var confirmedPurge = _requireConfirmation(report, flags,
      "Purging deletes audit rows, and the archive bundle is the only copy afterwards.");
    if (confirmedPurge !== 0) return confirmedPurge;
  }

  // Reading a bundle back has to work on a server whose database will
  // not open, because a chain that has just broken is one of the reasons
  // an operator reaches for the archive from before it.
  //
  // The two halves of a bundle need different things. The chain math is
  // self-contained and needs only the passphrase. The signature over an
  // archive's covering checkpoint was made with a key sealed on this
  // volume, so checking it needs the volume open. When the volume will
  // not open, the chain math is still checked and the report says the
  // signature was not, rather than reporting a clean bundle either way.
  if (verb === "verify-bundle") {
    var inDir = _requiredPath(report, flags, "in",
      "It names the bundle directory to read back.");
    if (inDir.code !== undefined) return inDir.code;
    var volume = null;
    var unopened = null;
    try {
      volume = await storeModule.open(config);
    } catch (err) {
      unopened = (err && err.message) || String(err);
    }
    var checked;
    try {
      checked = await b.auditTools.verifyBundle({
        in:                        inDir.path,
        passphrase:                passphrase,
        verifyCheckpointSignature: volume !== null,
      });
    } catch (err) {
      if (volume) await volume.close();
      return report.error(inDir.path + " could not be read back: " +
        ((err && err.message) || String(err)));
    }
    if (volume) await volume.close();

    var anchorLine;
    if (checked.kind !== "archive") {
      anchorLine = "  anchor:   none, which is what an exported range carries. The chain " +
        "math in it stands on its own.";
    } else if (volume !== null) {
      anchorLine = "  anchor:   a signed checkpoint covers the last row, and its signature " +
        "verified against this server's audit-signing key";
    } else {
      anchorLine = "  anchor:   a signed checkpoint covers the last row and its signature " +
        "was NOT checked, because the signing key is sealed on a volume that would not " +
        "open: " + unopened;
    }
    // The headline is scoped to what ran. A bundle whose covering
    // signature was not read has had its chain math checked and nothing
    // else, and chain math is the half a rewrite recomputes: a first
    // line saying it verifies is the only line most readers take away,
    // and the qualification three lines down does not reach them.
    var headline = checked.kind !== "archive" || volume !== null
      ? inDir.path + " verifies."
      : inDir.path + " verifies as far as this run could read it: the rows link, and the " +
        "signature over them was not checked.";
    _emit(report, flags,
      Object.assign({ signatureChecked: volume !== null }, checked),
      checked.ok
        ? [headline,
          "  kind:     " + checked.kind,
          "  rows:     " + checked.rowsVerified + " checked, counters " +
            checked.range.firstCounter + " to " + checked.range.lastCounter,
          anchorLine]
        : [inDir.path + " does not verify.",
          "  " + checked.reason]);
    return checked.ok ? 0 : 1;
  }

  if (verb === "verify-chain") {
    var opened;
    try {
      // The volume itself when it is free, and read-only when the server
      // is writing it. A read-only open verifies every checkpoint
      // signature it finds while anchoring none of its own, which is the
      // half of this verdict a rewritten chain cannot recompute and the
      // half a reader had no way to reach before. What it walks is the
      // chain up to the server's last write to disk, and the chain is
      // append-only, so that is a verified prefix rather than a partial
      // reading. The snapshot label above the answer says where it
      // stops.
      opened = await _openForReporting(config, "audit", "verify-chain");
    } catch (err) {
      if (!_isChainRefusal(err)) throw err;
      // The framework walks the chain before it hands back a database
      // and refuses to open one that does not verify. That refusal is
      // this verb's answer, so it is reported as a verdict rather than
      // as a command that crashed. It carries the row it stopped at and
      // the two hashes that disagree, which is what the walk below would
      // have reported had it been able to run.
      _emit(report, flags, {
        ok:          false,
        counter:     null,
        chain:       { ok: false, code: err.code, reason: err.message },
        checkpoints: null,
        anchor:      null,
      },
      ["Audit chain at " + config.hostname, "",
        "  FAIL  " + err.message, "",
          "This chain does not verify. Take a copy of the data volume before anything " +
          "else: the state at this moment is the evidence and a restart overwrites some " +
          "of it. Then find out which of the two it is, because they need opposite " +
          "responses. A single row failing its own hash with everything around it intact " +
          "is what storage damage looks like; a sequence that agrees with itself while a " +
          "signature or the record beside the volume disagrees is what a rewrite looks " +
          "like."]);
      return 1;
    }
    try {
      var chain = await b.audit.verify();
      var checkpoints = await b.audit.verifyCheckpoints();
      var tip = await b.auditChain.getChainTip(_readOneRow, AUDIT_TABLE);
      // The reading made from outside the database, taken from the open
      // rather than made here: it has to happen before the boot writes a
      // fresh record over the one being held against the rows, and by
      // the time this verb runs that write has already happened.
      var anchor = opened.auditAnchor || null;
      var ok = chain.ok === true && checkpoints.ok === true;
      _emit(report, flags,
        { ok: ok, counter: Number(tip.counter), chain: chain, checkpoints: checkpoints,
          anchor: anchor },
        _chainLines(config, chain, checkpoints, Number(tip.counter), anchor));
      return ok ? 0 : 1;
    } finally {
      await opened.close();
    }
  }

  var store = await storeModule.open(config);
  try {
    b.audit.registerNamespace(AUDIT_NAMESPACE);

    if (verb === "read") {
      // Newest first, and the order is load-bearing rather than
      // cosmetic. A capped read keeps the first rows in whatever order
      // it asked for, so reading ascending and cutting at the limit
      // hands back the oldest rows on the volume and drops everything
      // an operator opened the trail to look at.
      // The framework records the read below before it answers, and it
      // takes the actor for that row off the criteria it was handed.
      // An operator reading somebody else's trail is exactly the read
      // whose own row has to name them.
      var readCriteria = {
        limit: AUDIT_READ_DEFAULT_ROWS,
        order: "desc",
        actor: auditActor.current(),
      };
      if (flags.limit !== undefined) {
        if (typeof flags.limit !== "number" || !isFinite(flags.limit) ||
            flags.limit < 1 || flags.limit > AUDIT_READ_MAX_ROWS ||
            Math.floor(flags.limit) !== flags.limit) {
          return report.error("--limit takes a whole number of rows between 1 and " +
            AUDIT_READ_MAX_ROWS + ".", 2);
        }
        readCriteria.limit = flags.limit;
      }
      if (flags.from !== undefined) {
        var readFrom = _momentFrom(report, flags.from, "from");
        if (readFrom.code !== undefined) return readFrom.code;
        readCriteria.from = readFrom.ms;
      }
      if (flags.to !== undefined) {
        var readTo = _momentFrom(report, flags.to, "to");
        if (readTo.code !== undefined) return readTo.code;
        readCriteria.to = readTo.ms;
      }
      if (flags.action !== undefined) readCriteria.action = flags.action;
      if (flags.outcome !== undefined) {
        if (AUDIT_OUTCOMES.indexOf(flags.outcome) === -1) {
          return report.error("--outcome takes one of " + AUDIT_OUTCOMES.join(", ") +
            ". A verdict this cannot read would narrow the answer to nothing and look " +
            "like a quiet trail.", 2);
        }
        readCriteria.outcome = flags.outcome;
      }
      await b.audit.flush();
      // The framework records this read before it answers, so an
      // operator reading their own trail leaves a row saying so.
      var rows = await b.audit.query(readCriteria);
      return _emit(report, flags, rows, rows.length === 0
        ? ["No audit rows match."]
        : [rows.length + " row(s), newest first"].concat(rows.map(function (row) {
          return "  " + new Date(Number(row.recordedAt)).toISOString() +
            "  " + row.action + "  " + row.outcome +
            (row.actorUserId ? "  by " + row.actorUserId : "") +
            (row.resourceKind ? "  on " + row.resourceKind +
              (row.resourceId ? " " + row.resourceId : "") : "") +
            (row.reason ? "  reason: " + row.reason : "");
        })));
    }

    if (verb === "export") {
      var exportOut = _requiredPath(report, flags, "out",
        "It names a directory to write the bundle into, which must not already exist.");
      if (exportOut.code !== undefined) return exportOut.code;
      var criteria = { out: exportOut.path, passphrase: passphrase };
      if (flags.from !== undefined) {
        var fromAt = _momentFrom(report, flags.from, "from");
        if (fromAt.code !== undefined) return fromAt.code;
        criteria.from = fromAt.ms;
      }
      if (flags.to !== undefined) {
        var toAt = _momentFrom(report, flags.to, "to");
        if (toAt.code !== undefined) return toAt.code;
        criteria.to = toAt.ms;
      }
      if (flags.action !== undefined) criteria.action = flags.action;
      await b.audit.flush();
      var exported;
      try {
        exported = await b.auditTools.exportSlice(criteria);
      } catch (err) {
        return report.error("the slice could not be exported: " +
          ((err && err.message) || String(err)));
      }
      return _emit(report, flags, exported, [
        "Wrote an auditor's bundle to " + exported.outDir,
        "  " + exported.rowCount + " row(s), counters " + exported.range.firstCounter +
          " to " + exported.range.lastCounter,
        "  The live rows are untouched.",
        "  Check it before you hand it over: `blamepost audit verify-bundle --in " +
          exported.outDir + " --passphrase-file <path>`",
      ]);
    }

    if (verb === "archive") {
      var archiveOut = _requiredPath(report, flags, "out",
        "It names a directory to write the bundle into, which must not already exist.");
      if (archiveOut.code !== undefined) return archiveOut.code;
      if (flags.before === undefined) {
        return report.error("give --before. It is the cut this archives up to, and a cut " +
          "nobody named is the whole chain.", 2);
      }
      var beforeAt = _momentFrom(report, flags.before, "before");
      if (beforeAt.code !== undefined) return beforeAt.code;

      // The bundle's only unforgeable anchor is a signed checkpoint
      // covering its last row, so one is taken first rather than the
      // archive refusing for the want of it.
      await b.audit.flush();
      await b.audit.checkpoint({ skipIfUnchanged: true });
      await b.audit.flush();
      var tipBefore = await b.auditChain.getChainTip(_readOneRow, AUDIT_TABLE);

      var archived;
      try {
        archived = await b.auditTools.archive({
          out:        archiveOut.path,
          before:     beforeAt.ms,
          passphrase: passphrase,
        });
      } catch (err) {
        return report.error("nothing was archived: " + ((err && err.message) || String(err)));
      }
      var coversEverything = Number(archived.range.lastCounter) >= Number(tipBefore.counter);
      var archiveLines = [
        "Wrote an archive bundle to " + archived.outDir,
        "  " + archived.rowCount + " row(s), counters " + archived.range.firstCounter +
          " to " + archived.range.lastCounter,
        "  The live rows are untouched. Verify the bundle, then `blamepost audit purge`.",
      ];
      if (coversEverything) {
        archiveLines.push("");
        archiveLines.push("  This bundle holds every row the chain still has, so a purge of it");
        archiveLines.push("  will be refused: the next event needs a row to attach to. Archive an");
        archiveLines.push("  earlier cut if the point was to shorten the table.");
      }
      return _emit(report, flags,
        Object.assign({ purgeable: !coversEverything }, archived), archiveLines);
    }

    if (verb === "purge") {
      var archiveIn = _requiredPath(report, flags, "archive",
        "It names the verified archive bundle whose rows are being deleted.");
      if (archiveIn.code !== undefined) return archiveIn.code;

      var verified;
      try {
        verified = await b.auditTools.verifyBundle({ in: archiveIn.path, passphrase: passphrase });
      } catch (err) {
        return report.error("the archive could not be read back, so nothing was deleted: " +
          ((err && err.message) || String(err)));
      }
      if (!verified.ok) {
        return report.error("the archive does not verify, so nothing was deleted: " +
          verified.reason);
      }

      // The refusal that keeps this server able to start again. Every
      // append takes the hash of the row before it, and the boot-time
      // rollback check compares the recorded counter against the highest
      // one in the table. A purge that takes the last row leaves the next
      // event nothing to attach to and leaves that check with a counter
      // the table cannot match, and the server never starts again.
      await b.audit.flush();
      var tipNow = await b.auditChain.getChainTip(_readOneRow, AUDIT_TABLE);
      if (Number(tipNow.counter) <= Number(verified.range.lastCounter)) {
        return report.error("this archive holds every row the chain still has, up to counter " +
          verified.range.lastCounter + ", and the chain stands at " + tipNow.counter +
          ". A purge has to leave a row behind: the next event attaches to it, and the check " +
          "this server runs at boot compares against it. Archive an earlier cut and purge that.");
      }

      var purged;
      try {
        purged = await b.auditTools.purge({
          confirm:    true,
          archive:    archiveIn.path,
          passphrase: passphrase,
        });
      } catch (err) {
        return report.error("nothing was deleted: " + ((err && err.message) || String(err)));
      }
      await auditActor.record({
        action:   "blamepost.audit.purged",
        outcome:  "success",
        actor:    auditActor.current(),
        // The audit row has a first-class `reason` column, so the reason
        // goes there rather than into the metadata blob. An auditor
        // filtering on it needs a column, not a string to search inside.
        reason:   flags.reason,
        resource: { kind: "audit_chain", id: AUDIT_TABLE },
        metadata: {
          rowsDeleted:       purged.rowsDeleted,
          lastPurgedCounter: purged.lastPurgedCounter,
          archive:           archiveIn.path,
        },
      });
      await b.audit.flush();
      return _emit(report, flags, purged, [
        "Purged " + purged.rowsDeleted + " audit row(s), up to counter " +
          purged.lastPurgedCounter + ".",
        "  The archive bundle is the only copy of them now. Keep it, and keep the " +
          "passphrase file somewhere else.",
      ]);
    }

    return report.usage(USAGE_AUDIT);
  } finally {
    await store.close();
  }
}

// ---- backup -----------------------------------------------------------------

function _storageFrom(report, flags) {
  var given = _requiredPath(report, flags, "storage",
    "It names the directory bundles are written to and read from.");
  if (given.code !== undefined) return given;
  return { root: given.path, storage: b.backup.diskStorage({ root: given.path }) };
}

function _bundleFrom(report, flags) {
  return _requiredPath(report, flags, "bundle",
    "It names which bundle, by the id `blamepost backup list` prints.");
}

// Pull a bundle out of storage into a scratch directory and read its
// manifest, without a passphrase and without opening the database. This
// is the read an operator does while deciding what to restore, and it
// has to work when the live volume does not.
async function _withPulledBundle(storage, bundleId, use) {
  var scratch = _scratchDir("bundle");
  try {
    var bundleDir = _under(scratch, "bundle");
    await storage.readBundle(bundleId, bundleDir);
    return await use(bundleDir, scratch);
  } finally {
    _dropScratch(scratch);
  }
}

async function cmdBackup(flags, positionals) {
  var report = _reporter("backup");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_BACKUP);
  var unread = _refuseUnread(report, "backup", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);

  var passphrase = null;
  if (verb === "run" || verb === "verify" || verb === "purge") {
    var read = _passphraseFrom(report, flags, config);
    if (read.code !== undefined) return read.code;
    passphrase = read.passphrase;
  }

  var keep = null;
  if (verb === "run" || verb === "purge") {
    if (flags.keep !== undefined) {
      if (typeof flags.keep !== "number" || !isFinite(flags.keep) ||
          flags.keep < 1 || Math.floor(flags.keep) !== flags.keep) {
        return report.error("--keep takes a whole number of bundles to keep, one or more. " +
          "Zero would delete the bundle this run just wrote.", 2);
      }
      keep = flags.keep;
    } else if (verb === "purge") {
      return report.error("give --keep. It is how many bundles survive, newest first.", 2);
    }
  }

  // Checked before a store is opened or a storage directory is touched,
  // so a line missing it changes nothing at all.
  if (verb === "purge") {
    var confirmedPurge = _requireConfirmation(report, flags,
      "Purging deletes backup bundles, and there is no undo.");
    if (confirmedPurge !== 0) return confirmedPurge;
  }

  var chosen = _storageFrom(report, flags);
  if (chosen.code !== undefined) return chosen.code;

  if (verb === "list") {
    var bundles = await chosen.storage.listBundles();
    return _emit(report, flags, bundles, bundles.length === 0
      ? ["No bundles in " + chosen.root + "."]
      : [bundles.length + " bundle(s) in " + chosen.root + ", newest first"]
        .concat(bundles.map(function (entry) {
          return "  " + entry.bundleId + "  " + entry.size + " bytes  " + entry.createdAt;
        })));
  }

  if (verb === "inspect") {
    var wanted = _bundleFrom(report, flags);
    if (wanted.code !== undefined) return wanted.code;
    if (!(await chosen.storage.hasBundle(wanted.path))) {
      return report.error("no bundle " + JSON.stringify(wanted.path) + " in " + chosen.root +
        ". `blamepost backup list --storage " + chosen.root + "` prints the ids.", 2);
    }
    var described = await _withPulledBundle(chosen.storage, wanted.path,
      async function (bundleDir) {
        var manifest = b.restoreBundle.inspect({ bundleDir: bundleDir });
        var signature = b.backup.verifyManifestSignature(bundleDir, {
          expectedFingerprint: flags.fingerprint || undefined,
        });
        var total = 0;
        manifest.files.forEach(function (entry) { total += entry.encryptedSize || 0; });
        return {
          bundleId:      wanted.path,
          createdAt:     manifest.createdAt || null,
          fileCount:     manifest.files.length,
          encryptedSize: total,
          dataDir:       (manifest.metadata && manifest.metadata.dataDir) || null,
          hostname:      (manifest.metadata && manifest.metadata.hostname) || null,
          signature:     signature,
        };
      });
    _emit(report, flags, described, [
      described.bundleId,
      "  created:        " + described.createdAt,
      "  files:          " + described.fileCount,
      "  encrypted size: " + described.encryptedSize + " bytes",
      "  data directory: " + (described.dataDir ||
        "not recorded, so this bundle predates the check that a restore target matches"),
      "  server:         " + (described.hostname || "not recorded"),
      "  signature:      " + (described.signature.ok
        ? "verified, key " + described.signature.fingerprint
        : "NOT verified: " + described.signature.reason),
    ]);
    return described.signature.ok ? 0 : 1;
  }

  if (verb === "verify") {
    var target = _bundleFrom(report, flags);
    if (target.code !== undefined) return target.code;
    if (!(await chosen.storage.hasBundle(target.path))) {
      return report.error("no bundle " + JSON.stringify(target.path) + " in " + chosen.root +
        ". `blamepost backup list --storage " + chosen.root + "` prints the ids.", 2);
    }
    var outcome;
    try {
      outcome = await _withPulledBundle(chosen.storage, target.path,
        async function (bundleDir, scratch) {
          var extracted = await b.restoreBundle.extract({
            bundleDir:           bundleDir,
            stagingDir:          _under(scratch, "staging"),
            passphrase:          passphrase,
            requireSignature:    true,
            expectedFingerprint: flags.fingerprint || undefined,
          });
          var signature = b.backup.verifyManifestSignature(bundleDir, {
            expectedFingerprint: flags.fingerprint || undefined,
          });
          return {
            bundleId:   target.path,
            fileCount:  extracted.fileCount,
            totalBytes: extracted.totalBytes,
            signature:  signature,
          };
        });
    } catch (err) {
      return report.error(target.path + " does not open: " +
        ((err && err.message) || String(err)));
    }
    return _emit(report, flags, { ok: true, verify: outcome }, [
      outcome.bundleId + " verifies.",
      "  " + outcome.fileCount + " file(s) decrypted and checksummed, " +
        outcome.totalBytes + " bytes",
      "  signature: " + (outcome.signature.ok
        ? "verified, key " + outcome.signature.fingerprint
        : outcome.signature.reason),
      "  Nothing under " + config.paths.dataDir + " was read or written.",
    ]);
  }

  // run and purge both touch the audit trail, so both open the store.
  var store = await storeModule.open(config);
  try {
    b.audit.registerNamespace(AUDIT_NAMESPACE);

    if (verb === "run") {
      // A bundle carries the audit chain, so the chain is anchored
      // first. The bundle then holds a signature over its own last row,
      // and a restored copy can be checked against it.
      await b.audit.flush();
      await b.audit.checkpoint({ skipIfUnchanged: true });
      await b.audit.flush();

      var engine = b.backup.create({
        dataDir:      config.paths.dataDir,
        storage:      chosen.storage,
        passphrase:   passphrase,
        files:        _backupFiles(config.paths.dataDir),
        vaultKeyJson: function () { return b.vault.getKeysJson(); },
        retention:    keep === null ? null : { keep: keep },
        // A flush that fails means the snapshot would be older than the
        // database it claims to be, which is exactly the bundle nobody
        // finds out about until they restore it.
        requireFlush: true,
      });
      var summary = await engine.run({
        metadata: {
          // The database key is sealed to the absolute path of the
          // directory it belongs to, so a restore into a different one
          // produces a volume that will not open. Recording the path
          // here is what lets a restore refuse before it moves anything.
          dataDir:  config.paths.dataDir,
          hostname: config.hostname,
          version:  blamepost.version,
        },
      });

      // Read the bundle back out of storage and check the signature on
      // the manifest, so a bundle that cannot be authenticated never
      // reports success.
      var signed = await _withPulledBundle(chosen.storage, summary.bundleId,
        function (bundleDir) {
          return b.backup.verifyManifestSignature(bundleDir);
        });
      await auditActor.record({
        action:   "blamepost.backup.written",
        outcome:  signed.ok ? "success" : "failure",
        actor:    auditActor.current(),
        resource: { kind: "backup_bundle", id: summary.bundleId },
        metadata: {
          storage:   chosen.root,
          fileCount: summary.fileCount,
          bytes:     summary.bundleSize,
          signed:    signed.ok === true,
        },
      });
      await b.audit.flush();

      _emit(report, flags, Object.assign({ signature: signed }, summary), [
        "Wrote bundle " + summary.bundleId + " to " + chosen.root,
        "  " + summary.fileCount + " file(s), " + summary.bundleSize + " bytes, in " +
          summary.durationMs + "ms",
        "  signature: " + (signed.ok
          ? "verified, key " + signed.fingerprint
          : "NOT verified: " + signed.reason),
        "  Restoring it needs this passphrase file and the vault passphrase. Neither is " +
          "in the bundle.",
        "  A bundle nobody has restored is a hypothesis: `blamepost backup verify` reads " +
          "every file back.",
      ]);
      return signed.ok ? 0 : 1;
    }

    if (verb === "purge") {
      var purgeEngine = b.backup.create({
        dataDir:      config.paths.dataDir,
        storage:      chosen.storage,
        passphrase:   passphrase,
        files:        _backupFiles(config.paths.dataDir),
        vaultKeyJson: function () { return b.vault.getKeysJson(); },
      });
      var swept = await purgeEngine.purgeOlder({ keep: keep });
      await auditActor.record({
        action:   "blamepost.backup.purged",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "backup_storage", id: chosen.root },
        metadata: { kept: swept.kept, deleted: swept.deleted },
      });
      await b.audit.flush();
      return _emit(report, flags, swept, [
        "Kept the newest " + swept.kept + " bundle(s) in " + chosen.root + ".",
      ].concat(swept.deleted.length === 0
        ? ["  Nothing was old enough to delete."]
        : ["  Deleted " + swept.deleted.length + ":"].concat(
          swept.deleted.map(function (id) { return "    " + id; }))));
    }

    return report.usage(USAGE_BACKUP);
  } finally {
    await store.close();
  }
}

// ---- restore ----------------------------------------------------------------

// Open the volume that has just been put in place and ask it the
// questions a restore is for. The framework refuses to open a database
// whose audit chain does not verify, so reaching this at all is part of
// the answer, and what it reports is the rest.
//
// Three readings rather than the two named below, and the third is the
// one that arrives as a refused open rather than as a field. The store
// holds the record beside the volume against the rows before it hands
// back a handle, so a bundle carrying a rewritten trail lands in the
// catch and is reported as a restore that did not stand. The two counts
// below are the ones that need the handle to answer.
//
// `record` is called once, while the volume is open, with what the count
// found. It belongs to the caller rather than here because putting a
// bundle in place and putting the previous directory back are different
// acts: an auditor filtering on one must not find the other, and the
// name of each is written where the act is, in full, rather than passed
// in as a value nobody reading this file could resolve.
//
// What it answers with separates the two questions a caller has. `ok` is
// whether the volume that is now in place opened and verified, which is
// what decides whether the restore stands. `recorded` is whether the row
// describing that got written, which decides nothing and is worth saying
// out loud. Holding them apart is the point: while the recording could
// fail into the same field as the opening, a sink that was down read as
// a volume that would not open, and the caller below undid a restore
// that had worked.
async function _openRestoredVolume(config, record) {
  var handle;
  try {
    handle = await storeModule.open(config);
  } catch (err) {
    return { ok: false, reason: (err && err.message) || String(err) };
  }
  try {
    b.audit.registerNamespace(AUDIT_NAMESPACE);
    var chain = await b.audit.verify();
    var checkpoints = await b.audit.verifyCheckpoints();
    var accounts = handle.accounts.list().length;
    var domains = handle.domains.list().length;
    if (!chain.ok) {
      return { ok: false, reason: "the restored audit chain does not verify: " + chain.reason,
        chain: chain };
    }
    if (!checkpoints.ok) {
      return { ok: false,
        reason: "a signed checkpoint on the restored volume does not verify: " +
          checkpoints.reason,
        chain: chain, checkpoints: checkpoints };
    }
    var recorded = await record({ accounts: accounts, domains: domains });
    // The flush is wrapped for the same reason `record` is, and it was
    // the one call below that guard: a sink that will not take the write
    // raises here, the catch below reads it as a volume that would not
    // open, and the caller undoes a restore that worked. Everything this
    // verdict is built on has already been read, so a trail that cannot
    // be written is reported beside the verdict rather than becoming it.
    var flushed = true;
    var flushReason = null;
    try { await b.audit.flush(); }
    catch (flushErr) {
      flushed = false;
      flushReason = (flushErr && flushErr.message) || String(flushErr);
    }
    return {
      ok: true, chain: chain, checkpoints: checkpoints,
      accounts: accounts, domains: domains, recorded: recorded === true,
      flushed: flushed, flushReason: flushReason,
    };
  } catch (err) {
    return { ok: false, reason: (err && err.message) || String(err) };
  } finally {
    if (handle) await handle.close();
  }
}

async function cmdRestore(flags, positionals) {
  var report = _reporter("restore");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_RESTORE);
  var unread = _refuseUnread(report, "restore", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);

  if (verb === "list-rollbacks") {
    var points = b.restoreRollback.list({ dataDir: config.paths.dataDir });
    return _emit(report, flags, points, points.length === 0
      ? ["No rollback points. One is kept every time `blamepost restore apply` runs."]
      : [points.length + " rollback point(s), newest first"].concat(
        points.map(function (point) {
          var operator = (point.marker && point.marker.operator) || {};
          return "  " + point.rollbackPath + "\n" +
            "    swapped " + point.swappedAt +
            (operator.bundleId ? "\n    bundle  " + operator.bundleId : "") +
            (operator.reason ? "\n    reason  " + operator.reason : "");
        })));
  }

  if (verb === "rollback") {
    var confirmedRollback = _requireConfirmation(report, flags,
      "Rolling back replaces the live data volume with the directory kept before a restore, " +
      "and discards what is there now.");
    if (confirmedRollback !== 0) return confirmedRollback;
    var chosenPoint = flags.point;
    if (chosenPoint !== undefined && !b.atomicFile.exists(chosenPoint)) {
      return report.error("no rollback point at " + JSON.stringify(chosenPoint) +
        ". `blamepost restore list-rollbacks` prints the ones this volume has.", 2);
    }
    if (chosenPoint === undefined) {
      var held = b.restoreRollback.list({ dataDir: config.paths.dataDir });
      if (held.length === 0) {
        return report.error("this volume holds no rollback point, so there is nothing to " +
          "put back. One is kept every time `blamepost restore apply` runs.", 2);
      }
      chosenPoint = held[0].rollbackPath;
    }
    var rolledBack;
    try {
      rolledBack = await b.restoreRollback.rollback({
        dataDir:      config.paths.dataDir,
        rollbackPath: chosenPoint,
      });
    } catch (err) {
      return report.error("nothing was rolled back: " + ((err && err.message) || String(err)));
    }
    var back = await _openRestoredVolume(config, function (found) {
      return auditActor.record({
        action:   "blamepost.restore.rolled_back",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "data_volume", id: config.paths.dataDir },
        metadata: {
          restoredFrom: rolledBack.restoredFrom,
          discarded:    rolledBack.discardedAt,
          accounts:     found.accounts,
          domains:      found.domains,
        },
      });
    });
    // The rollback stands either way, and an operator standing at a
    // terminal is the one caller who can be told that the volume they
    // just put back holds no record of the putting back.
    if (back.ok && back.recorded === false) {
      report.writeErr("blamepost restore rollback: the volume was rolled back and the row " +
        "recording it could not be written, so this volume's audit trail has no entry for " +
        "it. Note what was put back and when somewhere else, and check where audit rows " +
        "are being written.");
    }
    // Written and not settled onto the volume is the same absence with a
    // different cause, so it is said rather than swallowed by a row that
    // was accepted into a buffer nobody drained.
    if (back.ok && back.flushed === false) {
      report.writeErr("blamepost restore rollback: the row recording it was written and " +
        "could not be settled onto the volume (" + back.flushReason + "), so the trail may " +
        "carry no entry for this rollback. The rollback itself stands.");
    }
    _emit(report, flags, Object.assign({ verified: back.ok }, rolledBack), [
      "Rolled back to " + rolledBack.restoredFrom,
      "  The directory that was live is kept at " + rolledBack.discardedAt,
      back.ok
        ? "  It opened and its audit chain verified."
        : "  It did NOT open: " + back.reason,
    ]);
    return back.ok ? 0 : 1;
  }

  if (verb === "apply") {
    var read = _passphraseFrom(report, flags, config);
    if (read.code !== undefined) return read.code;
    var chosen = _storageFrom(report, flags);
    if (chosen.code !== undefined) return chosen.code;
    var wanted = _bundleFrom(report, flags);
    if (wanted.code !== undefined) return wanted.code;
    var confirmedApply = _requireConfirmation(report, flags,
      "A restore replaces every file on the live data volume.");
    if (confirmedApply !== 0) return confirmedApply;

    if (!(await chosen.storage.hasBundle(wanted.path))) {
      return report.error("no bundle " + JSON.stringify(wanted.path) + " in " + chosen.root +
        ". `blamepost backup list --storage " + chosen.root + "` prints the ids.", 2);
    }

    // The database key is sealed to the absolute path of the directory
    // it belongs to, so a bundle taken from one directory produces a
    // volume that will not open anywhere else. Reading the manifest is
    // cheap and needs no passphrase, so the mismatch is refused here
    // rather than found after the live directory has been moved aside.
    var origin = await _withPulledBundle(chosen.storage, wanted.path, function (bundleDir) {
      var manifest = b.restoreBundle.inspect({ bundleDir: bundleDir });
      return (manifest.metadata && manifest.metadata.dataDir) || null;
    });
    if (origin !== null && origin !== config.paths.dataDir) {
      return report.error("this bundle was taken from " + origin + " and this server's data " +
        "directory is " + config.paths.dataDir + ". The database key is sealed to the path " +
        "of the directory it belongs to, so a restore into a different one produces a volume " +
        "that will not open. Point BLAMEPOST_DATA_DIR at " + origin +
        " and run it again.", 2);
    }

    var restoreHandle = b.restore.create({
      dataDir:             config.paths.dataDir,
      storage:             chosen.storage,
      passphrase:          read.passphrase,
      requireSignature:    true,
      expectedFingerprint: flags.fingerprint || undefined,
      // The database is not open at this point, so an audit event would
      // be written nowhere. The restore records itself in the volume it
      // just put in place, which is the one that can hold the row.
      audit:               false,
    });
    var applied;
    try {
      applied = await restoreHandle.run({
        bundleId: wanted.path,
        marker:   { reason: flags.reason },
      });
    } catch (err) {
      return report.error("nothing was restored: " + ((err && err.message) || String(err)));
    }

    var verdict = await _openRestoredVolume(config, function (found) {
      return auditActor.record({
        action:   "blamepost.restore.applied",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "data_volume", id: config.paths.dataDir },
        metadata: {
          bundleId:     wanted.path,
          storage:      chosen.root,
          rollbackPath: applied.rollbackPath,
          accounts:     found.accounts,
          domains:      found.domains,
        },
      });
    });
    if (!verdict.ok) {
      // A restore that lands and does not open is the failure this verb
      // exists to survive. The directory that was here before was kept,
      // so it goes back.
      var undone = null;
      if (applied.rollbackPath) {
        try {
          undone = await b.restoreRollback.rollback({
            dataDir:      config.paths.dataDir,
            rollbackPath: applied.rollbackPath,
          });
        } catch (err) {
          undone = { failed: (err && err.message) || String(err) };
        }
      }
      report.writeErr("blamepost restore apply: the restored data directory did not open: " +
        verdict.reason);
      _emit(report, flags,
        { ok: false, bundleId: wanted.path, reason: verdict.reason,
          rolledBackTo: undone && undone.restoredFrom ? undone.restoredFrom : null },
        [undone && undone.restoredFrom
          ? "Rolled back to " + undone.restoredFrom + ", which is what was here before."
          : undone && undone.failed
            ? "The rollback failed too: " + undone.failed +
              ". The bundle is still in storage and the rollback point is still on disk."
            : "There was nothing to roll back to, because the data directory was empty " +
              "before this ran. The bundle is still in storage."]);
      return 1;
    }

    // The restore stands. What did not happen is the row describing it,
    // and the volume it would have gone into is the one that was just
    // replaced, so nothing else on this machine carries the fact.
    if (verdict.recorded === false) {
      report.writeErr("blamepost restore apply: the volume was restored and the row " +
        "recording it could not be written, so this volume's audit trail has no entry for " +
        "it. Note the bundle id and the time somewhere else, and check where audit rows are " +
        "being written.");
    }
    if (verdict.flushed === false) {
      report.writeErr("blamepost restore apply: the row recording it was written and could " +
        "not be settled onto the volume (" + verdict.flushReason + "), so the trail may " +
        "carry no entry for this restore. The restore itself stands.");
    }

    // `applied` also carries the vault keypair the bundle was sealed
    // with. It is the key to every sealed column on the volume, so the
    // report is built field by field rather than from the whole object:
    // a terminal, a log and a pipeline that captures one are all places
    // it must never reach.
    return _emit(report, flags, {
      ok:           true,
      bundleId:     applied.bundleId,
      fileCount:    applied.fileCount,
      totalBytes:   applied.totalBytes,
      rollbackPath: applied.rollbackPath,
      durationMs:   applied.durationMs,
      verified:     true,
      chain:        verdict.chain,
      checkpoints:  verdict.checkpoints,
      accounts:     verdict.accounts,
      domains:      verdict.domains,
    }, [
      "Restored " + applied.bundleId + " into " + config.paths.dataDir,
      "  " + applied.fileCount + " file(s), " + applied.totalBytes + " bytes, in " +
        applied.durationMs + "ms",
      // Null when there was no data directory here to move aside, which
      // is what a restore onto a fresh host looks like. The failure path
      // above already reads it that way; printing the word null as a
      // location is the same fact reported as a place an operator could
      // go and look.
      applied.rollbackPath
        ? "  kept the directory it replaced at " + applied.rollbackPath
        : "  nothing was here to replace, so no earlier directory was kept",
      "  chain:    " + verdict.chain.rowsVerified + " row(s) verified, " +
        verdict.checkpoints.checkpointsVerified + " signed checkpoint(s)",
      "  holds:    " + verdict.accounts + " account(s) across " + verdict.domains + " domain(s)",
      "",
      // Two runs, both before the server takes the volume, and in this
      // order because only one of them opens a message body.
      //
      // What has just been verified is the bundle's signature and the
      // audit chain in the database. Neither says whether the mail is
      // still readable: a backup taken over a volume that had already
      // lost or damaged a body preserves it exactly, and one taken while
      // mail was arriving can carry a row whose body had not been
      // written yet. `blobs report --verify` is the only thing that
      // unseals each body and hashes it back against the row naming it.
      //
      // `doctor` counts bodies without opening them, so it cannot answer
      // that question. Both verbs answer while the server holds the
      // volume, off a read-only open whose rows stop at the server's last
      // write to disk; running them here instead reads rows that nothing
      // is still writing to, which is why the epilogue sends the operator
      // to them before the start rather than after it.
      "This volume opened and its audit chain verified. Neither of those opens a message",
      "body, so before starting the server:",
      "",
      "  blamepost blobs report --verify",
      "    unseals every body a row names and hashes it back against that row. A backup",
      "    keeps whatever state the volume was in when it was taken, so this is where a",
      "    message that was already unreadable shows up.",
      "",
      "  blamepost doctor",
      "    a restore rewinds DKIM state, and this is what holds the selectors against the",
      "    records in the zone. Run it here rather than after the server starts: once the",
      "    server holds the volume it reads rows that stop at the server's last write to",
      "    disk, and says how old that reading is before it reports anything.",
    ]);
  }

  return report.usage(USAGE_RESTORE);
}

// ---- dispatch ---------------------------------------------------------------

// A value the operator gave that could not be read. Every layer this CLI
// calls into refuses a malformed address, domain or option with a code
// under its own `<area>/bad-...` namespace, and that is a different
// answer from a server that tried and failed: one is fixed by retyping
// the line, the other is not. The exit code says which, so a script can
// tell a typo from an outage without parsing the message.
function _isArgumentFault(err) {
  return !!(err && typeof err.code === "string" && /\/bad-/.test(err.code));
}

// One line naming what went wrong, and the exit code that classifies it.
// The stack belongs to whoever is debugging blamepost, not to the
// operator reading a refusal, so it is printed only when they have asked
// for that much detail.
function _reportFailure(command, err) {
  var message = (err && err.message) || String(err);
  var argumentFault = _isArgumentFault(err);
  process.stderr.write("blamepost" + (command ? " " + command : "") + ": " + message + "\n");
  if (String(process.env.BLAMEPOST_LOG_LEVEL || "").toLowerCase() === "debug") {
    if (err && err.stack) process.stderr.write(err.stack + "\n");
  } else if (!argumentFault) {
    // Offered only where it would help. A mistyped address is fixed by
    // retyping it, and pointing at a stack trace suggests otherwise.
    process.stderr.write("Re-run with BLAMEPOST_LOG_LEVEL=debug for the full trace.\n");
  }
  return argumentFault ? 2 : 1;
}

// The three commands that take no verb, and therefore no arguments.
//
// `VERB_SURFACE` refuses an argument a verb will not read, but it is
// keyed by verb and these three have none, so nothing spoke for them and
// the dispatch below dropped their positionals on the floor: they are
// the only commands called without `positionals` at all. What that cost
// was the same thing the table exists to prevent. `blamepost doctor
// example.com` read as a report about one domain and was a report about
// every hosted domain, with nothing said about the name that had been
// ignored, and a clean answer about a zone nobody asked after is worse
// than a refusal.
var VERBLESS_COMMANDS = {
  serve:  "runs the server, which serves every hosted domain",
  init:   "prepares the volume, which is not per-domain",
  doctor: "checks every hosted domain",
};

async function _run(command, flags, positionals) {
  if (Object.prototype.hasOwnProperty.call(VERBLESS_COMMANDS, command) &&
      positionals.length > 0) {
    return _reporter(command).error("`" + command + "` takes no arguments, so " +
      positionals.join(" and ") + " would be ignored. It " +
      VERBLESS_COMMANDS[command] + ".", 2);
  }
  switch (command) {
    case "serve":   return await cmdServe(flags);
    case "init":    return await cmdInit(flags);
    case "account": return await cmdAccount(flags, positionals);
    case "domain":  return await cmdDomain(flags, positionals);
    case "dkim":    return await cmdDkim(flags, positionals);
    case "queue":   return await cmdQueue(flags, positionals);
    case "blobs":   return await cmdBlobs(flags, positionals);
    case "doctor":  return await cmdDoctor(flags);
    case "audit":   return await cmdAudit(flags, positionals);
    case "backup":  return await cmdBackup(flags, positionals);
    case "restore": return await cmdRestore(flags, positionals);
    default:
      process.stderr.write("blamepost: no command named '" + command + "'\n");
      return 2;
  }
}

async function main(argv) {
  var parser = _parser();
  var parsed;
  try {
    parsed = parser.parse(argv);
  } catch (err) {
    process.stderr.write("blamepost: " + ((err && err.message) || String(err)) + "\n");
    process.stderr.write("Run `blamepost help` for the list of commands.\n");
    return 2;
  }
  if (parsed.helpRequested) {
    process.stdout.write(parsed.helpText + "\n");
    return 0;
  }

  // No command means serve. That is what the container runs, and it is
  // the only thing an operator wants from a bare invocation.
  var command = parsed.command || "serve";
  var flags = parsed.flags || {};
  var positionals = parsed.positionals || [];

  try {
    // Everything the command does runs under the operator who ran it,
    // so the rows it writes name them without every verb having to
    // carry the identity down to the layer that writes the row. A verb
    // whose principal is somebody else, such as an account proving its
    // own credential, names that principal at the row instead.
    return await auditActor.runAs(auditActor.forCommandLine(), function () {
      return _run(command, flags, positionals);
    });
  } catch (err) {
    return _reportFailure(command, err);
  }
}

// `VERB_SURFACE` is exported so the suite can reconcile it against the
// usage each group prints. A verb added to a group without a row here
// keeps working and quietly stops refusing the flags it does not read,
// which is the failure this table exists to prevent, and it is invisible
// from the outside because the verb still does its job.
module.exports = { main: main, VERB_SURFACE: VERB_SURFACE };

if (require.main === module) {
  main(process.argv.slice(2)).then(function (code) {
    // Set the code rather than exiting. `serve` returns while its
    // listeners still hold the event loop, and calling exit here would
    // stop the server the moment it finished starting. Every other
    // command lets the loop drain and the process ends with this code.
    process.exitCode = typeof code === "number" ? code : 0;
  }).catch(function (err) {
    // Anything the dispatcher's own boundary did not catch: a failure in
    // argument parsing itself, or in the reporting of a failure.
    process.exitCode = _reportFailure("", err);
  });
}
