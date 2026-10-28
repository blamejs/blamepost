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
// The screen between text somebody else wrote and a person reading it.
// A terminal acts on bytes a browser renders inertly, so the values this
// binary prints go through the same reader the browser surface uses.
var displayText = require("../lib/text");
var configModule = require("../lib/config");
var storeModule = require("../lib/store");
// The sending credential registry. It is composed against the handles a
// store open already hands out rather than being reached through one, so
// the verbs below take it the same way `blamepost.mail.dkim.create` is
// taken: built from the open this run made, and given back with it.
var credentialsModule = require("../lib/store/credentials");
// The table names the report verbs read rows back through. The store
// module owns every write to those three tables; what is taken here is
// the framework's query builder over the names it declares, so there is
// one schema and one place that changes it.
var storeTables = require("../lib/store/tables");
// How the store renders the reasons a name was refused. The argument
// readers below quote a name back to the operator, and taking the
// rendering from the same place the store's own refusals take it is what
// keeps one bad address from reading two ways depending on which verb
// caught it.
var storeErrors = require("../lib/store/errors");

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

// A file holding a secret this server reads off disk is one line: a
// bundle passphrase, or the provider API token `zone token set` seals.
// The cap is here so a mistyped path pointing at a mailbox or a database
// cannot be read into memory before it is rejected.
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
  "  list [--domain <domain>]              selectors and their states\n" +
  "  records --domain <domain>             every record that must be in the zone right now\n" +
  "  generate --domain <domain>            first keys for a domain that has none\n" +
  "           [--selector <name>]          name the pair rather than taking the dated default\n" +
  "  rotate --domain <domain> [--selector <name>]  mint a replacement pair; both pairs sign\n" +
  "                                        meanwhile. The default name carries the month, so\n" +
  "                                        rotating twice in one month needs --selector\n" +
  "  retire --domain <domain> --selector <name>   stop signing with the outgoing pair\n" +
  "  sweep [--domain <domain>] [--immediate]   report retired selectors whose records can now be removed\n" +
  "  reseal [--domain <domain>]            seal the private keys already on this volume to the\n" +
  "                                        selectors they belong to. Run it once after upgrading\n" +
  "                                        from a version that sealed them to the volume alone.\n" +
  "                                        Safe to run again; keys already sealed that way are\n" +
  "                                        left alone\n" +
  "\n" +
  "list, records, generate, rotate and retire take the domain as the argument as well, so\n" +
  "`blamepost dkim records example.com` is the same line. sweep and reseal read --domain\n" +
  "only, and refuse an argument.";

var USAGE_ZONE =
  "Usage: blamepost zone <verb>\n" +
  "\n" +
  "  preview <domain> --reason <text>      what would change at the DNS provider to publish\n" +
  "                                        this domain's DKIM records. Nothing is written\n" +
  "  verify <domain> --reason <text>       read those records back twice, from the provider\n" +
  "                                        and through a resolver, and report where the two\n" +
  "                                        disagree\n" +
  "  verify-token --reason <text>          ask the provider whether the sealed token is live.\n" +
  "                                        It takes no domain: the answer is about the account\n" +
  "                                        the token belongs to, and a token that is live is\n" +
  "                                        not the same as one scoped to a zone\n" +
  "  allowlist <domain>                    exactly what this server will write in one domain's\n" +
  "                                        zone: the record types, the addresses each type is\n" +
  "                                        permitted at, and the ceiling on one change set\n" +
  "  token set --token-file <path>         seal the provider API token onto this volume. The\n" +
  "            --reason <text>             file holds the token and nothing else\n" +
  "  token clear --reason <text> --confirm erase the sealed token from this volume\n" +
  "\n" +
  "preview, verify, verify-token and allowlist write nothing and answer while the server runs.\n" +
  "allowlist opens no data volume at all: it reports the gate's own reach, so it answers after\n" +
  "the server has stopped and when the database will not open. token set and token clear change\n" +
  "a credential on the data volume, so they need the server stopped.\n" +
  "\n" +
  "The records this server offers to publish are the DKIM selector records, which are the\n" +
  "ones it holds the only authoritative value for. The sender policy, the DMARC policy and\n" +
  "the reporting addresses name senders and mailboxes outside this server, so they stay\n" +
  "yours to publish. Nothing here removes a record: a retired selector's record is pulled\n" +
  "by hand once `blamepost dkim sweep` says its window has closed.";

var USAGE_CREDENTIAL =
  "Usage: blamepost credential <verb>\n" +
  "\n" +
  "  list <domain>                         the sending credentials one hosted domain holds,\n" +
  "       [--include-revoked]              newest first, with the state of each one's return\n" +
  "       [--include-expired]              path. Revoked and expired ones are left out unless\n" +
  "                                        you ask for them\n" +
  "  show <id>                             one credential: the domain it speaks for, the\n" +
  "                                        mailbox its bounces go to, what it may not send as,\n" +
  "                                        its ceilings, and whether its bounces are still\n" +
  "                                        arriving where it named. Ids come from list\n" +
  "  bounces <domain>                      the domain's return path, and every live credential\n" +
  "                                        whose bounces have stopped reaching their mailbox\n" +
  "  ceiling <id>                          one credential's two ceilings, the window this\n" +
  "          [--limit <n>]                 volume reads, and what the trail recorded when a\n" +
  "                                        ceiling was crossed or a window given back\n" +
  "  add <domain> --bounce-to <address>    issue a credential for one hosted domain. The token\n" +
  "      --reason <text>                   is printed once and nothing can read it back\n" +
  "      [--expires <when>]                a moment, or never; one year from now by default\n" +
  "      [--max-messages <n>]              messages it may send in one window\n" +
  "      [--max-recipients <n>]            recipients it may address in one window\n" +
  "      [--window-minutes <n>]            the window both of those are measured over\n" +
  "  rotate <id> --reason <text>           replace the secret and print the new token once.\n" +
  "         [--grace-hours <n>]            The old one stops at once unless you name a window\n" +
  "  revoke <id> --reason <text>           stop the credential working, keeping its row so the\n" +
  "                                        identifier on earlier audit rows still resolves\n" +
  "  remove <id> --destroy --reason <text>  take the row off the volume as well. revoke is the\n" +
  "                                        answer almost every time\n" +
  "  refusals <id> --reason <text>         replace the local parts this credential may not\n" +
  "           --local-part <name>          send as. Repeat --local-part, or give one\n" +
  "           [--clear --confirm]          comma-separated list. --clear leaves it able to\n" +
  "                                        send as every address in its domain\n" +
  "\n" +
  "list, show and bounces write nothing and answer while the server runs. The rest need the\n" +
  "server stopped: five of them change the data volume, and ceiling reads the audit trail,\n" +
  "which files a row for every read of it.\n" +
  "\n" +
  "The counters the two ceilings are measured against live in the process that is sending, so\n" +
  "the window ceiling prints is the one the next start begins from rather than the one that\n" +
  "refused a message. What the server counted while it was running is on the trail, which is\n" +
  "the half of that verb's answer that covers a running server.\n" +
  "\n" +
  "A credential speaks for every local part in one hosted domain, so it is not an account and\n" +
  "holds no mailbox. Its bounces come back to bounces+<id>@<domain>, and the domain carries one\n" +
  "alias at bounces@<domain> pointing at the mailbox you named; leave that address free for it.\n" +
  "A bounce mailbox archived after the credential was created leaves the credential working and\n" +
  "every bounce refused at the door, which is what show and bounces report.\n" +
  "\n" +
  "The token is printed to this terminal and nowhere else. It is not written to a file and not\n" +
  "recorded in the audit trail, so this terminal and its scrollback are where it is exposed:\n" +
  "copy it into wherever the application keeps its secrets, then clear the scrollback. A token\n" +
  "that has been lost is replaced with rotate rather than read back.";

var USAGE_REPORTS =
  "Usage: blamepost reports <verb>\n" +
  "\n" +
  "  list [--domain <domain>]              what receivers have reported about your domains: how\n" +
  "       [--from <when>] [--to <when>]    much mail they counted, how much of that aligned, the\n" +
  "       [--limit <n>]                    sending addresses that failed both alignments, and\n" +
  "       [--include-unauthenticated]      which organizations reported at all. The window is\n" +
  "                                        the last 30 days unless --from or --to moves it, and\n" +
  "                                        it is matched against the period each report covers\n" +
  "                                        rather than the moment it arrived\n" +
  "  show <id> [--limit <n>]               one aggregate report: the policy it was judged\n" +
  "                                        against, who sent it, what this server concluded\n" +
  "                                        about the message that carried it, and the sending\n" +
  "                                        addresses it counted. Ids come from list\n" +
  "  forget <address> --reason <text>      destroy every stored report row naming one address,\n" +
  "         --confirm                      answering an erasure request from somebody who has\n" +
  "                                        no account here. There is no copy afterwards\n" +
  "\n" +
  "list and show write nothing and answer while the server runs. forget destroys rows on the\n" +
  "data volume, so it needs the server stopped.\n" +
  "\n" +
  "A report counts toward the reading only when this server authenticated the message that\n" +
  "carried it, because anybody who can send mail to a published reporting address can write\n" +
  "one. What is left out is counted beside every total rather than dropped, and list folds it\n" +
  "back into the arithmetic when asked.\n" +
  "\n" +
  "A date is ISO 8601 or milliseconds since the epoch. This reads the reports peers send\n" +
  "here; it publishes no DNS record and changes no policy.";

var USAGE_DMARC =
  "Usage: blamepost dmarc <verb>\n" +
  "\n" +
  "  status <domain>                       whether the reports carry the next policy step:\n" +
  "                                        every rule with what it asks for beside what the\n" +
  "                                        domain has, and the record text for all three\n" +
  "                                        levels whichever way the answer goes\n" +
  "  preview <domain>                      the record text on its own, built from what the\n" +
  "          [--level <level>]             domain publishes today. It opens no data volume,\n" +
  "                                        so it answers while the server runs, after it has\n" +
  "                                        stopped, and when the database will not open\n" +
  "  mark <domain> --source <address>      write down what one failing sending address is, so\n" +
  "       --disposition <what>             a step stops waiting on it. <what> is ours-and-fixed\n" +
  "       --reason <text>                  for a sending path of yours whose alignment is\n" +
  "                                        corrected, or not-ours for one that is not yours\n" +
  "  markings <domain>                     every marking in force for one domain, newest first\n" +
  "\n" +
  "Nothing here publishes a record. status and mark write to the audit trail, so they need the\n" +
  "server stopped; preview reads DNS and nothing else.\n" +
  "\n" +
  "Stepping up is refused until every rule is met, and a domain still accumulating evidence is\n" +
  "the ordinary state rather than a fault, so status exits zero whichever way it answers.\n" +
  "Stepping down is not gated at all: an operator whose mail is being discarded needs the\n" +
  "shortest way back, so every reading prints the weaker record beside the verdict, including\n" +
  "the readings that refuse to step up.\n" +
  "\n" +
  "A step rests on the reports whose carrier this server authenticated and on nothing else,\n" +
  "because anybody who can send mail to a published reporting address can write one. The\n" +
  "sending addresses a marking names are the ones `blamepost reports list` prints.";

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
  "  repair --confirm --reason <text>      destroy the mail the message store holds that\n" +
  "                                        no mailbox row names, so the quota counter it\n" +
  "                                        is charged against falls by what went\n" +
  "\n" +
  "A message body is written to disk and then a row is written naming it, and nothing\n" +
  "spans the pair. report answers either way, falling back to a read-only open whose\n" +
  "rows stop at the server's last write to disk. reclaim deletes files, so it needs the\n" +
  "server stopped and is refused while another process holds the volume. A body is\n" +
  "removed only once it has been on disk for a day, and inside that window one that is\n" +
  "arriving looks exactly like one that was stranded.\n" +
  "\n" +
  "repair destroys mail and needs the server stopped for the same reason. It removes\n" +
  "only messages the store holds that no mailbox row names, which no protocol lists and\n" +
  "no client can delete; report names how many there are and how many bytes they hold\n" +
  "before you run it. A preservation order and the retention floor keep one exactly as\n" +
  "they keep any other message, and a mailbox holding one they kept goes on being\n" +
  "charged for it. The bodies those messages named are freed by reclaim afterwards.";

var USAGE_ATTACHMENTS =
  "Usage: blamepost attachments <verb>\n" +
  "\n" +
  "  report                                how many stored messages record whether they\n" +
  "                                        carry files, and how many do not\n" +
  "  backfill [--limit <n>]                read the octets of the messages that do not and\n" +
  "                                        record the answer\n" +
  "\n" +
  "A message records whether it carries files when it is filed, as the IMAP keyword\n" +
  "$HasAttachment or $HasNoAttachment. An IMAP client shows the keyword and a JMAP\n" +
  "client reads hasAttachment from it. Mail filed before this server derived it carries\n" +
  "neither, and until backfill has run, the folder listing says the answer is unknown\n" +
  "for those messages and JMAP answers hasAttachment true rather than hiding a file.\n" +
  "\n" +
  "backfill writes to the volume, so it needs the server stopped and is refused while\n" +
  "another process holds it. report opens the volume the same way. Each message is\n" +
  "marked on its own, so a run that stops partway has done everything it reached and\n" +
  "running it again reaches the rest; --limit caps how many messages one run opens and\n" +
  "the answer says how many it left. A message above the 8 MiB read bound, and one\n" +
  "whose stored body cannot be read back, stay unmarked and are counted separately,\n" +
  "because what those carry is not known rather than nothing.";

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
  "        --passphrase-file <path>        what it replaced as a rollback point under\n" +
  "        --confirm --reason <text>       .restore on the volume. The restored volume is\n" +
  "        [--fingerprint <hex>]           opened, its audit chain verified and its signing\n" +
  "                                        key held against the manifest's before success\n" +
  "  rollback --confirm --reason <text>    put the most recent rollback point back, or undo\n" +
  "           [--point <path>]             a restore that stopped partway; or a named point\n" +
  "  list-rollbacks                        every rollback point this volume still holds\n" +
  "\n" +
  "Stop the server first. Both verbs refuse while another process holds the data volume.";

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
    // No confirmation and no reason. It changes which seal a key is
    // written under and nothing about which keys exist, which domains
    // sign, or what any zone publishes, so there is nothing for a
    // confirmation to describe. It is absent from
    // `lib/store/SNAPSHOT_VERBS` because it writes to the volume, and a
    // read-only copy cannot take the write.
    reseal:   { args: 0, flags: ["domain"] },
  },
  zone: {
    preview: { args: 1, flags: ["reason"] },
    verify:  { args: 1, flags: ["reason"] },
    // No confirmation, and no argument. It asks the provider whether the
    // sealed credential is live and changes nothing at the provider, on
    // the volume or in the zone, so there is no reach past the command
    // line for a confirmation to describe. It takes no domain because
    // the endpoint answers about the account the token belongs to rather
    // than about a zone, and a domain on the line would read as a scope
    // check this answer does not make.
    "verify-token": { args: 0, flags: ["reason"] },
    // No confirmation and no reason. It asks the gate what it will write
    // and asks nothing of the provider, so no request leaves this
    // process and there is no zone read for a row to answer for. A
    // reason here would record that somebody looked at a constant.
    //
    // It is absent from `lib/store/SNAPSHOT_VERBS` because it never
    // reaches that layer: the answer is the gate's own reach, which is
    // settled by the configuration, so this verb opens no volume and has
    // no read-only path to fall back to.
    allowlist: { args: 1, flags: [] },
    // One row for both halves of the credential verb. `set` and `clear`
    // arrive as the argument rather than as verbs of their own, so the
    // group offers three verbs and the gate covers three, and a reader
    // never meets a `set` that means nothing on its own.
    token:   { args: 1, flags: ["token-file", "reason", "confirm"] },
  },
  credential: {
    list:     { args: 1, flags: ["include-revoked", "include-expired"] },
    show:     { args: 1, flags: [] },
    bounces:  { args: 1, flags: [] },
    // No confirmation and no reason. It changes no credential, writes
    // nothing to the volume and names one identifier on the command
    // line, so there is no reach past that line for a confirmation to
    // describe: the line `dmarc mark` is on rather than the one
    // `reports forget` is on. The row `b.audit.query` files for the read
    // carries the operator, which is the account of it that matters, and
    // a reason on a read that changes nothing would be a reason for
    // looking rather than for doing.
    //
    // It is deliberately absent from `lib/store/SNAPSHOT_VERBS` beside
    // list, show and bounces. Reading the trail files a row before the
    // answer comes back, a read-only handle cannot write that row, and a
    // read that claims to be recorded and is not is worse than one that
    // refuses. `audit read` and `dmarc markings` are excluded for the
    // same reason.
    ceiling:  { args: 1, flags: ["limit"] },
    add:      { args: 1, flags: ["bounce-to", "reason", "expires", "max-messages",
      "max-recipients", "window-minutes"] },
    rotate:   { args: 1, flags: ["reason", "grace-hours"] },
    revoke:   { args: 1, flags: ["reason"] },
    remove:   { args: 1, flags: ["destroy", "reason"] },
    refusals: { args: 1, flags: ["local-part", "clear", "confirm", "reason"] },
  },
  reports: {
    list:   { args: 0, flags: ["domain", "from", "to", "limit", "include-unauthenticated"] },
    show:   { args: 1, flags: ["limit"] },
    forget: { args: 1, flags: ["reason", "confirm"] },
  },
  dmarc: {
    status:   { args: 1, flags: [] },
    preview:  { args: 1, flags: ["level"] },
    // No confirmation. A marking names one domain and one sending
    // address, both on the command line, so what it reaches is what an
    // operator can read back before pressing return. The line is drawn
    // by whether the reach is visible rather than by whether the verb
    // writes: `reports forget` takes one address and destroys the rows
    // of every reporter that named it, which is why that one asks.
    mark:     { args: 1, flags: ["source", "disposition", "reason"] },
    markings: { args: 1, flags: [] },
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
    repair:  { args: 0, flags: ["confirm", "reason"] },
  },
  attachments: {
    report: { args: 0, flags: [] },
    // No confirmation and no reason. It writes a mark this server derives
    // from the message itself, destroys nothing and changes nothing a
    // reader can see except the answer to a question nothing had
    // answered, so there is nothing for a confirmation to describe. The
    // run files one audit row carrying its counts.
    backfill: { args: 0, flags: ["limit"] },
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

// Text on its way to this operator's terminal, screened a line at a
// time.
//
// The screen is `blamepost.text.forDisplay` and what it removes is
// written where it is defined. What is added here is the split, and the
// split is the whole reason this exists rather than a bare call: the
// screen's contract is one line, because folding a line feed to a space
// is what keeps two words from running together where a break was. A
// caller holding several lines has to split them and screen each one, and
// the two values this file hands to a stream in more than one piece are a
// stack trace and a pretty-printed JSON answer. Screening either whole
// would put both onto one line.
//
// `_headerText` below stays what it is and is not replaced by this. It
// screens a single value before `_column` measures it, and a width
// computed from the codepoints a screen is about to remove pads the
// column to the wrong place, so a table's screen has to run at the value
// rather than at the line.
function _linesForDisplay(value) {
  if (value === null || value === undefined) return "";
  return String(value).split("\n").map(function (line) {
    return displayText.forDisplay(line);
  }).join("\n");
}

// One reporter, with the screen above on everything it prints.
//
// It is here rather than at each of the places a message is built
// because this is the boundary all of them cross. A refusal quoting a
// path, an argument the parser could not read, a receiver's own words
// and a record a third party published all reach an operator through
// these six verbs, and a screen written at the sites instead is a screen
// a verb added later arrives without.
//
// Every verb answers what the framework's own reporter answers, because
// the answer is an exit code the caller returns and nothing here has an
// opinion about it.
//
// A message that is absent is carried across as absent rather than as
// the empty string. The framework writes no line at all for one and
// writes a blank line for the other, and `ok` is called with nothing by
// the verbs whose whole answer is the exit code.
function _screened(value) {
  return value === null || value === undefined ? value : _linesForDisplay(value);
}

function _screenedReporter(inner) {
  return {
    ok:         function (message) { return inner.ok(_screened(message)); },
    error:      function (message, exitCode) {
      return inner.error(_screened(message), exitCode);
    },
    usage:      function (usageText) { return inner.usage(_screened(usageText)); },
    helpStdout: function (usageText) { return inner.helpStdout(_screened(usageText)); },
    write:      function (line) { return inner.write(_screened(line)); },
    writeErr:   function (line) { return inner.writeErr(_screened(line)); },
  };
}

function _reporter(verb) {
  return _screenedReporter(b.cliHelpers.makeReporter(ctx, "blamepost " + verb));
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

// Why one of the two readers below refused, in the spelling the store's
// own refusals use. The list is deduplicated there, and a name carrying
// the same fault in two labels reads back as one reason rather than as
// the same word twice.
function _whyRefused(detail) {
  var kinds = storeErrors.issueKinds(detail);
  return kinds === "" ? "" : " (" + kinds + ")";
}

// A domain given as an argument or as a scoping flag, checked for shape
// before it is looked up and before it narrows a report. A mistyped name
// refused here is an argument problem the operator sees immediately; the
// same name carried further comes back as a resolver failure, as a clean
// report about a zone nobody asked about, or as a lookup that found
// nothing. Answers either `{ domain }` or `{ code }`, and the code is the
// one the caller returns.
function _readDomainArg(report, raw) {
  var verdict = address.parseDomain(raw);
  if (!verdict.ok) {
    return {
      code: report.error(JSON.stringify(String(raw)) + " is not a usable domain name" +
        _whyRefused(verdict.detail) + ".", 2),
    };
  }
  return { domain: verdict.domain };
}

// A mailbox named as the argument to a verb, checked the same way.
//
// `store.accounts.get` and `store.domains.get` both answer null for a row
// that is not on this volume AND for a string that could never name one.
// That is what a lookup owes a wire listener holding an untrusted peer's
// input: a verdict rather than a throw. Deciding which of the two
// happened belongs here instead, because this is the layer the operator
// typed at. One is answered by creating the account and the other by
// retyping the line, and a run that prints "no account" over a string
// that is not an address says the first about the second, at the exit
// code that means this server tried and failed.
//
// A token carrying no at sign is handed back untouched. The lookup reads
// one of those as an account id, which is what `--json` prints beside
// every row, so measuring it against the shape of an address would
// refuse an identifier this server handed out.
//
// Answers either `{ address }` or `{ code }`, and the code is the one the
// caller returns.
function _readAddressArg(report, raw) {
  if (typeof raw !== "string" || raw.indexOf("@") === -1) return { address: raw };
  var verdict = address.parse(raw);
  if (!verdict.ok) {
    return {
      code: report.error("address " + JSON.stringify(raw) +
        " is not a usable mailbox address" + _whyRefused(verdict.detail) + ".", 2),
    };
  }
  return { address: verdict.address };
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
            description: "Selector name. Required by retire; generate and rotate take one " +
              "instead of the dated default. The other verbs here refuse it." },
          { name: "immediate", type: "boolean",
            description: "Withdraw a retiring selector before its overlap elapses. " +
              "Right when a key is exposed, wrong otherwise: mail signed with it and " +
              "still being retried starts failing DKIM." },
        ] },
      { name: "zone",
        description: "Read a hosted DNS provider's zone against the records this server " +
          "expects, and hold the credential that lets it. Nothing here publishes a record.",
        flags: [
          { name: "token-file", type: "string",
            description: "File holding the provider API token, read once and sealed onto " +
              "this volume. It is read from a file rather than the command line, because a " +
              "command line is in the shell history and in the process list." },
          { name: "reason", type: "string",
            description: "Why the zone is being read or the credential changed. Recorded in " +
              "the audit trail, and required by every verb here." },
          { name: "confirm", type: "boolean",
            description: "Confirm that clear erases the sealed token. This server stops " +
              "being able to edit any zone, and the token is not revoked at the provider by " +
              "erasing it here." },
        ] },
      { name: "credential",
        description: "Issue, inspect and withdraw the sending credentials an application " +
          "presents to send mail as a hosted domain.",
        flags: [
          { name: "bounce-to", type: "string",
            description: "Mailbox on this server that the credential's bounces are delivered " +
              "to. It has to exist and be in service before the credential is written, " +
              "because a credential pointing at nothing discards every bounce at the door " +
              "while the application goes on sending." },
          { name: "reason", type: "string",
            description: "Why a credential is being issued, rotated, withdrawn or narrowed. " +
              "Recorded in the audit trail, and required by each: a credential can send as " +
              "every address in a hosted domain." },
          { name: "expires", type: "string",
            description: "When the credential stops working. ISO 8601 or milliseconds since " +
              "the epoch, or never for one with no end date. One year from now by default." },
          { name: "max-messages", type: "number",
            description: "Messages the credential may send in one window." },
          { name: "max-recipients", type: "number",
            description: "Recipients the credential may address in one window. It is counted " +
              "separately from the messages because a hundred messages of one recipient and " +
              "one message of a hundred thousand are different events, and the second is the " +
              "one a stolen credential produces." },
          { name: "window-minutes", type: "number",
            description: "The rolling window both ceilings are measured over, in minutes." },
          { name: "grace-hours", type: "number",
            description: "How long the previous secret keeps working after a rotation, in " +
              "hours. There is none unless you name one: the reason to rotate is usually " +
              "that the old secret is in somebody else's hands." },
          { name: "local-part", type: "list",
            description: "A local part this credential may not send as. Repeat it, or give " +
              "one comma-separated list, to name several. The list replaces whatever the " +
              "credential held rather than adding to it." },
          { name: "clear", type: "boolean",
            description: "Leave the refusal list empty, so the credential may send as every " +
              "address in its domain, postmaster and abuse included." },
          { name: "confirm", type: "boolean",
            description: "Confirm that clearing the refusal list opens up every address in " +
              "the domain. What it opens up is not on the command line, which is why it is " +
              "asked for." },
          { name: "destroy", type: "boolean",
            description: "Take the credential's row off the volume rather than only stopping " +
              "the credential. The identifier on every audit row it produced stops resolving." },
          { name: "include-revoked", type: "boolean",
            description: "Keep revoked credentials in the listing." },
          { name: "include-expired", type: "boolean",
            description: "Keep expired credentials in the listing. Both are left out by " +
              "default because the common question is which credentials can still send." },
          { name: "limit", type: "number",
            description: "How many trail rows of each kind ceiling reads. The answer says " +
              "when a read came back full, because a window that has been crossed many " +
              "times is one whose oldest crossings fall off the end." },
        ] },
      { name: "reports",
        description: "Read what receivers report about mail claiming your domains, and " +
          "answer an erasure request about one of those reports.",
        flags: [
          { name: "domain", type: "string",
            description: "Read one domain instead of every one this server hosts." },
          { name: "from", type: "string",
            description: "Earliest moment a report's period may end, inclusive. ISO 8601 " +
              "or milliseconds since the epoch. Thirty days before the other end by default." },
          { name: "to", type: "string",
            description: "Latest moment a report's period may begin, inclusive. Now by default." },
          { name: "limit", type: "number",
            description: "How many rows each list inside the answer prints. The rest are " +
              "counted rather than dropped, so the answer says what it did not show." },
          { name: "include-unauthenticated", type: "boolean",
            description: "Count the reports whose carrier this server could not authenticate " +
              "as well. They are left out by default because anybody who can send mail to a " +
              "published reporting address can write one, and a policy moved on one is a " +
              "policy moved by whoever wanted it moved." },
          { name: "reason", type: "string",
            description: "Why the report rows are being destroyed. Recorded in the audit " +
              "trail, and required by forget: the row is the only record they were here." },
          { name: "confirm", type: "boolean",
            description: "Confirm that forget destroys report rows. It reaches a reporting " +
              "organization's contact mailbox as well as a stranger's envelope, so an " +
              "address belonging to a reporter takes that reporter's counting with it." },
        ] },
      { name: "dmarc",
        description: "Read whether a hosted domain's reports carry the next DMARC policy " +
          "step, print the record text for each policy level, and record what a failing " +
          "sending address is. Nothing here publishes a record.",
        flags: [
          { name: "level", type: "string",
            description: "Print the record for one policy level rather than all three: " +
              "none, quarantine or reject." },
          { name: "source", type: "string",
            description: "The sending address a reporter named, as an IPv4 or IPv6 address. " +
              "`blamepost reports list` prints the ones failing both alignments." },
          { name: "disposition", type: "string",
            description: "What that address is: ours-and-fixed for a sending path of yours " +
              "whose alignment has been corrected, or not-ours for one that is not yours. " +
              "The two are read differently, because continued failure contradicts the " +
              "first and is expected of the second." },
          { name: "reason", type: "string",
            description: "What you found out about the address and how. Recorded in the " +
              "audit trail as the marking itself, and required by mark." },
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
      { name: "attachments",
        description: "Record whether each stored message carries files, for mail filed " +
          "before this server derived it.",
        flags: [
          { name: "limit", type: "number",
            description: "How many unmarked messages one run opens. The answer says how " +
              "many it left, and running it again reaches those." },
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
// The log level is applied here rather than in `serve` alone, because
// every verb below runs framework code that reports what it recovered
// from at debug, and an operator debugging `doctor` or `queue list`
// wants those lines as much as one debugging the server. Applying it at
// the single point the configuration is built also means the level a
// file sets reaches the logger, which a reader of the environment
// variable alone never sees.
function _configFrom(flags) {
  var env = Object.assign({}, process.env);
  if (flags.config) env.BLAMEPOST_CONFIG = flags.config;
  if (flags["data-dir"]) env.BLAMEPOST_DATA_DIR = flags["data-dir"];
  if (flags.hostname) env.BLAMEPOST_HOSTNAME = flags.hostname;
  var config = configModule.load({ env: env });
  configModule.applyLogLevel(config);
  // Which file the run read and which volume it settled on, written
  // before anything acts on either. It is the first question behind a
  // command that behaved as though it had read something else, and the
  // answer is otherwise only visible by reconstructing the search from
  // the environment. Written at debug because it says nothing an
  // ordinary run needs.
  b.log.boot("config").debug("configuration resolved", {
    configPath: config.configPath,
    dataDir:    config.dataDir,
    hostname:   config.hostname,
  });
  return config;
}

// Whether a verb may answer from a read-only open of the data volume
// while the server writes it, rather than being refused until it is
// stopped.
//
// The set lives in `lib/store`, beside the open it describes and beside
// the refusal that names it to an operator. Reading it from there rather
// than restating it here is what keeps the two in step: a verb added to
// the set is a verb the refusal names, in the same edit, with nothing to
// remember. `doctor` is a whole command rather than a group and a verb,
// so the set lists it against the empty string and this matches it the
// same way.
var NO_VERB = "";

function _mayReadASnapshot(group, verb) {
  var eligible = storeModule.SNAPSHOT_VERBS;
  if (!Object.prototype.hasOwnProperty.call(eligible, group)) return false;
  return eligible[group].indexOf(String(verb === undefined ? NO_VERB : verb)) !== -1;
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

// Untrusted text on its way to a terminal. A subject and a From line are
// written by whoever sent the message, a reporting organization's name
// and its report identifier are written by whoever sent the report, and
// an audit row's reason quotes whichever of those caused it. This prints
// all of them to an operator who is deciding which records an order
// covers, or reading back what the server did.
//
// It is the one screen the browser surface, the zone diff and the doctor
// report also run, so a value that reads as one line in a browser reads
// as one line in this table. It is the display that is corrected, never
// the stored value.
//
// A terminal acts on what a browser renders inertly, which is why this
// column matters more here than there: an escape introducer on this
// table can clear the row above or repaint the `HELD` marker onto a
// message that does not carry one, and a tab moves the value out from
// under the heading that names it.
function _headerText(value, fallback) {
  if (typeof value !== "string" || value.length === 0) return fallback;
  return displayText.forDisplay(value);
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
  // Every verb here but `list` names one mailbox in the same place, so
  // the name is read once rather than at each of the ten lookups below.
  // Doing it before the volume is opened is what makes the refusal an
  // answer about the line the operator typed: nothing has been decrypted,
  // no row has been searched for, and the exit code says the line is what
  // needs changing.
  var named = _readAddressArg(report, positionals[1]);
  if (named.code !== undefined) return named.code;
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
  // Every verb here but `list` names one domain in the same place. Five
  // of them carried the name into a write that refused it and one, `show`,
  // carried it into a lookup that answers null for a name it could not
  // read, so the same string was an argument fault on five verbs and a
  // missing domain on the sixth.
  if (positionals[1] !== undefined) {
    var wantedDomain = _readDomainArg(report, positionals[1]);
    if (wantedDomain.code !== undefined) return wantedDomain.code;
  }
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
        "  Remove the DKIM records for " + removedDomain.domain + " from its zone: nothing",
        "  here removes a DNS record on any setting, so they stay published until you",
        "  pull them.",
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
    if (verb === "reseal") {
      var moved = await handle.reseal({ domain: domain });
      // The counts are what an operator reads to decide whether the run
      // is still owed. A key already sealed to its selector is named as
      // such rather than left out, because a run reporting nothing at all
      // reads the same as a run that found nothing to look at.
      var resealLines = moved.resealed.length === 0
        ? ["Every signing key on this volume is already sealed to the selector it belongs to."]
        : [moved.resealed.length + " signing key(s) are now sealed to the selector they " +
            "belong to:"]
          .concat(moved.resealed.map(function (s) {
            return "  " + s.domain + "  " + s.selector + "  " + s.algorithm;
          }));
      if (moved.alreadyBound.length > 0) {
        resealLines.push(moved.alreadyBound.length + " were already sealed that way and " +
          "were not rewritten.");
      }
      if (moved.absent.length > 0) {
        resealLines.push(moved.absent.length + " retired selector(s) have no private key " +
          "left on this volume, which is what retiring one does.");
      }
      return _emit(report, flags, moved, resealLines);
    }
    return report.usage(USAGE_DKIM);
  } finally {
    await store.close();
  }
}

// ---- zone -------------------------------------------------------------------

// A raw provider token, read from a file rather than from the command
// line. A value on a command line is in the shell history and in the
// process list of every other user on the host, and a credential that
// has been in either is a credential to reissue rather than to seal.
//
// The read is bounded and the file has to be a regular file. A path
// pointing at a mailbox or a device is a typo, and reading one into
// memory before rejecting it is the part worth not doing.
function _tokenFrom(report, flags) {
  var path = nodePath.resolve(flags["token-file"]);
  var stat;
  try { stat = nodeFs.statSync(path); }
  catch (e) {
    return { code: report.error("--token-file names " + path + ", which cannot be read: " +
      ((e && e.message) || String(e)) + ".", 2) };
  }
  if (!stat.isFile()) {
    return { code: report.error("--token-file names " + path + ", which is not a regular " +
      "file. It holds the provider API token and nothing else.", 2) };
  }
  var text;
  try {
    text = b.atomicFile.fdSafeReadSync(path,
      { maxBytes: PASSPHRASE_FILE_MAX_BYTES, encoding: "utf8" });
  } catch (e2) {
    return { code: report.error("--token-file at " + path + " could not be read: " +
      ((e2 && e2.message) || String(e2)) + ".", 2) };
  }
  var token = String(text).trim();
  if (token.length === 0) {
    return { code: report.error("--token-file at " + path + " is empty. It holds the " +
      "provider API token on one line.", 2) };
  }
  return { token: token, path: path };
}

// The records this server holds the only authoritative value for, in the
// shape the write gate takes.
//
// The DKIM selector records and nothing else. Every other record in the
// mail posture names something outside this server: the sender policy
// lists whoever else sends for the domain, the DMARC and TLS reporting
// records name mailboxes an operator chose, and the MTA-STS policy is
// served rather than published. This server cannot state any of those
// without inventing the operator's half of them, so it offers the ones
// it computes and leaves the rest alone.
//
// `dnsRecords` already drops a retired selector, so what comes back is
// what has to be in the zone right now: the active pairs, and any pair
// still inside its retirement overlap.
function _zoneRecordsFor(handle, domain) {
  return handle.dnsRecords(domain).map(function (record) {
    return { type: "TXT", name: record.dnsName, content: record.dnsTxtValue };
  });
}

async function cmdZone(flags, positionals) {
  var report = _reporter("zone");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_ZONE);
  var unread = _refuseUnread(report, "zone", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);

  if (verb === "token") {
    return await _cmdZoneToken(report, config, flags, positionals);
  }

  if (verb === "verify-token") {
    return await _cmdZoneVerifyToken(report, config, flags);
  }

  if (verb === "allowlist") {
    return _cmdZoneAllowlist(report, config, flags, positionals);
  }

  if (verb !== "preview" && verb !== "verify") return report.usage(USAGE_ZONE);
  if (!positionals[1]) return report.usage(USAGE_ZONE);
  if (!flags.reason) {
    return report.error("give --reason. Reading a zone at the provider is recorded in the " +
      "audit trail beside the writes made to it, and a row with no reason answers nothing " +
      "later about why the zone was being looked at.", 2);
  }
  // The provider is checked before the volume is opened, so an operator
  // who has not turned the zone writer on is told that rather than being
  // told about a domain.
  var noProvider = _zoneProviderRefusal(report, config);
  if (noProvider !== null) return noProvider;
  var shape = _readDomainArg(report, positionals[1]);
  if (shape.code !== undefined) return shape.code;

  var store = await _openForReporting(config, "zone", verb);
  // The writer is closed by name in the finally below rather than the
  // gate it built. It owns every gate it hands out, so closing it
  // removes the outbound scanner each one installed; closing a gate here
  // as well would be a second answer to the same question.
  var zone = null;
  try {
    var hosted = store.domains.get(shape.domain);
    if (!hosted) {
      return report.error("this server does not host " + shape.domain +
        ", so it has no records to publish for it.", 2);
    }
    var dkimHandle = blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store });
    var desired = _zoneRecordsFor(dkimHandle, hosted.domain);
    if (desired.length === 0) {
      return report.error("no DKIM selector for " + hosted.domain + " is publishable, so " +
        "there is nothing to compare against the zone. Mint a pair with `blamepost dkim " +
        "generate --domain " + hosted.domain + "`.");
    }

    zone = blamepost.dns.fromConfig(config);
    var gate = zone.forDomain(hosted.domain);
    var previewed = await gate.preview({ desired: desired, reason: flags.reason });

    if (verb === "preview") {
      return _emit(report, flags, previewed, [
        "Against " + hosted.domain + " at the " + zone.provider + " zone:",
        previewed.diff,
        "",
        "Nothing was written. This server does not apply a zone change from the command",
        "line, because applying one needs the data volume and the server holds it while it",
        "runs; the administration console is where a change is applied.",
      ]);
    }

    // What `verify` reads twice. The entries are the records that have to
    // be in the zone, offered to the gate as though they had just been
    // written, because "is this record at the provider and can the world
    // see it" is the same question either way and the gate already asks
    // it in both directions at once.
    var expected = desired.map(function (record) {
      return { action: "publish", record: record };
    });
    var verdict = await gate.verify(
      { applyId: null, zone: previewed.zone, written: expected },
      { reason: flags.reason });
    var lines = [hosted.domain + ": " + (verdict.ok
      ? "every record this server publishes is at the provider and visible to a resolver."
      : "one or more records disagree.")];
    verdict.checks.forEach(function (entry) {
      lines.push("  " + entry.verdict + "  " + entry.type + " " + entry.name);
    });
    if (!verdict.ok) {
      lines.push("");
      lines.push("  pending is a resolver that has no answer yet, which time fixes.");
      lines.push("  conflict is a resolver answering with something else, which it does not:");
      lines.push("  mail is being judged against a record this server did not publish.");
    }
    return _emit(report, flags, verdict, lines);
  } finally {
    if (zone !== null) zone.close();
    await store.close();
  }
}

// The refusal every zone verb meets before a volume is opened, when the
// operator has not turned the zone writer on. It is one function because
// three verbs give it and an operator who reads a different sentence
// from `preview` than from `verify-token` has two settings to look for
// and one to find. Returns the exit code, or null when a provider is
// named.
function _zoneProviderRefusal(report, config) {
  if (config.zoneProvider !== configModule.ZONE_PROVIDER_NONE) return null;
  return report.error("BLAMEPOST_ZONE_PROVIDER names no provider, so this server edits no " +
    "zone and reads none. Set it to one of " +
    configModule.ZONE_PROVIDERS.filter(function (name) {
      return name !== configModule.ZONE_PROVIDER_NONE;
    }).join(", ") + " and seal a token with `blamepost zone token set --token-file <path> " +
    "--reason <text>`. Left alone, the records stay yours to publish; " +
    "`blamepost dkim records <domain>` prints them.", 2);
}

// What the write gate will write in one domain's zone, asked of the gate
// rather than read off the source.
//
// An operator deciding what to trust a provider token with is asking how
// far this server can reach with it, and the answer is a property of the
// gate every write goes through. It opens no data volume and sends
// nothing to the provider: the reach is settled by the configuration, so
// this answers while the server runs, after it has stopped, and when the
// database will not open. The gate is closed on the way out because
// building one installs an outbound scanner on the transport, and a gate
// discarded without closing leaves the framework counting an interceptor
// nothing will use again.
function _cmdZoneAllowlist(report, config, flags, positionals) {
  if (!positionals[1]) return report.usage(USAGE_ZONE);
  var refused = _zoneProviderRefusal(report, config);
  if (refused !== null) return refused;
  var shape = _readDomainArg(report, positionals[1]);
  if (shape.code !== undefined) return shape.code;

  var zone;
  try {
    zone = blamepost.dns.fromConfig(config);
  } catch (buildErr) {
    return report.error((buildErr && buildErr.message) || String(buildErr));
  }
  try {
    var reach = zone.forDomain(shape.domain).allowlist();
    return _emit(report, flags, reach, [
      "In the " + zone.provider + " zone for " + reach.domain + ", this server writes:",
    ].concat(reach.addresses.map(function (entry) {
      return "  " + _column(entry.type, 8) + entry.describes;
    })).concat([
      "",
      "  record types:    " + reach.types.join(", "),
      "  MX writes:       " + (reach.allowMxWrites
        ? "on, so the mail exchanger at the apex is one it may replace"
        : "off, so the mail exchanger at the apex is yours to publish"),
      "  one change set:  at most " + reach.maxChanges + " change(s)",
      "",
      "  An address this list does not name is refused before a request is built, whatever",
      "  the token at the provider is scoped to. The two bounds are separate: this is what",
      "  the server will ask for, and the token's scope is what the provider will allow.",
      "  `blamepost zone preview " + reach.domain + " --reason <text>` reads the zone with",
      "  the token and reports what it found.",
    ]));
  } finally {
    zone.close();
  }
}

// Ask the provider whether the sealed credential is live.
//
// It reads and writes nothing at the provider, nothing in the zone and
// nothing on the volume, so it answers from a read-only open the way
// `preview` and `verify` do. The volume is opened for the audit row
// rather than for the answer: the credential comes off the sealed file
// through the configuration, and the question is about the account at
// the provider, which is not on this volume at all.
//
// The three endings are kept apart because an operator does different
// things about each. A live token is the answer they wanted. A token the
// provider refuses is the credential to replace. A provider that could
// not be reached leaves the token unjudged, and reporting that as a bad
// credential would send an operator to reissue one that was never the
// problem.
async function _cmdZoneVerifyToken(report, config, flags) {
  if (!flags.reason) {
    return report.error("give --reason. Reading the provider credential is recorded in the " +
      "audit trail beside the writes it authorizes, and a row with no reason answers nothing " +
      "later about why the credential was being looked at.", 2);
  }
  var refused = _zoneProviderRefusal(report, config);
  if (refused !== null) return refused;

  var store = await _openForReporting(config, "zone", "verify-token");
  var zone = null;
  try {
    b.audit.registerNamespace(AUDIT_NAMESPACE);
    // Building the handle opens no seal and reaches nothing. What it
    // refuses here is a credential that is missing, sealed twice over or
    // not sealed at all, and each of those carries the sentence saying
    // what to do about it, so they are reported as themselves rather
    // than folded into the verdict below.
    try {
      zone = blamepost.dns.fromConfig(config);
    } catch (buildErr) {
      return report.error((buildErr && buildErr.message) || String(buildErr));
    }

    var verdict;
    try {
      verdict = await zone.verifyToken();
    } catch (askErr) {
      var code = (askErr && askErr.code) || "";
      var said = (askErr && askErr.message) || String(askErr);
      // A sealed token that does not open is a verdict on the credential
      // this volume holds, the same as one the provider refuses, and it
      // is reported the same way.
      if (code === blamepost.dns.cloudflare.CODES.tokenUnverified ||
          code === blamepost.dns.CODES.tokenSealUnopened) {
        await auditActor.record({
          action:   "blamepost.dns.credential_verified",
          outcome:  "denied",
          actor:    auditActor.current(),
          reason:   flags.reason,
          resource: { kind: "volume", id: config.dataDir },
          metadata: { provider: zone.provider, code: code },
        });
        return report.error(said);
      }
      // Everything else leaves the credential unjudged: a throttled
      // provider, a reply this client could not read, a name that did
      // not resolve. The token is not reported as bad, because nothing
      // here has heard the provider say so.
      await auditActor.record({
        action:   "blamepost.dns.credential_verified",
        outcome:  "failure",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "volume", id: config.dataDir },
        metadata: { provider: zone.provider, code: code || null },
      });
      return report.error("the " + zone.provider + " API did not answer whether this token " +
        "is live: " + said + " The token has not been shown to be bad; nothing here reached " +
        "the provider to ask. Run this again once the provider answers.");
    }

    var noted = await auditActor.record({
      action:   "blamepost.dns.credential_verified",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   flags.reason,
      resource: { kind: "volume", id: config.dataDir },
      metadata: { provider: zone.provider, tokenId: verdict.id },
    });
    return _emit(report, flags, verdict, [
      "The " + zone.provider + " API reports this server's sealed token is active" +
        (verdict.id === null ? "." : " (" + verdict.id + ")."),
      "  A token that is active is not a token that may write. The provider does not report",
      "  scope here, so whether it can edit a particular zone is answered by",
      "  `blamepost zone preview <domain> --reason <text>`, which reads that zone with it.",
    ].concat(noted ? [] : [
      "  The audit trail has no row for this. The answer above stands either way.",
    ]));
  } finally {
    if (zone !== null) zone.close();
    await store.close();
  }
}

// The credential half. It writes the data volume, so it runs with the
// server stopped and never falls back to a read-only copy: a token
// sealed into a copy nothing keeps is a token the operator believes they
// installed.
async function _cmdZoneToken(report, config, flags, positionals) {
  var action = positionals[1];
  if (action !== "set" && action !== "clear") return report.usage(USAGE_ZONE);
  if (!flags.reason) {
    return report.error("give --reason. Installing or erasing the credential that edits " +
      "this server's DNS is recorded in the audit trail, and a row with no reason answers " +
      "nothing later about who changed it or why.", 2);
  }

  var read = null;
  if (action === "set") {
    if (!flags["token-file"]) {
      return report.error("give --token-file. The token is read from a file rather than " +
        "from the command line, because a command line is in the shell history and in the " +
        "process list.", 2);
    }
    read = _tokenFrom(report, flags);
    if (read.code !== undefined) return read.code;
  } else if (flags.confirm !== true) {
    return report.error("give --confirm. Erasing the sealed token stops this server from " +
      "editing any zone, and it does not revoke the token at the provider: whoever holds a " +
      "copy, including one inside a backup bundle taken while it was here, can still edit " +
      "the zone. Revoke it at the provider as well.", 2);
  }

  // Opened writable, and never as a snapshot: sealing needs the volume's
  // vault open and the row has to outlive this process.
  var store = await storeModule.open(config);
  try {
    // The namespace the rows below are written under. An action under a
    // namespace nothing registered is refused by the audit layer and
    // dropped without a word, so it is registered here rather than
    // relied on from whichever other subsystem happened to run first.
    b.audit.registerNamespace(AUDIT_NAMESPACE);
    if (action === "set") {
      var stored = await blamepost.dns.storeToken(config, read.token);
      var noted = await auditActor.record({
        action:   "blamepost.dns.credential_set",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "volume", id: config.dataDir },
        metadata: { path: stored.path, from: read.path },
      });
      return _emit(report, flags, { path: stored.path, recorded: noted }, [
        "Sealed the provider token onto this volume at " + stored.path + ".",
        "  It opens only on this volume: a copy taken to another one will not unseal, and",
        "  a backup bundle taken from now on carries it.",
        "  Delete " + read.path + ", which still holds the token in the clear.",
      ].concat(config.zoneProvider === configModule.ZONE_PROVIDER_NONE ? [
        "  BLAMEPOST_ZONE_PROVIDER still names no provider, so nothing reads this yet.",
      ] : []).concat(noted ? [] : [
        "  The audit trail has no row for this. The credential is installed either way.",
      ]));
    }

    var cleared = blamepost.dns.clearToken(config);
    // A clear over a volume that held nothing is a success and not a
    // failure: what was asked for is true afterwards either way, and
    // whether there was something to erase is a fact about the volume
    // that the row carries as `held`. Filing it as a failure would put a
    // failure row on the trail for a correct no-op, which is noise for
    // whoever is alerting on failures.
    var clearNoted = await auditActor.record({
      action:   "blamepost.dns.credential_cleared",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   flags.reason,
      resource: { kind: "volume", id: config.dataDir },
      metadata: { path: cleared.path, held: cleared.removed },
    });
    return _emit(report, flags, cleared, (cleared.removed
      ? ["Erased the sealed provider token at " + cleared.path + ".",
        "  This server can no longer edit a zone.",
        "  Erasing it here revokes nothing. Revoke the token at the provider as well:",
        "  every backup bundle taken while it was on this volume still carries it."]
      : ["This volume held no sealed provider token at " + cleared.path + ".",
        "  Nothing was erased. A token supplied as BLAMEPOST_ZONE_API_TOKEN is not on the",
        "  volume and is not what this verb reaches; unset the variable instead."])
      .concat(clearNoted ? [] : [
        "  The audit trail has no row for this.",
      ]));
  } finally {
    await store.close();
  }
}

// ---- credential -------------------------------------------------------------

// The two windows an operator writes in a unit the registry does not
// hold, derived from the registry's own bounds rather than written out
// again. A refusal computed from these names the number the operator
// typed; one computed from the milliseconds underneath names a number
// they never wrote.
var MAX_GRACE_HOURS   = credentialsModule.MAX_GRACE_MS  / TIME.hours(1);
var MIN_WINDOW_MINUTES = credentialsModule.MIN_WINDOW_MS / TIME.minutes(1);
var MAX_WINDOW_MINUTES = credentialsModule.MAX_WINDOW_MS / TIME.minutes(1);

// The two trail actions that say what became of a credential's ceiling.
// The first is filed by the submission listener when a message was
// refused for crossing one; the second by the registry when an operator
// gave a window back. Spelled here as the strings they are so a reader
// can grep for either in `blamepost audit read --action`.
var CEILING_REACHED_ACTION  = "blamepost.mail.listeners.sending_credential_ceiling_reached";
var CEILING_RELEASED_ACTION = "domain.sending_credential_ceiling_released";

// How many rows of each kind one reading takes, and the most an operator
// may ask for. Both actions are narrow, so a default this size covers a
// credential that has been crossing its ceiling all morning, and the
// answer says when a read came back full rather than presenting a
// truncated list as the whole of it.
var CEILING_TRAIL_DEFAULT_ROWS = 20;
var CEILING_TRAIL_MAX_ROWS     = 500;

// A whole number of one unit, converted into the milliseconds the
// registry takes. The bounds are stated in the unit the operator wrote,
// because a refusal quoting milliseconds is a refusal about a number
// nobody typed.
function _durationFrom(report, raw, name, low, high, perUnit) {
  if (raw === undefined || raw === null) return { ms: undefined };
  if (typeof raw !== "number" || !isFinite(raw) || Math.floor(raw) !== raw ||
      raw < low || raw > high) {
    return { code: report.error("--" + name + " takes a whole number between " + low +
      " and " + high + ", and was given " + JSON.stringify(raw) + ".", 2) };
  }
  return { ms: perUnit(raw) };
}

// When a credential stops working. Absent means the registry's own
// default, the word `never` means the operator has decided to watch this
// one by hand, and anything else is a moment.
function _expiresFrom(report, raw) {
  if (raw === undefined || raw === null) return { value: undefined };
  if (String(raw).trim().toLowerCase() === "never") return { value: null };
  var moment = _momentFrom(report, raw, "expires");
  if (moment.code !== undefined) return { code: moment.code };
  return { value: moment.ms };
}

// What state a credential is in, in one word, read off the row rather
// than off any flag. A record whose keyed binding no longer holds is its
// own state and not a variety of live: the policy an operator would read
// off it is gone, and `verify` refuses it.
function _credentialState(record, nowMs) {
  if (!record.bindingHolds) return "unreadable";
  if (typeof record.revokedAt === "number") return "revoked";
  if (typeof record.expiresAt === "number" && record.expiresAt <= nowMs) return "expired";
  return "live";
}

// Where a credential's bounces are going, in one clause. The reading is
// resolved on every read rather than stored, so this is the only place an
// archived bounce mailbox shows up at all.
function _returnPathClause(record) {
  if (record.returnPathDeliverable === true) {
    return "reaching " + record.bounceMailbox;
  }
  var lands = (record.returnPathDeliversTo || []).join(", ");
  return "NOT reaching " + (record.bounceMailbox || "its mailbox") + ": " +
    (record.returnPathReason || "unknown") +
    (lands.length > 0 ? ", it lands at " + lands : ", it reaches no mailbox");
}

// The exposure the token has, said where the token is printed. It is the
// mirror of the token file `zone token set` reads: there the risk is the
// shell history and the process list, and here it is the terminal the
// value was written to.
function _tokenLines(token, id) {
  return [
    "  token: " + token,
    "  That is the only time this token is printed. It cannot be recovered: the volume",
    "  holds a digest of it and nothing here returns it again.",
    "  It is not written to a file and not recorded in the audit trail, so this terminal",
    "  and its scrollback are where it is exposed. Copy it into wherever the application",
    "  keeps its secrets, then clear the scrollback.",
    "  A token that has been lost is replaced with `blamepost credential rotate " + id +
      " --reason <text>`.",
  ];
}

function _credentialLines(record) {
  var state = _credentialState(record, Date.now());
  if (!record.bindingHolds) {
    return [
      record.id + "  " + state,
      "  domain claimed: " + (record.storedDomain || "none recorded"),
      "  This credential's stored policy does not match the keyed digest beside it, so this",
      "  server cannot say which domain it speaks for or what it may send as, and `verify`",
      "  refuses it. The row was edited on the volume, or written by something other than",
      "  this server. Remove it with `blamepost credential remove " + record.id +
        " --destroy --reason <text>`.",
    ];
  }
  return [
    record.id + "  " + state,
    "  domain:          " + record.domain,
    "  created:         " + _day(record.createdAt),
    "  expires:         " + (record.expiresAt === null ? "never" : _day(record.expiresAt)),
    "  last used:       " + (record.lastUsedAt === null ? "never" : _day(record.lastUsedAt)),
    "  revoked:         " + (record.revokedAt === null ? "no" : _day(record.revokedAt)),
    "  bounce mailbox:  " + record.bounceMailbox,
    "  return path:     " + record.returnPath,
    "                   " + _returnPathClause(record),
    "  may not send as: " + (record.refusedLocalParts.length === 0
      ? "nothing, so it may send as every address in " + record.domain
      : record.refusedLocalParts.join(", ")),
    "  ceilings:        " + record.maxMessages + " message(s) and " +
      record.maxRecipients + " recipient(s) every " +
      (record.windowMs / TIME.minutes(1)) + " minute(s)",
    "  The counters those ceilings are measured against live in the process that is",
    "  sending, so they are not readable from here and this command does not print them.",
    "  `blamepost credential ceiling " + record.id + "` reads what the server recorded on",
    "  the trail each time one of them was crossed.",
  ];
}

// What the trail holds about one credential's ceiling, read as two narrow
// queries rather than one wide one.
//
// Each query names an action, which is what keeps a busy trail from
// pushing these rows off the end of a wider read: a credential's
// crossings are rare beside its verifies, and a read of everything its
// identifier appears on would return the verifies. The credential is
// matched on the metadata each row carries rather than on the actor,
// because the two actions disagree about the actor by design. A crossing
// is filed against the credential that was refused; a release is filed
// against the operator who lifted it, over the domain.
//
// `b.audit.query` files a row for every read of the trail, so this is
// two rows per invocation and not one per action per credential. That is
// the reason the whole answer is taken in one pass here instead of a
// query behind each line that prints.
async function _ceilingTrail(id, limit) {
  async function rowsFor(action) {
    var rows = await b.audit.query({ action: action, order: "desc", limit: limit });
    return {
      // Whether the read came back full. A truncated list of crossings is
      // missing the OLDEST ones, which is where a credential that has
      // been climbing all morning started, so the answer says so rather
      // than reading as the complete account.
      truncated: rows.length >= limit,
      rows: rows.filter(function (row) {
        var detail = _auditMetadata(row);
        return detail.credentialId === id;
      }),
    };
  }
  return {
    reached:  await rowsFor(CEILING_REACHED_ACTION),
    released: await rowsFor(CEILING_RELEASED_ACTION),
  };
}

// The metadata an audit row carries, as an object. A row whose metadata
// is absent or is not an object answers as an empty one: this reads the
// trail to print it, and a malformed row is a row that names no
// credential rather than a reason to abandon the whole reading.
function _auditMetadata(row) {
  if (!row || typeof row.metadata !== "string" || row.metadata.length === 0) return {};
  var parsed;
  try { parsed = JSON.parse(row.metadata); }
  catch (_e) { return {}; }
  return (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed))
    ? parsed : {};
}

// A count off an audit row, or a named absence. The numbers on these rows
// are written by the layer that files them and read here, which is two
// places for a field name to be spelled, so a row that carries the name
// this reader does not expect prints as a count nobody recorded rather
// than as the word `undefined` beside a real moment.
function _recordedCount(value) {
  return typeof value === "number" && isFinite(value) ? String(value) : "an unrecorded number of";
}

// One recorded crossing, in the line an operator reads. Which of the two
// ceilings was crossed is named, because they are set for different
// reasons and raising the wrong one changes nothing.
function _ceilingReachedLine(row) {
  var detail = _auditMetadata(row);
  return "  " + _moment(Number(row.recordedAt)) + "  " +
    (detail.recipientsExceeded === true ? "recipient" : "message") + " ceiling  " +
    "sent " + _recordedCount(detail.messages) + " message(s) to " +
    _recordedCount(detail.recipients) + " recipient(s) against ceilings of " +
    _recordedCount(detail.maxMessages) + " and " + _recordedCount(detail.maxRecipients);
}

function _ceilingReleasedLine(row) {
  var detail = _auditMetadata(row);
  return "  " + _moment(Number(row.recordedAt)) + "  window given back  " +
    "held " + _recordedCount(detail.messages) + " message(s) and " +
    _recordedCount(detail.recipients) + " recipient(s)" +
    (row.reason ? "  reason: " + _headerText(row.reason, "") : "");
}

async function cmdCredential(flags, positionals) {
  var report = _reporter("credential");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_CREDENTIAL);
  var unread = _refuseUnread(report, "credential", verb, flags, positionals);
  if (unread !== 0) return unread;
  if (!Object.prototype.hasOwnProperty.call(VERB_SURFACE.credential, verb)) {
    return report.usage(USAGE_CREDENTIAL);
  }
  if (!positionals[1]) return report.usage(USAGE_CREDENTIAL);

  // Every verb that changes a credential wants a reason, and the refusal
  // arrives before a volume is opened so an operator who forgot one is
  // not told about a server that is running instead.
  var changes = ["add", "rotate", "revoke", "remove", "refusals"];
  if (changes.indexOf(verb) !== -1 && !flags.reason) {
    return report.error("give --reason. A sending credential can send as every address in a " +
      "hosted domain, so issuing, rotating, withdrawing or widening one is an operator " +
      "action, and a row with no reason answers nothing later about why it happened.", 2);
  }

  var domain = null;
  if (verb === "list" || verb === "bounces" || verb === "add") {
    var shape = _readDomainArg(report, positionals[1]);
    if (shape.code !== undefined) return shape.code;
    domain = shape.domain;
  }

  var expires = { value: undefined };
  var window = { ms: undefined };
  var grace = { ms: undefined };
  var localParts = _messageIds(flags["local-part"]);

  if (verb === "add") {
    if (!flags["bounce-to"]) {
      return report.error("give --bounce-to. A credential has to name a mailbox on this " +
        "server for its bounces, and it has to exist and be in service before the credential " +
        "is written: one pointing at nothing discards every bounce at the door while the " +
        "application goes on sending, and nobody is told.", 2);
    }
    expires = _expiresFrom(report, flags.expires);
    if (expires.code !== undefined) return expires.code;
    window = _durationFrom(report, flags["window-minutes"], "window-minutes",
      MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES, TIME.minutes);
    if (window.code !== undefined) return window.code;
  }

  if (verb === "rotate") {
    grace = _durationFrom(report, flags["grace-hours"], "grace-hours",
      0, MAX_GRACE_HOURS, TIME.hours);
    if (grace.code !== undefined) return grace.code;
  }

  // Refused at the argument rather than carried into the query, so a
  // number the trail reader cannot use is a refusal naming the bounds an
  // operator typed against instead of a reading over a row count nobody
  // asked for.
  var trailRows = CEILING_TRAIL_DEFAULT_ROWS;
  if (verb === "ceiling" && flags.limit !== undefined) {
    if (typeof flags.limit !== "number" || !isFinite(flags.limit) ||
        Math.floor(flags.limit) !== flags.limit ||
        flags.limit < 1 || flags.limit > CEILING_TRAIL_MAX_ROWS) {
      return report.error("--limit takes a whole number of rows between 1 and " +
        CEILING_TRAIL_MAX_ROWS + ".", 2);
    }
    trailRows = flags.limit;
  }

  if (verb === "remove" && flags.destroy !== true) {
    return report.error("give --destroy. Removing a credential takes its row off the volume, " +
      "and the identifier on every audit row it produced stops resolving to anything. To " +
      "stop the credential working and keep the row, run `blamepost credential revoke " +
      positionals[1] + " --reason <text>` instead.", 2);
  }

  // A refusal list is replaced whole, so a call that names none is
  // ambiguous between "leave it alone" and "refuse nobody", and the
  // second is a widening to every address in the domain. The two are
  // separated rather than guessed at, and the widening is the one that
  // takes a confirmation: what it opens up is not on the command line.
  if (verb === "refusals") {
    if (flags.clear === true && localParts.length > 0) {
      return report.error("--clear and --local-part ask for different lists. --clear leaves " +
        "the credential refusing nothing; --local-part names the complete list it refuses. " +
        "Give one or the other.", 2);
    }
    if (flags.clear !== true && localParts.length === 0) {
      return report.error("give --local-part, naming the complete list this credential may " +
        "not send as, or --clear to leave it refusing nothing. The list is replaced rather " +
        "than added to, so a call naming none of it would be a widening nobody wrote down.",
      2);
    }
    if (flags.clear === true && flags.confirm !== true) {
      return report.error("give --confirm. Clearing the list leaves this credential able to " +
        "send as every address in its domain, postmaster and abuse among them, and that set " +
        "is not on the command line. Name the addresses to keep refusing with --local-part " +
        "instead, or confirm the widening.", 2);
    }
  }

  var config = _configFrom(flags);
  var store = await _openForReporting(config, "credential", verb);
  // The registry the open already built, rather than a second one
  // composed here. The ceiling counters live in the instance, so two of
  // them in one process count a credential's traffic separately and
  // neither reaches the ceiling the operator set.
  var registry = store.credentials;
  try {
    if (verb === "list") {
      var rows = await registry.list({
        domain:         domain,
        includeRevoked: flags["include-revoked"] === true,
        includeExpired: flags["include-expired"] === true,
      });
      var listedAt = Date.now();
      return _emit(report, flags, rows, rows.length === 0
        ? ["No sending credentials for " + domain + "." +
          (flags["include-revoked"] || flags["include-expired"] ? "" :
            " Revoked and expired ones are left out; --include-revoked and --include-expired" +
            " add them.")]
        : [_column("id", 20) + _column("state", 12) + _column("created", 12) +
            _column("expires", 12) + "bounces"]
          .concat(rows.map(function (row) {
            return _column(row.id, 20) +
              _column(_credentialState(row, listedAt), 12) +
              _column(_day(row.createdAt), 12) +
              _column(row.expiresAt === null ? "never" : _day(row.expiresAt), 12) +
              _returnPathClause(row);
          })));
    }

    if (verb === "show") {
      var one = await registry.show(positionals[1]);
      if (!one) {
        return report.error("no sending credential with id " +
          JSON.stringify(positionals[1]) + " is on this volume. `blamepost credential list " +
          "<domain>` prints the ids one domain holds.");
      }
      return _emit(report, flags, one, _credentialLines(one));
    }

    if (verb === "bounces") {
      var reported = await registry.returnPathReport({ domain: domain });
      return _emit(report, flags, reported, [
        domain + " returns its bounces to " + reported.returnPathAddress + ".",
        "  " + _plural(reported.credentials, "live credential", "live credentials") +
          " use it, each with a tag of its own so the mailbox can tell whose bounce it is.",
      ].concat(reported.unreachable.length === 0
        ? ["  Every one of them is receiving its bounces."]
        : reported.unreachable.map(function (entry) {
          return "  " + entry.credentialId + " named " + entry.bounceMailbox +
            "; " + entry.returnPath + " " +
            (entry.returnPathDeliversTo.length === 0
              ? "reaches no mailbox"
              : "lands at " + entry.returnPathDeliversTo.join(", ")) +
            " (" + entry.returnPathReason + ")";
        }).concat([
          "  Each of those credentials is still sending, and every bounce it earns is",
          "  refused at the door. Put the mailbox back in service, or issue a replacement",
          "  credential naming one that is.",
        ])));
    }

    if (verb === "ceiling") {
      // The reading refuses a credential this server cannot read rather
      // than answering about ceilings taken off a row somebody edited, so
      // the refusal is carried across as itself and the trail is not read
      // for an identifier that names nothing.
      var reading;
      try {
        reading = await registry.counters.read(positionals[1]);
      } catch (readErr) {
        return report.error((readErr && readErr.message) || String(readErr));
      }
      b.audit.registerNamespace(AUDIT_NAMESPACE);
      // The trail is flushed first for the reason `audit read` flushes
      // it: a crossing recorded moments ago is still in the buffer, and
      // an answer taken without this reports the incident an operator is
      // looking at as one that never happened.
      await b.audit.flush();
      var trail = await _ceilingTrail(positionals[1], trailRows);
      var answer = {
        reading:  reading,
        reached:  trail.reached.rows,
        released: trail.released.rows,
      };
      return _emit(report, flags, answer, [
        reading.credentialId + "  " + reading.domain,
        "  ceilings:    " + reading.maxMessages + " message(s) and " +
          reading.maxRecipients + " recipient(s) every " +
          (reading.windowMs / TIME.minutes(1)) + " minute(s)",
        "  window now:  " + reading.messages + " message(s) and " +
          reading.recipients + " recipient(s)" +
          (reading.exceeded ? ", which is at or past a ceiling" : ", which is inside both"),
        "  This command counted nothing against that window. The counters a running server",
        "  measures against live in the process that is sending, and this command cannot",
        "  open the volume while the server holds it, so the numbers above are the ones the",
        "  next start begins from rather than the ones that refused a message. The rows",
        "  below are what the server recorded while it was running.",
        "",
      ].concat(trail.reached.rows.length === 0
        ? ["No message has been refused for crossing a ceiling on this credential."]
        : [_plural(trail.reached.rows.length, "crossing", "crossings") + ", newest first" +
            (trail.reached.truncated ? " (the read came back full, so the oldest are " +
              "missing; --limit takes more)" : "")]
          .concat(trail.reached.rows.map(_ceilingReachedLine)))
        .concat(trail.released.rows.length === 0
          ? []
          : [""].concat([_plural(trail.released.rows.length,
            "window given back", "windows given back") + ", newest first" +
            (trail.released.truncated ? " (the read came back full)" : "")])
            .concat(trail.released.rows.map(_ceilingReleasedLine)))
        .concat(trail.reached.rows.length === 0 ? [] : [
          "",
          "  A crossing defers the message rather than losing it. The refusal is 452 4.5.3",
          "  on submission and 429 over the browser port, and the window is rolling, so it",
          "  drains without anything being done to it. A credential crossing a ceiling it",
          "  never used to reach is the shape a stolen one makes. Replace its secret with",
          "  `blamepost credential rotate " + reading.credentialId + " --reason <text>`.",
        ]));
    }

    if (verb === "add") {
      var made = await registry.create({
        domain:        domain,
        bounceMailbox: flags["bounce-to"],
        reason:        flags.reason,
        expiresAt:     expires.value,
        maxMessages:   flags["max-messages"],
        maxRecipients: flags["max-recipients"],
        windowMs:      window.ms,
      });
      return _emit(report, flags, made, [
        "Issued " + made.id + " for " + made.domain + ".",
      ].concat(_tokenLines(made.token, made.id)).concat([
        "",
        "  return path: " + made.returnPath,
        "  Put that in the envelope sender of everything this credential sends, so its",
        "  bounces come back to " + made.bounceMailbox + " rather than to an address in " +
          made.domain + " that holds no mailbox.",
        "  expires: " + (made.expiresAt === null ? "never" : _day(made.expiresAt)),
        "  may not send as: " + (made.refusedLocalParts.length === 0
          ? "nothing"
          : made.refusedLocalParts.join(", ")),
        "  ceilings: " + made.maxMessages + " message(s) and " + made.maxRecipients +
          " recipient(s) every " + (made.windowMs / TIME.minutes(1)) + " minute(s)",
      ]));
    }

    if (verb === "rotate") {
      var rotated = await registry.rotate({
        id:      positionals[1],
        reason:  flags.reason,
        graceMs: grace.ms,
      });
      return _emit(report, flags, rotated, [
        "Rotated " + rotated.id + " for " + (rotated.domain || "an unreadable domain") + ".",
      ].concat(_tokenLines(rotated.token, rotated.id)).concat([
        "",
        rotated.priorSecretUntil === null
          ? "  The previous secret stopped working now. Nothing named a window, which is the" +
            " right answer when the reason to rotate is that somebody else holds the old one."
          : "  The previous secret keeps working until " +
            new Date(rotated.priorSecretUntil).toISOString() + ". A verdict produced by it" +
            " says so, so you can see whether the application has finished migrating.",
        "  The ceilings are not reset. Volume already sent is volume already sent.",
      ]));
    }

    if (verb === "revoke") {
      var stopped = await registry.revoke({ id: positionals[1], reason: flags.reason });
      return _emit(report, flags, stopped, [
        (stopped.revoked
          ? "Revoked " + stopped.id
          : "Credential " + stopped.id + " was already revoked") +
          " for " + (stopped.domain || "an unreadable domain") + ".",
        "  Its row is kept, so the identifier on every audit row it produced still resolves.",
        stopped.returnPathAliasRemoved
          ? "  The domain's return path alias went with it: this was the last credential using" +
            " the one this server wrote."
          : "  The domain's return path alias is left in place, because it is shared with the" +
            " domain's other credentials or was not written by this server.",
        "  `blamepost credential remove " + stopped.id + " --destroy --reason <text>` takes" +
          " the row as well, which is rarely what you want.",
      ]);
    }

    if (verb === "remove") {
      var erased = await registry.remove({
        id: positionals[1], destroy: true, reason: flags.reason,
      });
      return _emit(report, flags, erased, [
        "Erased " + erased.id + " for " + (erased.domain || "an unreadable domain") + ".",
        "  Every audit row naming that identifier now names something nothing can look up.",
        erased.returnPathAliasRemoved
          ? "  The domain's return path alias went with it: this was the last credential using" +
            " the one this server wrote."
          : "  The domain's return path alias is left in place, because it is shared with the" +
            " domain's other credentials or was not written by this server.",
      ]);
    }

    // refusals
    var narrowed = await registry.setRefusedLocalParts({
      id:         positionals[1],
      localParts: flags.clear === true ? [] : localParts,
      reason:     flags.reason,
    });
    return _emit(report, flags, narrowed, narrowed.refusedLocalParts.length === 0
      ? [narrowed.id + " may now send as every address in " + narrowed.domain + ".",
        "  Nothing on this credential refuses postmaster or abuse any more."]
      : [narrowed.id + " may not send as: " + narrowed.refusedLocalParts.join(", ") + ".",
        "  Every other local part in " + narrowed.domain + " is one it may write as."]);
  } finally {
    // Closing the store is what gives the registry's counter cache back,
    // because the store is what built it. A timer left armed holds the
    // event loop and the command never exits.
    await store.close();
  }
}

// ---- reports ----------------------------------------------------------------

// The period a reporting verb reads when the operator names neither end.
// A DMARC record asks receivers for a report a day, so thirty of them is
// a month of counting.
var REPORTS_WINDOW_MS = TIME.days(30);

// How many rows each list inside one answer prints when the operator
// asks for no number.
var REPORTS_DEFAULT_LIMIT = 10;

// How many rows one answer reads before it stops and says that it
// stopped. A period holds a few reports per reporter per day and one
// record per sending address inside each, so both sit far above an
// ordinary volume, and what they bound is a peer deciding how much
// memory a listing costs.
var REPORTS_MAX_REPORT_ROWS = 5000;
var REPORTS_MAX_RECORD_ROWS = 20000;

// The longest report id this carries to the database. An id is a row
// identifier this server minted, so a longer one is a mistyped line
// rather than a row that exists.
var REPORT_ID_MAX_CHARS = 200;

// The range a `Date` holds. A moment outside it prints as the number it
// is rather than throwing on the way to the screen: it arrived on a
// command line, and a listing that dies on it says less than one that
// shows it.
var MAX_MOMENT_MS = 8640000000000000;

function _moment(ms) {
  if (typeof ms !== "number" || !isFinite(ms) || Math.abs(ms) > MAX_MOMENT_MS) {
    return String(ms);
  }
  return new Date(ms).toISOString();
}

// The range a reporting verb reads over. Either end may be given and the
// other is derived, so `--from` alone reads from that moment to now and
// `--to` alone reads the thirty days before it. A range whose start is
// after its end is refused rather than answered, because the answer is
// an empty reading and an empty reading is what a domain nobody reports
// on looks like.
function _reportsWindow(report, flags) {
  var until = Date.now();
  if (flags.to !== undefined) {
    var end = _momentFrom(report, flags.to, "to");
    if (end.code !== undefined) return { code: end.code };
    until = end.ms;
  }
  var since = until - REPORTS_WINDOW_MS;
  if (flags.from !== undefined) {
    var start = _momentFrom(report, flags.from, "from");
    if (start.code !== undefined) return { code: start.code };
    since = start.ms;
  }
  if (since > until) {
    return { code: report.error("--from is " + _moment(since) + " and --to is " +
      _moment(until) + ", so the range covers no time at all and every domain would " +
      "answer as one nobody reports on.", 2) };
  }
  return { since: since, until: until };
}

// How many rows each list prints. The shape is checked here and the
// ceiling is not: the two listings this verb reads hold their own bound
// and refuse above it in their own words, so a number written here would
// be a second copy of theirs that stops agreeing the day one of them
// moves. A number that is not a whole one above zero never reaches them
// as a bound at all, which is why that half is checked.
function _reportsLimit(report, flags) {
  if (flags.limit === undefined) return { limit: REPORTS_DEFAULT_LIMIT };
  if (typeof flags.limit !== "number" || !Number.isInteger(flags.limit) || flags.limit < 1) {
    return { code: report.error("--limit is " + JSON.stringify(String(flags.limit)) +
      ", and it has to be a whole number of rows above zero.", 2) };
  }
  return { limit: flags.limit };
}

// The stored aggregate reports whose reporting period overlaps a range.
// The two comparisons are the pair the store's own reading uses, so a
// report is in this answer exactly when its records are in that one.
function _reportRowQuery(domain, since, until) {
  var query = b.db.from(storeTables.DMARC_REPORTS)
    .where("windowEnd", ">=", since)
    .where("windowBegin", "<=", until);
  return domain === null ? query : query.where("policyDomain", "=", domain);
}

// One stored report as an answer carries it. `counted` is published
// beside the verdict rather than left for a reader to derive, because
// deriving it means knowing which of the recorded verdicts is the one
// that counts, and a reader that guesses wrong reads an excluded report
// as evidence.
//
// `organization` is the registered domain the carrier passed DMARC for,
// and null on a report that counts toward no organization. `orgName` is
// the name the report gave itself, which whoever sent the report wrote.
function _reportRow(row) {
  return {
    id:             row._id,
    organization:   _recordedOrganization(row),
    orgName:        row.orgName,
    reportId:       row.reportId,
    windowBegin:    row.windowBegin,
    windowEnd:      row.windowEnd,
    receivedAt:     row.receivedAt,
    records:        row.storedCount,
    refusedRecords: row.refusedCount,
    evidence:       row.evidence,
    counted:        row.evidence === storeTables.REPORT_EVIDENCE_VERIFIED,
  };
}

// The organization a report row counts toward, or null when the row
// recorded none.
function _recordedOrganization(row) {
  var value = row.verifiedOrgDomain;
  return (typeof value === "string" && value !== storeTables.REPORT_ORGANIZATION_NONE)
    ? value
    : null;
}

// One domain's reading: the counting the store answers with, the reports
// behind it, and the sending addresses that failed both alignments.
//
// `rows` is that domain's report rows, read once for every domain at the
// call site so a listing over twenty domains is one query rather than
// twenty.
async function _domainReading(store, domain, range, limit, wide, rows) {
  var windows = store.reports.rollup({
    domain:                 domain,
    since:                  range.since,
    until:                  range.until,
    includeUnauthenticated: wide,
  });

  var counted = 0;
  var aligned = 0;
  var unauthenticated = 0;
  windows.forEach(function (entry) {
    counted += entry.counted;
    aligned += entry.aligned;
    unauthenticated += entry.unauthenticated;
  });

  // The two listings the store answers, rather than a second grouping
  // over the same rows here. Both apply the same evidence condition the
  // counting above applies, so the addresses and the organizations
  // printed are the ones the totals were computed over, and the sender
  // listing records that somebody unsealed sending addresses, which a
  // grouping written here would not.
  var failing = await store.reports.failingSources({
    domain:                 domain,
    since:                  range.since,
    until:                  range.until,
    limit:                  limit,
    includeUnauthenticated: wide,
  });
  var heard = store.reports.reporters({
    domain:                 domain,
    since:                  range.since,
    until:                  range.until,
    limit:                  limit,
    includeUnauthenticated: wide,
  });

  // What the report rows say about themselves, which neither listing
  // above answers: the verdict each one carries, and the ones that
  // stored no record at all.
  var verdicts = Object.create(null);
  var storingNothing = 0;
  rows.forEach(function (row) {
    verdicts[row.evidence] = (verdicts[row.evidence] || 0) + 1;
    if (row.storedCount === 0) storingNothing += 1;
  });

  return {
    domain:                  domain,
    hosted:                  store.domains.get(domain) !== null,
    since:                   range.since,
    until:                   range.until,
    includesUnauthenticated: wide,
    counted:                 counted,
    aligned:                 aligned,
    unaligned:               counted - aligned,
    // The volume the three numbers above leave out, published beside
    // them on both readings. A total that is quietly short of what
    // arrived is the one an operator acts on without knowing to ask.
    unauthenticated:              unauthenticated,
    failingSourceCount:           failing.total,
    failingSourcesShown:          failing.sources,
    failingSourcesTruncated:      failing.truncated,
    failingSourcesUnauthenticated: failing.unauthenticated,
    organizationCount:            heard.total,
    organizations:                heard.reporters,
    organizationsTruncated:       heard.truncated,
    unauthenticatedReports:       heard.unauthenticatedReports,
    unattributedReports:          heard.unattributedReports,
    windows:                      windows,
    reports:                      rows.length,
    reportsShown:                 rows.slice(0, limit).map(_reportRow),
    reportsStoringNothing:        storingNothing,
    evidence:                     verdicts,
  };
}

// What one domain's reading looks like at a terminal, in the order the
// question is asked: how much mail, how much of it aligned, what was
// left out of that arithmetic, who is failing, and who reported at all.
function _domainLines(reading) {
  var lines = [reading.domain + (reading.hosted ? "" : "  (this server no longer hosts it)")];
  lines.push("  " + _moment(reading.since) + " to " + _moment(reading.until));

  if (reading.reports === 0) {
    lines.push("  No aggregate report covering this period has arrived for this domain.");
    lines.push("  A domain nobody reports on and a domain nobody spoofs read the same here, so");
    lines.push("  this is the absence rather than a clean bill. Check the rua= address in the");
    lines.push("  domain's DMARC record, and that mail sent to it reaches this server.");
    return lines;
  }

  lines.push("  counted " + reading.counted + "   aligned " + reading.aligned +
    "   unaligned " + reading.unaligned);
  if (reading.includesUnauthenticated) {
    lines.push("  This reading counts the reports nobody authenticated as well, so nothing");
    lines.push("  above rests on the carrier having been authenticated: " +
      _plural(reading.unauthenticated, "message", "messages") + " of that total");
    lines.push("  came from a report anybody who can send mail to a published reporting");
    lines.push("  address could have written.");
  } else if (reading.unauthenticated > 0) {
    lines.push("  " + _plural(reading.unauthenticated, "message", "messages") +
      " sit outside that arithmetic, in reports whose carrier this server could not");
    lines.push("  authenticate. Anybody who can send mail to a published reporting address can");
    lines.push("  write one, so they are counted here and nowhere else. Fold them in with");
    lines.push("  `blamepost reports list --include-unauthenticated`.");
  }

  if (reading.failingSourceCount === 0) {
    lines.push("  No sending address failed both alignments.");
  } else {
    lines.push("  " + _plural(reading.failingSourceCount, "sending address",
      "sending addresses") + " failed both alignments, largest first:");
    reading.failingSourcesShown.forEach(function (source) {
      lines.push("    " + _column(source.readable
        ? source.sourceIp
        : "(sealed, could not be opened)", 34) +
        _column(source.messages + " failed", 14) +
        _column(source.aligned + " aligned", 14) +
        "last seen " + _moment(source.lastSeen));
    });
    if (reading.failingSourcesTruncated) {
      lines.push("    " + (reading.failingSourceCount - reading.failingSourcesShown.length) +
        " more, not shown. Raise --limit to see them.");
    }
  }

  lines.push("  " + _plural(reading.organizationCount, "organization", "organizations") +
    " reported, each named by the registered domain its reports passed DMARC for:");
  reading.organizations.forEach(function (org) {
    lines.push("    " + _column(org.organization === null
      ? "(no authenticated domain)"
      : org.organization, 34) +
      _column(org.reports + " report(s)", 14) +
      _column(org.records + " record(s)", 14) +
      "most recent " + _moment(org.newestAt));
    lines.push("      the name its reports give: " + _headerText(org.orgName, "(unnamed)") +
      (org.names > 1
        ? " (" + (org.names - 1) + " other name" + (org.names === 2 ? "" : "s") +
          " also used)"
        : ""));
  });
  if (reading.organizationsTruncated) {
    lines.push("    " + (reading.organizationCount - reading.organizations.length) +
      " more, not shown. Raise --limit to see them.");
  }
  if (reading.unauthenticatedReports > 0) {
    lines.push("  " + _plural(reading.unauthenticatedReports, "report", "reports") +
      " arrived from a carrier this server could not authenticate" +
      (reading.includesUnauthenticated
        ? ", and the organizations"
        : ", and no organization"));
    lines.push(reading.includesUnauthenticated
      ? "  above include whoever those name."
      : "  is listed above on the strength of one.");
  }
  if (reading.unattributedReports > 0) {
    lines.push("  " + _plural(reading.unattributedReports, "report", "reports") +
      " in the totals arrived before this server recorded the domain a report passed");
    lines.push("  DMARC for. A report like that counts toward no organization.");
  }

  lines.push("  " + _plural(reading.reports, "aggregate report", "aggregate reports") +
    ", newest first:");
  reading.reportsShown.forEach(function (row) {
    lines.push("    " + _column(row.id, 38) +
      _column(row.organization === null
        ? "(no authenticated domain)"
        : row.organization, 32) +
      _column(row.records + " record(s)", 14) +
      _column(row.refusedRecords + " refused", 12) +
      (row.counted ? "counted" : "not counted: " + row.evidence));
  });
  if (reading.reports > reading.reportsShown.length) {
    lines.push("    " + (reading.reports - reading.reportsShown.length) +
      " more, not shown. Raise --limit to see them.");
  }
  if (reading.reportsStoringNothing > 0) {
    lines.push("  " + _plural(reading.reportsStoringNothing, "report", "reports") +
      " stored no record at all, so nothing in them reaches the counting above.");
    lines.push("  `blamepost reports show <id>` says how many records each one carried and how");
    lines.push("  many were refused when it was read.");
  }
  return lines;
}

// One report as `show` prints it, and the records it carried.
function _reportLines(row, records, recordTotal, shown) {
  var lines = [
    "Aggregate report " + row._id,
    "  about " + row.policyDomain + ", covering " + _moment(row.windowBegin) + " to " +
      _moment(row.windowEnd),
    "  counted as the organization " + (_recordedOrganization(row) === null
      ? "(none: no authenticated domain was recorded for it)"
      : _recordedOrganization(row) + ", the registered domain its carrier passed DMARC for"),
    "  the name the report gives itself: " + _headerText(row.orgName, "(unnamed)") +
      ", report id " + _headerText(row.reportId, "(unnamed)"),
    "  its contact mailbox: " + (row.reportEmail || "(none given)"),
    "  arrived here " + _moment(row.receivedAt),
    "  policy published in the zone at the time: p=" + (row.requestedPolicy || "(none)") +
      " sp=" + (row.subdomainPolicy || "(none)") +
      " adkim=" + (row.alignmentDkim || "(none)") +
      " aspf=" + (row.alignmentSpf || "(none)") +
      " pct=" + (row.samplePercent === null || row.samplePercent === undefined
        ? "(none)" : row.samplePercent) +
      " fo=" + (row.failureOptions || "(none)"),
    "  " + _plural(row.storedCount, "record", "records") + " stored, " +
      row.refusedCount + " refused when the report was read",
  ];

  if (row.evidence === storeTables.REPORT_EVIDENCE_VERIFIED) {
    lines.push("  This server authenticated the message that carried it, so it counts toward");
    lines.push("  the reading `blamepost reports list` prints.");
  } else {
    lines.push("  This server did not authenticate the message that carried it: " +
      row.evidence + ".");
    lines.push("  It is stored and it is not counted. A report is a document anybody who can");
    lines.push("  send mail to a published reporting address may write, so moving a policy on");
    lines.push("  one moves the policy for whoever wrote it.");
  }

  if (records.length === 0) {
    lines.push("");
    lines.push("  It carried no record this server could store.");
    return lines;
  }

  lines.push("");
  lines.push("  " + _column("sending address", 40) + _column("messages", 10) +
    _column("disposition", 14) + _column("dkim", 8) + _column("spf", 8) + "header from");
  records.forEach(function (record) {
    // The sending address is a sealed cell. A row whose cell will not
    // open still counts messages against a disposition, and printing the
    // absence rather than the word `null` is what says which of the two
    // an operator is looking at.
    lines.push("  " + _column(typeof record.sourceIp === "string" && record.sourceIp.length > 0
      ? record.sourceIp
      : "(sealed, could not be opened)", 40) +
      _column(String(record.messageCount), 10) +
      _column(record.disposition, 14) +
      _column(record.alignedDkim, 8) +
      _column(record.alignedSpf, 8) +
      (record.headerFrom || "(none)"));
  });
  if (recordTotal > shown) {
    lines.push("  " + (recordTotal - shown) +
      " more record(s), not shown. Raise --limit to see them.");
  }
  return lines;
}

async function cmdReports(flags, positionals) {
  var report = _reporter("reports");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_REPORTS);
  var unread = _refuseUnread(report, "reports", verb, flags, positionals);
  if (unread !== 0) return unread;
  if (verb !== "list" && verb !== "show" && verb !== "forget") {
    return report.usage(USAGE_REPORTS);
  }
  var config = _configFrom(flags);

  if (verb === "forget") {
    return await _cmdReportsForget(report, config, flags, positionals);
  }

  var limitRead = _reportsLimit(report, flags);
  if (limitRead.code !== undefined) return limitRead.code;
  var limit = limitRead.limit;

  if (verb === "show") {
    return await _cmdReportsShow(report, config, flags, positionals, limit);
  }

  var windowRead = _reportsWindow(report, flags);
  if (windowRead.code !== undefined) return windowRead.code;
  var range = { since: windowRead.since, until: windowRead.until };

  var wanted = null;
  if (flags.domain !== undefined) {
    var shape = _readDomainArg(report, flags.domain);
    if (shape.code !== undefined) return shape.code;
    wanted = shape.domain;
  }

  var store = await _openForReporting(config, "reports", "list");
  try {
    if (wanted !== null && store.domains.get(wanted) === null &&
        _reportRowQuery(wanted, 0, MAX_MOMENT_MS).count() === 0) {
      var hosted = store.domains.list().map(function (row) { return row.domain; });
      return report.error("this server does not host " + wanted + " and holds no report " +
        "about it, so there is nothing to read. Hosted domains: " +
        (hosted.length
          ? hosted.join(", ")
          : "none. Add one with `blamepost domain add <domain>`."), 2);
    }

    var total = _reportRowQuery(wanted, range.since, range.until).count();
    var rows = _reportRowQuery(wanted, range.since, range.until)
      .orderBy("receivedAt", "desc").limit(REPORTS_MAX_REPORT_ROWS).all();

    // Every domain worth an answer: the ones this server hosts, so a
    // domain nobody has reported on still gets a line saying so, and the
    // ones the rows name, so a domain that was removed while its reports
    // were still on the volume is not silently dropped.
    var byDomain = Object.create(null);
    rows.forEach(function (row) {
      if (!byDomain[row.policyDomain]) byDomain[row.policyDomain] = [];
      byDomain[row.policyDomain].push(row);
    });
    var names = [];
    if (wanted !== null) names.push(wanted);
    else {
      store.domains.list().forEach(function (row) {
        if (names.indexOf(row.domain) === -1) names.push(row.domain);
      });
      Object.keys(byDomain).forEach(function (name) {
        if (names.indexOf(name) === -1) names.push(name);
      });
    }
    names.sort();

    var wide = flags["include-unauthenticated"] === true;
    var readings = [];
    for (var n = 0; n < names.length; n += 1) {
      readings.push(await _domainReading(store, names[n], range, limit, wide,
        byDomain[names[n]] || []));
    }

    var lines = [];
    if (readings.length === 0) {
      lines.push("This server hosts no domain and holds no report, so there is nothing to");
      lines.push("read. Add a domain with `blamepost domain add <domain>` and publish its");
      lines.push("DMARC record with an rua= address that reaches this server.");
    }
    readings.forEach(function (reading, index) {
      if (index > 0) lines.push("");
      _domainLines(reading).forEach(function (line) { lines.push(line); });
    });
    if (total > rows.length) {
      lines.push("");
      lines.push("Read the newest " + rows.length + " of " + total + " report(s) in this " +
        "range. Narrow it with --from and --to for an answer over all of them.");
    }
    return _emit(report, flags, readings, lines);
  } finally {
    await store.close();
  }
}

async function _cmdReportsShow(report, config, flags, positionals, limit) {
  if (positionals[1] === undefined) return report.usage(USAGE_REPORTS);
  var wanted = String(positionals[1]).trim();
  if (wanted.length === 0 || wanted.length > REPORT_ID_MAX_CHARS) {
    return report.error("give the id of one aggregate report. `blamepost reports list` " +
      "prints them, and an id is a row identifier this server minted rather than the " +
      "identifier the reporting organization put in its own report.", 2);
  }

  var store = await _openForReporting(config, "reports", "show");
  try {
    var row = b.db.from(storeTables.DMARC_REPORTS).where({ _id: wanted }).first();
    if (!row) {
      return report.error("no aggregate report on this volume has the id " +
        JSON.stringify(wanted) + ". `blamepost reports list` prints the ids it holds, and a " +
        "report is destroyed once its retention window passes.", 2);
    }
    var recordTotal = b.db.from(storeTables.DMARC_RECORDS)
      .where({ reportRowId: row._id }).count();
    // Bounded by the read ceiling as well as by the flag. Every record
    // row is unsealed on the way out, so a request for a hundred
    // thousand of them is a request to hold a hundred thousand sending
    // addresses in memory at once, and what was not printed is counted
    // below rather than dropped.
    var records = b.db.from(storeTables.DMARC_RECORDS)
      .where({ reportRowId: row._id })
      .orderBy("messageCount", "desc")
      .limit(Math.min(limit, REPORTS_MAX_RECORD_ROWS)).all();
    return _emit(report, flags, {
      report:  _reportRow(row),
      policy: {
        requested:     row.requestedPolicy,
        subdomain:     row.subdomainPolicy,
        alignmentDkim: row.alignmentDkim,
        alignmentSpf:  row.alignmentSpf,
        samplePercent: row.samplePercent,
        failureOptions: row.failureOptions,
      },
      domain:       row.policyDomain,
      contact:      row.reportEmail,
      records:      records.map(function (record) {
        return {
          sourceIp:       record.sourceIp,
          messages:       record.messageCount,
          disposition:    record.disposition,
          alignedDkim:    record.alignedDkim,
          alignedSpf:     record.alignedSpf,
          authDkimDomain: record.authDkimDomain,
          authDkimResult: record.authDkimResult,
          authSpfDomain:  record.authSpfDomain,
          authSpfResult:  record.authSpfResult,
          headerFrom:     record.headerFrom,
          envelopeFrom:   record.envelopeFrom,
          envelopeTo:     record.envelopeTo,
          overrideReason: record.overrideReason,
        };
      }),
      recordsHeld:  recordTotal,
      recordsShown: records.length,
    }, _reportLines(row, records, recordTotal, records.length));
  } finally {
    await store.close();
  }
}

// The erasure verb, and the one address on this volume that belongs to
// somebody with no account here.
//
// It writes, so it opens the volume for writing and is refused while the
// server holds it, and it never falls back to a private copy: an erasure
// carried out against a copy nothing keeps is an erasure the person who
// asked for it was told had happened.
async function _cmdReportsForget(report, config, flags, positionals) {
  var confirmed = _requireConfirmation(report, flags,
    "Forgetting an address destroys every report row naming it, along with the key each " +
    "row was sealed under, and there is no copy. The address is matched in three places " +
    "and one of them is the contact mailbox a reporting organization writes into its own " +
    "reports, so an address belonging to a reporter takes every report that reporter sent " +
    "with it, and the counting `blamepost reports list` reads comes from those rows.");
  if (confirmed !== 0) return confirmed;

  var wanted;
  try {
    wanted = address.canonical(positionals[1], "address").address;
  } catch (e) {
    return report.error("give the address the erasure was asked about. " +
      ((e && e.message) || String(e)), 2);
  }

  var store = await storeModule.open(config);
  try {
    // What names the address, counted before anything is destroyed, over
    // the three columns the store erases by. It is published beside the
    // destroyed count rather than instead of it: the two coming apart is
    // a row that matched and stayed, and the person who asked for the
    // erasure has no way to ask again.
    var forensicFrom = b.db.from(storeTables.DMARC_FORENSIC)
      .where({ originalMailFrom: wanted }).all();
    var forensicRcpt = b.db.from(storeTables.DMARC_FORENSIC)
      .where({ originalRcptTo: wanted }).all();
    var contact = b.db.from(storeTables.DMARC_REPORTS)
      .where({ reportEmail: wanted }).all();
    var seen = Object.create(null);
    forensicFrom.concat(forensicRcpt).forEach(function (row) { seen[row._id] = true; });
    var matchedForensic = Object.keys(seen).length;
    var matched = matchedForensic + contact.length;

    if (matched === 0) {
      return _emit(report, flags, {
        address: wanted, matched: 0, matchedForensic: 0, matchedAggregate: 0,
        destroyed: 0, preserved: [], failed: [],
      }, [
        "No report row on this volume names " + wanted + ".",
        "  Nothing was destroyed. A forensic report is stored only where the operator has",
        "  turned that on, and every report row is destroyed on its own retention window,",
        "  so an address that was here may already be gone.",
      ]);
    }

    var removed = await store.reports.forgetAddress(wanted, flags.reason);
    var lines = [
      "Erased " + wanted + " from the stored reports.",
      "  " + _plural(matched, "row", "rows") + " named it: " +
        _plural(matchedForensic, "forensic row", "forensic rows") + " and " +
        _plural(contact.length, "aggregate report row", "aggregate report rows") + ".",
      "  " + _plural(removed.destroyed, "row", "rows") + " destroyed, with the key each one",
      "  was sealed under, so what is left in the write-ahead log reads as absent rather",
      "  than as ciphertext somebody may still hold a key for.",
    ];
    removed.preserved.forEach(function (entry) {
      lines.push("  kept  " + entry.table + " " + entry.rowId + ": " + entry.code +
        ". It is preserved on purpose. Release the order and run this again.");
    });
    removed.failed.forEach(function (entry) {
      lines.push("  FAIL  " + entry.table + " " + entry.rowId + " could not be erased: " +
        entry.code + ".");
    });
    var accounted = removed.destroyed + removed.preserved.length + removed.failed.length;
    if (accounted !== matched) {
      lines.push("  " + Math.abs(matched - accounted) + " row(s) that named this address " +
        "are accounted for by neither outcome. Run this again, and if the number holds, " +
        "the rows are on the volume and the person who asked has not been answered.");
    }
    _emit(report, flags, {
      address:          removed.address,
      matched:          matched,
      matchedForensic:  matchedForensic,
      matchedAggregate: contact.length,
      destroyed:        removed.destroyed,
      preserved:        removed.preserved,
      failed:           removed.failed,
    }, lines);
    // A destroying verb that reports success over a row it left behind is
    // the one answer nobody can correct afterwards, so the exit code says
    // which of the two happened. A row something is preserving on purpose
    // is not one of them: the system is working and the request finishes
    // when the order is released.
    return (removed.failed.length > 0 || accounted !== matched) ? 1 : 0;
  } finally {
    await store.close();
  }
}

// ---- dmarc ------------------------------------------------------------------

// The address a record this server offers points its `rua` tag at.
//
// It is the postmaster address, resolved here the way the outbound
// handle resolves it, because that is already the address whose arriving
// mail this server reads reports about its own sending at and the one
// the operator guide tells an operator to point at a mailbox on a domain
// they host.
//
// The assembled server reads the same value off the delivery handle
// rather than computing it, and `dmarc-policy-wiring.test.js` holds the
// two against each other: this file cannot build a delivery handle for
// `preview`, because building one creates the spool directory and
// `preview` has to answer on a volume that will not open at all.
//
// It comes back canonical, through the one derivation that decides what
// a name means here. The outbound handle's default carries an uppercase
// local part, the stepper canonicalizes whatever it is given, and a verb
// publishing the raw form would report an address that differs from the
// one in the record beside it by nothing an operator could see.
function _reportingAddressFor(config) {
  return address.canonical(config.postmaster || ("MAILER-DAEMON@" + config.hostname),
    "blamepost dmarc: the reporting address").address;
}

// The stepper, over a store this command already opened. Composed here
// the way `blamepost.create` composes it, from the same report handle,
// the same posture checker and the same resolver, so a verdict read at
// the command line and one read on the running server are the same
// reading rather than two.
function _dmarcPolicyOver(store, config) {
  var sharedResolver = blamepost.resolver();
  return blamepost.mail.dmarcPolicy.create({
    store:   store.reports,
    posture: blamepost.mail.posture.create({
      hostname: config.hostname,
      resolver: sharedResolver,
      dkim:     blamepost.mail.dkim.create({ dataDir: config.dataDir, store: store }),
    }),
    dnsLookup:        blamepost.mail.posture.txtLookup(sharedResolver),
    reportingAddress: _reportingAddressFor(config),
  });
}

// The three record texts, one line each, widest label padded so the
// values line up under one another and a reader comparing two of them is
// comparing the same column.
function _dmarcRecordLines(records, dropped, only) {
  var levels = blamepost.mail.dmarcPolicy.LEVELS.filter(function (level) {
    return only === null || level === only;
  });
  var width = levels.reduce(function (widest, level) {
    return Math.max(widest, level.length);
  }, 0);
  var lines = levels.map(function (level) {
    return "  " + level + new Array(width - level.length + 3).join(" ") + records[level];
  });
  if (dropped.length > 0) {
    lines.push("");
    lines.push("  " + _plural(dropped.length, "tag", "tags") + " on the published record " +
      "falls outside the tag grammar of RFC 9989 section 4.8 and is left out of every " +
      "record above: " + dropped.join(", ") + ". The record came out of DNS and the value " +
      "above is printed at a terminal and pasted into a provider's form.");
  }
  return lines;
}

async function cmdDmarc(flags, positionals) {
  var report = _reporter("dmarc");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_DMARC);
  var unread = _refuseUnread(report, "dmarc", verb, flags, positionals);
  if (unread !== 0) return unread;
  if (!Object.prototype.hasOwnProperty.call(VERB_SURFACE.dmarc, verb)) {
    return report.usage(USAGE_DMARC);
  }
  if (positionals[1] === undefined) return report.usage(USAGE_DMARC);

  var config = _configFrom(flags);
  var shape = _readDomainArg(report, positionals[1]);
  if (shape.code !== undefined) return shape.code;

  if (verb === "preview") {
    return await _cmdDmarcPreview(report, config, flags, shape.domain);
  }
  if (verb === "mark") {
    return await _cmdDmarcMark(report, config, flags, shape.domain);
  }

  // Both readings write to the audit trail on the way to their answer,
  // so neither falls back to a read-only copy. `b.audit.query` files a
  // row for every read of the trail, and `status` writes a second one
  // whenever the policy it resolves differs from the last one recorded,
  // which is what the reject rule reads to answer how long the domain
  // has already been at quarantine. A read that claims to be recorded
  // and is not is worse than one that refuses.
  var store = await storeModule.open(config);
  try {
    var hosted = store.domains.get(shape.domain);
    if (!hosted) {
      var names = store.domains.list().map(function (row) { return row.domain; });
      return report.error("this server does not host " + shape.domain + ", so it publishes " +
        "no policy for it and holds no reports about it. Hosted domains: " +
        (names.length
          ? names.join(", ")
          : "none. Add one with `blamepost domain add <domain>`."), 2);
    }
    b.audit.registerNamespace(AUDIT_NAMESPACE);
    var policy = _dmarcPolicyOver(store, config);
    if (verb === "markings") return await _cmdDmarcMarkings(report, flags, policy, shape.domain);
    return await _cmdDmarcStatus(report, flags, policy, shape.domain);
  } finally {
    await store.close();
  }
}

// The record text alone, over no data volume at all.
//
// A domain whose mail is being discarded is answered by publishing the
// weaker record, and an operator doing that is doing it because
// something is already wrong. So this verb opens nothing, takes no lock
// and asks the store no question: it reads the record the domain
// publishes today, keeps every tag on it that the grammar allows, and
// prints what each level would be published as. A reversal that needs
// this server's database to open is a reversal that is missing on the
// day it is wanted.
async function _cmdDmarcPreview(report, config, flags, domain) {
  var levels = blamepost.mail.dmarcPolicy.LEVELS;
  var only = null;
  if (flags.level !== undefined) {
    only = String(flags.level).trim().toLowerCase();
    if (levels.indexOf(only) === -1) {
      return report.error("--level names one of " + levels.join(", ") + ", and it is " +
        JSON.stringify(String(flags.level)) + ".", 2);
    }
  }

  var reportingAddress = _reportingAddressFor(config);
  var found = await blamepost.mail.posture.dmarcRecord(domain, {
    dnsLookup: blamepost.mail.posture.txtLookup(blamepost.resolver()),
  });

  var records = {};
  var dropped = [];
  for (var i = 0; i < levels.length; i += 1) {
    var built = blamepost.mail.dmarcPolicy.recordFor({
      level:            levels[i],
      reportingAddress: reportingAddress,
      published:        found.record,
    });
    records[levels[i]] = built.value;
    for (var d = 0; d < built.dropped.length; d += 1) {
      if (dropped.indexOf(built.dropped[d]) === -1) dropped.push(built.dropped[d]);
    }
  }

  // What the record above was built over. The four readings are kept
  // apart because they call for different things: a lookup that did not
  // complete says nothing about the zone, and a record nobody can read a
  // policy out of is a zone to correct rather than a policy to step.
  var head;
  if (found.state === "published") {
    head = domain + " publishes p=" + found.policy + " at " + found.name + ".";
  } else if (found.state === "absent") {
    head = domain + " publishes no DMARC record at " + found.name + ", so the records below " +
      "carry the tags this server would start it with and nothing else.";
  } else if (found.state === "unusable") {
    head = "The record at " + found.name + " is published and no receiver reads a policy " +
      "from it: " + found.why + ". The records below are built as though the name were " +
      "empty, so anything the published one carries is not in them.";
  } else {
    head = "The record at " + found.name + " could not be read: " + found.why + ". The " +
      "records below are built as though the name were empty, so any reporting address, " +
      "alignment mode or subdomain policy already published is not carried into them.";
  }

  var lines = [head, ""];
  _dmarcRecordLines(records, dropped, only).forEach(function (line) { lines.push(line); });
  lines.push("");
  lines.push("Publish one of these at " + found.name + ". Nothing here writes a zone, and");
  lines.push("nothing was read off the data volume, so this answers while the server runs");
  lines.push("and when its database will not open.");
  lines.push("");
  lines.push("The rua tag names " + reportingAddress + ". Point BLAMEPOST_POSTMASTER at a");
  lines.push("mailbox on a domain you host, or replace the address before you publish:");
  lines.push("a domain asking for reports at an address nobody reads accumulates nothing.");
  return _emit(report, flags, {
    domain:           domain,
    name:             found.name,
    state:            found.state,
    level:            found.policy,
    published:        found.record,
    why:              found.why,
    reportingAddress: reportingAddress,
    records:          records,
    recordsDropped:   dropped,
  }, lines);
}

// Where one domain stands, and what each rule asks for beside what it
// has.
//
// It exits zero whichever way it answers. A domain a fortnight into
// accumulating evidence is the ordinary state of a domain being moved to
// quarantine, not a fault, and a command that exits non-zero every day
// for two weeks is one an operator stops reading.
async function _cmdDmarcStatus(report, flags, policy, domain) {
  var verdict = await policy.evaluate({ domain: domain });
  var rules = policy.describe();

  var lines = [];
  lines.push(domain + (verdict.level === null
    ? " publishes no DMARC policy this server could read."
    : " publishes p=" + verdict.level + "."));
  if (verdict.next !== null) {
    lines.push("  The next step is " + verdict.next + ", and it is " +
      (verdict.ok ? "carried by the evidence." : "not carried yet: " + verdict.reason + "."));
  } else {
    lines.push("  There is no step to judge: " + verdict.reason + ".");
  }
  lines.push("  " + verdict.detail);

  if (verdict.checks.length > 0) {
    lines.push("");
    lines.push("Rules for the step to " + verdict.next);
    verdict.checks.forEach(function (check) {
      lines.push("  " + (check.ok ? "ok  " : "FAIL") + "  " + check.name +
        (check.required === null
          ? ""
          : "  " + JSON.stringify(check.found) + " of " + JSON.stringify(check.required)));
    });
  }

  if (verdict.evidence !== null) {
    var e = verdict.evidence;
    lines.push("");
    lines.push("Evidence over the last " + _plural(e.windowDays, "day", "days"));
    lines.push("  counted " + e.counted + "   aligned " + e.aligned + "   " +
      e.alignedPercent + " percent");
    lines.push("  reported on " + _plural(e.reportDays, "day", "days") + " by " +
      _plural(e.organizations, "organization", "organizations") +
      ", largest silent run " + _plural(e.largestGapDays, "day", "days"));
    lines.push("  " + _plural(e.failingSources, "sending address", "sending addresses") +
      " failed both alignments. Each one over " + rules.sourceFloorMessages +
      " messages needs a marking before the step is carried:");
    lines.push("  `blamepost reports list` prints them, and `blamepost dmarc mark` records");
    lines.push("  what each one is.");
  }

  lines.push("");
  lines.push("Records");
  _dmarcRecordLines(verdict.records, verdict.recordsDropped, null)
    .forEach(function (line) { lines.push(line); });
  lines.push("");
  // The stepper answers what stepping down offers against the policy it
  // read, and a reading that could not resolve one has no policy to
  // answer against. Printing its sentence there would tell an operator
  // which policy the domain publishes on a run whose whole finding is
  // that nobody knows.
  if (verdict.level === null) {
    lines.push("Which policy this domain publishes is not known, so there is nothing to say");
    lines.push("about stepping down from it. Publishing any record above needs no evidence");
    lines.push("and no threshold whichever policy it turns out to be.");
  } else {
    lines.push(verdict.reversal.detail);
    if (verdict.reversal.to.length > 0) {
      lines.push("  Weaker than what this domain publishes: " + verdict.reversal.to.join(", ") +
        ". `blamepost dmarc preview " + domain + "` prints those without opening the volume.");
    }
  }
  lines.push("Nothing here publishes a record. Put the value you want in the zone yourself.");

  return _emit(report, flags, { verdict: verdict, rules: rules }, lines);
}

// One operator's written finding about one failing sending address.
//
// The marking is what lets a policy tighten, so a row the trail would not
// take is reported as a marking that was not made rather than as a
// command that worked. Nothing is written until every argument reads,
// which is what keeps a mistyped address from costing a trail row.
async function _cmdDmarcMark(report, config, flags, domain) {
  var dispositions = blamepost.mail.dmarcPolicy.DISPOSITIONS;
  if (flags.source === undefined) {
    return report.error("give --source, the sending address a reporter named. `blamepost " +
      "reports list` prints the addresses failing both alignments for a domain, largest " +
      "first, and those are the ones a step waits on.", 2);
  }
  if (flags.disposition === undefined) {
    return report.error("give --disposition, which is " + dispositions.join(" or ") +
      ". A sending path of yours whose alignment is fixed and an address that is not yours " +
      "are read differently: continued failure contradicts the first and is expected of " +
      "the second.", 2);
  }
  if (dispositions.indexOf(String(flags.disposition)) === -1) {
    return report.error("--disposition names one of " + dispositions.join(" or ") +
      ", and it is " + JSON.stringify(String(flags.disposition)) + ". A sending path of " +
      "yours whose alignment is fixed and an address that is not yours are read " +
      "differently: continued failure contradicts the first and is expected of the second.",
    2);
  }
  if (!flags.reason) {
    return report.error("give --reason. The marking is the evidence a policy tightens on, " +
      "and one with no reason answers nothing later about why mail from this address was " +
      "accounted for.", 2);
  }

  var store = await storeModule.open(config);
  try {
    var hosted = store.domains.get(domain);
    if (!hosted) {
      return report.error("this server does not host " + domain + ", so a marking against " +
        "it would never be read.", 2);
    }
    b.audit.registerNamespace(AUDIT_NAMESPACE);
    var written;
    try {
      written = await _dmarcPolicyOver(store, config).markSource({
        domain:      domain,
        sourceIp:    flags.source,
        disposition: flags.disposition,
        reason:      flags.reason,
      });
    } catch (e) {
      return report.error((e && e.message) || String(e), 2);
    }

    _emit(report, flags, written, [
      "Marked one sending address for " + written.domain + " as " + written.disposition + ".",
      "  " + written.reason,
      written.recorded
        ? "  The marking is in the audit trail, which is where every reading of it comes " +
          "from. A later marking for the same address supersedes this one and leaves both " +
          "readable."
        : "  The audit trail did not take the row, so nothing was marked. Until it does, " +
          "this address goes on blocking the step.",
    ]);
    // The marking IS the row. A verb that reported success over a row the
    // trail refused would leave an operator waiting for a step that has
    // nothing to clear it.
    return written.recorded ? 0 : 1;
  } finally {
    await store.close();
  }
}

// What has already been written down about one domain's failing senders.
async function _cmdDmarcMarkings(report, flags, policy, domain) {
  var held = await policy.markings({ domain: domain });
  var ids = Object.keys(held.marked).sort(function (one, other) {
    return held.marked[other].at - held.marked[one].at;
  });

  var lines = [];
  if (!held.ok) {
    lines.push("The audit trail could not be read, so which of " + domain + "'s failing");
    lines.push("senders have been looked at is not known. That is not the same as none:");
    lines.push("reporting no marking here would report every source as unreviewed.");
    _emit(report, flags, held, lines);
    return 1;
  }

  lines.push(_plural(ids.length, "marking", "markings") + " in force for " + domain + ".");
  ids.forEach(function (id) {
    var entry = held.marked[id];
    lines.push("  " + new Date(entry.at).toISOString() + "  " + entry.disposition);
    lines.push("    " + entry.reason);
  });
  if (ids.length === 0) {
    lines.push("  Nothing has been written down yet. `blamepost dmarc status " + domain + "`");
    lines.push("  says how many senders a step is waiting on.");
  }
  lines.push("");
  lines.push("A marking is filed under the domain and the keyed digest of the sending");
  lines.push("address, never the address itself, because the address belongs to somebody");
  lines.push("with no account here. `blamepost reports list` is where the addresses are.");
  if (held.truncated) {
    lines.push("");
    lines.push("This read reached its own ceiling, so an older marking may be missing from");
    lines.push("it, and a step is refused rather than judged over part of the set.");
  }
  return _emit(report, flags, held, lines);
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
        // The id is the body file's own name with its suffix removed, and
        // this list exists because no descriptor accounts for that file,
        // so the name is not one this server wrote. U+009B opens an
        // escape sequence, so an unscreened id can erase the line it is
        // printed on, which here is the line telling the operator why the
        // queue reads as empty while mail is being refused.
        unclaimed.map(function (entry) {
          return displayText.forDisplay(entry.id);
        }).join(", ") + ".");
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
      // A body that is gone is named rather than printed as a value,
      // because an operator reading a number cannot tell a missing body
      // from one of no bytes, and the two want different work.
      "size       " + (typeof shown.sizeBytes === "number"
        ? shown.sizeBytes + " byte(s)"
        : "the message body is missing, so there is nothing to send"),
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
      entry.rowBytes + "." +
      // How much of this entry a repair would take, per mailbox rather
      // than only in the closing sentence, because an operator decides
      // mailbox by mailbox which of them they are willing to lose mail
      // from.
      (entry.unfiledCount > 0
        ? " " + _plural(entry.unfiledCount, "message", "messages") + ", " +
          entry.unfiledBytes + " bytes, is mail the store holds that no row names."
        : "") +
      (entry.detail ? " " + entry.detail : ""));
  });
  report.orphans.forEach(function (entry) {
    lines.push("  note  " + entry.digest.slice(0, 16) + "... " + entry.sizeBytes +
      " bytes, referenced by nothing" +
      (entry.reclaimable
        ? ", reclaimable now"
        : ", reclaimable from " + new Date(entry.reclaimableAt).toUTCString()));
  });
  report.unexpected.forEach(function (entry) {
    // Screened, because this list exists precisely for a file nothing on
    // this server put there under a name nothing on this server chose.
    // U+009B opens an escape sequence, so an unscreened name can erase
    // the line it is printed on, and the line it erases is a finding in
    // the report written to say what is wrong with the volume.
    lines.push("  note  " + displayText.forDisplay(entry.path) + ": " + entry.detail +
      ". Nothing removes it.");
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
    var removable = report.quotaDrift.filter(function (entry) {
      return entry.unfiledCount > 0;
    });
    lines.push("A mailbox whose quota exceeds the messages in it is charged for mail no " +
      "protocol can list. Reclaiming bodies does not change it: the count lives in the " +
      "message store, not on disk.");
    if (removable.length > 0) {
      lines.push("Run `blamepost blobs repair --confirm --reason <text>` with the server " +
        "stopped to destroy that mail and let the counter fall by what went. A " +
        "preservation order and the retention floor keep a message here exactly as they " +
        "keep any other, and a mailbox holding one they kept stays charged for it.");
    }
    if (removable.length < report.quotaDrift.length) {
      lines.push("Where the store counts FEWER messages than the mailbox lists, nothing " +
        "here raises the counter: those rows name messages the store no longer has. " +
        "Restore the volume from a backup whose database and blob directory were taken " +
        "together.");
    }
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

    if (verb === "repair") {
      // It destroys somebody's mail, so it takes the same two flags the
      // reclaim above does. What it removes is mail no protocol lists,
      // which is exactly why the operator has to say so deliberately:
      // nobody is going to notice it going.
      var repairGate = _requireConfirmation(report, flags,
        "Repairing destroys the mail the message store holds that no mailbox row names. " +
        "Run `blamepost blobs report` first: it removes nothing and says how many " +
        "messages this would take and how many bytes they hold.");
      if (repairGate !== 0) return repairGate;

      b.audit.registerNamespace(AUDIT_NAMESPACE);
      var repaired = await store.blobs.repairQuota({ reason: flags.reason });
      var repairLines = [
        "Destroyed " + _plural(repaired.removed.length, "message", "messages") + ", " +
          repaired.removedBytes + " bytes, that the message store held and no mailbox " +
          "row named.",
      ];
      // Named one per line, because an operator answering for mail that
      // was kept has to be able to say which record and which rule, and
      // the two rules need opposite responses.
      repaired.kept.forEach(function (entry) {
        repairLines.push("  kept  " + (entry.account || "an account with no row") + " " +
          entry.mailbox + ": " + entry.objectid + " (" + entry.sizeBytes + " bytes), " +
          entry.reason + (entry.detail ? ". " + entry.detail : ""));
      });
      // Mailboxes the repair could not close. Named for the same reason,
      // and separately, because nothing an operator does to this verb
      // changes them.
      repaired.unrepairable.forEach(function (entry) {
        repairLines.push("  FAIL  " + (entry.account || "an account with no row") + " " +
          entry.mailbox + ": " + entry.detail);
      });
      if (repaired.removed.length > 0) {
        repairLines.push("");
        repairLines.push("The bodies those messages named are referenced by nothing now. " +
          "Run `blamepost blobs reclaim --confirm --reason <text>` once they have settled.");
      }
      _emit(report, flags, repaired, repairLines);
      // Non-zero while any mailbox still disagrees with its counter, so a
      // run that could not finish is not read as one that did.
      return repaired.ok ? 0 : 1;
    }

    return report.usage(USAGE_BLOBS);
  } finally {
    await store.close();
  }
}

// ---- attachments ------------------------------------------------------------

function _attachmentReportLines(seen) {
  var lines = [
    _plural(seen.messages, "stored message", "stored messages") + " across " +
      _plural(seen.folders, "mailbox", "mailboxes") + ".",
    "  " + seen.present + " carry files, " + seen.absent + " carry none.",
  ];
  if (seen.unmarked === 0) {
    lines.push("  Every message records the answer.");
    return lines;
  }
  lines.push("  " + _plural(seen.unmarked, "message", "messages") + " record neither, so a " +
    "JMAP client is told they may carry files and the folder listing says the answer is " +
    "not known.");
  lines.push("Run `blamepost attachments backfill` to read those and record it.");
  return lines;
}

function _attachmentBackfillLines(run) {
  var lines = [
    "Opened " + _plural(run.examined, "message", "messages") + " that recorded nothing, " +
      "and marked " + run.marked + ": " + run.present + " carrying files, " +
      run.absent + " carrying none.",
  ];
  if (run.unknown > 0) {
    lines.push("  Left " + _plural(run.unknown, "message", "messages") + " unmarked that " +
      "this server could not open: above the 8 MiB read bound, or a stored body it could " +
      "not read back. What those carry is not known, so a later run opens them again.");
  }
  // Named one per line, because an operator answering for a message
  // whose octets the volume would not produce has to be able to say
  // which one, and the remedy is a different verb.
  run.failed.forEach(function (entry) {
    lines.push("  FAIL  " + entry.folder + ": " + entry.objectid + ": " + entry.detail);
  });
  if (run.failed.length > 0) {
    lines.push("Run `blamepost blobs report --verify` for the bodies those rows name.");
  }
  if (run.remaining > 0) {
    lines.push(_plural(run.remaining, "message", "messages") + " were not reached under " +
      "the limit. Run this again to reach them.");
  }
  return lines;
}

async function cmdAttachments(flags, positionals) {
  var report = _reporter("attachments");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_ATTACHMENTS);
  var unread = _refuseUnread(report, "attachments", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);
  // Both verbs open the volume outright. The backfill writes flags, and
  // the report counts them over every mailbox: a read-only copy would
  // answer as of the server's last write to disk, which is the one
  // reading an operator must not act on here, since what they do next is
  // decide whether a write has already been done.
  var store = await storeModule.open(config);

  try {
    if (verb === "report") {
      var seen = store.mailbox.attachmentReport();
      _emit(report, flags, seen, _attachmentReportLines(seen));
      return 0;
    }

    if (verb === "backfill") {
      var limit = null;
      if (flags.limit !== undefined) {
        // Refused here rather than handed on. A ceiling that is not a
        // whole number is a run that stops somewhere the operator did not
        // choose, and the answer it prints would read as a volume that is
        // finished.
        if (typeof flags.limit !== "number" || !Number.isInteger(flags.limit) ||
            flags.limit < 1) {
          return report.error("--limit is " + JSON.stringify(String(flags.limit)) +
            ", which is not a whole number of messages of at least one. Leave it out to " +
            "open every message that records nothing.", 2);
        }
        limit = flags.limit;
      }
      b.audit.registerNamespace(AUDIT_NAMESPACE);
      var run = store.mailbox.markAttachments(limit === null ? {} : { limit: limit });
      // The row the run files is emitted on the mail layer's hot-path
      // handle, which buffers. This process ends a moment after the
      // answer is printed, so without this the only record that the run
      // happened leaves with it.
      await b.audit.flush();
      _emit(report, flags, run, _attachmentBackfillLines(run));
      // Non-zero when a stored body could not be read, so a scheduled run
      // that has started failing to open mail is not read as one that
      // finished.
      return run.failed.length > 0 ? 1 : 0;
    }

    return report.usage(USAGE_ATTACHMENTS);
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
        stranded.slice(0, 5).map(function (entry) {
          // A spool id is the part of a file name before its suffix, and
          // a body with no descriptor is a file this server did not
          // finish writing under a name it may not have chosen. Screened
          // for the reason the blob paths above are.
          return displayText.forDisplay(entry.id);
        }).join(", ") +
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
      // Screened here rather than where the names are collected, because
      // `onDisk` and `claimed` above hold the same names and compare them
      // against a selector's keyRef: a screened value there would stop
      // matching the row that claims it. A key file no row names is a file
      // this server did not write, so its name reaches the terminal only
      // through the screen.
      " no selector record names (" + unclaimed.slice(0, 5).map(function (name) {
        return displayText.forDisplay(name);
      }).join(", ") +
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
    // The closing line is the one most readers take away, so it says
    // what the rows above it say and nothing else. Each sentence is
    // written by the count it is about, rather than by a chain of
    // conditions where one arm can describe a state the counts are not
    // in: a summary naming a FAIL when none was printed sends a reader
    // hunting for a line that is not there, and it was reachable while
    // the sentence and its guard were written separately.
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
    if (mismatched === 0 && unchecked === 0) {
      // Nothing above disagreed and nothing went unread, which is the
      // same set of runs the exit status calls clean: a check that fails
      // is counted in one of the two, so neither count can be zero while
      // the run is not ok.
      lines.push("Everything this server expects is in place.");
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
//
// The names the store reserves at the top of the volume are left out. The
// lock names the process that took the backup, and a restore that put it
// back would hand the restored volume a lock naming a process in another
// container. The restore work directory holds whole earlier volumes.
function _walkDataFiles(root, relative, into) {
  var entries = b.atomicFile.listDir(_under(root, relative), { includeStat: true });
  for (var i = 0; i < entries.length; i += 1) {
    if (relative === "" && storeModule.VOLUME_RESERVED.indexOf(entries[i].name) !== -1) continue;
    var childRelative = relative === "" ? entries[i].name : relative + "/" + entries[i].name;
    if (entries[i].isDirectory) _walkDataFiles(root, childRelative, into);
    else if (entries[i].isFile) into.push(childRelative);
  }
  return into;
}

// The include list a bundle is built from: the framework's own list
// first, so the files it marks required keep their mark and the absence
// of one refuses the backup rather than producing one that cannot be
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
  // read, held open by the purge boundary the framework records.
  // Reporting it beside a reading that passed would put the sentence an
  // operator carries into an incident review over rows nobody looked at,
  // and reporting it as a break would refuse a volume that may have been
  // through an ordinary retention run. It is its own line because it is
  // its own fact.
  //
  // A purge signs the boundary it writes, under the key sealed with the
  // vault passphrase, and a boundary carrying no signature is a row
  // something else put there. Which of the two is holding the gap open
  // is what the record cost whoever wrote it, so the line says which
  // rather than naming the weaker of the two every time.
  var witnessed = !!(anchor && anchor.checked === true);
  var unproven  = !!(anchor && anchor.proven === false);
  var signedGap = unproven && anchor.signed === true;
  if (unproven) {
    lines.push("  note  a gap this run did not read, trusted on " +
      (signedGap ? "a signed purge boundary" : "an unsigned counter") + ". " +
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
      "are gone, and what stands in for them is " +
      (signedGap ? "a boundary saying where a purge stopped" : "an unsigned counter in " +
        "the database") + " rather than an archive anything here verified. So this run " +
      "cannot say what was in that range and is not saying it: an erasure and a " +
      "retention run leave the same " +
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
          // The reason and the resource an event names are quoted from
          // whatever caused it, which reaches back to a sender's header,
          // a peer's refusal or an account holder's filter script. This
          // line is printed into a terminal, so both go through the
          // screen the browser's own trail page already runs.
          return "  " + new Date(Number(row.recordedAt)).toISOString() +
            "  " + row.action + "  " + row.outcome +
            (row.actorUserId ? "  by " + row.actorUserId : "") +
            (row.resourceKind ? "  on " + row.resourceKind +
              (row.resourceId ? " " + _headerText(row.resourceId, "") : "") : "") +
            (row.reason ? "  reason: " + _headerText(row.reason, "") : "");
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

      // The refusal that keeps this server able to start again. The
      // volume carries a record beside the database naming one audit row
      // by its counter and its hash, and every open holds the trail
      // against that row before it hands back a database. A purge whose
      // range reaches that counter deletes the row the record names, so
      // the next open finds the record standing against a row that is
      // gone or against a different one, writes the finding onto the
      // volume, and refuses every open after that until an operator
      // clears it.
      //
      // The counter compared here is the one read at this command's own
      // open, before anything it does. The live chain tip is the wrong
      // reading and reads as the right one: opening the volume appends
      // rows of its own, so a tip taken after that is a tip this command
      // lengthened on its way in, and an archive of every row the
      // operator had can never cover it. A check on that tip passes on
      // the archive it exists to refuse.
      await b.audit.flush();
      var anchoredAt = store.auditAnchor;
      if (!anchoredAt || anchoredAt.checked !== true) {
        return report.error("this volume carries no readable record of its last anchoring, " +
          "so nothing here can say whether this purge would take the row the next open holds " +
          "the trail against. Nothing was deleted. Any command that opens the volume writes " +
          "that record, so run `blamepost audit verify-chain` and then this again.");
      }
      if (Number(anchoredAt.counter) <= Number(verified.range.lastCounter)) {
        return report.error("this archive covers counters " + verified.range.firstCounter +
          " to " + verified.range.lastCounter + ", and this volume's record beside the " +
          "database is anchored at counter " + anchoredAt.counter + ", inside that range. " +
          "Purging it deletes " + verified.rowsVerified + " row(s), the anchored one among " +
          "them, and what it leaves behind is a volume whose next open refuses and stays " +
          "refused until an operator clears the finding. Nothing was deleted. Archive a cut " +
          "that ends below counter " + anchoredAt.counter + " and purge that.");
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

// Where a stored bundle lies. `b.backup.diskStorage` keeps each bundle as
// a directory named by its id under the storage root, and its `hasBundle`
// refuses an id outside the framework's format, so a caller that has had
// `true` from `hasBundle` holds a path that stays under the root. Bundles
// are read where they lie rather than copied into the temp directory
// first, which cost the bundle's whole size on that filesystem before a
// byte of it had been checked.
function _storedBundleDir(chosen, bundleId) {
  return _under(chosen.root, bundleId);
}

// Bytes this process may still write on the filesystem holding `target`,
// read at the nearest directory that exists, or null when the platform
// does not say.
function _freeBytes(target) {
  var at = nodePath.resolve(target);
  for (;;) {
    try {
      var stats = nodeFs.statfsSync(at);
      return Number(stats.bavail) * Number(stats.bsize);
    } catch (_err) {
      var up = nodePath.dirname(at);
      if (up === at) return null;
      at = up;
    }
  }
}

// Refuse work that would fill the filesystem holding `where` before it
// starts, rather than failing partway with a full disk. Answers 0, or the
// exit code of the refusal it printed.
function _refuseWithoutRoom(report, where, needed, what) {
  var free = _freeBytes(where);
  if (free === null || free >= needed) return 0;
  return report.error(what + " needs " + needed + " bytes on the filesystem holding " + where +
    ", and " + free + " are free. Nothing was changed.");
}

// The plaintext bytes a bundle's entries decrypt to, over the entries
// `keep` accepts. The caller passes the same predicate it will decrypt
// under, because a room check made over one set and a decryption made
// over another is a check that runs out of room having reported enough:
// `restore apply` skips the names the volume reserves and `backup verify`
// opens every file the bundle holds, and a bundle written before those
// names were reserved carries a whole earlier volume under them.
function _plaintextBytes(manifest, keep) {
  var total = 0;
  manifest.files.forEach(function (entry) {
    if (typeof keep !== "function" || keep(entry)) total += Number(entry.size) || 0;
  });
  return total;
}

// Whether an audit signing key is one this volume holds or held before a
// rotation. Asked with the store open, when `b.auditSign` is the volume's.
// A manifest's signature, checked against the key a caller pinned or,
// with no pin, against the key the manifest carries. The framework trusts
// a key only when one is named or the audit signer holds it, and these
// verbs run without opening the volume, so the unpinned check names the
// manifest's own key: it says the manifest is unmodified, and the caller
// decides separately whether that key is one it trusts.
function _manifestSignature(manifest, pinnedFingerprint) {
  var expected = _fingerprintToCheck(manifest, pinnedFingerprint);
  return b.backup.verifyManifestSignature(manifest,
    expected === null ? {} : { expectedFingerprint: expected });
}

// The fingerprint a manifest's signature is checked against: the pinned
// one when a caller gave one, the fingerprint of the key the manifest
// carries otherwise, and null when it carries no readable key.
function _fingerprintToCheck(manifest, pinnedFingerprint) {
  if (typeof pinnedFingerprint === "string" && pinnedFingerprint.length > 0) {
    return pinnedFingerprint;
  }
  var sig = manifest && manifest.signature;
  try {
    return sig && typeof sig.publicKey === "string"
      ? b.auditSign.fingerprintOf(sig.publicKey) : null;
  } catch (_e) { return null; }
}

function _isVolumeSigningKey(fingerprint) {
  if (fingerprint === b.auditSign.getPublicKeyFingerprint()) return true;
  return b.auditSign.getPublicKeyByFingerprint(fingerprint) !== null;
}

// What a bundle's manifest records about where it came from, held
// against this server: the id it was written as, the data directory it
// was taken from, and the server it was taken on. Answers null when all
// three agree, and the first that does not otherwise, as `{ reason,
// detail, remedy, exit }`.
//
// `reason` is the clause a verdict carries. `detail` is the finding an
// operator reads and `remedy` is what to do about it, held apart so the
// caller can say what its own verb did in between: a restore says nothing
// was restored, and a verify says nothing was decrypted. `remedy` is the
// empty string where there is nothing to do. `exit` separates a bundle
// that belongs to another volume, which no command line here can change,
// from one an operator restores by pointing this run at the directory or
// the name the bundle records.
//
// Every verb that reports on a bundle asks this, because `restore apply`
// asks it before it moves a file. A bundle it refuses cannot be restored,
// so a verify that calls that bundle good sends an operator away
// believing they hold a copy, and a retention sweep that counts one
// deletes a bundle that would have restored in order to keep one that
// will not.
function _originFault(manifest, bundleId, config) {
  var meta = manifest.metadata || {};
  if (meta.bundleId !== bundleId) {
    return {
      exit:   1,
      reason: "it was written as " + (typeof meta.bundleId === "string"
        ? meta.bundleId : "no bundle id at all") + " and is stored as " + bundleId +
        ", so it is another bundle's files renamed or copied in storage",
      detail: "the bundle stored as " + bundleId + " records that it was written as " +
        (typeof meta.bundleId === "string" ? meta.bundleId : "no bundle id at all") + ". A " +
        "bundle's id is written into its manifest when the bundle is taken, so this is another " +
        "bundle's files renamed or copied in storage, and restoring it would put back a volume " +
        "from a moment other than the one its name gives.",
      remedy: "",
    };
  }
  if (meta.dataDir !== config.paths.dataDir) {
    return {
      exit:   2,
      reason: "it " + (typeof meta.dataDir === "string"
        ? "was taken from " + meta.dataDir : "records no data directory") +
        " and this server's data directory is " + config.paths.dataDir,
      detail: "this bundle " + (typeof meta.dataDir === "string"
        ? "was taken from " + meta.dataDir
        : "does not record the data directory it was taken from") + " and this server's data " +
        "directory is " + config.paths.dataDir + ". The database key is sealed to the path of " +
        "the directory it belongs to, so a restore into a different one produces a volume that " +
        "will not open.",
      remedy: typeof meta.dataDir === "string"
        ? " Point BLAMEPOST_DATA_DIR at " + meta.dataDir + " and run it again." : "",
    };
  }
  if (meta.hostname !== config.hostname) {
    return {
      exit:   2,
      reason: "it " + (typeof meta.hostname === "string"
        ? "was taken on the server named " + meta.hostname : "records no server") +
        " and this server is named " + config.hostname,
      detail: "this bundle " + (typeof meta.hostname === "string"
        ? "was taken on the server named " + meta.hostname
        : "does not record the server it was taken on") + " and this server is named " +
        config.hostname + ". A bundle carries its server's hosted domains, accounts and DKIM " +
        "keys.",
      remedy: typeof meta.hostname === "string"
        ? " To read it here, run this with BLAMEPOST_HOSTNAME set to " + meta.hostname + "."
        : "",
    };
  }
  return null;
}

// The one place a bundle's manifest is read, and the verdict on where it
// came from in the same answer. Answers `{ manifest, fault }`, and raises
// what the reader raises when the manifest cannot be read at all.
//
// It is one call rather than two because the two were separate and three
// of the four verbs that read a manifest never made the second one. A
// caller that can get the manifest on its own is a caller that can report
// on a bundle without ever asking whether this server could restore it,
// which is how `backup verify`, `backup inspect` and the retention sweep
// came to vouch for bundles `restore apply` refuses outright.
function _readBundle(bundleDir, bundleId, config) {
  var manifest = b.restoreBundle.inspect({ bundleDir: bundleDir });
  return { manifest: manifest, fault: _originFault(manifest, bundleId, config) };
}

// Whether a stored bundle is one a restore could use, checked without
// decrypting its files: the manifest reads within the limits a restore
// reads it under, the signature verifies under a key this volume holds or
// held, the origin it records is this server's, every file the manifest
// lists is present at the size it lists, and the vault key inside it opens
// with this passphrase. `backup verify` decrypts every file; this is the
// check a sweep can afford for every bundle it counts. Answers
// `{ ok, reason, signature }`.
async function _bundleStands(bundleDir, passphrase, bundleId, config) {
  var read;
  try {
    read = _readBundle(bundleDir, bundleId, config);
  } catch (err) {
    return { ok: false, signature: null,
      reason: "its manifest cannot be read: " + ((err && err.message) || String(err)) };
  }
  var manifest = read.manifest;
  var signature = _manifestSignature(manifest, null);
  if (!signature.ok) {
    return { ok: false, signature: signature,
      reason: "its signature does not verify: " + signature.reason };
  }
  if (!_isVolumeSigningKey(signature.fingerprint)) {
    return { ok: false, signature: signature,
      reason: "it is signed by key " + signature.fingerprint + ", which this volume has " +
        "never held" };
  }
  // Asked before the files are weighed, because a bundle belonging to
  // another volume or another moment is one no amount of intact
  // ciphertext makes restorable here.
  if (read.fault !== null) {
    return { ok: false, signature: signature, reason: read.fault.reason };
  }
  for (var i = 0; i < manifest.files.length; i += 1) {
    var entry = manifest.files[i];
    var size;
    try {
      // The manifest names each file, so its path is resolved through the
      // bundle directory and refused if it leaves it.
      var blobPath = b.safePath.resolve(bundleDir, entry.encryptedPath);
      size = nodeFs.lstatSync(blobPath).size;
    } catch (_err) {
      size = -1;
    }
    if (size !== entry.encryptedSize) {
      return { ok: false, signature: signature,
        reason: size === -1
          ? "the file for " + entry.relativePath + " is missing"
          : "the file for " + entry.relativePath + " is " + size + " bytes and the manifest " +
            "lists " + entry.encryptedSize };
    }
  }
  // The vault key opens the way a restore opens it. A bundle written
  // under the per-bundle key scheme seals it under a subkey of a key
  // derived from the passphrase and the bundle's own salt; an older
  // bundle seals it under the passphrase directly.
  var bundleKey = null;
  try {
    var sealed = Buffer.from(manifest.vaultKeyEnc, "base64");
    var vaultKey;
    if (manifest.keyScheme === b.backupManifest.KEY_SCHEME_BUNDLE) {
      bundleKey = await b.backupCrypto.deriveKey(passphrase, manifest.bundleSalt);
      vaultKey = b.backupCrypto.decryptUnderSubkey(sealed, bundleKey, manifest.vaultKeySalt,
        b.backupCrypto.VAULT_KEY_LABEL, b.backupCrypto.VAULT_KEY_LABEL);
    } else {
      vaultKey = await b.backupCrypto.decryptWithPassphrase(sealed, passphrase,
        manifest.vaultKeySalt);
    }
    vaultKey.fill(0);
  } catch (_err) {
    return { ok: false, signature: signature,
      reason: "it does not open with this passphrase" };
  } finally {
    if (bundleKey) bundleKey.fill(0);
  }
  return { ok: true, signature: signature, reason: null };
}

// Directories under the storage root named like a bundle that the
// storage's listing left out, newest first. Empty for storage that is
// not a local directory.
function _unlistedBundleDirs(chosen, listed) {
  var seen = Object.create(null);
  listed.forEach(function (entry) { seen[entry.bundleId] = true; });
  var names;
  try { names = nodeFs.readdirSync(chosen.root, { withFileTypes: true }); }
  catch (_e) { return []; }
  return names.filter(function (entry) {
    return entry.isDirectory() && b.backup.BUNDLE_ID_RE.test(entry.name) &&
      seen[entry.name] !== true;
  }).map(function (entry) { return entry.name; }).sort().reverse();
}

// Keep the newest `keep` bundles that stand and delete the older ones
// that stand. A directory that does not stand is neither counted nor
// deleted: a bundle id sorts by time, so counting a directory that only
// carries a later id would keep it in place of a bundle that restores.
async function _sweepBundles(chosen, keep, passphrase, config) {
  var listed = await chosen.storage.listBundles();
  var standing = [];
  var notCounted = [];
  for (var i = 0; i < listed.length; i += 1) {
    var id = listed[i].bundleId;
    var verdict = await _bundleStands(_storedBundleDir(chosen, id), passphrase, id, config);
    if (verdict.ok) standing.push(id);
    else notCounted.push({ bundleId: id, reason: verdict.reason });
  }
  // The storage lists only bundles that hold what a restore needs, so a
  // directory named like a bundle that is missing its manifest or a file
  // it declares is not listed at all. It is reported here as not counted
  // and left in place, as a listed bundle that does not stand is.
  _unlistedBundleDirs(chosen, listed).forEach(function (name) {
    notCounted.push({ bundleId: name, reason: "it is not a complete bundle: its manifest is " +
      "missing or unreadable, or a file the manifest declares is missing or the wrong size" });
  });
  var deleted = [];
  var notDeleted = [];
  var older = standing.slice(keep);
  for (var j = 0; j < older.length; j += 1) {
    try {
      await chosen.storage.deleteBundle(older[j]);
      deleted.push(older[j]);
    } catch (err) {
      notDeleted.push({ bundleId: older[j], reason: (err && err.message) || String(err) });
    }
  }
  return {
    keep:       keep,
    kept:       standing.slice(0, keep),
    deleted:    deleted,
    notDeleted: notDeleted,
    notCounted: notCounted,
  };
}

function _sweepLines(chosen, swept) {
  var lines = ["  kept " + swept.kept.length + " bundle(s) that verify, newest first:"]
    .concat(swept.kept.map(function (id) { return "    " + id; }));
  lines.push(swept.deleted.length === 0
    ? "  deleted nothing"
    : "  deleted " + swept.deleted.length + ":");
  swept.deleted.forEach(function (id) { lines.push("    " + id); });
  swept.notDeleted.forEach(function (entry) {
    lines.push("  could not delete " + entry.bundleId + ": " + entry.reason);
  });
  if (swept.notCounted.length > 0) {
    // Each entry carries its own reason, and there are more of them than
    // the passphrase and the signing key: a bundle recording another id,
    // another data directory or another server is one a restore refuses,
    // so a heading naming two of the reasons describes the wrong bundle
    // for the rest.
    lines.push("  left in " + chosen.root + " and not counted, each with the reason a " +
      "restore here could not use it:");
    swept.notCounted.forEach(function (entry) {
      lines.push("    " + entry.bundleId + "  " + entry.reason);
    });
  }
  return lines;
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
    var inspectedDir = _storedBundleDir(chosen, wanted.path);
    var inspected;
    var manifest;
    var signature;
    try {
      inspected = _readBundle(inspectedDir, wanted.path, config);
      manifest = inspected.manifest;
      signature = _manifestSignature(manifest, flags.fingerprint);
    } catch (err) {
      return report.error(wanted.path + " cannot be read: " + ((err && err.message) || String(err)));
    }
    var total = 0;
    manifest.files.forEach(function (entry) { total += entry.encryptedSize || 0; });
    var described = {
      bundleId:      wanted.path,
      recordedId:    (manifest.metadata && manifest.metadata.bundleId) || null,
      createdAt:     manifest.createdAt || null,
      fileCount:     manifest.files.length,
      encryptedSize: total,
      dataDir:       (manifest.metadata && manifest.metadata.dataDir) || null,
      hostname:      (manifest.metadata && manifest.metadata.hostname) || null,
      signature:     signature,
      // Why a restore here would refuse it, or null when it would not.
      // A description that reported the three recorded fields and left
      // the reader to compare them by eye is how a bundle recording
      // another server passed this verb while `restore apply` refused it.
      originFault:   inspected.fault === null ? null : inspected.fault.reason,
      restoresHere:  inspected.fault === null,
      pinned:        typeof flags.fingerprint === "string" && flags.fingerprint.length > 0,
    };
    _emit(report, flags, described, [
      described.bundleId,
      "  written as:     " + (described.recordedId === wanted.path
        ? "this id" : (described.recordedId || "no id")),
      "  created:        " + described.createdAt,
      "  files:          " + described.fileCount,
      "  encrypted size: " + described.encryptedSize + " bytes",
      "  data directory: " + (described.dataDir || "not recorded"),
      "  server:         " + (described.hostname || "not recorded"),
      "  restores here:  " + (described.restoresHere
        ? "yes, as far as the manifest says: it records this id, this data directory and " +
          "this server. `blamepost backup verify` reads every file back."
        : "no. " + inspected.fault.detail),
      "  signature:      " + (!described.signature.ok
        ? "NOT verified: " + described.signature.reason
        : described.pinned
          ? "verified, key " + described.signature.fingerprint + ", the key --fingerprint named"
          : "verified against the key the manifest carries, " +
            described.signature.fingerprint + ". Anyone can sign a manifest with a key of " +
            "their own, so this says nothing about who wrote it: `restore apply` holds it " +
            "against the signing key sealed inside the bundle, and --fingerprint holds it " +
            "against one you recorded."),
    ]);
    return described.signature.ok && described.restoresHere ? 0 : 1;
  }

  if (verb === "verify") {
    var target = _bundleFrom(report, flags);
    if (target.code !== undefined) return target.code;
    if (!(await chosen.storage.hasBundle(target.path))) {
      return report.error("no bundle " + JSON.stringify(target.path) + " in " + chosen.root +
        ". `blamepost backup list --storage " + chosen.root + "` prints the ids.", 2);
    }
    var verifiedDir = _storedBundleDir(chosen, target.path);
    var checked;
    var checkedManifest;
    try {
      checked = _readBundle(verifiedDir, target.path, config);
      checkedManifest = checked.manifest;
    } catch (err) {
      return report.error(target.path + " does not open: " +
        ((err && err.message) || String(err)));
    }
    // Before a byte is decrypted, and in the same words `restore apply`
    // refuses in. This verb answers whether a bundle can be restored, and
    // every file opening says nothing about that on a bundle belonging to
    // another volume or another moment.
    var wrongOrigin = _bundleMismatch(report, checkedManifest, target.path, config,
      "No file in it was decrypted, and nothing under " + config.paths.dataDir +
      " was read or written.");
    if (wrongOrigin !== 0) return wrongOrigin;
    // Every file is decrypted into a private directory under the temp
    // directory and removed afterwards, so that filesystem has to hold
    // the whole plaintext for a moment.
    var noScratchRoom = _refuseWithoutRoom(report, nodeOs.tmpdir(),
      _plaintextBytes(checkedManifest), "Verifying " + target.path);
    if (noScratchRoom !== 0) return noScratchRoom;
    var outcome;
    var scratch = _scratchDir("verify");
    try {
      var extracted = await b.restoreBundle.extract({
        bundleDir:           verifiedDir,
        stagingDir:          _under(scratch, "staging"),
        passphrase:          passphrase,
        requireSignature:    true,
        expectedFingerprint: _fingerprintToCheck(checkedManifest, flags.fingerprint) || undefined,
      });
      outcome = {
        bundleId:   target.path,
        fileCount:  extracted.fileCount,
        totalBytes: extracted.totalBytes,
        signature:  _manifestSignature(extracted.manifest, flags.fingerprint),
      };
    } catch (err) {
      return report.error(target.path + " does not open: " +
        ((err && err.message) || String(err)));
    } finally {
      _dropScratch(scratch);
    }
    var pinnedVerify = typeof flags.fingerprint === "string" && flags.fingerprint.length > 0;
    return _emit(report, flags, { ok: true, verify: outcome }, [
      outcome.bundleId + " verifies.",
      "  " + outcome.fileCount + " file(s) decrypted and checksummed, " +
        outcome.totalBytes + " bytes",
      "  signature: " + (pinnedVerify
        ? "verified, key " + outcome.signature.fingerprint + ", the key --fingerprint named"
        : "verified against the key the manifest carries, " + outcome.signature.fingerprint +
          ", which says nothing about who wrote it without --fingerprint"),
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

      // Read the bundle back where storage put it before anything older is
      // deleted, so a bundle that cannot be used never reports success and
      // never costs the bundles before it.
      var stands = await _bundleStands(_storedBundleDir(chosen, summary.bundleId), passphrase,
        summary.bundleId, config);
      var signed = stands.signature || { ok: false, reason: stands.reason };
      var retained = null;
      if (stands.ok && keep !== null) {
        retained = await _sweepBundles(chosen, keep, passphrase, config);
      }
      await auditActor.record({
        action:   "blamepost.backup.written",
        outcome:  stands.ok ? "success" : "failure",
        actor:    auditActor.current(),
        resource: { kind: "backup_bundle", id: summary.bundleId },
        metadata: {
          storage:   chosen.root,
          fileCount: summary.fileCount,
          bytes:     summary.bundleSize,
          signed:    signed.ok === true,
          verified:  stands.ok,
          deleted:   retained === null ? [] : retained.deleted,
        },
      });
      await b.audit.flush();

      var runLines = [
        "Wrote bundle " + summary.bundleId + " to " + chosen.root,
        "  " + summary.fileCount + " file(s), " + summary.bundleSize + " bytes, in " +
          summary.durationMs + "ms",
        "  signature: " + (signed.ok
          ? "verified, key " + signed.fingerprint
          : "NOT verified: " + signed.reason),
      ];
      if (!stands.ok) {
        runLines.push("  This bundle cannot be used: " + stands.reason + ". Nothing older " +
          "was deleted.");
      }
      if (retained !== null) runLines = runLines.concat(_sweepLines(chosen, retained));
      runLines.push("  Restoring it needs this passphrase file and the vault passphrase. " +
        "Neither is in the bundle.");
      runLines.push("  A bundle nobody has restored is a hypothesis: `blamepost backup verify` " +
        "reads every file back.");
      _emit(report, flags,
        Object.assign({ signature: signed, verified: stands.ok, retention: retained }, summary),
        runLines);
      return stands.ok ? 0 : 1;
    }

    if (verb === "purge") {
      var swept = await _sweepBundles(chosen, keep, passphrase, config);
      // Storage holding bundles and not one of them verifying is a
      // passphrase or a volume that does not belong to this storage, not
      // a storage directory with nothing in it to delete.
      var noneStand = swept.kept.length === 0 && swept.notCounted.length > 0;
      await auditActor.record({
        action:   "blamepost.backup.purged",
        outcome:  noneStand ? "failure" : "success",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "backup_storage", id: chosen.root },
        metadata: {
          kept:       swept.kept,
          deleted:    swept.deleted,
          notCounted: swept.notCounted.map(function (entry) { return entry.bundleId; }),
        },
      });
      await b.audit.flush();
      if (noneStand) {
        _emit(report, flags, swept, ["None of the " + swept.notCounted.length + " bundle(s) in " +
          chosen.root + " verify with this passphrase and this volume's signing key, so " +
          "nothing was deleted."].concat(_sweepLines(chosen, swept)));
        return 1;
      }
      return _emit(report, flags, swept,
        ["Swept " + chosen.root + ", keeping the newest " + keep + " bundle(s) that verify."]
          .concat(_sweepLines(chosen, swept)));
    }

    return report.usage(USAGE_BACKUP);
  } finally {
    await store.close();
  }
}

// ---- restore ----------------------------------------------------------------

// A restore works inside the data directory. In the shipped container the
// data directory is the mount point of a volume: Linux will not rename it,
// will not rename a file into it from another filesystem such as the temp
// directory, and the image's user cannot create anything beside it. So the
// bundle is decrypted into the store's work directory on the volume, and
// the swap moves the entries at the top of the volume rather than the
// directory itself. The names the store reserves are never moved.
//
// Layout under the work directory, each name carrying the moment it was
// made:
//
//   incoming-<moment>/    a bundle decrypted and not yet in place
//   <moment>/             a rollback point: the entries a restore replaced
//   <moment>.json         what that restore was, for `list-rollbacks`
//   discarded-<moment>/   the entries a rollback replaced
//   in-flight.json        a move that has started and not finished

var ROLLBACK_POINT_NAME = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/;
var WORK_ENTRY_NAME = /^(?:incoming-|discarded-)?\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/;

function _restoreWork(dataDir) {
  return _under(dataDir, storeModule.RESTORE_WORK_DIR);
}

function _inFlightPath(dataDir) {
  return _under(_restoreWork(dataDir), storeModule.RESTORE_IN_FLIGHT);
}

function _markerPath(dataDir, pointName) {
  return _under(_restoreWork(dataDir), pointName + ".json");
}

// Whether a bundle entry lands on a name a restore writes. Bundles written
// before the store reserved its names carry the lock of the process that
// took them, and a lock naming a process in another container refuses
// every open of the restored volume.
function _restorableEntry(entry) {
  var first = String(entry.relativePath).split(/[\\/]/)[0];
  return storeModule.VOLUME_RESERVED.indexOf(first) === -1;
}

function _movableNames(dir) {
  var names;
  try {
    names = nodeFs.readdirSync(dir);
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw err;
  }
  return names.filter(function (name) {
    return storeModule.VOLUME_RESERVED.indexOf(name) === -1;
  }).sort();
}

function _isEmptyDir(dir) {
  try {
    return nodeFs.lstatSync(dir).isDirectory() && nodeFs.readdirSync(dir).length === 0;
  } catch (_err) {
    return false;
  }
}

function _occupied(target) {
  try {
    nodeFs.lstatSync(target);
    return true;
  } catch (_err) {
    return false;
  }
}

// Move every entry `from` holds into `to`. A name already present at the
// destination refuses the whole move before any entry moves, with one
// exception: an empty directory at the source is removed instead, because
// opening a volume creates the directories it expects and an undo meets
// those. Refusing first is what makes a second undo of a move that was
// already undone refuse rather than carry the volume off.
function _moveEntries(from, to) {
  var names = _movableNames(from);
  var collisions = names.filter(function (name) {
    return _occupied(_under(to, name)) && !_isEmptyDir(_under(from, name));
  });
  if (collisions.length > 0) {
    throw new Error(to + " already holds " + collisions.join(", ") + ", so nothing in " + from +
      " was moved");
  }
  b.atomicFile.ensureDir(to, 0o700);
  names.forEach(function (name) {
    var source = _under(from, name);
    var target = _under(to, name);
    if (_occupied(target)) {
      nodeFs.rmdirSync(source);
      return;
    }
    b.atomicFile.renameWithRetry(source, target);
  });
}

// Remove something in the work directory once the volume itself is
// settled. A removal that fails leaves clutter rather than a broken
// volume, so it is noted in `left` for the caller to report and not
// raised. `emptyOnly` removes a directory only when nothing is in it.
function _tidyWork(left, target, emptyOnly) {
  try {
    if (!emptyOnly) nodeFs.rmSync(target, { recursive: true, force: true });
    else if (_isEmptyDir(target)) nodeFs.rmdirSync(target);
  } catch (err) {
    left.push(target + " (" + ((err && err.message) || String(err)) + ")");
  }
}

// Remove the in-flight record once the files are where the verb left
// them. Answers null, or the reason it could not be removed: a record left
// in place keeps every open of the volume refusing, which the caller has
// to say.
function _settleInFlight(dataDir) {
  try {
    nodeFs.rmSync(_inFlightPath(dataDir), { force: true });
    return null;
  } catch (err) {
    return (err && err.message) || String(err);
  }
}

function _reportLeftovers(report, verb, left) {
  if (left.length === 0) return;
  report.writeErr("blamepost restore " + verb + ": these could not be removed from the work " +
    "directory and can be deleted by hand: " + left.join("; "));
}

function _writeInFlight(dataDir, record) {
  b.atomicFile.writeSync(_inFlightPath(dataDir), JSON.stringify(record, null, 2) + "\n",
    { fileMode: 0o600 });
}

// The record of a move that has not finished, null when there is none, or
// `{ unreadable }` when there is one this command cannot act on. A record
// naming a directory outside the work directory is one of those, since
// acting on it would move the volume somewhere nobody chose.
function _readInFlight(dataDir) {
  var recordPath = _inFlightPath(dataDir);
  if (!nodeFs.existsSync(recordPath)) return null;
  var parsed;
  try {
    parsed = JSON.parse(String(b.atomicFile.fdSafeReadSync(recordPath, {
      maxBytes: BYTES.kib(64), refuseSymlink: true, encoding: "utf8",
    })));
  } catch (err) {
    return { unreadable: (err && err.message) || String(err) };
  }
  if (!parsed || (parsed.operation !== "apply" && parsed.operation !== "rollback") ||
      (parsed.phase !== 1 && parsed.phase !== 2) ||
      !WORK_ENTRY_NAME.test(String(parsed.aside)) ||
      !WORK_ENTRY_NAME.test(String(parsed.incoming))) {
    return { unreadable: "it does not describe a move this command makes" };
  }
  return parsed;
}

// A moment no name in the work directory carries yet.
function _freshStamp(dataDir) {
  var work = _restoreWork(dataDir);
  for (var offset = 0; ; offset += 1) {
    var moment = new Date(Date.now() + offset);
    var stamp = b.atomicFile.pathTimestamp(moment);
    var taken = [stamp, "incoming-" + stamp, "discarded-" + stamp, stamp + ".json"]
      .some(function (name) { return nodeFs.existsSync(_under(work, name)); });
    if (!taken) return stamp;
  }
}

// Set the entries on the volume aside and put others in their place. The
// record is written before each half, so a process killed at any point
// leaves a record saying which entries are where.
function _swapVolume(dataDir, record) {
  var work = _restoreWork(dataDir);
  _writeInFlight(dataDir, Object.assign({}, record, { phase: 1 }));
  _moveEntries(dataDir, _under(work, record.aside));
  _writeInFlight(dataDir, Object.assign({}, record, { phase: 2 }));
  _moveEntries(_under(work, record.incoming), dataDir);
}

// Undo the move the record on the volume describes. Answers null when the
// volume is back as it was before the move started, and the reason
// otherwise, in which case the record stays and every open of the volume
// keeps refusing. The record goes as soon as the files are back, before
// anything is tidied, so it never describes a move that has already been
// undone. What could not be tidied is added to `left`.
function _undoInFlight(dataDir, left) {
  var record = _readInFlight(dataDir);
  if (record === null) return null;
  if (record.unreadable) {
    return _inFlightPath(dataDir) + " cannot be read (" + record.unreadable + "), so nothing " +
      "here can say where the volume's files are, and none was moved back.";
  }
  var work = _restoreWork(dataDir);
  // A move that reached its second half created the directory the old
  // entries went to and still has the one the new entries came from. When
  // either is gone, the move was already undone and tidied, or somebody
  // removed files by hand, and moving the volume's entries into a
  // directory that no longer holds anything would carry the volume off.
  if (record.phase === 2) {
    var gone = [record.aside, record.incoming].filter(function (name) {
      var dir = _under(work, name);
      return !_occupied(dir) || !nodeFs.lstatSync(dir).isDirectory();
    });
    if (gone.length > 0) {
      return _inFlightPath(dataDir) + " records a move between " + record.aside + " and " +
        record.incoming + " in " + work + ", and " + gone.join(" and ") + " is not there, so " +
        "that move has already been undone or its files were removed by hand. Nothing was " +
        "moved. Check that the volume is the one you want, then delete that file by hand.";
    }
  }
  try {
    if (record.phase === 2) {
      _moveEntries(dataDir, _under(work, record.incoming));
      // The entries that came in are out again, which is where a move
      // stopped in its first half stands. The record says so before any
      // original entry comes back, so an undo stopped from here on
      // resumes by putting the rest back rather than by moving them
      // toward the incoming entries that share their names.
      _writeInFlight(dataDir, Object.assign({}, record, { phase: 1 }));
    }
    _moveEntries(_under(work, record.aside), dataDir);
  } catch (err) {
    return "Putting the files back failed (" + ((err && err.message) || String(err)) + "). " +
      _inFlightPath(dataDir) + " still records where each file is, and every open of this " +
      "volume refuses until `blamepost restore rollback --confirm --reason <text>` has put " +
      "them back, which it does once the cause is fixed.";
  }
  var unsettled = _settleInFlight(dataDir);
  if (unsettled !== null) {
    return "Every file was put back, and " + _inFlightPath(dataDir) + " could not be removed (" +
      unsettled + "). Every open of this volume refuses while it exists, so delete it by hand. " +
      "`blamepost restore rollback` refuses it too, because the move it records has already " +
      "been undone.";
  }
  if (record.operation === "apply") _tidyWork(left, _under(work, record.incoming), false);
  _tidyWork(left, _under(work, record.aside), true);
  return null;
}

// Bundles decrypted by a restore that was stopped before it moved a file.
// Nothing refers to them once no move is in flight.
function _dropStaleIncoming(dataDir) {
  var work = _restoreWork(dataDir);
  _movableNames(work).forEach(function (name) {
    if (name.indexOf("incoming-") === 0 && WORK_ENTRY_NAME.test(name)) {
      nodeFs.rmSync(_under(work, name), { recursive: true, force: true });
    }
  });
}

// The rollback points on the volume, newest first.
function _rollbackPoints(dataDir) {
  var work = _restoreWork(dataDir);
  return _movableNames(work).filter(function (name) {
    return ROLLBACK_POINT_NAME.test(name) && nodeFs.lstatSync(_under(work, name)).isDirectory();
  }).sort().reverse().map(function (name) {
    var marker;
    try {
      marker = JSON.parse(String(b.atomicFile.fdSafeReadSync(_markerPath(dataDir, name), {
        maxBytes: BYTES.kib(64), refuseSymlink: true, encoding: "utf8",
      })));
    } catch (_err) {
      // A point whose marker is gone is still a point; the name carries
      // the moment it was set aside.
      marker = null;
    }
    return {
      name:         name,
      rollbackPath: _under(work, name),
      swappedAt:    (marker && marker.swappedAt) ||
        name.replace(/T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/, "T$1:$2:$3.$4Z"),
      marker:       marker,
    };
  });
}

// The origin verdict above, printed as the refusal an operator reads.
// `closing` is what this verb did about it, and it lands between the
// finding and what to do next, so the sentence an operator acts on is
// last. Answers 0, or the exit code of the refusal it printed.
//
// The manifest is not yet authenticated when a restore runs this, so it
// only ever refuses: an edit that made a bundle pass here has re-signed
// the manifest, and the signing key check after the volume opens refuses
// that.
function _bundleMismatch(report, manifest, bundleId, config, closing) {
  var fault = _originFault(manifest, bundleId, config);
  if (fault === null) return 0;
  return report.error(fault.detail + " " + closing + fault.remedy, fault.exit);
}

// Open the volume that has just been put in place and ask it the
// questions a restore is for. The framework refuses to open a database
// whose audit chain does not verify, so reaching this at all is part of
// the answer, and what it reports is the rest.
//
// `signedBy` is the fingerprint of the key that signed the bundle's
// manifest, or null for a rollback. The manifest carries the key it is
// checked under, so a signature that verifies says nothing about who made
// it. The audit signing key sealed inside the bundle is the one key its
// writer held, and an attacker holding neither passphrase can neither read
// it nor replace it, so the restored volume's own key is what the
// manifest's signer is held against.
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
async function _openRestoredVolume(config, record, signedBy) {
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
    if (signedBy) {
      var sealedKey = b.auditSign.getPublicKeyFingerprint();
      if (sealedKey !== signedBy) {
        return { ok: false,
          reason: "the bundle's manifest was signed by key " + signedBy + ", and the audit " +
            "signing key sealed inside the bundle is " + sealedKey + ". Only the holder of that " +
            "key could have signed for this bundle, so its manifest was signed by somebody " +
            "else after it was written and the list of files it names cannot be trusted",
          chain: chain, checkpoints: checkpoints };
      }
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

// The lines both restore verbs print on standard error when the act stood
// and the row describing it did not. The volume that act replaced is the
// one that would have held the row, so nothing else on the machine does.
function _unrecordedNotes(report, verb, noun, verdict) {
  if (verdict.recorded === false) {
    report.writeErr("blamepost restore " + verb + ": the volume was " + noun + " and the row " +
      "recording it could not be written, so this volume's audit trail has no entry for it. " +
      "Note what was put in place and when somewhere else, and check where audit rows are " +
      "being written.");
  }
  // Written and not settled onto the volume is the same absence with a
  // different cause, so it is said rather than swallowed by a row that was
  // accepted into a buffer nobody drained.
  if (verdict.flushed === false) {
    report.writeErr("blamepost restore " + verb + ": the row recording it was written and " +
      "could not be settled onto the volume (" + verdict.flushReason + "), so the trail may " +
      "carry no entry for it. The volume itself stays " + noun + ".");
  }
}

// `restore apply` from the moment the volume is held.
async function _applyHeld(report, flags, config, chosen, bundleId, bundleDir, passphrase) {
  var started = Date.now();
  var dataDir = config.paths.dataDir;
  if (_readInFlight(dataDir) !== null) {
    return report.error("an earlier restore or rollback on this volume stopped partway, and " +
      _inFlightPath(dataDir) + " records where it left each file. Nothing was restored. Run " +
      "`blamepost restore rollback --confirm --reason <text>` to put back the volume it " +
      "replaced, then run this again.");
  }
  // Read before anything is decrypted or moved, so the answer describes the
  // storage the operator chose this bundle from.
  var newerBundles;
  try {
    newerBundles = (await chosen.storage.listBundles()).filter(function (entry) {
      return entry.bundleId > bundleId;
    }).length;
  } catch (_err) {
    // Reported as not read rather than as none.
    newerBundles = null;
  }

  var work = _restoreWork(dataDir);
  b.atomicFile.ensureDir(work, 0o700);
  _dropStaleIncoming(dataDir);

  // Where the replaced volume's trail had reached, read from the record
  // beside its database before anything moves.
  var replaced = storeModule.recordedAnchor(dataDir);
  var stamp = _freshStamp(dataDir);
  var record = {
    version:   1,
    operation: "apply",
    aside:     stamp,
    incoming:  "incoming-" + stamp,
    startedAt: new Date(started).toISOString(),
    bundleId:  bundleId,
    reason:    flags.reason,
  };
  var incomingDir = _under(work, record.incoming);

  var extracted;
  try {
    // With no pin, the signature is checked against the key the manifest
    // carries, and that key is held against the volume's own signing key
    // once the restored volume opens. The origin the manifest records is
    // held against this server after extraction, on the reading the files
    // came from.
    var expectedFingerprint = _fingerprintToCheck(
      _readBundle(bundleDir, bundleId, config).manifest, flags.fingerprint);
    extracted = await b.restoreBundle.extract({
      bundleDir:           bundleDir,
      stagingDir:          incomingDir,
      passphrase:          passphrase,
      requireSignature:    true,
      expectedFingerprint: expectedFingerprint || undefined,
      filter:              _restorableEntry,
    });
  } catch (err) {
    return report.error("nothing was restored: " + ((err && err.message) || String(err)));
  }
  // The manifest is read a second time to decrypt, so the checks made on
  // the first reading are made again on the reading the files came from.
  var left = [];
  var changed = _bundleMismatch(report, extracted.manifest, bundleId, config,
    "Nothing was restored.");
  if (changed !== 0) {
    _tidyWork(left, incomingDir, false);
    _reportLeftovers(report, "apply", left);
    return changed;
  }
  // `extracted` also carries the vault keypair the bundle was sealed with,
  // which is the key to every sealed column on the volume, so only the
  // fields named here are read from it and nothing built from the whole
  // object is printed.
  var signedBy = _manifestSignature(extracted.manifest, null).fingerprint;
  var bundleCreatedAt = extracted.manifest.createdAt;
  var fileCount = extracted.fileCount;
  var totalBytes = extracted.totalBytes;

  try {
    _swapVolume(dataDir, record);
  } catch (err) {
    var swapFailure = (err && err.message) || String(err);
    var notPutBack = _undoInFlight(dataDir, left);
    if (notPutBack === null) {
      _tidyWork(left, incomingDir, false);
      _reportLeftovers(report, "apply", left);
      return report.error("nothing was restored: moving the volume's files failed (" +
        swapFailure + "), and every file was put back where it was.");
    }
    return report.error("moving the volume's files failed (" + swapFailure + "). " + notPutBack);
  }

  var restored = storeModule.recordedAnchor(dataDir);
  var rollbackPath = _isEmptyDir(_under(work, stamp)) ? null : _under(work, stamp);
  var verdict = await _openRestoredVolume(config, function (found) {
    return auditActor.record({
      action:   "blamepost.restore.applied",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   flags.reason,
      resource: { kind: "data_volume", id: dataDir },
      metadata: {
        bundleId:        bundleId,
        bundleCreatedAt: bundleCreatedAt,
        storage:         chosen.root,
        rollbackPath:    rollbackPath,
        replacedAnchor:  replaced === null ? null : replaced.counter,
        restoredAnchor:  restored === null ? null : restored.counter,
        accounts:        found.accounts,
        domains:         found.domains,
      },
    });
  }, signedBy);

  if (!verdict.ok) {
    // A restore that lands and does not verify is the failure this verb
    // exists to survive, so the entries it replaced go back.
    var undoFailure = _undoInFlight(dataDir, left);
    report.writeErr("blamepost restore apply: the restored data directory did not open: " +
      verdict.reason);
    _reportLeftovers(report, "apply", left);
    _emit(report, flags,
      { ok: false, bundleId: bundleId, reason: verdict.reason, putBack: undoFailure === null },
      [undoFailure === null
        ? "Nothing was restored. The volume that was here before is back in place."
        : "The volume that was here before is not back in place. " + undoFailure]);
    return 1;
  }

  // The restore stands from here. The record goes first, so a failure
  // tidying afterwards cannot leave a record describing a move that
  // finished.
  var standing = _settleInFlight(dataDir);
  if (standing !== null) {
    report.writeErr("blamepost restore apply: the volume was restored and verified, and " +
      _inFlightPath(dataDir) + " could not be removed (" + standing + "). Every open of this " +
      "volume refuses while it exists. Delete it by hand to keep this volume, or run " +
      "`blamepost restore rollback --confirm --reason <text>` to put back the one it replaced.");
    return 1;
  }
  _tidyWork(left, incomingDir, false);
  if (rollbackPath === null) {
    _tidyWork(left, _under(work, stamp), true);
  } else {
    try {
      b.atomicFile.writeSync(_markerPath(dataDir, stamp), JSON.stringify({
        version:         1,
        swappedAt:       new Date().toISOString(),
        bundleId:        bundleId,
        bundleCreatedAt: bundleCreatedAt,
        reason:          flags.reason,
      }, null, 2) + "\n", { fileMode: 0o600 });
    } catch (err) {
      report.writeErr("blamepost restore apply: the description of the rollback point at " +
        rollbackPath + " could not be written (" + ((err && err.message) || String(err)) +
        "). The point is still listed and still usable.");
    }
  }
  _reportLeftovers(report, "apply", left);

  _unrecordedNotes(report, "apply", "restored", verdict);

  var replacedCounter = replaced === null ? null : replaced.counter;
  var restoredCounter = restored === null ? null : restored.counter;

  var lines = [
    "Restored " + bundleId + " into " + dataDir,
    "  " + fileCount + " file(s), " + totalBytes + " bytes, in " + (Date.now() - started) + "ms",
    "  taken:    " + bundleCreatedAt,
    "  signed:   key " + signedBy + ", the audit signing key the restored volume holds",
    rollbackPath
      ? "  kept the entries it replaced at " + rollbackPath
      : "  nothing was here to replace, so no rollback point was kept",
    "  chain:    " + verdict.chain.rowsVerified + " row(s) verified, " +
      verdict.checkpoints.checkpointsVerified + " signed checkpoint(s)",
    "  holds:    " + verdict.accounts + " account(s) across " + verdict.domains + " domain(s)",
  ];
  if (replacedCounter !== null && restoredCounter !== null && replacedCounter > restoredCounter) {
    lines.push("  rewinds:  the volume it replaced had anchored its audit trail at counter " +
      replacedCounter + ", and this bundle's trail is anchored at counter " + restoredCounter +
      ". What the trail recorded in between is not on this volume: accounts, credentials, " +
      "aliases and keys added, changed, revoked or removed since " + bundleCreatedAt + " are " +
      "as they were then. Those rows are in the rollback point.");
  } else if (replacedCounter === null && rollbackPath) {
    lines.push("  rewinds:  the volume it replaced held no readable record of where its audit " +
      "trail had reached, so nothing here can say how much this restore rewinds.");
  }
  if (newerBundles === null) {
    lines.push("  storage:  the bundles in " + chosen.root + " could not be listed, so nothing " +
      "here can say whether a newer one exists.");
  } else if (newerBundles > 0) {
    lines.push("  storage:  " + newerBundles + " bundle(s) in " + chosen.root + " are newer " +
      "than this one.");
  }

  return _emit(report, flags, {
    ok:              true,
    bundleId:        bundleId,
    bundleCreatedAt: bundleCreatedAt,
    signedBy:        signedBy,
    fileCount:       fileCount,
    totalBytes:      totalBytes,
    rollbackPath:    rollbackPath,
    replacedAnchor:  replacedCounter,
    restoredAnchor:  restoredCounter,
    newerBundles:    newerBundles,
    durationMs:      Date.now() - started,
    verified:        true,
    chain:           verdict.chain,
    checkpoints:     verdict.checkpoints,
    accounts:        verdict.accounts,
    domains:         verdict.domains,
  }, lines.concat([
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
  ]));
}

// `restore rollback` from the moment the volume is held. With a move on
// record that did not finish, it undoes that move; otherwise it puts a
// rollback point back.
async function _rollbackHeld(report, flags, config) {
  var dataDir = config.paths.dataDir;
  var work = _restoreWork(dataDir);
  var left = [];

  var pending = _readInFlight(dataDir);
  if (pending !== null) {
    if (flags.point !== undefined) {
      return report.error("an earlier restore or rollback on this volume stopped partway, and " +
        "it has to be undone before a rollback point can be chosen. Run this again without " +
        "--point.", 2);
    }
    if (pending.unreadable) {
      return report.error(_inFlightPath(dataDir) + " cannot be read, so nothing here can say " +
        "where the volume's files are: " + pending.unreadable + ". Nothing was moved.");
    }
    var what = pending.operation === "apply"
      ? "the restore of " + pending.bundleId
      : "the rollback";
    var stuck = _undoInFlight(dataDir, left);
    _reportLeftovers(report, "rollback", left);
    if (stuck !== null) {
      return report.error(what + " that stopped partway was not undone. " + stuck);
    }
    var recovered = await _openRestoredVolume(config, function (found) {
      return auditActor.record({
        action:   "blamepost.restore.rolled_back",
        outcome:  "success",
        actor:    auditActor.current(),
        reason:   flags.reason,
        resource: { kind: "data_volume", id: dataDir },
        metadata: {
          interrupted: pending.operation,
          bundleId:    pending.bundleId || null,
          startedAt:   pending.startedAt || null,
          accounts:    found.accounts,
          domains:     found.domains,
        },
      });
    }, null);
    if (recovered.ok) _unrecordedNotes(report, "rollback", "rolled back", recovered);
    _emit(report, flags,
      { ok: recovered.ok, verified: recovered.ok, undone: pending.operation,
        bundleId: pending.bundleId || null },
      ["Undid " + what + " that stopped partway, and put back the volume that was here " +
        "before it started.",
      recovered.ok
        ? "  It opened and its audit chain verified."
        : "  It did NOT open: " + recovered.reason]);
    return recovered.ok ? 0 : 1;
  }

  var points = _rollbackPoints(dataDir);
  var point = null;
  if (flags.point !== undefined) {
    var named = String(flags.point);
    point = points.filter(function (candidate) {
      return candidate.name === named ||
        nodePath.resolve(candidate.rollbackPath) === nodePath.resolve(named);
    })[0] || null;
    if (point === null) {
      return report.error(JSON.stringify(named) + " is not one of this volume's rollback " +
        "points, so nothing was moved. `blamepost restore list-rollbacks` prints the ones it " +
        "holds.", 2);
    }
  } else {
    if (points.length === 0) {
      return report.error("this volume holds no rollback point, so there is nothing to put " +
        "back. One is kept every time `blamepost restore apply` replaces a volume.", 2);
    }
    point = points[0];
  }

  var stamp = _freshStamp(dataDir);
  var record = {
    version:   1,
    operation: "rollback",
    aside:     "discarded-" + stamp,
    incoming:  point.name,
    startedAt: new Date().toISOString(),
    reason:    flags.reason,
  };
  try {
    _swapVolume(dataDir, record);
  } catch (err) {
    var swapFailure = (err && err.message) || String(err);
    var notPutBack = _undoInFlight(dataDir, left);
    _reportLeftovers(report, "rollback", left);
    if (notPutBack === null) {
      return report.error("nothing was rolled back: moving the volume's files failed (" +
        swapFailure + "), and every file was put back where it was.");
    }
    return report.error("moving the volume's files failed (" + swapFailure + "). " + notPutBack);
  }

  var discardedAt = _isEmptyDir(_under(work, record.aside)) ? null : _under(work, record.aside);
  var back = await _openRestoredVolume(config, function (found) {
    return auditActor.record({
      action:   "blamepost.restore.rolled_back",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   flags.reason,
      resource: { kind: "data_volume", id: dataDir },
      metadata: {
        restoredFrom: point.rollbackPath,
        discarded:    discardedAt,
        accounts:     found.accounts,
        domains:      found.domains,
      },
    });
  }, null);

  if (!back.ok) {
    var undoFailure = _undoInFlight(dataDir, left);
    report.writeErr("blamepost restore rollback: the rollback point did not open: " + back.reason);
    _reportLeftovers(report, "rollback", left);
    _emit(report, flags,
      { ok: false, verified: false, rollbackPath: point.rollbackPath, reason: back.reason,
        putBack: undoFailure === null },
      ["The rollback point at " + point.rollbackPath + " did NOT open: " + back.reason,
        undoFailure === null
          ? "  The volume that was live before this ran is back in place, and the point is " +
            "still at " + point.rollbackPath + "."
          : "  The volume that was live before this ran is not back in place. " + undoFailure]);
    return 1;
  }

  // The rollback stands from here, so the record goes before anything is
  // tidied.
  var standing = _settleInFlight(dataDir);
  if (standing !== null) {
    report.writeErr("blamepost restore rollback: the volume was rolled back and verified, and " +
      _inFlightPath(dataDir) + " could not be removed (" + standing + "). Every open of this " +
      "volume refuses while it exists. Delete it by hand to keep this volume, or run this " +
      "command again to put back the entries it replaced.");
    return 1;
  }
  _tidyWork(left, point.rollbackPath, true);
  _tidyWork(left, _markerPath(dataDir, point.name), false);
  if (discardedAt === null) _tidyWork(left, _under(work, record.aside), true);
  _reportLeftovers(report, "rollback", left);

  // The rollback stands either way, and an operator standing at a
  // terminal is the one caller who can be told that the volume they just
  // put back holds no record of the putting back.
  _unrecordedNotes(report, "rollback", "rolled back", back);
  _emit(report, flags,
    { ok: true, verified: true, restoredFrom: point.rollbackPath, discardedAt: discardedAt }, [
      "Rolled back to " + point.rollbackPath,
      discardedAt
        ? "  The entries that were live are kept at " + discardedAt
        : "  Nothing was live, so nothing was kept.",
      "  It opened and its audit chain verified.",
    ]);
  return 0;
}

async function cmdRestore(flags, positionals) {
  var report = _reporter("restore");
  var verb = positionals[0];
  if (!verb) return report.usage(USAGE_RESTORE);
  var unread = _refuseUnread(report, "restore", verb, flags, positionals);
  if (unread !== 0) return unread;
  var config = _configFrom(flags);

  if (verb === "list-rollbacks") {
    var listedDir = config.paths.dataDir;
    var pending = _readInFlight(listedDir);
    if (pending !== null) {
      report.writeErr("blamepost restore list-rollbacks: " + (pending.unreadable
        ? _inFlightPath(listedDir) + " records a restore or rollback that did not finish and " +
          "cannot be read (" + pending.unreadable + ")"
        : "a " + (pending.operation === "apply" ? "restore" : "rollback") + " started at " +
          JSON.stringify(pending.startedAt) + " stopped partway, and " +
          _inFlightPath(listedDir) + " records it") + ". Every open of this volume refuses " +
        "until `blamepost restore rollback --confirm --reason <text>` has put it back.");
    }
    var points = _rollbackPoints(listedDir);
    return _emit(report, flags, points, points.length === 0
      ? ["No rollback points. One is kept every time `blamepost restore apply` replaces a " +
        "volume."]
      : [points.length + " rollback point(s), newest first"].concat(
        points.map(function (point) {
          var marker = point.marker || {};
          return "  " + point.rollbackPath + "\n" +
            "    swapped " + point.swappedAt +
            (marker.bundleId ? "\n    bundle  " + marker.bundleId : "") +
            (marker.reason ? "\n    reason  " + marker.reason : "");
        })));
  }

  if (verb === "rollback") {
    var confirmedRollback = _requireConfirmation(report, flags,
      "Rolling back replaces the live data volume with the entries kept before a restore.");
    if (confirmedRollback !== 0) return confirmedRollback;
    var rollbackHold;
    try {
      rollbackHold = storeModule.holdVolume(config);
    } catch (err) {
      return report.error("nothing was rolled back: " + ((err && err.message) || String(err)));
    }
    try {
      return await _rollbackHeld(report, flags, config);
    } finally {
      rollbackHold.release();
    }
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

    // What the manifest records about where the bundle came from, and the
    // room its files need, are both read without the passphrase and
    // without the volume, so a bundle that cannot be restored here is
    // refused before anything is held or moved.
    var bundleDir = _storedBundleDir(chosen, wanted.path);
    var described;
    try {
      described = _readBundle(bundleDir, wanted.path, config).manifest;
    } catch (err) {
      return report.error(wanted.path + " cannot be read, so nothing was restored: " +
        ((err && err.message) || String(err)));
    }
    var mismatch = _bundleMismatch(report, described, wanted.path, config,
      "Nothing was restored.");
    if (mismatch !== 0) return mismatch;
    var noRoom = _refuseWithoutRoom(report, config.paths.dataDir,
      _plaintextBytes(described, _restorableEntry),
      "Restoring " + wanted.path);
    if (noRoom !== 0) return noRoom;

    var applyHold;
    try {
      applyHold = storeModule.holdVolume(config);
    } catch (err) {
      return report.error("nothing was restored: " + ((err && err.message) || String(err)));
    }
    try {
      return await _applyHeld(report, flags, config, chosen, wanted.path, bundleDir,
        read.passphrase);
    } finally {
      applyHold.release();
    }
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
//
// Both writes go through the screen. The message is whatever the layer
// underneath was holding, which for an unreadable argument is the token
// itself and for a refused lookup is the name that was looked up, and
// the stack carries that same message on its first line. The stack is
// screened per line by the same helper the reporter uses, so the frames
// below it stay on their own lines.
function _reportFailure(command, err) {
  var message = _linesForDisplay((err && err.message) || String(err));
  var argumentFault = _isArgumentFault(err);
  process.stderr.write("blamepost" + (command ? " " + command : "") + ": " + message + "\n");
  // The level in effect rather than the environment variable. A level
  // written in the configuration file is an equal origin everywhere else
  // it is read, and an operator who set `logLevel` there and got no
  // trace was reading a document that promised one.
  if (configModule.logLevelInEffect() === "debug") {
    if (err && err.stack) process.stderr.write(_linesForDisplay(err.stack) + "\n");
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
    case "zone":    return await cmdZone(flags, positionals);
    case "credential": return await cmdCredential(flags, positionals);
    case "reports": return await cmdReports(flags, positionals);
    case "dmarc":   return await cmdDmarc(flags, positionals);
    case "queue":   return await cmdQueue(flags, positionals);
    case "blobs":   return await cmdBlobs(flags, positionals);
    case "attachments": return await cmdAttachments(flags, positionals);
    case "doctor":  return await cmdDoctor(flags);
    case "audit":   return await cmdAudit(flags, positionals);
    case "backup":  return await cmdBackup(flags, positionals);
    case "restore": return await cmdRestore(flags, positionals);
    default:
      // The name is quoted back so the operator can see what was read,
      // and it is screened for the same reason every other quoted value
      // here is: an argument reaching this server from a container
      // entrypoint, a scheduled job or a line copied off a page is not
      // text this server wrote.
      process.stderr.write("blamepost: no command named '" +
        _linesForDisplay(command) + "'\n");
      return 2;
  }
}

async function main(argv) {
  var parser = _parser();
  var parsed;
  try {
    parsed = parser.parse(argv);
  } catch (err) {
    process.stderr.write("blamepost: " +
      _linesForDisplay((err && err.message) || String(err)) + "\n");
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
