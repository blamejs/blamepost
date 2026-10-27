// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which of the things a filter script asks for actually reach the
 * message, and what the account holder is told about the rest.
 *
 * Two ways a stored filter stops doing what it says, both silent from
 * where its author is standing.
 *
 * The first is a name the parser reads and the interpreter does not
 * carry. RFC 5228 section 3.2 has an author declare an extension in
 * `require`, and a `require` naming one this server cannot run is
 * refused while the author is looking at the error. An action written
 * WITHOUT that declaration is not declared, so the grammar reads it as
 * an ordinary command and the name is resolved at delivery instead:
 * `vacation`, `reject`, `addflag`, and a plain misspelling of
 * `fileinto` all pass the check RFC 5804 section 2.6 asks for. The
 * script is stored, activated, and then refused once per arriving
 * message, and a refusal there costs the WHOLE script, including the
 * rules that were working the day before the author added the line.
 *
 * The second is an action the interpreter emits and delivery does not
 * apply. A message is filed once here, so a script naming two
 * destinations gets one of them, and which one it gets should follow
 * from what the author wrote rather than from the order they wrote it
 * in. RFC 5228 section 2.10.3 lets an implementation limit the actions
 * it takes and requires it to say when it did.
 *
 * Run standalone: node test/layer-2-integration/sieve-action-reach.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var PEER     = "sender@example.net";
var ALIAS    = "sales@example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var count = helpers.count;

var plainResponse = wire.saslPlain;

// The rule that works, and the same rule with one more line under it.
// The added line is the shape an author reaches for after reading the
// RFC index: `reject` is RFC 5429 and needs a `require` this server
// refuses, so an author who leaves the `require` off gets a script the
// parser accepts and the interpreter will not run.
var WORKING_FILTER =
  "require [\"fileinto\"];\n" +
  "if header :contains \"X-Category\" \"filed\" { fileinto \"Junk\"; }\n";

var EDITED_FILTER = WORKING_FILTER +
  "if header :contains \"X-Category\" \"never\" { reject \"not here\"; }\n";

// The three code points a hostile folder name is built from, and the
// pattern that looks for them coming back out. Both are built rather
// than written: a raw control octet does not survive being written into
// a source file, and one in this file would leave every gate reading it
// as binary and scanning none of it.
var RLO  = String.fromCharCode(0x202e);
var ZWSP = String.fromCharCode(0x200b);
var CSI  = String.fromCharCode(0x009b);
var ACTS_ON_READER = new RegExp(
  "[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u202a-\\u202e]");

// ---- driving the wire ------------------------------------------------------

async function deliver(mxPort, caPem, to, category) {
  var peer = await Wire.mx(mxPort, { caPem: caPem, servername: HOSTNAME, label: "mx-deliver" });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + to + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw([
    "From: " + PEER,
    "To: " + to,
    "Subject: one " + category + " message",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + category + Date.now() + "@example.net>",
    "X-Category: " + category,
    "",
    "Body.",
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");
  var reply = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

async function imapSession(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
  await session.read(/^a1 OK/m, "authenticated");
  return session;
}

// One reader per case rather than one per reading. Each `SELECT` on an
// open session answers the count, so a case that measures a folder
// before and after a delivery costs one connection rather than four.
// Opening one per reading spent the listener's connection budget for
// the peer address partway through the run, which is the budget doing
// its job and is not what this file is measuring.
function reader(port, caPem, address, label) {
  var session = null;
  var tag = 0;
  return {
    // How many messages a folder holds, read the way a client reads it.
    count: async function (folder) {
      if (session === null) session = await imapSession(port, caPem, address, label);
      tag += 1;
      var t = "s" + tag;
      session.send(t + " SELECT " + folder);
      var selected = await session.read(new RegExp("^" + t + " (OK|NO|BAD)", "m"),
        "SELECT " + folder + " answered");
      if (!new RegExp("^" + t + " OK", "m").test(selected)) return -1;
      var m = /^\* (\d+) EXISTS/m.exec(selected);
      return m ? Number(m[1]) : -1;
    },
    close: function () {
      if (session === null) return;
      tag += 1;
      session.send("s" + tag + " LOGOUT");
      session.close();
      session = null;
    },
  };
}

function putRefusal(identity, actor, name, body) {
  try {
    identity.mailbox.sieveScripts.put(actor, name, body);
    return null;
  } catch (e) { return e; }
}

// ---- cases -----------------------------------------------------------------

// RFC 5804 section 2.6 has the server check a script before it accepts
// one. The check has to answer the question the account holder is
// actually asking, which is whether this filter will run, not whether
// its punctuation is in the right places.
function anUnrunnableNameIsRefusedWhileTheAuthorIsPresent(identity, alice, address) {
  var actor = { id: alice.id, address: address, roles: ["account"] };

  // Each of these parses. None of them runs: the grammar reads any
  // identifier followed by arguments and a semicolon as a command, and
  // the interpreter resolves the name at delivery.
  var unrunnable = [
    { name: "away",     body: "vacation :days 7 \"back next week\";\n",
      why:  "an RFC 5230 responder written without its require" },
    { name: "bounce",   body: "reject \"not accepting mail\";\n",
      why:  "an RFC 5429 refusal written without its require" },
    { name: "flagged",  body: "addflag \"\\\\Seen\";\n",
      why:  "an RFC 5232 flag action written without its require" },
    { name: "mistyped", body: "require [\"fileinto\"];\nfileinfo \"Junk\";\n",
      why:  "a misspelling of an action this server does carry" },
    { name: "untested", body: "if spamtest :is \"5\" { discard; }\n",
      why:  "a test this server does not carry" },
  ];

  for (var i = 0; i < unrunnable.length; i += 1) {
    var entry = unrunnable[i];
    var threw = putRefusal(identity, actor, entry.name, entry.body);
    count(entry.why + " is refused when it is uploaded",
      threw !== null && threw.code === "mailbox/script-refused",
      threw ? threw.code + ": " + threw.message.slice(0, 120) : "accepted");
    count("and " + entry.why + " leaves nothing stored",
      identity.mailbox.sieveScripts.get(actor, entry.name) === null,
      JSON.stringify(identity.mailbox.sieveScripts.get(actor, entry.name)));
  }

  // The refusal quotes the interpreter quoting the script, so the name
  // in it was written by whoever holds the account.
  var quoted = putRefusal(identity, actor, "quoted",
    "vacation :days 7 \"back next week\";\n");
  count("and the refusal names what could not be run",
    quoted !== null && /vacation/.test(quoted.message),
    quoted ? quoted.message.slice(0, 160) : "accepted");
}

// The behavioral half, driven the way an account holder drives it: a
// filter that works, then an edit, then the next message.
async function anEditThatCannotRunDoesNotSilentlyStopTheFilter(
  ports, caPem, address, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };

  var look = reader(ports.imap, caPem, address, "edit-reader");
  try {
  identity.mailbox.sieveScripts.put(actor, "daily", WORKING_FILTER);
  identity.mailbox.sieveScripts.setActive(actor, "daily");

  var junkBefore = await look.count("Junk");
  await deliver(ports.mx, caPem, address, "filed");
  var junkAfter = await look.count("Junk");
  count("the filter files the message before the edit",
    junkAfter === junkBefore + 1, "Junk before " + junkBefore + ", after " + junkAfter);

  // The edit. It keeps every line that was working and adds one whose
  // name the interpreter does not carry.
  var threw = putRefusal(identity, actor, "daily", EDITED_FILTER);
  count("an edit adding a line this server cannot run is refused",
    threw !== null && threw.code === "mailbox/script-refused",
    threw ? threw.code + ": " + threw.message.slice(0, 120) : "accepted");

  var stored = identity.mailbox.sieveScripts.get(actor, "daily");
  count("and the refused edit leaves the working script as it was",
    stored !== null && stored.body === WORKING_FILTER,
    stored ? JSON.stringify(stored.body.slice(0, 80)) : "null");

  // The line that matters: mail keeps being filed. Before this, the
  // edit was accepted and every message from that moment went to INBOX,
  // which is where an author looking for their filed mail does not look.
  var inboxBefore2 = await look.count("INBOX");
  var junkBefore2  = await look.count("Junk");
  var reply = await deliver(ports.mx, caPem, address, "filed");
  count("the peer's message is accepted", /^250 /m.test(reply), visible(reply));

  var junkAfter2  = await look.count("Junk");
  var inboxAfter2 = await look.count("INBOX");
  count("and the next message is still filed where the filter says",
    junkAfter2 === junkBefore2 + 1, "Junk before " + junkBefore2 + ", after " + junkAfter2);
  count("rather than falling into INBOX with the filter dead",
    inboxAfter2 === inboxBefore2, "INBOX before " + inboxBefore2 + ", after " + inboxAfter2);
  } finally { look.close(); }
}

// A message is filed once here. Which destination it takes follows from
// what the author wrote, not from the order they wrote it in, and the
// one that was not used is reported rather than dropped in silence.
async function anExplicitFolderOutranksTheKeepWrittenBesideIt(
  ports, caPem, address, identity, alice, audit) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  var look = reader(ports.imap, caPem, address, "both-reader");
  try {
  identity.mailbox.sieveScripts.put(actor, "both",
    "require [\"fileinto\"];\n" +
    "keep;\n" +
    "if header :contains \"X-Category\" \"both\" { fileinto \"Junk\"; }\n");
  identity.mailbox.sieveScripts.setActive(actor, "both");

  var inboxBefore = await look.count("INBOX");
  var junkBefore  = await look.count("Junk");

  var before = audit.forAction("blamepost.mail.sieve.action_unavailable").length;
  await deliver(ports.mx, caPem, address, "both");

  var inboxAfter = await look.count("INBOX");
  var junkAfter  = await look.count("Junk");

  count("a keep written beside a fileinto does not take the folder the script named",
    junkAfter === junkBefore + 1, "Junk before " + junkBefore + ", after " + junkAfter);
  count("and the message is not left in INBOX instead",
    inboxAfter === inboxBefore, "INBOX before " + inboxBefore + ", after " + inboxAfter);

  // The row is written where the delivery ran and reaches the capture on
  // its own schedule, so the wait is on the row rather than on a budget.
  var reported = true;
  try {
    await helpers.waitUntil(function () {
      return audit.forAction("blamepost.mail.sieve.action_unavailable").length > before;
    }, { timeoutMs: 5000, label: "sieve-action-reach: the unapplied keep is reported" });
  } catch (_e) { reported = false; }

  var rows = audit.forAction("blamepost.mail.sieve.action_unavailable");
  count("and the copy that was not also made is reported",
    reported && rows.length === before + 1,
    rows.length + " rows, " + before + " before");
  count("naming the action the script asked for and this server did not take",
    rows.length > before &&
      helpers.metadataOf(rows[rows.length - 1]).sieveAction === "keep",
    JSON.stringify(rows.length ? helpers.metadataOf(rows[rows.length - 1]) : null));
  } finally { look.close(); }
}

// The folder a `fileinto` names is a string literal inside the account
// holder's own script. It is the one mailbox name on this server that
// was never a wire argument, so it reaches the name gate without having
// passed anything, and RFC 5228 section 4.1 says what happens when it
// cannot be used: the message is delivered somewhere the owner can read
// it rather than lost.
//
// The name is also printed, into a log line and into an audit row an
// operator reads in a terminal, so the second half of each case is that
// what comes back out carries no character that acts on the reader.
async function ahostileFolderNameEndsInInboxAndIsScreened(
  ports, caPem, address, identity, alice, audit) {
  var actor = { id: alice.id, address: address, roles: ["account"] };

  var hostile = [
    { why: "a relative path",                folder: "../../etc/passwd" },
    { why: "a relative level inside a path", folder: "INBOX/../Junk" },
    { why: "a name differing only in case",  folder: "junk" },
    { why: "a LIST wildcard",                folder: "*" },
    { why: "a right-to-left override",       folder: RLO + "knuJ" },
    { why: "a zero-width space",             folder: "Ju" + ZWSP + "nk" },
    { why: "a C1 control",                   folder: "Ju" + CSI + "nk" },
    { why: "a level padded with a space",    folder: "Junk " },
    { why: "an empty level",                 folder: "Junk//Deep" },
    { why: "a message address",              folder: "obj_deadbeef" },
  ];

  var before = audit.forAction("blamepost.mail.sieve.folder_missing").length;
  var look = reader(ports.imap, caPem, address, "hostile-reader");
  try {
  for (var i = 0; i < hostile.length; i += 1) {
    var entry = hostile[i];
    identity.mailbox.sieveScripts.put(actor, "hostile",
      "require [\"fileinto\"];\nfileinto \"" + entry.folder + "\";\n");
    identity.mailbox.sieveScripts.setActive(actor, "hostile");

    var inboxBefore = await look.count("INBOX");
    var junkBefore  = await look.count("Junk");
    var reply = await deliver(ports.mx, caPem, address, "hostile");
    count("a fileinto naming " + entry.why + " still lets the peer's message be accepted",
      /^250 /m.test(reply), visible(reply));

    var inboxAfter = await look.count("INBOX");
    var junkAfter  = await look.count("Junk");
    count("a fileinto naming " + entry.why + " delivers to INBOX rather than losing the message",
      inboxAfter === inboxBefore + 1, "INBOX before " + inboxBefore + ", after " + inboxAfter);
    count("and " + entry.why + " reaches no folder it was not written as",
      junkAfter === junkBefore, "Junk before " + junkBefore + ", after " + junkAfter);
  }

  await helpers.waitUntil(function () {
    return audit.forAction("blamepost.mail.sieve.folder_missing").length >=
      before + hostile.length;
  }, { timeoutMs: 5000, label: "sieve-action-reach: every refused folder is reported" });

  var rows = audit.forAction("blamepost.mail.sieve.folder_missing").slice(before);
  count("every refused folder is reported once", rows.length === hostile.length,
    rows.length + " rows for " + hostile.length + " names");

  // U+202E reorders the line it is printed on, U+009B opens an escape
  // sequence, and U+200B makes two names render identically. None of
  // them may survive into the row an operator reads.
  var unscreened = rows.filter(function (row) {
    var named = String(helpers.metadataOf(row).folder || "");
    return ACTS_ON_READER.test(named);
  });
  count("and the name each row quotes carries nothing that acts on the reader",
    unscreened.length === 0,
    JSON.stringify(unscreened.map(function (r) { return helpers.metadataOf(r).folder; })));
  } finally { look.close(); }
}

// RFC 5228 section 5.4 reads the envelope recipient, which is the
// address that caused the delivery. Filing by the address mail arrived
// at is the reason the test exists: one mailbox collects several
// addresses and the owner wants each in its own folder, and the only
// thing that tells them apart is the envelope, since every one of those
// messages carries the same `To` header as often as not.
//
// An alias is where the address that caused the delivery and the
// mailbox behind it stop being the same string, so it is the case that
// says which one the test is answering.
async function theEnvelopeTestReadsTheAddressMailArrivedAt(
  ports, caPem, address, alias, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  var look = reader(ports.imap, caPem, address, "envelope-reader");
  try {
  identity.mailbox.sieveScripts.put(actor, "by-alias",
    "require [\"fileinto\", \"envelope\"];\n" +
    "if envelope :is \"to\" \"" + alias + "\" { fileinto \"Junk\"; }\n");
  identity.mailbox.sieveScripts.setActive(actor, "by-alias");

  var inboxBefore = await look.count("INBOX");
  var junkBefore  = await look.count("Junk");

  var reply = await deliver(ports.mx, caPem, alias, "aliased");
  count("a message to the alias is accepted", /^250 /m.test(reply), visible(reply));

  var inboxAfter = await look.count("INBOX");
  var junkAfter  = await look.count("Junk");
  count("a script filing on the address mail arrived at files a message to the alias",
    junkAfter === junkBefore + 1, "Junk before " + junkBefore + ", after " + junkAfter);
  count("and does not leave it in INBOX unfiltered",
    inboxAfter === inboxBefore, "INBOX before " + inboxBefore + ", after " + inboxAfter);

  // The other direction, so the test is reading the envelope rather than
  // matching everything: mail to the mailbox's own address is not the
  // alias and must not be filed by that rule.
  var inboxBefore2 = await look.count("INBOX");
  var junkBefore2  = await look.count("Junk");
  await deliver(ports.mx, caPem, address, "direct");
  var inboxAfter2 = await look.count("INBOX");
  var junkAfter2  = await look.count("Junk");
  count("a message to the mailbox's own address takes the implicit keep",
    inboxAfter2 === inboxBefore2 + 1, "INBOX before " + inboxBefore2 + ", after " + inboxAfter2);
  count("and the rule written for the alias does not file it",
    junkAfter2 === junkBefore2, "Junk before " + junkBefore2 + ", after " + junkAfter2);
  } finally { look.close(); }
}

// The two orders a `keep` and a `discard` can be written in. Neither may
// end with the message gone: RFC 5228 section 2.10.2 has the explicit
// keep file the message and section 2.10.1 has discard cancel only the
// implicit one.
async function aKeepBesideADiscardStillKeeps(ports, caPem, address, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  var orders = [
    { name: "keep-first",    body: "keep;\ndiscard;\n" },
    { name: "discard-first", body: "discard;\nkeep;\n" },
  ];

  var look = reader(ports.imap, caPem, address, "keep-discard-reader");
  try {
    for (var i = 0; i < orders.length; i += 1) {
      identity.mailbox.sieveScripts.put(actor, orders[i].name, orders[i].body);
      identity.mailbox.sieveScripts.setActive(actor, orders[i].name);

      var before = await look.count("INBOX");
      await deliver(ports.mx, caPem, address, "keepdiscard");
      var after = await look.count("INBOX");
      count("a script written as '" + orders[i].name + "' keeps the message",
        after === before + 1, "INBOX before " + before + ", after " + after);
    }
  } finally { look.close(); }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sieve-action-reach");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server   = null;
  var running  = false;
  var identity = null;
  var audit    = null;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "sieve action reach test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    await identity.aliases.add({ address: ALIAS, destination: alice.address });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var ports = { mx: sections.mx.port, imap: sections.imap.port };

    anUnrunnableNameIsRefusedWhileTheAuthorIsPresent(identity, alice, alice.address);
    await anEditThatCannotRunDoesNotSilentlyStopTheFilter(
      ports, leaf.ca, alice.address, identity, alice);

    audit = helpers.auditCapture();
    await anExplicitFolderOutranksTheKeepWrittenBesideIt(
      ports, leaf.ca, alice.address, identity, alice, audit);
    await ahostileFolderNameEndsInInboxAndIsScreened(
      ports, leaf.ca, alice.address, identity, alice, audit);
    await theEnvelopeTestReadsTheAddressMailArrivedAt(
      ports, leaf.ca, alice.address, ALIAS, identity, alice);
    await aKeepBesideADiscardStillKeeps(ports, leaf.ca, alice.address, identity, alice);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (audit) {
      try { audit.release(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "sieve-action-reach", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
