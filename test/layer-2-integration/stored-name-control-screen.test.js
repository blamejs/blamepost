// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The names an account holder gets to choose, driven over the wires they
 * choose them on.
 *
 * A mailbox name and a Sieve script name are the two strings this server
 * takes from an account holder, stores, and then prints back: into a
 * LISTSCRIPTS reply, into an IMAP refusal, into a structured log line
 * and into an audit row. Every one of those is read by a terminal, and
 * the C1 range at U+0080 to U+009F is where a single code point becomes
 * an escape sequence: U+009B is the control sequence introducer, so a
 * name carrying it repaints whatever is reading the stream.
 *
 * The framework's control-character table stops at U+001F and U+007F.
 * `b.codepointClass.C0_CTRL_RANGES` is the C0 block and
 * `isForbiddenControlChar` adds the delete code point, so
 * `firstControlCharOffset` answers -1 for every code point in the C1
 * range. This server's own table for a field it stores is
 * `blamepost.text.hasControlChar`, which covers C0, delete and C1, and
 * the gates in front of both names asked the narrower question.
 *
 * Three gates and one screen, so the file drives all four:
 *
 *   - PUTSCRIPT and RENAMESCRIPT, over port 4190, where the name is
 *     stored under the account.
 *   - SELECT, over port 143, in both the quoted and the literal form the
 *     grammar gives a mailbox name, where the refusal quotes the name
 *     back to the client.
 *   - The folder a Sieve script names in `fileinto`, which is not a
 *     stored name at all: it is a literal inside a script body, and it
 *     reaches the operator's log and the audit row exactly on the path
 *     where the mailbox gate has already refused it.
 *
 * The byte is built from its code point rather than written, because a
 * raw C1 octet does not survive an editor or a file read intact.
 *
 * Run standalone: node test/layer-2-integration/stored-name-control-screen.test.js
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

var count        = helpers.count;
var auditCapture = helpers.auditCapture;
var metadataOf   = helpers.metadataOf;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var PEER     = "sender@example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The C1 control sequence introducer, and the range it sits in. Written
// from the code point for the reason the file block gives.
var CSI      = String.fromCharCode(0x9b);
var PAD      = String.fromCharCode(0x80);
var APC      = String.fromCharCode(0x9f);
var C1_RANGE = new RegExp("[" + String.fromCharCode(0x80) + "-" + String.fromCharCode(0x9f) + "]");

// One ManageSieve reply line.
var ONE_REPLY = /^(?:OK|NO|BYE)[^\r\n]*\r\n/m;

var lastReply = wire.lastManageSieveReply;

function replyTo(session, what) {
  return session.read(ONE_REPLY, what).then(lastReply);
}

// A command whose payload is a literal, in the non-synchronizing form
// RFC 5804 section 4 gives ManageSieve.
function sendLiteral(session, command, payload, note) {
  session.sendNonSyncLiteral(command, payload, note);
}

// ---- the script-name gate ---------------------------------------------------

// RFC 5804 section 1.6 makes a script name a UTF-8 string, and section
// 2.3 has the server refuse a PUTSCRIPT it will not carry out with NO.
// A name carrying a C1 control is one of those: it is stored under the
// account, echoed by LISTSCRIPTS to every client the account holder
// signs in with, and written into the operator's log on every message
// the script files.
async function aScriptNameCarryingAC1ControlIsRefused(session) {
  var hostile = "cs" + CSI + "i";
  sendLiteral(session, 'PUTSCRIPT "' + hostile + '"',
    'require ["fileinto"];\nkeep;\n', "<a script under a name carrying the C1 CSI>");
  var stored = await replyTo(session, "PUTSCRIPT answered");
  count("a PUTSCRIPT whose name carries a C1 control is refused, because the name is stored " +
    "and then printed into a listing, a log line and an audit row",
    /^NO/.test(stored), visible(stored));

  session.send("LISTSCRIPTS");
  var listing = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("and the refusal stored nothing, so no later client reads the control back",
    !C1_RANGE.test(listing), visible(listing));
}

// The whole range rather than the one code point that opens an escape
// sequence. A gate written around U+009B alone passes the other
// thirty-one, and the range is what the display screen this server
// already ships removes.
async function everyCodePointInTheC1RangeIsRefused(session) {
  var edges = [["the first C1 code point", PAD], ["the last C1 code point", APC]];
  for (var i = 0; i < edges.length; i += 1) {
    var name = "edge" + i + edges[i][1];
    sendLiteral(session, 'PUTSCRIPT "' + name + '"',
      'require ["fileinto"];\nkeep;\n', "<a script named with " + edges[i][0] + ">");
    var reply = await replyTo(session, "PUTSCRIPT answered");
    count("a script name carrying " + edges[i][0] + " is refused, so the gate covers the " +
      "range rather than the one code point that opens an escape sequence",
      /^NO/.test(reply), visible(reply));
  }
}

// RENAMESCRIPT is the second way a name enters the table, and a gate on
// the upload alone leaves it open: the account holder stores a name the
// rule accepts and then moves it to one the rule does not.
async function aRenameOntoAControlNameIsRefused(session) {
  sendLiteral(session, 'PUTSCRIPT "plain"',
    'require ["fileinto"];\nkeep;\n', "<a script under an ordinary name>");
  var stored = await replyTo(session, "PUTSCRIPT answered");
  count("a script under an ordinary name is stored", /^OK/.test(stored), visible(stored));

  session.send('RENAMESCRIPT "plain" "re' + CSI + 'named"');
  var renamed = await replyTo(session, "RENAMESCRIPT answered");
  count("RENAMESCRIPT onto a name carrying a C1 control is refused, so the gate on the " +
    "upload is not the only one",
    /^NO/.test(renamed), visible(renamed));

  session.send("LISTSCRIPTS");
  var listing = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  count("and the script is still under the name it was stored with",
    listing.indexOf('"plain"') !== -1 && !C1_RANGE.test(listing), visible(listing));

  session.send('DELETESCRIPT "plain"');
  await session.read(ONE_REPLY, "DELETESCRIPT answered");
}

// The reading verbs ask the same gate, so a row that reached the table
// by some other route cannot be operated on by name either.
async function everyScriptVerbAsksTheSameGate(session) {
  var hostile = "cs" + CSI + "i";
  var verbs = [
    ["GETSCRIPT",    'GETSCRIPT "' + hostile + '"'],
    ["SETACTIVE",    'SETACTIVE "' + hostile + '"'],
    ["DELETESCRIPT", 'DELETESCRIPT "' + hostile + '"'],
    ["HAVESPACE",    'HAVESPACE "' + hostile + '" 128'],
  ];
  for (var i = 0; i < verbs.length; i += 1) {
    session.send(verbs[i][1]);
    var reply = await session.read(ONE_REPLY, verbs[i][0] + " answered");
    count(verbs[i][0] + " refuses a name carrying a C1 control rather than looking it up",
      /^NO/.test(lastReply(reply)), visible(reply));
    count("and the refusal carries no control of its own, so reading it is safe",
      !C1_RANGE.test(reply), visible(reply));
  }
}

// ---- the mailbox-name gate --------------------------------------------------

async function imapSession(port, caPem, address, label) {
  return Wire.imap(port, {
    caPem:      caPem,
    servername: HOSTNAME,
    address:    address,
    password:   ALICE_PASSWORD,
    label:      label,
  });
}

// RFC 9051 section 5.1 makes a mailbox name UTF-8, and the grammar
// carries one either as a quoted string or as a literal. The two reach
// the handler by different readers, so a gate on one of them is a gate
// on half the surface.
//
// The refusal is what makes this worth driving over the socket rather
// than through the adapter: the name the client sent is quoted back in
// the NO, so a control admitted by the gate is a control written to the
// client's terminal by the server's own refusal.
async function aMailboxNameCarryingAC1ControlIsRefused(port, caPem, address) {
  var session = await imapSession(port, caPem, address, "imap-control-name");
  try {
    var hostile = "Junk" + CSI + "x";

    var quoted = session.tag();
    session.send(quoted + ' SELECT "' + hostile + '"');
    var quotedReply = await session.read(new RegExp("^" + quoted + " (OK|NO|BAD)", "m"),
      "SELECT with a quoted name answered");
    count("SELECT refuses a mailbox name carrying a C1 control",
      /(NO|BAD)/.test(quotedReply), visible(quotedReply));
    count("and the refusal does not quote the control back to the client, so a server " +
      "refusing a hostile name does not carry it out itself",
      !C1_RANGE.test(quotedReply), visible(quotedReply));

    var asLiteral = session.tag();
    await session.sendLiteral(asLiteral + " SELECT", hostile, "<a mailbox name as a literal>");
    var literalReply = await session.read(new RegExp("^" + asLiteral + " (OK|NO|BAD)", "m"),
      "SELECT with a literal name answered");
    count("SELECT refuses the same name sent as a literal, which reaches the handler by a " +
      "different reader",
      /(NO|BAD)/.test(literalReply), visible(literalReply));
    count("and that refusal carries no control either",
      !C1_RANGE.test(literalReply), visible(literalReply));

    var still = session.tag();
    session.send(still + ' SELECT "INBOX"');
    var ok = await session.read(new RegExp("^" + still + " (OK|NO|BAD)", "m"),
      "SELECT INBOX answered");
    count("and the session is still usable after both refusals",
      new RegExp("^" + still + " OK", "m").test(ok), visible(ok));
  } finally { session.close(); }
}

// ---- the folder a script names ----------------------------------------------

// `fileinto` takes a string literal inside a script body, so there is no
// name gate in front of it at all: the script is stored, and the folder
// it names is read at delivery time. When the account holds no folder by
// that name the message goes to INBOX and the operator is told which
// folder was missing, in a log line and in an audit row, and the name in
// both of them is whatever the account holder typed.
var FILEINTO_SCRIPT = "fileinto-control";

async function deliver(mxPort, caPem, to, subject) {
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
    "Subject: " + subject,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + subject.replace(/[^a-z0-9]/gi, "") + "@example.net>",
    "",
    "Body of " + subject + ".",
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");
  var reply = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

async function heldBy(port, caPem, address, folder, label) {
  var session = await imapSession(port, caPem, address, label);
  try {
    var tag = session.tag();
    session.send(tag + ' STATUS "' + folder + '" (MESSAGES)');
    var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "STATUS answered");
    var match = reply.match(/MESSAGES (\d+)/);
    return match === null ? -1 : parseInt(match[1], 10);
  } finally { session.close(); }
}

async function theFolderAScriptNamesIsScreenedBeforeItIsPrinted(session, ports, caPem, address,
  audit, stderr) {
  var body = 'require ["fileinto"];\nfileinto "Junk' + CSI + 'x";\n';
  sendLiteral(session, 'PUTSCRIPT "' + FILEINTO_SCRIPT + '"', body,
    "<a script filing into a folder whose name carries the C1 CSI>");
  var stored = await replyTo(session, "PUTSCRIPT answered");
  count("a script naming that folder is inside every rule the upload gate applies, because " +
    "the folder is a literal in the body rather than a name the gate sees",
    /^OK/.test(stored), visible(stored));

  session.send('SETACTIVE "' + FILEINTO_SCRIPT + '"');
  var activated = await replyTo(session, "SETACTIVE answered");
  count("and it can be made the active script", /^OK/.test(activated), visible(activated));

  var inboxBefore = await heldBy(ports.imap, caPem, address, "INBOX", "inbox-before-fileinto");
  stderr.take();
  var accepted = await deliver(ports.mx, caPem, address, "fileinto");
  count("the peer's message is accepted", /^250 /m.test(accepted), visible(accepted));

  await helpers.waitUntil(function () {
    return heldBy(ports.imap, caPem, address, "INBOX", "inbox-poll-fileinto")
      .then(function (n) { return n === inboxBefore + 1; });
  }, {
    timeoutMs: 8000,
    label:     "stored-name-control-screen: the message reaching INBOX when the folder is absent",
  });
  count("and it lands in INBOX rather than being lost with the folder the script named", true);

  // The row is written from the delivery path rather than returned to
  // it, so it is polled for rather than read once.
  var rows = await helpers.waitUntil(function () {
    var held = audit.forAction("blamepost.mail.sieve.folder_missing");
    return held.length > 0 ? held : false;
  }, {
    timeoutMs: 8000,
    label:     "stored-name-control-screen: the audit row naming the folder that was missing",
  });
  count("the operator gets an audit row naming the folder that was missing",
    rows.length > 0, "rows " + rows.length);
  var named = metadataOf(rows[rows.length - 1]).folder;
  count("and the folder it names carries no control, so an operator reading the trail in a " +
    "terminal reads a name rather than an escape sequence",
    !C1_RANGE.test(String(named)), JSON.stringify(String(named)));

  var written = stderr.take();
  count("the operator also gets a log line about it",
    /Sieve for /.test(written), visible(written.slice(0, 200)));
  count("and that line carries no control either, because it is the same value through the " +
    "same screen",
    !C1_RANGE.test(written), visible(written.slice(0, 200)));
}

// ---- stderr, where the boot logger writes an error --------------------------

// `b.log.boot` splits its sinks by level, so `log.error` is written to
// stderr. The claim here is about what an operator reads, and stderr is
// where they read it.
function captureStderr() {
  var original = process.stderr.write;
  var held = [];
  process.stderr.write = function (chunk) {
    held.push(typeof chunk === "string" ? chunk : String(chunk));
    return true;
  };
  return {
    take: function () {
      var text = held.join("");
      held = [];
      return text;
    },
    release: function () { process.stderr.write = original; },
  };
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("stored-name-control");
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
  var session  = null;
  var audit    = null;
  var stderr   = null;

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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "stored name screen test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
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

    var ports = {
      mx:          sections.mx.port,
      imap:        sections.imap.port,
      managesieve: sections.managesieve.port,
    };

    audit = auditCapture();

    session = await Wire.managesieve(ports.managesieve, {
      caPem:      leaf.ca,
      servername: HOSTNAME,
      address:    alice.address,
      password:   ALICE_PASSWORD,
      label:      "managesieve-names",
    });

    await aScriptNameCarryingAC1ControlIsRefused(session);
    await everyCodePointInTheC1RangeIsRefused(session);
    await aRenameOntoAControlNameIsRefused(session);
    await everyScriptVerbAsksTheSameGate(session);
    await aMailboxNameCarryingAC1ControlIsRefused(ports.imap, leaf.ca, alice.address);

    stderr = captureStderr();
    try {
      await theFolderAScriptNamesIsScreenedBeforeItIsPrinted(session, ports, leaf.ca,
        alice.address, audit, stderr);
    } finally {
      stderr.release();
      stderr = null;
    }

    session.send("LOGOUT");
    await session.read(ONE_REPLY, "LOGOUT answered");
    session.close();
    session = null;

    audit.release();
    audit = null;

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (stderr) stderr.release();
    if (session) session.close();
    if (audit) audit.release();
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

module.exports = { name: "stored-name-control-screen", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
