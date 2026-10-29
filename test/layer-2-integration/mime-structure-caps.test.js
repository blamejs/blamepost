// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * mime-structure-caps: how much structure a message may declare before
 * this server stops reading it, measured at the numbers the threat model
 * publishes.
 *
 * A multipart message describes its own shape, so a stranger chooses how
 * much of it there is to walk. Sixteen boundaries nested inside one
 * another cost sixteen recursive reads; sixteen thousand cost sixteen
 * thousand, and every one of them arrives on port 25 from a peer that
 * has not signed in and does not have to. The caps are the answer and
 * the numbers are published: sixteen levels of nesting, sixty-four
 * parts.
 *
 * Nothing measured them. Every MIME parse in this repository passes no
 * options, so both numbers belong to the vendored parser rather than to
 * anything here, and a refresh that moved either one would change what
 * this server accepts while the shipped document went on promising the
 * old number. So the numbers below are written as the document writes
 * them and never read back out of the parser: a parser asked to confirm
 * its own default agrees with itself before a refresh and after one.
 *
 * Four messages per cap, two on each side of it, and both wire
 * protocols that put a message into a mailbox:
 *
 *   - A message at the published limit is accepted and lands, so the
 *     limit is not somewhere below where the document says it is.
 *   - A message one step past it is refused and does not land, so the
 *     limit is not somewhere above.
 *   - The same pair over IMAP `APPEND`, because an account holder
 *     uploading a message reaches the same parser by another door and a
 *     bound enforced on one protocol is not a bound.
 *
 * The peer's refusal is `554 5.6.0`, which is permanent. RFC 5321
 * section 4.2.1 makes a 5yz reply final, so the peer stops instead of
 * retrying a structure this server will never read on any attempt. RFC
 * 3463 section 3.7 defines X.6.0 as a content problem none of the other
 * detail codes expresses, and no registered subcode names a message
 * that declares more structure than a parser will walk. Pinned exactly
 * here because the code is what an operator filters a log on.
 *
 * Run standalone: node test/layer-2-integration/mime-structure-caps.test.js
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

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var PEER     = "sender@example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The two numbers THREAT-MODEL.md publishes, written here as the
// document writes them. Reading them off the parser instead would assert
// that the parser agrees with itself, which is the one thing that stays
// true across the refresh this file exists to catch.
var DOCUMENTED_MAX_NESTING_DEPTH = 16;
var DOCUMENTED_MAX_PARTS         = 64;

// The root of the tree is itself a part, so the widest multipart a
// message may carry is one leaf fewer than the published part count.
// Nesting counts from the other end: the outermost multipart is the
// first level, so a message may carry exactly the published depth.
var WIDEST_ACCEPTED_LEAF_COUNT = DOCUMENTED_MAX_PARTS - 1;

// What a peer is told about a message whose structure this server
// declines to read.
var STRUCTURE_REFUSAL_CODE = "554 5.6.0";

// ---- the messages ----------------------------------------------------------

function headerBlock(subject) {
  return [
    "From: " + PEER,
    "To: alice@" + DOMAIN,
    "Subject: " + subject,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + subject + "@example.net>",
    "MIME-Version: 1.0",
    "",
  ].join("\r\n");
}

// A message whose multipart boundaries nest `levels` deep.
//
// Every boundary token is the same width and none of them is a prefix of
// another. RFC 2046 section 5.1.1 matches a boundary on the start of a
// line, so a run named b1 also matches the delimiter of a run named b10:
// a fixture numbered without padding collapses at the tenth level and
// stops nesting there, while still looking like the message it was
// written to be.
function nestedMessage(levels, subject) {
  var body = "Content-Type: text/plain\r\n\r\nthe innermost leaf\r\n";
  for (var i = levels; i >= 1; i -= 1) {
    var boundary = "nest" + String(i + 100).slice(1) + "x";
    body = "Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n" +
      "\r\n" +
      "--" + boundary + "\r\n" +
      body +
      "--" + boundary + "--\r\n";
  }
  return headerBlock(subject) + body;
}

// A message carrying `leaves` sibling parts under one multipart root.
function wideMessage(leaves, subject) {
  var body = "Content-Type: multipart/mixed; boundary=\"wide\"\r\n\r\n";
  for (var i = 0; i < leaves; i += 1) {
    body += "--wide\r\nContent-Type: text/plain\r\n\r\nleaf " + i + "\r\n";
  }
  body += "--wide--\r\n";
  return headerBlock(subject) + body;
}

// ---- the wire --------------------------------------------------------------

// One inbound message from a peer this server has never met, which is
// the path a hostile structure actually arrives on.
async function deliver(mxPort, caPem, to, text) {
  var peer = await Wire.mx(mxPort, {
    caPem: caPem, servername: HOSTNAME, label: "mx-structure" });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + to + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(text + "\r\n.\r\n", "<the message and its terminating dot>");
  var reply = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return reply.trim();
}

function imapSession(port, caPem, address, label) {
  return Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME,
    address: address, password: ALICE_PASSWORD, label: label });
}

// How many messages INBOX holds, read the way a client reads it.
async function inboxCount(port, caPem, address, label) {
  var session = await imapSession(port, caPem, address, label);
  var tag = session.tag();
  session.send(tag + " SELECT INBOX");
  var selected = await session.read(
    new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "SELECT INBOX answered");
  session.close();
  if (!new RegExp("^" + tag + " OK", "m").test(selected)) return -1;
  var m = /^\* (\d+) EXISTS/m.exec(selected);
  return m ? Number(m[1]) : -1;
}

// One message offered to the MX listener, and what became of it.
async function offeredToTheMx(ports, caPem, address, text, label) {
  var before = await inboxCount(ports.imap, caPem, address, label + "-before");
  var reply  = await deliver(ports.mx, caPem, address, text);
  var after  = await inboxCount(ports.imap, caPem, address, label + "-after");
  return {
    reply:  reply,
    landed: after - before,
    detail: visible(reply) + "; INBOX " + before + " -> " + after,
  };
}

// The same message offered over IMAP APPEND, which is the other door
// into the same parser. RFC 9051 section 6.3.12; the literal is
// synchronizing because this listener does not advertise LITERAL+.
async function offeredToImapAppend(port, caPem, address, text, label) {
  var session = await imapSession(port, caPem, address, label);
  var tag = session.tag();
  var refused = null;
  try {
    await session.sendLiteral(tag + " APPEND INBOX", text, "<the message>");
  } catch (openerRefused) {
    refused = openerRefused.message;
  }
  // The TAGGED reply is the verdict. A listener may put untagged lines
  // in front of it, and a read that stopped on the first of those would
  // report whichever line the runner happened to see first rather than
  // what became of the message.
  var reply = refused === null
    ? await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND answered")
    : refused;
  session.close();
  return reply.trim();
}

// ---- cases -----------------------------------------------------------------

// One cap, four messages: two at the limit and two past it, over both
// protocols that file a message.
//
// The pair on each protocol is the assertion rather than either half. A
// message at the limit that was refused would mean the cap sits below
// the published number and every refusal below would be meaningless; a
// message past it that was accepted would mean the cap sits above.
async function aStructureIsReadUpToTheCapAndNotPastIt(ports, caPem, address, vector) {
  var inside = await offeredToTheMx(ports, caPem, address, vector.inside, "inside");
  var past   = await offeredToTheMx(ports, caPem, address, vector.past, "past");

  count(vector.label + " at the published limit is accepted from a peer and lands in the " +
    "mailbox", /^250 /.test(inside.reply) && inside.landed === 1, inside.detail);

  count(vector.label + " one step past the published limit is refused rather than walked, " +
    "and nothing lands", !/^2\d\d /.test(past.reply) && past.landed === 0, past.detail);

  // Pinned exactly. A peer acts on the code rather than on the prose,
  // and an operator reading a log filters on it.
  count("and the peer is told " + STRUCTURE_REFUSAL_CODE + " rather than having the " +
    "message accepted or the connection dropped",
    past.reply.indexOf(STRUCTURE_REFUSAL_CODE) === 0, visible(past.reply));

  var appendedInside = await offeredToImapAppend(ports.imap, caPem, address,
    vector.inside, "append-inside");
  var appendedPast   = await offeredToImapAppend(ports.imap, caPem, address,
    vector.past, "append-past");

  count(vector.label + " uploaded with IMAP APPEND at the published limit is stored",
    /^\S+ OK/m.test(appendedInside), visible(appendedInside.slice(-200)));

  count("and one step past it is refused there too, so the bound is the parser's rather " +
    "than one wire protocol's",
    /^\S+ (NO|BAD)/m.test(appendedPast), visible(appendedPast.slice(-200)));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("mimecaps");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "structure caps test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

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

    await aStructureIsReadUpToTheCapAndNotPastIt(ports, leaf.ca, alice.address, {
      label:  "a message nested " + DOCUMENTED_MAX_NESTING_DEPTH + " levels deep",
      inside: nestedMessage(DOCUMENTED_MAX_NESTING_DEPTH, "nested-at-the-limit"),
      past:   nestedMessage(DOCUMENTED_MAX_NESTING_DEPTH + 1, "nested-past-the-limit"),
    });

    await aStructureIsReadUpToTheCapAndNotPastIt(ports, leaf.ca, alice.address, {
      label:  "a message carrying " + WIDEST_ACCEPTED_LEAF_COUNT + " parts under one root",
      inside: wideMessage(WIDEST_ACCEPTED_LEAF_COUNT, "wide-at-the-limit"),
      past:   wideMessage(WIDEST_ACCEPTED_LEAF_COUNT + 1, "wide-past-the-limit"),
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
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

module.exports = { name: "mime-structure-caps", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
