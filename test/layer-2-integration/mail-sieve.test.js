// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Filtering, which is the feature an account holder configures once and
 * then trusts without ever checking again.
 *
 * That trust is the whole risk. A filter files mail into a folder the
 * owner stops watching closely, so a filter that breaks quietly is
 * discovered when somebody asks about a message that was never read.
 * Before this, nothing evaluated an active script at all: ManageSieve
 * stored it, delivery appended to INBOX regardless, and a user could
 * write a rule, see it saved, and watch it do nothing forever.
 *
 * The safety property is asserted first, on purpose, and it outranks the
 * feature: a script that goes wrong MUST NOT cost the message. Upload
 * catches the parse errors, which is the only moment the account holder
 * is present to be told. What survives upload can still be wrong at
 * delivery, by naming a folder that does not exist or asking for an
 * action this build cannot perform, and each of those ends in INBOX with
 * a line in the log. A filter that eats mail when it breaks is worse
 * than no filter.
 *
 * Then the feature: a script that files into a folder puts the message
 * there and not in INBOX, and a script that discards is the one case
 * where a message is allowed to vanish, because the owner said so in
 * writing.
 *
 * Run standalone: node test/layer-2-integration/mail-sieve.test.js
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

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The threshold one account holder writes into a `size :over` test, and
// a body large enough to sit under it in octets and over it once
// decoded. 0xE9 is "e acute" in every Latin-1 derived charset, which is
// what an 8BITMIME body carries without complaint, and standing alone
// it is a sequence no UTF-8 decoder can accept, so each one costs three
// bytes in a decoded copy where the peer sent one.
var SIZE_THRESHOLD_BYTES    = 3000;
var UNDECODABLE_OCTET       = 0xE9;
var UNDECODABLE_BODY_OCTETS = 1500;

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// ---- driving the wire ------------------------------------------------------

async function deliver(mxPort, caPem, to, subject) {
  var peer = await Wire.connect(mxPort, "mx-deliver");
  await peer.read(/^220 /m, "banner");
  peer.send("EHLO peer.example.net");
  await peer.read(/^250 /m, "EHLO accepted");
  peer.send("STARTTLS");
  await peer.read(/^220 /m, "STARTTLS accepted");
  await peer.upgrade(caPem, HOSTNAME);
  peer.send("EHLO peer.example.net");
  await peer.read(/^250 /m, "EHLO accepted over TLS");
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
    "X-Category: " + subject,
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

// The octets of one message, headers and all, so a case can measure the
// message it is about rather than assume it.
function messageOctets(to, subject, bodyBytes) {
  var headers = [
    "From: " + PEER,
    "To: " + to,
    "Subject: " + subject,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + subject.replace(/[^a-z0-9]/gi, "") + "@example.net>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=iso-8859-1",
    "Content-Transfer-Encoding: 8bit",
    "",
    "",
  ].join("\r\n");
  return Buffer.concat([Buffer.from(headers, "ascii"), bodyBytes, Buffer.from("\r\n", "ascii")]);
}

// The same delivery, with a body the caller supplies as octets. A
// message is a sequence of octets and a peer picks the charset as
// freely as it picks the length, so a case about a size has to be able
// to send bytes that are not text. The payload stays a Buffer through
// the join: a `+` would decode it first and the octets the case is
// about would arrive as replacement characters.
async function deliverBytes(mxPort, caPem, to, subject, bodyBytes) {
  var peer = await Wire.mx(mxPort, { caPem: caPem, servername: HOSTNAME, label: "mx-deliver-bytes" });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + to + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(Buffer.concat([messageOctets(to, subject, bodyBytes),
    Buffer.from(".\r\n", "ascii")]), "<the message and its terminating dot>");
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

// How many messages a folder holds, read the way a client reads it.
async function existsIn(port, caPem, address, folder, label) {
  var session = await imapSession(port, caPem, address, label);
  session.send("s0 SELECT " + folder);
  var selected = await session.read(/^s0 (OK|NO|BAD)/m, "SELECT " + folder + " answered");
  session.send("s1 LOGOUT");
  session.close();
  if (!/^s0 OK/m.test(selected)) return -1;
  var m = /^\* (\d+) EXISTS/m.exec(selected);
  return m ? Number(m[1]) : -1;
}

// ---- cases -----------------------------------------------------------------

// The first line of defense is refusing a bad script at upload, which
// is the only moment the account holder is present to be told. A parse
// error that reaches delivery is one nobody will ever see reported.
function anUnparseableScriptIsRefusedAtUpload(identity, alice, address) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  var threw = null;
  try {
    identity.mailbox.sieveScripts.put(actor, "unparseable",
      "if header :is \"Subject\"", { force: true });
  } catch (e) { threw = e; }

  count("a script that does not parse is refused when it is uploaded",
    threw !== null, threw ? threw.message.slice(0, 90) : "accepted");
  count("and the refusal says it was the parse that failed",
    threw !== null && /did not parse/.test(threw.message),
    threw ? threw.message.slice(0, 90) : "");
  count("so nothing unparseable is left active",
    identity.mailbox.sieveScripts.active(actor) === null,
    JSON.stringify(identity.mailbox.sieveScripts.active(actor)));
}

// The safety property. A script can parse cleanly at upload and still
// be wrong at delivery, because it names a folder that does not exist
// or asks for something this build cannot do. Every one of those keeps
// the message.
async function abrokenScriptNeverCostsTheMessage(ports, caPem, address, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };

  var broken = [
    { name: "unknown-folder",
      body: "require [\"fileinto\"];\nif header :contains \"Subject\" \"filed\" " +
            "{ fileinto \"NoSuchFolder\"; }",
      why:  "a script naming a folder this account does not have" },
    { name: "unsendable",
      body: "require [\"fileinto\"];\nif header :contains \"Subject\" \"filed\" " +
            "{ redirect \"elsewhere@example.net\"; }",
      why:  "a script asking for an action this build cannot perform" },
  ];

  for (var i = 0; i < broken.length; i += 1) {
    var entry = broken[i];
    identity.mailbox.sieveScripts.put(actor, entry.name, entry.body, { force: true });
    identity.mailbox.sieveScripts.setActive(actor, entry.name);

    var before = await existsIn(ports.imap, caPem, address, "INBOX", "count-before");
    var reply = await deliver(ports.mx, caPem, address, "filed" + i);
    count(entry.why + " still lets the peer's message be accepted",
      /^250 /m.test(reply), visible(reply));

    var after = await existsIn(ports.imap, caPem, address, "INBOX", "count-after");
    count(entry.why + " delivers to INBOX rather than losing the message",
      after === before + 1, "before " + before + ", after " + after);
  }
}

// A script that parses and runs must actually move the message, or the
// whole feature is decoration.
async function aWorkingScriptFilesTheMessage(ports, caPem, address, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  identity.mailbox.sieveScripts.put(actor, "file-junk",
    "require [\"fileinto\"];\n" +
    "if header :contains \"X-Category\" \"spammy\" { fileinto \"Junk\"; }", { force: true });
  identity.mailbox.sieveScripts.setActive(actor, "file-junk");

  var inboxBefore = await existsIn(ports.imap, caPem, address, "INBOX", "inbox-before");
  var junkBefore  = await existsIn(ports.imap, caPem, address, "Junk", "junk-before");

  await deliver(ports.mx, caPem, address, "spammy");

  var inboxAfter = await existsIn(ports.imap, caPem, address, "INBOX", "inbox-after");
  var junkAfter  = await existsIn(ports.imap, caPem, address, "Junk", "junk-after");

  count("a matching message lands in the folder the script named",
    junkAfter === junkBefore + 1, "Junk before " + junkBefore + ", after " + junkAfter);
  count("and it is not also left in INBOX",
    inboxAfter === inboxBefore, "INBOX before " + inboxBefore + ", after " + inboxAfter);

  // The same script, a message that does not match. RFC 5228 section
  // 2.10.2: the implicit keep applies, so it belongs in INBOX.
  await deliver(ports.mx, caPem, address, "ordinary");
  var inboxFinal = await existsIn(ports.imap, caPem, address, "INBOX", "inbox-final");
  count("a message the script does not match takes the implicit keep to INBOX",
    inboxFinal === inboxAfter + 1, "INBOX before " + inboxAfter + ", after " + inboxFinal);
}

// The one case where a message is allowed to disappear, because the
// account holder wrote it down.
async function discardIsTheOneWayAMessageMayVanish(ports, caPem, address, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  identity.mailbox.sieveScripts.put(actor, "drop-noise",
    "if header :contains \"X-Category\" \"noise\" { discard; }", { force: true });
  identity.mailbox.sieveScripts.setActive(actor, "drop-noise");

  var before = await existsIn(ports.imap, caPem, address, "INBOX", "discard-before");
  var reply = await deliver(ports.mx, caPem, address, "noise");
  count("the peer is told the discarded message was accepted, per RFC 5228",
    /^250 /m.test(reply), visible(reply));

  var after = await existsIn(ports.imap, caPem, address, "INBOX", "discard-after");
  count("and it reaches no folder, because the owner asked for that",
    after === before, "before " + before + ", after " + after);
}

// RFC 5228 section 5.9 defines the `size` test on the number of OCTETS
// in the message, and a peer chooses those octets. A Latin-1 body under
// 8BITMIME is an ordinary arrival, and every octet in it that no UTF-8
// decoder can accept becomes a three byte replacement character, so a
// size counted on a decoded copy of the message is larger than the
// message. The account holder wrote a threshold and the server answers
// it against a number the peer can inflate, which files ordinary mail
// into the folder reserved for the large.
async function sizeIsCountedInOctetsRatherThanInDecodedText(ports, caPem, address, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  identity.mailbox.sieveScripts.put(actor, "file-large",
    "require [\"fileinto\"];\n" +
    "if size :over " + SIZE_THRESHOLD_BYTES + " { fileinto \"Junk\"; }", { force: true });
  identity.mailbox.sieveScripts.setActive(actor, "file-large");

  var body    = Buffer.alloc(UNDECODABLE_BODY_OCTETS, UNDECODABLE_OCTET);
  var octets  = messageOctets(address, "sized", body).length;
  var decoded = Buffer.byteLength(messageOctets(address, "sized", body).toString("utf8"), "utf8");

  count("the message the peer sends is under the threshold its owner wrote",
    octets < SIZE_THRESHOLD_BYTES, octets + " octets against " + SIZE_THRESHOLD_BYTES);
  count("while a decoded copy of the same message is over it",
    decoded > SIZE_THRESHOLD_BYTES, decoded + " bytes once decoded");

  var inboxBefore = await existsIn(ports.imap, caPem, address, "INBOX", "size-inbox-before");
  var junkBefore  = await existsIn(ports.imap, caPem, address, "Junk", "size-junk-before");

  var reply = await deliverBytes(ports.mx, caPem, address, "sized", body);
  count("the peer's message is accepted", /^250 /m.test(reply), visible(reply));

  var inboxAfter = await existsIn(ports.imap, caPem, address, "INBOX", "size-inbox-after");
  var junkAfter  = await existsIn(ports.imap, caPem, address, "Junk", "size-junk-after");

  count("a message under the threshold does not match `size :over` and stays in INBOX",
    inboxAfter === inboxBefore + 1, "INBOX before " + inboxBefore + ", after " + inboxAfter);
  count("and it is not filed as though it were over it",
    junkAfter === junkBefore, "Junk before " + junkBefore + ", after " + junkAfter);
}

// With no script at all, delivery is what it always was. This is the
// case that proves the hook did not change the ordinary path.
async function noScriptMeansInbox(ports, caPem, address, identity, alice) {
  var actor = { id: alice.id, address: address, roles: ["account"] };
  identity.mailbox.sieveScripts.setActive(actor, "");
  count("no script is active once it is deactivated",
    identity.mailbox.sieveScripts.active(actor) === null,
    JSON.stringify(identity.mailbox.sieveScripts.active(actor)));

  var before = await existsIn(ports.imap, caPem, address, "INBOX", "plain-before");
  await deliver(ports.mx, caPem, address, "plain");
  var after = await existsIn(ports.imap, caPem, address, "INBOX", "plain-after");
  count("an account with no filter still gets its mail in INBOX",
    after === before + 1, "before " + before + ", after " + after);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sieve");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "sieve test" });
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

    anUnparseableScriptIsRefusedAtUpload(identity, alice, alice.address);
    await abrokenScriptNeverCostsTheMessage(ports, leaf.ca, alice.address, identity, alice);
    await aWorkingScriptFilesTheMessage(ports, leaf.ca, alice.address, identity, alice);
    await discardIsTheOneWayAMessageMayVanish(ports, leaf.ca, alice.address, identity, alice);
    await sizeIsCountedInOctetsRatherThanInDecodedText(ports, leaf.ca, alice.address,
      identity, alice);
    await noScriptMeansInbox(ports, leaf.ca, alice.address, identity, alice);

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

module.exports = { name: "mail-sieve", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
