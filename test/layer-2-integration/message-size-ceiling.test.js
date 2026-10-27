// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * message-size-ceiling: the largest message this server accepts is one
 * number, and the wire and the mailbox both hold it.
 *
 * A sending server asks how large a message may be before it sends one.
 * `EHLO` answers with the SIZE keyword of RFC 1870, and a sender that
 * respects the answer sends a message inside it and expects delivery.
 * So the number on that line is a promise, and everything downstream of
 * it has to keep the promise: the DATA reader, the parse, and the append
 * that puts the message in a mailbox. A layer under the wire holding a
 * smaller number of its own is a message accepted, transferred in full,
 * and refused at the last step, after the peer has sent every byte, and
 * the mail is lost.
 *
 * Two numbers used to be smaller. The message store was built without
 * being told what the listeners accept, so it applied the vendored
 * framework's own ceilings: fifty mebibytes for the message and
 * twenty-five for its body. The second of those is the one an operator
 * met, because an ordinary single-part message IS its body, so a
 * twenty-six mebibyte message went out over a wire advertising fifty and
 * came back refused.
 *
 * The vectors below drive the two paths that put a message in a mailbox,
 * because a ceiling enforced on one is not a ceiling:
 *
 *   - A peer's `DATA` on the MX listener, which is where a stranger
 *     arrives and where the SIZE keyword was read.
 *   - An account holder's IMAP `APPEND`, which reaches the same append
 *     by another door. The IMAP listener refuses a literal larger than
 *     the ceiling when it is announced, and the message store refuses a
 *     message larger than the ceiling that reaches the append by any
 *     other call, so both are measured.
 *
 * Each is measured on both sides of the ceiling, and a message inside it
 * is read back afterwards rather than only counted: a message that is
 * accepted and then cannot be fetched is the same lost mail arriving one
 * step later.
 *
 * The refusal is permanent in both framings. RFC 5321 section 4.2.1
 * makes a 5yz reply final, and RFC 1870 section 6.2 gives 552 for a
 * message larger than the server accepts; a transient answer would have
 * the sender retry the whole transfer for days against a ceiling that
 * never moves.
 *
 * Run standalone: node test/layer-2-integration/message-size-ceiling.test.js
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

var BYTES = b.constants.BYTES;

// The number docs/operator-guide.md publishes under its ceilings table,
// written here as the document writes it. Read off the framework instead
// and this file would assert that the framework agrees with itself,
// which stays true across the refresh that would break the document.
var DOCUMENTED_MAX_MESSAGE_BYTES = 52428800;

// The body ceiling the vendored store applies when nobody names one,
// which is half its message ceiling.
var FRAMEWORK_BODY_CEILING_BYTES = BYTES.mib(25);

// Above that and comfortably under the published message ceiling, which
// is the band a store on the framework's numbers refuses and the wire
// invites. A message here is the one an operator loses.
var INSIDE_THE_CEILING_BYTES = BYTES.mib(30);

// A ceiling an operator lowers to, and a message past it. Small enough
// that the IMAP vector is cheap and far enough under the shipped number
// that a store still holding the shipped one accepts what this refuses.
var LOWERED_CEILING_BYTES = BYTES.mib(4);
var PAST_THE_LOWERED_CEILING_BYTES = BYTES.mib(8);

// How far past the ceiling the undeclared sender goes on the wire.
//
// Small, and the size is load-bearing rather than arbitrary. Once the
// listener has refused, it stops reading a body and reads the rest of
// the message as commands, and past a few hundred kibibytes of those it
// cuts the connection: measured against a one mebibyte ceiling, an
// overshoot of 2 KiB and one of 64 KiB both deliver the refusal, and one
// of 256 KiB delivers nothing at all and resets the connection instead.
// So a larger overshoot here would measure that cut rather than this
// ceiling, and would measure it as a wire read that never completes.
var WIRE_OVERSHOOT_BYTES = BYTES.kib(8);

// What a peer is told about a message this server will not store.
var TOO_BIG_CODE = "552";

// ---- the messages ----------------------------------------------------------

// One single-part message of about `bodyBytes` octets of body. Single
// part on purpose: an ordinary message IS its body, which is what makes
// a body ceiling under the message ceiling reachable by ordinary mail
// rather than only by a crafted one.
function message(subject, bodyBytes) {
  var head = [
    "From: " + PEER,
    "To: alice@" + DOMAIN,
    "Subject: " + subject,
    "Date: Sat, 22 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + subject + "@example.net>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=us-ascii",
    "Content-Transfer-Encoding: 7bit",
    "",
    "",
  ].join("\r\n");
  // Lines well inside the 998 octets RFC 5322 section 2.1.1 allows, and
  // no line that begins with a dot, so nothing in the body reads as the
  // terminator of the DATA transfer.
  var line = "x".repeat(78) + "\r\n";
  return head + line.repeat(Math.ceil(bodyBytes / line.length));
}

// ---- the wire --------------------------------------------------------------

// What the MX listener tells a sender it will accept, which is the
// promise every case below measures against.
async function advertisedSize(mxPort, caPem) {
  var peer = await Wire.mx(mxPort, {
    caPem: caPem, servername: HOSTNAME, label: "size-keyword" });
  // A fresh EHLO rather than the ladder's, because the ladder's reply
  // has already been taken off the buffer and the transcript keeps it
  // with its line terminators escaped for readability. RFC 5321 section
  // 4.1.4 lets a client issue EHLO again at any point.
  peer.send("EHLO peer.example.net");
  var greeting = await peer.read(/^250 /m, "EHLO answered");
  peer.send("QUIT");
  peer.close();
  var found = /^250[ -]SIZE (\d+)/m.exec(greeting);
  return found ? Number(found[1]) : -1;
}

// What a peer is told when it declares an oversize message up front,
// which is what the SIZE keyword exists for: RFC 1870 section 6.1 has
// the sender put the octet count on `MAIL FROM` and the receiver answer
// before a single octet of the message is sent.
async function declareSize(mxPort, caPem, octets) {
  var peer = await Wire.mx(mxPort, {
    caPem: caPem, servername: HOSTNAME, label: "declared-size" });
  peer.send("MAIL FROM:<" + PEER + "> SIZE=" + octets);
  var reply = await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("QUIT");
  peer.close();
  return reply.trim();
}

// One inbound message from a peer this server has never met, which is
// the path the SIZE keyword was read on.
async function deliver(mxPort, caPem, to, text, label) {
  var peer = await Wire.mx(mxPort, {
    caPem: caPem, servername: HOSTNAME, label: label });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + to + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(text + "\r\n.\r\n", "<" + text.length + " octets and the terminating dot>");
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
  var found = /^\* (\d+) EXISTS/m.exec(selected);
  return found ? Number(found[1]) : -1;
}

// The size the mailbox reports for the newest message, read back over
// IMAP. A message accepted and then unreadable is the same lost mail one
// step later, so a landing is not counted until the mailbox will quote
// its size.
async function newestSize(port, caPem, address, label) {
  var session = await imapSession(port, caPem, address, label);
  var tag = session.tag();
  session.send(tag + " SELECT INBOX");
  var selected = await session.read(
    new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "SELECT INBOX answered");
  var exists = /^\* (\d+) EXISTS/m.exec(selected);
  if (!exists || Number(exists[1]) === 0) { session.close(); return -1; }
  var fetchTag = session.tag();
  session.send(fetchTag + " FETCH " + exists[1] + " (RFC822.SIZE)");
  var fetched = await session.read(
    new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"), "FETCH RFC822.SIZE answered");
  session.close();
  var sized = /RFC822\.SIZE (\d+)/.exec(fetched);
  return sized ? Number(sized[1]) : -1;
}

// One message offered to the MX listener, and what became of it.
async function offeredToTheMx(ports, caPem, address, text, label) {
  var before = await inboxCount(ports.imap, caPem, address, label + "-before");
  var reply  = await deliver(ports.mx, caPem, address, text, label);
  var after  = await inboxCount(ports.imap, caPem, address, label + "-after");
  return {
    reply:  reply,
    landed: after - before,
    detail: visible(reply) + "; INBOX " + before + " -> " + after,
  };
}

// The same message offered over IMAP APPEND. RFC 9051 section 6.3.12;
// the literal is synchronizing because this listener does not advertise
// LITERAL+.
async function offeredToImapAppend(port, caPem, address, text, label) {
  var session = await imapSession(port, caPem, address, label);
  var tag = session.tag();
  var refused = null;
  try {
    await session.sendLiteral(tag + " APPEND INBOX", text, "<the message>");
  } catch (openerRefused) {
    refused = openerRefused.message;
  }
  // The tagged reply is the verdict. A listener may put untagged lines
  // in front of it, and a read that stopped on the first of those would
  // report whichever line the runner saw first rather than what became
  // of the message.
  var reply = refused === null
    ? await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND answered")
    : refused;
  session.close();
  return reply.trim();
}

// ---- cases -----------------------------------------------------------------

// The published number is the one a sender may actually use. This is the
// case an operator meets: a message the wire invited, refused after the
// peer sent every octet of it.
async function aMessageInsideThePublishedCeilingIsDelivered(ports, caPem, address) {
  var advertised = await advertisedSize(ports.mx, caPem);
  count("the MX listener advertises the message ceiling the operator guide publishes, " +
    "which is the promise every case below holds it to",
    advertised === DOCUMENTED_MAX_MESSAGE_BYTES, String(advertised));

  var text = message("inside-the-ceiling", INSIDE_THE_CEILING_BYTES);
  count("the vector is larger than the body ceiling the vendored store applies when nothing " +
    "names one, so a store left on the framework's numbers refuses it",
    text.length > FRAMEWORK_BODY_CEILING_BYTES &&
      text.length < DOCUMENTED_MAX_MESSAGE_BYTES,
    text.length + " octets");

  var offered = await offeredToTheMx(ports, caPem, address, text, "inside");
  count("a message inside the advertised ceiling is accepted from a peer and lands in the " +
    "mailbox, rather than being taken in full and refused at the append",
    /^250 /.test(offered.reply) && offered.landed === 1, offered.detail);

  // No smaller than what was sent, and not much larger. A receiver adds
  // its own trace headers on the way in, so the stored message is the
  // one that arrived plus a `Received:` line and the authentication
  // results beside it; anything short of what was sent is a body that
  // did not survive the append.
  var size = await newestSize(ports.imap, caPem, address, "inside-readback");
  count("and the mailbox reads it back whole, at the size it arrived plus the trace headers " +
    "this server added, so the message is stored rather than accepted and lost",
    size >= text.length && size - text.length < 4096,
    size + " octets read back against " + text.length + " sent");
}

// The other side of the same number, taken on the declared path.
//
// A sender that declares its size is answered before it sends any of the
// message, which is what the SIZE keyword is for and what makes this the
// vector to measure the published ceiling with: the undeclared shape
// needs the whole ceiling transferred before the listener can know, and
// fifty mebibytes over TLS is a transfer a loaded runner does not finish
// inside a wire read's budget. The undeclared shape is measured against
// the lowered ceiling below, where the same refusal costs megabytes
// rather than tens of them.
async function aMessagePastItIsRefusedPermanently(ports, caPem) {
  var declared = await declareSize(ports.mx, caPem, DOCUMENTED_MAX_MESSAGE_BYTES + 1);

  count("a sender declaring one octet past the advertised ceiling is refused at MAIL FROM, " +
    "before it sends any of the message",
    !/^2\d\d /.test(declared), visible(declared));

  count("and it is told " + TOO_BIG_CODE + ", which RFC 5321 section 4.2.1 makes final, so " +
    "the sender stops rather than offering the same message again against a ceiling that " +
    "does not move",
    declared.indexOf(TOO_BIG_CODE) === 0, visible(declared));

  // The declaration is a hint rather than a promise, so a sender inside
  // it is not thereby accepted; what this pins is that declaring an
  // honest size below the ceiling is not itself refused, which would
  // make the case above pass for the wrong reason.
  var honest = await declareSize(ports.mx, caPem, INSIDE_THE_CEILING_BYTES);
  count("while a sender declaring a size inside the ceiling is taken",
    /^250 /.test(honest), visible(honest));
}

// The second door into the same append, taken twice. The IMAP listener
// refuses a literal past the operator's ceiling on its announcement, so
// an oversize APPEND never reaches the store. The store's own number is
// then measured by the call APPEND makes, which is also the call every
// other path that files a message makes, so a store left on the
// framework's number is caught here rather than by whichever path skips
// the listener.
async function theCeilingReachesTheStoreAndNotOnlyTheWire(ports, caPem, address, held) {
  var inside = message("append-inside", LOWERED_CEILING_BYTES / 2);
  var past   = message("append-past", PAST_THE_LOWERED_CEILING_BYTES);

  var appendedInside = await offeredToImapAppend(ports.imap, caPem, address,
    inside, "append-inside");
  count("an upload inside the operator's lowered ceiling is stored, so the refusal below " +
    "is the ceiling rather than APPEND being broken",
    /^\S+ OK/m.test(appendedInside), visible(appendedInside.slice(-200)));

  var appendedPast = await offeredToImapAppend(ports.imap, caPem, address,
    past, "append-past");
  count("an upload past it is refused by the IMAP listener when the literal is announced, " +
    "against the operator's lowered ceiling rather than a literal limit of its own",
    /refused the literal opener/.test(appendedPast) && /\S+ NO Literal \d+ bytes exceeds cap/
      .test(appendedPast) && appendedPast.indexOf(String(LOWERED_CEILING_BYTES)) !== -1,
    visible(appendedPast.slice(-200)));

  var storeRefusal = null;
  try {
    held.identity.mailbox.appendMessage("INBOX", Buffer.from(past, "utf8"),
      { actor: { id: held.alice.id } });
  } catch (refused) {
    storeRefusal = refused;
  }
  count("and the message store refuses the same message at the append, so the ceiling " +
    "holds for a message that reaches the store without passing the IMAP listener",
    storeRefusal !== null && /maxMessageBytes/.test(storeRefusal.message) &&
      storeRefusal.message.indexOf(String(LOWERED_CEILING_BYTES)) !== -1,
    storeRefusal === null ? "stored" : storeRefusal.message.slice(0, 200));

  // The same number on the other protocol, so the two agree rather than
  // each holding one of its own.
  var advertised = await advertisedSize(ports.mx, caPem);
  count("and the MX listener advertises that same lowered ceiling, so a sender and a " +
    "mailbox client are told one number",
    advertised === LOWERED_CEILING_BYTES, String(advertised));

  // The undeclared sender, measured here rather than against the shipped
  // ceiling: the listener cannot answer until the running total crosses
  // the number, so the cost of this vector is the ceiling itself and
  // fifty mebibytes over TLS is a transfer a loaded runner does not
  // finish inside a wire read's budget.
  var offered = await offeredToTheMx(ports, caPem, address,
    message("mx-past-lowered", LOWERED_CEILING_BYTES + WIRE_OVERSHOOT_BYTES),
    "past-lowered");

  count("a peer that declared nothing and sent past the lowered ceiling is cut during the " +
    "transfer and nothing lands",
    !/^2\d\d /.test(offered.reply) && offered.landed === 0, offered.detail);

  count("and it is told " + TOO_BIG_CODE + " there too, so the refusal is permanent whether " +
    "the sender declared a size or not",
    offered.reply.indexOf(TOO_BIG_CODE) === 0, visible(offered.reply));
}

// ---- the server ------------------------------------------------------------

// One assembled server on ephemeral loopback ports, with the MX and IMAP
// listeners bound and nothing else.
async function withServer(root, limits, body) {
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

    var env = {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    };
    if (limits !== null) env.BLAMEPOST_LIMITS = JSON.stringify(limits);
    var cfg = config.load({ env: env, cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "message size ceiling test" });
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

    await body({ mx: sections.mx.port, imap: sections.imap.port }, leaf.ca, alice.address,
      { identity: identity, alice: alice });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
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
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  // Whether the number is HELD here rather than borrowed from the
  // vendored framework is asked at layer 0, by
  // test/layer-0-primitives/published-bound-parity.test.js. This file
  // asks the other half: whether every layer under the wire runs it.
  var shipped = helpers.tempDir("sizeceil-shipped");
  try {
    await withServer(shipped, null, async function (ports, caPem, address) {
      await aMessageInsideThePublishedCeilingIsDelivered(ports, caPem, address);
      await aMessagePastItIsRefusedPermanently(ports, caPem);
    });
  } finally {
    helpers.removeTempDir(shipped);
  }

  var lowered = helpers.tempDir("sizeceil-lowered");
  try {
    await withServer(lowered, { maxMessageBytes: LOWERED_CEILING_BYTES },
      async function (ports, caPem, address, held) {
        await theCeilingReachesTheStoreAndNotOnlyTheWire(ports, caPem, address, held);
      });
  } finally {
    helpers.removeTempDir(lowered);
  }

  return helpers.getChecks();
}

module.exports = { name: "message-size-ceiling", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
