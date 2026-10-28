// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The same octets, submitted through every door this server has, are
 * stored as the same message.
 *
 * A message reaches the volume four ways. A peer transmits it to the MX
 * listener inside SMTP `DATA`. An account holder's client uploads it as
 * an IMAP `APPEND` literal. An authenticated client submits it inside
 * `DATA`, or inside RFC 3030 `BDAT` chunks. Three of those four carry
 * their own count and one does not: `DATA` ends at a sequence rather
 * than at a number, and RFC 5321 section 4.1.1.4 writes that sequence
 * as `<CRLF>.<CRLF>` and then says the first CRLF "is actually the
 * terminator of the previous line". That line is a line of the mail
 * data, and section 2.3.7 makes a line's CRLF part of the line, so
 * those two octets are the sender's and not the terminator's.
 *
 * A reader that ends the message where the terminator begins keeps the
 * previous line's CRLF for the terminator and hands the message over
 * two octets short. Nothing about that is visible at the wire: the
 * transaction is accepted, the reply is `250`, and the message reads
 * correctly.
 *
 * What it costs shows up in four places, and each is a case below.
 *
 *   - A message that ends with a blank line reaches the account holder
 *     without it. The writers that put a CRLF back before a terminator
 *     do it only when the buffer does not already end with one, so a
 *     message whose last line is blank ends with a CRLF, gets nothing
 *     added, and arrives one line shorter than it was sent. The blank
 *     line is body content, and a MIME epilogue is made of them.
 *
 *   - A message with no body loses the empty line that ends its header
 *     block, because that line's CRLF is the one taken. The stored
 *     message then has no header/body separator anywhere in it, and
 *     every consumer that finds the header block by looking for one
 *     answers about a message that no longer has the shape it arrived
 *     in.
 *
 *   - The same message stored by two doors is two different messages.
 *     `lib/store/blobs.js` names a body by the SHA3-512 of its content
 *     and releases it by reference count, so identical content is one
 *     blob held by many rows. Two octets of difference is a second
 *     blob, and the account is charged for both.
 *
 *   - What an IMAP client is served stops matching what a POP3 client
 *     is served. `RFC822.SIZE` and the `BODY[]` literal both count the
 *     stored octets, so IMAP hands back a body whose last line has no
 *     terminator, while POP3 `RETR` writes the CRLF back before its own
 *     terminator and the same message arrives one line longer.
 *
 * The claim about the inbound direction is a suffix claim, because RFC
 * 8601 section 5 has the receiver prepend its own
 * `Authentication-Results` header: the octets the peer transmitted
 * occur in the stored message once, contiguously, and at its end.
 *
 * `BDAT` is the control. RFC 3030 section 3 gives a chunk a byte count
 * and no terminator, so nothing is subtracted from it, and the octets
 * it stores are the octets that were transmitted. It is measured beside
 * the `DATA` path on the same listener with the same fixture, so a
 * disagreement between the two is a disagreement this server has with
 * itself rather than a reading of a specification.
 *
 * Run standalone: node test/layer-2-integration/data-terminator-parity.test.js
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
var imapLiteral = wire.imapLiteral;
var pop3Body    = wire.pop3Body;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var PEER     = "sender@example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var CRLF     = Buffer.from("\r\n", "ascii");
var CRLFCRLF = Buffer.from("\r\n\r\n", "ascii");

var count = helpers.count;

// ---- fixtures ---------------------------------------------------------------

function headerBlock(subject, messageId, from) {
  return [
    "From: " + from,
    "To: alice@" + DOMAIN,
    "Subject: " + subject,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + messageId + ">",
    "",
  ].join("\r\n") + "\r\n";
}

// An ordinary message: a header block, a body, one CRLF at the end.
var ORDINARY = Buffer.from(
  headerBlock("the same bytes at every door", "parity-ordinary@example.net", PEER) +
  "first line of the body\r\n" +
  "second line of the body\r\n", "ascii");

// The same shape with a blank line after the last line of text, which is
// what a MIME epilogue and a great deal of ordinary mail ends with.
var BLANK_TAIL = Buffer.from(
  headerBlock("the last line is blank", "parity-blank@example.net", PEER) +
  "one line of body\r\n" +
  "\r\n", "ascii");

// Header fields, the empty line that ends them, and no body at all. RFC
// 5322 section 3.5 makes the body optional, so this is a message a peer
// is entitled to send.
var HEADER_ONLY = Buffer.from(
  headerBlock("no body at all", "parity-empty@example.net", PEER), "ascii");

// What an authenticated client submits to itself, used twice: once
// inside DATA and once inside a BDAT chunk.
var SUBMITTED = Buffer.from(
  headerBlock("submitted two ways", "parity-submitted@example.com", "alice@" + DOMAIN) +
  "the body of the submitted message\r\n", "ascii");

// ---- readers ----------------------------------------------------------------

// One whole-message fetch, read as octets. RFC822.SIZE and the literal
// count are two claims about the same message and both are measured,
// because a response that re-counts what it re-encoded is internally
// consistent and still wrong.
async function fetchWhole(session, seq, what) {
  var tag = session.tag();
  session.send(tag + " FETCH " + seq + " (RFC822.SIZE BODY.PEEK[])");
  var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    what + " answered");
  var view = raw.toString("latin1");
  var sizeMatch = /RFC822\.SIZE (\d+)/.exec(view);
  var lit = imapLiteral(raw);
  count(what + ": the fetch reports a size", sizeMatch !== null, visible(view.slice(0, 200)));
  count(what + ": the literal count is the number of octets that follow it",
    lit.present === lit.announced,
    "announced " + lit.announced + ", present " + lit.present);
  count(what + ": RFC822.SIZE and the literal count are the same number",
    sizeMatch !== null && parseInt(sizeMatch[1], 10) === lit.announced,
    (sizeMatch ? sizeMatch[1] : "no size") + " reported, " + lit.announced + " announced");
  return lit.payload;
}

// ---- the peers --------------------------------------------------------------

async function aPeerDelivers(port, caPem, address, payload, label) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, label: label, helo: "peer.example.net" });
  try {
    peer.send("MAIL FROM:<" + PEER + ">");
    await peer.read(/^\d{3} /m, "MAIL FROM answered");
    peer.send("RCPT TO:<" + address + ">");
    await peer.read(/^\d{3} /m, "RCPT TO answered");
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    // No line of any fixture opens with a dot, so nothing needs stuffing.
    peer.sendRaw(Buffer.concat([payload, Buffer.from(".\r\n", "ascii")]),
      "<" + label + " and its terminating dot>");
    var accepted = await peer.read(/^\d{3} /m, "message answered");
    count(label + ": the peer's message is accepted", /^250 /m.test(accepted),
      visible(accepted));
    peer.send("QUIT");
  } finally { peer.close(); }
}

// One APPEND, read by the tag it was sent under, then a NOOP barrier so
// the next command starts on a clear buffer. Both are the reasons
// `mail-octet-fidelity.test.js` gives for the same shape.
async function anAccountHolderUploads(session, payload, label) {
  var tag = session.tag();
  await session.sendLiteral(tag + " APPEND INBOX", payload, "<" + label + ">");
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "APPEND answered");
  count(label + ": the upload is accepted",
    new RegExp("^" + tag + " OK", "m").test(reply), visible(reply));
  var barrier = session.tag();
  session.send(barrier + " NOOP");
  await session.read(new RegExp("^" + barrier + " (OK|NO|BAD)", "m"), "NOOP answered");
}

// A submission inside DATA, and the same octets inside one BDAT chunk.
// The two travel over separate sessions because a transaction ends at
// its reply either way, and a single session would leave which command
// finished the first message a question the second one depends on.
async function anAccountHolderSubmits(port, ladder, payload, useBdat) {
  var label = useBdat ? "submission by BDAT" : "submission by DATA";
  var session = await Wire.submission(port,
    Object.assign({ label: label, helo: "client.example.com" }, ladder));
  try {
    if (useBdat) {
      count(label + ": the listener advertises CHUNKING, so this path is one a client " +
        "may take (RFC 3030 section 2)", /CHUNKING/.test(session.transcript()),
        visible(session.transcript().slice(-300)));
    }
    session.send("MAIL FROM:<alice@" + DOMAIN + ">");
    await session.read(/^\d{3} /m, "MAIL FROM answered");
    session.send("RCPT TO:<alice@" + DOMAIN + ">");
    await session.read(/^\d{3} /m, "RCPT TO answered");
    if (useBdat) {
      // RFC 3030 section 2: the chunk is exactly the announced number of
      // octets and carries no terminator, so nothing about where it ends
      // is inferred from its content.
      session.sendRaw(Buffer.concat([
        Buffer.from("BDAT " + payload.length + " LAST\r\n", "ascii"), payload]),
        "<the chunk and its count>");
    } else {
      session.send("DATA");
      await session.read(/^354 /m, "DATA answered");
      session.sendRaw(Buffer.concat([payload, Buffer.from(".\r\n", "ascii")]),
        "<the message and its terminating dot>");
    }
    var accepted = await session.read(/^\d{3} /m, "message answered");
    count(label + ": the message is accepted", /^250 /m.test(accepted), visible(accepted));
    session.send("QUIT");
  } finally { session.close(); }
}

// ---- cases ------------------------------------------------------------------

// The inbound claim, stated as a suffix for the header the receiver
// writes (RFC 8601 section 5).
function theStoredMessageEndsWithWhatThePeerTransmitted(stored, transmitted, label) {
  var at = stored.indexOf(transmitted);
  count(label + ": the octets the peer transmitted are in the stored message, " +
    "contiguously and at its end",
    at !== -1 && at === stored.length - transmitted.length,
    "found at " + at + " in " + stored.length + " octets, transmitted " +
      transmitted.length + " octets; stored tail " +
      stored.subarray(Math.max(0, stored.length - transmitted.length - 4))
        .toString("hex").slice(0, 120));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("terminator-parity");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory backed directory and reads this variable to find it. Pointing
  // it inside the test's own temporary tree keeps the encrypted at rest
  // path exactly as it ships rather than opting the test out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

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

    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "terminator parity test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // POP3 is off by default and one of the cases is about what it writes.
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        // The message authentication gate resolves SPF and DMARC against
        // live DNS at the end of DATA and this process has no resolver,
        // so enforce mode would defer and the run would measure the
        // absence of DNS rather than the octets.
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

    var ladder = {
      caPem:      leaf.ca,
      servername: HOSTNAME,
      address:    alice.address,
      password:   ALICE_PASSWORD,
      binary:     true,
    };

    // Sequence numbers below are the order the mailbox took these in.
    await aPeerDelivers(sections.mx.port, leaf.ca, alice.address, ORDINARY, "inbound");        // 1
    await aPeerDelivers(sections.mx.port, leaf.ca, alice.address, BLANK_TAIL, "blank tail");   // 2
    await aPeerDelivers(sections.mx.port, leaf.ca, alice.address, HEADER_ONLY, "no body");     // 3
    await anAccountHolderSubmits(sections.submission.port, ladder, SUBMITTED, false);          // 4
    await anAccountHolderSubmits(sections.submission.port, ladder, SUBMITTED, true);           // 5

    var imap = await Wire.imap(sections.imap.port,
      Object.assign({ label: "imap-parity" }, ladder));
    try {
      await anAccountHolderUploads(imap, ORDINARY, "upload");                                  // 6

      var selectTag = imap.tag();
      imap.send(selectTag + " SELECT INBOX");
      var selected = await imap.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
        "SELECT answered");
      count("every door put its message in the mailbox",
        /^\* 6 EXISTS/m.test(selected), visible(selected));

      var inbound   = await fetchWhole(imap, 1, "inbound");
      var blankTail = await fetchWhole(imap, 2, "blank tail");
      var noBody    = await fetchWhole(imap, 3, "no body");
      var byData    = await fetchWhole(imap, 4, "submission by DATA");
      var byBdat    = await fetchWhole(imap, 5, "submission by BDAT");
      var uploaded  = await fetchWhole(imap, 6, "upload");

      // ---- the two doors, on the same octets --------------------------
      theStoredMessageEndsWithWhatThePeerTransmitted(inbound, ORDINARY, "inbound");

      count("an upload is stored as the octets the client sent, which is what a literal " +
        "count means (RFC 9051 section 6.3.12)",
        uploaded.equals(ORDINARY),
        "stored " + uploaded.length + " octets, sent " + ORDINARY.length +
          "; stored tail " + uploaded.subarray(-12).toString("hex"));

      count("the message a peer delivered and the message a client uploaded end with the " +
        "same octets, so the door a message came through is not part of what it is",
        inbound.subarray(-16).equals(uploaded.subarray(-16)),
        "inbound tail " + inbound.subarray(-16).toString("hex") +
          ", uploaded tail " + uploaded.subarray(-16).toString("hex"));

      // The content-addressed store names a body by the SHA3-512 of its
      // content (`lib/store/blobs.js`), so this is the question of
      // whether the account is charged once or twice for one message.
      count("and they hash to one digest, so the same message delivered twice is one blob " +
        "rather than two charged against the account",
        b.crypto.sha3Hash(inbound.subarray(inbound.length - uploaded.length)) ===
          b.crypto.sha3Hash(uploaded),
        b.crypto.sha3Hash(inbound.subarray(Math.max(0, inbound.length - uploaded.length)))
          .slice(0, 24) + " vs " + b.crypto.sha3Hash(uploaded).slice(0, 24));

      // ---- the blank line the sender wrote ----------------------------
      theStoredMessageEndsWithWhatThePeerTransmitted(blankTail, BLANK_TAIL, "blank tail");
      count("a message whose last line is blank keeps that line, because a blank line is " +
        "body content rather than the framing around it",
        blankTail.subarray(-4).equals(CRLFCRLF),
        "stored tail " + blankTail.subarray(-8).toString("hex"));

      // ---- the message with no body -----------------------------------
      theStoredMessageEndsWithWhatThePeerTransmitted(noBody, HEADER_ONLY, "no body");
      count("a message with no body keeps the empty line that ends its header block, so a " +
        "consumer looking for the header/body separator finds the one the peer sent",
        noBody.indexOf(CRLFCRLF) !== -1,
        "stored " + noBody.length + " octets, tail " + noBody.subarray(-12).toString("hex"));

      // ---- the two submission paths -----------------------------------
      count("a submission sent in one BDAT chunk is stored as the octets it counted",
        byBdat.equals(SUBMITTED),
        "stored " + byBdat.length + " octets, sent " + SUBMITTED.length +
          "; stored tail " + byBdat.subarray(-12).toString("hex"));

      // The same octets sent inside DATA are stored the same: the DATA
      // reader ends the body after the CRLF that ends its last line,
      // which RFC 5321 §4.1.1.4 makes part of the mail data, and a BDAT
      // chunk carries its own count.
      count("a submission sent inside DATA is stored as the same octets as one sent in a " +
        "BDAT chunk", byData.equals(byBdat),
        "DATA stored " + byData.length + " octets ending " +
          byData.subarray(-12).toString("hex") + ", BDAT stored " + byBdat.length +
          " octets ending " + byBdat.subarray(-12).toString("hex"));
      count("and both are the fixture's length",
        byBdat.length === SUBMITTED.length && byData.length === SUBMITTED.length,
        "the fixture is " + SUBMITTED.length + " octets, BDAT stored " + byBdat.length +
          ", DATA stored " + byData.length);

      imap.send(imap.tag() + " LOGOUT");
    } finally { imap.close(); }

    // A POP3 maildrop is opened exclusively (RFC 1939 section 3), so the
    // IMAP session is done with before this one starts.
    var pop3 = await Wire.pop3(sections.pop3.port,
      Object.assign({ label: "pop3-parity" }, ladder));
    try {
      // Message 2 is the one whose last line is blank. What a POP3 client
      // is handed is the message plus the CRLF its terminator is framed
      // by, so the blank line has to survive to here as content.
      pop3.send("RETR 2");
      var raw = await pop3.readBytes(/\r\n\.\r\n/, "RETR answered");
      var view = raw.toString("latin1");
      var sizeMatch = /^\+OK (\d+) octets/m.exec(view);
      count("RETR reports a size in octets", sizeMatch !== null,
        visible(view.slice(0, 200)));
      var written = pop3Body(raw);
      var reported = sizeMatch ? parseInt(sizeMatch[1], 10) : written.length;
      var framing = written.subarray(reported);
      count("the octets after the +OK line are the message it counted, and at most the CRLF " +
        "the terminator is framed by",
        framing.length === 0 || (framing.length === 2 && framing.equals(CRLF)),
        reported + " counted, " + written.length + " written, trailing " +
          framing.toString("hex"));

      count("a POP3 client is handed the blank line the sender wrote",
        written.subarray(0, reported).subarray(-4).equals(CRLFCRLF),
        "written " + written.length + " octets, counted " + reported +
          ", tail " + written.subarray(-8).toString("hex"));

      pop3.send("QUIT");
      await pop3.read(/^(\+OK|-ERR)/m, "QUIT answered");
    } finally { pop3.close(); }

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "data-terminator-parity",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
