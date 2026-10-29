// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A peer delivers a message to the MX listener, and the account holder
 * reads back the octets the peer transmitted.
 *
 * `test/layer-2-integration/mail-octet-fidelity.test.js` makes that
 * claim for a message an authenticated client APPENDs. Every other
 * byte-exact case in the suite is on IMAP, POP3 or submission. The
 * inbound direction, which is the one a stranger drives and the one
 * every message from outside this server takes, had no octet-level
 * vector at all: `mail-roundtrip` reads the FETCH response as text and
 * asks whether a substring is in it, and a substring check on a decoded
 * string cannot tell a message that survived from a message that was
 * decoded and re-encoded, because both decode to the same string.
 *
 * The difference is measurable. `toString("utf8")` replaces every octet
 * sequence that is not valid UTF-8 with U+FFFD, which is three octets
 * where there was one, and `.length` and `.slice()` on the result count
 * UTF-16 code units rather than octets. A message that goes through that
 * on the way in is stored longer than it arrived, is not the message the
 * sender wrote, and carries whatever signature the sender put on the
 * form that no longer exists.
 *
 * Mail is allowed to be 8-bit. RFC 6152 defines the extension and this
 * listener advertises it in its EHLO response, so a peer offering
 * `BODY=8BITMIME` is entitled to send a body this test's fixture sends:
 * `0xe9` and `0xe8`, which are `e` acute and `e` grave in Latin-1 and
 * are not valid UTF-8 anywhere in the message. One is in a header field
 * and one is in the body, because a header block and a body are separate
 * paths through the server and only one of them is a body.
 *
 * ## Which reader, and why
 *
 * POP3 `RETR` is the primary reader. `mailbox.getMessage` hands the
 * stored buffer to the listener as `rawBytes` and the listener writes it
 * with one dot-stuffing pass, so nothing between the sealed blob and the
 * socket renders a section or re-counts a string. RFC 1939 section 3
 * makes `RETR` the whole message and reports its size in octets, so the
 * count and the payload are both claims this file can hold the server
 * to.
 *
 * IMAP `BODY.PEEK[]` is read beside it and the two answers are compared
 * to each other. A whole-message fetch and a partial fetch take
 * different routes to the socket, and a server that carries octets on
 * one and text on the other loses the message on whichever route a
 * client happens to use. `BODY[]` is also the only whole-message read an
 * IMAP client has here: `_sectionBytes` refuses a MIME part by number
 * with `mailbox/unsupported-fetch`, so a client wanting one part fetches
 * `BODY[]` and splits it, and the octets of `BODY[]` are therefore what
 * every IMAP consumer of a part depends on.
 *
 * ## What the server is allowed to add
 *
 * RFC 8601 section 5 has the receiver prepend its own
 * `Authentication-Results` header, and the MX listener does. So the
 * stored message is longer than the transmitted one at the front, and
 * the claim is stated as a suffix: the octets the peer transmitted occur
 * in the stored message once, contiguously, and at its end. A prefix is
 * a header the receiver wrote; a changed byte inside that run is the
 * sender's message altered.
 *
 * Run standalone: node test/layer-2-integration/inbound-octet-fidelity.test.js
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

var count = helpers.count;

// ---- the fixture ------------------------------------------------------------

// "caf" and an `e` acute as Latin-1 writes it. A lone `0xe9` is not a
// valid UTF-8 sequence, so a decode replaces it and a re-encode of the
// replacement is three octets rather than one.
var LATIN1_SUBJECT = Buffer.from([0x63, 0x61, 0x66, 0xe9]);

// "premi", an `e` grave, then "re". The second 8-bit octet, in the body
// rather than in a header field.
var LATIN1_BODY_WORD = Buffer.from([0x70, 0x72, 0x65, 0x6d, 0x69, 0xe8, 0x72, 0x65]);

// The marker is ASCII so a failure message can quote it, and distinctive
// enough that finding it in a response means these bytes traveled rather
// than that something plausible was rebuilt.
var MARKER = "inbound marker 4d91e07b";

var SENT_MESSAGE = Buffer.concat([
  Buffer.from([
    "From: " + PEER,
    "To: alice@" + DOMAIN,
    "Subject: ",
  ].join("\r\n"), "ascii"),
  LATIN1_SUBJECT,
  Buffer.from([
    "",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <inbound-octet-9c14@example.net>",
    "",
    "",
  ].join("\r\n"), "ascii"),
  LATIN1_BODY_WORD,
  Buffer.from(" ligne, " + MARKER + "\r\nseconde ligne\r\n", "ascii"),
]);

// Every octet the peer put on the wire, the CRLF that closed the last
// line included. RFC 5321 section 4.1.1.4 writes the end-of-data
// sequence as `<CRLF>.<CRLF>` and says the first CRLF "is actually the
// terminator of the previous line", so that CRLF is the sender's and the
// message this server holds ends with it.
//
// This read `SENT_MESSAGE.subarray(0, SENT_MESSAGE.length - 2)` for as
// long as the inbound path stored the message without it, and called the
// difference framing. It is content: the same subtraction takes the
// blank line off a message whose last line is blank, and takes the empty
// line off the end of a header block on a message with no body.
// `test/layer-2-integration/data-terminator-parity.test.js` measures
// both, and this file now asks for the whole message.
var TRANSMITTED = SENT_MESSAGE;

// What a decode leaves behind. U+FFFD encoded as UTF-8 is these three
// octets, and one of them appears per octet sequence the decode could
// not read, so its presence anywhere in a stored message is the decode
// itself rather than an inference about one.
var REPLACEMENT_CHARACTER = Buffer.from([0xef, 0xbf, 0xbd]);

// How many times one octet appears in a buffer. The fixture carries each
// of its two 8-bit octets exactly once, so a count that moved says a
// rewrite happened even when the total length did not change.
function octetCount(bytes, octet) {
  var n = 0;
  for (var i = 0; i < bytes.length; i += 1) if (bytes[i] === octet) n += 1;
  return n;
}

// ---- the peer ---------------------------------------------------------------

// One inbound message, transmitted as octets. The payload goes out as a
// Buffer through `sendRaw`, which is the only way to put an octet that
// is not valid UTF-8 on the wire: a string would be encoded on the way
// out and the sequence would be replaced before the listener saw it.
//
// `BODY=8BITMIME` is on the MAIL FROM because that is what a conforming
// peer sends for this content, and the listener advertises the extension
// (RFC 6152).
async function aPeerDeliversAnEightBitMessage(port, caPem, address) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, label: "mx-8bit", helo: "peer.example.net" });
  try {
    peer.send("MAIL FROM:<" + PEER + "> BODY=8BITMIME");
    var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");
    count("a peer offering an 8-bit body is accepted, because the listener advertises " +
      "8BITMIME (RFC 6152)", /^250 /m.test(mailReply), visible(mailReply));

    peer.send("RCPT TO:<" + address + ">");
    var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
    count("the recipient this server hosts is accepted", /^250 /m.test(rcptReply),
      visible(rcptReply));

    peer.send("DATA");
    var dataReply = await peer.read(/^\d{3} /m, "DATA answered");
    count("the peer is invited to send the message", /^354 /m.test(dataReply),
      visible(dataReply));

    // The message ends with CRLF already, so the RFC 5321 section 4.5.2
    // terminator is a line of its own. No line in the fixture opens with
    // a dot, so nothing needs stuffing on the way out.
    peer.sendRaw(Buffer.concat([SENT_MESSAGE, Buffer.from(".\r\n", "ascii")]),
      "<the 8-bit message and its terminating dot>");
    var accepted = await peer.read(/^\d{3} /m, "message answered");
    count("the message is accepted once the dot arrives", /^250 /m.test(accepted),
      visible(accepted));

    peer.send("QUIT");
  } finally {
    peer.close();
  }
}

// ---- the account holder -----------------------------------------------------

// RETR, read as octets. The size on the `+OK` line and the payload are
// two claims and both are about the same message, so a response that
// re-encodes and then counts the re-encoding is internally consistent
// and still wrong. This holds the server to the transmitted bytes rather
// than to its own arithmetic.
async function retrReturnsWhatThePeerTransmitted(session) {
  session.send("RETR 1");
  var raw = await session.readBytes(/\r\n\.\r\n/, "RETR answered");
  var view = raw.toString("latin1");
  var sizeMatch = /^\+OK (\d+) octets/m.exec(view);
  count("RETR reports a size in octets", sizeMatch !== null, visible(view.slice(0, 200)));
  if (!sizeMatch) throw new Error("RETR answered without a size: " + visible(view.slice(0, 300)));
  var reported = parseInt(sizeMatch[1], 10);

  // A multi-line response ends with CRLF dot CRLF (RFC 1939 section 3),
  // so a stored message that does not itself end with CRLF is given one
  // before the dot. Those two octets are framing and the count on the
  // `+OK` line is the message, so the two are separated here rather than
  // compared as though they were the same number.
  var written = pop3Body(raw);
  var framing = written.subarray(reported);
  count("the octets after the +OK line are the message it counted, and at most the CRLF " +
    "the terminator is framed by",
    framing.length === 0 ||
      (framing.length === 2 && framing[0] === 0x0d && framing[1] === 0x0a),
    reported + " counted, " + written.length + " written, trailing " + framing.toString("hex"));

  var stored = written.subarray(0, reported);

  // The claim the file exists to make. A prefix is a header the receiver
  // wrote (RFC 8601 section 5); the sender's octets have to be present,
  // contiguous, and unchanged.
  var at = stored.indexOf(TRANSMITTED);
  count("the octets the peer transmitted are in the stored message, contiguously and at " +
    "its end, so nothing between the wire and the volume rewrote the sender's message",
    at !== -1 && at === stored.length - TRANSMITTED.length,
    "found at " + at + " in " + stored.length + " octets, message is " +
      TRANSMITTED.length + " octets; stored tail " +
      stored.subarray(Math.max(0, stored.length - TRANSMITTED.length)).toString("hex")
        .slice(0, 160));

  // The direct reading of the same thing. A decode substitutes U+FFFD
  // for every sequence it cannot read, and re-encoding that is three
  // octets where the message had one, so its presence is the decode
  // rather than an inference about one.
  count("no octet of the stored message is the replacement character a decode leaves behind",
    stored.indexOf(REPLACEMENT_CHARACTER) === -1,
    "found at offset " + stored.indexOf(REPLACEMENT_CHARACTER));

  count("the 8-bit octet in the header field is still one octet and still that octet",
    octetCount(stored, 0xe9) === 1, String(octetCount(stored, 0xe9)) + " occurrences of 0xe9");
  count("and so is the one in the body, which reaches the volume by a different path",
    octetCount(stored, 0xe8) === 1, String(octetCount(stored, 0xe8)) + " occurrences of 0xe8");

  return stored;
}

// The same message over the other reader. A whole-message fetch and a
// partial fetch take different routes to the socket, so a server that
// carries octets on one and text on the other loses the message on
// whichever route a client happens to use.
async function bodyMatchesWhatRetrReturned(session, stored) {
  var tag = session.tag();
  session.send(tag + " FETCH 1 (RFC822.SIZE BODY.PEEK[])");
  var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "size and body answered");
  var view = raw.toString("latin1");
  var sizeMatch = /RFC822\.SIZE (\d+)/.exec(view);
  count("the fetch reports a size", sizeMatch !== null, visible(view.slice(0, 200)));

  var lit = imapLiteral(raw);
  count("RFC822.SIZE is the same octet count POP3 reported for the same message",
    sizeMatch !== null && parseInt(sizeMatch[1], 10) === stored.length,
    (sizeMatch ? sizeMatch[1] : "no size") + " over IMAP, " + stored.length + " over POP3");
  count("the literal count is the number of octets that follow it",
    lit.present === lit.announced,
    "announced " + lit.announced + ", present " + lit.present);
  count("and it announces the stored octet count rather than a re-encoding of it",
    lit.announced === stored.length,
    "announced " + lit.announced + " for a " + stored.length + " octet message");
  count("BODY[] returns the message the other reader returned, byte for byte",
    lit.payload.equals(stored),
    "IMAP " + lit.payload.length + " octets " + lit.payload.toString("hex").slice(0, 80) +
      ", POP3 " + stored.length + " octets " + stored.toString("hex").slice(0, 80));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-octets");
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
        // The MX listener refuses to bind until an operator says the
        // zone is live. Both halves are required, the server wide
        // variable here and the per domain row below.
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "inbound octet test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // POP3 is off by default and it is the primary reader here.
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
        // absence of DNS rather than the octets. What that gate does with
        // a real answer belongs to a case that can give it one.
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

    await aPeerDeliversAnEightBitMessage(sections.mx.port, leaf.ca, alice.address);

    var ladder = {
      caPem:      leaf.ca,
      servername: HOSTNAME,
      address:    alice.address,
      password:   ALICE_PASSWORD,
      binary:     true,
    };

    // The maildrop is opened exclusively (RFC 1939 section 3), so this
    // session is done with before the IMAP one starts.
    var stored;
    var pop3 = await Wire.pop3(sections.pop3.port,
      Object.assign({ label: "pop3-inbound-octets" }, ladder));
    try {
      pop3.send("STAT");
      var stat = await pop3.read(/^(\+OK|-ERR)/m, "STAT answered");
      count("the maildrop holds the message the peer delivered",
        /^\+OK 1 /m.test(stat), visible(stat));

      stored = await retrReturnsWhatThePeerTransmitted(pop3);

      pop3.send("QUIT");
      await pop3.read(/^(\+OK|-ERR)/m, "QUIT answered");
    } finally {
      pop3.close();
    }

    var imap = await Wire.imap(sections.imap.port,
      Object.assign({ label: "imap-inbound-octets" }, ladder));
    try {
      var selectTag = imap.tag();
      imap.send(selectTag + " SELECT INBOX");
      var selected = await imap.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
        "SELECT answered");
      count("the recipient can select INBOX by the name a client uses",
        new RegExp("^" + selectTag + " OK", "m").test(selected), visible(selected));

      await bodyMatchesWhatRetrReturned(imap, stored);

      imap.send(imap.tag() + " LOGOUT");
    } finally {
      imap.close();
    }

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

module.exports = { name: "inbound-octet-fidelity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
