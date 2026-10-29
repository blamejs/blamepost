// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a peer's own bytes do on their way back out of a refusal.
 *
 * A submission this server will not relay is refused after the message
 * has been accepted for transfer, and the refusal names why. One of the
 * reasons is that the header block could not be read at all, and the
 * sentence that says so quotes the parser's own message. That message
 * quotes the header line the peer sent: `safeMime.parse` answers a line
 * carrying no colon with the first 64 characters of the line itself.
 *
 * So the peer chooses those characters. A line carrying the single-byte
 * control sequence introducer at U+009B, an escape at U+001B, a
 * right-to-left override at U+202E or a lone carriage return puts all
 * four into the refusal sentence, and that sentence is written into an
 * audit row an operator reads back in a console table.
 *
 * Two surfaces, and they are not the same surface:
 *
 *   - THE WIRE. The reply a peer reads is the fixed sentence the listener
 *     keeps per refusal class, and the framework runs it through its own
 *     line-injection check before writing it. Nothing the peer sent is in
 *     it. The case below measures that rather than assuming it, because
 *     the value is one property assignment away from being the long
 *     sentence instead, and a `550` carrying a bare CR would let the
 *     remainder be read as a second server reply.
 *   - THE AUDIT ROW. `b.audit.safeEmit` redacts credential shapes and
 *     nothing else, so a control character written into an event's
 *     metadata reaches the row as it arrived. The screen for that is
 *     `blamepost.text.forDisplay`, at the site that builds the value.
 *
 * ## What this file drives
 *
 *   - A real submission session that sends a header block whose second
 *     line carries no colon and four characters a reader acts on. The
 *     reply the peer receives is read as OCTETS, so the assertion is
 *     about the bytes on the wire rather than about a decoding of them.
 *   - The audit row that refusal writes, and whether the reason it
 *     carries still holds any of the four.
 *   - The same session's reply read as one response: exactly one status
 *     line, every CR followed by an LF, and nothing after the terminator.
 *   - A second submission from a domain holding no selector, which is the
 *     other refusal path in the same listener that writes a caught
 *     parser's text into a row.
 *
 * Run standalone:
 *   node test/layer-2-integration/refusal-error-text-screen.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers     = require("../helpers");
var wire        = require("../helpers/wire");
var b           = require("../../lib/vendor/blamejs");
var config      = require("../../lib/config");
var store       = require("../../lib/store");
var displayText = require("../../lib/text");
var blamepost   = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "amber cascade thimble 7734";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The four characters the vector carries, each built from its code point
// so this file is plain ASCII and no scanner reading it as binary stops
// part way. A raw control octet typed into a source file does not
// survive the round trip anyway.
//
// CSI is the single-byte control sequence introducer: one code point that
// opens an escape sequence, so a value carrying it colors or moves
// whatever prints it. ESC opens the two-byte form of the same thing. The
// right-to-left override renders the text after it in reverse, which is
// how a name reading `Invoice exe.jpg` is stored as `gpj.exe`. And a
// carriage return with no line feed after it ends a line for a reader
// that splits on either, which is what turns one console row into two.
var CSI = String.fromCharCode(0x9b);
var ESC = String.fromCharCode(0x1b);
var RLO = String.fromCharCode(0x202e);
var CR  = String.fromCharCode(0x0d);

// The header line that draws the refusal. It carries no colon, which is
// what `safeMime.parse` answers with the line itself, and the four
// characters above sit inside the first 64 the answer quotes.
//
// A line feed is deliberately absent, and its absence is a measurement
// rather than an omission: the parser splits the header block on line
// feeds before it looks at any line, so a line feed is the one character
// of the four that cannot be inside a line by the time the message
// quoting it is built. The fold from a line feed to a space is asserted
// where it can be reached, in test/layer-0-primitives/display-screen.test.js.
var HOSTILE_HEADER_LINE =
  "X-Report" + CSI + "31m" + ESC + "[2K" + RLO + "gpj.exe" + CR + "second-half";

// Every one of them, for an assertion that names which one survived
// rather than answering a bare false.
var ACTED_ON = [
  ["the control sequence introducer U+009B", CSI],
  ["the escape U+001B",                      ESC],
  ["the right-to-left override U+202E",      RLO],
  ["a carriage return with no line feed",    CR],
];

// One submission of one header block, with the octets the peer read back.
//
// The session is opened in binary mode on purpose. A text-mode socket
// decodes each chunk as it arrives, so a claim about what octets crossed
// the wire can no longer be made from it: a reply carrying the two UTF-8
// octets of U+009B and a reply carrying nothing at all both decode to
// something a search for the character can miss.
async function submitHeaderBlock(port, caPem, label, signIn, envelopeFrom,
                                 recipient, headerLines) {
  var sender = await Wire.submission(port, Object.assign({
    caPem: caPem, servername: HOSTNAME, label: label, binary: true,
  }, signIn));

  sender.send("MAIL FROM:<" + envelopeFrom + ">");
  var envelope = await sender.read(/^\d{3} /m, "MAIL FROM answered");
  sender.send("RCPT TO:<" + recipient + ">");
  await sender.read(/^\d{3} /m, "RCPT TO answered");
  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw(Buffer.from(headerLines.join("\r\n") + "\r\n\r\n" +
    "A message whose header block the parser cannot read.\r\n.\r\n", "utf8"),
  "<a header block carrying characters a reader acts on>");
  var reply = await sender.readBytes(/^\d{3} /m, "message answered");

  sender.send("QUIT");
  sender.close();
  return { envelope: envelope, reply: reply };
}

// ---- the wire --------------------------------------------------------------

// What the peer actually read. The claim is two separate ones and they
// fail differently: a reply carrying a character a terminal acts on is a
// refusal that repaints the operator's screen at the far end, and a reply
// carrying a bare CR or a second line is a refusal a peer can read as two
// server responses.
function theReplyIsOneWellFormedResponse(drove) {
  // A latin1 view is a one-to-one mapping from octets to characters, so
  // an assertion written over it is an assertion about the bytes.
  var octets = drove.hostile.reply.toString("latin1");
  // The reply's own terminator removed, because RFC 5321 section 4.2
  // ends every reply with one and a search that counted it would report
  // the shape the protocol requires. What is left is any carriage return
  // the reply carries in a position the protocol has no use for.
  var body = octets.replace(/\r\n/g, "");

  count("the message was refused, so the reply below is the refusal rather than an accept",
    /^550 5\.6\.0 /m.test(octets), visible(octets));

  ACTED_ON.forEach(function (entry) {
    // The character as the peer would have to have encoded it, and as a
    // single octet. A reply built by concatenating a JS string is
    // written out as UTF-8, so U+009B leaves as two octets; a reply
    // built from a latin1 buffer would carry the one. Neither may be
    // there, so both are searched for.
    var asUtf8 = Buffer.from(entry[1], "utf8").toString("latin1");
    count("the reply the peer reads carries no " + entry[0],
      body.indexOf(asUtf8) === -1 && body.indexOf(entry[1]) === -1,
      visible(octets));
  });

  // RFC 5321 section 4.2 writes a reply as one line ending CRLF. A bare
  // CR inside one, or a second line after the terminator, is the shape a
  // peer reads as two responses.
  var lines = octets.split("\r\n").filter(function (piece) { return piece.length > 0; });
  count("and it is exactly one response line rather than a status line with a second " +
    "reply smuggled after it",
  lines.length === 1, JSON.stringify(lines.map(visible)));
  count("with every carriage return in it followed by a line feed",
    body.indexOf(CR) === -1, visible(octets));
}

// ---- the audit row ---------------------------------------------------------

// The row the same refusal wrote, and whether the peer's characters are
// still in it. This is the surface the screen is for: the reply above is
// a fixed sentence the peer never contributed to, and the row quotes the
// parser's own answer, which the peer wrote most of.
function theRowCarriesNothingAReaderActsOn(rows) {
  var refusals = rows.forAction("blamepost.mail.listeners.submission_from_not_owned");
  count("the refusal wrote a row, so there is something for an operator to read back",
    refusals.length >= 1, "rows: " + JSON.stringify(rows.rows().map(function (row) {
      return row && row.action;
    })));
  if (refusals.length === 0) return;

  var metadata = helpers.metadataOf(refusals[refusals.length - 1]);
  var reason   = String(metadata.reason || "");

  count("the row's reason quotes the parser, so it is carrying the peer's own header line " +
    "rather than a sentence this server wrote on its own",
  reason.indexOf("header block could not be read") !== -1, reason.slice(0, 200));

  ACTED_ON.forEach(function (entry) {
    count("the row an operator reads back carries no " + entry[0],
      reason.indexOf(entry[1]) === -1, JSON.stringify(reason).slice(0, 240));
  });

  // The screen's own postcondition, which is the claim the site makes
  // rather than a list of the characters this vector happened to send. A
  // value that is already screened is unchanged by screening it again,
  // so a reason that differs from its own screening is one that never
  // went through it, whatever it happens to carry.
  count("and the reason is unchanged by the display screen, which is what says it went " +
    "through it rather than that this vector missed",
  displayText.forDisplay(reason) === reason, JSON.stringify(reason).slice(0, 240));
}

// The other refusal path in the same listener that writes a caught
// error's text into a row: a domain holding no selector cannot be signed
// for, and the message is relayed unsigned with a row saying so.
//
// The text the framework puts in that message names a domain and a code
// and carries nothing a peer chose, so this case cannot be made to fail
// by sending hostile bytes. What it asserts is the screen's
// postcondition, which holds whatever the message says, and what it adds
// is that the line is REACHED at run time rather than only read.
function theUnsignedRowIsScreenedToo(rows) {
  var unsigned = rows.forAction("blamepost.mail.listeners.submission_unsigned_no_key")
    .concat(rows.forAction("blamepost.mail.listeners.submission_unsigned"));
  count("a domain with no selector relays unsigned and says so in a row",
    unsigned.length >= 1, "rows: " + JSON.stringify(rows.rows().map(function (row) {
      return row && row.action;
    })));
  if (unsigned.length === 0) return;

  var metadata = helpers.metadataOf(unsigned[unsigned.length - 1]);
  var reason   = String(metadata.reason || "");
  count("and that row's reason is unchanged by the display screen",
    displayText.forDisplay(reason) === reason, JSON.stringify(reason).slice(0, 240));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("refusal-error-text-screen");
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
  var capture  = null;

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
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, by: "refusal error text screen test" });

    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
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

    // No selector is generated for the hosted domain, which is what makes
    // the second case below reach the unsigned-relay path.
    capture = helpers.auditCapture();

    var drove = {
      hostile: await submitHeaderBlock(sections.submission.port, leaf.ca,
        "hostile-header-block",
        { address: alice.address, password: ALICE_PASSWORD },
        alice.address, bob.address,
        ["From: <" + alice.address + ">", HOSTILE_HEADER_LINE]),

      unsigned: await submitHeaderBlock(sections.submission.port, leaf.ca,
        "no-selector-relay",
        { address: alice.address, password: ALICE_PASSWORD },
        alice.address, bob.address,
        ["From: <" + alice.address + ">",
          "To: <" + bob.address + ">",
          "Subject: a message from a domain holding no selector",
          "Date: Mon, 31 Aug 2026 12:00:00 +0000",
          "Message-ID: <no-selector-1@" + DOMAIN + ">"]),
    };

    count("the hostile case reached the author binding rather than being stopped at " +
      "MAIL FROM, so the envelope sender above is one the account holds",
    /^250 /m.test(drove.hostile.envelope), visible(drove.hostile.envelope));

    // The reply reaches the peer before the row reaches the audit store,
    // so the rows are waited for rather than read at whatever moment the
    // last socket happened to close.
    await helpers.waitUntil(function () {
      return capture.forAction("blamepost.mail.listeners.submission_from_not_owned")
        .length >= 1 &&
        capture.forAction("blamepost.mail.listeners.submission_unsigned_no_key")
          .concat(capture.forAction("blamepost.mail.listeners.submission_unsigned"))
          .length >= 1;
    }, {
      timeoutMs: 5000,
      label:     "refusal error text screen: both refusals write their audit rows",
    });

    theReplyIsOneWellFormedResponse(drove);
    theRowCarriesNothingAReaderActsOn(capture);
    theUnsignedRowIsScreenedToo(capture);

    capture.release();
    capture = null;

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (capture) {
      try { capture.release(); }
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

module.exports = {
  name:      "refusal-error-text-screen",
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
