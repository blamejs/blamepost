// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A message is a sequence of octets, and the mailbox protocols count in
 * them. This file holds a client to that.
 *
 * The counts are not incidental. RFC 9051 section 6.4.5 defines the
 * partial fetch `BODY[]<start.count>` on octets, and its `{n}` literal
 * announces how many octets follow, which is how the client knows where
 * the response ends and the next one begins. RFC 1939 section 3 gives
 * POP3 `RETR` and `TOP` the same shape. A server that answers those in
 * characters is answering a different question, and the two only agree
 * while every byte of the message happens to be ASCII.
 *
 * Two things go wrong once they do not, and both are here:
 *
 *   - A window addressed in octets, served by slicing text, lands
 *     somewhere else. A UTF-8 message is longer in octets than it is in
 *     characters, so the window drifts further from where the client
 *     asked with every multi-byte character before it, and a window past
 *     the character count of the message comes back empty although the
 *     octets are there. A client reading a large message in windows
 *     reassembles a message that is not the one that was stored, and
 *     nothing in the exchange says so.
 *
 *   - An octet that is not valid UTF-8 does not survive being decoded.
 *     Mail carries them: an 8BITMIME peer may send a Latin-1 body, and
 *     an unencoded 8-bit header field is common enough that every
 *     server has to hold it. Decoding replaces each such octet with
 *     U+FFFD, which is three octets rather than one, so the message the
 *     client is given is neither the message that was stored nor the
 *     size the server reported for it.
 *
 * The cases drive the wire: an IMAP client APPENDs a message as a
 * literal, fetches windows of it back, and a POP3 client opens the same
 * maildrop. The client keeps the socket in binary mode, because a test
 * that decodes before asserting cannot tell a server that returned the
 * stored octets from one that returned a lossy re-encoding of them.
 * Both decode to the same string, which is exactly how this class of
 * defect stays invisible.
 *
 * `RETR` is here as the control. It hands the stored buffer to the
 * listener untouched and always has, so a change that fixes the windows
 * and breaks whole-message retrieval fails here rather than in
 * somebody's mail client.
 *
 * Run standalone: node test/layer-2-integration/mail-octet-fidelity.test.js
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

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var count = helpers.count;

// ---- the two fixtures -------------------------------------------------------

// Header lines are shared, so the two messages differ only in the thing
// each is here to prove.
function headerBlock(subject, messageId) {
  return Buffer.from([
    "From: sender@example.net",
    "To: alice@" + DOMAIN,
    "Subject: " + subject,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + messageId + "@example.net>",
    "",
    "",
  ].join("\r\n"), "utf8");
}

// The multi-byte message. Its body is built so that an octet window and
// a character window over it cannot coincide:
//
//   offset  0  aaaa                4 octets, 4 characters
//   offset  4  U+00E9 x4           8 octets, 4 characters
//   offset 12  bbbbbbbb            8 octets, 8 characters
//
// so the body is 20 octets and 16 characters. A window at octets 4
// through 12 is the four accented characters exactly; the same numbers
// read as characters run four octets past them. A window at octet 17 is
// inside the message and past its character count altogether.
var UTF8_BODY = Buffer.from("aaaaéééébbbbbbbb", "utf8");
var UTF8_HEADER = headerBlock("octet window probe", "octet-utf8");
var UTF8_MESSAGE = Buffer.concat([UTF8_HEADER, UTF8_BODY]);

// The 8-bit message. `0xe9` and `0xe8` are `e` acute and `e` grave in
// Latin-1 and are not valid UTF-8 anywhere in this message, in a header
// field and in the body, because a header block and a body are separate
// paths through the server and only one of them is a body.
var LATIN1_SUBJECT_BYTES = Buffer.from([0x63, 0x61, 0x66, 0xe9]);          // "caf" + e-acute
var LATIN1_HEADER = Buffer.concat([
  Buffer.from([
    "From: sender@example.net",
    "To: alice@" + DOMAIN,
    "Subject: ",
  ].join("\r\n"), "ascii"),
  LATIN1_SUBJECT_BYTES,
  Buffer.from([
    "",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <octet-latin1@example.net>",
    "",
    "",
  ].join("\r\n"), "ascii"),
]);
// "premiere ligne" with an e grave, then a second line that is ASCII, so
// TOP with a line count of one has something to stop before.
var LATIN1_BODY = Buffer.concat([
  Buffer.from([0x70, 0x72, 0x65, 0x6d, 0x69, 0xe8, 0x72, 0x65]),          // "premi" + e-grave + "re"
  Buffer.from(" ligne\r\nseconde ligne\r\n", "ascii"),
]);
var LATIN1_MESSAGE = Buffer.concat([LATIN1_HEADER, LATIN1_BODY]);

// ---- reading a response off the wire ----------------------------------------

// The octets of an IMAP literal in a response. A latin1 view of the
// buffer is a one to one mapping from octets to characters, so an index
// into the view is an offset into the buffer and the announced count can
// be applied to the buffer directly.
//
// Both halves are returned because the pair is the claim: a literal that
// announces one count and is followed by a different number of octets
// desynchronises the client's parser, whatever the payload says.
function imapLiteral(bytes) {
  var view  = bytes.toString("latin1");
  var match = /\{(\d+)\}\r\n/.exec(view);
  if (!match) {
    throw new Error("no literal in the FETCH response: " + visible(view.slice(0, 300)));
  }
  var announced = parseInt(match[1], 10);
  var from      = match.index + match[0].length;
  // Everything from the literal to the close of the FETCH response,
  // which is what the announced count is a claim about.
  var closed  = view.lastIndexOf(")\r\n", view.length);
  var present = closed === -1 ? bytes.length - from : closed - from;
  return {
    announced: announced,
    present:   present,
    payload:   bytes.subarray(from, from + announced),
  };
}

// The message body of a POP3 multi-line response: everything between the
// `+OK` line and the terminating dot, with RFC 1939 section 3 dot
// stuffing undone.
function pop3Body(bytes) {
  var view  = bytes.toString("latin1");
  var open  = view.indexOf("\r\n");
  if (open === -1) throw new Error("no +OK line: " + visible(view.slice(0, 300)));
  var end = view.indexOf("\r\n.\r\n", open);
  if (end === -1) throw new Error("no terminating dot: " + visible(view.slice(0, 300)));
  var body = bytes.subarray(open + 2, end + 2);
  // Undoing the stuffing on the octets rather than on a decoded copy,
  // for the same reason the socket is in binary mode.
  var out = [];
  var at  = 0;
  var text = body.toString("latin1");
  for (;;) {
    var dot = text.indexOf("\r\n..", at);
    if (dot === -1) { out.push(body.subarray(at)); break; }
    out.push(body.subarray(at, dot + 3));
    at = dot + 4;
  }
  return Buffer.concat(out);
}

// ---- cases ------------------------------------------------------------------

// A window the client addressed in octets is the window it is served.
async function partialFetchIsAddressedInOctets(session, seq) {
  // Octets 4 through 12 of the body are the four accented characters and
  // nothing else. Read as characters the same numbers reach four octets
  // past them, into the run of `b`.
  var wanted = UTF8_BODY.subarray(4, 12);

  var tag = session.tag();
  session.send(tag + " FETCH " + seq + " BODY.PEEK[TEXT]<4.8>");
  var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "partial fetch answered");
  var lit = imapLiteral(raw);

  count("a partial fetch of eight octets returns eight octets",
    lit.announced === 8, "literal announced " + lit.announced + ", expected 8");
  count("the literal count is the number of octets that follow it",
    lit.present === lit.announced,
    "announced " + lit.announced + ", present " + lit.present);
  count("and those octets are the ones at that offset in the stored message",
    lit.payload.equals(wanted),
    "got " + lit.payload.toString("hex") + ", stored " + wanted.toString("hex"));
}

// A window that starts past the character count of the message but
// inside its octets is still inside the message.
async function aWindowPastTheCharacterCountStillHasOctets(session, seq) {
  var wanted = UTF8_BODY.subarray(17, 20);

  var tag = session.tag();
  session.send(tag + " FETCH " + seq + " BODY.PEEK[TEXT]<17.3>");
  var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "tail window answered");
  var lit = imapLiteral(raw);

  count("a window inside the message is not answered as though the message ended",
    lit.announced === 3, "literal announced " + lit.announced + ", expected 3");
  count("the tail octets come back",
    lit.payload.equals(wanted),
    "got " + lit.payload.toString("hex") + ", stored " + wanted.toString("hex"));
}

// The claim a client actually relies on. A client reading a large body
// in windows walks it by the counts the server gives it: ask at an
// offset, take what arrives, advance by that many octets, ask again.
// That walk is the whole contract, and it only terminates on the right
// message if the offset the client names and the octets the server
// counts are the same unit.
//
// The window size is deliberately not a divisor of the message: a walk
// whose windows happen to line up with the characters can reassemble a
// message even from a server counting the wrong thing, which is how a
// case like this passes while the defect is live.
async function aWindowedReadReassemblesTheMessage(session, seq) {
  var pieces = [];
  var at     = 0;
  var WINDOW = 6;
  for (var step = 0; step < 10; step += 1) {
    var tag = session.tag();
    session.send(tag + " FETCH " + seq + " BODY.PEEK[TEXT]<" + at + "." + WINDOW + ">");
    var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
      "window at " + at + " answered");
    var lit = imapLiteral(raw);
    if (lit.announced === 0) break;
    pieces.push(lit.payload);
    at += lit.announced;
  }
  var rebuilt = Buffer.concat(pieces);
  count("a client walking the body by the counts it is given reassembles it exactly",
    rebuilt.equals(UTF8_BODY),
    "rebuilt " + rebuilt.length + " octets " + rebuilt.toString("hex") +
      ", stored " + UTF8_BODY.length + " octets " + UTF8_BODY.toString("hex"));
}

// RFC822.SIZE is the size of the message, and BODY[] is the message. A
// client that trusted the first to allocate for the second has to be
// right.
async function reportedSizeMatchesTheBodyItDescribes(session, seq) {
  var tag = session.tag();
  session.send(tag + " FETCH " + seq + " (RFC822.SIZE BODY.PEEK[])");
  var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "size and body answered");
  var view = raw.toString("latin1");
  var sizeMatch = /RFC822\.SIZE (\d+)/.exec(view);
  count("the fetch reports a size", sizeMatch !== null, visible(view.slice(0, 200)));
  if (!sizeMatch) return;
  var lit = imapLiteral(raw);
  count("RFC822.SIZE is the stored octet count",
    parseInt(sizeMatch[1], 10) === UTF8_MESSAGE.length,
    "reported " + sizeMatch[1] + ", stored " + UTF8_MESSAGE.length);
  count("and the whole-message literal announces the same count",
    lit.announced === UTF8_MESSAGE.length,
    "literal " + lit.announced + ", stored " + UTF8_MESSAGE.length);
}

// The 8-bit message over IMAP. This is the claim the file exists to
// make, and it is three claims that have to hold together.
//
// RFC822.SIZE is what a client allocates on. The literal count is what
// it uses to find where the response ends, so a literal announcing one
// number and followed by a different number of octets puts the client's
// parser out of step with the connection and the response after it is
// read as part of the message. And the payload is the message: an octet
// that did not survive the trip is a message the account holder cannot
// get back, under a tagged OK that says nothing went wrong.
//
// Asserting the count without the payload is the trap here. A response
// that re-encodes the message and then counts the re-encoding is
// internally consistent and still wrong, which is exactly the shape this
// stopped being.
async function theEightBitMessageIsReturnedIntact(session, seq) {
  var tag = session.tag();
  session.send(tag + " FETCH " + seq + " (RFC822.SIZE BODY.PEEK[])");
  var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "8-bit fetch answered");
  var view = raw.toString("latin1");
  var sizeMatch = /RFC822\.SIZE (\d+)/.exec(view);
  var lit = imapLiteral(raw);

  count("an 8-bit message is reported at its stored size",
    sizeMatch !== null && parseInt(sizeMatch[1], 10) === LATIN1_MESSAGE.length,
    sizeMatch ? sizeMatch[1] + " vs stored " + LATIN1_MESSAGE.length : visible(view.slice(0, 200)));
  count("its literal count is the number of octets that follow it",
    lit.present === lit.announced,
    "announced " + lit.announced + ", present " + lit.present);
  count("and the literal announces the stored octet count rather than a re-encoding of it",
    lit.announced === LATIN1_MESSAGE.length,
    "announced " + lit.announced + " for a " + LATIN1_MESSAGE.length + " octet message");
  count("BODY[] returns the 8-bit message byte for byte",
    lit.payload.equals(LATIN1_MESSAGE),
    "got " + lit.payload.length + " octets " + lit.payload.toString("hex").slice(0, 80) +
      ", stored " + LATIN1_MESSAGE.length + " octets " +
      LATIN1_MESSAGE.toString("hex").slice(0, 80));
}

// The window verbs over the same 8-bit message. A whole-message fetch
// and a partial fetch take different routes to the socket, and a server
// that carries octets on one and text on the other loses the message on
// whichever route a client happens to use for a large mailbox.
async function anEightBitWindowIsTheStoredOctets(session, seq) {
  // The run of octets around the e-grave in the body, which is where a
  // decode would show up as both a different length and a different
  // byte.
  var at     = LATIN1_MESSAGE.indexOf(LATIN1_BODY);
  var wanted = LATIN1_MESSAGE.subarray(at + 3, at + 8);

  var tag = session.tag();
  session.send(tag + " FETCH " + seq + " BODY.PEEK[]<" + (at + 3) + ".5>");
  var raw = await session.readBytes(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "8-bit window answered");
  var lit = imapLiteral(raw);
  count("a window over an 8-bit message announces the octets it was asked for",
    lit.announced === 5, "literal announced " + lit.announced + ", expected 5");
  count("and returns the stored octets at that offset",
    lit.payload.equals(wanted),
    "got " + lit.payload.toString("hex") + ", stored " + wanted.toString("hex"));
}

// POP3 TOP hands back a header block and a number of body lines. Both
// are parts of the stored message, so both are the stored octets.
async function topReturnsTheStoredHeaderOctets(session, msgNum) {
  session.send("TOP " + msgNum + " 0");
  var raw = await session.readBytes(/\r\n\.\r\n/, "TOP 0 answered");
  var body = pop3Body(raw);
  count("TOP with no body lines returns the stored header block byte for byte",
    body.equals(LATIN1_HEADER),
    "got " + body.toString("hex") + ", stored " + LATIN1_HEADER.toString("hex"));
}

async function topReturnsTheStoredBodyOctets(session, msgNum) {
  // The header block already ends with the blank line, so one body line
  // is the header block followed by the first line of the body.
  var firstLine = LATIN1_BODY.subarray(0, LATIN1_BODY.indexOf("\r\n") + 2);
  var wanted    = Buffer.concat([LATIN1_HEADER, firstLine]);

  session.send("TOP " + msgNum + " 1");
  var raw = await session.readBytes(/\r\n\.\r\n/, "TOP 1 answered");
  var body = pop3Body(raw);
  count("TOP with one body line returns that line's stored octets",
    body.equals(wanted),
    "got " + body.toString("hex") + ", stored " + wanted.toString("hex"));
}

// The control. RETR has always handed the stored buffer to the listener
// untouched; this is here so a change to the windows cannot quietly cost
// whole-message retrieval.
async function retrIsByteExact(session, msgNum) {
  session.send("RETR " + msgNum);
  var raw = await session.readBytes(/\r\n\.\r\n/, "RETR answered");
  var view = raw.toString("latin1");
  var sizeMatch = /^\+OK (\d+) octets/m.exec(view);
  count("RETR reports a size in octets", sizeMatch !== null, visible(view.slice(0, 200)));
  if (sizeMatch) {
    count("and it is the stored octet count",
      parseInt(sizeMatch[1], 10) === LATIN1_MESSAGE.length,
      "reported " + sizeMatch[1] + ", stored " + LATIN1_MESSAGE.length);
  }
  var body = pop3Body(raw);
  count("RETR returns the stored message byte for byte",
    body.equals(LATIN1_MESSAGE),
    "got " + body.length + " octets, stored " + LATIN1_MESSAGE.length);
}

// ---- runner -----------------------------------------------------------------

// Both fixtures go in through APPEND, which is the one client path that
// carries a literal of arbitrary octets (RFC 9051 section 6.3.12). A
// fixture written through the store would not prove that a message can
// reach the store intact in the first place.
async function appendBoth(session) {
  await session.sendLiteral(session.tag() + " APPEND INBOX", UTF8_MESSAGE,
    "<the multi-byte message>");
  var first = await session.read(/^\S+ (OK|NO|BAD)/m, "first APPEND answered");
  count("a message carrying multi-byte characters is accepted",
    /^\S+ OK/m.test(first), visible(first));

  await session.sendLiteral(session.tag() + " APPEND INBOX", LATIN1_MESSAGE,
    "<the 8-bit message>");
  var second = await session.read(/^\S+ (OK|NO|BAD)/m, "second APPEND answered");
  count("a message carrying octets that are not valid UTF-8 is accepted",
    /^\S+ OK/m.test(second), visible(second));
}

async function run() {
  var root    = helpers.tempDir("octets");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

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
      },
      cwd: root,
    });

    // Given back before the directory under it goes, whichever way this
    // run ends. A database handle still open while its files are removed
    // is a locked file on Windows and a teardown rejection on Linux, and
    // either one lands on top of the verdict this run had already
    // reached.
    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // POP3 is off by default and half of this file is about it.
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
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

    var imap = await Wire.imap(sections.imap.port,
      Object.assign({ label: "imap-octets" }, ladder));
    try {
      await appendBoth(imap);

      var selectTag = imap.tag();
      imap.send(selectTag + " SELECT INBOX");
      var selected = await imap.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
        "SELECT answered");
      count("the mailbox holds both messages",
        /^\* 2 EXISTS/m.test(selected), visible(selected));

      // Sequence 1 is the multi-byte message; the windows are about it.
      await partialFetchIsAddressedInOctets(imap, 1);
      await aWindowPastTheCharacterCountStillHasOctets(imap, 1);
      await aWindowedReadReassemblesTheMessage(imap, 1);
      await reportedSizeMatchesTheBodyItDescribes(imap, 1);
      await theEightBitMessageIsReturnedIntact(imap, 2);
      await anEightBitWindowIsTheStoredOctets(imap, 2);

      imap.send(imap.tag() + " LOGOUT");
    } finally {
      imap.close();
    }

    // A POP3 maildrop is opened exclusively, so the IMAP session is done
    // with before this one starts.
    var pop3 = await Wire.pop3(sections.pop3.port,
      Object.assign({ label: "pop3-octets" }, ladder));
    try {
      pop3.send("STAT");
      var stat = await pop3.read(/^(\+OK|-ERR)/m, "STAT answered");
      count("the maildrop reports both messages", /^\+OK 2 /m.test(stat), visible(stat));

      // Message 2 is the 8-bit one, in the order they were appended.
      await topReturnsTheStoredHeaderOctets(pop3, 2);
      await topReturnsTheStoredBodyOctets(pop3, 2);
      await retrIsByteExact(pop3, 2);

      pop3.send("QUIT");
      await pop3.read(/^(\+OK|-ERR)/m, "QUIT answered");
    } finally {
      pop3.close();
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

module.exports = { name: "mail-octet-fidelity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
