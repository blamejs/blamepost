// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a peer can make this server put into a delivery report.
 *
 * When one recipient on a message can be delivered to and another
 * cannot, the message is stored for the first and a report is composed
 * for the second. RFC 3462 section 3 puts the original headers in the
 * last part of that report so the sender can tell which message it is
 * about: the headers, not the message. The peer chooses those bytes,
 * sends them once, and this server copies them into a report addressed
 * to whoever the envelope named, which on a forged envelope is somebody
 * who never sent anything.
 *
 * The recipient that fails here is a mailbox that is FULL rather than
 * one that does not exist, and that is what reaches the report at all
 * rather than a convenience of the fixture. RFC 5321 section 3.3
 * answers an address this server does not hold with `550 5.1.1` at
 * RCPT, before the peer transmits a byte of the message, so a message
 * addressed to one is never accepted and never reported on. What
 * survives to the end of DATA is the recipient whose condition is
 * temporary and might yet clear: a mailbox that filled while the peer
 * was transmitting, an account suspended mid-message, a domain switched
 * off. Those are the reports this server composes, so those are the
 * ones whose size a peer gets to choose.
 *
 * That makes the size of the copied block a wire-input question rather
 * than a formatting one, and the answer has to hold for a well formed
 * message as well as a malformed one. A bound that only applies when
 * the peer forgets the blank line is a bound every real sender walks
 * past.
 *
 * The same question applies to the audit row. A peer chooses the
 * recipient list and may name a hundred addresses on one message, so a
 * row that names all of them is a row whose size the peer picked.
 *
 * And the last record here is one this server writes about itself. When
 * a domain's mail relays without a DKIM signature the message still
 * goes, because refusing an account's own mail over a key problem is a
 * worse outage than sending it unattributable. The row saying so is
 * then the only way an operator finds out, and an operator asks an
 * audit trail one question first: what failed.
 *
 * The run drives real listeners over real sockets. The stores, the
 * delivery handle and the signer are stand-ins, because the claims are
 * about what the listeners' own handoffs pass onward, and a stand-in is
 * the only way to read that without going through the spool.
 *
 * Size is one half of the question and where the block ends is the
 * other. RFC 5322 section 2.1 ends the header block at the first empty
 * line, and a peer that wrote that line as a bare LF is out of spec and
 * still gets its message stored exactly as it sent it, so the block has
 * to be found by scanning forward to the first empty line however it
 * was written. Looking through the whole message for a CRLFCRLF first
 * finds a separator that is not the first one on precisely the messages
 * that carry a bare-LF separator and a CRLFCRLF further down, which is
 * what an ordinary quoted forward and a MIME preamble both look like.
 * Everything between the real separator and that one is then copied
 * into the report as though the peer had written it as a header.
 *
 * Seven claims:
 *
 *   - A message whose header block is far larger than the report cap is
 *     reported on with a bounded copy of it.
 *   - A message with no header separator at all, which is the malformed
 *     shape, is bounded too, and still identifies itself, so the bound
 *     is not bought by reporting nothing.
 *   - A block of octets this server cannot decode as text is bounded by
 *     what the report carries rather than by what was measured before a
 *     decode, because the decode is where a bound stops holding.
 *   - A message separated by a bare LF whose body carries a CRLFCRLF is
 *     reported on with its headers and none of its body.
 *   - A message separated by a bare LF and carrying no CRLF blank line
 *     anywhere is too, so the answer does not depend on what the body
 *     happens to contain.
 *   - A message naming more recipients than a row should list is
 *     recorded with a bounded list and an exact count.
 *   - A relay whose signature could not be produced is recorded as a
 *     failure, which is the outcome the query an operator runs filters
 *     on.
 *
 * Run standalone: node test/layer-2-integration/wire-refusal-report.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var certs     = require("../helpers/certs");
var b         = require("../../lib/vendor/blamejs");
var listeners = require("../../lib/mail/listeners");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var KNOWN = "alice@" + DOMAIN;
var FULL  = "full@" + DOMAIN;
var PEER  = "sender@example.net";

var ALICE_PASSWORD = "quiet lantern bicycle 4291";

// The cap on how many refused recipients one record names, matching
// `MAX_REPORTED_RECIPIENTS` in lib/mail/listeners.js. The message below
// carries more than this so a bounded list and an unbounded one cannot
// look the same.
var RECIPIENT_CAP  = 32;
var LONG_RECIPIENT_LIST = 40;

// The report carries the original headers, and this is the whole of
// what it is allowed to carry. It matches `MAX_REPORTED_HEADER_BYTES`
// in lib/mail/mailbox.js, which is where the reader every report path
// asks now lives; a run that raises the cap there raises it here, and
// the assertions below are written as "no more than", so a smaller cap
// needs no edit at all.
var REPORT_CAP_BYTES = 4096;

// Comfortably past the cap and cheap to send: one padding header
// repeated until the block is large. A peer wanting amplification would
// send far more; this is enough to tell a bounded copy from a whole one.
var PADDING_HEADERS = 400;
var PADDING_VALUE   = new Array(200).join("x");

// A header block padded with an octet that is not valid UTF-8 on its
// own. 0xE9 is "e acute" in every Latin-1 derived charset, which is what
// a non-conforming sender puts in a Subject and what 8BITMIME carries
// without complaint, and standing alone it is a sequence no UTF-8
// decoder can accept. Each one it replaces costs three bytes where the
// peer sent one, so a block measured before the decode and carried after
// it is three times the size the measurement allowed.
var UNDECODABLE_OCTET  = 0xE9;
var UNDECODABLE_PADDING = 6000;

// A line the peer writes into the BODY. A report is meant to carry the
// headers of the message it is about, so this string appearing in one
// means body text of the peer's choosing reached a report addressed to
// whoever the envelope named.
var BODY_ONLY_LINE = "X-Not-A-Header: body-only-6d2c74e8";

var SHUTDOWN_TIMEOUT_MS = 5000;

var count = helpers.count;

// ---- stand-ins -------------------------------------------------------------

// The identity store. One address delivers; every other address at this
// domain is a mailbox that exists and is full. `resolve` is the only
// routing verb the MX handoff calls.
//
// Full rather than absent, and the two are not interchangeable here. The
// listener asks this store at RCPT and refuses a PERMANENT condition on
// the wire, so an address that does not exist ends the transaction there
// and produces no report to measure. A mailbox over quota is temporary,
// the mailbox owner can clear it, and RFC 3463 gives it a 4.2.2 of its
// own, so the recipient is accepted and met at the handoff, which is the
// one place a report is composed.
function identityAnswering() {
  return {
    resolve: function (address) {
      if (String(address).toLowerCase() === KNOWN) {
        return {
          deliverable: true,
          local:       true,
          targets:     [{ local: true, deliverable: true, accountId: "acct_alice", mailbox: KNOWN }],
        };
      }
      return { deliverable: false, local: true, reason: "mailbox/over-quota", targets: [] };
    },
    accounts: {
      authenticate: async function (credentials) {
        if (credentials && credentials.address === KNOWN && credentials.password === ALICE_PASSWORD) {
          return { ok: true, accountId: "acct_alice", address: KNOWN, domain: DOMAIN, isAdmin: false };
        }
        return { ok: false, reason: "credentials-rejected" };
      },
      // The same one account, read again. A credential is verified once
      // and the session it opens outlives the answer, so every message a
      // submission session hands over re-reads the account behind it.
      // Answered synchronously, because the shipped store answers this
      // one off a row and a promise here would read as an account with no
      // status at all.
      get: function (idOrAddress) {
        var asked = String(idOrAddress).toLowerCase();
        if (asked !== "acct_alice" && asked !== KNOWN) return null;
        return {
          id: "acct_alice", address: KNOWN, domain: DOMAIN,
          status: "active", isAdmin: false,
        };
      },
    },
    domains:  {
      list: async function () {
        return [{ domain: DOMAIN, status: "active", dnsAcknowledged: true }];
      },
      // The second half of that re-read: an account in service on a
      // domain the operator has withdrawn is not one this server serves.
      get: function (domain) {
        return String(domain).toLowerCase() === DOMAIN
          ? { domain: DOMAIN, status: "active", dnsAcknowledged: true }
          : null;
      },
    },
    // The submission listener reads the aliases that land in an
    // account's mailbox to decide which authors it may write. This
    // deployment has none, so the only address the one account here may
    // write is its own, which is what these cases send under.
    aliases:  { list: function () { return []; } },
  };
}

// A signer that cannot produce a signature, which is what a domain whose
// key is missing or unreadable looks like from here.
function failingSigner() {
  return {
    sign: async function () {
      throw new Error("no usable signing key for that domain");
    },
  };
}

// The metadata reader and the audit capture both live in
// `test/helpers`, so every file that reads a row reads it the same way.
var metadataOf   = helpers.metadataOf;
var auditCapture = helpers.auditCapture;

// The message store, recording what was appended and nothing more. No
// Sieve script, so delivery files into INBOX by the ordinary path.
function messageRecorder() {
  var appended = [];
  return {
    appendMessage: async function (folder, body) {
      appended.push({ folder: folder, bytes: body.length });
      return { objectid: "obj_" + appended.length };
    },
    sieveScripts: { active: function () { return null; } },
    appended:     function () { return appended.slice(); },
  };
}

// The delivery handle, recording the reports it was asked to send.
function deliveryRecorder() {
  var reports = [];
  return helpers.standInDelivery({
    bounce: async function (bounceOpts) {
      reports.push(bounceOpts);
      return { delivered: [], deferred: [], failed: [] };
    },
    reports: function () { return reports.slice(); },
  });
}

// ---- the peer --------------------------------------------------------------

async function mxSession(port, caPem, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^220 /m, "banner");
  session.send("EHLO peer.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO peer.example.net");
  await session.read(/^250 /m, "EHLO accepted over TLS");
  return session;
}

// The message and the dot that ends it. A Buffer payload stays a Buffer
// through the join: concatenating the terminator with `+` would decode
// it first, so a case written to carry a specific octet would arrive as
// a replacement character and stop testing what it says it tests.
function terminated(message) {
  if (!Buffer.isBuffer(message)) return message + ".\r\n";
  return Buffer.concat([message, Buffer.from(".\r\n", "ascii")]);
}

// One message to both addresses: the deliverable one stores it, the full
// one produces the report this run reads.
async function sendToBoth(port, caPem, message, label) {
  var peer = await mxSession(port, caPem, label);
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + KNOWN + ">");
  await peer.read(/^250 /m, "the deliverable recipient is accepted");
  peer.send("RCPT TO:<" + FULL + ">");
  await peer.read(/^250 /m, "the full mailbox is accepted at RCPT, its condition being temporary");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(terminated(message), "<the message and its terminating dot>");
  var accepted = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return accepted;
}

function identifyingHeaders(marker) {
  return [
    "From: " + PEER,
    "To: " + KNOWN,
    "Subject: " + marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@example.net>",
  ];
}

function paddedHeaders(marker) {
  var lines = identifyingHeaders(marker);
  for (var i = 0; i < PADDING_HEADERS; i += 1) {
    lines.push("X-Padding-" + i + ": " + PADDING_VALUE);
  }
  return lines.join("\r\n");
}

// The same block, padded with octets rather than with letters. The
// identifying headers stay in front so a bounded copy still names the
// message, which is what stops the bound from being bought by reporting
// nothing.
function undecodableHeaders(marker) {
  var head = Buffer.from(identifyingHeaders(marker).join("\r\n") + "\r\nX-Padding: ", "ascii");
  return Buffer.concat([head, Buffer.alloc(UNDECODABLE_PADDING, UNDECODABLE_OCTET)]);
}

// ---- cases -----------------------------------------------------------------

async function aWellFormedMessageIsReportedOnWithinTheCap(port, caPem, delivery) {
  var marker  = "padded-3f80ab21";
  var message = paddedHeaders(marker) + "\r\n\r\nA short body.\r\n";
  var accepted = await sendToBoth(port, caPem, message, "mx-padded");
  count("the message is accepted for the recipient that resolves",
    /^250 /m.test(accepted), visible(accepted));

  var reports = delivery.reports();
  count("and a report is composed for the recipient that does not",
    reports.length === 1 && reports[0].recipient === FULL,
    JSON.stringify(reports.map(function (r) { return r.recipient; })));

  var carried = Buffer.byteLength(String(reports[0].originalHeaders || ""), "utf8");
  count("the header block the peer sent is far larger than the report cap",
    Buffer.byteLength(paddedHeaders(marker), "utf8") > REPORT_CAP_BYTES * 4,
    Buffer.byteLength(paddedHeaders(marker), "utf8") + " bytes sent");
  count("and the report carries no more of it than the cap allows",
    carried <= REPORT_CAP_BYTES, carried + " bytes carried");
  count("while still carrying enough to identify the message",
    String(reports[0].originalHeaders || "").indexOf("Message-ID:") !== -1,
    String(reports[0].originalHeaders || "").slice(0, 120));
}

// The shape that skips the header separator entirely. This branch was
// always bounded; the case exists so the two branches cannot drift back
// apart, which is how the bound came to apply to one of them.
async function aMessageWithNoSeparatorIsBoundedToo(port, caPem, delivery) {
  var marker  = "unseparated-3f80ab21";
  var message = paddedHeaders(marker) + "\r\n";
  var accepted = await sendToBoth(port, caPem, message, "mx-unseparated");
  count("a message with no header separator is still accepted for the resolving recipient",
    /^250 /m.test(accepted), visible(accepted));

  var reports = delivery.reports();
  count("and it too produces one report", reports.length === 2,
    JSON.stringify(reports.map(function (r) { return r.recipient; })));

  var carried = Buffer.byteLength(String(reports[1].originalHeaders || ""), "utf8");
  count("bounded by the same cap", carried <= REPORT_CAP_BYTES, carried + " bytes carried");
  count("and still naming the message it is about",
    String(reports[1].originalHeaders || "").indexOf("Message-ID:") !== -1,
    String(reports[1].originalHeaders || "").slice(0, 120));
}

// The block whose octets are not text. RFC 3462 section 3 asks for the
// original headers, and a message is a sequence of octets rather than a
// string: the peer picks the charset as freely as it picks the length,
// and 8BITMIME is advertised on this listener, so a header carrying
// Latin-1 is an ordinary arrival rather than an attack.
//
// A cap applied to the octets and then handed to a UTF-8 decode is not a
// cap on what leaves. Every octet the decode cannot accept is replaced
// by a three byte character, so a peer sending nothing but those turns
// the bound into three times itself, in a message addressed to whoever
// the envelope named, which on a forged envelope is somebody who never
// sent anything.
async function aBlockOfOctetsIsBoundedByWhatItCarries(port, caPem, delivery) {
  var marker = "octets-3f80ab21";
  var block  = undecodableHeaders(marker);
  var message = Buffer.concat([block, Buffer.from("\r\n\r\nA short body.\r\n", "ascii")]);

  var accepted = await sendToBoth(port, caPem, message, "mx-octets");
  count("a message whose headers carry octets this server cannot decode is still accepted",
    /^250 /m.test(accepted), visible(accepted));

  var reports = delivery.reports();
  count("and it produces one report", reports.length === 3,
    JSON.stringify(reports.map(function (r) { return r.recipient; })));

  var carried = Buffer.byteLength(String(reports[2].originalHeaders || ""), "utf8");
  count("the header block the peer sent is larger than the report cap",
    block.length > REPORT_CAP_BYTES, block.length + " octets sent");
  count("and the report carries no more than the cap allows, measured on what it carries",
    carried <= REPORT_CAP_BYTES, carried + " bytes carried");
  count("while still naming the message it is about",
    String(reports[2].originalHeaders || "").indexOf("Message-ID:") !== -1,
    String(reports[2].originalHeaders || "").slice(0, 120));
}

// The separator a peer actually wrote, against the one a scan goes
// looking for.
//
// This message ends its headers with a bare LF, which is out of spec and
// arrives every day, and then quotes a forwarded message in its body,
// which puts a CRLFCRLF further down. The first empty line is the bare
// one. A scan that asks for CRLFCRLF over the whole message finds the
// quoted one instead, and everything in between, which is body the peer
// wrote, is copied into the report as the message's headers.
async function aBareLfSeparatorIsFoundBeforeALaterCrlfPair(port, caPem, delivery) {
  var marker  = "barelf-3f80ab21";
  var message = identifyingHeaders(marker).join("\n") + "\n\n" +
    "A short body.\n" +
    BODY_ONLY_LINE + "\n" +
    "\r\n\r\n" +
    "The quoted forward starts here.\r\n";

  var accepted = await sendToBoth(port, caPem, message, "mx-barelf");
  count("a message separated by a bare LF is accepted for the recipient that resolves",
    /^250 /m.test(accepted), visible(accepted));

  var reports = delivery.reports();
  count("and it produces one report", reports.length === 4,
    JSON.stringify(reports.map(function (r) { return r.recipient; })));

  var carried = String(reports[3].originalHeaders || "");
  count("the report names the message it is about",
    carried.indexOf("Message-ID:") !== -1, carried.slice(0, 120));
  count("and carries none of the body the peer wrote after the separator",
    carried.indexOf(BODY_ONLY_LINE) === -1, visible(carried).slice(0, 200));
}

// The same separator with nothing further down to find. Where the first
// message has a later CRLFCRLF to land on, this one has none at all, so
// a scan that comes back empty falls through to reporting the message
// whole. Both shapes are here because a fix that only stops the scan
// landing in the wrong place leaves this one reporting everything.
//
// The last line of the body ends CRLF while the rest of the message
// does not, and that is not incidental. The line the peer sends next is
// the terminating dot, and a dot line opening on a bare LF is the
// smuggling shape the listener refuses outright, so a peer that wants
// this message accepted has to write that one boundary canonically. It
// is the shape a real bare-LF sender arrives in for the same reason.
async function aBareLfMessageWithNoCrlfPairIsBoundedToItsHeaders(port, caPem, delivery) {
  var marker  = "barelf-only-3f80ab21";
  var message = identifyingHeaders(marker).join("\n") + "\n\n" +
    "A short body.\n" +
    BODY_ONLY_LINE + "\r\n";

  var accepted = await sendToBoth(port, caPem, message, "mx-barelf-only");
  count("a message carrying no CRLF blank line at all is accepted for the recipient that resolves",
    /^250 /m.test(accepted), visible(accepted));

  var reports = delivery.reports();
  count("and it too produces one report", reports.length === 5,
    JSON.stringify(reports.map(function (r) { return r.recipient; })));

  var carried = String(reports[4].originalHeaders || "");
  count("the report still names the message it is about",
    carried.indexOf("Message-ID:") !== -1, carried.slice(0, 120));
  count("and still carries none of the body",
    carried.indexOf(BODY_ONLY_LINE) === -1, visible(carried).slice(0, 200));
}

// A long recipient list, none of it deliverable, so the whole message is
// refused. That is the path that writes the audit row naming them, and
// the peer chose how many names it offered.
//
// Every one of them is a mailbox that exists and is full. That is what
// makes the list reach the row: a name this server does not hold is
// answered `550 5.1.1` at RCPT and never becomes part of a message, so
// a run built on addresses nobody holds would measure a row that is
// never written. Full mailboxes are accepted, the message is refused
// whole once none of them can take it, and the row that says so names
// the list the peer chose.
async function aLongRecipientListIsRecordedWithinBounds(port, caPem, audit) {
  var peer = await mxSession(port, caPem, "mx-long-list");
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  for (var i = 0; i < LONG_RECIPIENT_LIST; i += 1) {
    peer.send("RCPT TO:<full" + i + "@" + DOMAIN + ">");
    await peer.read(/^250 /m, "recipient " + i + " accepted at RCPT");
  }
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw([
    "From: " + PEER,
    "To: " + KNOWN,
    "Subject: long-list-3f80ab21",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <long-list-3f80ab21@example.net>",
    "",
    "A short body.",
    "",
  ].join("\r\n") + ".\r\n", "<the message and its terminating dot>");

  var answered = await peer.read(/^\d{3} /m, "message answered");
  count("a message no recipient on it can take is not accepted",
    !/^250 /m.test(answered), visible(answered));
  peer.send("QUIT");
  peer.close();

  var rows = await helpers.waitUntil(function () {
    var found = audit.forAction("blamepost.mail.inbound.refused");
    return found.length > 0 ? found : false;
  }, { timeoutMs: 5000, label: "wire-refusal-report: the refusal audit row is written" });

  var metadata = metadataOf(rows[rows.length - 1]);
  var named    = String(metadata.recipients).split(", ").filter(function (part) {
    return /^full\d+@/.test(part);
  });
  count("the row names at least one of the recipients the peer listed",
    named.length > 0, JSON.stringify(metadata.recipients).slice(0, 120));
  count("and no more of them than the cap allows",
    named.length <= RECIPIENT_CAP, named.length + " named");
  count("while saying how many there were in total",
    metadata.recipientCount === LONG_RECIPIENT_LIST,
    JSON.stringify(metadata.recipientCount));
  count("so the names it left out are still accounted for",
    String(metadata.recipients).indexOf(
      "and " + (LONG_RECIPIENT_LIST - RECIPIENT_CAP) + " more") !== -1,
    String(metadata.recipients).slice(-40));
}

// A relay this server could not sign. The message goes, and the row that
// says it went unsigned is the only notice an operator gets.
async function anUnsignedRelayIsRecordedAsAFailure(port, caPem, audit) {
  var session = await Wire.connect(port, "submission-unsigned");
  await session.read(/^220 /m, "banner");
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted over TLS");
  session.send("AUTH PLAIN " + wire.saslPlain(KNOWN, ALICE_PASSWORD));
  await session.read(/^235 /m, "authenticated");

  session.send("MAIL FROM:<" + KNOWN + ">");
  await session.read(/^250 /m, "MAIL FROM accepted");
  session.send("RCPT TO:<" + KNOWN + ">");
  await session.read(/^250 /m, "RCPT TO accepted");
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  session.sendRaw([
    "From: " + KNOWN,
    "To: " + KNOWN,
    "Subject: unsigned-3f80ab21",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <unsigned-3f80ab21@example.com>",
    "",
    "A short body.",
    "",
  ].join("\r\n") + ".\r\n", "<the message and its terminating dot>");
  var accepted = await session.read(/^\d{3} /m, "message answered");
  count("the message still relays when it could not be signed",
    /^250 /m.test(accepted), visible(accepted));
  session.send("QUIT");
  session.close();

  var rows = await helpers.waitUntil(function () {
    var found = audit.forAction("blamepost.mail.listeners.submission_unsigned");
    return found.length > 0 ? found : false;
  }, { timeoutMs: 5000, label: "wire-refusal-report: the unsigned-relay audit row is written" });

  var row = rows[rows.length - 1];
  count("and the row recording it is a failure, not a success",
    row.outcome === "failure", JSON.stringify(row.outcome));
  count("naming the domain whose mail left unattributable",
    metadataOf(row).domain === DOMAIN, JSON.stringify(metadataOf(row).domain));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("wire-refusal-report");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var handle  = null;
  var running = false;
  var audit   = null;

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

    var mxPort         = await reservePort();
    var submissionPort = await reservePort();
    var delivery       = deliveryRecorder();
    var messages       = messageRecorder();

    audit = auditCapture();

    handle = listeners.create({
      config: {
        hostname:        HOSTNAME,
        dnsAcknowledged: true,
        // Message authentication resolves the sender's published policy
        // at the end of DATA, which is a different subject with its own
        // run. Monitor keeps its verdict off this one's answer.
        inbound:         { mode: "monitor" },
        listeners: {
          mx:          { enabled: true,  port: mxPort,               address: LOOPBACK },
          submission:  { enabled: true,  port: submissionPort,       address: LOOPBACK },
          submissions: { enabled: false, port: await reservePort(),  address: LOOPBACK },
          imap:        { enabled: false, port: await reservePort(),  address: LOOPBACK },
          pop3:        { enabled: false, port: await reservePort(),  address: LOOPBACK },
          managesieve: { enabled: false, port: await reservePort(),  address: LOOPBACK },
        },
      },
      store:      identityAnswering(),
      mailStore:  messages,
      certificate: certs.handle(leaf),
      delivery:   delivery,
      dkim:       failingSigner(),
    });
    await handle.start();
    running = true;

    await aWellFormedMessageIsReportedOnWithinTheCap(mxPort, leaf.ca, delivery);
    await aMessageWithNoSeparatorIsBoundedToo(mxPort, leaf.ca, delivery);
    await aBlockOfOctetsIsBoundedByWhatItCarries(mxPort, leaf.ca, delivery);
    await aBareLfSeparatorIsFoundBeforeALaterCrlfPair(mxPort, leaf.ca, delivery);
    await aBareLfMessageWithNoCrlfPairIsBoundedToItsHeaders(mxPort, leaf.ca, delivery);

    count("every message reached the mailbox that resolves",
      messages.appended().length === 5,
      JSON.stringify(messages.appended()));

    await aLongRecipientListIsRecordedWithinBounds(mxPort, leaf.ca, audit);
    await anUnsignedRelayIsRecordedAsAFailure(submissionPort, leaf.ca, audit);

    await handle.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && handle) {
      try { await handle.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // The audit store is process-wide, so it is handed back whatever
    // happened above.
    if (audit) {
      try { audit.release(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "wire-refusal-report", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
