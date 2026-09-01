// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a delivery report is allowed to quote back.
 *
 * `blamepost.mail.mailbox.reportedHeaderBlock` is the one reader every
 * report path in this server asks. RFC 3462 section 3 puts the original
 * headers in the last part of a report so the sender can tell which of
 * their messages it is about, and three paths owe that quote: a
 * recipient the inbound listener cannot deliver to, an outbound entry
 * whose retry budget ran out, and a message an operator cancelled.
 *
 * They ask one reader because the two decisions inside it are decisions
 * about what a STRANGER may put into a report this server addresses to a
 * third party and signs its own name to. A report goes to whoever an
 * envelope named, and on a forged envelope that is somebody who never
 * sent anything.
 *
 *   - Where the block ends. The peer chose the framing, and a scan that
 *     finds the wrong empty line copies body text of the peer's choosing
 *     into the quote.
 *   - How much of it goes. The peer chose the length and the charset,
 *     and a bound measured before a decode is not a bound on what
 *     leaves.
 *
 * A second copy of either would be a second answer, and the copy is the
 * one that goes stale. So the reader is asserted here directly, once,
 * rather than only through whichever consumer happened to have a test.
 * `test/layer-2-integration/wire-refusal-report` drives the same rules
 * through a real listener and a real peer; this file is what says they
 * hold whoever is asking.
 *
 * Pure: bytes in, text out. No sockets, no disk.
 *
 * Run standalone: node test/layer-0-primitives/reported-header-block.test.js
 */

var helpers = require("../helpers");
var mailbox = require("../../lib/mail/mailbox");

var check = helpers.check;
var count = helpers.count;

var reportedHeaderBlock = mailbox.reportedHeaderBlock;

// The whole of what a quote may carry. It matches
// `MAX_REPORTED_HEADER_BYTES` in lib/mail/mailbox.js, and every
// assertion below is written as "no more than", so a smaller cap needs
// no edit here.
var CAP_BYTES = 4096;

// Enough header lines to run well past the cap, so a bound that stopped
// applying shows up as a quote several times its size rather than as a
// value that happens to fit.
function paddedHeaders(marker) {
  var lines = [
    "From: alice@example.com",
    "To: bob@example.net",
    "Message-ID: <" + marker + "@example.com>",
  ];
  for (var i = 0; i < 400; i += 1) {
    lines.push("X-Padding-" + i + ": " + new Array(64).join("p"));
  }
  return lines.join("\r\n");
}

function bytesIn(text) {
  return Buffer.byteLength(String(text), "utf8");
}

// ---------------------------------------------------------------------------
// Where the block ends
// ---------------------------------------------------------------------------

function anOrdinaryMessageQuotesItsHeadersAndNoneOfItsBody() {
  var raw = Buffer.from(
    "From: alice@example.com\r\n" +
    "To: bob@example.net\r\n" +
    "Subject: hello\r\n" +
    "\r\n" +
    "X-Not-A-Header: this is body text the peer wrote\r\n", "utf8");

  var quoted = reportedHeaderBlock(raw);
  check("the quote carries the headers the message actually has",
    /^From: alice@example\.com$/m.test(quoted) &&
    /^To: bob@example\.net$/m.test(quoted) &&
    /^Subject: hello$/m.test(quoted));
  check("and none of the body, however a line in it is spelled",
    quoted.indexOf("X-Not-A-Header") === -1);
  check("the empty line that ends the block is left out, because RFC 3462 section 3 asks " +
    "for the headers and the last header line's own terminator ends them",
    quoted.slice(-4) !== "\r\n\r\n" && /Subject: hello\r\n$/.test(quoted));
}

// The separator a peer actually wrote, against the one a scan goes
// looking for. This message ends its headers with a bare LF, which is
// out of spec and arrives every day, and then quotes a forwarded message
// in its body, which puts a CRLFCRLF further down. The first empty line
// is the bare one, and everything between it and the later one is body.
function theFirstEmptyLineEndsTheBlockWhicheverTerminatorWroteIt() {
  var raw = Buffer.from(
    "From: alice@example.com\n" +
    "To: bob@example.net\n" +
    "\n" +
    "Forwarded message follows.\r\n" +
    "X-Smuggled: a line the peer put in its own body\r\n" +
    "\r\n" +
    "the forwarded body\r\n", "utf8");

  var quoted = reportedHeaderBlock(raw);
  check("a block ended by a bare LF ends there rather than at the CRLF pair further down",
    quoted.indexOf("X-Smuggled") === -1 && quoted.indexOf("Forwarded message") === -1);
  check("and the headers before it are all carried",
    /^From: alice@example\.com$/m.test(quoted) && /^To: bob@example\.net$/m.test(quoted));
}

// A message that never sent the separator. This branch was always
// bounded; the case exists so it and the ordinary one cannot drift
// apart, which is how the bound came to apply to only one of them.
function aMessageWithNoSeparatorIsBoundedToo() {
  var raw = Buffer.from(paddedHeaders("unseparated-3f80ab21"), "utf8");
  count("the block the peer sent is far larger than the cap",
    raw.length > CAP_BYTES * 4, raw.length + " bytes sent");

  var quoted = reportedHeaderBlock(raw);
  count("a message with no separator at all is still bounded by the cap",
    bytesIn(quoted) <= CAP_BYTES, bytesIn(quoted) + " bytes carried");
  count("and still carries enough to name the message it is about",
    quoted.indexOf("Message-ID:") !== -1, quoted.slice(0, 120));
}

// ---------------------------------------------------------------------------
// How much of it goes
// ---------------------------------------------------------------------------

function aBlockLargerThanTheCapIsCutToIt() {
  var block = paddedHeaders("padded-3f80ab21");
  var raw = Buffer.from(block + "\r\n\r\nA short body.\r\n", "utf8");
  count("the header block the peer sent is far larger than the cap",
    Buffer.byteLength(block, "utf8") > CAP_BYTES * 4,
    Buffer.byteLength(block, "utf8") + " bytes sent");

  var quoted = reportedHeaderBlock(raw);
  count("the quote carries no more than the cap allows",
    bytesIn(quoted) <= CAP_BYTES, bytesIn(quoted) + " bytes carried");
  count("while still carrying enough to identify the message, because a quote that names " +
    "nothing is one the sender cannot act on",
    quoted.indexOf("Message-ID:") !== -1, quoted.slice(0, 120));
}

// The cap is taken twice and both are load-bearing. A cap applied to the
// octets and then handed to a UTF-8 decode is not a cap on what leaves:
// every octet the decode cannot accept becomes a three byte replacement
// character, so a peer sending nothing but those turns the bound into
// three times itself.
function aBlockOfUndecodableOctetsIsBoundedByWhatItCarries() {
  var head = Buffer.from("Message-ID: <octets-3f80ab21@example.com>\r\nX-Octets: ", "ascii");
  var raw = Buffer.concat([head, Buffer.alloc(CAP_BYTES * 2, 0x80)]);
  count("the block the peer sent is larger than the cap", raw.length > CAP_BYTES,
    raw.length + " octets sent");

  var quoted = reportedHeaderBlock(raw);
  count("the quote is bounded by what it CARRIES rather than by what was read, so a decode " +
    "that grows every octet cannot grow the report past the cap",
    bytesIn(quoted) <= CAP_BYTES, bytesIn(quoted) + " bytes carried");
  count("and it still names the message it is about",
    quoted.indexOf("Message-ID:") !== -1, quoted.slice(0, 60));
}

// The budget is spent one code point at a time, which is what keeps the
// cut off the middle of a character. A quote ending in half of one is a
// quote a reader cannot render and an encoder cannot write.
function theCutNeverLandsInsideACharacter() {
  var head = "X-Wide: ";
  var raw = Buffer.from(head + new Array(3000).join("€"), "utf8");
  count("the block is larger than the cap and every character in it is three octets wide",
    raw.length > CAP_BYTES, raw.length + " octets sent");

  var quoted = reportedHeaderBlock(raw);
  count("the quote is inside the cap", bytesIn(quoted) <= CAP_BYTES,
    bytesIn(quoted) + " bytes carried");
  check("and carries no replacement character, so the cut fell on a character boundary " +
    "rather than through one",
    quoted.indexOf("�") === -1);
  count("with the header name that preceded them intact",
    quoted.indexOf(head) === 0, quoted.slice(0, 20));
}

// ---------------------------------------------------------------------------
// What a caller may hand it
// ---------------------------------------------------------------------------

function aMessageHandedOverAsTextIsReadTheSameWay() {
  var quoted = reportedHeaderBlock(
    "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n");
  check("a caller holding text rather than octets gets the same block",
    /^From: alice@example\.com$/m.test(quoted) && quoted.indexOf("body") === -1);

  check("and an empty message answers with an empty quote rather than raising, because a " +
    "report with nothing to quote is still a report its sender needs",
    reportedHeaderBlock(Buffer.alloc(0)) === "");
}

// ---------------------------------------------------------------------------

async function run() {
  await helpers.withTestTimeout("reported-header-block: an ordinary message quotes its headers",
    function () { return anOrdinaryMessageQuotesItsHeadersAndNoneOfItsBody(); });
  await helpers.withTestTimeout("reported-header-block: the first empty line ends the block",
    function () { return theFirstEmptyLineEndsTheBlockWhicheverTerminatorWroteIt(); });
  await helpers.withTestTimeout("reported-header-block: a message with no separator is bounded",
    function () { return aMessageWithNoSeparatorIsBoundedToo(); });
  await helpers.withTestTimeout("reported-header-block: a block larger than the cap is cut to it",
    function () { return aBlockLargerThanTheCapIsCutToIt(); });
  await helpers.withTestTimeout("reported-header-block: undecodable octets are bounded by what they carry",
    function () { return aBlockOfUndecodableOctetsIsBoundedByWhatItCarries(); });
  await helpers.withTestTimeout("reported-header-block: the cut never lands inside a character",
    function () { return theCutNeverLandsInsideACharacter(); });
  await helpers.withTestTimeout("reported-header-block: a message handed over as text",
    function () { return aMessageHandedOverAsTextIsReadTheSameWay(); });
  return helpers.getChecks();
}

module.exports = {
  name:      "reported-header-block",
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
