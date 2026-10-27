// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Where a message's header block ends, driven with the octets a peer puts
 * in a DATA body.
 *
 * `headerBreak` in `lib/mail/mailbox.js` is the one answer every surface
 * in this server asks for: the submission listener trims a message to its
 * header block before the author binding reads `From` and `Sender`, the
 * reply builder in `lib/mail/compose.js` splits the original there, and
 * `reportedHeaderBlock` quotes the header block into every delivery report
 * this server writes. The octets are the peer's, so the peer decides
 * whether they carry a blank line, which terminator wrote it, and whether
 * a CRLF blank line sits further down in the body.
 *
 * `headerBreak` is held to its documented answer: the first empty line in
 * the octets, written by CRLF or by a bare LF, whichever comes first, with
 * the offset and terminator length pointing at exactly those octets.
 *
 * `reportedHeaderBlock` is held to its two caps: what it returns fits in
 * 4096 UTF-8 bytes, it is whole Unicode, and it is text the header block
 * carries rather than text past the blank line.
 *
 * The header block the submission listener hands to the MIME reader is
 * the octets before that line's terminator followed by CRLF CRLF. The
 * author binding reads `From` and `Sender` off that block, and a receiver
 * reads them off the whole message, so the MIME reader has to find the
 * same header fields in both. A field the two readings disagree about is
 * an author this server measured under one name and signed under another.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js header-block @fuzz/header-block_seed_corpus/crlf.eml
 */

var b       = require("../lib/vendor/blamejs");
var mailbox = require("../lib/mail/mailbox");
var harness = require("./harness");

var holds       = harness.holds;
var neverThrows = harness.neverThrows;

var MIME_REFUSALS = [b.safeMime.SafeMimeError];

var CRLF_BLANK = Buffer.from("\r\n\r\n", "ascii");
var LF_BLANK   = Buffer.from("\n\n", "ascii");

var MAX_REPORTED_HEADER_BYTES = 4096;

var LONE_SURROGATE_RE = /[\ud800-\udbff](?![\udc00-\udfff])|(?:^|[^\ud800-\udbff])[\udc00-\udfff]/;

function _firstBlankLine(data) {
  var crlf = data.indexOf(CRLF_BLANK);
  var lf = data.indexOf(LF_BLANK);
  if (crlf === -1 && lf === -1) return null;
  if (lf === -1 || (crlf !== -1 && crlf < lf)) return { at: crlf, terminator: 2 };
  return { at: lf, terminator: 1 };
}

function _breakHolds(data) {
  var brk = neverThrows("blamepost.mail.mailbox.headerBreak", function () {
    return mailbox.headerBreak(data);
  });
  var expected = _firstBlankLine(data);
  holds("headerBreak finds the first blank line, whichever terminator wrote it",
    JSON.stringify(brk) === JSON.stringify(expected), { found: brk, expected: expected });
  return brk;
}

function _reportedBlockHolds(data, brk) {
  var quoted = neverThrows("blamepost.mail.mailbox.reportedHeaderBlock", function () {
    return mailbox.reportedHeaderBlock(data);
  });
  holds("reportedHeaderBlock returns text", typeof quoted === "string", typeof quoted);
  holds("reportedHeaderBlock fits in " + MAX_REPORTED_HEADER_BYTES + " UTF-8 bytes",
    Buffer.byteLength(quoted, "utf8") <= MAX_REPORTED_HEADER_BYTES, Buffer.byteLength(quoted, "utf8"));
  holds("reportedHeaderBlock is whole Unicode", !LONE_SURROGATE_RE.test(quoted), quoted.length);

  // The header block decoded whole. The quote is cut from a bounded
  // window of it, so its last character may be the replacement a decode
  // leaves for a sequence the window cut in half; everything before that
  // character is text the header block carries.
  var end = brk === null ? data.length : brk.at + brk.terminator;
  var whole = data.subarray(0, end).toString("utf8");
  var points = Array.from(quoted);
  var allButLast = points.slice(0, Math.max(0, points.length - 1)).join("");
  holds("reportedHeaderBlock quotes text from the header block and nothing past it",
    whole.startsWith(quoted) || whole.startsWith(allButLast),
    { quotedBytes: Buffer.byteLength(quoted, "utf8"), headerBlockBytes: end });
}

// The block `lib/mail/listeners.js` builds before the author binding reads
// it: the octets before the blank line's terminator, then CRLF CRLF.
function _listenerBlock(data, brk) {
  var end = brk === null ? data.length : brk.at;
  return Buffer.concat([data.subarray(0, end), CRLF_BLANK]);
}

function _headerFields(bytes) {
  var tree = harness.read(MIME_REFUSALS, function () {
    return b.safeMime.parse(bytes, mailbox.MESSAGE_PARSE_CAPS);
  });
  if (tree === null) return null;
  return (tree.headers && tree.headers.raw) || {};
}

function _readingsAgree(data, brk) {
  var whole = _headerFields(data);
  if (whole === null) return;
  var block = _headerFields(_listenerBlock(data, brk));
  if (block === null) return;
  holds("the header fields read off the listener's header block are the fields read off the " +
    "whole message", JSON.stringify(block) === JSON.stringify(whole),
  { block: block, whole: whole });
}

module.exports.fuzz = function (data) {
  var brk = _breakHolds(data);
  _reportedBlockHolds(data, brk);
  _readingsAgree(data, brk);
};

// The readers above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at each one.
module.exports.targets = function () {
  return [
    { name: "blamepost.mail.mailbox.headerBreak", of: mailbox, call: "headerBreak" },
    { name: "blamepost.mail.mailbox.reportedHeaderBlock", of: mailbox, call: "reportedHeaderBlock" },
    { name: "b.safeMime.parse", of: b.safeMime, call: "parse" },
  ];
};
