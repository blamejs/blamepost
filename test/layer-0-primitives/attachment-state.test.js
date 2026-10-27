// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * attachment-state: whether a message carries files, read off its octets.
 *
 * RFC 8621 section 4.1.4 defines `hasAttachment` as true when the message
 * has parts a client should offer as downloadable, and RFC 2183 is what a
 * sender uses to say which parts those are. The reading is one function,
 * because the conversation page lists the parts a person clicks and the
 * mark written when a message is filed counts them, and two readings
 * would show a reader a list of files on a message their JMAP client was
 * told carries none.
 *
 * Four primitives are driven here. `blamepost.mail.mailbox.leafParts` is
 * the walk, `blamepost.mail.mailbox.attachmentState` is the answer over
 * it, and `blamepost.mail.mailbox.attachmentMark` and
 * `blamepost.mail.mailbox.isAttachmentKeyword` read the recorded answer
 * back off a message's flags.
 *
 * THREE ANSWERS. `present` and `absent` are the two a message this server
 * opened produces. `unknown` is the third, and it is the one worth
 * driving: a message above the octet read bound and a message whose
 * structure does not parse both have to reach it, because answering
 * either as `absent` hides every file on it from a client that filters.
 *
 * One of those two arms is not reachable from a message this build filed.
 * The message store parses under `MESSAGE_PARSE_CAPS` when it accepts a
 * message, so a message on the volume parses under the same caps when it
 * is read back. The arm answers for a volume restored from a build whose
 * caps differed, which is the only way the two can disagree, and it is
 * driven here on octets built to fail rather than asserted about a stored
 * message that cannot exist.
 *
 * Run standalone: node test/layer-0-primitives/attachment-state.test.js
 */

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var mailbox = require("../../lib/mail/mailbox");

var count = helpers.count;

var ATTACHED = Buffer.from("zebra7741 quarterly totals\n", "utf8");

// The part ceiling every message parse in this server runs under, read
// off the shipped value so a vector built to exceed it still does when
// the number moves.
var MAX_PARTS = mailbox.MESSAGE_PARSE_CAPS.maxParts;

function headerBlock(subject, extra) {
  return "Message-ID: <" + subject + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <reader@example.com>\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" + extra;
}

function message(subject, extra, body) {
  return Buffer.from(headerBlock(subject, extra) + "\r\n" + body, "utf8");
}

// ---------------------------------------------------------------------------
// What counts as a file
// ---------------------------------------------------------------------------

function aMessageThatIsOnlyItsOwnTextCarriesNothing() {
  count("a single text/plain message carries nothing",
    mailbox.attachmentState(message("plain",
      "Content-Type: text/plain; charset=utf-8\r\n", "just words\r\n")) === "absent",
    "text/plain");

  count("a single text/html message carries nothing",
    mailbox.attachmentState(message("html",
      "Content-Type: text/html; charset=utf-8\r\n", "<p>just words</p>\r\n")) === "absent",
    "text/html");

  // The two readings of one body. RFC 2046 section 5.1.4 makes these
  // alternatives of the same content, and the body renderer shows one of
  // them, so neither is a file.
  count("the plain and rich readings of one body are not two files",
    mailbox.attachmentState(message("alternative",
      "Content-Type: multipart/alternative; boundary=\"inner\"\r\n",
      "--inner\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n\r\njust words\r\n" +
      "--inner\r\n" +
      "Content-Type: text/html; charset=utf-8\r\n\r\n<p>just words</p>\r\n" +
      "--inner--\r\n")) === "absent",
    "multipart/alternative");
}

function everyWayASenderSaysThisIsAFile() {
  // RFC 2183 section 2.1: the disposition says so outright.
  count("a part marked attachment is a file",
    mailbox.attachmentState(message("disposed",
      "Content-Type: multipart/mixed; boundary=\"edge\"\r\n",
      "--edge\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n\r\nthe text\r\n" +
      "--edge\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      "Content-Disposition: attachment\r\n\r\nthe file\r\n" +
      "--edge--\r\n")) === "present",
    "disposition");

  // RFC 2183 section 2.3: a name is the sender saying the same thing, and
  // a part named but marked inline is still a part the reader cannot see
  // without being told it is there.
  count("a part the sender named is a file even when it is marked inline",
    mailbox.attachmentState(message("named",
      "Content-Type: multipart/related; boundary=\"rel\"\r\n",
      "--rel\r\n" +
      "Content-Type: text/html; charset=utf-8\r\n\r\n<p>the picture is below</p>\r\n" +
      "--rel\r\n" +
      "Content-Type: image/png\r\n" +
      "Content-Disposition: inline; filename=\"pixel.png\"\r\n" +
      "Content-Transfer-Encoding: base64\r\n\r\n" + ATTACHED.toString("base64") + "\r\n" +
      "--rel--\r\n")) === "present",
    "inline with a name");

  // Neither header, and the reader still cannot see it. A sender who
  // attaches an image and says nothing has still attached it.
  count("a part that is neither text nor named is a file",
    mailbox.attachmentState(message("bare",
      "Content-Type: multipart/mixed; boundary=\"edge\"\r\n",
      "--edge\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n\r\nthe text\r\n" +
      "--edge\r\n" +
      "Content-Type: application/zip\r\n" +
      "Content-Transfer-Encoding: base64\r\n\r\n" + ATTACHED.toString("base64") + "\r\n" +
      "--edge--\r\n")) === "present",
    "unnamed non-text part");

  // RFC 2046 section 5.2.1: a forwarded message is one part rather than a
  // body to descend into.
  count("a forwarded message is one file",
    mailbox.attachmentState(message("forward",
      "Content-Type: multipart/mixed; boundary=\"cover\"\r\n",
      "--cover\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n\r\nsee below\r\n" +
      "--cover\r\n" +
      "Content-Type: message/rfc822\r\n" +
      "Content-Disposition: attachment\r\n" +
      "\r\nSubject: the one being forwarded\r\n\r\nits body\r\n" +
      "--cover--\r\n")) === "present",
    "message/rfc822");
}

// ---------------------------------------------------------------------------
// The third answer
// ---------------------------------------------------------------------------

function aMessageThisServerCannotOpenIsNotAMessageWithNoFiles() {
  var filler = new Array(1024).join("x");
  var lines = [];
  var wanted = mailbox.MAX_SOURCE_READ_BYTES + b.constants.BYTES.kib(64);
  while (lines.length * (filler.length + 2) < wanted) lines.push(filler);
  var oversize = message("wide",
    "Content-Type: text/plain; charset=utf-8\r\n", lines.join("\r\n") + "\r\n");
  count("the oversize vector really is above the read bound",
    oversize.length > mailbox.MAX_SOURCE_READ_BYTES, String(oversize.length));
  count("a message above the read bound is unknown rather than bare",
    mailbox.attachmentState(oversize) === "unknown", "oversize");

  // More parts than the structure caps admit. A message this shape is
  // refused by the message store's own append, so nothing this build
  // files reaches the arm below; octets built to fail are what drives it.
  var parts = [];
  for (var i = 0; i < MAX_PARTS + 8; i += 1) {
    parts.push("--wide\r\nContent-Type: text/plain; charset=utf-8\r\n\r\npart " + i + "\r\n");
  }
  var tooMany = message("crowded",
    "Content-Type: multipart/mixed; boundary=\"wide\"\r\n",
    parts.join("") + "--wide--\r\n");
  var refused = false;
  try { mailbox.leafParts(tooMany); }
  catch (_e) { refused = true; }
  count("the crowded vector really is one the shared parse refuses",
    refused, String(tooMany.length) + " bytes");
  count("a message whose structure does not parse is unknown rather than bare",
    mailbox.attachmentState(tooMany) === "unknown", "unparsed");

  count("octets that are not a message at all are unknown",
    mailbox.attachmentState(Buffer.alloc(0)) === "unknown", "empty");
  count("a value that is not octets is unknown",
    mailbox.attachmentState(null) === "unknown", "null");
}

// ---------------------------------------------------------------------------
// The walk the surfaces share
// ---------------------------------------------------------------------------

function theWalkNumbersAndNamesEveryLeaf() {
  var nested = message("nested",
    "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
    "--outer\r\n" +
    "Content-Type: multipart/alternative; boundary=\"inner\"\r\n" +
    "\r\n--inner\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n\r\nthe plain reading\r\n" +
    "--inner\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n\r\n<p>the rich reading</p>\r\n" +
    "--inner--\r\n" +
    "--outer\r\n" +
    "Content-Type: application/pdf\r\n" +
    "Content-Disposition: attachment; filename=\"totals.pdf\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n\r\n" + ATTACHED.toString("base64") + "\r\n" +
    "--outer--\r\n");

  var leaves = mailbox.leafParts(nested);
  count("the walk reaches every leaf of a nested message",
    leaves.length === 3, JSON.stringify(leaves.map(function (l) { return l.number; })));
  // RFC 9051 section 6.4.5 numbers these 1.1, 1.2 and 2. A flat index over
  // the leaves would number them 1, 2 and 3, and disagree about the file.
  count("the numbering is the one an IMAP client already uses",
    leaves.map(function (l) { return l.number; }).join(",") === "1.1,1.2,2",
    JSON.stringify(leaves.map(function (l) { return l.number; })));
  count("only the part the sender marked is a file",
    leaves.filter(function (l) { return l.isFile; }).length === 1,
    JSON.stringify(leaves.map(function (l) { return l.isFile; })));
  count("and the walk carries the name the sender gave it",
    leaves[2].name === "totals.pdf", JSON.stringify(leaves[2].name));
}

// ---------------------------------------------------------------------------
// Reading the mark back
// ---------------------------------------------------------------------------

function theMarkReadsBackAsTheAnswerItRecorded() {
  count("the present keyword reads back as present",
    mailbox.attachmentMark(["\\Seen", mailbox.ATTACHMENT_KEYWORDS.present]) === "present",
    mailbox.ATTACHMENT_KEYWORDS.present);
  count("the absent keyword reads back as absent",
    mailbox.attachmentMark([mailbox.ATTACHMENT_KEYWORDS.absent]) === "absent",
    mailbox.ATTACHMENT_KEYWORDS.absent);
  count("a message holding neither reads back as unknown",
    mailbox.attachmentMark(["\\Seen", "$Junk"]) === "unknown", "neither");
  count("flags this server never wrote read back as unknown",
    mailbox.attachmentMark(null) === "unknown", "null");

  // RFC 9051 section 2.3.2 makes flag names case-insensitive, so a client
  // naming one in lower case is naming the same mark. A comparison that
  // missed that would let a client write the mark under another spelling
  // and hold two answers at once.
  count("the mark is read without case",
    mailbox.attachmentMark(["$hasattachment"]) === "present", "lower case");
  count("and the keyword is recognized without case",
    mailbox.isAttachmentKeyword("$HASNOATTACHMENT") === true, "upper case");
  count("an ordinary keyword is not one of the marks",
    mailbox.isAttachmentKeyword("$Junk") === false, "$Junk");
}

async function run() {
  aMessageThatIsOnlyItsOwnTextCarriesNothing();
  everyWayASenderSaysThisIsAFile();
  aMessageThisServerCannotOpenIsNotAMessageWithNoFiles();
  theWalkNumbersAndNamesEveryLeaf();
  theMarkReadsBackAsTheAnswerItRecorded();
  return helpers.getChecks();
}

module.exports = { name: "attachment-state", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
