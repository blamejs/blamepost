// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The IMAP SEARCH key grammar, read directly.
 *
 * `blamepost.mail.listeners.compileSearch` is pure: an argument string
 * in, a predicate over message rows out, or a refusal carrying the IMAP
 * condition it is answered with. So it is asserted here rather than
 * through a listener, and the wire behavior on top of it is pinned in
 * `test/layer-2-integration/imap-search.test.js`.
 *
 * The distinction this file exists for is the one a wire test cannot
 * make cleanly, because both spellings arrive as a refusal: RFC 9051
 * section 7.1 separates BAD from NO, and clients act on the two
 * differently. A command this server could not parse is BAD and tells
 * the client to fix its own dialog. A command it parsed and will not
 * run is NO and tells the client the server will not answer that
 * question. Reporting a key this server cannot answer as a syntax error
 * sends a client looking for a typo it did not make.
 *
 * The second property pinned here is that a refusal ends the WHOLE
 * expression. An expression has no partial evaluation: answering
 * `OR SUBJECT round CC bravo` from the half this server can run reports
 * the messages matching a query the client never sent, under a code
 * that says the query ran.
 *
 * Run standalone: node test/layer-0-primitives/imap-search-grammar.test.js
 */

var helpers   = require("../helpers");
var listeners = require("../../lib/mail/listeners");

var count = helpers.count;

var compileSearch = listeners.compileSearch;

// The mailbox every predicate below is evaluated against. The rows are
// the shape `blamepost.mail.mailbox.searchScan` returns, written out
// here so a grammar assertion depends on nothing but the grammar.
var MAILBOX = [
  {
    seq: 1, uid: 11, objectid: "obj_a",
    flags: ["\\Seen"], internalDate: Date.UTC(2020, 1, 1, 12, 0, 0), sizeBytes: 400,
    subject: "Roundtrip probe", from: "Sender <sender@example.net>",
    to: "Alice <alice@example.com>",
    messageId: "<first@example.net>", inReplyTo: "", references: "",
  },
  {
    seq: 2, uid: 12, objectid: "obj_b",
    flags: ["Urgent"], internalDate: Date.UTC(2021, 5, 15, 8, 30, 0), sizeBytes: 900,
    subject: "Second note", from: "Alpha <alpha@example.org>",
    to: "Bravo <bravo@example.org>",
    messageId: "<second@example.org>", inReplyTo: "<first@example.net>",
    references: "<first@example.net>",
  },
  {
    seq: 3, uid: 20, objectid: "obj_c",
    flags: [], internalDate: Date.UTC(2022, 6, 20, 23, 59, 59), sizeBytes: 1500,
    subject: "Rückmeldung über Größe", from: "Dritte <dritte@example.org>",
    to: "Alice <alice@example.com>",
    messageId: "<third@example.org>", inReplyTo: "", references: "",
  },
];

var CTX = { highestSeq: 3, highestUid: 20 };

function matches(expression) {
  var predicate = compileSearch(expression, null);
  var hits = [];
  for (var i = 0; i < MAILBOX.length; i += 1) {
    if (predicate(MAILBOX[i], CTX)) hits.push(MAILBOX[i].seq);
  }
  return hits;
}

function sameSet(got, want) {
  if (got.length !== want.length) return false;
  for (var i = 0; i < got.length; i += 1) {
    if (got[i] !== want[i]) return false;
  }
  return true;
}

function answers(expression, wanted) {
  var got = null;
  var thrown = null;
  try { got = matches(expression); } catch (e) { thrown = e; }
  count("`" + expression + "` matches " + JSON.stringify(wanted),
    thrown === null && sameSet(got, wanted),
    thrown === null ? JSON.stringify(got) : "refused: " + thrown.message);
}

// A refusal, under the condition RFC 9051 section 7.1 gives it.
function refuses(expression, condition, why) {
  var thrown = null;
  try { compileSearch(expression, null); } catch (e) { thrown = e; }
  count("`" + expression + "` refuses with " + condition + ", because " + why,
    thrown !== null && thrown.searchCondition === condition &&
    thrown.code === "listeners/imap-search-refused",
    thrown === null ? "nothing was thrown" :
      (thrown.searchCondition || "?") + " " + thrown.message);
}

// ---- what the grammar answers ----------------------------------------------

function testEveryAnswerableKey() {
  answers("ALL", [1, 2, 3]);

  // RFC 9051 section 6.4.4 makes every string key a substring match,
  // and matches without regard to case. The first of these is the case
  // an index of whole tokens cannot produce.
  answers("SUBJECT \"round\"", [1]);
  answers("SUBJECT \"ROUNDTRIP\"", [1]);
  answers("SUBJECT \"größe\"", [3]);
  answers("SUBJECT Roundtrip", [1]);
  answers("SUBJECT \"\"", [1, 2, 3]);

  // From and To are separate fields, which is what tells a sender from
  // a recipient.
  answers("FROM \"alpha\"", [2]);
  answers("TO \"bravo\"", [2]);
  answers("FROM \"bravo\"", []);
  answers("TO \"alpha\"", []);

  answers("SEEN", [1]);
  answers("UNSEEN", [2, 3]);
  answers("ANSWERED", []);
  answers("UNANSWERED", [1, 2, 3]);
  answers("DELETED", []);
  answers("UNDELETED", [1, 2, 3]);
  answers("DRAFT", []);
  answers("UNDRAFT", [1, 2, 3]);
  answers("FLAGGED", []);
  answers("UNFLAGGED", [1, 2, 3]);
  answers("KEYWORD Urgent", [2]);
  answers("KEYWORD urgent", [2]);
  answers("UNKEYWORD Urgent", [1, 3]);

  // IMAP4rev2 removed the \Recent flag and this server never sets one,
  // so these three have an exact answer rather than an approximated
  // one. Answering them is strictly better than refusing: no message is
  // ever left out of one, and a client old enough to send one is told
  // the truth rather than that the command failed.
  answers("RECENT", []);
  answers("NEW", []);
  answers("OLD", [1, 2, 3]);

  answers("LARGER 899", [2, 3]);
  answers("SMALLER 901", [1, 2]);
  answers("LARGER 1500", []);
  answers("SMALLER 400", []);

  answers("BEFORE 15-Jun-2021", [1]);
  answers("ON 15-Jun-2021", [2]);
  answers("SINCE 15-Jun-2021", [2, 3]);
  answers("ON 01-Feb-2020", [1]);

  answers("2:3", [2, 3]);
  answers("1,3", [1, 3]);
  answers("3:*", [3]);
  answers("UID 12:20", [2, 3]);
  answers("UID 11", [1]);

  answers("HEADER SUBJECT \"round\"", [1]);
  answers("HEADER FROM \"alpha\"", [2]);
  answers("HEADER TO \"bravo\"", [2]);
  answers("HEADER MESSAGE-ID \"second@example.org\"", [2]);
  answers("HEADER IN-REPLY-TO \"first@example.net\"", [2]);
  // RFC 9051 section 6.4.4: an empty string asks whether the header is
  // there at all, whatever it says.
  answers("HEADER IN-REPLY-TO \"\"", [2]);

  answers("OR SEEN KEYWORD Urgent", [1, 2]);
  answers("NOT SEEN", [2, 3]);
  answers("UNSEEN SUBJECT \"second\"", [2]);
  answers("(SEEN)", [1]);
  answers("OR (SEEN) (KEYWORD Urgent)", [1, 2]);
  answers("NOT (OR SEEN KEYWORD Urgent)", [3]);
  answers("NOT NOT SEEN", [1]);

  answers("CHARSET UTF-8 SUBJECT \"round\"", [1]);
  answers("CHARSET \"US-ASCII\" SUBJECT \"round\"", [1]);
  answers("charset utf-8 subject \"round\"", [1]);
}

// A term the client sent as a literal is the last string in the
// expression, which is where the command line put it.
function testLiteralTerm() {
  var predicate = compileSearch("SUBJECT", "Größe");
  count("a term carried as a literal is read as the string its key takes",
    predicate(MAILBOX[2], CTX) && !predicate(MAILBOX[0], CTX));
}

// ---- what the grammar refuses ----------------------------------------------

function testKeysThisServerCannotAnswer() {
  // Parsed and understood, and not answerable from what the message
  // store keeps. NO rather than BAD: the client's syntax is fine.
  refuses("CC \"bravo\"", "NO", "the Cc header is not kept");
  refuses("BCC \"bravo\"", "NO", "the Bcc header is not kept");
  refuses("SENTBEFORE 15-Jun-2021", "NO", "the Date header is read and not parsed");
  refuses("SENTON 15-Jun-2021", "NO", "the Date header is read and not parsed");
  refuses("SENTSINCE 15-Jun-2021", "NO", "the Date header is read and not parsed");
  // BODY is the one a search over an extracted-text store is most
  // tempted to answer, and the one that answers wrongly. The store keeps
  // the first text part and the first HTML part, so a conforming
  // message carrying a second text part, or text inside a forwarded
  // message part, matches in a place nothing reads. RFC 9051 section
  // 6.4.4 lets a server skip parts that are neither text nor a message
  // and does not let it skip those, so the miss is a wrong answer rather
  // than a permitted narrowing.
  refuses("BODY \"4d91e07b\"", "NO", "only one text part of a body is kept");
  refuses("BODY \"\"", "NO", "an empty term does not make an unreadable body readable");
  refuses("TEXT \"4d91e07b\"", "NO", "it would miss the headers that are not kept");
  refuses("HEADER X-Mailer \"anything\"", "NO", "that field is not kept");
  refuses("HEADER DATE \"2021\"", "NO", "that field is not kept");
  // References is kept as its message ids re-joined with commas rather
  // than as the text of the header, so a substring of the header as
  // sent is not a substring of what is kept.
  refuses("HEADER REFERENCES \"first@example.net\"", "NO",
    "it is stored re-joined rather than as sent");
  refuses("RETURN (COUNT) ALL", "NO", "the extended result form is not served");
  refuses("CHARSET ISO-8859-1 ALL", "NO", "a term is read as UTF-8");
}

// The whole of the refusal rule. Each of these carries a key this
// server answers beside one it does not, and none of them may report
// the answerable half.
function testARefusalEndsTheWholeExpression() {
  refuses("OR SUBJECT \"round\" CC \"bravo\"", "NO",
    "an OR has no half a client asked for on its own");
  refuses("CC \"bravo\" OR SUBJECT \"round\" SEEN", "NO",
    "the unanswerable key is read wherever it sits");
  refuses("SUBJECT \"round\" CC \"bravo\"", "NO",
    "two keys side by side are one question");
  refuses("OR SUBJECT \"round\" BODY \"round\"", "NO",
    "the widest single search a client sends is still one question");
  refuses("NOT CC \"bravo\"", "NO", "a negation of an unanswerable key is unanswerable");
  refuses("(SUBJECT \"round\" TEXT \"4d91e07b\")", "NO",
    "a group holding an unanswerable key is unanswerable");
  refuses("NOT (OR SEEN TEXT \"x\")", "NO", "nesting does not make it answerable");

  // And the refusal happens before anything is evaluated, so there is
  // no result set anywhere for a caller to mistake for an answer.
  var thrown = null;
  try { compileSearch("OR SUBJECT \"round\" CC \"bravo\"", null); }
  catch (e) { thrown = e; }
  count("a refused expression compiles to no predicate at all, so nothing can be " +
    "evaluated from its answerable half",
    thrown !== null && typeof thrown !== "function",
    thrown === null ? "a predicate was returned" : thrown.message);
}

function testMalformedExpressions() {
  refuses("", "BAD", "an expression needs at least one key");
  refuses("NOSUCHKEY \"x\"", "BAD", "that is not a search key");
  refuses("LARGER notanumber", "BAD", "a size is a number of octets");
  refuses("LARGER", "BAD", "a size key needs a size");
  refuses("SMALLER -1", "BAD", "a size is not negative");
  refuses("BEFORE 32-Wxy-2020", "BAD", "that is not a date");
  refuses("BEFORE 31-Feb-2020", "BAD", "that date does not exist");
  refuses("ON 2020-02-01", "BAD", "a date is written as 1-Feb-2020");
  refuses("(SEEN", "BAD", "a group that never closes");
  refuses("SEEN)", "BAD", "a group that was never opened");
  refuses("()", "BAD", "an empty group");
  refuses("NOT", "BAD", "a negation with nothing to negate");
  refuses("OR SEEN", "BAD", "an OR with one half missing");
  refuses("SUBJECT", "BAD", "a string key with no string");
  refuses("KEYWORD \\Seen", "BAD", "a system flag is not a keyword");
  refuses("KEYWORD \"has a space\"", "BAD", "a keyword is one atom");
  refuses("UID 0", "BAD", "a UID set starts at one");
  refuses("UID banana", "BAD", "that is not a UID set");
  refuses("0", "BAD", "a sequence number starts at one");
  refuses("\"round\"", "BAD", "a quoted string is not a search key");
  refuses("CHARSET", "BAD", "CHARSET needs a charset");

  // The nesting bound. A pathological expression costs a refusal rather
  // than a stack.
  refuses(new Array(40).join("(") + "SEEN" + new Array(40).join(")"), "BAD",
    "it nests deeper than this server reads");
}

// ---- the run ---------------------------------------------------------------

async function run() {
  count("blamepost.mail.listeners.compileSearch is exported",
    typeof compileSearch === "function");
  testEveryAnswerableKey();
  testLiteralTerm();
  testKeysThisServerCannotAnswer();
  testARefusalEndsTheWholeExpression();
  testMalformedExpressions();
  return helpers.getChecks();
}

module.exports = {
  name: "imap-search-grammar",
  run:  run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
