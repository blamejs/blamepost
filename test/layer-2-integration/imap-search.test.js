// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * IMAP SEARCH, driven over a real session against a bound listener.
 *
 * Its sibling `imap-search-refusal.test.js` pins the one thing SEARCH
 * must never do: report a result set it did not compute. This file
 * pins the other half, which is that the keys this server claims to
 * answer are actually answered, and answered with the semantics RFC
 * 9051 section 6.4.4 gives them rather than with whatever the message
 * store happens to make cheap.
 *
 * Three of the vectors below are the ones that decide whether the
 * implementation is right or merely present:
 *
 *   - `SUBJECT "round"` against a subject reading "Roundtrip". The
 *     RFC makes every string key a SUBSTRING match. The store's
 *     full-text index holds keyed hashes of whole tokens, so it
 *     answers this one with nothing while the correct answer is a
 *     message. A search wired to that index passes every other case
 *     here and fails this one.
 *   - `FROM` against an address that appears only in a To header. The
 *     same index folds both into one address column, so it cannot
 *     tell a sender from a recipient and reports a match that is not
 *     one.
 *   - A subject in a writing system that needs more than one octet
 *     per character, matched case-insensitively. This tree stores
 *     message octets exactly, and every earlier defect in this area
 *     came from a decode that looked harmless.
 *
 * The refusals are pinned as hard as the answers. A key this server
 * cannot answer exactly refuses the WHOLE expression, because
 * `OR SUBJECT x CC y` has no partial evaluation: dropping the half it
 * cannot run and answering from the half it can is a wrong answer
 * wearing a success code.
 *
 * It needs no external service. The ports are ephemeral on the
 * loopback interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/imap-search.test.js
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

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The three messages Alice's INBOX is loaded with. Each one carries a
// marker nothing else in the mailbox carries, so a match is the search
// working rather than ordinary words colliding.
//
// The first subject holds a word with a shorter word inside it, which
// is the case a whole-token index answers wrongly and a substring match
// answers correctly. The second puts a distinctive label in To and a
// different one in From, so a column that folds the two reports a
// sender that is a recipient. The third is written in a script that
// needs two octets per character.
var M1_SUBJECT = "Roundtrip probe 8fa21c";
var M1_BODY    = "The body that was appended, marker 4d91e07b.";
var M2_SUBJECT = "Second note about nothing";
var M3_SUBJECT = "Rückmeldung über Größe";
var M3_BODY    = "Ein Körper mit Umlauten.";

// Bob's one message. Alice must never see this subject in any result,
// on any key, however the expression is spelled.
var BOB_SUBJECT = "zebra7741 belongs to bob and to nobody else";

// The internal dates the three messages are appended with, so BEFORE,
// ON and SINCE have a fixed answer rather than one that depends on the
// day the suite runs.
var M1_DATE = "01-Feb-2020 12:00:00 +0000";
var M2_DATE = "15-Jun-2021 08:30:00 +0000";
var M3_DATE = "20-Jul-2022 23:59:59 +0000";
var PIVOT_DATE = "15-Jun-2021";

// A keyword flag, set on the third message only.
var KEYWORD = "Urgent";

// RFC 9051 section 7.3.4 writes a result set as `* SEARCH` followed by
// the message numbers. The bare form is the server saying it found
// nothing, and the absence of the line entirely is the server not
// having answered at all.
var SEARCH_LINE_RE = /^\* SEARCH([^\r\n]*)\r?$/m;

// The message numbers on the untagged SEARCH line, `[]` when the line
// is there and carries none, and `null` when there is no such line.
// The three are different outcomes and the assertions below tell them
// apart: `[]` from a refusal is the failure the sibling file is about.
function resultNumbers(reply) {
  var found = SEARCH_LINE_RE.exec(reply);
  if (!found) return null;
  var body = found[1].trim();
  if (body.length === 0) return [];
  return body.split(/[ \t]+/).map(function (n) { return parseInt(n, 10); });
}

function sameSet(got, want) {
  if (!Array.isArray(got) || got.length !== want.length) return false;
  var a = got.slice().sort(function (x, y) { return x - y; });
  var e = want.slice().sort(function (x, y) { return x - y; });
  for (var i = 0; i < a.length; i += 1) {
    if (a[i] !== e[i]) return false;
  }
  return true;
}

// One SEARCH round trip. Returns the tagged verdict, the numbers the
// untagged line carried, and the whole reply for a failure to quote.
async function runSearch(session, expression) {
  var tag = session.tag();
  session.send(tag + " " + expression);
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    expression + " answered");
  return {
    reply:    reply,
    ok:       new RegExp("^" + tag + " OK", "m").test(reply),
    refused:  new RegExp("^" + tag + " (NO|BAD)", "m").test(reply),
    bad:      new RegExp("^" + tag + " BAD", "m").test(reply),
    numbers:  resultNumbers(reply),
  };
}

// A key this server answers: the tagged reply is OK and the numbers on
// the untagged line are exactly the ones the mailbox holds for it.
async function expectMatch(session, expression, wanted, what) {
  var outcome = await runSearch(session, expression);
  count("SEARCH " + what + " answers with " + JSON.stringify(wanted) + " (" + expression + ")",
    outcome.ok && sameSet(outcome.numbers, wanted), visible(outcome.reply));
  return outcome;
}

// A key this server cannot answer exactly: the tagged reply refuses,
// the refusal names the verb, and NO untagged SEARCH line is written.
// The last of those is the whole point. A refusal that also emits an
// empty result set has told the client both things at once, and every
// client believes the result set.
async function expectRefusal(session, expression, what) {
  var outcome = await runSearch(session, expression);
  count("SEARCH " + what + " refuses rather than answering (" + expression + ")",
    outcome.refused, visible(outcome.reply));
  count("the refusal of " + what + " names the verb it refused",
    outcome.refused && /SEARCH/i.test(outcome.reply), visible(outcome.reply));
  count("the refusal of " + what + " writes no result set at all",
    outcome.numbers === null, visible(outcome.reply));
  return outcome;
}

function messageText(fields, body) {
  return fields.concat(["", body, ""]).join("\r\n");
}

async function append(session, mailbox, internalDate, message, note) {
  var tag = session.tag();
  await session.sendLiteral(
    tag + " APPEND " + mailbox + " \"" + internalDate + "\"", message, note);
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    note + " appended");
  count(note + " is appended, so the mailbox has something to find",
    new RegExp("^" + tag + " OK", "m").test(reply), visible(reply));
  return reply;
}

async function selectInbox(session, who) {
  var tag = session.tag();
  session.send(tag + " SELECT INBOX");
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "SELECT answered");
  count(who + " selects INBOX", new RegExp("^" + tag + " OK", "m").test(reply), visible(reply));
  return reply;
}

// The UID and the octet count the listener reports for every message in
// the selected mailbox, read over the same wire. The size bounds below
// are derived from these rather than computed from the fixture text, so
// LARGER and SMALLER are measured against the number this server itself
// reports for the message rather than against a second count of it.
async function fetchSizes(session, expected, what) {
  var tag = session.tag();
  session.send(tag + " FETCH 1:* (UID RFC822.SIZE)");
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "FETCH answered");
  var rows = [];
  var line = /^\* (\d+) FETCH \(([^\r\n]*)\)\r?$/gm;
  var found;
  while ((found = line.exec(reply)) !== null) {
    var uid  = /UID (\d+)/.exec(found[2]);
    var size = /RFC822\.SIZE (\d+)/.exec(found[2]);
    if (!uid || !size) continue;
    rows.push({
      seq:  parseInt(found[1], 10),
      uid:  parseInt(uid[1], 10),
      size: parseInt(size[1], 10),
    });
  }
  count("FETCH reports a UID and an octet count for " + what,
    rows.length === expected, visible(reply));
  return rows;
}

async function storeFlags(session, seqSet, change, what) {
  var tag = session.tag();
  session.send(tag + " STORE " + seqSet + " " + change);
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), what + " stored");
  count(what, new RegExp("^" + tag + " OK", "m").test(reply), visible(reply));
  return reply;
}

// ---- the run ---------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-search-keys");
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
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
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

    // Given back before the directory under it goes, whichever way this
    // run ends. A database handle still open while its files are removed
    // is a locked file on Windows and a teardown rejection on Linux, and
    // either one lands on top of the verdict this run had already
    // reached.
    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "imap search test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, listeners: sections, inbound: { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var session = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME,
      address: alice.address, password: ALICE_PASSWORD,
      label: "imap-search-alice",
    });

    // ---- the mailbox under test -------------------------------------------
    //
    // Put there over the wire the client actually speaks. The listener
    // ships without LITERAL+ under its strict profile, so each literal
    // is the synchronising form RFC 9051 section 4.3 defines.

    await append(session, "INBOX", M1_DATE, messageText([
      "From: sender@example.net",
      "To: " + alice.address,
      "Subject: " + M1_SUBJECT,
      "Message-ID: <search-8fa21c@example.net>",
    ], M1_BODY), "the substring message");

    await append(session, "INBOX", M2_DATE, messageText([
      "From: alpha@example.org",
      "To: bravo@example.org",
      "Subject: " + M2_SUBJECT,
      "Message-ID: <second@example.org>",
      "In-Reply-To: <search-8fa21c@example.net>",
    ], "A shorter body."), "the sender and recipient message");

    // The charset is declared because RFC 2045 section 5.2 makes an
    // undeclared body US-ASCII, and a message carrying these octets
    // without saying so is a message the store reads as the mangling
    // that produces. This is the shape a conforming client sends, and
    // the subject beside it is the RFC 6532 spelling, carried as UTF-8
    // in the header itself.
    await append(session, "INBOX", M3_DATE, messageText([
      "From: dritte@example.org",
      "To: " + alice.address,
      "Subject: " + M3_SUBJECT,
      "Message-ID: <third@example.org>",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
    ], M3_BODY), "the non-ASCII message");

    // SEARCH is a Selected-state command (RFC 9051 section 6.4.4), and
    // this session has not selected yet, so the refusal is about the
    // dialog rather than about the key.
    var beforeSelect = await runSearch(session, "SEARCH ALL");
    count("SEARCH outside Selected state refuses and writes no result set",
      beforeSelect.refused && beforeSelect.numbers === null, visible(beforeSelect.reply));

    await selectInbox(session, "alice");
    var rows = await fetchSizes(session, 3, "all three messages");
    var sizes = rows.map(function (r) { return r.size; }).sort(function (x, y) { return x - y; });
    var smallest = sizes[0];
    var largest  = sizes[sizes.length - 1];
    count("the three messages are not all the same size, so a size bound separates them",
      smallest < largest, "smallest " + smallest + ", largest " + largest);
    var largestSeq  = rows.filter(function (r) { return r.size === largest;  })
      .map(function (r) { return r.seq; });
    var smallestSeq = rows.filter(function (r) { return r.size === smallest; })
      .map(function (r) { return r.seq; });

    await storeFlags(session, "2", "+FLAGS (\\Seen)", "the second message is marked read");
    await storeFlags(session, "3", "+FLAGS (" + KEYWORD + ")",
      "the third message carries a keyword");

    // ---- the keys this server answers -------------------------------------

    await expectMatch(session, "SEARCH ALL", [1, 2, 3], "ALL");

    // The vector a whole-token index cannot answer. "round" is a prefix
    // inside "Roundtrip", and RFC 9051 section 6.4.4 makes every string
    // key a substring match.
    await expectMatch(session, "SEARCH SUBJECT \"round\"", [1],
      "a subject substring a whole-token index would miss");
    await expectMatch(session, "SEARCH SUBJECT \"ROUNDTRIP\"", [1],
      "a subject matched without regard to case");
    await expectMatch(session, "SEARCH SUBJECT \"probe 8fa21c\"", [1],
      "a subject substring spanning a space");

    // The vector a shared address column cannot answer. "bravo" is a
    // recipient of the second message and the sender of nothing.
    await expectMatch(session, "SEARCH TO \"bravo\"", [2], "a recipient");
    await expectMatch(session, "SEARCH FROM \"alpha\"", [2], "a sender");
    var fromIsNotTo = await runSearch(session, "SEARCH FROM \"bravo\"");
    count("SEARCH FROM does not match an address that appears only in To " +
      "(SEARCH FROM \"bravo\")",
      fromIsNotTo.ok && Array.isArray(fromIsNotTo.numbers) &&
      fromIsNotTo.numbers.indexOf(2) === -1, visible(fromIsNotTo.reply));
    var toIsNotFrom = await runSearch(session, "SEARCH TO \"alpha\"");
    count("SEARCH TO does not match an address that appears only in From " +
      "(SEARCH TO \"alpha\")",
      toIsNotFrom.ok && Array.isArray(toIsNotFrom.numbers) &&
      toIsNotFrom.numbers.indexOf(2) === -1, visible(toIsNotFrom.reply));

    // A subject that needs two octets per character, matched with a
    // term written in lower case.
    await expectMatch(session, "SEARCH SUBJECT \"größe\"", [3],
      "a non-ASCII subject matched without regard to case");
    await expectMatch(session, "SEARCH SUBJECT \"über\"", [3],
      "a non-ASCII subject substring");

    await expectMatch(session, "SEARCH SEEN", [2], "SEEN");
    await expectMatch(session, "SEARCH UNSEEN", [1, 3], "UNSEEN");
    await expectMatch(session, "SEARCH ANSWERED", [], "ANSWERED, which nothing carries");
    await expectMatch(session, "SEARCH UNANSWERED", [1, 2, 3], "UNANSWERED");
    await expectMatch(session, "SEARCH UNFLAGGED", [1, 2, 3], "UNFLAGGED");
    await expectMatch(session, "SEARCH UNDELETED", [1, 2, 3], "UNDELETED");
    await expectMatch(session, "SEARCH UNDRAFT", [1, 2, 3], "UNDRAFT");
    await expectMatch(session, "SEARCH KEYWORD " + KEYWORD, [3], "KEYWORD");
    await expectMatch(session, "SEARCH UNKEYWORD " + KEYWORD, [1, 2], "UNKEYWORD");

    // IMAP4rev2 removed the \Recent flag and this server never sets it,
    // so all three of these have an exact answer rather than a guessed
    // one: nothing is recent, nothing is new, and everything is old.
    await expectMatch(session, "SEARCH RECENT", [], "RECENT, which nothing carries");
    await expectMatch(session, "SEARCH NEW", [], "NEW, which nothing carries");
    await expectMatch(session, "SEARCH OLD", [1, 2, 3], "OLD, which everything carries");

    await expectMatch(session, "SEARCH LARGER " + (largest - 1), largestSeq, "LARGER");
    await expectMatch(session, "SEARCH SMALLER " + (smallest + 1), smallestSeq, "SMALLER");
    await expectMatch(session, "SEARCH LARGER " + largest, [],
      "LARGER at the largest message's own size, which is not larger than itself");

    await expectMatch(session, "SEARCH BEFORE " + PIVOT_DATE, [1], "BEFORE");
    await expectMatch(session, "SEARCH ON " + PIVOT_DATE, [2], "ON");
    await expectMatch(session, "SEARCH SINCE " + PIVOT_DATE, [2, 3], "SINCE");

    await expectMatch(session, "SEARCH 2:3", [2, 3], "a sequence set");
    await expectMatch(session, "SEARCH 1,3", [1, 3], "a discontinuous sequence set");
    await expectMatch(session, "SEARCH 3:*", [3], "a sequence set ending at the highest number");
    await expectMatch(session, "SEARCH UID " + rows[1].uid + ":" + rows[2].uid, [2, 3],
      "a UID set");

    await expectMatch(session, "SEARCH HEADER SUBJECT \"round\"", [1], "HEADER Subject");
    await expectMatch(session, "SEARCH HEADER FROM \"alpha\"", [2], "HEADER From");
    await expectMatch(session, "SEARCH HEADER TO \"bravo\"", [2], "HEADER To");
    await expectMatch(session, "SEARCH HEADER MESSAGE-ID \"second@example.org\"", [2],
      "HEADER Message-ID");
    await expectMatch(session, "SEARCH HEADER IN-REPLY-TO \"8fa21c\"", [2],
      "HEADER In-Reply-To");

    await expectMatch(session, "SEARCH OR SUBJECT \"Roundtrip\" SUBJECT \"Second\"", [1, 2], "OR");
    await expectMatch(session, "SEARCH NOT SUBJECT \"Roundtrip\"", [2, 3], "NOT");
    await expectMatch(session, "SEARCH UNSEEN SUBJECT \"round\"", [1], "an implicit AND");
    await expectMatch(session, "SEARCH (SEEN)", [2], "a parenthesised key");
    await expectMatch(session, "SEARCH OR (SEEN) (KEYWORD " + KEYWORD + ")", [2, 3],
      "OR over two parenthesised keys");
    await expectMatch(session, "SEARCH NOT (OR SEEN KEYWORD " + KEYWORD + ")", [1],
      "NOT over a parenthesised OR");

    await expectMatch(session, "SEARCH CHARSET UTF-8 SUBJECT \"größe\"", [3],
      "CHARSET UTF-8");
    await expectMatch(session, "SEARCH CHARSET US-ASCII SUBJECT \"round\"", [1],
      "CHARSET US-ASCII");
    await expectMatch(session, "SEARCH charset utf-8 subject \"round\"", [1],
      "a command written in lower case");

    // An unquoted term is an atom, which RFC 9051 section 9 allows
    // wherever it allows an astring.
    await expectMatch(session, "SEARCH SUBJECT Roundtrip", [1], "an unquoted term");

    // A term carried as a literal, which is the only spelling for a
    // term holding a character the quoted form cannot.
    var literalTag = session.tag();
    await session.sendLiteral(literalTag + " SEARCH SUBJECT",
      "Größe", "<the search term>");
    var literalReply = await session.read(
      new RegExp("^" + literalTag + " (OK|NO|BAD)", "m"), "literal SEARCH answered");
    count("SEARCH answers a term carried as a literal",
      new RegExp("^" + literalTag + " OK", "m").test(literalReply) &&
      sameSet(resultNumbers(literalReply), [3]), visible(literalReply));

    // ---- the keys this server refuses -------------------------------------

    await expectRefusal(session, "SEARCH CC \"bravo\"",
      "CC, whose header this server does not keep");
    await expectRefusal(session, "SEARCH BCC \"bravo\"",
      "BCC, whose header this server does not keep");
    await expectRefusal(session, "SEARCH SENTBEFORE 15-Jun-2021",
      "SENTBEFORE, which needs a Date header nothing parses");
    await expectRefusal(session, "SEARCH SENTON 15-Jun-2021",
      "SENTON, which needs a Date header nothing parses");
    await expectRefusal(session, "SEARCH SENTSINCE 15-Jun-2021",
      "SENTSINCE, which needs a Date header nothing parses");
    // The message loaded above carries this marker in its body, so the
    // correct answer to a BODY search for it is a message. It is
    // refused anyway, and that is the point: the store keeps the first
    // text part and the first HTML part, so a conforming message with a
    // second text part matches in a place nothing reads. A key that is
    // right about this mailbox and wrong about the next one is a key
    // whose answer nobody can rely on, so it refuses for every mailbox.
    await expectRefusal(session, "SEARCH BODY \"4d91e07b\"",
      "BODY, of which this server keeps only the first text part");
    await expectRefusal(session, "SEARCH TEXT \"4d91e07b\"",
      "TEXT, which would miss the headers this server does not keep");
    await expectRefusal(session, "SEARCH HEADER X-Mailer \"anything\"",
      "HEADER for a field outside the stored set");
    await expectRefusal(session, "SEARCH HEADER REFERENCES \"8fa21c\"",
      "HEADER References, which is stored re-joined rather than as sent");
    await expectRefusal(session, "SEARCH HEADER DATE \"2021\"",
      "HEADER Date, which is stored nowhere");

    // The whole point of refusing rather than filtering. Both of these
    // carry a key this server answers beside one it does not, and the
    // answerable half must not be reported on its own: a client reading
    // `OR SUBJECT round CC bravo` as its own question would take the
    // reply as the answer to both halves.
    await expectRefusal(session, "SEARCH OR SUBJECT \"round\" CC \"bravo\"",
      "an OR whose second half cannot be answered");
    await expectRefusal(session, "SEARCH SUBJECT \"round\" CC \"bravo\"",
      "an implicit AND whose second half cannot be answered");
    await expectRefusal(session, "SEARCH NOT CC \"bravo\"",
      "a NOT over a key that cannot be answered");
    await expectRefusal(session, "SEARCH (SUBJECT \"round\" TEXT \"4d91e07b\")",
      "a parenthesised group holding a key that cannot be answered");
    await expectRefusal(session, "SEARCH OR SUBJECT \"round\" BODY \"round\"",
      "the widest single search a client sends, which is still one question");

    await expectRefusal(session, "SEARCH CHARSET ISO-8859-1 SUBJECT \"round\"",
      "a charset this server does not read");
    var badCharset = await runSearch(session, "SEARCH CHARSET ISO-8859-1 ALL");
    count("the charset refusal carries the BADCHARSET code RFC 9051 section 7.1 defines",
      badCharset.refused && /BADCHARSET/.test(badCharset.reply), visible(badCharset.reply));

    // ---- malformed expressions --------------------------------------------

    await expectRefusal(session, "SEARCH", "an expression with no key at all");
    await expectRefusal(session, "SEARCH NOSUCHKEY \"x\"", "a key that is not a key");
    await expectRefusal(session, "SEARCH LARGER notanumber", "a size that is not a number");
    await expectRefusal(session, "SEARCH BEFORE 32-Wxy-2020", "a date that is not a date");
    await expectRefusal(session, "SEARCH (SEEN", "an unbalanced open parenthesis");
    await expectRefusal(session, "SEARCH SEEN)", "an unbalanced close parenthesis");
    await expectRefusal(session, "SEARCH NOT", "a NOT with nothing after it");
    await expectRefusal(session, "SEARCH OR SEEN", "an OR with one half missing");
    await expectRefusal(session, "SEARCH SUBJECT", "a string key with no string");
    await expectRefusal(session, "SEARCH KEYWORD \\Seen",
      "a system flag where RFC 9051 section 9 wants a keyword");
    await expectRefusal(session, "SEARCH UID 0", "a UID set starting below one");
    await expectRefusal(session, "SEARCH RETURN (COUNT) ALL",
      "the ESEARCH return form this listener does not serve");
    await expectRefusal(session,
      "SEARCH " + new Array(40).join("(") + "SEEN" + new Array(40).join(")"),
      "an expression nested past the depth this server reads");

    // ---- one account cannot search another's mail -------------------------

    var bobSession = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME,
      address: bob.address, password: BOB_PASSWORD,
      label: "imap-search-bob",
    });
    await append(bobSession, "INBOX", M1_DATE, messageText([
      "From: someone@example.net",
      "To: " + bob.address,
      "Subject: " + BOB_SUBJECT,
      "Message-ID: <bobs-only@example.net>",
    ], "bob's own body"), "bob's message");
    await selectInbox(bobSession, "bob");

    await expectMatch(bobSession, "SEARCH SUBJECT \"zebra7741\"", [1],
      "bob's own subject, from bob's session");
    await expectMatch(bobSession, "SEARCH ALL", [1],
      "ALL from bob's session, which holds one message");

    var aliceOnBob = await runSearch(session, "SEARCH SUBJECT \"zebra7741\"");
    count("alice searching her own INBOX never reaches bob's message " +
      "(SEARCH SUBJECT \"zebra7741\")",
      aliceOnBob.ok && sameSet(aliceOnBob.numbers, []), visible(aliceOnBob.reply));
    var aliceAll = await runSearch(session, "SEARCH ALL");
    count("alice's ALL still answers with her own three messages and no fourth",
      aliceAll.ok && sameSet(aliceAll.numbers, [1, 2, 3]), visible(aliceAll.reply));

    bobSession.send(bobSession.tag() + " LOGOUT");
    bobSession.close();

    // ---- the UID form answers in unique identifiers ------------------------
    //
    // RFC 9051 section 6.4.9 changes exactly one thing about SEARCH: the
    // numbers on the untagged line are unique identifiers rather than
    // message sequence numbers. The search KEYS keep the meaning section
    // 6.4.4 gives them, so a bare sequence set is still a sequence set and
    // a `UID` key is still uids. Only the answer changes.
    //
    // A client asks for this form precisely because a sequence number does
    // not survive the session that issued it, so it is the clients keeping a
    // durable cache that a wrong answer here misleads, and it misleads them
    // silently, because sequence numbers and uids are both small integers
    // and a result set of the wrong kind looks exactly like a result set of
    // the right one. What follows is a FETCH, a STORE or a COPY aimed at
    // messages the user never chose.
    //
    // The vectors are worthless while a message's sequence number and its
    // uid are the same integer, which is what an untouched mailbox gives:
    // append three messages and both run 1, 2, 3. So one message is removed
    // first, which renumbers the sequence but never the uid, and the guard
    // below refuses to let the rest of the block pass on a mailbox where the
    // two still agree.
    await storeFlags(session, "1", "+FLAGS (\\Deleted)",
      "the first message is flagged for removal, so the uids can be pulled " +
      "off the sequence numbers");
    var expungeTag = session.tag();
    session.send(expungeTag + " EXPUNGE");
    var expungeReply = await session.read(
      new RegExp("^" + expungeTag + " (OK|NO|BAD)", "m"), "EXPUNGE answered");
    count("EXPUNGE removes the flagged message, so what remains is renumbered",
      new RegExp("^" + expungeTag + " OK", "m").test(expungeReply) &&
      /^\* 1 EXPUNGE/m.test(expungeReply), visible(expungeReply));

    var afterRows = await fetchSizes(session, 2, "the two messages that survived");
    var remainingUids = afterRows.map(function (r) { return r.uid; });
    var remainingSeqs = afterRows.map(function (r) { return r.seq; });
    count("the mailbox now holds a message whose uid is not its sequence number, " +
      "so a result set of the wrong kind is distinguishable",
      afterRows.length === 2 && afterRows.some(function (r) { return r.uid !== r.seq; }),
      JSON.stringify(afterRows));

    var uidAll = await runSearch(session, "UID SEARCH ALL");
    count("UID SEARCH is answered rather than refused",
      uidAll.ok && uidAll.numbers !== null, visible(uidAll.reply));
    count("UID SEARCH ALL answers with the uids " + JSON.stringify(remainingUids) +
      " and not the sequence numbers " + JSON.stringify(remainingSeqs),
      uidAll.ok && sameSet(uidAll.numbers, remainingUids), visible(uidAll.reply));

    // The subtle half. The key is a SEQUENCE set, because section 6.4.9
    // rewrites the answer and not the grammar; the answer is the matching
    // message's uid. A handler that swapped the key's meaning as well would
    // pass the previous vector and fail this one.
    var uidBySeq = await runSearch(session, "UID SEARCH " + afterRows[0].seq);
    count("UID SEARCH over a sequence-set key reads the key as sequence numbers " +
      "and answers with the uid",
      uidBySeq.ok && sameSet(uidBySeq.numbers, [afterRows[0].uid]), visible(uidBySeq.reply));

    var uidByUid = await runSearch(session, "UID SEARCH UID " + afterRows[1].uid);
    count("UID SEARCH over a UID key reads the key as uids and answers with the uid",
      uidByUid.ok && sameSet(uidByUid.numbers, [afterRows[1].uid]), visible(uidByUid.reply));

    var uidBySubject = await runSearch(session, "UID SEARCH SUBJECT \"Second\"");
    var secondRow = afterRows.filter(function (r) { return r.uid === rows[1].uid; })[0];
    count("UID SEARCH over an ordinary key answers with that message's uid",
      uidBySubject.ok && secondRow !== undefined &&
      sameSet(uidBySubject.numbers, [secondRow.uid]), visible(uidBySubject.reply));

    // A key the plain form refuses is refused on the UID form too, and it
    // refuses without writing a result set. One handler serves both, so a
    // client cannot reach an answer through the UID spelling that the
    // sequence spelling declines to give.
    await expectRefusal(session, "UID SEARCH CC \"bravo\"",
      "CC on the UID form, whose header this server does not keep");
    await expectRefusal(session, "UID SEARCH NOSUCHKEY \"x\"",
      "a key that is not a key, on the UID form");

    session.send(session.tag() + " LOGOUT");
    session.close();

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

module.exports = { name: "imap-search", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
