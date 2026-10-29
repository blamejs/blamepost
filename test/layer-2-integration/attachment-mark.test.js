// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether a message carries files, as the three surfaces that answer the
 * question report it, driven over real sockets against the shipped
 * listeners.
 *
 * RFC 8621 section 4.1.4 defines `hasAttachment` as true when the message
 * has parts a client should offer as downloadable. A client filters and
 * renders on it, so a server that answers it the same way for every
 * message tells every client that no message on the volume carries
 * anything, including the messages whose own conversation page lists
 * their files.
 *
 * The fact is recorded when the message is filed rather than derived when
 * it is read. `Email/get` takes a client-chosen set of identifiers, so a
 * derivation per identifier lets one authenticated request order a blob
 * read and a parse per message named. The mark is an IMAP keyword, which
 * is what puts the same answer in front of an IMAP client, and the keyword
 * is written inside the one call every message reaching a mailbox makes.
 *
 * What is driven:
 *
 *   - `Email/get` over HTTP for a message with a file, a message with
 *     none, a message whose only file is marked inline, and a message
 *     above the octet read bound.
 *   - The folder listing and the search results, which are one projection
 *     and must not disagree.
 *   - `Email/set`, which may not write the mark: a client that could set
 *     it could make `hasAttachment` say whatever it liked, and the whole
 *     keyword-replacement form must not take it off either.
 *   - IMAP: the keyword an ordinary client sees in FETCH FLAGS, a message
 *     filed by IMAP APPEND, and a STORE that tries to change the mark.
 *
 * THREE ANSWERS, NOT TWO. A message this server did not open is not a
 * message with no files. It holds neither keyword, the listing says the
 * files are unknown rather than showing nothing, and `hasAttachment`
 * answers true, which RFC 8621 section 4.1.4 allows a server to decide by
 * its own reading and which is the answer that does not hide a file.
 *
 * It needs no external service. Every port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/attachment-mark.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers = require("../helpers");
var browser = require("../helpers/browser");
var wire    = require("../helpers/wire");

var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var READER          = "alice@" + DOMAIN;
var READER_PASSWORD = "a long enough account password for one test run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The mark the listing carries for a message that has files, and the one
// it carries for a message this server did not open. Two classes rather
// than one, because the whole point is that the second is not the absence
// of the first.
var FILES_MARK_RE   = /<span class="mark mark-files"[^>]*>/;
var UNKNOWN_MARK_RE = /<span class="mark mark-files-unknown"[^>]*>/;

// A word only the subject of one fixture carries, so a row can be found
// on a page that lists several.
function rowOf(html, marker) {
  var rows = String(html).split("<li class=\"msg");
  for (var i = 1; i < rows.length; i += 1) {
    if (rows[i].indexOf(marker) !== -1) return rows[i];
  }
  return "";
}

function describe(answer) {
  return answer.status + " " + String(answer.body || "").replace(/\s+/g, " ").slice(0, 240);
}

// ---------------------------------------------------------------------------
// The fixture messages
// ---------------------------------------------------------------------------

var ATTACHED = Buffer.from("zebra7741 quarterly totals\n", "utf8");

function headerBlock(id, subject, extra) {
  return "Message-ID: <" + id + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + READER + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" + extra;
}

// One text body and nothing else.
function plainMessage() {
  return Buffer.from(
    headerBlock("plain", "plainmarker9001 an ordinary message",
      "Content-Type: text/plain; charset=utf-8\r\n") +
    "\r\nnothing unusual in this one\r\n", "utf8");
}

// A text body and one file, marked the way RFC 2183 section 2.1 marks one.
function filedMessage() {
  return Buffer.from(
    headerBlock("filed", "filedmarker9002 one with a file on it",
      "Content-Type: multipart/mixed; boundary=\"edge\"\r\n") +
    "\r\n--edge\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthe file is on this one\r\n" +
    "--edge\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"totals.bin\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED.toString("base64") + "\r\n" +
    "--edge--\r\n", "utf8");
}

// An image the sender marked inline. RFC 2183 section 2.2 is what the
// sender used, and this server holds inline images back, so the reader
// cannot see the picture without being told the part is there. A reading
// that counted only `attachment` dispositions would report this message
// as bare.
function inlineMessage() {
  return Buffer.from(
    headerBlock("inline", "inlinemarker9003 one with a picture in it",
      "Content-Type: multipart/related; boundary=\"rel\"\r\n") +
    "\r\n--rel\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n" +
    "\r\n<p>the picture is below</p>\r\n" +
    "--rel\r\n" +
    "Content-Type: image/png\r\n" +
    "Content-Disposition: inline; filename=\"pixel.png\"\r\n" +
    "Content-ID: <pixel@example.net>\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED.toString("base64") + "\r\n" +
    "--rel--\r\n", "utf8");
}

// A message above the octet read bound. Its octets are stored and served,
// and nothing opens them to walk the structure, so what it carries is
// unknown rather than absent.
function oversizeMessage() {
  var filler = new Array(1024).join("x");
  var lines = [];
  var wanted = mailbox.MAX_SOURCE_READ_BYTES + b.constants.BYTES.kib(64);
  while (lines.length * (filler.length + 2) < wanted) lines.push(filler);
  return Buffer.from(
    headerBlock("oversize", "widemarker9004 one too large to open",
      "Content-Type: multipart/mixed; boundary=\"wide\"\r\n") +
    "\r\n--wide\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthe wide one\r\n" +
    "--wide\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"wide.bin\"\r\n" +
    "\r\n" + lines.join("\r\n") + "\r\n" +
    "--wide--\r\n", "utf8");
}

// The message IMAP APPEND files, so the wire path is measured rather than
// assumed to reach the same code the fixtures above do.
function appendedMessage() {
  return headerBlock("appended", "appendmarker9005 filed over the wire",
    "Content-Type: multipart/mixed; boundary=\"line\"\r\n") +
    "\r\n--line\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthis one arrived over IMAP\r\n" +
    "--line\r\n" +
    "Content-Type: application/pdf\r\n" +
    "Content-Disposition: attachment; filename=\"note.pdf\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED.toString("base64") + "\r\n" +
    "--line--\r\n";
}

// ---------------------------------------------------------------------------
// IMAP
// ---------------------------------------------------------------------------

async function ask(session, command, what) {
  var tag = session.tag();
  session.send(tag + " " + command);
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what || command);
  return { text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
}

// ---------------------------------------------------------------------------
// What a JMAP client is told
// ---------------------------------------------------------------------------

async function emailsOf(reader, accountId, ids) {
  var response = await reader.jmap([
    ["Email/get", { accountId: accountId, ids: ids }, "c0"],
  ]);
  var answer = browser.answer(response, 0);
  var listed = answer && answer[1] && Array.isArray(answer[1].list) ? answer[1].list : [];
  var byId = Object.create(null);
  for (var i = 0; i < listed.length; i += 1) byId[listed[i].id] = listed[i];
  return { byId: byId, response: response };
}

async function testEmailGetAnswersWhatEachMessageCarries(reader, accountId, ids) {
  var got = await emailsOf(reader, accountId,
    [ids.plain, ids.filed, ids.inline, ids.oversize]);
  var filed = got.byId[ids.filed];
  var plain = got.byId[ids.plain];
  var inline = got.byId[ids.inline];
  var wide = got.byId[ids.oversize];

  count("Email/get answers for every message the request named",
    filed !== undefined && plain !== undefined && inline !== undefined && wide !== undefined,
    describe(got.response));
  if (filed === undefined || plain === undefined) return;

  count("a message carrying a file is reported as carrying one",
    filed.hasAttachment === true, JSON.stringify(filed.hasAttachment));
  count("a message carrying only its own text is reported as carrying nothing",
    plain.hasAttachment === false, JSON.stringify(plain.hasAttachment));
  count("a picture the sender marked inline still counts as a file",
    inline.hasAttachment === true, JSON.stringify(inline.hasAttachment));
  // The one answer that must not be `false`. Reporting a message this
  // server never opened as bare hides every file on it, and the message
  // is large precisely because it is carrying something.
  count("a message this server did not open is not reported as bare",
    wide.hasAttachment === true, JSON.stringify(wide.hasAttachment));
}

// The mark is an IMAP keyword, and JMAP has its own property for it.
// Serving it in both places gives a client two answers to one question
// and a keyword map it cannot write back unchanged.
async function testTheKeywordIsNotServedAsAJmapKeyword(reader, accountId, ids) {
  var got = await emailsOf(reader, accountId, [ids.filed, ids.plain, ids.oversize]);
  var names = [];
  var keys = [ids.filed, ids.plain, ids.oversize];
  for (var i = 0; i < keys.length; i += 1) {
    var email = got.byId[keys[i]];
    if (email === undefined || !email.keywords) continue;
    var held = Object.keys(email.keywords);
    for (var k = 0; k < held.length; k += 1) {
      if (/^\$has(no)?attachment$/i.test(held[k])) names.push(held[k]);
    }
  }
  count("the keyword map a JMAP client reads carries neither derived keyword",
    names.length === 0, JSON.stringify(names));
}

async function testEmailSetCannotWriteTheMark(reader, accountId, ids) {
  var refused = await reader.jmap([
    ["Email/set", {
      accountId: accountId,
      update: (function () {
        var update = {};
        update[ids.plain] = { "keywords/$hasattachment": true };
        return update;
      }()),
    }, "c0"],
  ]);
  var answer = browser.answer(refused, 0);
  var body = answer && answer[1] ? answer[1] : {};
  count("Email/set refuses a client writing the mark this server derives",
    body.notUpdated !== undefined &&
    Object.prototype.hasOwnProperty.call(body.notUpdated, ids.plain),
    JSON.stringify(body).slice(0, 240));

  var after = await emailsOf(reader, accountId, [ids.plain]);
  count("and the message it named still reports carrying nothing",
    after.byId[ids.plain] !== undefined && after.byId[ids.plain].hasAttachment === false,
    JSON.stringify(after.byId[ids.plain] && after.byId[ids.plain].hasAttachment));
}

// The whole-keyword-set form replaces what a message holds. A mark this
// server derives is not one of the client's keywords, so a replacement
// naming other keywords must leave it where it is. Taking it off would
// make `hasAttachment` go false on a message that has not changed.
async function testAWholeKeywordSetLeavesTheMarkAlone(reader, accountId, ids) {
  var applied = await reader.jmap([
    ["Email/set", {
      accountId: accountId,
      update: (function () {
        var update = {};
        update[ids.filed] = { keywords: { $seen: true } };
        return update;
      }()),
    }, "c0"],
  ]);
  var answer = browser.answer(applied, 0);
  var body = answer && answer[1] ? answer[1] : {};
  count("Email/set accepts a whole keyword set on a message carrying a file",
    body.updated !== undefined &&
    Object.prototype.hasOwnProperty.call(body.updated, ids.filed),
    JSON.stringify(body).slice(0, 240));

  var after = await emailsOf(reader, accountId, [ids.filed]);
  var email = after.byId[ids.filed];
  count("the replacement took the keywords it named and left the mark",
    email !== undefined && email.hasAttachment === true &&
    email.keywords !== undefined && email.keywords.$seen === true,
    JSON.stringify(email && email.keywords));

  // `hasAttachment` on its own cannot see this regression. A message the
  // replacement stripped holds neither mark, which answers true for the
  // same reason a message this server never opened does, so the boolean
  // reads the same before and after. The listing is where the three
  // answers are told apart, and it is what has to be read to know the
  // mark is still there.
  var page = await reader.get("/mail?folder=INBOX");
  var row = rowOf(page.body, "filedmarker9002");
  count("and the listing still says the message carries files rather than not knowing",
    FILES_MARK_RE.test(row) && !UNKNOWN_MARK_RE.test(row),
    row.replace(/\s+/g, " ").slice(0, 300));
}

// ---------------------------------------------------------------------------
// What a reader sees
// ---------------------------------------------------------------------------

async function testTheListingSaysWhichMessagesCarryFiles(reader) {
  var page = await reader.get("/mail?folder=INBOX");
  count("the folder listing renders", page.status === 200, describe(page));

  var filed = rowOf(page.body, "filedmarker9002");
  var plain = rowOf(page.body, "plainmarker9001");
  var wide  = rowOf(page.body, "widemarker9004");
  count("every fixture row is on the listing",
    filed.length > 0 && plain.length > 0 && wide.length > 0,
    filed.length + "/" + plain.length + "/" + wide.length);

  count("the row of a message carrying a file says so",
    FILES_MARK_RE.test(filed), filed.replace(/\s+/g, " ").slice(0, 300));
  count("the row of a message carrying nothing says nothing",
    !FILES_MARK_RE.test(plain) && !UNKNOWN_MARK_RE.test(plain),
    plain.replace(/\s+/g, " ").slice(0, 300));
  count("the row of a message this server did not open says the files are unknown",
    UNKNOWN_MARK_RE.test(wide), wide.replace(/\s+/g, " ").slice(0, 300));
  count("and that row does not claim the message carries files",
    !FILES_MARK_RE.test(wide), wide.replace(/\s+/g, " ").slice(0, 300));
}

// The listing and the results are one projection. A mark on one and not
// the other is the shape a second copy of the derivation takes.
async function testTheSearchResultsSayTheSame(reader) {
  var page = await reader.get("/search?q=" + encodeURIComponent("filedmarker9002") +
    "&folder=INBOX");
  count("the search results render", page.status === 200, describe(page));
  var filed = rowOf(page.body, "filedmarker9002");
  count("a result row carries the same mark the listing row does",
    filed.length > 0 && FILES_MARK_RE.test(filed),
    filed.replace(/\s+/g, " ").slice(0, 300));
}

// ---------------------------------------------------------------------------
// What an IMAP client sees
// ---------------------------------------------------------------------------

function flagsIn(text) {
  var found = /FLAGS \(([^)]*)\)/.exec(String(text));
  return found === null ? "" : found[1];
}

async function testImapSeesTheKeywordAndCannotChangeIt(session, seq) {
  await ask(session, "SELECT INBOX");

  var filed = await ask(session, "FETCH " + seq.filed + " (FLAGS)");
  count("an IMAP client reading a message with a file sees the registered keyword",
    flagsIn(filed.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) !== -1,
    visible(filed.text));

  var plain = await ask(session, "FETCH " + seq.plain + " (FLAGS)");
  count("a message with no file carries the keyword that says so",
    flagsIn(plain.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.absent) !== -1,
    visible(plain.text));
  count("and it does not carry both at once",
    flagsIn(plain.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) === -1,
    visible(plain.text));

  var wide = await ask(session, "FETCH " + seq.oversize + " (FLAGS)");
  count("a message this server did not open carries neither keyword",
    flagsIn(wide.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) === -1 &&
    flagsIn(wide.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.absent) === -1,
    visible(wide.text));

  // A client that can set the mark can make every surface that reads it
  // lie, and nothing recomputes it afterwards.
  var written = await ask(session,
    "STORE " + seq.plain + " +FLAGS (" + mailbox.ATTACHMENT_KEYWORDS.present + ")");
  count("STORE refuses a client writing the mark this server derives",
    written.verdict === "NO", visible(written.text));

  var removed = await ask(session,
    "STORE " + seq.filed + " -FLAGS (" + mailbox.ATTACHMENT_KEYWORDS.present + ")");
  count("STORE refuses a client taking the mark off as well",
    removed.verdict === "NO", visible(removed.text));

  var still = await ask(session, "FETCH " + seq.filed + " (FLAGS)");
  count("and the message still carries it",
    flagsIn(still.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) !== -1,
    visible(still.text));

  // Replacing the whole flag set names only the flags a client sets. The
  // derived mark is not one of them, so it survives the replacement, in
  // the answer to the STORE and in what is stored.
  var replacedFiled = await ask(session, "STORE " + seq.filed + " FLAGS (\\Seen)");
  count("a FLAGS replacement on a message with a file keeps its mark in the answer",
    replacedFiled.verdict === "OK" &&
    flagsIn(replacedFiled.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) !== -1,
    visible(replacedFiled.text));
  var replacedPlain = await ask(session, "STORE " + seq.plain + " FLAGS (\\Seen)");
  count("and on a message with no file it keeps that mark",
    replacedPlain.verdict === "OK" &&
    flagsIn(replacedPlain.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.absent) !== -1,
    visible(replacedPlain.text));
  var afterFiled = await ask(session, "FETCH " + seq.filed + " (FLAGS)");
  var afterPlain = await ask(session, "FETCH " + seq.plain + " (FLAGS)");
  count("both marks are still stored after the replacement",
    flagsIn(afterFiled.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) !== -1 &&
    flagsIn(afterPlain.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.absent) !== -1,
    visible(afterFiled.text) + " / " + visible(afterPlain.text));
}

async function testImapAppendFilesTheMessageMarked(session) {
  var tag = session.tag();
  await session.sendLiteral(tag + " APPEND INBOX", appendedMessage(), "<appended>");
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND appended");
  count("a message filed by IMAP APPEND is accepted",
    new RegExp("^" + tag + " OK", "m").test(text), visible(text));

  var found = await ask(session, "SEARCH SUBJECT \"appendmarker9005\"");
  var hit = /^\* SEARCH ([0-9 ]+)/m.exec(found.text);
  var seq = hit === null ? "" : hit[1].trim().split(/\s+/)[0];
  count("the appended message is found by its subject", seq.length > 0, visible(found.text));
  if (seq.length === 0) return;

  var flags = await ask(session, "FETCH " + seq + " (FLAGS)");
  count("a message filed over the wire carries the mark too",
    flagsIn(flags.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) !== -1,
    visible(flags.text));
}

// A client sending the mark itself on an APPEND is claiming a fact this
// server derives. The derivation is what the message ends up carrying,
// so a claim that disagrees with the octets does not survive the filing.
async function testAnAppendedClaimDoesNotSurvive(session) {
  var tag = session.tag();
  await session.sendLiteral(
    tag + " APPEND INBOX (" + mailbox.ATTACHMENT_KEYWORDS.present + ")",
    headerBlock("claimed", "claimmarker9006 a claim about nothing",
      "Content-Type: text/plain; charset=utf-8\r\n") + "\r\nno file on this one\r\n",
    "<claimed>");
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "APPEND claimed");
  count("an APPEND carrying the mark is accepted rather than refused",
    new RegExp("^" + tag + " OK", "m").test(text), visible(text));

  var found = await ask(session, "SEARCH SUBJECT \"claimmarker9006\"");
  var hit = /^\* SEARCH ([0-9 ]+)/m.exec(found.text);
  var seq = hit === null ? "" : hit[1].trim().split(/\s+/)[0];
  if (seq.length === 0) {
    count("the claimed message is found by its subject", false, visible(found.text));
    return;
  }
  var flags = await ask(session, "FETCH " + seq + " (FLAGS)");
  count("the octets decide the mark rather than what the client claimed",
    flagsIn(flags.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.absent) !== -1 &&
    flagsIn(flags.text).indexOf(mailbox.ATTACHMENT_KEYWORDS.present) === -1,
    visible(flags.text));
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

function inboxRows(identity, accountId) {
  var folder = identity.mailbox.accountFolders({ id: accountId })
    .filter(function (f) { return f.name === "INBOX"; })[0];
  return identity.messageStore.queryByModseq(folder.storeName, { sinceModseq: 0 });
}

async function run() {
  var root    = helpers.tempDir("attachment-mark");
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
  var sessions = [];
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

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var reader = await identity.accounts.create({
      address: READER, password: READER_PASSWORD });

    // The order these are appended in is the order the inbox reads back
    // in, which is what turns the names below into identifiers.
    var order = ["plain", "filed", "inline", "oversize"];
    identity.mailbox.appendMessage("INBOX", plainMessage(), { actor: { id: reader.id } });
    identity.mailbox.appendMessage("INBOX", filedMessage(), { actor: { id: reader.id } });
    identity.mailbox.appendMessage("INBOX", inlineMessage(), { actor: { id: reader.id } });
    identity.mailbox.appendMessage("INBOX", oversizeMessage(), { actor: { id: reader.id } });

    var rows = inboxRows(identity, reader.id);
    var ids = {};
    var seq = {};
    for (var i = 0; i < order.length && i < rows.length; i += 1) {
      ids[order[i]] = rows[i].objectid;
      seq[order[i]] = i + 1;
    }
    count("the fixture landed every message this file drives",
      Object.keys(ids).length === order.length, JSON.stringify(Object.keys(ids)));

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };
    var httpPort = await reservePort();

    server = blamepost.create({
      config:       Object.assign({}, cfg, { httpPort: httpPort, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var session = browser.browserAt("http://" + LOOPBACK + ":" + httpPort);
    var landed = await session.signIn(READER, READER_PASSWORD);
    count("the mailbox owner signs in", landed.status === 302, describe(landed));

    await testEmailGetAnswersWhatEachMessageCarries(session, reader.id, ids);
    await testTheKeywordIsNotServedAsAJmapKeyword(session, reader.id, ids);
    await testEmailSetCannotWriteTheMark(session, reader.id, ids);
    await testAWholeKeywordSetLeavesTheMarkAlone(session, reader.id, ids);
    await testTheListingSaysWhichMessagesCarryFiles(session);
    await testTheSearchResultsSayTheSame(session);

    var imap = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME,
      address: READER, password: READER_PASSWORD,
      label: "attachment-mark imap",
    });
    sessions.push(imap);
    await testImapSeesTheKeywordAndCannotChangeIt(imap, seq);
    await testImapAppendFilesTheMessageMarked(imap);
    await testAnAppendedClaimDoesNotSurvive(imap);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    sessions.forEach(function (s) { s.close(); });
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "attachment-mark", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
