// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The blob download endpoint of RFC 8620 section 6.2, driven over a real
 * socket against the shipped listener.
 *
 * A client reads the session document once and shapes its whole session
 * around what it found. That document names a `downloadUrl`, and
 * `Email/get` answers `hasAttachment` off the mark the mail layer wrote
 * when the message was filed. A client holding both is a client that has
 * been told a message carries a file and has been handed the route to
 * fetch it, so the route has to answer the octets rather than a refusal.
 *
 * What is driven:
 *
 *   - The session document's `downloadUrl`, and that it carries the four
 *     RFC 8620 section 6.2 variables a client fills in.
 *   - The whole message, under the `blobId` `Email/get` answers, compared
 *     byte for byte with the octets that were filed.
 *   - One part, under the part-scoped blob id, compared byte for byte
 *     with the octets the sender encoded AND with what the browser route
 *     serves for the same part, so the two surfaces cannot come to
 *     disagree about what a file is.
 *   - Part numbering through a nested multipart, which is where RFC 9051
 *     section 6.4.5 numbering and a flat index over the leaves disagree
 *     about every file on the message.
 *   - The response posture: one media type for every part whatever the
 *     sender claimed and whatever the client asked for, `nosniff`, and a
 *     `Content-Disposition` carrying both RFC 6266 forms, with the RFC
 *     8187 `filename*` for a name that has no ASCII spelling.
 *   - A part claiming `text/html`, fetched with `accept=text/html`, which
 *     is the shape that would render on the origin the session cookie is
 *     scoped to.
 *   - Another account's blob, in both directions, and an accountId the
 *     reader does not hold.
 *   - The refusals: a blob id outside the RFC 8620 section 1.2 grammar, an
 *     identifier nothing holds, a part number nothing holds, the message's
 *     own text, and a message above the octet read bound.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/jmap-blob-download.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var READER_PASSWORD  = "quiet lantern bicycle 4291";
var OTHER_PASSWORD   = "another quiet lantern 7715";

var READER = "alice@" + DOMAIN;
var OTHER  = "bob@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// RFC 8620 section 1.2 gives an Id this grammar, and the blob ids this
// server mints have to sit inside it or a client cannot put one in the
// URL template. The dot RFC 9051 section 6.4.5 numbers parts with is
// outside it, which is why a part-scoped blob id cannot simply carry the
// part number as written.
var JMAP_ID_RE = /^[A-Za-z0-9_-]{1,255}$/;

// U+202E reverses the reading order of everything after it. Built rather
// than written, because a source file carrying the raw code point is
// classified as binary and drops out of every diff.
var RLO = String.fromCharCode(0x202e);

var HOSTILE_NAME   = "quarterly " + RLO + "gpj.exe";
var HOSTILE_SERVED = "quarterly _gpj.exe";

// A name with no ASCII spelling, which is what RFC 8187 exists for. The
// apostrophe is in it deliberately: RFC 8187 section 3.2.1 splits an
// ext-value on that character, so an encoder leaving it raw hands a
// receiver a name that ends at the apostrophe.
var UNICODE_NAME      = "reçu café's.pdf";
var UNICODE_EXT_VALUE = "re%C3%A7u%20caf%C3%A9%27s.pdf";

// Valid UTF-8 with characters above the ASCII range, so a response read
// back as UTF-8 and re-encoded is byte-identical to what went in and a
// transfer that mangled the high bytes is visible.
var ATTACHED_TEXT  = "zebra7741 quarterly totals café ✓\n";
var ATTACHED_BYTES = Buffer.from(ATTACHED_TEXT, "utf8");

var HTML_PART_TEXT  = "<h1>tapir9930 this must never render here</h1>\n";
var HTML_PART_BYTES = Buffer.from(HTML_PART_TEXT, "utf8");

var OTHERS_TEXT  = "hedgehog5512 belongs to the other account\n";
var OTHERS_BYTES = Buffer.from(OTHERS_TEXT, "utf8");

var JMAP_HEADERS = { Accept: "application/json" };

function describe(answer) {
  return answer.status + " " + String(answer.body || "").replace(/\s+/g, " ").slice(0, 220);
}

function header(answer, name) {
  return String(answer.headers[name] === undefined ? "" : answer.headers[name]);
}

// One blob id naming a part, as a client reading the grammar builds it.
// The part number's dots become dashes because RFC 8620 section 1.2 does
// not admit a dot in an Id.
function partBlob(objectId, partNumber) {
  return objectId + "-p" + String(partNumber).split(".").join("-");
}

// The download URL a client fills in from the session document, which is
// the only way this route is reached in the wild.
function downloadUrl(session, accountId, blobId, name, type) {
  return String(session.downloadUrl)
    .split("{accountId}").join(encodeURIComponent(accountId))
    .split("{blobId}").join(encodeURIComponent(blobId))
    .split("{name}").join(encodeURIComponent(name))
    .split("{type}").join(encodeURIComponent(type));
}

// ---------------------------------------------------------------------------
// The fixture messages
// ---------------------------------------------------------------------------

function headerBlock(id, to, subject, extra) {
  return "Message-ID: <" + id + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" + extra;
}

// A text body and one file, which is the ordinary shape. RFC 9051
// section 6.4.5 numbers the text 1 and the file 2.
function filedMessage(id, to) {
  return Buffer.from(
    headerBlock(id, to, "one with a file on it",
      "Content-Type: multipart/mixed; boundary=\"edge\"\r\n") +
    "\r\n--edge\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthe file is on this one\r\n" +
    "--edge\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"" + HOSTILE_NAME + "\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED_BYTES.toString("base64") + "\r\n" +
    "--edge--\r\n", "utf8");
}

// An alternative body, then two files. RFC 9051 section 6.4.5 numbers
// these 1.1, 1.2, 2 and 3; a flat index over the leaves numbers them 1,
// 2, 3 and 4, so the two disagree about every file on this message.
function nestedMessage(id, to) {
  return Buffer.from(
    headerBlock(id, to, "one with a nested body and two files",
      "Content-Type: multipart/mixed; boundary=\"outer\"\r\n") +
    "\r\n--outer\r\n" +
    "Content-Type: multipart/alternative; boundary=\"inner\"\r\n" +
    "\r\n--inner\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthe plain reading of this one\r\n" +
    "--inner\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n" +
    "\r\n<p>the rich reading of this one</p>\r\n" +
    "--inner--\r\n" +
    "--outer\r\n" +
    "Content-Type: application/pdf\r\n" +
    "Content-Disposition: attachment; filename*=UTF-8''" + UNICODE_EXT_VALUE + "\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED_BYTES.toString("base64") + "\r\n" +
    "--outer\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n" +
    "Content-Disposition: attachment; filename=\"page.html\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + HTML_PART_BYTES.toString("base64") + "\r\n" +
    "--outer--\r\n", "utf8");
}

// A message above the octet read bound. Its parts are neither listed nor
// served, on either surface.
function oversizeMessage(id, to) {
  var filler = new Array(1024).join("x");
  var lines = [];
  var wanted = mailbox.MAX_SOURCE_READ_BYTES + b.constants.BYTES.kib(64);
  while (lines.length * (filler.length + 2) < wanted) lines.push(filler);
  return Buffer.from(
    headerBlock(id, to, "one too large to open",
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

function othersMessage(id, to) {
  return Buffer.from(
    headerBlock(id, to, "the other accounts quarterly numbers",
      "Content-Type: multipart/mixed; boundary=\"edge\"\r\n") +
    "\r\n--edge\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nnothing unusual in this one\r\n" +
    "--edge\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"theirs.bin\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + OTHERS_BYTES.toString("base64") + "\r\n" +
    "--edge--\r\n", "utf8");
}

// ---------------------------------------------------------------------------
// What the session document promises
// ---------------------------------------------------------------------------

async function theSessionNamesADownloadRoute(reader) {
  var answer = await reader.get("/jmap/session", JMAP_HEADERS);
  count("the session document answers", answer.status === 200, describe(answer));
  var doc = JSON.parse(answer.body);

  var url = String(doc.downloadUrl || "");
  var variables = ["{accountId}", "{blobId}", "{name}", "{type}"];
  for (var i = 0; i < variables.length; i += 1) {
    count("the downloadUrl template carries the RFC 8620 section 6.2 variable " + variables[i],
      url.indexOf(variables[i]) !== -1, url);
  }
  return doc;
}

// ---------------------------------------------------------------------------
// The octets
// ---------------------------------------------------------------------------

async function theWholeMessageComesBackUnderItsOwnBlobId(reader, session, accountId, ids, filed) {
  var url = downloadUrl(session, accountId, ids.filed, "message.eml", "message/rfc822");
  var got = await reader.get(url, { Accept: "*/*" });
  count("the blobId Email/get answers for a message downloads that message",
    got.status === 200, describe(got));
  count("and it is the octets that were filed, byte for byte",
    Buffer.from(got.body, "utf8").equals(filed), String(got.body).length + " bytes back");
}

async function onePartComesBackAsItsOctets(reader, session, accountId, ids) {
  var blobId = partBlob(ids.filed, "2");
  count("a part-scoped blob id sits inside the RFC 8620 section 1.2 Id grammar",
    JMAP_ID_RE.test(blobId), blobId);

  var url = downloadUrl(session, accountId, blobId, "quarterly.exe", "application/octet-stream");
  var got = await reader.get(url, { Accept: "*/*" });
  count("a part-scoped blob id downloads that part", got.status === 200, describe(got));
  count("and it is the octets the sender encoded, decoded once",
    Buffer.from(got.body, "utf8").equals(ATTACHED_BYTES), String(got.body).length + " bytes back");
  return got;
}

// The two surfaces read the same message with the same reader, so a part
// either is a file on both or is a file on neither. Comparing the octets
// rather than the verdict is what catches a second reading that agrees
// about which parts exist and disagrees about their numbering.
async function bothSurfacesServeTheSameOctets(reader, session, accountId, ids) {
  var viaJmap = await reader.get(
    downloadUrl(session, accountId, partBlob(ids.filed, "2"), "f.bin", "application/octet-stream"),
    { Accept: "*/*" });
  var viaBrowser = await reader.get(
    "/mail/" + encodeURIComponent(ids.filed) + "/parts/2?folder=INBOX", { Accept: "*/*" });
  count("the browser route serves the same part", viaBrowser.status === 200, describe(viaBrowser));
  count("the two surfaces answer the same octets for the same part",
    viaJmap.status === 200 && viaBrowser.status === 200 &&
    Buffer.from(viaJmap.body, "utf8").equals(Buffer.from(viaBrowser.body, "utf8")),
    describe(viaJmap) + " against " + describe(viaBrowser));
  count("and they name the same file in Content-Disposition",
    header(viaJmap, "content-disposition") === header(viaBrowser, "content-disposition"),
    header(viaJmap, "content-disposition") + " against " + header(viaBrowser, "content-disposition"));
}

async function partNumberingFollowsTheMessageTree(reader, session, accountId, ids) {
  // RFC 9051 section 6.4.5 numbers the PDF 2 on this message. A flat
  // index over the leaves would number it 3, so asking for 2 and getting
  // the PDF is what says the numbering is the tree's rather than a
  // counter's.
  var pdf = await reader.get(
    downloadUrl(session, accountId, partBlob(ids.nested, "2"), "r.pdf", "application/pdf"),
    { Accept: "*/*" });
  count("part 2 of a nested message is the first file rather than the third leaf",
    pdf.status === 200 && Buffer.from(pdf.body, "utf8").equals(ATTACHED_BYTES), describe(pdf));

  var html = await reader.get(
    downloadUrl(session, accountId, partBlob(ids.nested, "3"), "page.html", "text/html"),
    { Accept: "*/*" });
  count("part 3 of a nested message is the second file",
    html.status === 200 && Buffer.from(html.body, "utf8").equals(HTML_PART_BYTES), describe(html));

  // 1.1 and 1.2 are the alternative body, which is the message's own
  // text rather than a file, so neither is served.
  var texts = ["1.1", "1.2"];
  for (var i = 0; i < texts.length; i += 1) {
    var body = await reader.get(
      downloadUrl(session, accountId, partBlob(ids.nested, texts[i]), "t.txt", "text/plain"),
      { Accept: "*/*" });
    count("part " + texts[i] + " is the message's own text and is not served as a file",
      body.status === 404, describe(body));
  }
}

// ---------------------------------------------------------------------------
// What the response says it is
// ---------------------------------------------------------------------------

function theResponsePostureHolds(got) {
  count("the part is served as octets rather than under the type the sender claimed",
    header(got, "content-type").indexOf("application/octet-stream") === 0,
    header(got, "content-type"));
  count("and the response refuses to be reread as another type",
    header(got, "x-content-type-options") === "nosniff",
    header(got, "x-content-type-options"));

  var disposition = header(got, "content-disposition");
  count("the response disposes the part as an attachment",
    disposition.indexOf("attachment") === 0, disposition);
  count("the RFC 6266 filename carries the name with the override replaced",
    disposition.indexOf("filename=\"" + HOSTILE_SERVED + "\"") !== -1, disposition);
  count("the served name carries no right-to-left override",
    disposition.indexOf(RLO) === -1, JSON.stringify(disposition));
  count("and the name comes from the message rather than from the URL the client wrote",
    disposition.indexOf("quarterly.exe") === -1, disposition);
}

async function aNonAsciiNameCarriesBothForms(reader, session, accountId, ids) {
  var got = await reader.get(
    downloadUrl(session, accountId, partBlob(ids.nested, "2"), "r.pdf", "application/pdf"),
    { Accept: "*/*" });
  var disposition = header(got, "content-disposition");
  count("a name with no ASCII spelling still carries an RFC 6266 filename",
    /filename="[^"]+"/.test(disposition), disposition);
  count("and it carries the name itself in the RFC 8187 filename* form",
    disposition.indexOf("filename*=UTF-8''" + UNICODE_EXT_VALUE) !== -1, disposition);
  count("the apostrophe is percent-encoded, so the ext-value does not end early",
    disposition.indexOf("filename*=UTF-8''") !== -1 &&
    disposition.slice(disposition.indexOf("filename*=UTF-8''") + 17).indexOf("'") === -1,
    disposition);
  count("the RFC 8187 form carries the name the sender wrote",
    decodeURIComponent(UNICODE_EXT_VALUE) === UNICODE_NAME, UNICODE_EXT_VALUE);
}

// A part claiming `text/html`, asked for as `text/html`. RFC 8620 section
// 6.2 lets a client name a type and this server serves one type for every
// part, so the claim and the request are both refused rather than echoed:
// a document served here renders on the origin the session cookie is
// scoped to.
async function aPartClaimingToBeADocumentIsNotOne(reader, session, accountId, ids) {
  var got = await reader.get(
    downloadUrl(session, accountId, partBlob(ids.nested, "3"), "page.html", "text/html"),
    { Accept: "text/html" });
  count("a part claiming to be a document is fetched", got.status === 200, describe(got));
  count("and it does not come back as one, whatever the client asked for",
    header(got, "content-type").indexOf("text/html") === -1,
    header(got, "content-type"));
  count("its octets are unchanged",
    Buffer.from(got.body, "utf8").equals(HTML_PART_BYTES), String(got.body).length + " bytes");
}

// ---------------------------------------------------------------------------
// What is out of reach
// ---------------------------------------------------------------------------

async function anotherAccountsBlobIsUnreachable(reader, other, session, otherSession, scope) {
  // The reader, naming their own accountId and the other account's blob.
  var borrowed = await reader.get(
    downloadUrl(session, scope.readerAccount, scope.othersObjectId, "t.bin",
      "application/octet-stream"), { Accept: "*/*" });
  count("a blob id another account holds is not served under this account's id",
    borrowed.status === 404, describe(borrowed));
  count("and none of the other account's octets reach the reader",
    String(borrowed.body).indexOf("hedgehog5512") === -1, describe(borrowed));

  var borrowedPart = await reader.get(
    downloadUrl(session, scope.readerAccount, partBlob(scope.othersObjectId, "2"), "t.bin",
      "application/octet-stream"), { Accept: "*/*" });
  count("nor is one of its parts", borrowedPart.status === 404, describe(borrowedPart));

  // The reader, naming the OTHER account's id. The accountId is one this
  // actor is not enumerated for, which RFC 8620 section 3.6.1 answers
  // before the blob is looked at.
  var foreign = await reader.get(
    downloadUrl(session, scope.otherAccount, scope.othersObjectId, "t.bin",
      "application/octet-stream"), { Accept: "*/*" });
  count("an accountId this actor does not hold is refused",
    foreign.status === 404, describe(foreign));

  // The reader, naming an accountId they do not hold and a blob they DO.
  // Resolution is bound to the actor, so a route that read the blob and
  // never looked at the accountId would answer this one with the octets,
  // under a scope the actor was never enumerated for. That is the vector
  // the accountId check exists for: every other miss here is already
  // refused by the resolution being actor-bound, so this is the only one
  // that goes quiet if the check is dropped.
  var wrongScope = await reader.get(
    downloadUrl(session, scope.otherAccount, partBlob(scope.readerObjectId, "2"), "t.bin",
      "application/octet-stream"), { Accept: "*/*" });
  count("a blob this account holds is not served under an accountId it does not",
    wrongScope.status === 404, describe(wrongScope));
  count("and its octets are not in the answer",
    String(wrongScope.body).indexOf("zebra7741") === -1, describe(wrongScope));

  // And the other way, so the scoping is not one account being special.
  var mine = await other.get(
    downloadUrl(otherSession, scope.otherAccount, partBlob(scope.readerObjectId, "2"), "t.bin",
      "application/octet-stream"), { Accept: "*/*" });
  count("the other account cannot reach the reader's part either",
    mine.status === 404, describe(mine));
  count("and none of the reader's octets reach it",
    String(mine.body).indexOf("zebra7741") === -1, describe(mine));
}

async function everyMissIsTheSameRefusal(reader, session, accountId, ids) {
  var vectors = [
    { label: "an identifier nothing holds",
      blobId: "obj_00000000000000000000000000000000" },
    { label: "a part number nothing holds",
      blobId: partBlob(ids.filed, "9") },
    { label: "a part number nothing holds, nested",
      blobId: partBlob(ids.filed, "2.7") },
    { label: "the message's own text rather than a file",
      blobId: partBlob(ids.filed, "1") },
    { label: "a part of a message above the octet read bound",
      blobId: partBlob(ids.oversize, "2") },
    { label: "a message above the octet read bound, whole",
      blobId: ids.oversize },
  ];
  var bodies = [];
  for (var i = 0; i < vectors.length; i += 1) {
    var got = await reader.get(
      downloadUrl(session, accountId, vectors[i].blobId, "t.bin", "application/octet-stream"),
      { Accept: "*/*" });
    count("a blob id naming " + vectors[i].label + " is refused",
      got.status === 404, vectors[i].blobId + " -> " + describe(got));
    bodies.push(String(got.body));
  }
  var first = bodies[0];
  var same = bodies.every(function (body) { return body === first; });
  count("every miss answers with one refusal, so a caller cannot tell them apart",
    same, JSON.stringify(bodies.map(function (x) { return x.slice(0, 80); })));
}

// RFC 8620 section 1.2 admits no dot in an Id, so a blob id carrying the
// part number as RFC 9051 writes it is outside the grammar and is refused
// at the point of parse rather than looked up.
async function aBlobIdOutsideTheGrammarIsRefused(reader, session, accountId, ids) {
  var vectors = [
    { label: "a dot", blobId: ids.filed + ".2" },
    { label: "a path segment", blobId: ids.filed + "/2" },
    { label: "a percent escape", blobId: ids.filed + "%2e2" },
  ];
  for (var i = 0; i < vectors.length; i += 1) {
    var url = String(session.downloadUrl)
      .split("{accountId}").join(encodeURIComponent(accountId))
      .split("{blobId}").join(vectors[i].blobId)
      .split("{name}").join("t.bin")
      .split("{type}").join("application%2Foctet-stream");
    var got = await reader.get(url, { Accept: "*/*" });
    count("a blob id carrying " + vectors[i].label + " is refused rather than resolved",
      got.status === 400 || got.status === 404, vectors[i].blobId + " -> " + describe(got));
    count("and it serves no octets",
      String(got.body).indexOf("zebra7741") === -1, describe(got));
  }
}

// The route is behind the account gate, so an unauthenticated caller
// reaches no blob at all.
async function anUnauthenticatedCallerReachesNothing(origin, session, accountId, ids) {
  var stranger = browser.browserAt(origin);
  var got = await stranger.get(
    downloadUrl(session, accountId, partBlob(ids.filed, "2"), "t.bin",
      "application/octet-stream"), { Accept: "*/*" });
  count("a caller with no session reaches no blob",
    got.status !== 200, describe(got));
  count("and no octets are in the answer",
    String(got.body).indexOf("zebra7741") === -1, describe(got));
}

// ---------------------------------------------------------------------------
// The route table
// ---------------------------------------------------------------------------

function testTheRouteIsRegistered(handle) {
  var scratch = new b.router.Router();
  handle.routes(scratch);
  var serving = scratch.inspectRoutes().filter(function (route) {
    return route.method === "GET" && route.pattern.indexOf("/jmap/download/") === 0;
  });
  count("the surface registers one route that serves a blob",
    serving.length === 1,
    scratch.inspectRoutes().map(function (r) { return r.method + " " + r.pattern; })
      .filter(function (p) { return p.indexOf("/jmap/") !== -1; }).join(", "));
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

function wiringFor(cfg, identity) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent: b.mail.agent.create({
      store: identity.messageStore, dispatch: { mode: "local" },
    }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: identity.messageStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: identity.mailbox,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    listeners: function () { return []; },
    address:   LOOPBACK,
    httpPort:  0,
  };
}

function inboxOf(identity, accountId) {
  var folder = b.db.from(mailbox.FOLDERS)
    .where({ account: accountId, wireName: "INBOX" }).first().folder;
  var rows = identity.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: 100 });
  return { storeFolder: folder, rows: rows };
}

function landedIds(identity, accountId, order) {
  var inbox = inboxOf(identity, accountId);
  var out = {};
  for (var i = 0; i < order.length && i < inbox.rows.length; i += 1) {
    out[order[i]] = inbox.rows[i].objectid;
  }
  return out;
}

async function accountIdOf(reader) {
  var answer = await reader.get("/jmap/session", JMAP_HEADERS);
  return Object.keys(JSON.parse(answer.body).accounts)[0];
}

async function run() {
  var root    = helpers.tempDir("jmap-blob-download");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;
  var blobsServed = 0;
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var readerAccount = await identity.accounts.create({
      address: READER, password: READER_PASSWORD });
    var otherAccount = await identity.accounts.create({
      address: OTHER, password: OTHER_PASSWORD });

    var filedOctets = filedMessage("filed", READER);
    identity.mailbox.appendMessage("INBOX", filedOctets, { actor: { id: readerAccount.id } });
    identity.mailbox.appendMessage("INBOX", nestedMessage("nested", READER),
      { actor: { id: readerAccount.id } });
    identity.mailbox.appendMessage("INBOX", oversizeMessage("oversize", READER),
      { actor: { id: readerAccount.id } });
    identity.mailbox.appendMessage("INBOX", othersMessage("theirs", OTHER),
      { actor: { id: otherAccount.id } });

    var ids = landedIds(identity, readerAccount.id, ["filed", "nested", "oversize"]);
    var theirs = inboxOf(identity, otherAccount.id).rows[0].objectid;
    count("the fixture landed every message this file drives",
      Object.keys(ids).length === 3 && theirs.length > 0, JSON.stringify(ids));

    var handle = blamepost.web.create(wiringFor(cfg, identity));
    testTheRouteIsRegistered(handle);

    listener = blamepost.web.serve(wiringFor(cfg, identity));
    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var reader = browser.browserAt(origin);
    var landed = await reader.signIn(READER, READER_PASSWORD);
    count("the mailbox owner signs in", landed.status === 302, describe(landed));
    var other = browser.browserAt(origin);
    var landedOther = await other.signIn(OTHER, OTHER_PASSWORD);
    count("the other account signs in", landedOther.status === 302, describe(landedOther));

    var session = await theSessionNamesADownloadRoute(reader);
    var accountId = Object.keys(session.accounts)[0];
    var otherSession = JSON.parse(
      (await other.get("/jmap/session", JMAP_HEADERS)).body);
    var otherAccountId = await accountIdOf(other);

    await theWholeMessageComesBackUnderItsOwnBlobId(reader, session, accountId, ids, filedOctets);
    var onePart = await onePartComesBackAsItsOctets(reader, session, accountId, ids);
    theResponsePostureHolds(onePart);
    await bothSurfacesServeTheSameOctets(reader, session, accountId, ids);
    await partNumberingFollowsTheMessageTree(reader, session, accountId, ids);
    await aNonAsciiNameCarriesBothForms(reader, session, accountId, ids);
    await aPartClaimingToBeADocumentIsNotOne(reader, session, accountId, ids);
    await anotherAccountsBlobIsUnreachable(reader, other, session, otherSession, {
      readerAccount:   accountId,
      otherAccount:    otherAccountId,
      readerObjectId:  ids.filed,
      othersObjectId:  theirs,
    });
    await everyMissIsTheSameRefusal(reader, session, accountId, ids);
    await aBlobIdOutsideTheGrammarIsRefused(reader, session, accountId, ids);
    await anUnauthenticatedCallerReachesNothing(origin, session, accountId, ids);
    blobsServed = 6;

    await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    listener = null;

    return helpers.getChecks();
  } finally {
    if (listener !== null) {
      try { await listener.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
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
    console.log("EXAMINED " + blobsServed + " served-blobs");
  }
}

module.exports = { name: "jmap-blob-download", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
