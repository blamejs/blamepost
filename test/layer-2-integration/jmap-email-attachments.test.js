// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The `attachments` property of RFC 8621 section 4.1.4, driven as a real
 * JMAP request over a real socket against the shipped listener.
 *
 * A client is told a message carries a file by `hasAttachment` and is
 * handed a download route by the session document. Without this property
 * it holds neither the blob ids that route resolves nor the names, types
 * and sizes a person picks a file by, so it can only guess at the id
 * grammar. The list closes that: a client reads a `blobId` out of the
 * answer and fills it into `downloadUrl`, which is the round trip driven
 * here.
 *
 * What is driven:
 *
 *   - A call that does not name `attachments`, which carries no such
 *     property. The list costs a stored-body read and a structure parse
 *     per message, so a client that did not ask does not pay.
 *   - A call that names it, and every body-part property this server
 *     answers: `partId`, `blobId`, `size`, `name`, `type`, `charset`,
 *     `disposition`, `cid`, `language` and `location`.
 *   - The round trip: every `blobId` in the list, fetched through the
 *     session document's `downloadUrl` and compared byte for byte with
 *     the octets the sender encoded.
 *   - Part numbering through two levels of multipart, where a flat index
 *     over the leaves disagrees with RFC 9051 section 6.4.5 about every
 *     file, and where the part number carries a dot that RFC 8620
 *     section 1.2 does not admit in an Id.
 *   - The list against the browser surface's own list for the same
 *     message, so the two cannot come to disagree about what a file is.
 *   - A name a stranger wrote, which reaches the client screened.
 *   - A message with no file, which answers an empty list, and a message
 *     above the octet read bound, which answers no list at all rather
 *     than an empty one beside `hasAttachment: true`.
 *   - Another account's identifier, which is not found and leaks neither
 *     a name nor an octet.
 *   - A malformed `properties` argument, refused at the point of parse.
 *   - The measured cost of one call naming fifty identifiers.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/jmap-email-attachments.test.js
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

var JMAP_ERROR  = "urn:ietf:params:jmap:error:";
var JMAP_HEADERS = { Accept: "application/json" };

// How many identifiers one call may name, which is what the session
// document advertises as `maxObjectsInGet`. The cost of naming the
// property for that many is measured rather than assumed.
var IDS_IN_ONE_CALL = 50;

// U+202E reverses the reading order of everything after it. Built rather
// than written, because a source file carrying the raw code point is
// classified as binary and drops out of every diff.
var RLO = String.fromCharCode(0x202e);

var HOSTILE_NAME  = "quarterly " + RLO + "gpj.exe";
var HOSTILE_SHOWN = "quarterly gpj.exe";

// The same trick in the media type the sender claimed, which a client
// shows beside the name to the person deciding whether to open the file.
//
// The charset parameter cannot carry it. The parse refuses a part whose
// charset is outside its allowlist, so `utf-8` with an override in it
// costs the whole message its structure rather than reaching a reader,
// and the case below asks for the ordinary name that survives.
var HOSTILE_TYPE       = "text/" + RLO + "lmth";
var HOSTILE_TYPE_SHOWN = "text/lmth";

var TYPED_TEXT  = "civet4408 the type on this one lies about itself";
var TYPED_BYTES = Buffer.from(TYPED_TEXT, "utf8");

var ATTACHED_TEXT  = "zebra7741 quarterly totals café ✓\n";
var ATTACHED_BYTES = Buffer.from(ATTACHED_TEXT, "utf8");

// Written with no trailing line terminator of its own, because RFC 2046
// section 5.1.1 counts the CRLF before a boundary delimiter as part of
// the delimiter rather than of the body above it.
var UNNAMED_TEXT  = "marmot6620 a part the sender did not type a name for";
var UNNAMED_BYTES = Buffer.from(UNNAMED_TEXT, "utf8");

var IMAGE_BYTES = Buffer.from("okapi1183 not really a picture\n", "utf8");

var DEEP_HTML_TEXT  = "<h1>tapir9930 two multiparts down</h1>\n";
var DEEP_HTML_BYTES = Buffer.from(DEEP_HTML_TEXT, "utf8");

var OTHERS_TEXT  = "hedgehog5512 belongs to the other account\n";
var OTHERS_BYTES = Buffer.from(OTHERS_TEXT, "utf8");

var OTHERS_FILENAME = "their-quarterly-numbers.bin";

var IMAGE_CID      = "logo@example.net";
var IMAGE_LOCATION = "http://example.net/assets/logo.png";

function describe(answer) {
  return answer.status + " " + String(answer.body || "").replace(/\s+/g, " ").slice(0, 240);
}

// One blob id naming a part, as a client reading the grammar builds it.
// The part number's dots become dashes because RFC 8620 section 1.2 does
// not admit a dot in an Id.
function partBlob(objectId, partNumber) {
  return objectId + "-p" + String(partNumber).split(".").join("-");
}

function downloadUrl(session, accountId, blobId, name, type) {
  return String(session.downloadUrl)
    .split("{accountId}").join(encodeURIComponent(accountId))
    .split("{blobId}").join(encodeURIComponent(blobId))
    .split("{name}").join(encodeURIComponent(name))
    .split("{type}").join(encodeURIComponent(type));
}

function byPartId(list) {
  var out = {};
  for (var i = 0; i < list.length; i += 1) out[String(list[i].partId)] = list[i];
  return out;
}

function partIdsOf(list) {
  return list.map(function (part) { return String(part.partId); }).join(",");
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

// A text body and three files. RFC 9051 section 6.4.5 numbers the text 1,
// the named file 2, the one with no Content-Type header of its own 3 and
// the one whose declared type and charset carry a reading-order override
// 4. Part 3 is the branch where the implicit type of RFC 2045 section 5.2
// decides both the type and the charset.
function filedMessage(id, to) {
  return Buffer.from(
    headerBlock(id, to, "one with two files on it",
      "Content-Type: multipart/mixed; boundary=\"edge\"\r\n") +
    "\r\n--edge\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nthe files are on this one\r\n" +
    "--edge\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"" + HOSTILE_NAME + "\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED_BYTES.toString("base64") + "\r\n" +
    "--edge\r\n" +
    "Content-Disposition: attachment\r\n" +
    // A Content-Id holding nothing but the brackets RFC 2392 removes,
    // which leaves an empty string where a client expects an identifier
    // or nothing at all.
    "Content-ID: <>\r\n" +
    "\r\n" + UNNAMED_TEXT + "\r\n" +
    "--edge\r\n" +
    "Content-Type: " + HOSTILE_TYPE + "; charset=utf-8\r\n" +
    "Content-Disposition: attachment; filename=\"typed.dat\"\r\n" +
    "\r\n" + TYPED_TEXT + "\r\n" +
    "--edge--\r\n", "utf8");
}

// An alternative body, an inline image, and one file two multiparts down.
// RFC 9051 section 6.4.5 numbers the files 2 and 3.1; a flat index over
// the leaves numbers them 3 and 4. The deep one is what makes the dot in
// a part number load bearing, because a blob id cannot carry one.
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
    "Content-Type: image/png\r\n" +
    "Content-Disposition: inline; filename=\"logo.png\"\r\n" +
    "Content-ID: <" + IMAGE_CID + ">\r\n" +
    "Content-Language: en, de\r\n" +
    "Content-Location: " + IMAGE_LOCATION + "\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + IMAGE_BYTES.toString("base64") + "\r\n" +
    "--outer\r\n" +
    "Content-Type: multipart/mixed; boundary=\"deep\"\r\n" +
    "\r\n--deep\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n" +
    "Content-Disposition: attachment; filename=\"page.html\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + DEEP_HTML_BYTES.toString("base64") + "\r\n" +
    "--deep--\r\n" +
    "--outer--\r\n", "utf8");
}

// No file at all, which answers an empty list rather than no list.
function bareMessage(id, to) {
  return Buffer.from(
    headerBlock(id, to, "one with nothing on it",
      "Content-Type: text/plain; charset=utf-8\r\n") +
    "\r\nnothing is attached to this one\r\n", "utf8");
}

// A message above the octet read bound. It is not opened, so the files on
// it are neither counted nor listed.
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
    "Content-Disposition: attachment; filename=\"" + OTHERS_FILENAME + "\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + OTHERS_BYTES.toString("base64") + "\r\n" +
    "--edge--\r\n", "utf8");
}

// One of the fifty the cost is measured over. Each carries a file, so
// the measurement is over the shape that pays rather than the shape that
// short-circuits on the mark. The file is the size of an ordinary
// document a person sends, because the cost is a read and a parse over
// the octets and both are linear in them.
var BULK_FILE_BYTES = b.constants.BYTES.kib(256);

function bulkMessage(n, to) {
  var body = new Array(BULK_FILE_BYTES + 1).join("y");
  return Buffer.from(
    headerBlock("bulk" + n, to, "bulk " + n,
      "Content-Type: multipart/mixed; boundary=\"bulk\"\r\n") +
    "\r\n--bulk\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\nbulk " + n + "\r\n" +
    "--bulk\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"bulk-" + n + ".bin\"\r\n" +
    "\r\n" + body + "\r\n" +
    "--bulk--\r\n", "utf8");
}

// The other fifty: the same count of identifiers with no file on any of
// them. The mark written when each was filed records that, so this is
// the shape the list answers without opening anything.
function bulkBareMessage(n, to) {
  return Buffer.from(
    headerBlock("plain" + n, to, "plain " + n,
      "Content-Type: text/plain; charset=utf-8\r\n") +
    "\r\nplain " + n + "\r\n", "utf8");
}

// ---------------------------------------------------------------------------
// The calls
// ---------------------------------------------------------------------------

async function get(reader, accountId, ids, properties) {
  var args = { accountId: accountId, ids: ids };
  if (properties !== undefined) args.properties = properties;
  var response = await reader.jmap([["Email/get", args, "c0"]]);
  return { status: response.status, body: response.body, first: browser.answer(response, 0) };
}

function emailsById(answer) {
  var out = {};
  var list = (answer.first && answer.first[1] && answer.first[1].list) || [];
  for (var i = 0; i < list.length; i += 1) out[list[i].id] = list[i];
  return out;
}

// ---------------------------------------------------------------------------
// What a client that did not ask is charged
// ---------------------------------------------------------------------------

async function aCallThatDoesNotNameItCarriesNoList(reader, accountId, ids) {
  var everyProperty = await get(reader, accountId, [ids.filed, ids.nested]);
  var byId = emailsById(everyProperty);
  count("a call naming no properties answers the messages it named",
    Object.keys(byId).length === 2, describe(everyProperty));
  count("and it carries no attachments property, so it pays for no read",
    byId[ids.filed] !== undefined &&
    !Object.prototype.hasOwnProperty.call(byId[ids.filed], "attachments"),
    JSON.stringify(Object.keys(byId[ids.filed] || {})));

  var named = await get(reader, accountId, [ids.filed], ["id", "subject"]);
  var namedById = emailsById(named);
  count("nor does a call naming other properties",
    namedById[ids.filed] !== undefined &&
    !Object.prototype.hasOwnProperty.call(namedById[ids.filed], "attachments"),
    JSON.stringify(Object.keys(namedById[ids.filed] || {})));
}

// ---------------------------------------------------------------------------
// The list itself
// ---------------------------------------------------------------------------

async function theListNamesEveryFileAndNothingElse(reader, accountId, ids) {
  var answer = await get(reader, accountId, [ids.filed], ["id", "attachments"]);
  var email = emailsById(answer)[ids.filed];
  count("a call naming attachments answers the message",
    email !== undefined, describe(answer));
  var parts = (email && email.attachments) || [];
  count("the list names the three files and neither the body nor the multipart",
    parts.length === 3, partIdsOf(parts));

  var at = byPartId(parts);
  count("the named file is numbered as RFC 9051 section 6.4.5 numbers it",
    at["2"] !== undefined, partIdsOf(parts));
  count("the part with no Content-Type header of its own is listed too",
    at["3"] !== undefined, partIdsOf(parts));

  var named = at["2"] || {};
  count("its blobId is the message identifier with the part marker and number",
    named.blobId === partBlob(ids.filed, "2"), String(named.blobId));
  count("its size is the octet count after transfer decoding",
    named.size === ATTACHED_BYTES.length, String(named.size) + " against " +
    ATTACHED_BYTES.length);
  count("its type is the media type with the parameters stripped",
    named.type === "application/octet-stream", String(named.type));
  count("its disposition is what the sender declared, with the parameters stripped",
    named.disposition === "attachment", String(named.disposition));
  count("a name a stranger wrote reaches the client screened",
    named.name === HOSTILE_SHOWN, JSON.stringify(named.name));
  count("and the reading-order override is not in it",
    String(named.name).indexOf(RLO) === -1, JSON.stringify(named.name));
  count("a part that declared no Content-Id answers null for cid",
    named.cid === null, JSON.stringify(named.cid));
  count("a part that declared no Content-Language answers null for language",
    named.language === null, JSON.stringify(named.language));
  count("a part that declared no Content-Location answers null for location",
    named.location === null, JSON.stringify(named.location));
  count("a part with a Content-Type that is not text carries no charset",
    named.charset === null, JSON.stringify(named.charset));

  var implicit = at["3"] || {};
  count("a part with no Content-Type header takes the implicit type of RFC 2045",
    implicit.type === "text/plain", String(implicit.type));
  count("and the implicit charset that goes with it",
    implicit.charset === "us-ascii", JSON.stringify(implicit.charset));
  count("a part the sender did not name answers null rather than a made-up name",
    implicit.name === null, JSON.stringify(implicit.name));
  count("a Content-Id holding only its brackets answers null rather than an empty string",
    implicit.cid === null, JSON.stringify(implicit.cid));
  count("its size is the octet count of the part body",
    implicit.size === UNNAMED_BYTES.length,
    String(implicit.size) + " against " + UNNAMED_BYTES.length);

  // The media type is read by the same person making the same decision
  // as the name, so it carries the same screen.
  var typed = at["4"] || {};
  count("a media type a stranger wrote reaches the client screened",
    typed.type === HOSTILE_TYPE_SHOWN, JSON.stringify(typed.type));
  count("and it carries no reading-order override",
    String(typed.type).indexOf(RLO) === -1, JSON.stringify(typed.type));
  count("the charset beside it is the one the part declared",
    typed.charset === "utf-8", JSON.stringify(typed.charset));
}

async function theNestedListFollowsTheMessageTree(reader, accountId, ids) {
  var answer = await get(reader, accountId, [ids.nested], ["id", "attachments"]);
  var email = emailsById(answer)[ids.nested];
  var parts = (email && email.attachments) || [];
  count("the nested message lists its two files",
    parts.length === 2, partIdsOf(parts));

  var at = byPartId(parts);
  count("the inline image is part 2 rather than the third leaf",
    at["2"] !== undefined, partIdsOf(parts));
  count("the file two multiparts down is part 3.1 rather than the fourth leaf",
    at["3.1"] !== undefined, partIdsOf(parts));
  count("neither half of the alternative body is listed as a file",
    at["1.1"] === undefined && at["1.2"] === undefined, partIdsOf(parts));

  var image = at["2"] || {};
  count("an inline disposition is reported as the sender wrote it",
    image.disposition === "inline", String(image.disposition));
  count("the Content-Id comes back with the angle brackets removed",
    image.cid === IMAGE_CID, JSON.stringify(image.cid));
  count("the Content-Language comes back as a list of tags",
    Array.isArray(image.language) && image.language.join("|") === "en|de",
    JSON.stringify(image.language));
  count("the Content-Location comes back as the URI the part carried",
    image.location === IMAGE_LOCATION, JSON.stringify(image.location));
  count("an image part carries no charset",
    image.charset === null, JSON.stringify(image.charset));

  var deep = at["3.1"] || {};
  count("a text part reports the charset its Content-Type declared",
    deep.charset === "utf-8", JSON.stringify(deep.charset));
  count("its blobId writes the dot in the part number as a dash",
    deep.blobId === ids.nested + "-p3-1", String(deep.blobId));
  count("and that blobId sits inside the RFC 8620 section 1.2 Id grammar",
    /^[A-Za-z0-9_-]{1,255}$/.test(String(deep.blobId)), String(deep.blobId));
}

// The round trip a client actually performs: read a blobId out of the
// answer, fill it into the session document's template, fetch it. Nothing
// in this file builds a blob id for the fetch, so a list naming an id the
// route cannot resolve fails here rather than passing on a shape both
// halves of this file agreed to invent.
async function everyBlobIdInTheListResolves(reader, session, accountId, ids) {
  var answer = await get(reader, accountId, [ids.filed, ids.nested], ["id", "attachments"]);
  var byId = emailsById(answer);
  var fetched = 0;
  var pairs = [
    { emailId: ids.filed,  partId: "2",   octets: ATTACHED_BYTES },
    { emailId: ids.filed,  partId: "3",   octets: UNNAMED_BYTES },
    { emailId: ids.filed,  partId: "4",   octets: TYPED_BYTES },
    { emailId: ids.nested, partId: "2",   octets: IMAGE_BYTES },
    { emailId: ids.nested, partId: "3.1", octets: DEEP_HTML_BYTES },
  ];
  for (var i = 0; i < pairs.length; i += 1) {
    var listed = byPartId((byId[pairs[i].emailId] || {}).attachments || [])[pairs[i].partId];
    count("the list carries part " + pairs[i].partId + " of the message it belongs to",
      listed !== undefined, partIdsOf(((byId[pairs[i].emailId] || {}).attachments) || []));
    if (listed === undefined) continue;
    var got = await reader.get(
      downloadUrl(session, accountId, listed.blobId, "t.bin", "application/octet-stream"),
      { Accept: "*/*" });
    count("the blobId the list carries for part " + pairs[i].partId + " downloads",
      got.status === 200, String(listed.blobId) + " -> " + describe(got));
    count("and it is the octets the sender encoded, byte for byte",
      Buffer.from(got.body, "utf8").equals(pairs[i].octets),
      String(got.body).length + " bytes back for " + listed.blobId);
    count("the size the list reported is the octet count that came back",
      listed.size === Buffer.from(got.body, "utf8").length,
      String(listed.size) + " against " + Buffer.from(got.body, "utf8").length);
    fetched += 1;
  }
  return fetched;
}

// The conversation page and this list read the same message with the same
// reader. A part is a file on both or on neither, so the two part numbers
// are compared rather than the counts alone.
async function bothSurfacesNameTheSameParts(reader, accountId, ids) {
  var answer = await get(reader, accountId, [ids.nested], ["id", "attachments"]);
  var listed = ((emailsById(answer)[ids.nested] || {}).attachments || [])
    .map(function (part) { return String(part.partId); }).sort().join(",");

  var page = await reader.get("/mail/" + encodeURIComponent(ids.nested) + "?folder=INBOX",
    { Accept: "text/html" });
  count("the conversation page renders", page.status === 200, describe(page));
  var shown = [];
  // The part number ends the path and the folder follows it in the query, so
  // the number is closed by the `?` that opens the query rather than by the
  // attribute's own quote. Both are matched, because a reader that accepted
  // only the quote read every part link as absent once the folder moved off
  // the path, and answered that the page listed nothing.
  var re = /\/parts\/([0-9.]+)[?"]/g;
  var hit = re.exec(String(page.body));
  while (hit !== null) {
    if (shown.indexOf(hit[1]) === -1) shown.push(hit[1]);
    hit = re.exec(String(page.body));
  }
  count("the browser surface lists the same parts this property names",
    shown.sort().join(",") === listed,
    "page " + shown.join(",") + " against list " + listed);
}

// ---------------------------------------------------------------------------
// The two answers that are not a list of files
// ---------------------------------------------------------------------------

async function aMessageWithNoFileAnswersAnEmptyList(reader, accountId, ids) {
  var answer = await get(reader, accountId, [ids.bare], ["id", "hasAttachment", "attachments"]);
  var email = emailsById(answer)[ids.bare];
  count("a message with no file carries the property",
    email !== undefined && Object.prototype.hasOwnProperty.call(email, "attachments"),
    JSON.stringify(Object.keys(email || {})));
  count("and it is an empty list rather than a missing one",
    Array.isArray(email && email.attachments) && email.attachments.length === 0,
    JSON.stringify(email && email.attachments));
  count("which is the answer hasAttachment gives for the same message",
    email !== undefined && email.hasAttachment === false,
    JSON.stringify(email && email.hasAttachment));
}

async function aMessageThisServerDidNotOpenAnswersNoList(reader, accountId, ids) {
  var answer = await get(reader, accountId, [ids.oversize],
    ["id", "hasAttachment", "attachments"]);
  var email = emailsById(answer)[ids.oversize];
  count("a message above the octet read bound is answered for",
    email !== undefined, describe(answer));
  count("and hasAttachment does not hide a file on it",
    email !== undefined && email.hasAttachment === true,
    JSON.stringify(email && email.hasAttachment));
  count("the property is absent rather than an empty list beside that answer",
    email !== undefined &&
    !Object.prototype.hasOwnProperty.call(email, "attachments"),
    JSON.stringify(email && email.attachments));
}

// ---------------------------------------------------------------------------
// What is out of reach
// ---------------------------------------------------------------------------

// The vector that pins the scoping. Every other miss in this file is
// refused by the message not being in a folder this account holds, so
// this is the one that goes quiet if the resolution stops being bound to
// the acting account.
async function anotherAccountsMessageIsNotFound(reader, other, scope) {
  var answer = await get(reader, scope.readerAccount, [scope.othersObjectId],
    ["id", "attachments"]);
  var result = answer.first && answer.first[1];
  count("an identifier another account holds is reported not found",
    result !== undefined && Array.isArray(result.notFound) &&
    result.notFound.indexOf(scope.othersObjectId) !== -1, describe(answer));
  count("and no part of it is listed",
    (result && result.list ? result.list.length : 0) === 0, describe(answer));
  count("neither its filename nor its octets are in the answer",
    String(answer.body).indexOf(OTHERS_FILENAME) === -1 &&
    String(answer.body).indexOf("hedgehog5512") === -1, describe(answer));

  var mine = await get(other, scope.otherAccount, [scope.readerObjectId],
    ["id", "attachments"]);
  var back = mine.first && mine.first[1];
  count("and the other account cannot list the reader's parts either",
    back !== undefined && Array.isArray(back.notFound) &&
    back.notFound.indexOf(scope.readerObjectId) !== -1, describe(mine));
  count("nor read a name off them",
    String(mine.body).indexOf("gpj.exe") === -1, describe(mine));
}

async function aMalformedPropertiesArgumentIsRefused(reader, accountId, ids) {
  var vectors = [
    { label: "a string rather than a list", properties: "attachments" },
    { label: "a map rather than a list",    properties: { attachments: true } },
    { label: "a list carrying a number",    properties: ["id", 7] },
    { label: "a list carrying a map",       properties: ["id", { name: "attachments" }] },
  ];
  for (var i = 0; i < vectors.length; i += 1) {
    var answer = await get(reader, accountId, [ids.filed], vectors[i].properties);
    var first = answer.first || [];
    count("properties as " + vectors[i].label + " is refused at the point of parse",
      first[0] === "error" && first[1] &&
      first[1].type === JMAP_ERROR + "invalidArguments", describe(answer));
    count("and no message is answered for",
      String(answer.body).indexOf("gpj.exe") === -1, describe(answer));
  }

  var empty = await get(reader, accountId, [ids.filed], []);
  count("an empty list is a client naming no property rather than a refusal",
    (empty.first || [])[0] === "Email/get", describe(empty));
  var nulled = await get(reader, accountId, [ids.filed], null);
  count("a null properties is the same",
    (nulled.first || [])[0] === "Email/get", describe(nulled));
}

// ---------------------------------------------------------------------------
// What the property costs
// ---------------------------------------------------------------------------

// The measurement the decision to serve this under a named property
// rests on. Three calls, each naming as many identifiers as one call may
// and each answered by the same handler, so the differences between them
// are the stored-body read and the structure parse the list costs.
//
// The timings are printed rather than asserted. What they measure is one
// machine under whatever else it is running, so a threshold over them
// would fail on a loaded runner and say nothing about this server. What
// is asserted is what the calls answered.
async function theCostOfNamingItForFiftyIdsIsMeasured(reader, accountId, carrying, bare) {
  var withFiles = carrying.slice(0, IDS_IN_ONE_CALL);
  var withNone  = bare.slice(0, IDS_IN_ONE_CALL);
  count("the measurement names as many identifiers as one call may",
    withFiles.length === IDS_IN_ONE_CALL && withNone.length === IDS_IN_ONE_CALL,
    withFiles.length + " carrying a file, " + withNone.length + " carrying none");

  // One pass of each first, so no number carries a first-call cost the
  // others do not.
  await get(reader, accountId, withFiles, ["id"]);
  await get(reader, accountId, withFiles, ["id", "attachments"]);
  await get(reader, accountId, withNone, ["id"]);
  await get(reader, accountId, withNone, ["id", "attachments"]);

  // The shortest of several rounds rather than one reading or a mean.
  // Everything that moves a reading moves it upwards, so the floor is
  // the one figure that is about this server rather than about what else
  // the machine was doing while it answered.
  var ROUNDS = 5;
  var timings = { base: Infinity, pay: Infinity, quietBase: Infinity, mark: Infinity };
  var paying = null;
  var without = null;
  var marked = null;
  for (var round = 0; round < ROUNDS; round += 1) {
    var baseAt = Date.now();
    without = await get(reader, accountId, withFiles, ["id"]);
    timings.base = Math.min(timings.base, Date.now() - baseAt);

    var payAt = Date.now();
    paying = await get(reader, accountId, withFiles, ["id", "attachments"]);
    timings.pay = Math.min(timings.pay, Date.now() - payAt);

    // The same pair over the messages that carry nothing, so each
    // difference is read against its own baseline rather than against
    // the other: these messages are a fraction of the size, and the walk
    // that finds them is most of what both of their numbers are.
    var quietBaseAt = Date.now();
    await get(reader, accountId, withNone, ["id"]);
    timings.quietBase = Math.min(timings.quietBase, Date.now() - quietBaseAt);

    var markAt = Date.now();
    marked = await get(reader, accountId, withNone, ["id", "attachments"]);
    timings.mark = Math.min(timings.mark, Date.now() - markAt);
  }

  var listed = emailsById(paying);
  var keys = Object.keys(listed);
  var files = 0;
  var octets = 0;
  for (var i = 0; i < keys.length; i += 1) {
    var parts = listed[keys[i]].attachments || [];
    files += parts.length;
    for (var p = 0; p < parts.length; p += 1) octets += parts[p].size;
  }
  count("the call naming the property answers for every identifier",
    keys.length === IDS_IN_ONE_CALL, String(keys.length));
  count("and lists one file on each of them",
    files === IDS_IN_ONE_CALL, String(files) + " files over " + keys.length + " messages");
  count("the call that did not name it answers for the same identifiers",
    Object.keys(emailsById(without)).length === IDS_IN_ONE_CALL,
    String(Object.keys(emailsById(without)).length));

  var quiet = emailsById(marked);
  var quietKeys = Object.keys(quiet);
  var emptied = quietKeys.filter(function (id) {
    return Array.isArray(quiet[id].attachments) && quiet[id].attachments.length === 0;
  });
  count("fifty messages that carry no file all answer an empty list",
    quietKeys.length === IDS_IN_ONE_CALL && emptied.length === IDS_IN_ONE_CALL,
    emptied.length + " of " + quietKeys.length);

  console.log("MEASURED Email/get over " + IDS_IN_ONE_CALL + " ids that carry a file: " +
    timings.base + " ms not naming attachments, " + timings.pay +
    " ms naming it, listing " + files + " files totalling " + octets + " octets");
  console.log("MEASURED Email/get over " + IDS_IN_ONE_CALL + " ids that carry none: " +
    timings.quietBase + " ms not naming attachments, " + timings.mark + " ms naming it");
  return { files: files, octets: octets };
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

function inboxRows(identity, accountId) {
  var folder = b.db.from(mailbox.FOLDERS)
    .where({ account: accountId, wireName: "INBOX" }).first().folder;
  return identity.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: 500 });
}

async function run() {
  var root    = helpers.tempDir("jmap-email-attachments");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;
  var partsListed = 0;
  var blobsRoundTripped = 0;
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

    var order = ["filed", "nested", "bare", "oversize"];
    var octets = {
      filed:    filedMessage("filed", READER),
      nested:   nestedMessage("nested", READER),
      bare:     bareMessage("bare", READER),
      oversize: oversizeMessage("oversize", READER),
    };
    for (var o = 0; o < order.length; o += 1) {
      identity.mailbox.appendMessage("INBOX", octets[order[o]],
        { actor: { id: readerAccount.id } });
    }
    for (var n = 0; n < IDS_IN_ONE_CALL; n += 1) {
      identity.mailbox.appendMessage("INBOX", bulkMessage(n, READER),
        { actor: { id: readerAccount.id } });
    }
    for (var q = 0; q < IDS_IN_ONE_CALL; q += 1) {
      identity.mailbox.appendMessage("INBOX", bulkBareMessage(q, READER),
        { actor: { id: readerAccount.id } });
    }
    identity.mailbox.appendMessage("INBOX", othersMessage("theirs", OTHER),
      { actor: { id: otherAccount.id } });

    var rows = inboxRows(identity, readerAccount.id);
    var ids = {};
    for (var r = 0; r < order.length; r += 1) ids[order[r]] = rows[r].objectid;
    var objectIdOf = function (row) { return row.objectid; };
    var carryingIds = rows.slice(order.length, order.length + IDS_IN_ONE_CALL)
      .map(objectIdOf);
    var bareIds = rows.slice(order.length + IDS_IN_ONE_CALL,
      order.length + (2 * IDS_IN_ONE_CALL)).map(objectIdOf);
    var theirs = inboxRows(identity, otherAccount.id)[0].objectid;
    count("the fixture landed every message this file drives",
      Object.keys(ids).length === order.length &&
      carryingIds.length === IDS_IN_ONE_CALL && bareIds.length === IDS_IN_ONE_CALL &&
      theirs.length > 0,
      JSON.stringify(ids) + " plus " + carryingIds.length + " carrying a file and " +
      bareIds.length + " carrying none");

    listener = blamepost.web.serve(wiringFor(cfg, identity));
    var ports = await listener.start();
    var origin = "http://" + LOOPBACK + ":" + ports.http;

    var reader = browser.browserAt(origin);
    var landed = await reader.signIn(READER, READER_PASSWORD);
    count("the mailbox owner signs in", landed.status === 302, describe(landed));
    var other = browser.browserAt(origin);
    var landedOther = await other.signIn(OTHER, OTHER_PASSWORD);
    count("the other account signs in", landedOther.status === 302, describe(landedOther));

    var session = JSON.parse((await reader.get("/jmap/session", JMAP_HEADERS)).body);
    var accountId = Object.keys(session.accounts)[0];
    var otherSession = JSON.parse((await other.get("/jmap/session", JMAP_HEADERS)).body);
    var otherAccountId = Object.keys(otherSession.accounts)[0];

    await aCallThatDoesNotNameItCarriesNoList(reader, accountId, ids);
    await theListNamesEveryFileAndNothingElse(reader, accountId, ids);
    await theNestedListFollowsTheMessageTree(reader, accountId, ids);
    blobsRoundTripped = await everyBlobIdInTheListResolves(reader, session, accountId, ids);
    await bothSurfacesNameTheSameParts(reader, accountId, ids);
    await aMessageWithNoFileAnswersAnEmptyList(reader, accountId, ids);
    await aMessageThisServerDidNotOpenAnswersNoList(reader, accountId, ids);
    await anotherAccountsMessageIsNotFound(reader, other, {
      readerAccount:  accountId,
      otherAccount:   otherAccountId,
      readerObjectId: ids.filed,
      othersObjectId: theirs,
    });
    await aMalformedPropertiesArgumentIsRefused(reader, accountId, ids);
    var measured = await theCostOfNamingItForFiftyIdsIsMeasured(reader, accountId,
      carryingIds, bareIds);
    partsListed = 4 + measured.files;

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
    console.log("EXAMINED " + partsListed + " listed-body-parts");
    console.log("EXAMINED " + blobsRoundTripped + " round-tripped-blob-ids");
  }
}

module.exports = {
  name:      "jmap-email-attachments",
  run:       run,
  getChecks: helpers.getChecks,
};

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
