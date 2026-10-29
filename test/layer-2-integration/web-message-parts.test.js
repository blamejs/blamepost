// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The files a message carries, as a mailbox owner sees them and as this
 * server hands one back, driven over a real socket against the shipped
 * listener.
 *
 * A message that carries a file is the ordinary case, and the two
 * questions it asks are separate. The first is whether the reader can
 * SEE that the file is there, with the name, the media type and the size
 * the sender declared. The second is whether the octets can be fetched,
 * over a route that is scoped to the signed-in account and to the folder
 * the message is in.
 *
 * Both halves are hostile-input surfaces and they are hostile in
 * different ways. The name is text a stranger wrote and it is read by a
 * person deciding whether to open the file, so a right-to-left override
 * in it shows `report.exe` as `report.txt`. The media type is a claim a
 * stranger made about bytes a stranger sent, so a response that repeats
 * the claim lets a message decide what a browser does with it on the
 * mailbox origin. The name a file is SERVED under and the name it is
 * SHOWN under are therefore two answers, and both are read here.
 *
 * What is driven:
 *
 *   - The conversation page of a message with a file on it: the name,
 *     the type, the size and the link.
 *   - The page of a message with no file on it, which offers no list.
 *   - A fetch of one part, compared byte for byte with the octets the
 *     sender encoded.
 *   - The response headers: the type served, the disposition, the
 *     RFC 6266 filename and the RFC 8187 `filename*` form for a name
 *     that is not ASCII, and `nosniff`.
 *   - A part claiming `text/html`, which must not come back as a
 *     document this origin renders.
 *   - Part numbering through a nested multipart, which is where a flat
 *     index and RFC 9051 section numbering disagree.
 *   - An image the sender marked inline, a forwarded message, and a part
 *     with no name at all: three shapes a list that counted only
 *     `attachment` dispositions would leave the reader unable to see.
 *   - Another account's part, an identifier nothing holds, and a part
 *     number nothing holds: three refusals that have to be one answer.
 *   - A message above the octet read bound, whose parts are neither
 *     listed nor served.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/web-message-parts.test.js
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

// U+202E reverses the reading order of everything after it, so a name
// ending `gpj.exe` is read as `exe.jpg` by the person deciding whether to
// open it. Built rather than written, because a source file carrying the
// raw code point is classified as binary and drops out of every diff.
var RLO = String.fromCharCode(0x202e);

// The name the sender gave the file, and the two answers it produces.
// `SHOWN` is what the reader's eyes get: the screen removes the override,
// so the extension reads as the bytes say. `SERVED` is what the response
// names the file: the filename guard replaces the override rather than
// removing it, because a name written to a filesystem is a different
// question from a name read on a page.
var HOSTILE_NAME = "quarterly " + RLO + "gpj.exe";
var HOSTILE_SHOWN  = "quarterly gpj.exe";
var HOSTILE_SERVED = "quarterly _gpj.exe";

// A name with no ASCII spelling, which is what RFC 8187 exists for. The
// response has to carry both forms: an ASCII `filename` a receiver that
// reads only RFC 6266 can use, and `filename*` carrying the real name.
//
// The apostrophe is in it deliberately. RFC 8187 section 3.2.1 splits an
// ext-value on that character, into a charset, a language and the value,
// and it is not an `attr-char`. An encoder that leaves it raw, which is
// what `encodeURIComponent` does, hands a receiver a name that ends at
// the apostrophe and a third field nothing asked for.
var UNICODE_NAME = "reçu café's.pdf";
var UNICODE_EXT_VALUE = "re%C3%A7u%20caf%C3%A9%27s.pdf";

// The octets the fixture encodes into the attachment. Valid UTF-8 with
// characters above the ASCII range, so a response decoded as UTF-8 and
// re-encoded is byte-identical to what went in, and a transfer that
// mangled the high bytes is visible.
var ATTACHED_TEXT = "zebra7741 quarterly totals café ✓\n";
var ATTACHED_BYTES = Buffer.from(ATTACHED_TEXT, "utf8");

// The markup a part claiming to be a document carries. Distinctive enough
// that finding it rendered rather than downloaded is proof.
var HTML_PART_TEXT = "<h1>tapir9930 this must never render here</h1>\n";
var HTML_PART_BYTES = Buffer.from(HTML_PART_TEXT, "utf8");

var OTHERS_BODY    = "hedgehog5512 belongs to the other account";
var OTHERS_SUBJECT = "The other accounts quarterly numbers";

// The part list as the conversation page renders it. Each row names the
// part, so the reader is told what a message carries before they decide
// to fetch any of it.
var PART_ROW_RE  = /<li class="part-row">([\s\S]*?)<\/li>/g;
var PART_NAME_RE = /<span class="part-name">([^<]*)<\/span>/;
var PART_TYPE_RE = /<span class="part-type">([^<]*)<\/span>/;
var PART_SIZE_RE = /<span class="part-size">([^<]*)<\/span>/;
var PART_HREF_RE = /<a class="part-link" href="([^"]*)"/;

function describe(answer) {
  return answer.status + " " + String(answer.location || "") + " " +
    String(answer.body || "").replace(/\s+/g, " ").slice(0, 200);
}

// Every part row on a page, in the order the page carries them.
function partRows(html) {
  PART_ROW_RE.lastIndex = 0;
  var out = [];
  var hit = PART_ROW_RE.exec(String(html));
  while (hit !== null) {
    var row = hit[1];
    var name = PART_NAME_RE.exec(row);
    var type = PART_TYPE_RE.exec(row);
    var size = PART_SIZE_RE.exec(row);
    var href = PART_HREF_RE.exec(row);
    out.push({
      name: name === null ? null : name[1],
      type: type === null ? null : type[1],
      size: size === null ? null : size[1],
      href: href === null ? null : href[1],
    });
    hit = PART_ROW_RE.exec(String(html));
  }
  return out;
}

function header(answer, name) {
  return String(answer.headers[name] === undefined ? "" : answer.headers[name]);
}

// One refusal with the request taken out of it.
//
// Every page this server renders carries the path it was asked for in the
// theme form's hidden `back` field, which is how that form returns a
// reader to the page they were on. The value came off this request, so it
// tells the caller nothing they did not already send. Taking it out is
// what leaves the refusal itself to compare, which is the thing that must
// not differ between an identifier this account holds and one it does
// not.
function refusalShape(answer, asked) {
  return String(answer.body).split(asked).join("<asked>");
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

// One text body and nothing else, so the page has nothing to list.
function plainMessage(id, to, body) {
  return Buffer.from(
    headerBlock(id, to, "an ordinary message",
      "Content-Type: text/plain; charset=utf-8\r\n") +
    "\r\n" + body + "\r\n", "utf8");
}

// A text body and one file, which is the ordinary shape. The file is
// named with a right-to-left override in it.
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

// A nested multipart: an alternative body, then two files. RFC 9051
// section 6.4.5 numbers these 1.1, 1.2, 2 and 3, and a flat index over
// the leaf parts numbers them 1, 2, 3 and 4. The two disagree about
// every file on this message, which is what makes it worth driving.
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
    // Written as the literal RFC 2231 section 4 ext-value rather than
    // through `encodeURIComponent`, which would leave the apostrophe raw
    // and make the fixture carry the defect the assertions are for.
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

// The three shapes RFC 2183 leaves a reader unable to see without a list.
//
// An image inside a `multipart/related` body is marked `inline` with a
// name, and this server holds remote and inline images back, so a list
// that only counted `attachment` dispositions would leave it invisible
// and unreachable both. A forwarded message arrives as one
// `message/rfc822` part, which RFC 2046 section 5.2.1 defines and which
// `b.safeMime` reads as a leaf, so it is one file rather than a body to
// descend into. And a part that names itself nothing at all is still a
// part the reader asked for.
function relatedMessage(id, to) {
  return Buffer.from(
    headerBlock(id, to, "one with an inline image and a forward on it",
      "Content-Type: multipart/mixed; boundary=\"cover\"\r\n") +
    "\r\n--cover\r\n" +
    "Content-Type: multipart/related; boundary=\"rel\"\r\n" +
    "\r\n--rel\r\n" +
    "Content-Type: text/html; charset=utf-8\r\n" +
    "\r\n<p>the picture is below</p>\r\n" +
    "--rel\r\n" +
    "Content-Type: image/png\r\n" +
    "Content-Disposition: inline; filename=\"pixel.png\"\r\n" +
    "Content-ID: <pixel@example.net>\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED_BYTES.toString("base64") + "\r\n" +
    "--rel--\r\n" +
    "--cover\r\n" +
    "Content-Type: message/rfc822\r\n" +
    "Content-Disposition: attachment\r\n" +
    "\r\nSubject: the one being forwarded\r\n\r\nits body\r\n" +
    "--cover\r\n" +
    "Content-Type: application/zip\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" + ATTACHED_BYTES.toString("base64") + "\r\n" +
    "--cover--\r\n", "utf8");
}

// A message above the octet read bound. The store keeps it and the page
// shows its text, and nothing opens its octets, so its parts are neither
// listed nor served.
function oversizeMessage(id, to) {
  var filler = new Array(1024).join("x");
  var lines = [];
  // Comfortably past MAX_SOURCE_READ_BYTES, built from a repeated line so
  // the fixture costs a loop rather than a file.
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

// ---------------------------------------------------------------------------
// What the reader sees
// ---------------------------------------------------------------------------

// Where the browser surface addresses one message, and one file on it.
// The folder is named in the query string, so a fixture that spelled it
// into the path would ask for a route this server does not register.
function messageAt(objectId, folder) {
  return "/mail/" + encodeURIComponent(objectId) +
    "?folder=" + encodeURIComponent(folder === undefined ? "INBOX" : folder);
}

function partAt(objectId, partId, folder) {
  return "/mail/" + encodeURIComponent(objectId) + "/parts/" + partId +
    "?folder=" + encodeURIComponent(folder === undefined ? "INBOX" : folder);
}

async function testAMessageWithAFileSaysSo(reader, ids) {
  var page = await reader.get(messageAt(ids.filed));
  count("the conversation page of a message carrying a file renders",
    page.status === 200, describe(page));
  count("and it still renders the message's own text",
    page.body.indexOf("the file is on this one") !== -1, describe(page));

  var rows = partRows(page.body);
  count("the page lists exactly the one file the message carries",
    rows.length === 1, JSON.stringify(rows));
  if (rows.length !== 1) return null;

  count("the row carries the name the sender gave the file, with the override removed",
    rows[0].name === HOSTILE_SHOWN, JSON.stringify(rows[0].name));
  count("the shown name carries no right-to-left override",
    String(rows[0].name).indexOf(RLO) === -1, JSON.stringify(rows[0].name));
  count("the row names the media type the sender declared",
    rows[0].type === "application/octet-stream", JSON.stringify(rows[0].type));
  count("the row names the size of the decoded octets",
    rows[0].size !== null && rows[0].size.length > 0, JSON.stringify(rows[0].size));
  count("the row carries a link that stays on this server and inside this message",
    rows[0].href === partAt(ids.filed, "2"),
    JSON.stringify(rows[0].href));
  return rows[0];
}

async function testAMessageWithNoFileOffersNoList(reader, ids) {
  var page = await reader.get(messageAt(ids.plain));
  count("the conversation page of a message carrying no file renders",
    page.status === 200, describe(page));
  count("and lists nothing, because there is nothing on it to list",
    partRows(page.body).length === 0, describe(page));
}

// ---------------------------------------------------------------------------
// What a fetch hands back
// ---------------------------------------------------------------------------

async function testAPartComesBackAsItsOctets(reader, ids) {
  var got = await reader.get(partAt(ids.filed, "2"));
  count("the route serving a part answers", got.status === 200, describe(got));
  count("and hands back the octets the sender encoded, byte for byte",
    Buffer.from(got.body, "utf8").equals(ATTACHED_BYTES),
    JSON.stringify(String(got.body).slice(0, 80)));
  count("and states the length of what it sent",
    header(got, "content-length") === String(ATTACHED_BYTES.length),
    header(got, "content-length"));
}

async function testTheResponseSaysWhatItIsAndRefusesToBeReread(reader, ids) {
  var got = await reader.get(partAt(ids.filed, "2"));

  count("the response does not repeat the sender's media-type claim",
    header(got, "content-type") === "application/octet-stream",
    header(got, "content-type"));
  count("and leaves a browser no room to decide the type for itself",
    header(got, "x-content-type-options").toLowerCase() === "nosniff",
    header(got, "x-content-type-options"));

  var disposition = header(got, "content-disposition");
  count("the response is a download rather than something rendered in place",
    disposition.indexOf("attachment") === 0, disposition);
  count("and names the file under a name with the override replaced rather than removed",
    disposition.indexOf("filename=\"" + HOSTILE_SERVED + "\"") !== -1, disposition);
  count("no header carries a bare carriage return or line feed",
    disposition.indexOf("\r") === -1 && disposition.indexOf("\n") === -1, disposition);

  count("the part is not left in a cache after the reader signs out",
    header(got, "cache-control") === "private, no-store", header(got, "cache-control"));
}

async function testANonAsciiNameCarriesBothForms(reader, ids) {
  var page = await reader.get(messageAt(ids.nested));
  var rows = partRows(page.body);
  count("the nested message lists its two files and neither of its two body readings",
    rows.length === 2, JSON.stringify(rows));
  if (rows.length !== 2) return;

  count("the first file is numbered as RFC 9051 section 6.4.5 numbers it",
    rows[0].href === partAt(ids.nested, "2"),
    JSON.stringify(rows[0].href));
  count("and the second one after it",
    rows[1].href === partAt(ids.nested, "3"),
    JSON.stringify(rows[1].href));
  // The captured value is markup, so it is compared as a browser reads
  // it. Asserting the escaped form directly would pin one escaper's
  // spelling of an apostrophe rather than what the reader sees, and the
  // check below is what holds the escaping itself.
  count("the file with no ASCII spelling is shown under the name the sender wrote",
    b.codepointClass.decodeMarkupEntities(rows[0].name) === UNICODE_NAME,
    JSON.stringify(rows[0].name));
  count("and the name reaches the page escaped rather than as the characters it is made of",
    rows[0].name !== UNICODE_NAME && rows[0].name.indexOf("&#") !== -1,
    JSON.stringify(rows[0].name));

  var got = await reader.get(rows[0].href);
  count("the file with no ASCII spelling is served", got.status === 200, describe(got));
  var disposition = header(got, "content-disposition");
  count("its disposition carries an ASCII filename a receiver reading RFC 6266 alone can use",
    /filename="[\x20-\x7e]*"/.test(disposition) &&
      disposition.indexOf(UNICODE_NAME) === -1, disposition);
  count("and the RFC 8187 form carrying the name the sender actually wrote",
    disposition.indexOf("filename*=UTF-8''" + UNICODE_EXT_VALUE) !== -1, disposition);
  count("the extended form percent-encodes the apostrophe an ext-value is split on",
    disposition.split("filename*=")[1].split("'").length === 3, disposition);
}

async function testAPartClaimingToBeADocumentIsNotOne(reader, ids) {
  var page = await reader.get(messageAt(ids.nested));
  var rows = partRows(page.body);
  if (rows.length !== 2) return;

  count("the page names the claim the sender made about the second file",
    rows[1].type === "text/html", JSON.stringify(rows[1].type));

  var got = await reader.get(rows[1].href);
  count("a part claiming to be a document is served", got.status === 200, describe(got));
  count("and is not served as one",
    header(got, "content-type") === "application/octet-stream",
    header(got, "content-type"));
  count("and is a download rather than a page on this origin",
    header(got, "content-disposition").indexOf("attachment") === 0,
    header(got, "content-disposition"));
  count("and its markup arrived unchanged, because nothing here rewrites a file",
    Buffer.from(got.body, "utf8").equals(HTML_PART_BYTES),
    JSON.stringify(String(got.body).slice(0, 80)));
}

async function testEveryShapeOfFileIsListed(reader, ids) {
  var page = await reader.get(messageAt(ids.related));
  count("the message carrying an inline image and a forward renders",
    page.status === 200, describe(page));

  var rows = partRows(page.body);
  count("it lists three files and neither reading of its body",
    rows.length === 3, JSON.stringify(rows));
  if (rows.length !== 3) return;

  count("the image the sender marked inline is listed, because nothing else shows it",
    rows[0].name === "pixel.png" && rows[0].href === partAt(ids.related, "1.2"),
    JSON.stringify(rows[0]));
  count("and is named by the numbering that reaches inside the related body",
    rows[0].type === "image/png", JSON.stringify(rows[0].type));

  count("the forwarded message is one file rather than a body to descend into",
    rows[1].type === "message/rfc822" && rows[1].href === partAt(ids.related, "2"),
    JSON.stringify(rows[1]));
  count("a part the sender named nothing says so rather than showing an empty name",
    rows[1].name === "a file the sender did not name", JSON.stringify(rows[1].name));

  count("a part with no disposition and no name is still listed",
    rows[2].type === "application/zip" && rows[2].href === partAt(ids.related, "3"),
    JSON.stringify(rows[2]));

  var got = await reader.get(rows[1].href);
  count("an unnamed file is served", got.status === 200, describe(got));
  count("under a name this server chose, in both forms",
    header(got, "content-disposition") ===
      "attachment; filename=\"attachment.bin\"; filename*=UTF-8''attachment.bin",
    header(got, "content-disposition"));
  count("and carries the forwarded message's own octets",
    got.body.indexOf("the one being forwarded") !== -1,
    JSON.stringify(String(got.body).slice(0, 80)));
}

// ---------------------------------------------------------------------------
// What a fetch refuses
// ---------------------------------------------------------------------------

// A refusal that differs between "there is no such part", "there is no
// such message" and "there is one and it is not yours" is an oracle: a
// signed-in account walks identifiers and learns which of them name mail
// on this server. All three have to be the same answer, byte for byte
// once the identifier itself is taken out of it.
async function testNoRefusalSaysWhetherAnotherAccountsPartExists(reader, ids, theirs) {
  var missing = "obj_" + new Array(33).join("0");
  var mine = ids.filed;

  // Six ways to reach the route and fail, each with the path it was
  // asked at, so the request can be taken back out of the answer.
  var asked = [
    { label: "another account's part",  path: partAt(theirs.objectId, "2") },
    { label: "an identifier nothing holds", path: partAt(missing, "2") },
    { label: "a part number nothing holds", path: partAt(mine, "9") },
    { label: "a part number that is not a number", path: partAt(mine, "nine") },
    { label: "a part number counting from zero, which the numbering never does",
      path: partAt(mine, "0") },
    { label: "the message's own text body, which is not a file on it",
      path: partAt(mine, "1") },
  ];

  var shapes = [];
  for (var i = 0; i < asked.length; i += 1) {
    var answer = await reader.get(asked[i].path);
    count(asked[i].label + " is refused", answer.status === 404, describe(answer));
    shapes.push({ label: asked[i].label, body: refusalShape(answer, asked[i].path),
      raw: answer.body });
  }

  var differing = shapes.filter(function (s) { return s.body !== shapes[0].body; });
  count("all six refusals are one answer, once the request is taken out of each",
    differing.length === 0,
    differing.map(function (s) { return s.label; }).join(", ") || "one answer");

  count("none of them carries that account's mail",
    shapes[0].raw.indexOf(OTHERS_SUBJECT) === -1 &&
      shapes[0].raw.indexOf(OTHERS_BODY) === -1, shapes[0].raw.slice(0, 200));
  count("and none of them names a file, a media type or a size",
    shapes.filter(function (s) { return s.body.indexOf("part-row") !== -1; }).length === 0,
    shapes[0].body.slice(0, 200));

  // The framework refuses an encoded path separator where it parses the
  // request target, before any route matches. It is driven rather than
  // assumed, because the grammar this route applies would refuse the same
  // value, and a vector that never reached the route would otherwise
  // report the wrong control as the one holding.
  var traversal = await reader.get(partAt(mine, "..%2F..%2Fetc"));
  count("a part number carrying an encoded path separator reaches no part",
    traversal.status >= 400 && traversal.status !== 200, describe(traversal));

  var absentFolderPath = partAt(mine, "2", "NoFolderOfAnyAccount");
  var noFolder = await reader.get(absentFolderPath);
  count("a folder this account does not hold is refused before any part is read",
    noFolder.status === 404, describe(noFolder));
  var theirFolder = await reader.get(partAt(theirs.objectId, "2", theirs.storeFolder));
  count("and so is another account's store folder",
    theirFolder.status === 404, describe(theirFolder));
  count("the folder refusals are the same answer as the rest",
    refusalShape(noFolder, absentFolderPath) === shapes[0].body, describe(noFolder));
}

// A message this server will not open has no parts to list, so it has
// none to serve either, and the reader is told why on the page rather
// than left with a list that answers nothing.
async function testAMessageTooLargeToOpenOffersNoPart(reader, ids) {
  var page = await reader.get(messageAt(ids.oversize));
  count("the conversation page of a message above the read bound renders",
    page.status === 200, describe(page));
  count("and lists no file, because nothing opened its octets",
    partRows(page.body).length === 0, describe(page));
  count("and says the bound is why",
    page.body.indexOf("larger than") !== -1, describe(page));

  var got = await reader.get(partAt(ids.oversize, "2"));
  count("a part of a message above the read bound is not served",
    got.status === 404, describe(got));
}

// ---------------------------------------------------------------------------
// The route table
// ---------------------------------------------------------------------------

function testTheRouteIsRegistered(handle) {
  var scratch = new b.router.Router();
  handle.routes(scratch);
  var serving = scratch.inspectRoutes().filter(function (route) {
    return route.method === "GET" && route.pattern === "/mail/:objectId/parts/:partId";
  });
  count("the browser surface registers one route that serves a message part",
    serving.length === 1,
    scratch.inspectRoutes().map(function (r) { return r.method + " " + r.pattern; })
      .filter(function (p) { return p.indexOf("/mail") !== -1; }).join(", "));
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

async function run() {
  var root    = helpers.tempDir("web-message-parts");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var listener = null;
  var partsServed = 0;
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
    var reader = await identity.accounts.create({
      address: READER, password: READER_PASSWORD });
    var other = await identity.accounts.create({
      address: OTHER, password: OTHER_PASSWORD });

    // The order these are appended in is the order `landedIds` reads them
    // back in, so the names below and the sequence here are one list.
    identity.mailbox.appendMessage("INBOX",
      plainMessage("plain", READER, "nothing unusual in this one"),
      { actor: { id: reader.id } });
    identity.mailbox.appendMessage("INBOX",
      filedMessage("filed", READER), { actor: { id: reader.id } });
    identity.mailbox.appendMessage("INBOX",
      nestedMessage("nested", READER), { actor: { id: reader.id } });
    identity.mailbox.appendMessage("INBOX",
      relatedMessage("related", READER), { actor: { id: reader.id } });
    identity.mailbox.appendMessage("INBOX",
      oversizeMessage("oversize", READER), { actor: { id: reader.id } });

    identity.mailbox.appendMessage("INBOX",
      Buffer.from(
        headerBlock("theirs", OTHER, OTHERS_SUBJECT,
          "Content-Type: multipart/mixed; boundary=\"edge\"\r\n") +
        "\r\n--edge\r\n" +
        "Content-Type: text/plain; charset=utf-8\r\n\r\n" + OTHERS_BODY + "\r\n" +
        "--edge\r\n" +
        "Content-Type: application/octet-stream\r\n" +
        "Content-Disposition: attachment; filename=\"theirs.bin\"\r\n" +
        "\r\n" + OTHERS_BODY + "\r\n" +
        "--edge--\r\n", "utf8"),
      { actor: { id: other.id } });

    var ids = landedIds(identity, reader.id,
      ["plain", "filed", "nested", "related", "oversize"]);
    var theirInbox = inboxOf(identity, other.id);
    var theirs = {
      objectId:    theirInbox.rows[0].objectid,
      storeFolder: theirInbox.storeFolder,
    };
    count("the fixture landed every message this file drives",
      Object.keys(ids).length === 5 && theirs.objectId.length > 0, JSON.stringify(ids));
    count("the two accounts hold their inboxes in different store folders",
      theirs.storeFolder !== inboxOf(identity, reader.id).storeFolder, theirs.storeFolder);

    var handle = blamepost.web.create(wiringFor(cfg, identity));
    testTheRouteIsRegistered(handle);

    listener = blamepost.web.serve(wiringFor(cfg, identity));
    var ports = await listener.start();
    var session = browser.browserAt("http://" + LOOPBACK + ":" + ports.http);
    var landed = await session.signIn(READER, READER_PASSWORD);
    count("the mailbox owner signs in", landed.status === 302, describe(landed));

    await testAMessageWithAFileSaysSo(session, ids);
    await testAMessageWithNoFileOffersNoList(session, ids);
    await testAPartComesBackAsItsOctets(session, ids);
    await testTheResponseSaysWhatItIsAndRefusesToBeReread(session, ids);
    await testANonAsciiNameCarriesBothForms(session, ids);
    await testAPartClaimingToBeADocumentIsNotOne(session, ids);
    await testEveryShapeOfFileIsListed(session, ids);
    await testNoRefusalSaysWhetherAnotherAccountsPartExists(session, ids, theirs);
    await testAMessageTooLargeToOpenOffersNoPart(session, ids);
    partsServed = 5;

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
    console.log("EXAMINED " + partsServed + " served-parts");
  }
}

module.exports = { name: "web-message-parts", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
