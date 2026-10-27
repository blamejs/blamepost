// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the pages a mailbox owner reads hand back, measured over a real
 * socket against the shipped listener.
 *
 * The administration console has its own route walk. This file is the
 * other half of the browser surface: the mailbox, the conversation, the
 * search results and the compose form, which are the four pages an
 * ordinary account holder opens and the only place in this application
 * where markup a stranger wrote is interpolated into a document.
 *
 * Five questions, each driven rather than read out of the source:
 *
 *   - What a failure that happens BEFORE any route runs tells a stranger
 *     about the machine this server is installed on. The request-line
 *     bound is refused inside the router, so no session, no account and
 *     no TLS are needed to reach that answer, and it is the same handler
 *     that answers a fault on every account page.
 *   - Whether text a stranger chose reaches a reader's eyes as the
 *     characters it is made of. A subject and a display name are already
 *     screened; the recipient list, the bare sender address and the
 *     one-line preview are read on the same rows by the same person.
 *   - Whether the images a message carries stay held back, and whether
 *     the count offered beside the button describes something that is
 *     actually being held.
 *   - Whether any route answers the question "does this identifier name
 *     a message on this server", which is a different question from
 *     "does it name one of mine" and must never be answerable.
 *   - Whether every write a browser can make needs the token, and
 *     whether the fields a compose form carries can reach an outbound
 *     header.
 *   - Which routes serve a part of a message, and whether the name a
 *     sender gave a file is screened before a reader is shown it. The
 *     behavior of the route that serves one is driven in full by
 *     web-message-parts.test.js; what is read here is the route table and
 *     the name on the page.
 *
 * It needs no external service: the ports are ephemeral on the loopback
 * interface and the volume is a temporary directory.
 *
 * Run standalone: node test/layer-2-integration/web-account-surface.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var READER_PASSWORD  = "quiet lantern bicycle 4291";
var OTHER_PASSWORD   = "another quiet lantern 7715";

var READER = "alice@" + DOMAIN;
var OTHER  = "bob@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The two characters this server screens out of anything a stranger
// wrote, built rather than written: a raw C1 byte cannot survive being
// authored into a source file, and a source file carrying one is
// classified as binary and drops out of every diff a reviewer reads.
//
// U+202E reverses the reading order of everything after it, so a
// recipient list ending `gpj.exe` is read as `exe.jpg`. U+009B is the
// single-byte control sequence introducer, which repaints whatever
// terminal or pager the same value is later piped through.
var RLO = String.fromCharCode(0x202e);
var CSI = String.fromCharCode(0x9b);

// A family, which is three people joined by two zero-width joiners. It is
// what the screen would damage if it ran over a message body: the screen
// removes zero-width characters, and removing these two leaves three
// separate people where the sender wrote one family. It is the reason the
// body is rendered unscreened and the reason the preview beside it is not
// the same value.
var JOINED = "\u{1F468}‍\u{1F469}‍\u{1F467}";

// The word a stranger's message body carries, used to tell a page that
// rendered another account's mail from one that did not.
var OTHERS_BODY    = "zebra7741 belongs to the other account";
var OTHERS_SUBJECT = "The other accounts private numbers";

// A remote image source with a query string on it, so the rendered
// attribute can be compared to what the sender wrote character for
// character rather than merely for the host name.
var REMOTE_PIXEL = "https://tracker.example.net/p.gif?m=42&u=who";

// How long a request target has to be before the router refuses to parse
// it. The framework caps at 8192 characters and this is comfortably past
// it while staying well inside what a client will put on the wire.
var OVERLONG_QUERY_CHARS = 8600;

// The account routes a browser posts to. Each is driven with the cookies
// of a signed-in reader and with no token at all.
function accountWrites(objectId) {
  return [
    { path: "/mail/actions?folder=INBOX", body: "action=read&objectId=" + objectId },
    { path: "/compose", body: "to=friend%40example.net&subject=x&text=y" },
    { path: "/prefs/theme", body: "theme=dark" },
    { path: "/sign-out", body: "" },
  ];
}

// ---------------------------------------------------------------------------
// Reading the rendered pages
// ---------------------------------------------------------------------------

function firstGroup(html, pattern) {
  var hit = pattern.exec(String(html));
  return hit === null ? null : hit[1];
}

function allGroups(html, pattern) {
  pattern.lastIndex = 0;
  var out = [];
  var hit = pattern.exec(String(html));
  while (hit !== null) {
    out.push(hit[1]);
    hit = pattern.exec(String(html));
  }
  return out;
}

var LETTER_TO_RE   = /<p class="letter-to">to ([^<]*)<\/p>/;
var LETTER_ADDR_RE = /<span class="letter-addr">([^<]*)<\/span>/;
var LETTER_BODY_RE = /<div class="letter-body[^"]*">([\s\S]*?)<\/div>/;
var MSG_FROM_RE    = /<span class="msg-from" title="([^"]*)">/g;
var MSG_PREVIEW_RE = /<span class="msg-preview">([^<]*)<\/span>/g;
var IMAGEBAR_RE    = /(\d+) images are held back/;
var IMG_SRC_RE     = /<img[^>]*\ssrc="([^"]*)"/g;

function carriesScreenedOut(text) {
  var s = String(text === null || text === undefined ? "" : text);
  return s.indexOf(RLO) !== -1 || s.indexOf(CSI) !== -1;
}

// Every absolute reference to somewhere that is not this server, in any
// attribute a browser resolves. A page rendering none of these is a page
// that asked no other host for anything.
function offSiteReferences(html) {
  var found = [];
  var re = /(?:src|href|srcset|background|poster|action|cite)\s*=\s*"([^"]*)"/gi;
  var hit = re.exec(String(html));
  while (hit !== null) {
    if (/^(?:https?:)?\/\//i.test(hit[1]) && hit[1].indexOf("tracker.example.net") !== -1) {
      found.push(hit[1]);
    }
    hit = re.exec(String(html));
  }
  return found;
}

function describe(answer) {
  return answer.status + " " + String(answer.location || "") + " " +
    String(answer.body || "").replace(/\s+/g, " ").slice(0, 160);
}

// ---------------------------------------------------------------------------
// The fixture messages
// ---------------------------------------------------------------------------

function plainMessage(id, from, to, subject, body, extraHeaders) {
  return Buffer.from(
    "Message-ID: <" + id + "@example.net>\r\n" +
    "From: " + from + "\r\n" +
    "To: " + to + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    (extraHeaders || "") +
    "\r\n" + body + "\r\n", "utf8");
}

function htmlMessage(id, to, subject, markup) {
  return plainMessage(id, "Sender <sender@example.net>", "<" + to + ">", subject, markup,
    "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n");
}

function attachmentMessage(id, to, filename) {
  return Buffer.from(
    "Message-ID: <" + id + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: one with a file on it\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: multipart/mixed; boundary=\"edge\"\r\n" +
    "\r\n--edge\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n\r\nthe file is on this one\r\n" +
    "--edge\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Content-Disposition: attachment; filename=\"quarterly " + RLO + "gpj.exe\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n\r\nAAAAAAAA\r\n" +
    "--edge--\r\n", "utf8");
}

// ---------------------------------------------------------------------------
// A failure before any route runs
// ---------------------------------------------------------------------------

// The request-line bound is refused where the router parses the target,
// which is before the session is read and before any route matches. So
// this is the answer a passer-by gets, and it is produced by the handler
// that answers a fault on every page below it.
//
// What must not be in it: the exception's stack, the absolute path of
// the directory this server was installed into, and the names of the
// framework's own source files. Each of those tells somebody who has
// authenticated to nothing which build is running and where it lives.
//
// The posture must not depend on an environment variable. A container
// image can set one; `blamepost serve` under a service manager, which is
// the other documented way to run this, sets nothing.
async function testAFailureBeforeAnyRouteTellsAStrangerNothing(label, reader) {
  var overlong = "/?q=" + new Array(OVERLONG_QUERY_CHARS + 1).join("a");
  var answer = await reader.get(overlong);
  var body = String(answer.body || "");

  count(label + ": a request target past the bound is refused", answer.status >= 400,
    describe(answer));
  count(label + ": the refusal names the rule it broke rather than nothing",
    body.indexOf("safe-url/too-long") !== -1 || answer.status === 414 || answer.status === 431,
    describe(answer));
  count(label + ": the refusal carries no stack",
    body.indexOf(" at ") === -1 && body.toLowerCase().indexOf("\"stack\"") === -1,
    body.replace(/\s+/g, " ").slice(0, 200));
  count(label + ": the refusal names no file on the machine this server runs on",
    body.indexOf("lib/vendor") === -1 && body.indexOf("lib\\\\vendor") === -1 &&
    body.indexOf(".js:") === -1,
    body.replace(/\s+/g, " ").slice(0, 200));
  count(label + ": the refusal names no directory this server was installed into",
    body.indexOf(nodePath.sep === "\\" ? "C:\\" : "/home/") === -1 &&
    body.indexOf("blamepost\\\\lib") === -1 && body.indexOf("blamepost/lib") === -1,
    body.replace(/\s+/g, " ").slice(0, 200));
}

// ---------------------------------------------------------------------------
// Text a stranger chose, on its way to a reader
// ---------------------------------------------------------------------------

// The subject and the sender's display name go through the screen
// already. These three do not, and they are read by the same person on
// the same rows: the recipient list under the sender's name, the bare
// address beside it, and the one-line preview in the folder list.
//
// The message BODY is deliberately left alone, and the last check here
// is what proves the screen is aimed at the lines this server composed
// rather than applied to everything. Stripping the body would take the
// zero-width joiner out of an emoji sequence and the separator out of a
// Devanagari conjunct, so a reader would be shown a message that differs
// from the one that was sent.
async function testStrangerChosenHeaderTextIsScreened(reader, hostileId) {
  var page = await reader.get("/mail/" + encodeURIComponent(hostileId) + "?folder=INBOX");
  count("the conversation page for the hostile message renders", page.status === 200,
    describe(page));

  var to = firstGroup(page.body, LETTER_TO_RE);
  count("the page carries a recipient line to read", to !== null && to.length > 0,
    JSON.stringify(to));
  count("the recipient list is screened before it is shown", !carriesScreenedOut(to),
    JSON.stringify(to));

  var addr = firstGroup(page.body, LETTER_ADDR_RE);
  count("the page carries the sender's bare address", addr !== null && addr.length > 0,
    JSON.stringify(addr));
  count("the sender's bare address is screened before it is shown", !carriesScreenedOut(addr),
    JSON.stringify(addr));

  var listed = await reader.get("/mail?folder=INBOX");
  count("the folder list renders", listed.status === 200, describe(listed));

  var titles = allGroups(listed.body, MSG_FROM_RE);
  count("the list carries a row title for every message it shows", titles.length > 0,
    String(titles.length));
  count("no row title carries a character that changes what the row reads as",
    titles.filter(carriesScreenedOut).length === 0, JSON.stringify(titles));

  var previews = allGroups(listed.body, MSG_PREVIEW_RE);
  count("the list carries a preview for every message it shows", previews.length > 0,
    String(previews.length));
  count("no preview carries a character that changes what the row reads as",
    previews.filter(carriesScreenedOut).length === 0, JSON.stringify(previews));

  // The differential. A blanket strip over the whole page would satisfy
  // every check above and would also be this server editing the message:
  // the same screen that removes an override removes the joiners that
  // hold an emoji sequence together, so the reader would be shown three
  // people where the sender wrote a family.
  var body = firstGroup(page.body, LETTER_BODY_RE);
  count("the message body itself is rendered as the sender wrote it",
    body !== null && body.indexOf(JOINED) !== -1, JSON.stringify(body));
  count("and the preview of that same body on the folder list is not that value",
    previews.filter(function (line) { return line.indexOf(JOINED) !== -1; }).length === 0,
    JSON.stringify(previews));
}

// ---------------------------------------------------------------------------
// Remote content
// ---------------------------------------------------------------------------

// Nothing a message carries may ask another host for anything until the
// reader says so, and the count offered beside the button has to describe
// something that is actually being held: a reader who presses `Show them`
// on a message where nothing was ever going to load has been taught that
// the button does nothing, and has spent a widened policy to learn it.
async function testTheRemoteContentDefaultHolds(reader, ids) {
  var loud = await reader.get("/mail/" + encodeURIComponent(ids.remote) + "?folder=INBOX");
  count("a message carrying a remote image renders", loud.status === 200, describe(loud));
  count("and asks no other host for anything", offSiteReferences(loud.body).length === 0,
    JSON.stringify(offSiteReferences(loud.body)));
  var heldCount = firstGroup(loud.body, IMAGEBAR_RE);
  count("the reader is told an image is being held back", heldCount === "1", String(heldCount));

  var quiet = await reader.get("/mail/" + encodeURIComponent(ids.everythingElse) +
    "?folder=INBOX");
  count("a message whose remote content is a stylesheet, a link element, a background " +
    "attribute and a source set renders", quiet.status === 200, describe(quiet));
  count("and asks no other host for anything either",
    offSiteReferences(quiet.body).length === 0, JSON.stringify(offSiteReferences(quiet.body)));
  count("and nothing is offered back, because none of it was an image being held",
    IMAGEBAR_RE.exec(quiet.body) === null,
    String(quiet.body).replace(/\s+/g, " ").slice(0, 200));

  var commented = await reader.get("/mail/" + encodeURIComponent(ids.commented) +
    "?folder=INBOX");
  count("a message whose only image sits inside a comment renders", commented.status === 200,
    describe(commented));
  count("and is not reported as holding one back, because the comment is dropped on " +
    "every reading and nothing is withheld",
    IMAGEBAR_RE.exec(commented.body) === null,
    String(commented.body).replace(/\s+/g, " ").slice(0, 200));
}

// The opt-in, and what this server adds to the request the reader agreed
// to. It adds nothing: the source is the sender's own, character for
// character, so the remote host learns what the sender already put in
// the URL and nothing this server knows about who is reading.
async function testAskingForImagesAddsNothingOfThisServers(reader, remoteId) {
  var at = "/mail/" + encodeURIComponent(remoteId) + "?folder=INBOX";
  var shown = await reader.get(at + "&images=on");
  count("the reader can ask for the images", shown.status === 200, describe(shown));

  var sources = allGroups(shown.body, IMG_SRC_RE);
  count("the image is rendered", sources.indexOf(b.guardHtml.escapeAttr(REMOTE_PIXEL)) !== -1 ||
    sources.indexOf(REMOTE_PIXEL) !== -1, JSON.stringify(sources));
  count("and its source is what the sender wrote, with nothing appended",
    sources.filter(function (src) {
      return src.indexOf("tracker.example.net") !== -1 &&
        src.indexOf(READER) === -1 && src.indexOf(remoteId) === -1;
    }).length === 1, JSON.stringify(sources));

  var policy = String(shown.headers["content-security-policy"] || "");
  count("the widened policy admits https and nothing over cleartext",
    policy.indexOf("img-src 'self' data: https:") !== -1 && policy.indexOf("http:") === -1,
    policy);
  count("and the reader's own address in the path is not sent to the host the image " +
    "comes from, because the referrer policy stops at this origin",
    String(shown.headers["referrer-policy"] || "") === "same-origin",
    String(shown.headers["referrer-policy"]));
}

// Every page on this surface is a document carrying markup a stranger
// wrote, so what a browser is allowed to decide about a response on its
// own is part of the reading. `nosniff` is the control that stops a
// response being taken for something other than what its type says, and
// it is the one a served message part would have needed had this surface
// served one.
async function testAResponseIsReadAsWhatItSaysItIs(reader, objectId) {
  var page = await reader.get("/mail/" + encodeURIComponent(objectId) + "?folder=INBOX");
  count("a conversation page names its own type",
    /^text\/html\s*;\s*charset=/i.test(String(page.headers["content-type"] || "")),
    String(page.headers["content-type"]));
  count("and leaves a browser no room to read it as another",
    String(page.headers["x-content-type-options"] || "").toLowerCase() === "nosniff",
    String(page.headers["x-content-type-options"]));

  var asset = await reader.get("/static/blamepost.css");
  count("the asset mount answers", asset.status === 200, describe(asset));
  count("and leaves a browser no room there either",
    String(asset.headers["x-content-type-options"] || "").toLowerCase() === "nosniff",
    String(asset.headers["x-content-type-options"]));
}

// ---------------------------------------------------------------------------
// Whether a route answers that another account's object exists
// ---------------------------------------------------------------------------

// A refusal that differs between "there is no such thing" and "there is
// one and it is not yours" is an oracle: a signed-in account walks
// identifiers and learns which of them name mail on this server. Both
// answers have to be the same answer, byte for byte once the identifier
// itself is taken out of it.
async function testNoRouteSaysWhetherAnotherAccountsObjectExists(reader, theirs) {
  var missing = "obj_" + new Array(33).join("0");

  var theirMessage = await reader.get("/mail/" + encodeURIComponent(theirs.objectId) +
    "?folder=INBOX");
  var noMessage    = await reader.get("/mail/" + encodeURIComponent(missing) +
    "?folder=INBOX");
  count("another account's message is refused", theirMessage.status === 404,
    describe(theirMessage));
  count("and an identifier nothing holds is refused the same way", noMessage.status === 404,
    describe(noMessage));
  count("the two refusals are one answer",
    theirMessage.body.split(theirs.objectId).join("X") === noMessage.body.split(missing).join("X"),
    describe(theirMessage));
  count("neither carries that account's mail",
    theirMessage.body.indexOf(OTHERS_SUBJECT) === -1 &&
    theirMessage.body.indexOf(OTHERS_BODY) === -1, describe(theirMessage));

  var theirFolder = await reader.get("/mail?folder=" + encodeURIComponent(theirs.storeFolder));
  var noFolder    = await reader.get("/mail?folder=" +
    encodeURIComponent("NoFolderOfAnyAccount"));
  count("another account's store folder is refused", theirFolder.status === 404,
    describe(theirFolder));
  count("and a folder name nothing holds is refused the same way", noFolder.status === 404,
    describe(noFolder));
  count("those two refusals are one answer too",
    theirFolder.body.split(theirs.storeFolder).join("X") ===
      noFolder.body.split("NoFolderOfAnyAccount").join("X"), describe(theirFolder));

  // The compose form reads a message by identifier as well, to derive a
  // reply or to attach a forward. A form that came back filled in would
  // answer the same question the message page refuses to.
  var theirDraft = await reader.get("/compose?source=" + encodeURIComponent(theirs.objectId) +
    "&folder=INBOX&mode=forward");
  var noDraft = await reader.get("/compose?source=" + encodeURIComponent(missing) +
    "&folder=INBOX&mode=forward");
  count("a reply derived from another account's message renders an empty form",
    theirDraft.status === 200 && theirDraft.body.indexOf(OTHERS_SUBJECT) === -1,
    describe(theirDraft));
  count("and it is the same form an identifier nothing holds produces",
    theirDraft.body === noDraft.body, describe(theirDraft));

  // The posted half, which is where the octets would actually be read.
  var posted = await reader.form("/compose", {
    to: "attacker@example.net", subject: "x", text: "y",
    forwardOf: theirs.objectId, forwardFolder: "INBOX",
  });
  count("posting a forward of another account's message is refused", posted.status === 400,
    describe(posted));
  count("and the refusal carries none of it",
    posted.body.indexOf(OTHERS_SUBJECT) === -1 && posted.body.indexOf(OTHERS_BODY) === -1,
    describe(posted));

  var searched = await reader.get("/search?q=" + encodeURIComponent("zebra7741"));
  count("a search reaches this account's mail and no other's",
    searched.status === 200 && searched.body.indexOf(OTHERS_BODY) === -1 &&
    searched.body.indexOf(OTHERS_SUBJECT) === -1, describe(searched));
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

// Every state change a browser can make on this surface, sent with the
// session cookies and no token. The cookies matter: a request that sent
// none would be waved through as a stateless caller, which is a different
// rule and not the one under test.
async function testEveryAccountWriteNeedsTheToken(origin, ca, objectId) {
  var writes = accountWrites(objectId);
  for (var i = 0; i < writes.length; i += 1) {
    var reader = browser.browserAt(origin, { ca: ca });
    var landed = await reader.signIn(READER, READER_PASSWORD);
    count("a reader signs in before the untokened POST to " + writes[i].path,
      landed.status === 302, describe(landed));
    var answer = await reader.request("POST", writes[i].path, {
      "Content-Type": "application/x-www-form-urlencoded",
      "Origin":       origin,
      "Accept":       "text/html",
    }, writes[i].body);
    count("a POST to " + writes[i].path + " with no token is refused",
      answer.status === 403 || answer.status === 400, describe(answer));
  }
}

// The compose form's own fields, which are the only route by which a
// browser hands this server text that becomes a header. A line break in
// one of them would let the account holder write a second header, and the
// header worth writing is the one the submission binding exists to
// refuse.
async function testNoComposeFieldReachesAHeaderUnread(reader) {
  var folded = await reader.form("/compose", {
    to: "friend@example.net", text: "body",
    subject: "quarterly\r\nFrom: chair@" + DOMAIN,
  });
  count("a subject carrying a line break does not send", folded.status >= 400,
    describe(folded));

  var forgedParent = await reader.form("/compose", {
    to: "friend@example.net", subject: "x", text: "body",
    inReplyTo: "not a message identifier at all",
  });
  count("a parent identifier that is not one does not send", forgedParent.status >= 400,
    describe(forgedParent));

  var forgedChain = await reader.form("/compose", {
    to: "friend@example.net", subject: "x", text: "body",
    references: "<real@example.net> and some words",
  });
  count("a threading chain that is not one does not send", forgedChain.status >= 400,
    describe(forgedChain));

  var forgedAuthor = await reader.form("/compose", {
    to: "friend@example.net", subject: "x", text: "body", from: OTHER,
  });
  count("an author this account does not hold does not send", forgedAuthor.status === 400,
    describe(forgedAuthor));
  count("and the refusal says which addresses it may write instead",
    forgedAuthor.body.indexOf("is not an address this account may write") !== -1,
    describe(forgedAuthor));
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

// Exactly one route serves a part of a message, and every other route on
// this surface answers with a rendered page. That is a property of the
// route table rather than of any one page, so the table is what is read.
// A second such route would be a second set of answers about a content
// type, a disposition and a filename, and the two would drift.
//
// The behavior of the one route is driven in full by
// test/layer-2-integration/web-message-parts.test.js. What is read here is
// that the table holds it and nothing beside it.
function testOneRouteServesAMessagePart(server) {
  var scratch = new b.router.Router();
  server.web.routes(scratch);
  var serving = scratch.inspectRoutes().filter(function (route) {
    return /attach|download|part|blob|raw|source/i.test(route.pattern) &&
      route.pattern.indexOf("/jmap") !== 0;
  });
  var listed = serving.map(function (r) { return r.method + " " + r.pattern; });
  count("the browser surface registers one route that serves a message part",
    listed.length === 1 && listed[0] === "GET /mail/:objectId/parts/:partId",
    listed.join(", ") || "none");
}

// A file on a message is shown with the name the sender gave it, screened
// the way every other value a stranger chose on this page is. The fixture
// names the file with a right-to-left override in it, so a page that
// showed the name unscreened would show `quarterly exe.jpg` to the reader
// deciding whether to fetch it.
async function testAMessageWithAFileOnItNamesTheFile(reader, attachedId) {
  var page = await reader.get("/mail/" + encodeURIComponent(attachedId) + "?folder=INBOX");
  count("a message carrying a file renders its text", page.status === 200 &&
    page.body.indexOf("the file is on this one") !== -1, describe(page));

  var named = firstGroup(page.body, /<span class="part-name">([^<]*)<\/span>/);
  count("and names the file the sender put on it", named === "quarterly gpj.exe",
    JSON.stringify(named));
  count("with the override that reorders the name removed before it is shown",
    !carriesScreenedOut(named), JSON.stringify(named));

  var linked = firstGroup(page.body, /<a class="part-link" href="([^"]*)"/);
  count("and offers it under this message's own path",
    linked === "/mail/" + encodeURIComponent(attachedId) + "/parts/2?folder=INBOX",
    JSON.stringify(linked));
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

function baseEnv(dataDir, material) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    BLAMEPOST_TLS_CERT:         material.certFile,
    BLAMEPOST_TLS_KEY:          material.keyFile,
  };
}

async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
  }
  return sections;
}

// The store folder an account's inbox lives in, and the identity of the
// first message in it. Both are read out of the database, which is how a
// test names something a signed-in stranger has no legitimate route to.
function inboxOf(identity, accountId) {
  var folder = b.db.from(require("../../lib/mail/mailbox").FOLDERS)
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
  out.storeFolder = inbox.storeFolder;
  return out;
}

async function run() {
  var root    = helpers.tempDir("web-account-surface");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  var pagesDriven = 0;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "account surface run" });
    var reader = await identity.accounts.create({
      address: READER, password: READER_PASSWORD });
    var other = await identity.accounts.create({
      address: OTHER, password: OTHER_PASSWORD });

    // The order these are appended in is the order `landedIds` reads them
    // back in, so the names below and the sequence here are one list.
    identity.mailbox.appendMessage("INBOX", plainMessage("ordinary",
      "Sender <sender@example.net>", "<" + READER + ">",
      "an ordinary message", "nothing unusual in this one"),
    { actor: { id: reader.id } });

    // The charset is declared, and it has to be: a body carrying bytes
    // above 127 with nothing saying what they are is decoded as seven-bit
    // text and every high bit is cleared, so a message that declared
    // nothing could not carry one of these characters into a preview at
    // all and the differential at the end of the screening section would
    // pass for the wrong reason.
    identity.mailbox.appendMessage("INBOX", plainMessage("hostile",
      "\"Sender\" <se" + RLO + "nder@example.net>",
      "\"quarterly " + RLO + "gpj.exe\" <" + READER + ">, team" + CSI + "@example.net",
      "a recipient list worth reading twice",
      "the body says " + RLO + "kcab and " + JOINED + " stays joined",
      "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"),
    { actor: { id: reader.id } });

    identity.mailbox.appendMessage("INBOX", htmlMessage("remote", READER,
      "one remote image",
      "<p>hello</p><img src=\"" + REMOTE_PIXEL + "\" alt=\"a pixel\">"),
    { actor: { id: reader.id } });

    identity.mailbox.appendMessage("INBOX", htmlMessage("everythingElse", READER,
      "every other way to reach another host",
      "<style>body{background:url(https://tracker.example.net/s.png)}</style>" +
      "<link rel=\"icon\" href=\"https://tracker.example.net/f.ico\">" +
      "<div style=\"background:url(https://tracker.example.net/bg.png)\">x</div>" +
      "<table><tr><td background=\"https://tracker.example.net/td.png\">y</td></tr></table>" +
      "<form action=\"/compose\" method=\"post\">" +
      "<input name=\"to\" value=\"attacker@example.net\"></form>" +
      "<meta http-equiv=\"refresh\" content=\"0;url=https://tracker.example.net/go\">" +
      "<p OnMouseOver=\"fetch('https://tracker.example.net/h')\">z</p>"),
    { actor: { id: reader.id } });

    identity.mailbox.appendMessage("INBOX", htmlMessage("commented", READER,
      "an image nobody will ever load",
      "<!-- <img src=\"https://tracker.example.net/c.png\"> --><p>hi</p>"),
    { actor: { id: reader.id } });

    identity.mailbox.appendMessage("INBOX",
      attachmentMessage("attached", READER), { actor: { id: reader.id } });

    identity.mailbox.appendMessage("INBOX", plainMessage("theirs",
      "Sender <sender@example.net>", "<" + OTHER + ">", OTHERS_SUBJECT, OTHERS_BODY),
    { actor: { id: other.id } });

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });

    // Read before the server starts, so the mount the listener serves is
    // the last one made on this handle.
    testOneRouteServesAMessagePart(server);

    await server.start();
    running = true;

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var cleartext = "http://" + LOOPBACK + ":" + bound.http;
    var ca     = material.caPem;

    var ids = landedIds(identity, reader.id, [
      "ordinary", "hostile", "remote", "everythingElse", "commented", "attached",
    ]);
    var theirInbox = inboxOf(identity, other.id);
    var theirs = {
      objectId:    theirInbox.rows[0].objectid,
      storeFolder: theirInbox.storeFolder,
    };
    count("the fixture landed every message this file drives",
      Object.keys(ids).length === 7 && theirs.objectId.length > 0, JSON.stringify(ids));
    count("the two accounts hold their inboxes in different store folders",
      theirs.storeFolder !== ids.storeFolder, theirs.storeFolder + " / " + ids.storeFolder);

    var session = browser.browserAt(origin, { ca: ca });
    var landed = await session.signIn(READER, READER_PASSWORD);
    count("the mailbox owner signs in", landed.status === 302, describe(landed));

    await testAFailureBeforeAnyRouteTellsAStrangerNothing(
      "a passer-by on the cleartext port", browser.browserAt(cleartext));
    await testAFailureBeforeAnyRouteTellsAStrangerNothing(
      "a signed-in reader over TLS", session);

    await testStrangerChosenHeaderTextIsScreened(session, ids.hostile);
    await testTheRemoteContentDefaultHolds(session, ids);
    await testAskingForImagesAddsNothingOfThisServers(session, ids.remote);
    await testAResponseIsReadAsWhatItSaysItIs(session, ids.ordinary);
    await testNoRouteSaysWhetherAnotherAccountsObjectExists(session, theirs);
    await testNoComposeFieldReachesAHeaderUnread(session);
    await testAMessageWithAFileOnItNamesTheFile(session, ids.attached);
    await testEveryAccountWriteNeedsTheToken(origin, ca, ids.ordinary);

    pagesDriven = Object.keys(ids).length - 1;

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;

    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
    console.log("EXAMINED " + pagesDriven + " account-pages");
  }
}

module.exports = { name: "web-account-surface", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
