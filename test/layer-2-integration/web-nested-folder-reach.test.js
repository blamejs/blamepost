// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A folder whose name carries the hierarchy delimiter, opened from the
 * browser the way an account holder opens one: by clicking the entry the
 * folder rail rendered for it.
 *
 * An ordinary mail client makes `Clients/Acme` with one CREATE, and RFC
 * 9051 section 6.3.9 separates the levels of that name with the delimiter
 * the server declares. The name is then one of this account's folders like
 * any other, and the browser surface lists it in the rail beside INBOX.
 *
 * Nothing here asks what the link looks like. Every request this file
 * makes is a target the server itself rendered: the rail entry is read off
 * the page, the message link is read off the list the rail entry answered
 * with, the breadcrumb is read off the conversation, and the move form's
 * destination is read off the form. A fixture that spelled a URL of its
 * own would answer for the spelling the fixture chose rather than for the
 * one an account holder's browser follows.
 *
 * ## What this file drives
 *
 *   - The rail entry for a nested folder, followed as a click follows it.
 *   - The message list that folder answers with, and one message opened
 *     from it.
 *   - The breadcrumb back, which has to land on the folder that was open.
 *   - A file on a message in a nested folder, fetched under the message.
 *   - The reply link, which carries the folder the source message is in.
 *   - The rail on the nested folder's own page, which marks it current.
 *   - The line above the list saying what the mailbox holds.
 *   - A message moved into the nested folder from INBOX and moved back
 *     out of it, each through the form the page rendered.
 *   - A search scoped to the nested folder.
 *   - A second name carrying a backslash, which percent-encodes into the
 *     other escape a request path has no unambiguous reading for.
 *
 * It needs no external service. The ports are ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/web-nested-folder-reach.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
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
var ALICE            = "alice@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The nested name an ordinary client makes, and the level above it that
// one CREATE brings with it. Neither carries an RFC 6154 role, so both
// are ordinary folders rather than ones this server files into by name.
var TOP    = "Clients";
var NESTED = "Clients/Acme";

// The other name a request path has no unambiguous reading for. A mailbox
// name admits a backslash, and `encodeURIComponent` turns one into the
// second escape a path is refused for. It is made through the store
// rather than over IMAP, because a backslash inside an IMAP quoted string
// is the string's own escape character and the name that arrives would be
// decided by the quoting rather than by this fixture.
var BACKSLASH = "Backups\\2026";

var INBOX_SUBJECT  = "still in the inbox";
var NESTED_SUBJECT = "filed under acme";

// The octets one part carries, so a fetch can be compared with them
// rather than with the length of what came back. RFC 2046 section 5.1.1
// gives the CRLF before a boundary to the delimiter rather than to the
// part, so the bytes written into the message carry one more than the
// bytes a fetch answers with.
var FILE_BODY = "the ledger for the quarter";

// ---------------------------------------------------------------------------
// Reading the page the way a browser reads it
// ---------------------------------------------------------------------------

// Every folder the rail offers: the target the anchor carries, the label
// shown on it, and whether the page marked it as the one being read.
var RAIL_RE = /<a class="folder-link([^"]*)" href="\/([^"]*)"([\s\S]*?)>([\s\S]*?)<\/a>/g;

var MSG_RE       = /<li class="msg[^"]*">([\s\S]*?)<\/li>/g;
var MSG_HREF_RE  = /<a class="msg-body" href="\/([^"]*)"/;
var SUBJECT_RE   = /<span class="msg-subject">([^<]*)<\/span>/;
var CRUMB_RE     = /<p class="crumb"><a href="\/([^"]*)">Back to ([^<]*)<\/a>/;
var FORM_RE      = /<form method="post" action="\/([^"]*)" class="listform"/;
var OPTION_RE    = /<option value="([^"]*)">/g;
var PART_RE      = /<a class="part-link" href="\/([^"]*)"/;
var REPLY_RE     = /<a class="btn btn-primary" href="\/([^"]*)">Reply<\/a>/;
var PANE_SUB_RE  = /<p class="pane-sub">([^<]*)<\/p>/;
var PANE_TITLE_RE = /<h1 class="pane-title">([^<]*)<\/h1>/;

function describe(answer) {
  return answer.status + " " + String(answer.location || "") + " " +
    String(answer.body || "").replace(/\s+/g, " ").slice(0, 240);
}

function rail(html) {
  RAIL_RE.lastIndex = 0;
  var out = [];
  var hit = RAIL_RE.exec(String(html));
  while (hit !== null) {
    out.push({
      href:    hit[2],
      current: hit[1].indexOf("is-current") !== -1 &&
        hit[3].indexOf('aria-current="page"') !== -1,
      label:   hit[4].trim(),
    });
    hit = RAIL_RE.exec(String(html));
  }
  return out;
}

function railEntry(html, label) {
  var entries = rail(html);
  for (var i = 0; i < entries.length; i += 1) {
    if (entries[i].label === label) return entries[i];
  }
  return null;
}

// The subjects the message list shows, in the order it shows them.
function listedSubjects(html) {
  MSG_RE.lastIndex = 0;
  var out = [];
  var hit = MSG_RE.exec(String(html));
  while (hit !== null) {
    var subject = SUBJECT_RE.exec(hit[1]);
    if (subject !== null) out.push(subject[1].trim());
    hit = MSG_RE.exec(String(html));
  }
  return out;
}

// The target of the anchor on one listed message, found by its subject.
function messageHref(html, subject) {
  MSG_RE.lastIndex = 0;
  var hit = MSG_RE.exec(String(html));
  while (hit !== null) {
    var shown = SUBJECT_RE.exec(hit[1]);
    var href  = MSG_HREF_RE.exec(hit[1]);
    if (shown !== null && href !== null && shown[1].trim() === subject) return href[1];
    hit = MSG_RE.exec(String(html));
  }
  return null;
}

// The identifier the checkbox beside one listed message carries, which is
// what the bulk form posts for it.
function messageObjectId(html, subject) {
  MSG_RE.lastIndex = 0;
  var hit = MSG_RE.exec(String(html));
  while (hit !== null) {
    var shown = SUBJECT_RE.exec(hit[1]);
    var pick  = /name="objectId" value="([^"]*)"/.exec(hit[1]);
    if (shown !== null && pick !== null && shown[1].trim() === subject) return pick[1];
    hit = MSG_RE.exec(String(html));
  }
  return null;
}

function destinations(html) {
  OPTION_RE.lastIndex = 0;
  var out = [];
  var hit = OPTION_RE.exec(String(html));
  while (hit !== null) { out.push(hit[1]); hit = OPTION_RE.exec(String(html)); }
  return out;
}

function firstGroup(re, html) {
  var found = re.exec(String(html));
  return found === null ? null : found[1];
}

// An attribute value as the browser's parser hands it to the navigation,
// rather than as the bytes stand on the page. A link carrying more than
// one query parameter is written with `&amp;` between them, which is the
// correct spelling in HTML and not the character the request carries. A
// fixture reading the raw bytes would send the entity and measure a
// request no browser makes.
function attributeValue(raw) {
  return String(raw)
    .split("&lt;").join("<")
    .split("&gt;").join(">")
    .split("&quot;").join('"')
    .split("&#39;").join("'")
    .split("&amp;").join("&");
}

// A target the server rendered, followed the way a browser follows it:
// the template wrote the leading slash, so the value is what goes after
// it.
function follow(reader, href) {
  return reader.get("/" + attributeValue(href));
}

// The page a redirect names, fetched. A `Location` on this server is an
// absolute path, so it is asked for as it stands.
function followRedirect(reader, answer) {
  return reader.get(String(answer.location));
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

// The one that fails on a surface that cannot address a nested name at
// all: the rail renders the entry, and following it answers the folder.
// The theme switch on every page posts the page to come back to, and the
// folder being read is part of which page that is. It used to be carried
// by the path, so returning to it needed nothing said about it; the folder
// now travels in the query, and a value built from the path alone drops it
// and sends the reader to the inbox instead of back where they were. On a
// page that needs the folder to resolve at all, it lands on a refusal.
async function testTheThemeSwitchComesBackToTheFolderBeingRead(reader, folderPage, label) {
  var back = firstGroup(/name="back" value="([^"]*)"/, folderPage.body);
  count("the theme switch on " + label + " names a page to come back to",
    typeof back === "string" && back.length > 0, String(back));
  if (typeof back !== "string" || back.length === 0) return;

  count("and the page it comes back to is the one being read, folder and all",
    back.indexOf("folder=") !== -1, back);

  var returned = await follow(reader, back);
  count("so following it answers that same folder rather than somewhere else",
    returned.status === 200 && firstGroup(PANE_TITLE_RE, returned.body) === NESTED,
    returned.status + " " + String(firstGroup(PANE_TITLE_RE, returned.body)));
}

async function testTheRailReachesTheNestedFolder(reader, inboxPage) {
  var entry = railEntry(inboxPage.body, NESTED);
  count("the folder rail carries an entry for the nested folder",
    entry !== null, JSON.stringify(rail(inboxPage.body)));
  if (entry === null) return null;

  var page = await follow(reader, entry.href);
  count("following the rail entry for a nested folder answers that folder, because a " +
    "folder an account holder can make is one they can open",
    page.status === 200, describe(page));
  if (page.status !== 200) return null;

  count("the page it answers with is the nested folder's own",
    firstGroup(PANE_TITLE_RE, page.body) === NESTED,
    String(firstGroup(PANE_TITLE_RE, page.body)));
  count("and it lists the message that folder holds",
    listedSubjects(page.body).indexOf(NESTED_SUBJECT) !== -1,
    JSON.stringify(listedSubjects(page.body)));
  return page;
}

function testTheRailMarksTheNestedFolderCurrent(page) {
  var here = railEntry(page.body, NESTED);
  count("the rail on the nested folder's own page marks that folder as the one being read",
    here !== null && here.current === true, JSON.stringify(rail(page.body)));

  var elsewhere = railEntry(page.body, "Inbox");
  count("and marks no other folder as current",
    elsewhere !== null && elsewhere.current === false, JSON.stringify(rail(page.body)));
}

function testTheNestedFolderPageSaysWhatTheMailboxHolds(page) {
  var line = firstGroup(PANE_SUB_RE, page.body);
  count("the nested folder's page carries the line saying what the mailbox holds",
    line !== null && / stored in this mailbox, /.test(line), String(line));
}

async function testAMessageOpensAndTheBreadcrumbComesBack(reader, page) {
  var href = messageHref(page.body, NESTED_SUBJECT);
  count("the message in the nested folder carries a link to itself",
    href !== null, JSON.stringify(listedSubjects(page.body)));
  if (href === null) return null;

  var opened = await follow(reader, href);
  count("opening a message held in a nested folder answers the conversation",
    opened.status === 200, describe(opened));
  if (opened.status !== 200) return null;

  var crumb = CRUMB_RE.exec(String(opened.body));
  count("the conversation carries a breadcrumb back to the folder it was opened from",
    crumb !== null, String(opened.body).replace(/\s+/g, " ").slice(0, 300));
  if (crumb === null) return opened;

  count("the breadcrumb names the nested folder", crumb[2].trim() === NESTED, crumb[2]);
  var back = await follow(reader, crumb[1]);
  count("and following it lands back on that folder rather than on a refusal",
    back.status === 200 && firstGroup(PANE_TITLE_RE, back.body) === NESTED,
    describe(back));
  return opened;
}

async function testAFileOnThatMessageIsServed(reader, opened) {
  var href = firstGroup(PART_RE, opened.body);
  count("the message in the nested folder lists the file it carries",
    href !== null, String(opened.body).replace(/\s+/g, " ").slice(0, 300));
  if (href === null) return;

  var part = await follow(reader, href);
  count("fetching that file under a message in a nested folder answers the octets",
    part.status === 200 && part.body === FILE_BODY, describe(part));
}

async function testTheReplyLinkCarriesTheNestedFolder(reader, opened) {
  var href = firstGroup(REPLY_RE, opened.body);
  count("the conversation offers a reply link", href !== null,
    String(opened.body).replace(/\s+/g, " ").slice(0, 300));
  if (href === null) return;

  var form = await follow(reader, href);
  var subject = firstGroup(/<input id="subject" name="subject" type="text" value="([^"]*)">/,
    form.body);
  var to = firstGroup(/<input id="to" name="to" type="text" value="([^"]*)"/, form.body);
  count("the reply form for a message in a nested folder opens with the source read, " +
    "because the folder the source is in is named on the link the conversation rendered",
    form.status === 200 && subject !== null && subject.indexOf(NESTED_SUBJECT) !== -1 &&
      to === "sender@example.net",
    "GET /" + attributeValue(href) + " -> " + form.status +
    " subject=" + JSON.stringify(subject) + " to=" + JSON.stringify(to));
}

// The destination list is the other half of addressing a folder: a name
// the form posts rather than one a path carries. Both directions are
// driven, because a move out of the nested folder redirects back to it
// and a move into it redirects back to the folder it left.
async function testAMessageMovesIntoAndOutOfTheNestedFolder(reader, inboxHref) {
  var inbox = await follow(reader, inboxHref);
  count("the inbox renders for the move", inbox.status === 200, describe(inbox));
  if (inbox.status !== 200) return;

  count("the destination list offers the nested folder",
    destinations(inbox.body).indexOf(NESTED) !== -1,
    JSON.stringify(destinations(inbox.body)));

  var action = firstGroup(FORM_RE, inbox.body);
  var objectId = messageObjectId(inbox.body, INBOX_SUBJECT);
  count("the inbox form names where it posts and which message to post",
    action !== null && objectId !== null, String(action) + " " + String(objectId));
  if (action === null || objectId === null) return;

  await reader.readCsrf("/" + attributeValue(inboxHref));
  var moved = await reader.form("/" + attributeValue(action),
    { objectId: objectId, action: "move", destination: NESTED });
  count("moving a message into a nested folder is accepted and redirects",
    moved.status === 302, describe(moved));
  if (moved.status !== 302) return;

  var backOnInbox = await followRedirect(reader, moved);
  count("the redirect after the move lands on a page rather than a refusal",
    backOnInbox.status === 200, describe(backOnInbox));
  count("and the message is no longer in the inbox",
    listedSubjects(backOnInbox.body).indexOf(INBOX_SUBJECT) === -1,
    JSON.stringify(listedSubjects(backOnInbox.body)));

  var nestedEntry = railEntry(backOnInbox.body, NESTED);
  if (nestedEntry === null) return;
  var nested = await follow(reader, nestedEntry.href);
  count("the nested folder now holds the moved message",
    nested.status === 200 && listedSubjects(nested.body).indexOf(INBOX_SUBJECT) !== -1,
    describe(nested));
  if (nested.status !== 200) return;

  // And out again, posted from the nested folder's own page, so the form
  // it renders is the one being driven.
  var outAction = firstGroup(FORM_RE, nested.body);
  var outId = messageObjectId(nested.body, INBOX_SUBJECT);
  if (outAction === null || outId === null) {
    count("the nested folder's form names where it posts and which message to post",
      false, String(outAction) + " " + String(outId));
    return;
  }
  await reader.readCsrf("/" + attributeValue(nestedEntry.href));
  var returned = await reader.form("/" + attributeValue(outAction),
    { objectId: outId, action: "move", destination: "INBOX" });
  count("moving a message out of a nested folder is accepted and redirects",
    returned.status === 302, describe(returned));
  if (returned.status !== 302) return;

  var backOnNested = await followRedirect(reader, returned);
  count("the redirect after a move out of a nested folder lands on that folder",
    backOnNested.status === 200 && firstGroup(PANE_TITLE_RE, backOnNested.body) === NESTED,
    describe(backOnNested));
  count("and the message is no longer in the nested folder",
    listedSubjects(backOnNested.body).indexOf(INBOX_SUBJECT) === -1,
    JSON.stringify(listedSubjects(backOnNested.body)));
}

async function testASearchScopedToTheNestedFolder(reader) {
  var found = await reader.get("/search?q=" + encodeURIComponent("acme") +
    "&folder=" + encodeURIComponent(NESTED));
  count("a search scoped to a nested folder answers rather than refusing",
    found.status === 200, describe(found));
  count("and it finds the message filed there",
    found.body.indexOf(NESTED_SUBJECT) !== -1,
    String(found.body).replace(/\s+/g, " ").slice(0, 300));
}

async function testTheBackslashNameIsReachableToo(reader, page) {
  var entry = railEntry(page.body, BACKSLASH);
  count("the folder rail carries an entry for a name holding a backslash",
    entry !== null, JSON.stringify(rail(page.body)));
  if (entry === null) return;

  var opened = await follow(reader, entry.href);
  count("following it answers that folder, because a backslash percent-encodes into the " +
    "other escape a request path has no unambiguous reading for",
    opened.status === 200, describe(opened));
  count("and the page it answers with is that folder's own",
    firstGroup(PANE_TITLE_RE, opened.body) === BACKSLASH,
    String(firstGroup(PANE_TITLE_RE, opened.body)));
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

function plainMessage(id, subject) {
  return Buffer.from(
    "Message-ID: <" + id + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + ALICE + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "Nothing in the body decides anything here.\r\n", "utf8");
}

function messageCarryingAFile(id, subject) {
  var boundary = "b0undary";
  return Buffer.from(
    "Message-ID: <" + id + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + ALICE + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:05:00 +0000\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "The ledger is attached.\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: text/csv; charset=utf-8\r\n" +
    "Content-Disposition: attachment; filename=\"ledger.csv\"\r\n" +
    "\r\n" +
    FILE_BODY + "\r\n" +
    "--" + boundary + "--\r\n", "utf8");
}

// One CREATE of the nested name, which is how an account holder's client
// makes one and what brings the level above it into existence.
async function imapCreates(ctx, name, label) {
  var session = await Wire.imap(ctx.ports.imap, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label,
    address: ALICE, password: ALICE_PASSWORD,
  });
  try {
    var made = await session.imapAsk('CREATE "' + name + '"', "CREATE " + name);
    count(label + ": CREATE " + name + " is accepted", made.verdict === "OK",
      visible(made.text));
  } finally {
    session.close();
  }
}

async function withServer(fn) {
  var root    = helpers.tempDir("web-nested-folder");
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

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
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
    var alice = await identity.accounts.create({ address: ALICE, password: ALICE_PASSWORD });

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
        httpPort:  0,
        listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    await fn({
      ports:    { imap: sections.imap.port },
      httpPort: server.web.describe().bound.http,
      caPem:    leaf.ca,
      identity: identity,
      alice:    alice,
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
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
  }
}

async function run() {
  var reached = 0;
  try {
    await withServer(async function (ctx) {
      await imapCreates(ctx, NESTED, "created");
      ctx.identity.mailbox.createFolder({ id: ctx.alice.id }, BACKSLASH);

      var held = ctx.identity.mailbox.accountFolders({ id: ctx.alice.id })
        .map(function (row) { return row.name; });
      count("the account holds the nested names this run is about",
        held.indexOf(TOP) !== -1 && held.indexOf(NESTED) !== -1 &&
          held.indexOf(BACKSLASH) !== -1, JSON.stringify(held));

      ctx.identity.mailbox.appendMessage("INBOX",
        plainMessage("inbox-one", INBOX_SUBJECT), { actor: { id: ctx.alice.id } });
      ctx.identity.mailbox.appendMessage(NESTED,
        messageCarryingAFile("acme-one", NESTED_SUBJECT), { actor: { id: ctx.alice.id } });

      var reader = browser.browserAt("http://" + LOOPBACK + ":" + ctx.httpPort);
      var landed = await reader.signIn(ALICE, ALICE_PASSWORD);
      count("the account signs in", landed.status === 302, describe(landed));

      // Where a signed-in account lands, followed rather than spelled, so
      // the inbox this run works from is the one the server chose.
      var inbox = await followRedirect(reader, landed);
      count("the landing page after signing in renders", inbox.status === 200, describe(inbox));
      var inboxEntry = railEntry(inbox.body, "Inbox");
      count("the rail carries the inbox entry", inboxEntry !== null,
        JSON.stringify(rail(inbox.body)));
      if (inboxEntry === null) return;

      var nested = await testTheRailReachesTheNestedFolder(reader, inbox);
      if (nested !== null) {
        await testTheThemeSwitchComesBackToTheFolderBeingRead(
          reader, nested, "a nested folder's page");
      }
      if (nested !== null) {
        reached += 1;
        testTheRailMarksTheNestedFolderCurrent(nested);
        testTheNestedFolderPageSaysWhatTheMailboxHolds(nested);
        var opened = await testAMessageOpensAndTheBreadcrumbComesBack(reader, nested);
        if (opened !== null) {
          await testAFileOnThatMessageIsServed(reader, opened);
          await testTheReplyLinkCarriesTheNestedFolder(reader, opened);
        }
      }
      await testAMessageMovesIntoAndOutOfTheNestedFolder(reader, inboxEntry.href);
      await testASearchScopedToTheNestedFolder(reader);
      await testTheBackslashNameIsReachableToo(reader, inbox);
      if (railEntry(inbox.body, BACKSLASH) !== null) reached += 1;
    });

    return helpers.getChecks();
  } finally {
    console.log("EXAMINED " + reached + " opened-nested-folders");
  }
}

module.exports = {
  name:      "web-nested-folder-reach",
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
