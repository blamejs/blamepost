// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One server, two accounts, real HTTP: what one account can reach of
 * another's mail through the browser surface and through JMAP.
 *
 * The message store keeps one flat namespace of folders and records no
 * owner, so the folders an account owns are recorded in exactly one
 * place, the mailbox adapter, and every surface that lists or accepts a
 * folder has to ask it. A surface that asks anything else lists the
 * whole server: `b.mail.agent.folders` takes an actor for its scope
 * check and its audit trail and then returns the store's folder table
 * whole, which is a folder list for every account on the server, and a
 * store folder name accepted back off a URL reads the mail inside it.
 * That is a signed in account reading a stranger's mail over HTTP, so
 * it is driven here over a socket rather than argued about in a unit
 * test.
 *
 * The checks are a mailbox owner's whole reach: the folder list, a
 * folder page, a message page, a mutation, and the JMAP methods that
 * answer the same questions to a client.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/cross-account-isolation.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

var LOOPBACK = "127.0.0.1";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

// Distinctive enough that finding it anywhere in a response body is
// proof the response carried that account's mail, and not a coincidence
// of ordinary words in a page of markup.
var BOBS_SUBJECT   = "Bobs private quarterly numbers";
var BOBS_BODY      = "zebra7741 belongs to bob and to nobody else";
var ALICES_SUBJECT = "Alices own message";

// The mailboxes a fresh account owns, sorted, from the store's default
// set. This application creates no folder beyond these: there is no
// create verb on the adapter, IMAP CREATE and RENAME are refused, and
// JMAP serves no Mailbox/set. So the rendered list is the whole of it,
// and a seventh row is either somebody else's folder or a row built
// from something that is not a folder at all.
var DEFAULT_MAILBOXES = ["Archive", "Drafts", "INBOX", "Junk", "Sent", "Trash"];

// A folder row and a message row both link under /mail, and both are
// read by class rather than by the shape of the target. A folder is named
// in the query string and a message in the path, so a pattern matching
// the path alone would answer for the message and skip the folder
// entirely. The class is what the page marks the two kinds apart with.
var FOLDER_LINK_RE  = /class="folder-link[^"]*"\s+href="\/mail\?folder=([^"&]*)"/g;
var MESSAGE_LINK_RE = /class="msg-body"\s+href="\/mail\/([^"?&]*)/g;

// A message identity as the store issues it (RFC 8474 objectid) and as
// it appears in a path. A folder named this is not a folder.
var MESSAGE_ID_RE = /^obj_[0-9a-f]+$/;

// Every distinct link target the pattern finds, in the order the page
// carries them. The pattern is module scoped and global, so its cursor
// is reset before use rather than inherited from the last caller.
function hrefTargets(html, pattern) {
  pattern.lastIndex = 0;
  var found = [];
  var hit = pattern.exec(html);
  while (hit !== null) {
    var target = decodeURIComponent(hit[1]);
    if (found.indexOf(target) === -1) found.push(target);
    hit = pattern.exec(html);
  }
  return found;
}

function message(subject, to, body) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

// A cookie jar, because this drives the application the way a browser
// does: the session cookie and the CSRF cookie are both set by the
// server and both have to come back on the next request.
function cookieJar() {
  var held = Object.create(null);
  return {
    absorb: function (res) {
      var list = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
      for (var i = 0; i < list.length; i += 1) {
        var pair = list[i].split(";")[0];
        var eq = pair.indexOf("=");
        if (eq === -1) continue;
        held[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
      }
    },
    header: function () {
      return Object.keys(held).map(function (name) { return name + "=" + held[name]; }).join("; ");
    },
  };
}

function client(origin) {
  var jar = cookieJar();
  var csrf = "";
  async function get(path) {
    var res = await fetch(origin + path, {
      redirect: "manual",
      headers:  { "Cookie": jar.header() },
    });
    jar.absorb(res);
    var body = await res.text();
    return { status: res.status, body: body, location: res.headers.get("location") };
  }
  async function post(path, contentType, payload) {
    var res = await fetch(origin + path, {
      method:   "POST",
      redirect: "manual",
      headers: {
        "Content-Type": contentType,
        "Origin":       origin,
        "Cookie":       jar.header(),
        "X-CSRF-Token": csrf,
      },
      body: payload,
    });
    jar.absorb(res);
    var body = await res.text();
    return { status: res.status, body: body, location: res.headers.get("location") };
  }
  return {
    get:  get,
    post: post,
    signIn: async function (address, password) {
      var page = await get("/sign-in");
      var found = /name="_csrf" value="([^"]*)"/.exec(page.body);
      csrf = found === null ? "" : found[1];
      return post("/sign-in", "application/x-www-form-urlencoded",
        "address=" + encodeURIComponent(address) +
        "&password=" + encodeURIComponent(password) +
        "&_csrf=" + encodeURIComponent(csrf));
    },
    jmap: function (methodCalls) {
      return post("/jmap/api", "application/json", JSON.stringify({
        using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        methodCalls: methodCalls,
      }));
    },
  };
}

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

// The store folder holding an account's inbox, and the identity of the
// first message in it. Both are read straight out of the database,
// which is how this file names things a signed in stranger has no
// legitimate route to and then proves the route stays shut.
function storeFolderOf(accountId) {
  return b.db.from(mailbox.FOLDERS).where({ account: accountId, wireName: "INBOX" }).first().folder;
}

function firstMessageIn(identity, storeFolder) {
  var rows = identity.messageStore.queryByModseq(storeFolder, { sinceModseq: 0, limit: 1 });
  return rows.length > 0 ? rows[0].objectid : "";
}

async function testSignInLandsOnTheAccountsOwnInbox(alice) {
  var landed = await alice.signIn("alice@example.com", ALICE_PASSWORD);
  count("signing in redirects rather than rendering the form again",
    landed.status === 302, landed.status + " " + landed.body.slice(0, 120));

  var inbox = await alice.get(landed.location);
  count("the redirect lands on a mailbox this account owns",
    inbox.status === 200, inbox.status);
  // The message store bootstraps a folder set of its own under the same
  // names. A redirect built from a constant lands on one of those, and
  // the page renders an empty mailbox that belongs to nobody while the
  // account's real mail sits in a folder the page never names.
  check("the mailbox it lands on is the one holding this account's mail",
    inbox.body.indexOf(ALICES_SUBJECT) !== -1);
  return inbox;
}

function testTheFolderListIsThisAccountsOwn(inbox, bobsFolder) {
  var listed = hrefTargets(inbox.body, FOLDER_LINK_RE);

  count("the folder list is the six mailboxes a fresh account owns, and nothing besides",
    listed.slice().sort().join(",") === DEFAULT_MAILBOXES.join(","), listed.join(","));

  // This fixture put a message in the inbox, so the page renders a
  // message link too, and that link sits under the same path the folder
  // rail links to. Asserting it is there keeps the count above honest:
  // without it the exact set could pass on a page that had nothing to
  // confuse it with.
  var messageLinks = hrefTargets(inbox.body, MESSAGE_LINK_RE);
  count("the page renders the message link that sits under the mailbox path",
    messageLinks.length > 0 && MESSAGE_ID_RE.test(messageLinks[0]),
    messageLinks.join(","));

  count("no folder row is named after a message",
    listed.filter(function (name) {
      return MESSAGE_ID_RE.test(name.slice(name.lastIndexOf("/") + 1));
    }).length === 0, listed.join(","));
  // A wire name carrying the hierarchy separator is the shape that
  // makes a folder collide with a message path, and the shape LIST
  // reads as a parent. Neither belongs in the default set.
  count("no folder row carries the hierarchy separator",
    listed.filter(function (name) { return name.indexOf("/") !== -1; }).length === 0,
    listed.join(","));

  count("no store folder name reaches the page",
    listed.filter(function (name) { return name.indexOf("mbx_") === 0; }).length === 0,
    listed.join(","));
  count("another account's store folder is not among them",
    listed.indexOf(bobsFolder) === -1, listed.join(","));
}

async function testAnotherAccountsFolderIsNotReadable(alice, bobsFolder, bobsMessage) {
  var folderPage = await alice.get("/mail?folder=" + encodeURIComponent(bobsFolder));
  count("a URL carrying another account's store folder is refused",
    folderPage.status === 404, folderPage.status);
  check("the refusal carries none of that account's mail",
    folderPage.body.indexOf(BOBS_SUBJECT) === -1);

  var messagePage = await alice.get("/mail/" + encodeURIComponent(bobsMessage) +
    "?folder=" + encodeURIComponent(bobsFolder));
  count("a message inside another account's store folder is refused the same way",
    messagePage.status === 404, messagePage.status);
  check("the refusal carries none of that message's body",
    messagePage.body.indexOf(BOBS_BODY) === -1);

  // Reading is the loud half; a mutation through the same URL is the
  // half that leaves no page behind to notice.
  var mutation = await alice.post("/mail/actions?folder=" + encodeURIComponent(bobsFolder),
    "application/x-www-form-urlencoded",
    "action=trash&objectId=" + encodeURIComponent(bobsMessage));
  count("a mutation aimed at another account's store folder is refused as well",
    mutation.status === 404, mutation.status);
}

async function testJmapAnswersOnlyThisAccountsMailboxes(alice, accountId, bobsFolder, bobsMessage) {
  var mailboxes = await alice.jmap([["Mailbox/get", { accountId: accountId }, "c0"]]);
  count("JMAP answers Mailbox/get for a signed in account", mailboxes.status === 200,
    mailboxes.status);
  var list = JSON.parse(mailboxes.body).methodResponses[0][1].list;
  count("JMAP returns the six mailboxes this account owns",
    list.length === 6, String(list.length));
  count("no mailbox id is a store folder name",
    list.filter(function (m) { return String(m.id).indexOf("mbx_") === 0; }).length === 0,
    list.map(function (m) { return m.id; }).join(","));

  var query = await alice.jmap([
    ["Email/query", { accountId: accountId, filter: { inMailbox: bobsFolder } }, "c0"],
  ]);
  var ids = JSON.parse(query.body).methodResponses[0][1].ids;
  count("an Email/query naming another account's store folder returns nothing",
    Array.isArray(ids) && ids.length === 0, JSON.stringify(ids));

  var fetched = await alice.jmap([
    ["Email/get", { accountId: accountId, ids: [bobsMessage] }, "c0"],
  ]);
  var answer = JSON.parse(fetched.body).methodResponses[0][1];
  count("an Email/get naming another account's message answers not found",
    answer.list.length === 0 && answer.notFound.length === 1,
    JSON.stringify(answer.notFound));
  check("the Email/get answer carries none of that message's content",
    fetched.body.indexOf(BOBS_SUBJECT) === -1 && fetched.body.indexOf(BOBS_BODY) === -1);
}

async function run() {
  var root = helpers.tempDir("isolation");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var listener = null;
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         "mx.example.com",
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: "example.com" });
    var alice = await identity.accounts.create({
      address: "alice@example.com", password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@example.com", password: BOB_PASSWORD });

    identity.mailbox.appendMessage("INBOX",
      message(ALICES_SUBJECT, alice.address, "alice body"), { actor: { id: alice.id } });
    identity.mailbox.appendMessage("INBOX",
      message(BOBS_SUBJECT, bob.address, BOBS_BODY), { actor: { id: bob.id } });

    var bobsFolder = storeFolderOf(bob.id);
    var bobsMessage = firstMessageIn(identity, bobsFolder);
    count("the two accounts hold their inboxes in different store folders",
      bobsFolder.length > 0 && bobsFolder !== storeFolderOf(alice.id), bobsFolder);
    count("the message under test is in the other account's inbox",
      bobsMessage.length > 0, bobsMessage);

    listener = blamepost.web.serve(wiringFor(cfg, identity));
    var ports = await listener.start();
    var session = client("http://" + LOOPBACK + ":" + ports.http);

    var inbox = await testSignInLandsOnTheAccountsOwnInbox(session);
    testTheFolderListIsThisAccountsOwn(inbox, bobsFolder);
    await testAnotherAccountsFolderIsNotReadable(session, bobsFolder, bobsMessage);
    await testJmapAnswersOnlyThisAccountsMailboxes(session, alice.id, bobsFolder, bobsMessage);

    await listener.stop({ timeoutMs: 2000 });
    listener = null;
  } finally {
    if (listener !== null) {
      try { await listener.stop({ timeoutMs: 2000 }); }
      catch (_e) { /* the assertion that failed is the result, not this */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "cross-account-isolation", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
