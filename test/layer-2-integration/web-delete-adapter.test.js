// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the browser interface and JMAP leave behind when they delete or
 * file a message, measured on a running server.
 *
 * A message here is three things, not one. The message store holds the
 * row a protocol reads; the mailbox adapter holds the row binding that
 * message to a folder and to the UID an IMAP client addresses it by;
 * and the sealed original octets sit under `blobs/`, which is what
 * IMAP `BODY[]` and POP3 `RETR` both return. A caller that drives the
 * mail agent on its own moves or destroys the first of the three and
 * leaves the other two where they were.
 *
 * Both halves of that are worth a socket.
 *
 * A hard delete driven that way reports the message destroyed and
 * leaves its plaintext-bearing blob sealed on the volume, with an
 * adapter row still pointing at it. Nothing on the wire says so,
 * because the adapter intersects its rows with the store's before it
 * answers a client, so an orphan is invisible rather than wrong. The
 * only place the difference shows is the volume itself, which is why
 * this file counts rows and stats files instead of trusting a listing.
 *
 * A move driven that way is louder and worse. The store row goes to
 * Trash and the adapter row stays in the inbox, so the message is in
 * neither folder on IMAP while the browser still lists it, and the one
 * verb that could erase it answers not-in-folder from both ends. That
 * is a message which is unlistable, unreadable and unerasable at the
 * same time.
 *
 * So the vectors are: purge from the browser, destroy over JMAP, and
 * file into Trash from the browser, each asserted against the store,
 * the adapter's own rows, the sealed file on disk, and then IMAP and
 * POP3 as the clients that have to agree with all of it. A message
 * under a preservation order runs through every one of them and has to
 * come out the other side readable, with the reader never told it went.
 *
 * Messages are put in place through the adapter's `appendMessage`,
 * which is the call inbound delivery makes once a message has been
 * accepted. What is under test is the delete, so the arrival is set up
 * rather than driven.
 *
 * Run standalone: node test/layer-2-integration/web-delete-adapter.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// One folder per surface, so a delete driven on one does not carry a
// message another is about to ask for. POP3 has no folder vocabulary
// and reads the inbox, so the inbox is where the move vectors run.
var WEB_FOLDER  = "Archive";
var JMAP_FOLDER = "Junk";

// Distinctive enough that finding one in a page, a FETCH or a RETR is
// proof that message is still there rather than a coincidence of
// ordinary words in a page of markup.
var WEB_PURGED   = "browser-purged-message";
var WEB_HELD     = "browser-held-message";
var WEB_FAULTED  = "browser-faulted-purge-message";
var JMAP_PURGED  = "jmap-destroyed-message";
var JMAP_HELD    = "jmap-held-message";
var TRASH_FIRST  = "trashed-then-purged-message";
var TRASH_SECOND = "trashed-then-expunged-message";
var MOVED_BY_FORM = "filed-by-the-move-form-message";
var MOVED_BY_JMAP = "filed-by-a-jmap-client-message";
var WITNESS      = "left-alone-message";

// Where the two move vectors file their message. Neither carries the
// Trash role, so the move is an ordinary filing rather than the soft
// delete the Trash button performs.
var FORM_TARGET = "Drafts";
var JMAP_TARGET = "Sent";

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

function message(marker, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + marker.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body of " + marker + ".\r\n", "utf8");
}

// ---- what the volume says, which is the half no client can see -------------

function storeFolderOf(identity, accountId, wireName) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var found = folders.filter(function (f) { return f.name === wireName; })[0];
  return found ? found.storeName : "";
}

function objectIdsIn(identity, storeFolder) {
  return identity.messageStore.queryByModseq(storeFolder, { sinceModseq: 0 })
    .map(function (row) { return row.objectid; });
}

// Every adapter row naming this message, in any folder. The folder is
// deliberately not part of the query: a row left behind by a half
// finished move is in the folder the message came from, and one left
// behind by a half finished delete is in the folder it was deleted
// from, so a count scoped to one folder would miss whichever case it
// was not written for.
function adapterRowsFor(objectId) {
  return b.db.from(mailbox.MESSAGES).where({ objectid: objectId }).count();
}

function adapterFolderOf(objectId) {
  var row = b.db.from(mailbox.MESSAGES).where({ objectid: objectId }).first();
  return row ? row.folder : "";
}

// The sealed file behind one message, found through the row that names
// its digest, which is the same map the delete path reads. Captured
// before the delete, because the row that names the digest is one of
// the things the delete is supposed to remove.
function blobPathFor(identity, objectId) {
  var row = b.db.from(mailbox.MESSAGES).where({ objectid: objectId }).first();
  if (!row) return "";
  var digest = row.blobDigest;
  return nodePath.join(identity.mailbox.describe().blobDir,
    digest.slice(0, 2), digest.slice(2, 4), digest);
}

// ---- a browser's view of the HTTP surface ----------------------------------

// The session cookie and the CSRF cookie are both set by the server and
// both have to come back on the next request, so this holds a jar the
// way a browser does. The token is re-read from every page that carries
// one, because a page rendered after the session changed is the page
// whose token is current.
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

function browser(origin) {
  var jar = cookieJar();
  var csrf = "";

  function absorbToken(body) {
    var found = /name="_csrf" value="([^"]*)"/.exec(body);
    if (found !== null) csrf = found[1];
  }

  async function get(path) {
    var res = await fetch(origin + path, {
      redirect: "manual",
      headers:  { "Cookie": jar.header() },
    });
    jar.absorb(res);
    var body = await res.text();
    absorbToken(body);
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
    action: function (wireName, fields) {
      return post("/mail/actions?folder=" + encodeURIComponent(wireName),
        "application/x-www-form-urlencoded", fields);
    },
    signIn: async function (address, password) {
      await get("/sign-in");
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

// ---- protocol sessions -----------------------------------------------------

async function imapSession(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
  await session.read(/^a1 OK/m, "authenticated");
  return session;
}

async function pop3Session(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\+OK /m, "greeting");
  session.send("STLS");
  await session.read(/^\+OK /m, "STLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("USER " + address);
  await session.read(/^(\+OK|-ERR)/m, "USER answered");
  session.send("PASS " + ALICE_PASSWORD);
  await session.read(/^\+OK /m, "authenticated");
  return session;
}

// What a client reconnecting to the maildrop sees: how many messages it
// holds and which identities they carry. Read from a session of its own
// rather than from one that has already acted, because RFC 1939 gives
// one session an exclusive view that its own marks have already changed.
async function pop3Drop(port, caPem, address, label) {
  var session = await pop3Session(port, caPem, address, label);
  session.send("STAT");
  var stat = await session.read(/^\+OK \d+ \d+/m, "STAT answered");
  session.send("UIDL");
  var uidl = await session.read(/^\.\r\n/m, "UIDL answered");
  session.send("QUIT");
  await session.read(/^\+OK /m, "QUIT answered");
  session.close();
  var found = /^\+OK (\d+) /m.exec(stat);
  return {
    count: found === null ? -1 : parseInt(found[1], 10),
    uidl:  uidl,
  };
}

// One IMAP session, one folder, and the number of messages in it. A
// fresh SELECT each time, because the question is what a client
// connecting now would find rather than what one connection still
// remembers.
async function imapExists(port, caPem, address, wireName, label) {
  var client = await imapSession(port, caPem, address, label);
  client.send("s0 SELECT " + wireName);
  var selected = await client.read(/^s0 (OK|NO|BAD)/m, "SELECT answered");
  client.send("s1 LOGOUT");
  client.close();
  var found = /^\* (\d+) EXISTS/m.exec(selected);
  return { exists: found === null ? -1 : parseInt(found[1], 10), transcript: selected };
}

// ---- the browser purge -----------------------------------------------------

// Two messages named in one purge, one of them under a preservation
// order. The ordinary one has to leave every one of the three places a
// message lives; the held one has to stay in all three, and the reader
// has to be told that something was kept rather than that everything
// went.
async function theBrowserPurgeTakesTheRowAndTheOctets(ctx, session, planted) {
  var ordinaryBlob = blobPathFor(ctx.identity, planted.ordinaryId);
  var heldBlob     = blobPathFor(ctx.identity, planted.heldId);
  count("the purged message has sealed octets on disk to begin with",
    ordinaryBlob.length > 0 && nodeFs.existsSync(ordinaryBlob), ordinaryBlob);
  count("so does the one under a preservation order",
    heldBlob.length > 0 && nodeFs.existsSync(heldBlob), heldBlob);

  var purge = await session.action(WEB_FOLDER,
    "action=purge" +
    "&objectId=" + encodeURIComponent(planted.ordinaryId) +
    "&objectId=" + encodeURIComponent(planted.heldId));
  count("the purge button redirects rather than erroring", purge.status === 302,
    purge.status + " " + purge.body.slice(0, 120));
  count("and the reader is told some messages were kept rather than that all went",
    String(purge.location).indexOf("notice=purge-refused") !== -1, purge.location);

  var left = objectIdsIn(ctx.identity, planted.folder);
  count("the message store keeps the held message and nothing else",
    left.length === 1 && left[0] === planted.heldId, JSON.stringify(left));

  count("the adapter row for the purged message is gone as well",
    adapterRowsFor(planted.ordinaryId) === 0, String(adapterRowsFor(planted.ordinaryId)));
  count("and so are its sealed octets, rather than being left readable on the volume",
    nodeFs.existsSync(ordinaryBlob) === false, ordinaryBlob);

  count("the held message keeps its adapter row",
    adapterRowsFor(planted.heldId) === 1, String(adapterRowsFor(planted.heldId)));
  count("and its octets are still on the volume for whoever asks for them",
    nodeFs.existsSync(heldBlob), heldBlob);

  var page = await session.get("/mail?folder=" + encodeURIComponent(WEB_FOLDER));
  count("the browser still lists the held message",
    page.body.indexOf(WEB_HELD) !== -1, String(page.status));
  count("and no longer lists the purged one",
    page.body.indexOf(WEB_PURGED) === -1, String(page.status));
}

async function imapAgreesWithTheBrowserPurge(ctx, planted) {
  var client = await imapSession(ctx.ports.imap, ctx.caPem, ctx.alice.address, "imap-after-purge");
  client.send("p0 SELECT " + WEB_FOLDER);
  var selected = await client.read(/^p0 (OK|NO|BAD)/m, "SELECT answered");
  count("an IMAP client finds one message left in that folder",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  client.send("p1 FETCH 1 BODY[]");
  var fetched = await client.read(/^p1 (OK|NO|BAD)/m, "FETCH answered");
  count("the one left is the held message, still readable body and all",
    /^p1 OK/m.test(fetched) && fetched.indexOf(WEB_HELD) !== -1, visible(fetched));
  count("and the purged message's body is not served from the folder",
    fetched.indexOf(WEB_PURGED) === -1, visible(fetched));

  client.send("p2 LOGOUT");
  client.close();

  count("the purged message has no adapter row in any folder",
    adapterRowsFor(planted.ordinaryId) === 0, adapterFolderOf(planted.ordinaryId));
}

// ---- the purge the volume would not finish ---------------------------------

// The purge button has three answers and the third one had never been
// driven. `purged` says everything went. `purge-refused` says something
// is deliberately keeping a message, which is a rule the reader can act
// on. `purge-faulted` says neither: the message was destroyed and one of
// the two acts that remove it from this layer did not happen, so its
// sealed octets are still on the volume with nothing on either layer
// naming them. That is not the reader's to fix and reopening the folder
// does not explain it, which is why it is a notice of its own rather
// than folded into the refusal beside it. A page that reported retention
// here would name a rule that is not in force; one that reported success
// would say plaintext had gone when it is still sitting there.
//
// The volume is what refuses, so the volume is what is faulted: the blob
// release is synchronous, so it is the synchronous unlink that answers
// EPERM. Nothing about the route or the adapter is stood in for.
async function theBrowserPurgeSaysSoWhenTheVolumeWillNotFinish(ctx, session, planted) {
  var blob = blobPathFor(ctx.identity, planted.objectId);
  count("the message about to be purged has sealed octets on disk",
    blob.length > 0 && nodeFs.existsSync(blob), blob);

  // The digest is the file's own name, which is what the release unlinks
  // and therefore the fragment the fault has to match. A fault aimed at
  // anything else refuses nothing and reports green.
  var digest = nodePath.basename(blob);
  var fault = helpers.installSyncRemovalFault(digest);
  var purge;
  try {
    purge = await session.action(WEB_FOLDER,
      "action=purge&objectId=" + encodeURIComponent(planted.objectId));
  } finally {
    fault.remove();
  }

  count("the purge redirects rather than erroring", purge.status === 302,
    purge.status + " " + purge.body.slice(0, 120));
  count("the volume was actually asked to release those octets, so this is the refusal " +
    "being measured rather than a fault that was never in the way",
  fault.calls > 0, JSON.stringify({ calls: fault.calls, attempts: fault.attempts }));
  count("and the reader is told the removal could not be completed, rather than being " +
    "told a rule kept the message or that everything went",
  String(purge.location).indexOf("notice=purge-faulted") !== -1, purge.location);

  // The substance behind the notice. A page saying the right word over
  // the wrong state would satisfy the line above on its own.
  count("the message store row is gone, so the message really was destroyed",
    objectIdsIn(ctx.identity, planted.folder).indexOf(planted.objectId) === -1,
    JSON.stringify(objectIdsIn(ctx.identity, planted.folder)));
  count("its sealed octets are still on the volume, which is what the notice is about",
    nodeFs.existsSync(blob), blob);

  // And the reader is not shown a message that no longer exists. The
  // browser lists the intersection of the two layers, so a leftover on
  // one of them is invisible rather than wrong, which is precisely why
  // the notice is the only thing that can report this.
  var page = await session.get("/mail?folder=" + encodeURIComponent(WEB_FOLDER));
  count("the browser no longer lists the message it destroyed",
    page.body.indexOf(WEB_FAULTED) === -1, String(page.status));
}

// ---- the JMAP destroy ------------------------------------------------------

async function theJmapDestroyTakesTheRowAndTheOctets(ctx, session, planted) {
  var ordinaryBlob = blobPathFor(ctx.identity, planted.ordinaryId);
  var heldBlob     = blobPathFor(ctx.identity, planted.heldId);
  count("the message about to be destroyed has sealed octets on disk",
    ordinaryBlob.length > 0 && nodeFs.existsSync(ordinaryBlob), ordinaryBlob);

  var answer = await session.jmap([
    ["Email/set", {
      accountId: ctx.alice.id,
      destroy:   [planted.ordinaryId, planted.heldId],
    }, "c0"],
  ]);
  count("JMAP answers Email/set for a signed in account", answer.status === 200,
    String(answer.status));
  var result = JSON.parse(answer.body).methodResponses[0][1];

  count("the ordinary message is reported destroyed",
    Array.isArray(result.destroyed) && result.destroyed.length === 1 &&
    result.destroyed[0] === planted.ordinaryId, JSON.stringify(result.destroyed));
  var refusal = result.notDestroyed[planted.heldId];
  count("the held one comes back with the SetError type JMAP defines for a refusal",
    refusal && refusal.type === "forbidden", JSON.stringify(refusal));
  count("and names the preservation order as the reason",
    refusal && refusal.description === "legal-hold", JSON.stringify(refusal));

  var left = objectIdsIn(ctx.identity, planted.folder);
  count("the message store keeps the held message and nothing else",
    left.length === 1 && left[0] === planted.heldId, JSON.stringify(left));

  count("the destroyed message's adapter row went with it",
    adapterRowsFor(planted.ordinaryId) === 0, adapterFolderOf(planted.ordinaryId));
  count("and its sealed octets are off the volume rather than orphaned there",
    nodeFs.existsSync(ordinaryBlob) === false, ordinaryBlob);

  count("the held message keeps its adapter row",
    adapterRowsFor(planted.heldId) === 1, String(adapterRowsFor(planted.heldId)));
  count("and its octets are still on the volume",
    nodeFs.existsSync(heldBlob), heldBlob);

  var got = await session.jmap([
    ["Email/get", {
      accountId:  ctx.alice.id,
      ids:        [planted.ordinaryId, planted.heldId],
      properties: ["subject"],
    }, "c0"],
  ]);
  var view = JSON.parse(got.body).methodResponses[0][1];
  count("a client asking for both is answered with the held one only",
    view.list.length === 1 && view.list[0].id === planted.heldId,
    JSON.stringify(view.list.map(function (m) { return m.id; })));
  count("and told the destroyed one is not found",
    view.notFound.length === 1 && view.notFound[0] === planted.ordinaryId,
    JSON.stringify(view.notFound));
}

async function imapAgreesWithTheJmapDestroy(ctx) {
  var client = await imapSession(ctx.ports.imap, ctx.caPem, ctx.alice.address, "imap-after-destroy");
  client.send("j0 SELECT " + JMAP_FOLDER);
  var selected = await client.read(/^j0 (OK|NO|BAD)/m, "SELECT answered");
  count("an IMAP client finds one message left in the folder JMAP deleted from",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  client.send("j1 FETCH 1 BODY[]");
  var fetched = await client.read(/^j1 (OK|NO|BAD)/m, "FETCH answered");
  count("the one left is the held message, still readable",
    /^j1 OK/m.test(fetched) && fetched.indexOf(JMAP_HELD) !== -1, visible(fetched));
  count("and the destroyed message's body is not served",
    fetched.indexOf(JMAP_PURGED) === -1, visible(fetched));

  client.send("j2 LOGOUT");
  client.close();
}

// ---- the browser Trash button ----------------------------------------------

// The soft delete. Nothing is destroyed, so the whole assertion is that
// every protocol looks in the same place afterwards: the message left
// the inbox and is in Trash, on the wire as much as on the page.
async function theTrashButtonFilesWhereEveryProtocolLooks(ctx, session, trashed) {
  var filed = await session.action("INBOX",
    "action=trash&objectId=" + encodeURIComponent(trashed.objectId));
  count("the Trash button redirects rather than erroring", filed.status === 302,
    filed.status + " " + filed.body.slice(0, 120));
  count("and the reader is told the message was filed",
    String(filed.location).indexOf("notice=trashed") !== -1, filed.location);

  // The wire first, because that is what a person notices: a message
  // filed by the browser that no client can find is the whole failure,
  // and the volume assertions below say why it happened.
  var client = await imapSession(ctx.ports.imap, ctx.caPem, ctx.alice.address, "imap-after-trash");
  client.send("t0 SELECT Trash");
  var trash = await client.read(/^t0 (OK|NO|BAD)/m, "SELECT answered");
  count("an IMAP client finds the message in Trash rather than in neither folder",
    /^\* 1 EXISTS/m.test(trash), visible(trash));

  client.send("t1 FETCH 1 (FLAGS BODY[])");
  var fetched = await client.read(/^t1 (OK|NO|BAD)/m, "FETCH answered");
  count("it is readable there, body and all",
    /^t1 OK/m.test(fetched) && fetched.indexOf(trashed.marker) !== -1, visible(fetched));
  count("and it carries the deleted mark the browser put on it",
    /\\Deleted/.test(fetched), visible(fetched));

  client.send("t2 LOGOUT");
  client.close();

  var page = await session.get("/mail?folder=Trash");
  count("the browser lists it in Trash too, which is the half that never broke",
    page.body.indexOf(trashed.marker) !== -1, String(page.status));

  var inbox = await imapExists(ctx.ports.imap, ctx.caPem, ctx.alice.address, "INBOX",
    "imap-inbox-after-trash");
  count("and the inbox no longer holds it",
    inbox.exists === trashed.inboxAfter, String(inbox.exists));

  // Why: the row binding the message to a folder is the adapter's, and
  // it is the piece a move driven through the agent alone leaves in the
  // folder the message came from.
  var trashFolder = storeFolderOf(ctx.identity, ctx.alice.id, "Trash");
  count("the message store has the message in Trash",
    objectIdsIn(ctx.identity, trashFolder).indexOf(trashed.objectId) !== -1, trashFolder);
  count("and the adapter row followed it there rather than staying in the inbox",
    adapterFolderOf(trashed.objectId) === trashFolder,
    adapterFolderOf(trashed.objectId) + " vs " + trashFolder);
  count("with one row and not two", adapterRowsFor(trashed.objectId) === 1,
    String(adapterRowsFor(trashed.objectId)));
}

// A message the browser filed into Trash has to still be erasable, from
// the browser and from a client, because the failure this file exists
// for left it in neither folder and therefore reachable by neither.
async function aTrashedMessageIsStillPurgeableFromTheBrowser(ctx, session, trashed) {
  var blob = blobPathFor(ctx.identity, trashed.objectId);
  count("the trashed message still has its sealed octets before the purge",
    blob.length > 0 && nodeFs.existsSync(blob), blob);

  var purge = await session.action("Trash",
    "action=purge&objectId=" + encodeURIComponent(trashed.objectId));
  count("purging it out of Trash redirects rather than erroring", purge.status === 302,
    purge.status + " " + purge.body.slice(0, 120));
  count("and the reader is told it went, with nothing kept",
    String(purge.location).indexOf("notice=purged") !== -1, purge.location);

  var trashFolder = storeFolderOf(ctx.identity, ctx.alice.id, "Trash");
  count("the message store no longer holds it",
    objectIdsIn(ctx.identity, trashFolder).indexOf(trashed.objectId) === -1, trashFolder);
  count("the adapter row went with it",
    adapterRowsFor(trashed.objectId) === 0, adapterFolderOf(trashed.objectId));
  count("and so did the sealed octets",
    nodeFs.existsSync(blob) === false, blob);
}

async function aTrashedMessageIsStillExpungeableOverImap(ctx, trashed) {
  var blob = blobPathFor(ctx.identity, trashed.objectId);
  count("the trashed message still has its sealed octets before the EXPUNGE",
    blob.length > 0 && nodeFs.existsSync(blob), blob);

  var client = await imapSession(ctx.ports.imap, ctx.caPem, ctx.alice.address, "imap-expunge-trash");
  client.send("e0 SELECT Trash");
  var selected = await client.read(/^e0 (OK|NO|BAD)/m, "SELECT answered");
  count("the client finds the trashed message waiting in Trash",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  // No STORE first: the browser's Trash button already set \Deleted,
  // which is what makes the message a candidate. A client that had to
  // set the mark itself would be testing its own STORE rather than what
  // the browser left behind.
  client.send("e1 EXPUNGE");
  var expunged = await client.read(/^e1 (OK|NO|BAD)/m, "EXPUNGE answered");
  count("EXPUNGE succeeds", /^e1 OK/m.test(expunged), visible(expunged));
  count("and the client is told the message went",
    /^\* 1 EXPUNGE/m.test(expunged), visible(expunged));

  client.send("e2 SELECT Trash");
  var after = await client.read(/^e2 (OK|NO|BAD)/m, "SELECT answered");
  count("a fresh SELECT finds Trash empty", /^\* 0 EXISTS/m.test(after), visible(after));

  client.send("e3 LOGOUT");
  client.close();

  count("the adapter row is gone", adapterRowsFor(trashed.objectId) === 0,
    adapterFolderOf(trashed.objectId));
  count("and the sealed octets with it", nodeFs.existsSync(blob) === false, blob);
}

// ---- filing a message somewhere that is not Trash --------------------------

// The move form and the JMAP `mailboxIds` patch are the same operation
// as the Trash button without the mark, and they break the same way: a
// store row that moved and an adapter row that did not leaves the
// message in neither folder for every client that speaks a wire
// protocol. Both are driven, because a rule several surfaces share
// needs a vector per surface.
async function aFiledMessageIsWhereEveryProtocolLooks(ctx, filed) {
  var client = await imapSession(ctx.ports.imap, ctx.caPem, ctx.alice.address, filed.label);
  client.send("f0 SELECT " + filed.wireName);
  var selected = await client.read(/^f0 (OK|NO|BAD)/m, "SELECT answered");
  count("an IMAP client finds it in " + filed.wireName, /^\* 1 EXISTS/m.test(selected),
    visible(selected));

  client.send("f1 FETCH 1 BODY[]");
  var fetched = await client.read(/^f1 (OK|NO|BAD)/m, "FETCH answered");
  count("and it is readable there, body and all",
    /^f1 OK/m.test(fetched) && fetched.indexOf(filed.marker) !== -1, visible(fetched));

  client.send("f2 LOGOUT");
  client.close();

  var inbox = await imapExists(ctx.ports.imap, ctx.caPem, ctx.alice.address, "INBOX",
    filed.label + "-inbox");
  count("and the inbox no longer holds it", inbox.exists === filed.inboxAfter,
    String(inbox.exists));

  var target = storeFolderOf(ctx.identity, ctx.alice.id, filed.wireName);
  count("the message store has the message in " + filed.wireName,
    objectIdsIn(ctx.identity, target).indexOf(filed.objectId) !== -1, target);
  count("and the adapter row followed it rather than staying in the inbox",
    adapterFolderOf(filed.objectId) === target,
    adapterFolderOf(filed.objectId) + " vs " + target);
  count("with one row and not two", adapterRowsFor(filed.objectId) === 1,
    String(adapterRowsFor(filed.objectId)));
}

async function theMoveFormFilesTheMessage(ctx, session, filed) {
  var moved = await session.action("INBOX",
    "action=move" +
    "&destination=" + encodeURIComponent(filed.wireName) +
    "&objectId=" + encodeURIComponent(filed.objectId));
  count("the move form redirects rather than erroring", moved.status === 302,
    moved.status + " " + moved.body.slice(0, 120));
  count("and the reader is told the message was moved",
    String(moved.location).indexOf("notice=moved") !== -1, moved.location);
  await aFiledMessageIsWhereEveryProtocolLooks(ctx, filed);
}

async function aJmapClientFilesTheMessage(ctx, session, filed) {
  var patch = {};
  patch[filed.objectId] = { mailboxIds: {} };
  patch[filed.objectId].mailboxIds[filed.wireName] = true;

  var answer = await session.jmap([
    ["Email/set", { accountId: ctx.alice.id, update: patch }, "c0"],
  ]);
  count("JMAP answers the mailboxIds patch", answer.status === 200, String(answer.status));
  var result = JSON.parse(answer.body).methodResponses[0][1];
  count("the update is reported as applied",
    Object.prototype.hasOwnProperty.call(result.updated, filed.objectId),
    JSON.stringify(result.notUpdated));
  await aFiledMessageIsWhereEveryProtocolLooks(ctx, filed);
}

// POP3 reads the inbox and nothing else, so what it has to agree with
// is that the two messages the browser filed have left it and the one
// nobody touched has not. A maildrop that still lists a filed message
// hands a client a message the browser says is in Trash.
async function pop3AgreesAboutTheInbox(ctx, filedIds, witnessId) {
  var drop = await pop3Drop(ctx.ports.pop3, ctx.caPem, ctx.alice.address, "pop3-after-filing");
  count("the maildrop holds the one message nothing was done to", drop.count === 1,
    String(drop.count));
  count("and its unique id is that message", drop.uidl.indexOf(witnessId) !== -1,
    visible(drop.uidl));
  for (var i = 0; i < filedIds.length; i += 1) {
    count("no message the browser filed out of the inbox is still in the maildrop",
      drop.uidl.indexOf(filedIds[i]) === -1, visible(drop.uidl));
  }

  var session = await pop3Session(ctx.ports.pop3, ctx.caPem, ctx.alice.address, "pop3-retr");
  session.send("RETR 1");
  var retrieved = await session.read(/^\.\r\n/m, "RETR answered");
  count("the message it does hold is retrievable, body and all",
    retrieved.indexOf(WITNESS) !== -1, visible(retrieved));
  session.send("QUIT");
  await session.read(/^\+OK /m, "QUIT answered");
  session.close();
}

// ---- one running server ----------------------------------------------------

async function withServer(fn) {
  var root    = helpers.tempDir("web-delete");
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
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
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
      ports:    { imap: sections.imap.port, pop3: sections.pop3.port },
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
    // `server.stop` leaves the store alone, deliberately: it belongs to
    // whoever opened it. The database handle behind it is one per
    // process, so a second server opened before this one closes would
    // find the first server's rows under its own temporary directory.
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

// Put one message in a folder and hand back the identity the store gave
// it, read as the row the folder gained rather than by position in a
// listing. Position is a property of the store's own counters, and a
// hard delete rewrites one of them, so a test naming a message by where
// it sits in a list can end up holding a different message.
function appendAndIdentify(identity, alice, wireName, marker) {
  var folder = storeFolderOf(identity, alice.id, wireName);
  var before = objectIdsIn(identity, folder);
  identity.mailbox.appendMessage(wireName, message(marker, alice.address),
    { actor: { id: alice.id } });
  var gained = objectIdsIn(identity, folder).filter(function (id) {
    return before.indexOf(id) === -1;
  });
  return {
    folder:   folder,
    marker:   marker,
    objectId: gained.length === 1 ? gained[0] : "",
  };
}

function plantPair(identity, alice, wireName, ordinaryMarker, heldMarker) {
  var ordinary = appendAndIdentify(identity, alice, wireName, ordinaryMarker);
  var held     = appendAndIdentify(identity, alice, wireName, heldMarker);
  identity.messageStore.setLegalHold([held.objectId], { hold: true });
  return { folder: ordinary.folder, ordinaryId: ordinary.objectId, heldId: held.objectId };
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await withServer(async function (ctx) {
    var web  = plantPair(ctx.identity, ctx.alice, WEB_FOLDER, WEB_PURGED, WEB_HELD);
    var jmap = plantPair(ctx.identity, ctx.alice, JMAP_FOLDER, JMAP_PURGED, JMAP_HELD);

    // The inbox carries the four the browser and a JMAP client will
    // file plus one nothing is done to, so a maildrop that empties
    // itself for the wrong reason cannot read as a pass.
    var first    = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", TRASH_FIRST);
    var second   = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", TRASH_SECOND);
    var byForm   = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", MOVED_BY_FORM);
    var byClient = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", MOVED_BY_JMAP);
    var witness  = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", WITNESS);

    count("every planted message has an identity the store issued",
      [web.ordinaryId, web.heldId, jmap.ordinaryId, jmap.heldId,
        first.objectId, second.objectId, byForm.objectId, byClient.objectId,
        witness.objectId]
        .filter(function (id) { return typeof id === "string" && id.length > 0; }).length === 9);

    var session = browser("http://" + LOOPBACK + ":" + ctx.httpPort);
    var landed = await session.signIn("alice@" + DOMAIN, ALICE_PASSWORD);
    count("the account can sign in to the browser surface", landed.status === 302,
      landed.status + " " + landed.body.slice(0, 120));

    await theBrowserPurgeTakesTheRowAndTheOctets(ctx, session, web);
    await imapAgreesWithTheBrowserPurge(ctx, web);

    // Planted here rather than up front, so the two vectors above keep
    // counting the folder they were written against. Nothing after this
    // reads WEB_FOLDER.
    var faulted = appendAndIdentify(ctx.identity, ctx.alice, WEB_FOLDER, WEB_FAULTED);
    await theBrowserPurgeSaysSoWhenTheVolumeWillNotFinish(ctx, session, faulted);

    await theJmapDestroyTakesTheRowAndTheOctets(ctx, session, jmap);
    await imapAgreesWithTheJmapDestroy(ctx);

    await theTrashButtonFilesWhereEveryProtocolLooks(ctx, session,
      { objectId: first.objectId, marker: TRASH_FIRST, inboxAfter: 4 });
    await aTrashedMessageIsStillPurgeableFromTheBrowser(ctx, session,
      { objectId: first.objectId, marker: TRASH_FIRST });

    await theTrashButtonFilesWhereEveryProtocolLooks(ctx, session,
      { objectId: second.objectId, marker: TRASH_SECOND, inboxAfter: 3 });
    await aTrashedMessageIsStillExpungeableOverImap(ctx,
      { objectId: second.objectId, marker: TRASH_SECOND });

    await theMoveFormFilesTheMessage(ctx, session, {
      objectId:   byForm.objectId,
      marker:     MOVED_BY_FORM,
      wireName:   FORM_TARGET,
      inboxAfter: 2,
      label:      "imap-after-move-form",
    });
    await aJmapClientFilesTheMessage(ctx, session, {
      objectId:   byClient.objectId,
      marker:     MOVED_BY_JMAP,
      wireName:   JMAP_TARGET,
      inboxAfter: 1,
      label:      "imap-after-jmap-move",
    });

    await pop3AgreesAboutTheInbox(ctx,
      [first.objectId, second.objectId, byForm.objectId, byClient.objectId],
      witness.objectId);
  });

  return helpers.getChecks();
}

module.exports = { name: "web-delete-adapter", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to
// aggregate the suite total. Printing any other wording still exits
// zero, so the run would read as passing while contributing nothing to
// the count, which is the output a file asserting nothing produces.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    // Set the code rather than calling process.exit, which would tear
    // the process down before the stack above is flushed.
    process.exitCode = 1;
  });
}
