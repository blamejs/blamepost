// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What happens to a message when two filings reach one mailbox at once.
 *
 * RFC 9051 section 2.3.1.1 gives every message in a mailbox a unique
 * identifier that ascends and is never handed out twice, and the folder
 * carries the next one it will issue. A move is a new message in the
 * mailbox it arrives in (section 6.4.8), so it takes that mailbox's next
 * identifier rather than carrying its old one across, and the adapter's
 * own table enforces the uniqueness with an index on the folder and the
 * identifier together.
 *
 * That index is the last line rather than the first. Reaching it means
 * the identifier was already decided, and by then the message store has
 * already been told to move the message: the store row lands in the
 * destination, the row binding the message to a folder and to its
 * identifier does not, and the two sides disagree. This adapter answers
 * a client from the intersection of them, so a message in that state is
 * in no folder any protocol lists, and no delete verb can name it
 * either, because every one of them resolves an identifier against the
 * same intersection. Two rows in the database, one message nobody can
 * reach, and nothing on any wire says so.
 *
 * There is exactly one way for two filings to overlap in this process.
 * The database handle is one synchronous handle and the server is one
 * process, so a run of statements with no `await` in it cannot be cut in
 * half. An `await` between reading the counter and writing the rows that
 * consume it is the whole of the opening: both callers read the same
 * value, both file under it, and the second one fails after its other
 * half has already been committed.
 *
 * So the interleaving here is driven rather than raced. Calling the verb
 * without awaiting it runs its body up to its first `await` and no
 * further, which puts both callers past the read with neither past the
 * write, every time and on any machine. A test that started two clients
 * and hoped would pass on a quiet runner and report a mail loss as a
 * flake.
 *
 * Three shapes are driven, because they fail differently:
 *
 *   - Two moves into one destination.
 *   - Two moves with a delivery landing between them, which is the
 *     arrival path taking an identifier out of the same counter while
 *     both moves are suspended.
 *   - Two moves back into the inbox, which is the one folder POP3 can
 *     see, so the message a concurrent filing produced is asked for by
 *     a client that has no folder vocabulary at all.
 *
 * What is asserted is not that the second call fails cleanly. It is that
 * every message stays REACHABLE afterwards: listed and readable over
 * IMAP, answered over JMAP, downloadable over POP3, with identifiers
 * that ascend and never repeat.
 *
 * Run standalone: node test/layer-2-integration/mailbox-uid-allocation.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
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

// Where the concurrent filings land. Not Trash, so nothing here is a
// soft delete and no retention decision is in the way of the question
// being asked.
var DESTINATION = "Archive";

// Distinctive enough that finding one in a FETCH or a RETR is proof that
// message is still there rather than a coincidence of ordinary words.
var PAIR_FIRST    = "filed-first-of-a-concurrent-pair";
var PAIR_SECOND   = "filed-second-of-a-concurrent-pair";
var SPLIT_FIRST   = "filed-either-side-of-an-arrival-one";
var SPLIT_SECOND  = "filed-either-side-of-an-arrival-two";
var ARRIVED       = "delivered-between-two-suspended-moves";
var WITNESS       = "left-in-the-inbox-untouched";

// One message already in the destination before anything is filed into
// it, so the counter the concurrent filings read is above its opening
// value. Without it a fix that happened to write the opening value would
// read as a pass.
var SEEDED = "already-in-the-destination";

var count = helpers.count;

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

// ---- what the volume says, which is where the disagreement lives -----------

function storeFolderOf(identity, accountId, wireName) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var found = folders.filter(function (f) { return f.name === wireName; })[0];
  return found ? found.storeName : "";
}

// Every message identifier the message store holds in one folder.
function objectIdsIn(identity, storeFolder) {
  return identity.messageStore.queryByModseq(storeFolder, { sinceModseq: 0 })
    .map(function (row) { return row.objectid; });
}

// Every adapter row naming this message, in any folder. The folder is
// deliberately not part of the query: a row left behind by a filing that
// stopped halfway is in the folder the message came from, so a count
// scoped to the destination would miss exactly the case this file is
// about.
function adapterRowsFor(objectId) {
  return b.db.from(mailbox.MESSAGES).where({ objectid: objectId }).all();
}

// The counter the folder will issue next, read from the row that holds
// it rather than inferred from what is in the folder.
function folderCounter(identity, accountId, wireName) {
  var storeFolder = storeFolderOf(identity, accountId, wireName);
  var row = b.db.from(mailbox.FOLDERS).where({ folder: storeFolder }).first();
  return row ? row.uidnext : -1;
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

// One folder as a client that just connected sees it: how many messages
// it reports, what the next identifier will be, the identifiers already
// in it, and the bodies behind them.
async function imapView(ctx, wireName, label) {
  var client = await imapSession(ctx.ports.imap, ctx.caPem, ctx.alice.address, label);
  client.send("v0 SELECT " + wireName);
  var selected = await client.read(/^v0 (OK|NO|BAD)/m, "SELECT answered");
  client.send("v1 UID FETCH 1:* (UID BODY[])");
  var fetched = await client.read(/^v1 (OK|NO|BAD)/m, "UID FETCH answered");
  client.send("v2 LOGOUT");
  client.close();

  var exists  = /^\* (\d+) EXISTS/m.exec(selected);
  var uidnext = /UIDNEXT (\d+)/.exec(selected);
  var uids = [];
  var seen = /UID (\d+)/g;
  var m;
  while ((m = seen.exec(fetched)) !== null) uids.push(parseInt(m[1], 10));
  return {
    exists:     exists === null ? -1 : parseInt(exists[1], 10),
    uidnext:    uidnext === null ? -1 : parseInt(uidnext[1], 10),
    uids:       uids,
    selected:   selected,
    transcript: fetched,
  };
}

// What a client reconnecting to the maildrop sees. Read from a session
// of its own, because RFC 1939 gives one session an exclusive view that
// its own marks have already changed.
async function pop3Drop(ctx, label) {
  var session = await pop3Session(ctx.ports.pop3, ctx.caPem, ctx.alice.address, label);
  session.send("STAT");
  var stat = await session.read(/^\+OK \d+ \d+/m, "STAT answered");
  session.send("UIDL");
  var uidl = await session.read(/^\.\r\n/m, "UIDL answered");
  var bodies = "";
  var found = /^\+OK (\d+) /m.exec(stat);
  var held = found === null ? 0 : parseInt(found[1], 10);
  for (var i = 1; i <= held; i += 1) {
    session.send("RETR " + i);
    bodies += await session.read(/^\.\r\n/m, "RETR answered");
  }
  session.send("QUIT");
  await session.read(/^\+OK /m, "QUIT answered");
  session.close();
  return { count: held, uidl: uidl, bodies: bodies };
}

// ---- the shared verdict on one concurrent filing ---------------------------

// Everything that has to hold however the two calls interleaved. The
// identifiers are read back from the rows rather than predicted, because
// which suspended call resumes first is the framework's business; what
// this server owes is that neither of them collides and neither message
// is stranded.
function bothFilingsLandedWhole(ctx, filed, wireName) {
  var storeFolder = storeFolderOf(ctx.identity, ctx.alice.id, wireName);
  var inStore = objectIdsIn(ctx.identity, storeFolder);
  var uids = [];
  for (var i = 0; i < filed.length; i += 1) {
    var rows = adapterRowsFor(filed[i].objectId);
    count("the message the " + filed[i].which + " filing named has exactly one row " +
      "binding it to a folder",
      rows.length === 1, filed[i].marker + ": " + JSON.stringify(rows.map(function (r) {
        return r.folder + "#" + r.uid;
      })));
    count("and that row is in " + wireName + " rather than in the folder it came from",
      rows.length === 1 && rows[0].folder === storeFolder,
      filed[i].marker + ": " + (rows.length === 1 ? rows[0].folder : "") + " vs " + storeFolder);
    count("the message store agrees the message is there, so the two sides did not " +
      "come apart",
      inStore.indexOf(filed[i].objectId) !== -1, filed[i].marker);
    if (rows.length === 1) uids.push(rows[0].uid);
  }
  var distinct = uids.filter(function (uid, at) { return uids.indexOf(uid) === at; });
  count("the two filings took different identifiers out of the destination's counter",
    distinct.length === uids.length, JSON.stringify(uids));
  return uids;
}

// ---- the concurrency vectors -----------------------------------------------

// Two moves into one destination. Both bodies run to their first `await`
// before either resumes, which is the only interleaving this process has
// and the one the counter has to survive.
async function twoMovesIntoOneDestination(ctx, first, second) {
  var mail = ctx.identity.mailbox;
  var before = folderCounter(ctx.identity, ctx.alice.id, DESTINATION);

  var a = mail.moveObjects(ctx.actor, "INBOX", DESTINATION, [first.objectId]);
  var c = mail.moveObjects(ctx.actor, "INBOX", DESTINATION, [second.objectId]);
  var settled = await Promise.allSettled([a, c]);

  count("both filings completed rather than one of them failing after its other " +
    "half had already been committed",
    settled[0].status === "fulfilled" && settled[1].status === "fulfilled",
    settled.map(function (s) {
      return s.status + (s.reason ? ": " + String(s.reason.message || s.reason) : "");
    }).join(" | "));

  var uids = bothFilingsLandedWhole(ctx, [
    { objectId: first.objectId,  marker: first.marker,  which: "first" },
    { objectId: second.objectId, marker: second.marker, which: "second" },
  ], DESTINATION);

  var after = folderCounter(ctx.identity, ctx.alice.id, DESTINATION);
  count("the destination's counter moved past every identifier it issued, so the " +
    "next arrival cannot be handed one of these again",
    uids.length > 0 && after > Math.max.apply(null, uids),
    "next " + after + " over " + JSON.stringify(uids) + " (was " + before + ")");
  return uids;
}

// The same overlap with a delivery landing in the middle of it. An
// arrival is a synchronous run, so it takes an identifier out of the
// same counter while both moves are suspended on their own `await`, and
// a move that resumes with the value it read before the arrival hands
// out one the arrival already used.
async function twoMovesEitherSideOfAnArrival(ctx, first, second) {
  var mail = ctx.identity.mailbox;

  var a = mail.moveObjects(ctx.actor, "INBOX", DESTINATION, [first.objectId]);
  var arrival = mail.appendMessage(DESTINATION, message(ARRIVED, ctx.alice.address),
    { actor: ctx.actor });
  var c = mail.moveObjects(ctx.actor, "INBOX", DESTINATION, [second.objectId]);
  var settled = await Promise.allSettled([a, c]);

  count("both filings around the arrival completed",
    settled[0].status === "fulfilled" && settled[1].status === "fulfilled",
    settled.map(function (s) {
      return s.status + (s.reason ? ": " + String(s.reason.message || s.reason) : "");
    }).join(" | "));

  var uids = bothFilingsLandedWhole(ctx, [
    { objectId: first.objectId,  marker: first.marker,  which: "first" },
    { objectId: second.objectId, marker: second.marker, which: "second" },
  ], DESTINATION);

  var arrivedRows = adapterRowsFor(arrival.objectid);
  count("the message that arrived between them kept its own row",
    arrivedRows.length === 1, JSON.stringify(arrivedRows.map(function (r) { return r.uid; })));
  count("and its identifier is not one either filing also took",
    arrivedRows.length === 1 && uids.indexOf(arrivedRows[0].uid) === -1,
    (arrivedRows.length === 1 ? String(arrivedRows[0].uid) : "") + " vs " + JSON.stringify(uids));
  return { moved: uids, arrived: arrival.objectid };
}

// The way back. POP3 reads the inbox and has no folder vocabulary at
// all, so a message filed into it by a concurrent pair is the one a POP3
// client has to be able to download.
async function twoMovesBackIntoTheInbox(ctx, first, second) {
  var mail = ctx.identity.mailbox;

  var a = mail.moveObjects(ctx.actor, DESTINATION, "INBOX", [first.objectId]);
  var c = mail.moveObjects(ctx.actor, DESTINATION, "INBOX", [second.objectId]);
  var settled = await Promise.allSettled([a, c]);

  count("both filings back into the inbox completed",
    settled[0].status === "fulfilled" && settled[1].status === "fulfilled",
    settled.map(function (s) {
      return s.status + (s.reason ? ": " + String(s.reason.message || s.reason) : "");
    }).join(" | "));

  return bothFilingsLandedWhole(ctx, [
    { objectId: first.objectId,  marker: first.marker,  which: "first" },
    { objectId: second.objectId, marker: second.marker, which: "second" },
  ], "INBOX");
}

// ---- the clients that have to agree ----------------------------------------

async function imapCanListAndReadEveryFiledMessage(ctx, wireName, markers, label) {
  var view = await imapView(ctx, wireName, label);
  count("an IMAP client finds " + markers.length + " messages in " + wireName,
    view.exists === markers.length, String(view.exists) + " " + visible(view.selected));
  var distinct = view.uids.filter(function (uid, at) { return view.uids.indexOf(uid) === at; });
  count("every identifier the client is shown is its own",
    distinct.length === view.uids.length, JSON.stringify(view.uids));
  count("and the folder's next identifier is above all of them, which is what stops " +
    "one being issued twice",
    view.uids.length > 0 && view.uidnext > Math.max.apply(null, view.uids),
    "UIDNEXT " + view.uidnext + " over " + JSON.stringify(view.uids));
  for (var i = 0; i < markers.length; i += 1) {
    count("the client can read " + markers[i] + " back, body and all",
      view.transcript.indexOf(markers[i]) !== -1, visible(view.transcript));
  }
  return view;
}

async function jmapCanAnswerForEveryFiledMessage(ctx, session, wireName, filed) {
  var ids = filed.map(function (f) { return f.objectId; });
  var answer = await session.jmap([
    ["Email/get", {
      accountId:  ctx.alice.id,
      ids:        ids,
      properties: ["subject", "mailboxIds"],
    }, "g0"],
  ]);
  count("JMAP answers Email/get for the filed messages", answer.status === 200,
    String(answer.status));
  var view = browser.answer(answer, 0)[1];
  count("a JMAP client is answered for every one of them rather than told they are gone",
    Array.isArray(view.list) && view.list.length === ids.length &&
    (view.notFound || []).length === 0,
    JSON.stringify(view.notFound) + " " + JSON.stringify((view.list || []).map(function (e) {
      return e.id;
    })));
  for (var i = 0; i < (view.list || []).length; i += 1) {
    count("and told it is in " + wireName,
      Object.prototype.hasOwnProperty.call(view.list[i].mailboxIds || {}, wireName),
      JSON.stringify(view.list[i].mailboxIds));
  }
}

async function pop3CanDownloadEveryMessageLeftInTheInbox(ctx, markers, label) {
  var drop = await pop3Drop(ctx, label);
  count("the maildrop holds " + markers.length + " messages", drop.count === markers.length,
    String(drop.count) + " " + visible(drop.uidl));
  for (var i = 0; i < markers.length; i += 1) {
    count("a POP3 client can download " + markers[i],
      drop.bodies.indexOf(markers[i]) !== -1, visible(drop.bodies));
  }
}

// ---- one running server ----------------------------------------------------

async function withServer(fn) {
  var root    = helpers.tempDir("uid-alloc");
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
      actor:    { id: alice.id, roles: ["account"] },
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

// Put one message in a folder and hand back the identity the store gave
// it, read as the row the folder gained rather than by position in a
// listing.
function appendAndIdentify(identity, alice, wireName, marker) {
  var stored = identity.mailbox.appendMessage(wireName, message(marker, alice.address),
    { actor: { id: alice.id } });
  return { marker: marker, objectId: stored.objectid, uid: stored.uid };
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await withServer(async function (ctx) {
    var pairFirst   = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", PAIR_FIRST);
    var pairSecond  = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", PAIR_SECOND);
    var splitFirst  = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", SPLIT_FIRST);
    var splitSecond = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", SPLIT_SECOND);
    var witness     = appendAndIdentify(ctx.identity, ctx.alice, "INBOX", WITNESS);

    count("every planted message has an identity the store issued",
      [pairFirst, pairSecond, splitFirst, splitSecond, witness]
        .filter(function (m) { return typeof m.objectId === "string" && m.objectId.length > 0; })
        .length === 5);

    var seeded = appendAndIdentify(ctx.identity, ctx.alice, DESTINATION, SEEDED);
    count("the destination starts with a message in it, so its counter is not at its " +
      "opening value", seeded.uid >= 1, String(seeded.uid));

    var session = browser.browserAt("http://" + LOOPBACK + ":" + ctx.httpPort);
    var landed = await session.signIn("alice@" + DOMAIN, ALICE_PASSWORD);
    count("the account can sign in, because the JMAP methods are behind the door",
      landed.status === 302, landed.status + " " + String(landed.location));

    await twoMovesIntoOneDestination(ctx, pairFirst, pairSecond);
    await imapCanListAndReadEveryFiledMessage(ctx, DESTINATION,
      [SEEDED, PAIR_FIRST, PAIR_SECOND], "imap-after-concurrent-pair");
    await jmapCanAnswerForEveryFiledMessage(ctx, session, DESTINATION,
      [pairFirst, pairSecond]);

    var split = await twoMovesEitherSideOfAnArrival(ctx, splitFirst, splitSecond);
    await imapCanListAndReadEveryFiledMessage(ctx, DESTINATION,
      [SEEDED, PAIR_FIRST, PAIR_SECOND, SPLIT_FIRST, SPLIT_SECOND, ARRIVED],
      "imap-after-arrival-between-moves");
    await jmapCanAnswerForEveryFiledMessage(ctx, session, DESTINATION,
      [splitFirst, splitSecond, { objectId: split.arrived, marker: ARRIVED }]);

    await pop3CanDownloadEveryMessageLeftInTheInbox(ctx, [WITNESS], "pop3-inbox-emptied");

    await twoMovesBackIntoTheInbox(ctx, pairFirst, pairSecond);
    await imapCanListAndReadEveryFiledMessage(ctx, DESTINATION,
      [SEEDED, SPLIT_FIRST, SPLIT_SECOND, ARRIVED], "imap-after-filing-out-again");
    await imapCanListAndReadEveryFiledMessage(ctx, "INBOX",
      [WITNESS, PAIR_FIRST, PAIR_SECOND], "imap-after-filing-back");
    await pop3CanDownloadEveryMessageLeftInTheInbox(ctx,
      [WITNESS, PAIR_FIRST, PAIR_SECOND], "pop3-after-filing-back");
  });

  return helpers.getChecks();
}

module.exports = { name: "mailbox-uid-allocation", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
