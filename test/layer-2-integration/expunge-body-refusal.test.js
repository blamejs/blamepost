// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A hard delete the volume will not finish, and what each delete path
 * says about it afterwards.
 *
 * Destroying a message here is two acts on two stores. The message row
 * goes, and the sealed original octets under `blobs/` go with it once no
 * other row names them. The first act is a database write and the second
 * is a file removal, and a file removal is refused for reasons that have
 * nothing to do with the message: a mount that has gone read-only, a
 * permission an operator changed, another process holding the file open.
 * So a delete of several messages is a set of separate outcomes and any
 * one of them can be no.
 *
 * What these vectors measure is what happens to the rest of the set, and
 * what the caller is told. A removal allowed to raise takes the whole
 * expunge with it: every message behind the refused one keeps its row
 * while its store row has already gone, so it is addressable by nothing
 * and its body is pinned on the volume forever, and the client is handed
 * the file layer's own words in place of an answer about its mail.
 *
 * The refusal is produced by the volume rather than by a stand-in over
 * the removal, so the path under test is the shipped one. What stands at
 * the body's path is not a file, which is a state this server already
 * knows about on the way in, since the write path refuses a message
 * rather than writing over it, and it is the one removal refusal that
 * reads the same on every volume this server runs on. What is being
 * exercised is the removal, not the shape of what is under the name.
 *
 * Four callers reach the same delete path and each is measured here:
 * IMAP EXPUNGE and POP3 DELE at QUIT over a socket, the sessionless verb
 * JMAP `Email/set` `destroyed` and the browser interface drive, and the
 * account erasure that walks every mailbox one account holds.
 *
 * Run standalone: node test/layer-2-integration/expunge-body-refusal.test.js
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

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The adapter's own table, read here rather than imported so a rename
// shows up as a failing vector against the shipped schema.
var MESSAGES = "blamepost_mailbox_messages";

// POP3 reads the inbox and has no folder vocabulary, so the IMAP vectors
// take a folder of their own and the two never contend for a message.
var IMAP_FOLDER = "Archive";

// One account per caller. The wire vectors share one because the two
// listeners read different folders; the erasure destroys the account it
// runs on, and the sessionless verb wants a mailbox nothing else has
// been deleting from.
var WIRE_ADDRESS     = "wired@" + DOMAIN;
var ERASED_ADDRESS   = "erased@" + DOMAIN;
var OBJECTS_ADDRESS  = "objects@" + DOMAIN;
var WORM_ADDRESS     = "recorded@" + DOMAIN;

var count = helpers.count;

var plainResponse = wire.saslPlain;

function message(marker, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: " + to + "\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + marker + "@example.net>\r\n" +
    "\r\n" + "Body of " + marker + ".\r\n", "utf8");
}

function storeFolderOf(identity, accountId, wireName) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var found = folders.filter(function (f) { return f.name === wireName; })[0];
  return found ? found.storeName : "";
}

function rowsIn(storeFolder) {
  return b.db.from(MESSAGES).where({ folder: storeFolder }).orderBy("uid", "asc").all();
}

function blobPathOf(identity, digest) {
  return nodePath.join(identity.mailbox.describe().blobDir,
    digest.slice(0, 2), digest.slice(2, 4), digest);
}

// Put a message in a mailbox and answer with the row the adapter wrote
// for it, so a vector names a message by the digest its own row carries
// rather than by rebuilding one from the bytes.
function plant(identity, account, wireName, markers) {
  var folder = storeFolderOf(identity, account.id, wireName);
  var planted = [];
  markers.forEach(function (marker) {
    var before = rowsIn(folder).map(function (r) { return r.objectid; });
    identity.mailbox.appendMessage(wireName, message(marker, account.address),
      { actor: { id: account.id } });
    var gained = rowsIn(folder).filter(function (r) {
      return before.indexOf(r.objectid) === -1;
    });
    planted.push({
      marker:   marker,
      objectid: gained.length === 1 ? gained[0].objectid : "",
      digest:   gained.length === 1 ? gained[0].blobDigest : "",
      path:     gained.length === 1 ? blobPathOf(identity, gained[0].blobDigest) : "",
    });
  });
  return { folder: folder, messages: planted };
}

// Take the body out of the volume's reach, by leaving something at its
// path that a removal refuses. Answers with the same entry, so a vector
// reads which message it stuck.
function refuseRemovalOf(entry) {
  nodeFs.rmSync(entry.path, { force: true });
  nodeFs.mkdirSync(entry.path, { recursive: true });
  return entry;
}

function stillOnVolume(entry) {
  return nodeFs.existsSync(entry.path);
}

// A reply that names the operator's volume layout or the content digest
// of a stored message is answering a mailbox protocol's client with
// something no mailbox protocol owes it.
function namesTheVolume(reply, stuck) {
  return /blobs/.test(reply) || reply.indexOf(stuck.digest.slice(0, 16)) !== -1;
}

// ---- sessions ---------------------------------------------------------------

async function imapSession(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, ACCOUNT_PASSWORD));
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
  session.send("PASS " + ACCOUNT_PASSWORD);
  await session.read(/^\+OK /m, "authenticated");
  return session;
}

// ---- IMAP EXPUNGE -----------------------------------------------------------

// RFC 9051 section 6.4.3 gives EXPUNGE no refusal form, so what the
// client is owed is the untagged line for every message that left the
// mailbox and an OK. A message whose body could not be removed has still
// left: its store row is gone and no verb reaches it. Drawing no line for
// it leaves the client renumbering a mailbox around a message that is not
// in it, which is the same defect as drawing one for a message that is.
async function imapExpungeAnswersForTheWholeSet(port, caPem, address, planted, stuck) {
  var client = await imapSession(port, caPem, address, "imap-body-refused");

  client.send("c0 SELECT " + IMAP_FOLDER);
  var selected = await client.read(/^c0 (OK|NO|BAD)/m, "SELECT answered");
  count("the folder holds all three messages before the expunge",
    /^\* 3 EXISTS/m.test(selected), visible(selected));

  client.send("c1 STORE 1:3 +FLAGS (\\Deleted)");
  await client.read(/^c1 (OK|NO|BAD)/m, "STORE answered");

  client.send("c2 EXPUNGE");
  var expunged = await client.read(/^c2 (OK|NO|BAD)/m, "EXPUNGE answered");

  count("EXPUNGE completes with OK even though the volume would not remove one of the " +
    "stored bodies, because a file the volume held on to is not a reason to abandon the " +
    "messages behind it",
    /^c2 OK/m.test(expunged), visible(expunged));
  count("and an untagged EXPUNGE is drawn for every message that left the mailbox, so " +
    "the client renumbers around what actually went",
    (expunged.match(/^\* \d+ EXPUNGE/gm) || []).length === 3, visible(expunged));
  count("the reply names neither the volume layout nor the content digest of a stored " +
    "body, because a refusal from the file layer is answered to whoever asked to delete " +
    "their own mail",
    !namesTheVolume(expunged, stuck), visible(expunged));

  client.send("c3 SELECT " + IMAP_FOLDER);
  var after = await client.read(/^c3 (OK|NO|BAD)/m, "SELECT answered");
  count("a later session finds the mailbox empty, which is the state the untagged lines " +
    "described", /^\* 0 EXISTS/m.test(after), visible(after));

  client.send("c4 LOGOUT");
  client.close();

  count("every message behind the one whose body would not go was destroyed too, rather " +
    "than left bound to a mailbox with its store row already gone",
    rowsIn(planted.folder).length === 0,
    JSON.stringify({ rows: rowsIn(planted.folder).length }));

  var released = planted.messages.filter(function (entry) {
    return entry !== stuck && !stillOnVolume(entry);
  });
  count("the bodies the volume did give up are gone from disk",
    released.length === planted.messages.length - 1,
    JSON.stringify({ released: released.length }));
  count("and the one it refused is still there, which is what the report is about",
    stillOnVolume(stuck), stuck.path);
}

// ---- POP3 DELE at QUIT ------------------------------------------------------

// RFC 1939 section 6 does give this one a refusal form, and it is the
// form for exactly this case: the deletions happen in the UPDATE state
// and a commit that could not remove everything answers `-ERR some
// deleted messages not removed`. What the client must not be handed is
// the file layer's own sentence, which says nothing it can act on and
// says a good deal about the operator's volume.
async function pop3CommitAnswersForTheWholeSet(port, caPem, address, planted, stuck) {
  var client = await pop3Session(port, caPem, address, "pop3-body-refused");

  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("the maildrop holds all three messages before the commit",
    /^\+OK 3 /m.test(stat), visible(stat));

  for (var n = 1; n <= 3; n += 1) {
    client.send("DELE " + n);
    await client.read(/^(\+OK|-ERR)/m, "DELE " + n + " answered");
  }

  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");

  count("a commit that could not remove one message's stored body answers -ERR",
    /^-ERR/m.test(quit), visible(quit));
  count("and it carries the wording RFC 1939 section 6 defines, rather than the file " +
    "layer's own sentence about the volume",
    /some deleted messages not removed/i.test(quit), visible(quit));
  count("the count in the reply says how much of what the client marked actually went, " +
    "so a client configured to delete after download knows what it still has",
    /2 of 3 went/.test(quit), visible(quit));
  count("and the reply names neither the volume layout nor a content digest",
    !namesTheVolume(quit, stuck), visible(quit));
  client.close();

  count("the two messages behind the refused one were destroyed rather than abandoned",
    rowsIn(planted.folder).length === 0,
    JSON.stringify({ rows: rowsIn(planted.folder).length }));

  var released = planted.messages.filter(function (entry) {
    return entry !== stuck && !stillOnVolume(entry);
  });
  count("their bodies went with them",
    released.length === planted.messages.length - 1,
    JSON.stringify({ released: released.length }));

  var next = await pop3Session(port, caPem, address, "pop3-recount");
  next.send("STAT");
  var recount = await next.read(/^\+OK \d+ \d+/m, "STAT answered");
  count("a client reconnecting is offered nothing it can no longer read",
    /^\+OK 0 /m.test(recount), visible(recount));
  next.send("QUIT");
  await next.read(/^(\+OK|-ERR)/m, "QUIT answered");
  next.close();
}

// ---- the sessionless verb ---------------------------------------------------

// JMAP `Email/set` `destroyed` and the browser interface both name
// messages rather than flagging them, and both report the reason for
// anything that stayed. The reason vocabulary is what a caller passes
// through to its own protocol, so the token matters as much as the split.
async function expungeObjectsNamesTheBodyItCouldNotRemove(identity, account, planted, stuck) {
  var actor = { id: account.id, address: account.address, roles: ["account"] };
  var ids = planted.messages.map(function (entry) { return entry.objectid; });

  var outcome = null;
  var thrown = null;
  try {
    outcome = await identity.mailbox.expungeObjects(actor, "INBOX", ids);
  } catch (e) { thrown = e; }

  count("the verb answers with a report rather than raising, because the message it was " +
    "asked about first has already been destroyed by the time the volume refuses its body",
    thrown === null && outcome !== null,
    thrown === null ? "nothing was thrown" : helpers.formatErr(thrown));
  if (outcome === null) return;

  count("the message whose body the volume kept is reported as one that did not go",
    outcome.refused.length === 1 && outcome.refused[0].id === stuck.objectid,
    JSON.stringify(outcome.refused));
  count("under a reason a caller can pass through to its own protocol",
    outcome.refused.length === 1 && outcome.refused[0].reason === "body-not-removed",
    JSON.stringify(outcome.refused));
  count("and the message behind it is reported as destroyed, because it was",
    outcome.deleted.length === 1 && outcome.deleted[0] !== stuck.objectid,
    JSON.stringify(outcome.deleted));
}

// ---- the account erasure ----------------------------------------------------

// The erasure walks every mailbox one account holds and reports what it
// could not destroy, split by whether something is deliberately keeping
// the record or something went wrong with it. A body still on the volume
// is the second: nothing chose to keep it, and the operator answering an
// erasure request has to be told that mail this server was asked to lose
// is still there.
async function theErasureSeparatesWhatWentFromWhatStayed(identity, account, planted, stuck) {
  var removed = null;
  var thrown = null;
  try {
    removed = await identity.accounts["delete"]({
      id:      account.id,
      reason:  "erasure requested by the account holder",
      destroy: true,
    });
  } catch (e) { thrown = e; }

  count("the erasure answers with a report rather than raising over a body the volume " +
    "would not remove",
    thrown === null && removed !== null,
    thrown === null ? "nothing was thrown" : helpers.formatErr(thrown));
  if (removed === null) return;

  count("the message whose body did go is counted as destroyed, rather than reported as " +
    "held back along with the one that did not",
    removed.mailErased === 1, JSON.stringify({ mailErased: removed.mailErased }));

  count("the one whose body stayed is reported as a fault rather than as something kept " +
    "on purpose, because nothing chose to keep it",
    removed.mailFailed.length === 1 && removed.mailFailed[0].preserved !== true &&
    removed.mailFailed[0].objectid === stuck.objectid,
    JSON.stringify(removed.mailFailed));
  count("and nothing is reported as preserved, because no order and no floor was in force",
    removed.mailPreserved.length === 0, JSON.stringify(removed.mailPreserved));

  count("the report names the message and the mailbox it was in, so the operator can go " +
    "and look for it",
    removed.mailFailed.length === 1 &&
    String(removed.mailFailed[0].record).indexOf("INBOX") !== -1,
    JSON.stringify(removed.mailFailed));

  count("the mail rows this account held are gone, including the one whose body stayed, " +
    "so the body is reported by the volume walk rather than pinned by a row nothing " +
    "reaches",
    rowsIn(planted.folder).length === 0,
    JSON.stringify({ rows: rowsIn(planted.folder).length }));
  count("and the body itself is still on the volume, which is what the report says",
    stillOnVolume(stuck), stuck.path);

  // The row is written through the trail's emit path, which can land
  // after the erasure has answered, so the trail is polled for it.
  function incompleteRows() {
    return b.db.from("audit_log").all().filter(function (r) {
      return r.action === "blamepost.mail.mailbox.destruction_incomplete";
    });
  }
  var landed = true;
  try {
    await helpers.waitUntil(function () { return incompleteRows().length >= 1; }, {
      timeoutMs: 5000,
      label:     "expunge-body-refusal: the destruction_incomplete row reaches the trail",
    });
  } catch (_timedOut) { landed = false; }
  count("the volume's refusal is on the audit trail with the digest it refused, because " +
    "IMAP has no word for it and the operator has to hear it somewhere",
    landed, JSON.stringify(incompleteRows().map(function (r) { return r.action; })));
}

// ---- the row, which is the other half of the same act -----------------------

// Destroying a message here is two acts and the body is the second of
// them. The first is the row this layer keeps beside the store's, and it
// can be refused in its own right: write-once triggers on the table
// refuse a DELETE below the application entirely, which is what a volume
// under a records-retention posture has. The store row has already gone
// by the time it is reached, so this is the same class one act earlier,
// and it owes the same answer.
//
// It runs last and it is not undone. The declaration stands on the
// table for the rest of this volume's life, so anything after it would be
// measuring a mailbox nothing can delete from.
async function aRefusedRowAnswersForItselfToo(port, caPem, address, planted) {
  b.db.declareWorm({ tables: [MESSAGES] });

  var client = await imapSession(port, caPem, address, "imap-row-refused");
  client.send("d0 SELECT " + IMAP_FOLDER);
  var selected = await client.read(/^d0 (OK|NO|BAD)/m, "SELECT answered");
  count("the second folder holds both messages before the expunge",
    /^\* 2 EXISTS/m.test(selected), visible(selected));

  client.send("d1 STORE 1:2 +FLAGS (\\Deleted)");
  await client.read(/^d1 (OK|NO|BAD)/m, "STORE answered");

  client.send("d2 EXPUNGE");
  var expunged = await client.read(/^d2 (OK|NO|BAD)/m, "EXPUNGE answered");

  count("EXPUNGE completes rather than handing the client the table's own refusal, " +
    "because the store row of every message it named is already destroyed and the " +
    "client has to renumber around them",
    /^d2 OK/m.test(expunged), visible(expunged));
  count("and a line is drawn for each of them, so the mailbox the client is holding " +
    "matches the one the server has",
    (expunged.match(/^\* \d+ EXPUNGE/gm) || []).length === 2, visible(expunged));

  client.send("d3 LOGOUT");
  client.close();

  count("the rows the table would not give up are still there, paired with the bodies " +
    "they name rather than leaving octets nothing accounts for",
    rowsIn(planted.folder).length === 2,
    JSON.stringify({ rows: rowsIn(planted.folder).length }));

  var kept = planted.messages.filter(function (entry) { return stillOnVolume(entry); });
  count("and every body is still on the volume, because the row naming it never went",
    kept.length === planted.messages.length, JSON.stringify({ kept: kept.length }));
}

// ---- one running server -----------------------------------------------------

async function withServer(fn) {
  var root    = helpers.tempDir("expunge-body-refusal");
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
    var wired = await identity.accounts.create({
      address: WIRE_ADDRESS, password: ACCOUNT_PASSWORD });
    var erased = await identity.accounts.create({
      address: ERASED_ADDRESS, password: ACCOUNT_PASSWORD });
    var objects = await identity.accounts.create({
      address: OBJECTS_ADDRESS, password: ACCOUNT_PASSWORD });
    var recorded = await identity.accounts.create({
      address: WORM_ADDRESS, password: ACCOUNT_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
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
      caPem:    leaf.ca,
      identity: identity,
      wired:    wired,
      erased:   erased,
      objects:  objects,
      recorded: recorded,
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
  await withServer(async function (ctx) {
    // The refused body is the LOWEST identifier in every set, because the
    // delete path walks the set in that order. It is the position that
    // leaves messages behind it to abandon, which is the half of this
    // that a refusal on the last message would not measure.
    var imap = plant(ctx.identity, ctx.wired, IMAP_FOLDER,
      ["archive-stuck", "archive-second", "archive-third"]);
    var pop3 = plant(ctx.identity, ctx.wired, "INBOX",
      ["inbox-stuck", "inbox-second", "inbox-third"]);
    var swept = plant(ctx.identity, ctx.erased, "INBOX",
      ["erased-stuck", "erased-second"]);
    var named = plant(ctx.identity, ctx.objects, "INBOX",
      ["objects-stuck", "objects-second"]);
    var sealed = plant(ctx.identity, ctx.recorded, IMAP_FOLDER,
      ["recorded-first", "recorded-second"]);

    var imapStuck    = refuseRemovalOf(imap.messages[0]);
    var pop3Stuck    = refuseRemovalOf(pop3.messages[0]);
    var sweptStuck   = refuseRemovalOf(swept.messages[0]);
    var namedStuck   = refuseRemovalOf(named.messages[0]);

    count("every mailbox holds the messages it was given, and one body per mailbox is " +
      "out of the volume's reach before anything is deleted",
      rowsIn(imap.folder).length === 3 && rowsIn(pop3.folder).length === 3 &&
      rowsIn(swept.folder).length === 2 && rowsIn(named.folder).length === 2 &&
      stillOnVolume(imapStuck) && stillOnVolume(pop3Stuck) &&
      stillOnVolume(sweptStuck) && stillOnVolume(namedStuck),
      JSON.stringify({
        imap: rowsIn(imap.folder).length, pop3: rowsIn(pop3.folder).length,
        erased: rowsIn(swept.folder).length, objects: rowsIn(named.folder).length,
      }));

    await imapExpungeAnswersForTheWholeSet(ctx.ports.imap, ctx.caPem,
      ctx.wired.address, imap, imapStuck);
    await pop3CommitAnswersForTheWholeSet(ctx.ports.pop3, ctx.caPem,
      ctx.wired.address, pop3, pop3Stuck);
    await expungeObjectsNamesTheBodyItCouldNotRemove(ctx.identity, ctx.objects,
      named, namedStuck);
    await theErasureSeparatesWhatWentFromWhatStayed(ctx.identity, ctx.erased,
      swept, sweptStuck);
    // Last, because what it declares stands on the table for the rest of
    // this volume's life.
    await aRefusedRowAnswersForItselfToo(ctx.ports.imap, ctx.caPem,
      ctx.recorded.address, sealed);
  });

  return helpers.getChecks();
}

module.exports = {
  name:      "expunge-body-refusal",
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
