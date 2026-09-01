// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a hard delete has to remove, and why the mail agent alone does
 * not remove it.
 *
 * `b.mail.agent.expunge` is the gate: it reads the legal hold flag and
 * the retention floor and runs the destructive SQL on whatever survives
 * both. What it destroys is the store's row. It knows nothing about the
 * two things the adapter keeps beside that row, and it cannot, because
 * they are this application's and not the framework's: the row carrying
 * the IMAP UID, and the original message octets written sealed under
 * `blobs/` because IMAP BODY[] and POP3 RETR both have to return the
 * message exactly as it arrived.
 *
 * So a caller that reaches for the agent directly gets a delete that
 * reports success, empties the mailbox, and leaves the message body
 * sealed on disk with a row pointing at it. Under a right-to-erasure
 * request that is the whole of the failure: the message is gone from
 * every listing and still readable from the volume.
 *
 * It compounds. The octets are content addressed and shared between
 * accounts, so the file is removed only when the last row referencing it
 * goes. An orphaned row is a reference that never goes, which means a
 * later delete of the same message through the correct path also leaves
 * the file behind.
 *
 * Both halves are asserted below: what the agent alone leaves, which is
 * the reason `blamepost.mail.mailbox.expungeObjects` exists, and what
 * that verb removes.
 *
 * Run standalone: node test/layer-1-state/mailbox-expunge-path.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var mailbox = require("../../lib/mail/mailbox");
var store   = require("../../lib/store");

// The assertion that quotes the value that produced the verdict, and
// the counter behind it, are both the shared ones. A file that kept its
// own counter reported a total that only covered the assertions made
// through its own wrapper, so a `check` written directly ran and was
// invisible in the number the runner aggregated.
var count = helpers.count;

async function refuses(label, code, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + " " + thrown.message);
}

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";

function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    // The shape a signed in session carries, roles and no scopes array.
    // `b.permissions` reads a scopes array in preference to the roles,
    // so an empty one here would be an actor granted nothing rather than
    // an actor with a role, and every verb below would refuse.
    roles:     ["account"],
  };
}

function message(subject, body) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: Recipient <alice@example.com>\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

function storeFolderOf(handle, actor, wireName) {
  return handle.mailbox.accountFolders(actor)
    .filter(function (f) { return f.name === wireName; })[0].storeName;
}

// The sealed file behind one message, found through the row that names
// its digest, which is the same map the delete path reads.
function blobPathFor(handle, storeFolder, objectId) {
  var rows = b.db.from(mailbox.MESSAGES)
    .where({ folder: storeFolder, objectid: objectId }).all();
  if (rows.length !== 1) return "";
  var digest = rows[0].blobDigest;
  return nodePath.join(handle.mailbox.describe().blobDir,
    digest.slice(0, 2), digest.slice(2, 4), digest);
}

function adapterRowsFor(storeFolder, objectId) {
  return b.db.from(mailbox.MESSAGES).where({ folder: storeFolder, objectid: objectId }).count();
}

// How many rows the STORE holds for one object in one of its folders,
// read back through the store rather than through the adapter's table.
// The append and the hard delete under test here are the store's own,
// so the count that says whether they worked is the store's own too.
function rawCopiesOf(rawStore, storeFolder, objectId) {
  return rawStore.queryByModseq(storeFolder, {}).filter(function (r) {
    return r.objectid === objectId;
  }).length;
}

// ---- what the agent alone does not reach ------------------------------------

async function testTheAgentAloneLeavesTheOctets(handle, alice) {
  var appended = handle.mailbox.appendMessage("INBOX", message("agent-only", "still here"),
    { actor: alice });
  var folder = storeFolderOf(handle, alice, "INBOX");
  var blobPath = blobPathFor(handle, folder, appended.objectid);

  count("the adapter wrote the original octets sealed under blobs/",
    blobPath.length > 0 && nodeFs.existsSync(blobPath), blobPath);

  // Built the way a surface with no wire session would build it, over
  // the same store, which is the composition this file is about.
  var agent = b.mail.agent.create({ store: handle.messageStore, dispatch: { mode: "local" } });
  var verdict = await agent.expunge({
    actor: alice, folder: folder, objectIds: [appended.objectid],
  });
  count("the agent reports the message destroyed",
    Array.isArray(verdict.deleted) && verdict.deleted.length === 1,
    JSON.stringify(verdict));
  count("and the store no longer holds it",
    handle.messageStore.fetchByObjectId(folder, appended.objectid) === null);

  count("but the adapter's row is still there, because the agent does not own it",
    adapterRowsFor(folder, appended.objectid) === 1,
    String(adapterRowsFor(folder, appended.objectid)));
  count("and the message body is still sealed on the volume, readable to anyone " +
    "holding the vault", nodeFs.existsSync(blobPath), blobPath);

  return { folder: folder, objectid: appended.objectid, blobPath: blobPath };
}

// ---- what the adapter verb removes ------------------------------------------

async function testTheAdapterVerbRemovesBoth(handle, alice) {
  var appended = handle.mailbox.appendMessage("Archive", message("through-the-verb", "gone"),
    { actor: alice });
  var folder = storeFolderOf(handle, alice, "Archive");
  var blobPath = blobPathFor(handle, folder, appended.objectid);
  count("the octets are on disk to begin with", nodeFs.existsSync(blobPath), blobPath);

  var outcome = await handle.mailbox.expungeObjects(alice, "Archive", [appended.objectid]);
  count("the verb reports the message destroyed",
    outcome.deleted.length === 1 && outcome.deleted[0] === appended.objectid &&
    outcome.refused.length === 0, JSON.stringify(outcome));
  count("the store no longer holds it",
    handle.messageStore.fetchByObjectId(folder, appended.objectid) === null);
  count("the adapter's row went with it",
    adapterRowsFor(folder, appended.objectid) === 0);
  count("and so did the sealed octets", nodeFs.existsSync(blobPath) === false, blobPath);
}

// The octets are content addressed, so one message delivered to two
// accounts is one file. The file goes when the last row referencing it
// goes and not before, or a delete in one mailbox empties another.
async function testASharedBlobSurvivesTheFirstDelete(handle, alice, bob) {
  var body = message("shared-copy", "one file, two mailboxes");
  var mine = handle.mailbox.appendMessage("INBOX", body, { actor: alice });
  var theirs = handle.mailbox.appendMessage("INBOX", body, { actor: bob });
  var aliceFolder = storeFolderOf(handle, alice, "INBOX");
  var bobFolder = storeFolderOf(handle, bob, "INBOX");

  var blobPath = blobPathFor(handle, aliceFolder, mine.objectid);
  count("both accounts' rows point at one file",
    blobPath === blobPathFor(handle, bobFolder, theirs.objectid), blobPath);

  await handle.mailbox.expungeObjects(alice, "INBOX", [mine.objectid]);
  count("deleting one account's copy leaves the file, because the other still " +
    "references it", nodeFs.existsSync(blobPath), blobPath);
  count("and the other account can still read its own copy",
    handle.mailbox.fetchRange(bob, "INBOX", "1", "BODY.PEEK[]", {})[0]
      .payload.indexOf("one file, two mailboxes") !== -1);

  await handle.mailbox.expungeObjects(bob, "INBOX", [theirs.objectid]);
  count("deleting the last copy takes the file", nodeFs.existsSync(blobPath) === false,
    blobPath);
}

// ---- the transaction the destructive SQL runs under -------------------------

// `b.mailStore` wraps its append and its hard delete in one transaction
// each, and runs it through whichever calling convention its backend
// offers. There are two and they look alike from outside: the framework
// database runs a transaction body straight away and returns what the
// body returned, while a driver in the better-sqlite3 family hands back
// something to call. The store decides which it has by whether the body
// actually RAN, so `b.db` goes in with nothing in between.
//
// The property worth holding is not which convention wins. It is that a
// backend offering NEITHER is refused rather than run outside a
// transaction. A half-written hard delete leaves the flag rows, the
// search index and the quota counters describing a message that is gone,
// and on the append path a commit followed by a throw is a caller
// retrying over mail that is already durably stored, so it lands twice.
// The refusal travels under one stable code, which is what these read.
async function testTheStoreKeepsItsDestructiveWorkAtomic(handle, alice) {
  var direct = b.db.transaction(function () { return 41 + 1; });
  count("the framework database runs a transaction body immediately and returns its value",
    direct === 42 && typeof direct !== "function", JSON.stringify(direct));

  var folder = storeFolderOf(handle, alice, "INBOX");
  var raw = b.mailStore.create({ backend: b.db, init: false });

  var appended = raw.appendMessage(folder, message("unwrapped-append", "one copy only"));
  count("the store appends with the framework database passed straight in as its backend",
    appended !== null && typeof appended.objectid === "string",
    JSON.stringify(appended && appended.objectid));
  count("and exactly one copy landed, so nothing committed and then threw for a sender " +
    "to retry over",
    rawCopiesOf(raw, folder, appended.objectid) === 1,
    String(rawCopiesOf(raw, folder, appended.objectid)));

  raw.hardExpunge(folder, [appended.objectid]);
  count("the same handle hard deletes the row it wrote, which is the path every EXPUNGE " +
    "ends at",
    rawCopiesOf(raw, folder, appended.objectid) === 0);

  // A backend whose `transaction` neither runs the body nor hands back
  // anything to run it with. Both destructive paths have to refuse it.
  var unusable = b.mailStore.create({
    backend: {
      prepare:     function (sql) { return b.db.prepare(sql); },
      transaction: function () { return null; },
    },
    init: false,
  });
  await refuses("an append that cannot be made atomic is refused rather than written",
    "mail-store/unusable-transaction", function () {
      return unusable.appendMessage(folder, message("never-written", "not atomic"));
    });

  // hardExpunge answers an empty id list before it reaches a
  // transaction, so the refusal needs a row that really is there.
  var victim = raw.appendMessage(folder, message("expunge-victim", "removed atomically"));
  await refuses("and so is a hard delete that cannot be made atomic",
    "mail-store/unusable-transaction", function () {
      return unusable.hardExpunge(folder, [victim.objectid]);
    });
  count("the message the refused delete named is still there, so the refusal came before " +
    "any row went",
    rawCopiesOf(raw, folder, victim.objectid) === 1);
  raw.hardExpunge(folder, [victim.objectid]);
}

// ---- moving a message is the same problem wearing a different verb ----------

// Filing a message into Trash is a move, not a delete, and it is the
// commonest thing anybody does to a message. The store moves its own
// row; the adapter's row, which is what binds a message to a folder and
// carries the UID an IMAP client addresses it by, moves only if
// something moves it.
//
// The failure is not a stale listing. The message leaves the folder it
// was in and never arrives in the one it went to, so it is in neither
// on IMAP and POP3 while the browser interface, which reads the store,
// still shows it. And because the adapter can no longer place it, the
// owner cannot destroy it from either end: it is unreadable, unlistable
// and unerasable at the same time.
async function testMovingKeepsTheMessageAddressable(handle, alice) {
  var appended = handle.mailbox.appendMessage("INBOX", message("filed-away", "moved me"),
    { actor: alice });
  var inbox = storeFolderOf(handle, alice, "INBOX");
  var trash = storeFolderOf(handle, alice, "Trash");
  var blobPath = blobPathFor(handle, inbox, appended.objectid);

  count("the message is in INBOX and not in Trash to begin with",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 1 &&
    handle.mailbox.selectFolder(alice, "Trash", {}).exists === 0);

  var moved = await handle.mailbox.moveObjects(alice, "INBOX", "Trash", [appended.objectid]);
  count("the move reports the message it filed",
    moved.moved.length === 1 && moved.moved[0] === appended.objectid, JSON.stringify(moved));

  count("the message left INBOX",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 0);
  count("and arrived in Trash, which is the half a bare store move loses",
    handle.mailbox.selectFolder(alice, "Trash", {}).exists === 1);
  count("the store agrees it is in Trash",
    handle.messageStore.queryByModseq(trash, { sinceModseq: 0 }).length === 1 &&
    handle.messageStore.queryByModseq(inbox, { sinceModseq: 0 }).length === 0);
  count("no adapter row is left naming the folder it came from",
    adapterRowsFor(inbox, appended.objectid) === 0);

  // RFC 9051 section 6.4.8: a message moved into a mailbox is a new
  // message there and takes that mailbox's next UID. A client that
  // resynchronises by UID against a stale one refetches the wrong
  // message or none at all.
  var addressed = handle.mailbox.fetchRange(alice, "Trash", "1:*", "UID", { useUid: false });
  var destination = handle.mailbox.selectFolder(alice, "Trash", {});
  count("it took a UID from the mailbox it arrived in",
    addressed.length === 1 && /^UID 1$/.test(addressed[0].payload), JSON.stringify(addressed));
  count("and the destination's UIDNEXT moved past it",
    destination.uidnext === 2, String(destination.uidnext));

  count("the body is still readable where it now is",
    handle.mailbox.fetchRange(alice, "Trash", "1", "BODY.PEEK[]", {})[0]
      .payload.indexOf("moved me") !== -1);

  // The whole point of filing into Trash is being able to empty it.
  var outcome = await handle.mailbox.expungeObjects(alice, "Trash", [appended.objectid]);
  count("and the owner can destroy it from the folder it was filed into",
    outcome.deleted.length === 1, JSON.stringify(outcome));
  count("which takes the sealed octets with it",
    nodeFs.existsSync(blobPath) === false, blobPath);
}

async function testTheMoveVerbRefusesWhatItCannotOwn(handle, alice, bob) {
  var appended = handle.mailbox.appendMessage("INBOX", message("stay-put", "mine"),
    { actor: alice });

  await refuses("a move without an authenticated account refuses rather than reaching " +
    "for a shared folder", "mailbox/no-actor", function () {
      return handle.mailbox.moveObjects(null, "INBOX", "Trash", [appended.objectid]);
    });
  await refuses("a move to a folder the account does not have is refused",
    "mailbox/no-folder", function () {
      return handle.mailbox.moveObjects(alice, "INBOX", "Nowhere", [appended.objectid]);
    });
  await refuses("a move from a folder to itself is refused rather than renumbering the " +
    "message in place", "mailbox/bad-move", function () {
      return handle.mailbox.moveObjects(alice, "INBOX", "inbox", [appended.objectid]);
    });

  var crossed = await handle.mailbox.moveObjects(bob, "INBOX", "Trash", [appended.objectid]);
  count("one account cannot move another account's message",
    crossed.moved.length === 0 && crossed.refused.length === 1 &&
    crossed.refused[0].reason === "not-in-folder", JSON.stringify(crossed));
  count("and the message stays where its owner left it",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 1);

  await handle.mailbox.expungeObjects(alice, "INBOX", [appended.objectid]);
}

// ---- the verb's own refusals ------------------------------------------------

async function testTheVerbRefusesWhatItCannotOwn(handle, alice, bob) {
  var appended = handle.mailbox.appendMessage("Junk", message("not-yours", "mine"),
    { actor: alice });

  await refuses("a delete without an authenticated account refuses rather than " +
    "reaching for a shared folder", "mailbox/no-actor", function () {
      return handle.mailbox.expungeObjects(null, "Junk", [appended.objectid]);
    });
  await refuses("a delete naming a folder the account does not have is refused",
    "mailbox/no-folder", function () {
      return handle.mailbox.expungeObjects(alice, "Nowhere", [appended.objectid]);
    });

  var crossed = await handle.mailbox.expungeObjects(bob, "Junk", [appended.objectid]);
  count("one account cannot destroy another account's message, and is told which " +
    "identifier its folder does not hold",
    crossed.deleted.length === 0 && crossed.refused.length === 1 &&
    crossed.refused[0].reason === "not-in-folder", JSON.stringify(crossed));
  count("the message it aimed at is untouched",
    handle.messageStore.fetchByObjectId(
      storeFolderOf(handle, alice, "Junk"), appended.objectid) !== null);

  var unknown = await handle.mailbox.expungeObjects(alice, "Junk", ["obj_nosuchmessage"]);
  count("an identifier no folder holds is refused by name rather than passed down to " +
    "a store that has no account to check it against",
    unknown.refused.length === 1 && unknown.refused[0].reason === "not-in-folder",
    JSON.stringify(unknown));

  var twice = await handle.mailbox.expungeObjects(alice, "Junk",
    [appended.objectid, appended.objectid]);
  count("the same identifier named twice is destroyed once, so the quota counters " +
    "are not decremented for a message that only existed once",
    twice.deleted.length === 1, JSON.stringify(twice));
}

// ---- erasing everything one account holds ------------------------------------

// The same argument one level up. Erasing an account row reaches one row
// in one table, so the mailboxes, the messages, the filter scripts, the
// annotations and the sealed bodies all survive it unless something
// walks them, and nothing else ever would: the body release is reference
// counted and the references are exactly the rows that stayed.
//
// What is driven here is the rest of what an account holds, beside the
// mail the body cases next door already measure. A filter script names
// the correspondents its owner sorts on and an annotation is whatever
// their client stored, so both are the account's own material and both
// have to go. And a POP3 session holding the maildrop holds RFC 1939
// section 3's exclusive lock over an address that can be provisioned
// again, so it ends with the mailbox rather than at the idle sweep,
// which is a reclaim for an abandoned session and not for an erased one.
async function testErasingAnAccountReachesEverythingItHolds(handle) {
  var made = await handle.accounts.create({
    address: "hana@example.com", password: ALICE_PASSWORD });
  var hana = actorFor(made);

  handle.mailbox.appendMessage("INBOX", message("erased-mail", "gone"), { actor: hana });
  // A second message filed somewhere else, because the erasure walks
  // every mailbox the account holds and a fixture with mail in one of
  // them would pass whether or not it walked past the first.
  var filed = handle.mailbox.appendMessage("INBOX", message("filed-elsewhere", "also gone"),
    { actor: hana });
  await handle.mailbox.moveObjects(hana, "INBOX", "Archive", [filed.objectid]);
  handle.mailbox.sieveScripts.put(hana, "sortmail", "require [\"fileinto\"];\n", {});
  handle.mailbox.setMetadata(hana, "INBOX", [
    { entry: "/private/comment", value: "a note the client stored" },
  ]);
  var drop = handle.mailbox.openPop3Drop(hana, {});
  count("the account holds mail in two mailboxes, a script, an annotation and an open " +
    "maildrop",
    b.db.from(mailbox.FOLDERS).where({ account: made.id }).count() > 0 &&
    b.db.from(mailbox.SCRIPTS).where({ account: made.id }).count() === 1 &&
    b.db.from(mailbox.METADATA).where({ account: made.id }).count() === 1 &&
    b.db.from(mailbox.MESSAGES).count() >= 2 && drop.count === 1,
    JSON.stringify({ drop: drop.count }));

  var swept = await handle.accounts["delete"]({
    id: made.id, destroy: true, reason: "erasure requested by the account holder",
  });
  count("the erasure reports both messages destroyed, from the two different mailboxes " +
    "they were filed in, and every mailbox emptied",
    swept.mailErased === 2 && swept.mailboxesErased > 0 && swept.mailboxesKept === 0 &&
    swept.mailPreserved.length === 0 && swept.mailFailed.length === 0,
    JSON.stringify({ mail: swept.mailErased, erased: swept.mailboxesErased,
      kept: swept.mailboxesKept }));
  count("its mailbox rows are gone",
    b.db.from(mailbox.FOLDERS).where({ account: made.id }).count() === 0,
    String(b.db.from(mailbox.FOLDERS).where({ account: made.id }).count()));
  count("its filter scripts are gone, because a script names the correspondents its " +
    "owner sorts on",
    b.db.from(mailbox.SCRIPTS).where({ account: made.id }).count() === 0,
    String(b.db.from(mailbox.SCRIPTS).where({ account: made.id }).count()));
  count("its annotations are gone",
    b.db.from(mailbox.METADATA).where({ account: made.id }).count() === 0,
    String(b.db.from(mailbox.METADATA).where({ account: made.id }).count()));

  count("the maildrop it was holding is closed, so the exclusive lock does not outlive " +
    "the mailbox it was over",
    handle.mailbox.describe().openDrops === 0,
    String(handle.mailbox.describe().openDrops));
  var stale = null;
  try { handle.mailbox.listMessages(hana, drop.dropId); }
  catch (e) { stale = (e && e.code) || "thrown-without-a-code"; }
  count("and a command on it refuses rather than serving a listing of mail that is gone",
    stale === "mailbox/no-drop", String(stale));

  var again = null;
  try {
    await handle.accounts["delete"]({ id: made.id, destroy: true, reason: "again" });
  } catch (e) { again = (e && e.code) || "thrown-without-a-code"; }
  count("erasing the same account a second time refuses on the row that is already " +
    "gone, rather than sweeping mail that belongs to nobody",
    again === "store/no-such-account", String(again));
}

// The entry point refuses rather than half-running. Every one of these
// is checked before a single row is destroyed, because the alternative
// to a refusal here is an erasure that reached some of an account's
// mailboxes and reported nothing about the rest.
async function testTheErasureVerbRefusesWhatItCannotAnswerFor(handle, alice) {
  await refuses("an erasure with no acting account refuses rather than reaching for a " +
    "mailbox it cannot scope", "mailbox/no-actor", function () {
      return handle.mailbox.eraseAccountMail(null, alice.id, { reason: "erasure" });
    });
  await refuses("an erasure that names no account refuses rather than taking the actor's " +
    "own mailboxes as the target", "mailbox/bad-argument", function () {
      return handle.mailbox.eraseAccountMail(alice, "", { reason: "erasure" });
    });
  await refuses("an erasure with no reason refuses, because the audit row carrying it is " +
    "the only record afterwards that the mail was here", "mailbox/bad-argument", function () {
      return handle.mailbox.eraseAccountMail(alice, alice.id, {});
    });
  count("and none of those refusals touched the acting account's own mail",
    handle.mailbox.selectFolder(alice, "INBOX", {}) !== null &&
    b.db.from(mailbox.FOLDERS).where({ account: alice.id }).count() > 0,
    String(b.db.from(mailbox.FOLDERS).where({ account: alice.id }).count()) + " mailbox row(s)");
}

// ---- orchestration ----------------------------------------------------------

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-expunge-path-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         "mx.example.com",
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var handle = await store.open(cfg);
    await handle.domains.add({ domain: "example.com" });
    var alice = actorFor(await handle.accounts.create({
      address: "alice@example.com", password: ALICE_PASSWORD }));
    var bob = actorFor(await handle.accounts.create({
      address: "bob@example.com", password: BOB_PASSWORD }));

    var orphan = await testTheAgentAloneLeavesTheOctets(handle, alice);
    await testTheAdapterVerbRemovesBoth(handle, alice);
    await testASharedBlobSurvivesTheFirstDelete(handle, alice, bob);
    await testMovingKeepsTheMessageAddressable(handle, alice);
    await testTheMoveVerbRefusesWhatItCannotOwn(handle, alice, bob);
    await testTheVerbRefusesWhatItCannotOwn(handle, alice, bob);
    await testTheStoreKeepsItsDestructiveWorkAtomic(handle, alice);
    await testErasingAnAccountReachesEverythingItHolds(handle);
    await testTheErasureVerbRefusesWhatItCannotAnswerFor(handle, alice);

    // Tidy the row the first case deliberately orphaned, so the count in
    // `describe` is the truth for anything reading it afterwards.
    b.db.from(mailbox.MESSAGES)
      .where({ folder: orphan.folder, objectid: orphan.objectid }).deleteOne();
    nodeFs.rmSync(orphan.blobPath, { force: true });

    store.close();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try {
      nodeFs.rmSync(root, { recursive: true, force: true });
    } catch (_e) {
      // A temporary directory the platform will not release yet is not
      // a test result. The operating system reclaims it.
    }
  }

  return helpers.getChecks();
}

module.exports = {
  name: "mailbox-expunge-path",
  run:  run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
