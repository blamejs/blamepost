// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Placing a legal hold, and what a held message does afterwards.
 *
 * The refusal gate has been live since the adapter was written: a
 * message whose hold flag is set is refused by every hard delete, on
 * every wire. What did not exist was any way to set the flag, so the
 * browser interface rendered a field that could only ever read false.
 * A control that displays a state nobody can reach is worse than an
 * absent one, because it reads as working.
 *
 * No mail protocol has a verb for this and none should: a preservation
 * order arrives from a court, not from an IMAP client. The placement
 * path is therefore an adapter verb an operator drives, and it does two
 * things that are easy to mistake for one. It records the hold in the
 * framework's registry, which is what carries the reason, the
 * custodian, the citation and the hash-chained audit row a regulator
 * asks for. And it sets the per message flag, which is the thing the
 * delete path actually reads. The registry alone stops nothing; that is
 * asserted below rather than assumed, because it is the mistake this
 * file exists to prevent.
 *
 * The three verbs are `place`, `release` and `status` under
 * `blamepost.mail.mailbox.legalHold`, and every one of them is scoped by
 * the account whose mailbox it is, the same way every other verb on the
 * adapter is.
 *
 * Run standalone: node test/layer-1-state/mailbox-legal-hold.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
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

var CITATION = "FRCP-26";
var REASON   = "preservation order 24-cv-01933";
var APPROVER = "records@example.com";

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
  var folders = handle.mailbox.accountFolders(actor);
  return folders.filter(function (f) { return f.name === wireName; })[0].storeName;
}

// ---- the two substrates are not one substrate -------------------------------

// The framework's hold registry is keyed by subject and the mail
// store's gate reads a per message column. Recording a hold in the
// registry and stopping there leaves the delete path with nothing to
// read, which is the shape a placement path is most likely to be
// written in.
async function testTheRegistryAloneStopsNothing(handle, alice) {
  var appended = handle.mailbox.appendMessage("INBOX", message("registry-only", "x"),
    { actor: alice });
  var folder = storeFolderOf(handle, alice, "INBOX");

  var registry = b.legalHold.create({ db: b.db, audit: b.audit });
  registry.place("message:" + appended.objectid, {
    reason: "registry only, no flag", citation: CITATION });
  count("the framework registry reports the subject held",
    registry.isHeld("message:" + appended.objectid) === true);

  var meta = handle.messageStore.fetchByObjectId(folder, appended.objectid);
  count("but the message the delete path reads carries no hold",
    meta !== null && meta.legalHold === false, meta ? String(meta.legalHold) : "no row");

  registry.release("message:" + appended.objectid, { reason: "test teardown", approver: APPROVER });
  return appended.objectid;
}

// ---- placing one ------------------------------------------------------------

async function testPlacingAHold(handle, alice) {
  var appended = handle.mailbox.appendMessage("INBOX", message("held-message", "keep me"),
    { actor: alice });
  var folder = storeFolderOf(handle, alice, "INBOX");

  var placed = await handle.mailbox.legalHold.place(alice, "INBOX", [appended.objectid], {
    reason:    REASON,
    citation:  CITATION,
    custodian: "legal@example.com",
    placedBy:  "operator",
  });
  count("placing a hold reports the message it took", placed.held.length === 1 &&
    placed.held[0] === appended.objectid, JSON.stringify(placed));

  var meta = handle.messageStore.fetchByObjectId(folder, appended.objectid);
  count("the flag the delete path reads is now set",
    meta !== null && meta.legalHold === true, meta ? String(meta.legalHold) : "no row");

  var status = handle.mailbox.legalHold.status(alice, "INBOX", [appended.objectid]);
  count("the hold reads back with the reason it was placed for",
    status.length === 1 && status[0].held === true && status[0].reason === REASON,
    JSON.stringify(status));
  count("and with the citation an auditor asks for",
    status[0].citation === CITATION, JSON.stringify(status[0]));

  await b.audit.flush();
  var rows = await b.audit.query({ action: "legalhold.placed", limit: 20 });
  var mine = (rows || []).filter(function (r) { return r.reason === REASON; });
  count("placing a hold wrote an audit row carrying the reason in its own column",
    mine.length === 1, String((rows || []).length) + " legalhold.placed row(s)");

  count("placing the same hold twice reports it was already there rather than " +
    "recording a second one",
    (await handle.mailbox.legalHold.place(alice, "INBOX", [appended.objectid], {
      reason: REASON, citation: CITATION,
    })).alreadyHeld.length === 1);

  return appended.objectid;
}

// ---- what a hold does to a delete -------------------------------------------

async function testAHeldMessageSurvivesEveryDeletePath(handle, alice, heldId) {
  var folder = storeFolderOf(handle, alice, "INBOX");

  // IMAP: flag it deleted and expunge the folder.
  handle.mailbox.storeFlags(alice, "INBOX", "1:*", "add", ["\\Deleted"], {});
  var expunged = await handle.mailbox.expungeFolder(alice, "INBOX");
  count("EXPUNGE tells the client nothing was removed",
    expunged.expunged.length === 0, JSON.stringify(expunged.expunged));
  count("and names the hold as the reason it kept the message",
    Array.isArray(expunged.refused) && expunged.refused.length === 1 &&
    expunged.refused[0].reason === "legal-hold", JSON.stringify(expunged.refused));

  // POP3: mark it and commit the drop, which is the only place a POP3
  // session deletes anything.
  var drop = handle.mailbox.openPop3Drop(alice, {});
  count("the maildrop still holds the message", drop.count === 1, String(drop.count));
  handle.mailbox.markDelete(alice, drop.dropId, 1);
  await refuses("QUIT reports the commit could not remove what it was asked to, " +
    "rather than answering the client with success",
    "mailbox/expunge-refused", function () {
      return handle.mailbox.commitPop3Drop(alice, drop.dropId);
    });

  // A message another surface removed while the drop was open is the
  // outcome the client asked for, so the commit reports success. Only a
  // message that is still there is an error to report.
  var vanishing = handle.mailbox.appendMessage("INBOX", message("gone-meanwhile", "x"),
    { actor: alice });
  var raced = handle.mailbox.openPop3Drop(alice, {});
  var listed = handle.mailbox.listMessages(alice, raced.dropId);
  for (var i = 0; i < listed.length; i += 1) {
    handle.mailbox.markDelete(alice, raced.dropId, listed[i].msgNum);
  }
  await handle.mailbox.expungeObjects(alice, "INBOX", [vanishing.objectid]);
  await refuses("a commit still refuses when the held message is the one that stayed",
    "mailbox/expunge-refused", function () {
      return handle.mailbox.commitPop3Drop(alice, raced.dropId);
    });

  var soloDrop = handle.mailbox.openPop3Drop(alice, {});
  var soloList = handle.mailbox.listMessages(alice, soloDrop.dropId);
  count("only the held message is left in the maildrop", soloList.length === 1,
    String(soloList.length));
  handle.mailbox.resetPop3Drop(alice, soloDrop.dropId);
  count("a commit with nothing marked reports success",
    (await handle.mailbox.commitPop3Drop(alice, soloDrop.dropId)).deleted === 0);

  // The other half of that rule, on its own: the only message the
  // client marked is one another surface removed first. Nothing was
  // kept, so the commit reports success and the client is not sent back
  // for a message that has gone. The held message steps out of the
  // maildrop for this, because a POP3 session reads the inbox whole.
  await handle.mailbox.moveObjects(alice, "INBOX", "Archive", [heldId]);
  var doomed = handle.mailbox.appendMessage("INBOX", message("raced-away", "x"),
    { actor: alice });
  var raceDrop = handle.mailbox.openPop3Drop(alice, {});
  count("the maildrop holds the one message about to be raced", raceDrop.count === 1,
    String(raceDrop.count));
  handle.mailbox.markDelete(alice, raceDrop.dropId, 1);
  await handle.mailbox.expungeObjects(alice, "INBOX", [doomed.objectid]);
  var quiet = await handle.mailbox.commitPop3Drop(alice, raceDrop.dropId);
  count("a commit whose only marked message was already gone reports success",
    quiet.deleted === 0, JSON.stringify(quiet));
  await handle.mailbox.moveObjects(alice, "Archive", "INBOX", [heldId]);

  // The single verb the browser surface and JMAP drive.
  var byObject = await handle.mailbox.expungeObjects(alice, "INBOX", [heldId]);
  count("the shared delete verb refuses the held message by name",
    byObject.deleted.length === 0 && byObject.refused.length === 1 &&
    byObject.refused[0].reason === "legal-hold", JSON.stringify(byObject));

  // The three things a hold has to be worth, asserted rather than
  // inferred from the refusal.
  var selected = handle.mailbox.selectFolder(alice, "INBOX", {});
  count("a later session still finds the message", selected.exists === 1,
    String(selected.exists));
  var body = handle.mailbox.fetchRange(alice, "INBOX", "1", "BODY.PEEK[]", {});
  count("and its body is still readable, which is what a preservation order is for",
    body.length === 1 && body[0].payload.indexOf("keep me") !== -1,
    body.length ? body[0].payload.slice(0, 80) : "no row");
  var rows = handle.messageStore.queryByModseq(folder, { sinceModseq: 0 });
  count("the store agrees the message is still there", rows.length === 1,
    String(rows.length) + " row(s)");

  // Filing a held message into Trash is allowed, because a move
  // destroys nothing. What must not happen is the hold coming off on
  // the way: a preservation order that lifts itself when somebody
  // presses Trash is not one.
  var filed = await handle.mailbox.moveObjects(alice, "INBOX", "Trash", [heldId]);
  count("a held message can still be filed into another folder, because a move is not " +
    "a delete", filed.moved.length === 1, JSON.stringify(filed));
  var afterMove = await handle.mailbox.expungeObjects(alice, "Trash", [heldId]);
  count("and the hold traveled with it, so the delete is refused there too",
    afterMove.deleted.length === 0 && afterMove.refused.length === 1 &&
    afterMove.refused[0].reason === "legal-hold", JSON.stringify(afterMove));
  count("the message is readable from where it was filed",
    handle.mailbox.fetchRange(alice, "Trash", "1", "BODY.PEEK[]", {})[0]
      .payload.indexOf("keep me") !== -1);

  // Back where the release case expects to find it.
  await handle.mailbox.moveObjects(alice, "Trash", "INBOX", [heldId]);
}

// ---- releasing one ----------------------------------------------------------

async function testReleasingAHold(handle, alice, heldId) {
  var folder = storeFolderOf(handle, alice, "INBOX");

  await refuses("a release without an approver is refused, because a hold is not lifted " +
    "by whoever happens to be at the keyboard", "mailbox/bad-hold-release", function () {
      return handle.mailbox.legalHold.release(alice, "INBOX", [heldId], { reason: "done" });
    });

  var released = await handle.mailbox.legalHold.release(alice, "INBOX", [heldId], {
    reason: "matter closed", approver: APPROVER,
  });
  count("releasing the hold reports the message it freed",
    released.released.length === 1 && released.released[0] === heldId,
    JSON.stringify(released));

  var meta = handle.messageStore.fetchByObjectId(folder, heldId);
  count("the flag the delete path reads is clear again",
    meta !== null && meta.legalHold === false, meta ? String(meta.legalHold) : "no row");

  await b.audit.flush();
  var rows = await b.audit.query({ action: "legalhold.released", limit: 20 });
  count("releasing wrote its own audit row", (rows || []).length >= 1,
    String((rows || []).length));

  var gone = await handle.mailbox.expungeObjects(alice, "INBOX", [heldId]);
  count("and the message that was held can now be destroyed",
    gone.deleted.length === 1 && gone.refused.length === 0, JSON.stringify(gone));
  count("the store no longer holds it",
    handle.messageStore.queryByModseq(folder, { sinceModseq: 0 }).length === 0);
}

// ---- refusals ---------------------------------------------------------------

async function testTheEntryPointRefusesBadInput(handle, alice, bob) {
  var appended = handle.mailbox.appendMessage("Archive", message("refusals", "y"),
    { actor: alice });

  await refuses("a hold placed without a reason is refused, because a hold with no " +
    "reason is not a record of anything", "mailbox/bad-hold", function () {
      return handle.mailbox.legalHold.place(alice, "Archive", [appended.objectid], {});
    });
  await refuses("a hold placed without an authenticated account refuses rather than " +
    "reaching for a shared folder", "mailbox/no-actor", function () {
      return handle.mailbox.legalHold.place(null, "Archive", [appended.objectid],
        { reason: REASON });
    });
  await refuses("a hold placed on a folder the account does not have is refused",
    "mailbox/no-folder", function () {
      return handle.mailbox.legalHold.place(alice, "Nowhere", [appended.objectid],
        { reason: REASON });
    });
  await refuses("a hold that names no message is refused rather than taken as a " +
    "hold on the folder", "mailbox/bad-hold", function () {
      return handle.mailbox.legalHold.place(alice, "Archive", [], { reason: REASON });
    });
  await refuses("a sunset date is refused, because nothing here sweeps one and an " +
    "option that is accepted and never honored is a hold that lifts itself",
    "mailbox/bad-hold", function () {
      return handle.mailbox.legalHold.place(alice, "Archive", [appended.objectid],
        { reason: REASON, retainUntil: Date.now() + 1000 });
    });

  // The isolation rule the whole adapter is built on: bob names his own
  // Archive and gets his own, so alice's message is not in it.
  var crossed = await handle.mailbox.legalHold.place(bob, "Archive", [appended.objectid], {
    reason: REASON, citation: CITATION,
  });
  count("one account cannot place a hold on another account's message",
    crossed.held.length === 0 && crossed.notInFolder.length === 1,
    JSON.stringify(crossed));
  var meta = handle.messageStore.fetchByObjectId(
    storeFolderOf(handle, alice, "Archive"), appended.objectid);
  count("and the message it aimed at is untouched",
    meta !== null && meta.legalHold === false, meta ? String(meta.legalHold) : "no row");
}

// ---- a hold against an erasure ----------------------------------------------

// The one place two duties point in opposite directions. A right-to-
// erasure request says destroy everything this account holds; a
// preservation order says keep this message. The order wins, and GDPR
// Article 17(3)(e) is why: erasure does not apply where the processing
// is necessary for the establishment, exercise or defense of legal
// claims.
//
// So the erasure is partial, and everything about how it reports itself
// follows from that. The held message stays and stays readable. The
// operator is told which messages were held back and why, in a list
// separate from the one that means something faulted, because the two
// need opposite responses: a message a court is keeping is the system
// working, and a message that could not be erased for any other reason
// is somebody's mail on a volume that was supposed to lose it. And the
// audit trail carries the erasure whichever way it went, because a
// partial erasure is exactly the one a regulator asks about afterwards.
async function testAHoldOutranksAnErasure(handle) {
  var carol = await handle.accounts.create({
    address: "carol@example.com", password: ALICE_PASSWORD });
  var carolActor = actorFor(carol);

  var held = handle.mailbox.appendMessage("INBOX", message("under-order", "evidence"),
    { actor: carolActor });
  var ordinary = handle.mailbox.appendMessage("INBOX", message("ordinary-mail", "no order"),
    { actor: carolActor });
  var folder = storeFolderOf(handle, carolActor, "INBOX");

  await handle.mailbox.legalHold.place(carolActor, "INBOX", [held.objectid], {
    reason:   REASON,
    citation: CITATION,
  });

  var erased = await handle.accounts.delete({
    id:      carol.id,
    destroy: true,
    reason:  "erasure requested by the account holder",
  });

  count("the account row is kept while a message under it is held, because the record " +
    "the court ordered kept is only producible through the identity that owns it",
    erased.outcome === "partially-erased" && handle.accounts.get(carol.id) !== null,
    JSON.stringify(erased.outcome));
  count("and the identity it kept is out of service, so what survives the erasure is a " +
    "custodian for the held record rather than a working mailbox",
    handle.accounts.get(carol.id).status === "erasing",
    JSON.stringify(handle.accounts.get(carol.id).status));
  count("the mail that was not under an order went",
    erased.mailErased === 1 &&
    handle.messageStore.fetchByObjectId(folder, ordinary.objectid) === null,
    JSON.stringify({ erased: erased.mailErased }));
  count("the held message is reported as preserved rather than as failed, because a " +
    "court keeping a record is the system working",
    Array.isArray(erased.mailPreserved) && erased.mailPreserved.length === 1 &&
    erased.mailPreserved[0].reason === "legal-hold" &&
    Array.isArray(erased.mailFailed) && erased.mailFailed.length === 0,
    JSON.stringify({ preserved: erased.mailPreserved, failed: erased.mailFailed }));
  count("and it names the message, so an operator answering the request can say " +
    "which record is being kept and under what",
    erased.mailPreserved[0].objectid === held.objectid,
    JSON.stringify(erased.mailPreserved[0]));

  // The point of a preservation order, asserted as a read rather than as
  // a refusal code.
  var meta = handle.messageStore.fetchByObjectId(folder, held.objectid);
  count("the held message survived the erasure in the message store",
    meta !== null && meta.legalHold === true, meta ? String(meta.legalHold) : "no row");
  count("and its mailbox row stayed with it, so the mail is still addressable rather " +
    "than bound to a mailbox nothing can name",
    b.db.from("blamepost_mailbox_messages").where({ objectid: held.objectid }).count() === 1,
    String(b.db.from("blamepost_mailbox_messages").where({ objectid: held.objectid }).count()));

  await b.audit.flush();
  // Filed under the name for what actually happened. An erasure a court
  // held back is not a destruction, and a row calling it one would answer
  // the only question a regulator asks of this trail wrongly: whether the
  // erasure ever finished.
  var rows = await b.audit.query({ action: "account.erasure_held", limit: 20 });
  var mine = (rows || []).filter(function (r) {
    return r.resourceId === carol.id;
  });
  count("the erasure wrote its audit row, and recorded a preservation order as a " +
    "clean outcome rather than as a failure",
    mine.length === 1 && mine[0].outcome === "success",
    JSON.stringify(mine.map(function (r) { return r.outcome; })));
  var destroyedRows = (await b.audit.query({ action: "account.destroyed", limit: 20 }) || [])
    .filter(function (r) { return r.resourceId === carol.id; });
  count("and nothing in the trail says the account was destroyed, because it was not",
    destroyedRows.length === 0, JSON.stringify(destroyedRows.length));

  return { accountId: carol.id, objectid: held.objectid, folder: folder };
}

// ---- orchestration ----------------------------------------------------------

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-hold-"));
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

    var registryOnly = await testTheRegistryAloneStopsNothing(handle, alice);
    await handle.mailbox.expungeObjects(alice, "INBOX", [registryOnly]);

    var heldId = await testPlacingAHold(handle, alice);
    await testAHeldMessageSurvivesEveryDeletePath(handle, alice, heldId);
    await testReleasingAHold(handle, alice, heldId);
    await testTheEntryPointRefusesBadInput(handle, alice, bob);
    await testAHoldOutranksAnErasure(handle);

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
  name: "mailbox-legal-hold",
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
