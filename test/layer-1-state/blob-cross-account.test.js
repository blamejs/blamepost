// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One set of octets, several accounts, and what the store does when one
 * of those accounts stops existing.
 *
 * A message body is named by the SHA3-512 of its content, so two
 * accounts handed the same message hold one file between them. That is
 * what makes every mistake in this layer a cross-account mistake rather
 * than a mistake in one mailbox: a release that counts wrong removes a
 * body somebody else is still reading, a name a row can influence points
 * one account's message at another account's bytes, and a report that
 * looks at only one account's rows calls a volume clean while it is not.
 *
 * The reconciliation cases next door drive a single account, which is
 * the one arrangement in which none of that can happen. Everything here
 * needs at least two.
 *
 * Four properties are driven:
 *
 *   - **Sharing.** Identical octets delivered to two accounts are one
 *     file, and each account reads its own message back through the
 *     protocol verb its client speaks rather than through a query into
 *     the store.
 *   - **Release.** The file goes when the last row naming it goes, and
 *     not before. The account that did not delete keeps its mail, and
 *     the assertion is a read rather than a row count, because a row
 *     count cannot tell a readable body from a path with nothing at it.
 *   - **The name.** The digest in a row decides which file on the volume
 *     is opened and which file is removed. A row carrying anything that
 *     is not a digest is refused in front of the only derivation, so no
 *     value written into a row can address a file outside the body
 *     store.
 *   - **Quota against sharing.** Two accounts are each charged the whole
 *     message while the volume holds one copy of it. Those are different
 *     numbers on purpose, and the report keeps them in different fields,
 *     because an operator reading bytes freed as bytes uncharged frees a
 *     mailbox that is still full.
 *
 * Then the case the rest of it is here for. An account erased under a
 * right-to-erasure request has to lose its mail as well as its row, and
 * a body is where that is decided: bodies are sealed under the volume's
 * key rather than under anything the erasure destroys, so one left
 * behind opens exactly as it did before, on this volume and on every
 * backup taken from it afterwards. Nothing else would ever free it
 * either, because the release is reference counted and the reference is
 * the message row that stayed.
 *
 * So the erasure is driven here and measured on the filesystem: the body
 * only the erased account referenced is gone, the body it shared with a
 * live account is not, and that account still reads its mail on both
 * protocols that serve a body.
 *
 * The state an unfinished erasure leaves is still reported, and it is
 * driven from that state rather than from the verb: a volume written
 * before the mail erasure existed, a restore that took the identity
 * tables and not the mailbox tables, or an erasure held back by a
 * preservation order all leave mail no account holds. A report that
 * passed over it would let an erasure that did not finish read as one
 * that did.
 *
 * Run standalone: node test/layer-1-state/blob-cross-account.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var blobs   = require("../../lib/store/blobs");
var tables  = require("../../lib/store/tables");
var mailbox = require("../../lib/mail/mailbox");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

// Older than the settle window by a clear margin, so a filesystem whose
// timestamp resolution is coarse cannot land a file back inside it.
var WELL_AGED_MS = blobs.SETTLE_MS + b.constants.TIME.hours(6);

var MESSAGES = mailbox.MESSAGES;
var FOLDERS  = mailbox.FOLDERS;

// The shape a signed in session carries. The mail agent reads the roles
// in front of every delete, so an actor without them is refused before
// any of this layer is reached.
function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    roles:     ["account"],
  };
}

// The same octets whichever account they are delivered to, because that
// is the whole point: two accounts holding one file.
function sharedMessage(subject) {
  return Buffer.from(
    "From: Announcements <list@example.net>\r\n" +
    "To: everyone@example.net\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "The body of " + subject + ".\r\n", "utf8");
}

function digestOf(objectid) {
  var row = b.db.from(MESSAGES).where({ objectid: objectid }).first();
  return row ? row.blobDigest : null;
}

function ageFile(path) {
  var when = new Date(Date.now() - WELL_AGED_MS);
  nodeFs.utimesSync(path, when, when);
}

// The folder token the message store counts against, for one account's
// INBOX. Read from the row rather than rebuilt, because the token is
// what the store knows and the wire name is what the account knows.
function inboxTokenFor(accountId) {
  var rows = b.db.from(FOLDERS).where({ account: accountId }).all();
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i].wireName === "INBOX") return rows[i].folder;
  }
  return null;
}

// ---- sharing ---------------------------------------------------------------

function identicalOctetsAreOneFile(handle, alice, bob, blobDir) {
  var bytes = sharedMessage("one message two mailboxes");

  var hers = handle.mailbox.appendMessage("INBOX", bytes, { actor: alice });
  var his  = handle.mailbox.appendMessage("INBOX", bytes, { actor: bob });

  var hersDigest = digestOf(hers.objectid);
  var hisDigest  = digestOf(his.objectid);
  count("two accounts handed the same octets name the same body",
    hersDigest !== null && hersDigest === hisDigest,
    String(hersDigest).slice(0, 24) + " vs " + String(hisDigest).slice(0, 24));

  var bodyPath = blobs.pathFor(blobDir, hersDigest);
  count("and the volume holds one file for the two of them",
    nodeFs.existsSync(bodyPath), bodyPath);

  var report = handle.blobs.reconcile({ verify: true });
  count("the reconciliation counts one body on disk against one digest referenced",
    report.blobsOnDisk === 1 && report.digestsReferenced === 1,
    JSON.stringify({ onDisk: report.blobsOnDisk, referenced: report.digestsReferenced }));
  count("and unsealing it and hashing it back finds it is the message it is filed as",
    report.ok === true && report.corrupt.length === 0,
    JSON.stringify({ ok: report.ok, corrupt: report.corrupt }));

  // Read through the verb each client speaks, not through the row. A
  // shared body that a query can find and a FETCH cannot is the failure
  // this whole pair of assertions exists to catch.
  var hersBody = handle.mailbox.fetchRange(alice, "INBOX", "1", "BODY.PEEK[]", {});
  var hisBody  = handle.mailbox.fetchRange(bob, "INBOX", "1", "BODY.PEEK[]", {});
  count("each account reads the shared body back over IMAP",
    Buffer.isBuffer(hersBody[0].payload) && Buffer.isBuffer(hisBody[0].payload) &&
    hersBody[0].payload.indexOf("one message two mailboxes") !== -1 &&
    hisBody[0].payload.indexOf("one message two mailboxes") !== -1,
    hersBody[0].payload.length + " / " + hisBody[0].payload.length + " octets");

  return { digest: hersDigest, path: bodyPath, hers: hers, his: his, bytes: bytes };
}

// ---- release ---------------------------------------------------------------

async function theFileGoesWithTheLastRow(handle, alice, bob, shared) {
  var hers = await handle.mailbox.expungeObjects(alice, "INBOX", [shared.hers.objectid]);
  count("one account destroying its copy is accepted",
    hers.deleted.length === 1 && hers.refused.length === 0, JSON.stringify(hers));
  count("and the shared body is still on disk, because another row names it",
    nodeFs.existsSync(shared.path), shared.path);

  // The property the reference count exists for, asserted as a read.
  // A row that survives a delete it should have survived is worth
  // nothing if the octets under it went.
  var stillThere = handle.mailbox.fetchRange(bob, "INBOX", "1", "BODY.PEEK[]", {});
  count("the account that deleted nothing still reads its mail in full",
    stillThere[0].payload.indexOf("one message two mailboxes") !== -1,
    stillThere[0].payload.length + " octets");

  var drop = handle.mailbox.openPop3Drop(bob, {});
  var retrieved = handle.mailbox.getMessage(bob, drop.dropId, 1, {});
  count("and over POP3 as well, which reads the same body through the same check",
    retrieved !== null && Buffer.isBuffer(retrieved.rawBytes) &&
    retrieved.rawBytes.toString("utf8").indexOf("one message two mailboxes") !== -1,
    retrieved === null ? "nothing was returned" : String(retrieved.size));
  handle.mailbox.commitPop3Drop(bob, drop.dropId);

  var midway = handle.blobs.reconcile({ verify: true });
  count("and the volume still reconciles with one row gone and one left",
    midway.ok === true && midway.missing.length === 0,
    JSON.stringify({ ok: midway.ok, missing: midway.missing }));

  var his = await handle.mailbox.expungeObjects(bob, "INBOX", [shared.his.objectid]);
  count("the second account destroying its copy is accepted too",
    his.deleted.length === 1, JSON.stringify(his));
  count("and now that no row names the body, the file is gone",
    nodeFs.existsSync(shared.path) === false, shared.path);

  var after = handle.blobs.reconcile({ verify: true });
  count("removing the shared body left nothing unreferenced and nothing missing",
    after.ok === true && after.orphans.length === 0 && after.missing.length === 0,
    JSON.stringify({ orphans: after.orphans.length, missing: after.missing.length }));
}

// ---- the name --------------------------------------------------------------

// A digest arrives from a row, and a row carries whatever was written
// into it. Everything that opens or removes a file resolves the path
// through one derivation, so the shape check in front of that derivation
// is the whole of the defense and it is asserted directly.
function aRowCannotNameAFileOutsideTheBodyStore(blobDir) {
  var refused = [
    "../../../../etc/passwd",
    "..",
    "",
    "GG" + "0".repeat(126),
    "0".repeat(127),
    "0".repeat(129),
    // Upper case hex, which reads as a digest to a person and is a
    // different file name on a volume that distinguishes case.
    "A".repeat(128),
    "0".repeat(64) + "/" + "0".repeat(63),
    "0".repeat(64) + "\\" + "0".repeat(63),
  ];

  var wrong = [];
  for (var i = 0; i < refused.length; i += 1) {
    var code = null;
    try { blobs.pathFor(blobDir, refused[i]); }
    catch (e) { code = (e && e.code) || "thrown-without-a-code"; }
    if (code !== "mailbox/bad-blob-digest") {
      wrong.push(JSON.stringify(refused[i].slice(0, 24)) + " -> " + String(code));
    }
  }
  count("a value that is not a content digest is refused in front of the path derivation",
    wrong.length === 0, wrong.join(" ; "));

  var digest = b.crypto.sha3Hash(Buffer.from("octets", "utf8"));
  var built = blobs.pathFor(blobDir, digest);
  count("and a real digest resolves inside the body store and nowhere else",
    nodePath.resolve(built).indexOf(nodePath.resolve(blobDir) + nodePath.sep) === 0 &&
    nodePath.basename(built) === digest,
    built);

  var noDir = null;
  try { blobs.pathFor("", digest); }
  catch (e) { noDir = (e && e.code) || "thrown-without-a-code"; }
  count("and a caller that names no body store is refused rather than given a relative path",
    noDir === "store/bad-argument", String(noDir));
}

// ---- quota against sharing -------------------------------------------------

async function quotaIsChargedPerAccountAndFreedPerFile(handle, alice, bob, blobDir) {
  var bytes = sharedMessage("charged twice held once");
  var hers = handle.mailbox.appendMessage("INBOX", bytes, { actor: alice });

  var digest = digestOf(hers.objectid);
  var bodyPath = blobs.pathFor(blobDir, digest);
  var sealedBytes = nodeFs.statSync(bodyPath).size;

  var oneAccount = handle.blobs.reconcile({ verify: false });
  var hersUsed = handle.messageStore.quota(inboxTokenFor(alice.id)).usedBytes;

  // The second delivery of the same octets. Nothing about the file
  // changes, and the charge doubles.
  var his = handle.mailbox.appendMessage("INBOX", bytes, { actor: bob });
  var twoAccounts = handle.blobs.reconcile({ verify: false });
  var hisUsed = handle.messageStore.quota(inboxTokenFor(bob.id)).usedBytes;

  count("each account is charged the whole message rather than a share of it",
    hersUsed > 0 && hersUsed === hisUsed, hersUsed + " / " + hisUsed);
  count("and the second delivery of the same octets added nothing to the volume",
    twoAccounts.bytesOnDisk === oneAccount.bytesOnDisk &&
    twoAccounts.blobsOnDisk === oneAccount.blobsOnDisk,
    JSON.stringify({ before: oneAccount.bytesOnDisk, after: twoAccounts.bytesOnDisk }));
  count("so what the mailboxes are charged and what the volume holds are two " +
    "different numbers, which is why they are two different fields",
    hersUsed + hisUsed !== twoAccounts.bytesOnDisk,
    (hersUsed + hisUsed) + " charged vs " + twoAccounts.bytesOnDisk + " on disk");
  count("with nothing counted as drift, because both sides of the quota check " +
    "measure the same messages",
    twoAccounts.quotaDrift.length === 0, JSON.stringify(twoAccounts.quotaDrift));

  // What a reclaim frees is the file, so the number it reports is the
  // sealed size on disk rather than either row's message size.
  b.db.from(MESSAGES).where({ objectid: hers.objectid }).deleteOne();
  b.db.from(MESSAGES).where({ objectid: his.objectid }).deleteOne();
  ageFile(bodyPath);

  var freed = await handle.blobs.reclaim({
    reason: "octets stranded by an interrupted delivery",
  });
  count("a reclaim reports the sealed bytes it removed from the volume",
    freed.reclaimedBytes === sealedBytes, freed.reclaimedBytes + " vs " + sealedBytes);
  count("which is not the message size the mailbox was charged, and is not " +
    "presented as though it were",
    freed.reclaimedBytes !== hersUsed && freed.reclaimedBytes !== hersUsed + hisUsed,
    freed.reclaimedBytes + " vs " + hersUsed + " and " + (hersUsed + hisUsed));

  var hersAfter = handle.messageStore.quota(inboxTokenFor(alice.id)).usedBytes;
  count("and the quota the account is charged did not move, because the count " +
    "lives in the message store rather than on disk",
    hersAfter === hersUsed, hersAfter + " vs " + hersUsed);
}

// ---- what an erasure reaches -----------------------------------------------

// An erasure asked for in as many words is the right-to-erasure path,
// and the operator guide promises it renders the account's data
// unrecoverable everywhere it exists. Everywhere is four places, and the
// account row is one of them: the mailbox rows, the message rows, the
// message store's own rows and the sealed bodies under `blobs/` are the
// other three, and none of them is reachable from the account table.
//
// The body store is where the promise is decided, because a body is
// sealed under the volume's key rather than under anything the erasure
// destroys. A body left behind opens exactly as it did before, on this
// volume and on every backup taken from it afterwards, and the
// reference-counted release can never free it: the release counts
// message rows, so a message row that survived pins its body for the
// life of the volume.
//
// Sharing is the other half. Content addressing means one file can be
// the body of a message in a mailbox that is being erased and of a
// message in one that is not, so an erasure that frees by digest rather
// than by reference count takes the surviving account's mail with it.
async function erasureReachesTheMailAndStopsAtTheSurvivor(handle, blobDir) {
  var carol = await handle.accounts.create({
    address: "carol@" + DOMAIN, password: PASSWORD,
  });
  var dave = await handle.accounts.create({
    address: "dave@" + DOMAIN, password: PASSWORD,
  });
  var carolActor = actorFor(carol);
  var daveActor  = actorFor(dave);

  var hersOnly = handle.mailbox.appendMessage("INBOX",
    sharedMessage("only in the erased mailbox"), { actor: carolActor });
  var between = sharedMessage("in both mailboxes");
  var herCopy = handle.mailbox.appendMessage("INBOX", between, { actor: carolActor });
  var hisCopy = handle.mailbox.appendMessage("INBOX", between, { actor: daveActor });

  var hersOnlyPath = blobs.pathFor(blobDir, digestOf(hersOnly.objectid));
  var sharedPath   = blobs.pathFor(blobDir, digestOf(hisCopy.objectid));
  var carolFolders = b.db.from(FOLDERS).where({ account: carol.id }).count();

  var before = handle.blobs.reconcile({ verify: true });
  count("two live accounts, one body each and one between them, reconciles",
    before.ok === true && before.blobsOnDisk === 2,
    JSON.stringify({ ok: before.ok, onDisk: before.blobsOnDisk }));
  count("and the account about to be erased holds mailboxes to erase",
    carolFolders > 0, String(carolFolders) + " mailbox row(s)");

  var erased = await handle.accounts.delete({
    id:      carol.id,
    destroy: true,
    reason:  "erasure requested by the account holder",
  });
  count("the account is erased when asked in as many words",
    erased.outcome === "destroyed" && handle.accounts.get(carol.id) === null,
    JSON.stringify(erased.outcome));
  count("and the call answers for the mail as well as for the row, so an operator " +
    "reads what the erasure reached rather than inferring it",
    erased.mailErased === 2 && Array.isArray(erased.mailPreserved) &&
    erased.mailPreserved.length === 0 && Array.isArray(erased.mailFailed) &&
    erased.mailFailed.length === 0,
    JSON.stringify({ erased: erased.mailErased, preserved: erased.mailPreserved,
      failed: erased.mailFailed }));

  count("the erased account's message rows are gone",
    b.db.from(MESSAGES).where({ objectid: hersOnly.objectid }).count() === 0 &&
    b.db.from(MESSAGES).where({ objectid: herCopy.objectid }).count() === 0,
    String(b.db.from(MESSAGES).where({ objectid: hersOnly.objectid }).count()) + " / " +
      String(b.db.from(MESSAGES).where({ objectid: herCopy.objectid }).count()));
  count("its mailbox rows went with them, because an emptied mailbox belonging to " +
    "nobody is the residue the report would otherwise have to name forever",
    b.db.from(FOLDERS).where({ account: carol.id }).count() === 0,
    String(b.db.from(FOLDERS).where({ account: carol.id }).count()) + " left");
  count("and the message store no longer answers for its messages either",
    handle.messageStore.threadFor(hersOnly.objectid).length === 0,
    JSON.stringify(handle.messageStore.threadFor(hersOnly.objectid)));

  // The assertion the whole promise rests on. A body still on the volume
  // is a body that opens with the volume's key, so this is a read of the
  // filesystem rather than of a row.
  count("the body only the erased account referenced is off the volume, which is " +
    "what makes the erasure an erasure rather than a row deletion",
    nodeFs.existsSync(hersOnlyPath) === false, hersOnlyPath);
  count("and the body it shared with a live account is still there, because the " +
    "release counts rows rather than digests",
    nodeFs.existsSync(sharedPath), sharedPath);

  var after = handle.blobs.reconcile({ verify: true });
  count("the volume reconciles afterwards: no mail no account holds, nothing " +
    "unreferenced, nothing missing",
    after.ok === true && after.unowned.length === 0 && after.orphans.length === 0 &&
    after.missing.length === 0 && after.corrupt.length === 0,
    JSON.stringify({ ok: after.ok, unowned: after.unowned.length,
      orphans: after.orphans.length, missing: after.missing.length }));
  count("with one body left on disk for the one account that still holds mail",
    after.blobsOnDisk === 1 && after.digestsReferenced === 1,
    JSON.stringify({ onDisk: after.blobsOnDisk, referenced: after.digestsReferenced }));

  // The survivor reads its mail on both protocols that serve a body, not
  // on one. A release that counted wrong shows up here as an empty
  // response rather than as a row that is missing.
  count("the surviving account still reads the body it shared with the erased one, " +
    "over IMAP",
    handle.mailbox.fetchRange(daveActor, "INBOX", "1", "BODY.PEEK[]", {})[0]
      .payload.indexOf("in both mailboxes") !== -1, sharedPath);
  var drop = handle.mailbox.openPop3Drop(daveActor, {});
  var retrieved = handle.mailbox.getMessage(daveActor, drop.dropId, 1, {});
  count("and over POP3, which reads the same body through the same digest check",
    retrieved !== null && Buffer.isBuffer(retrieved.rawBytes) &&
    retrieved.rawBytes.toString("utf8").indexOf("in both mailboxes") !== -1,
    retrieved === null ? "nothing was returned" : String(retrieved.size));
  await handle.mailbox.commitPop3Drop(daveActor, drop.dropId);
}

// ---- mail that no account holds --------------------------------------------

// The reporting half, driven from the state it exists to name rather
// than from the erasure verb, because the erasure no longer produces it.
// What does produce it is an erasure that stopped after the account row:
// a volume written by an older release, a restore that took the identity
// tables and not the mailbox tables, or an erasure that refused partway
// and left the mail behind on purpose.
//
// The rows are intact in every one of those, so the reference-counted
// release never fires and no protocol lists any of it. A report that
// passed over the state would let an erasure that did not finish read as
// one that did.
async function anInterruptedErasureIsReportedRatherThanPassedOver(handle, blobDir) {
  var frank = await handle.accounts.create({
    address: "frank@" + DOMAIN, password: PASSWORD,
  });
  var frankActor = actorFor(frank);
  var filed = handle.mailbox.appendMessage("INBOX",
    sharedMessage("left behind by an erasure that stopped"), { actor: frankActor });
  var bodyPath = blobs.pathFor(blobDir, digestOf(filed.objectid));

  // The account row alone, exactly as far as the framework's own erase
  // reaches. Nothing else is touched, which is the whole point.
  b.db.eraseHard(tables.ACCOUNTS, frank.id, {
    reason:    "an erasure that reached the account row and stopped",
    subjectId: frank.address,
  });
  count("the account row is gone and its mail is not",
    handle.accounts.get(frank.id) === null &&
    b.db.from(MESSAGES).where({ objectid: filed.objectid }).count() === 1,
    String(b.db.from(MESSAGES).where({ objectid: filed.objectid }).count()) + " row(s)");

  var report = handle.blobs.reconcile({ verify: true });
  count("the volume is not reported as reconciled while it holds mail no account holds",
    report.ok === false, JSON.stringify({ ok: report.ok, unowned: report.unowned.length }));
  count("and the report names it rather than leaving the operator to infer it " +
    "from a count that did not move",
    report.unowned.some(function (entry) { return entry.account === frank.id; }),
    JSON.stringify(report.unowned));

  var mine = report.unowned.filter(function (entry) { return entry.account === frank.id; })[0];
  count("saying how many messages are held and how many bytes they are charged, " +
    "which is what decides whether this is one stray row or a mailbox",
    mine !== undefined && mine.messages > 0 && mine.rowBytes > 0 &&
    typeof mine.detail === "string" && mine.detail.length > 0, JSON.stringify(mine));
  count("and the digests, because those are the files an operator has to act on",
    mine !== undefined && Array.isArray(mine.digests) && mine.digests.length > 0 &&
    mine.digests.every(function (d) { return mailbox.BLOB_DIGEST_RE.test(d); }),
    JSON.stringify(mine && mine.digests));
  count("and it says the mailbox is the half that survived and the account is the " +
    "half that went, which is a different repair from a mailbox row that is gone",
    mine !== undefined && /the account that held it is not/.test(mine.detail) &&
    typeof mine.mailbox === "string" && mine.mailbox.length > 0,
    JSON.stringify(mine && { mailbox: mine.mailbox, detail: mine.detail }));

  // Not reported as unreferenced, because it is referenced. This is the
  // distinction the list exists to draw: an orphan is a file no row names
  // and a reclaim can free it, whereas this is a file a surviving row
  // names and no reclaim will ever touch.
  count("the stranded body is not reported as unreferenced octets, because a row " +
    "still names it",
    report.orphans.length === 0, JSON.stringify(report.orphans));

  var pinned = await handle.blobs.reclaim({
    reason: "checking what a reclaim frees over mail no account holds",
  });
  count("so a reclaim frees none of it, however long it has been on disk",
    pinned.reclaimed.length === 0 && nodeFs.existsSync(bodyPath),
    JSON.stringify(pinned.reclaimed) + " " + bodyPath);
}

// ---- a message row whose folder is gone ------------------------------------

// The same class from the other end. A folder row that goes without its
// messages leaves rows bound to a mailbox nothing can select: no
// protocol lists them, the quota comparison never reaches them because
// it walks folders, and the bodies they name are pinned for as long as
// they exist.
async function messagesWithNoFolderAreReportedToo(handle, blobDir) {
  var erin = await handle.accounts.create({
    address: "erin@" + DOMAIN, password: PASSWORD,
  });
  var erinActor = actorFor(erin);
  var filed = handle.mailbox.appendMessage("INBOX",
    sharedMessage("filed into a mailbox that then went"), { actor: erinActor });
  var bodyPath = blobs.pathFor(blobDir, digestOf(filed.objectid));

  var token = inboxTokenFor(erin.id);
  b.db.from(FOLDERS).where({ folder: token }).deleteOne();

  var report = handle.blobs.reconcile({ verify: false });
  count("a message row whose folder row is gone is reported rather than counted " +
    "by nothing",
    report.ok === false &&
    report.unowned.some(function (entry) { return entry.folder === token; }),
    JSON.stringify(report.unowned));
  count("and the body it names is still on disk and still pinned against a reclaim",
    nodeFs.existsSync(bodyPath), bodyPath);

  var entry = report.unowned.filter(function (e) { return e.folder === token; })[0];
  count("the entry says the mailbox row is the thing that is missing, and carries " +
    "no mailbox name because there is none to carry",
    entry !== undefined && /no mailbox row/.test(entry.detail) &&
    entry.mailbox === null && entry.account === null, JSON.stringify(entry));
}

// ---- what the operator is actually told ------------------------------------

// The library answer is only half of it. What an operator reads is the
// verb, and a divergence the report counts but does not render leaves
// them a non-zero exit and a sentence with nothing in it.
function theVerbNamesIt(cli) {
  var plain = cli(["blobs", "report"]);
  count("`blobs report` exits non-zero on a volume holding mail no account holds",
    plain.status === 1, "exit " + plain.status + " " + plain.both.slice(0, 200));
  count("and the summary names it rather than trailing off after `Diverged:`",
    /mailboxe?s? no account holds/.test(plain.stdout), plain.stdout.slice(0, 800));
  count("with a line per mailbox saying which half went and how much it holds",
    /a mailbox with no row: no mailbox row holds these messages/.test(plain.stdout) &&
    /the account that held it is not[^.]*\. \d+ messages?, \d+ bytes/.test(plain.stdout),
    plain.stdout.slice(0, 900));
  count("and answers the question an operator asks next, which is whether a " +
    "reclaim clears it",
    /reclaiming bodies does not free it/i.test(plain.stdout), plain.stdout.slice(0, 1200));

  var parsed;
  try { parsed = JSON.parse(cli(["blobs", "report", "--json"]).stdout); }
  catch (_e) { parsed = null; }
  count("`blobs report --json` carries the same list for a script to branch on",
    parsed !== null && Array.isArray(parsed.unowned) && parsed.unowned.length >= 2,
    JSON.stringify(parsed && parsed.unowned));

  var doctor = cli(["doctor", "--json"]);
  var finding;
  try {
    finding = (JSON.parse(doctor.stdout).local || []).filter(function (f) {
      return /message bodies/i.test(f.check);
    })[0];
  } catch (_e) { finding = null; }
  count("`doctor` fails its message-body check on the same volume, so a scheduled " +
    "health run is not the one place this stays quiet",
    finding !== undefined && finding !== null && finding.ok === false,
    JSON.stringify(finding));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("blob-cross-account");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    var handle = await store.open(cfg);
    await handle.domains.add({ domain: DOMAIN });

    var alice = actorFor(await handle.accounts.create({
      address: "alice@" + DOMAIN, password: PASSWORD,
    }));
    var bob = actorFor(await handle.accounts.create({
      address: "bob@" + DOMAIN, password: PASSWORD,
    }));

    var blobDir = handle.mailbox.describe().blobDir;

    var shared = identicalOctetsAreOneFile(handle, alice, bob, blobDir);
    await theFileGoesWithTheLastRow(handle, alice, bob, shared);
    aRowCannotNameAFileOutsideTheBodyStore(blobDir);
    await erasureReachesTheMailAndStopsAtTheSurvivor(handle, blobDir);
    await anInterruptedErasureIsReportedRatherThanPassedOver(handle, blobDir);
    await messagesWithNoFolderAreReportedToo(handle, blobDir);
    // Last of the library cases, because stranding a body to measure
    // what a reclaim frees takes the rows out from under a live
    // mailbox's quota counters and leaves that mailbox in drift for the
    // rest of the run.
    await quotaIsChargedPerAccountAndFreedPerFile(handle, alice, bob, blobDir);

    // One handle per process at a time: the database is encrypted at
    // rest and each process decrypts its own working copy, so a handle
    // held open while the child reads would answer off a stale snapshot.
    handle.close();
    theVerbNamesIt(cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    }));

    return helpers.getChecks();
  } finally {
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "blob-cross-account", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
