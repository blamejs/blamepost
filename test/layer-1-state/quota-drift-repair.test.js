// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The quota counter that has been charged for mail no protocol can list,
 * and the verb that puts it right.
 *
 * Filing a message writes three records in order: the sealed octets, the
 * message store's row, and this layer's row binding it to a mailbox. The
 * store's per-folder counter moves on the second. A process that stops
 * between the second and the third, and a rollback the store refuses,
 * both leave the counter charged for a message the owner can neither
 * read nor delete, and their mailbox fills up against nothing.
 *
 * `blobs report` has always named that state. What it could not do was
 * end it, and the counter is not something a repair may simply write: a
 * number set by hand is a number nobody can derive again. So the repair
 * removes the message-store rows no mailbox row names, through the same
 * delete path every wire protocol takes, and the store's own decrement
 * moves the counter by exactly the size of what it removed.
 *
 * Three verbs carry that between them, and each is driven on its own
 * below as well as through the one above it.
 * `blamepost.mail.mailbox.unfiledIn` is the only reader on this server
 * that can name a message no protocol lists, and the number the report
 * shows an operator comes from it.
 * `blamepost.mail.mailbox.sweepUnfiled` removes them for one mailbox.
 * `blamepost.store.blobs.repairQuota` walks every mailbox the counter
 * disagrees about and reports what it could not close.
 *
 * Which means the two gates in front of every other destruction on this
 * server are in front of this one: a preservation order and the
 * retention floor keep an unfiled message exactly as they keep a filed
 * one, and the mailbox goes on drifting while they do. Both are driven
 * below, because a repair that walked past them would destroy the
 * records an operator is answering a court with.
 *
 * The other direction is not repairable and is reported rather than
 * forced. A mailbox holding rows the message store has forgotten reads
 * as a counter that is too LOW, and nothing this server removes raises
 * it.
 *
 * Run standalone: node test/layer-1-state/quota-drift-repair.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var cliHelper  = require("../helpers/cli");
var b          = require("../../lib/vendor/blamejs");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var auditActor = require("../../lib/store/actor");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var DOMAIN = "example.com";
var ACCOUNT_PASSWORD = "a sufficiently long account password";

var MESSAGES = "blamepost_mailbox_messages";

var REPAIR_REASON = "the mailbox was charged for mail no protocol could list";

function mailFor(address, subject) {
  return Buffer.from(
    "From: sender@example.net\r\n" +
    "To: " + address + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 1 Jun 2026 10:00:00 +0000\r\n" +
    "Message-ID: <" + subject.replace(/\s+/g, "-") + "@example.net>\r\n" +
    "\r\n" +
    "the body of " + subject + "\r\n", "utf8");
}

function actorFor(row) {
  return { id: row.id, address: row.address, domain: row.domain, roles: ["account"] };
}

// The opaque token the message store knows a mailbox by, which is what
// its counter is kept against.
function storeFolderOf(handle, actor, wireName) {
  return handle.mailbox.accountFolders(actor)
    .filter(function (f) { return f.name === wireName; })[0].storeName;
}

function counterFor(handle, folder) {
  return handle.messageStore.quota(folder);
}

function storeRowCount(handle, folder) {
  return handle.messageStore.queryByModseq(folder, { sinceModseq: 0, limit: 10000 }).length;
}

function driftFor(handle, address) {
  return handle.blobs.reconcile().quotaDrift.filter(function (entry) {
    return entry.account === address;
  });
}

// A command's answer read as the JSON it was asked for, or null when the
// run printed something else. Written this way so a malformed answer
// reaches the claim as a failure carrying the output, rather than as a
// throw with the run's own text thrown away.
function jsonOf(result) {
  try { return JSON.parse(result.stdout); }
  catch (_e) { return null; }
}

function refusalOf(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

async function refusalOfAsync(fn) {
  try { await fn(); return null; }
  catch (e) { return e; }
}

// An account holding two ordinary messages and one the store has and
// this layer does not.
//
// The unfiled message is made by calling the message store's own append
// on its own, which is the second of the three writes the adapter makes
// and exactly the state an interruption after it leaves.
async function seedAccount(handle, address, unfiledSubjects) {
  var row = await handle.accounts.create({ address: address, password: ACCOUNT_PASSWORD });
  var actor = actorFor(row);
  var folder = storeFolderOf(handle, actor, "INBOX");

  handle.mailbox.appendMessage("INBOX", mailFor(address, "ordinary-one"), { actor: actor });
  handle.mailbox.appendMessage("INBOX", mailFor(address, "ordinary-two"), { actor: actor });

  var unfiled = [];
  for (var i = 0; i < unfiledSubjects.length; i += 1) {
    unfiled.push(handle.messageStore.appendMessage(
      folder, mailFor(address, unfiledSubjects[i]), {}).objectid);
  }

  return { row: row, actor: actor, folder: folder, address: address, unfiled: unfiled };
}

// ---- the report names what the repair would take ----------------------------

function theReportSaysHowMuchOfTheDriftIsRemovable(handle, seeded) {
  var entries = driftFor(handle, seeded.address);
  count("a mailbox charged for a message no row names is reported as drifting",
    entries.length === 1, JSON.stringify(entries));
  if (entries.length !== 1) return;

  count("and the store's count is above the rows, which is the direction a removal " +
    "closes",
    entries[0].storeCount > entries[0].rowCount && entries[0].storeBytes > entries[0].rowBytes,
    JSON.stringify(entries[0]));
  count("and the report says how much of the drift is mail the repair would remove, so " +
    "an operator knows what they are agreeing to before they run it",
    entries[0].unfiledCount === 1 && entries[0].unfiledBytes > 0,
    JSON.stringify(entries[0]));
  count("and the removable part accounts for the whole of this mailbox's drift",
    entries[0].unfiledCount === entries[0].storeCount - entries[0].rowCount &&
    entries[0].unfiledBytes === entries[0].storeBytes - entries[0].rowBytes,
    JSON.stringify(entries[0]));
}

// ---- the repair ------------------------------------------------------------

async function theRepairRemovesTheMailNoRowNames(handle, seeded) {
  var before = counterFor(handle, seeded.folder);
  var unfiledBytes = driftFor(handle, seeded.address)[0].unfiledBytes;

  var repaired = await handle.blobs.repairQuota({ reason: REPAIR_REASON });

  count("the repair reports the mailbox it found drifting before it ran",
    repaired.driftBefore.length === 1 && repaired.driftBefore[0].account === seeded.address,
    JSON.stringify(repaired.driftBefore));
  count("and names each message it removed, with the mailbox it was in",
    repaired.removed.length === 1 && repaired.removed[0].objectid === seeded.unfiled[0] &&
    repaired.removed[0].mailbox === "INBOX",
    JSON.stringify(repaired.removed));
  count("and keeps nothing back",
    repaired.kept.length === 0, JSON.stringify(repaired.kept));
  count("and reports the mailbox as no longer drifting",
    repaired.driftAfter.length === 0 && repaired.ok === true,
    JSON.stringify({ after: repaired.driftAfter, ok: repaired.ok }));

  var after = counterFor(handle, seeded.folder);
  count("the counter fell by exactly the size of the message that went, because the " +
    "store's own decrement moved it rather than a number being written",
    after.usedBytes === before.usedBytes - unfiledBytes &&
    after.usedCount === before.usedCount - 1,
    JSON.stringify({ before: before, after: after, unfiledBytes: unfiledBytes }));

  count("the message store no longer answers for the message, so its subject and its " +
    "body are off the volume rather than merely unreferenced",
    handle.messageStore.fetchByObjectId(seeded.folder, seeded.unfiled[0]) === null,
    JSON.stringify(handle.messageStore.fetchByObjectId(seeded.folder, seeded.unfiled[0])));

  count("and the two ordinary messages are untouched, so the repair reached the mail no " +
    "row named and nothing beside it",
    storeRowCount(handle, seeded.folder) === 2 &&
    b.db.from(MESSAGES).where({ folder: seeded.folder }).count() === 2,
    JSON.stringify({
      store: storeRowCount(handle, seeded.folder),
      rows:  b.db.from(MESSAGES).where({ folder: seeded.folder }).count(),
    }));

  count("the mailbox reconciles on the counter afterwards",
    driftFor(handle, seeded.address).length === 0,
    JSON.stringify(driftFor(handle, seeded.address)));
}

// ---- running it again ------------------------------------------------------

async function aSecondRunWritesNothing(handle) {
  var again = await handle.blobs.repairQuota({ reason: REPAIR_REASON });
  count("running the repair on a volume whose counters agree removes nothing and " +
    "refuses nothing, so an operator who is not sure whether it has run can run it",
    again.removed.length === 0 && again.kept.length === 0 && again.ok === true,
    JSON.stringify(again));
  count("and it walked the counters rather than answering from nothing",
    again.driftBefore.length === 0 && again.driftAfter.length === 0,
    JSON.stringify({ before: again.driftBefore, after: again.driftAfter }));
}

// ---- a reason is not optional ----------------------------------------------

async function theRepairNeedsAReason(handle) {
  var refused = await refusalOfAsync(function () { return handle.blobs.repairQuota({}); });
  count("the repair refuses to run without a reason, because once it has run the audit " +
    "row carrying the reason is the only record that the mail was ever here",
    refused !== null && refused.code === "store/bad-argument",
    refused ? String(refused.code) : "the repair ran with no reason");
}

// ---- the reader the report is built from ------------------------------------

// The adapter verb underneath the number the report shows. It is driven
// on its own rather than only through the reconciliation, because it is
// the only reader on this server that can name a message no protocol
// lists, and a wrong answer here is a wrong answer everywhere above it.
function theReaderTheReportIsBuiltFromNamesTheMail(handle, seeded) {
  var named = handle.mailbox.unfiledIn(seeded.folder);
  count("the reader names the message the store holds and no row names",
    named.length === 1 && named[0].objectid === seeded.unfiled[0], JSON.stringify(named));
  count("and not the two the mailbox does list, so the answer is the difference between " +
    "the layers rather than the contents of one",
    named.length === 1, JSON.stringify(named));
  count("and carries the size the store charged for it, which is what a caller " +
    "correcting a counter has to be able to say once the row is gone",
    typeof named[0].sizeBytes === "number" && named[0].sizeBytes > 0,
    JSON.stringify(named[0]));

  var refused = refusalOf(function () { return handle.mailbox.unfiledIn(""); });
  count("and a mailbox named by nothing is refused rather than answered about",
    refused !== null && refused.code === "mailbox/bad-argument",
    refused ? String(refused.code) : "an empty token was answered");
}

// ---- one mailbox swept on its own -------------------------------------------

// The adapter verb the repair drives per mailbox, exercised directly. The
// repair walks every mailbox the counter disagrees about; this is the one
// call underneath it, and the contract it has to hold is that a mailbox
// whose two layers agree costs nothing and answers empty.
async function aMailboxIsSweptOnItsOwn(handle) {
  var seeded = await seedAccount(handle, "swept@" + DOMAIN, ["swept-on-its-own"]);

  var unexplained = await refusalOfAsync(function () {
    return handle.mailbox.sweepUnfiled(seeded.actor, "INBOX", {});
  });
  count("a sweep refuses to run without a reason, for the reason the repair above it does",
    unexplained !== null && unexplained.code === "mailbox/bad-argument",
    unexplained ? String(unexplained.code) : "the sweep ran with no reason");

  var swept = await handle.mailbox.sweepUnfiled(seeded.actor, "INBOX", {
    reason: REPAIR_REASON,
  });
  count("the sweep removes the mail no row names and answers with it",
    swept.removed.length === 1 && swept.removed[0].objectid === seeded.unfiled[0] &&
    swept.removed[0].sizeBytes > 0, JSON.stringify(swept.removed));
  count("and keeps nothing back", swept.kept.length === 0, JSON.stringify(swept.kept));
  count("and leaves the messages the mailbox does list",
    b.db.from(MESSAGES).where({ folder: seeded.folder }).count() === 2 &&
    storeRowCount(handle, seeded.folder) === 2,
    JSON.stringify({
      rows:  b.db.from(MESSAGES).where({ folder: seeded.folder }).count(),
      store: storeRowCount(handle, seeded.folder),
    }));

  var again = await handle.mailbox.sweepUnfiled(seeded.actor, "INBOX", {
    reason: REPAIR_REASON,
  });
  count("and a mailbox whose two layers agree answers empty, which is every mailbox on " +
    "a volume where nothing has gone wrong",
    again.removed.length === 0 && again.kept.length === 0, JSON.stringify(again));
}

// ---- a preservation order outranks it --------------------------------------

async function aPreservationOrderKeepsTheMessageAndTheDrift(handle) {
  var seeded = await seedAccount(handle, "held@" + DOMAIN, ["held-from-the-court"]);

  var placed = await handle.mailbox.legalHold.place(seeded.actor, "INBOX", seeded.unfiled, {
    reason: "a preservation order names this correspondence",
  });
  count("a preservation order can be placed on a message no mailbox row names",
    placed && Array.isArray(placed.held) && placed.held.indexOf(seeded.unfiled[0]) !== -1,
    JSON.stringify(placed));

  var repaired = await handle.blobs.repairQuota({ reason: REPAIR_REASON });
  var kept = repaired.kept.filter(function (e) { return e.objectid === seeded.unfiled[0]; })[0];

  count("the repair keeps a message under a preservation order rather than removing it",
    handle.messageStore.fetchByObjectId(seeded.folder, seeded.unfiled[0]) !== null,
    "the repair destroyed a message a preservation order was keeping");
  count("and reports it under the same reason every other wire on this server answers " +
    "with, marked as something deliberately keeping it",
    kept !== undefined && kept.reason === "legal-hold" && kept.preserved === true,
    JSON.stringify(kept === undefined ? null : kept));
  count("and the mailbox is still reported as drifting, because it still is",
    repaired.driftAfter.some(function (d) { return d.account === seeded.address; }) &&
    repaired.ok === false,
    JSON.stringify({ after: repaired.driftAfter, ok: repaired.ok }));

  await handle.mailbox.legalHold.release(seeded.actor, "INBOX", seeded.unfiled, {
    reason: "the order lapsed", approver: "records@" + DOMAIN,
  });
  var afterRelease = await handle.blobs.repairQuota({ reason: REPAIR_REASON });
  count("and the repair takes it once the order is released, so the mailbox is not " +
    "charged for it forever",
    handle.messageStore.fetchByObjectId(seeded.folder, seeded.unfiled[0]) === null &&
    afterRelease.removed.some(function (e) { return e.objectid === seeded.unfiled[0]; }),
    JSON.stringify(afterRelease.removed));
}

// ---- the direction nothing removes ------------------------------------------

async function aCounterBelowTheRowsIsReportedRatherThanForced(handle) {
  var seeded = await seedAccount(handle, "stranded@" + DOMAIN, []);

  // The mirror of an interrupted filing: the message store's row is gone
  // and this layer's row is not, so the counter reads below the rows and
  // nothing this server removes raises it.
  var filed = b.db.from(MESSAGES).where({ folder: seeded.folder }).all();
  handle.messageStore.hardExpunge(seeded.folder, [filed[0].objectid]);

  var before = counterFor(handle, seeded.folder);
  var repaired = await handle.blobs.repairQuota({ reason: REPAIR_REASON });
  var after = counterFor(handle, seeded.folder);

  count("a counter below the rows is reported as a mailbox nothing here repairs",
    repaired.unrepairable.some(function (e) { return e.account === seeded.address; }),
    JSON.stringify(repaired.unrepairable));
  count("and the repair removes nothing for it",
    repaired.removed.filter(function (e) { return e.account === seeded.address; }).length === 0,
    JSON.stringify(repaired.removed));
  count("and writes no counter, because a number set by hand is one nobody can derive " +
    "again",
    after.usedBytes === before.usedBytes && after.usedCount === before.usedCount,
    JSON.stringify({ before: before, after: after }));
  count("and says so rather than reporting the volume repaired",
    repaired.ok === false, JSON.stringify(repaired.ok));
  count("and the entry says what is wrong rather than only naming the mailbox",
    repaired.unrepairable.every(function (e) {
      return typeof e.detail === "string" && e.detail.length > 0;
    }), JSON.stringify(repaired.unrepairable));
}

// ---- the trail it leaves ----------------------------------------------------

async function theRepairLeavesARow(handle) {
  await seedAccount(handle, "recorded@" + DOMAIN, ["recorded-unfiled"]);

  b.audit.registerNamespace("blamepost");
  var capture = helpers.auditCapture();
  var rows;
  try {
    await b.audit.flush();
    await auditActor.runAs(auditActor.forCommandLine(), function () {
      return handle.blobs.repairQuota({ reason: REPAIR_REASON });
    });
    await b.audit.flush();
    rows = capture.forAction("blamepost.store.blobs.quota_repaired");
  } finally {
    capture.release();
  }

  count("the repair is recorded, because it destroys mail",
    rows.length === 1, String(rows.length) + " row(s)");
  if (rows.length === 0) return;
  var row = rows[0];
  count("and the row names who ran it", typeof row.actorUserId === "string" &&
    row.actorUserId.indexOf("cli:") === 0, JSON.stringify(row.actorUserId));
  count("and carries the reason the operator gave",
    String(row.reason || "").indexOf(REPAIR_REASON) !== -1, JSON.stringify(row.reason));

  var metadata = helpers.metadataOf(row);
  count("and counts what went and what stayed",
    metadata.removed === 1 && metadata.kept === 0,
    JSON.stringify({ removed: metadata.removed, kept: metadata.kept }));
  count("and carries no message content, because the chain is append-only and a value " +
    "written into it once cannot be taken back out",
    JSON.stringify(metadata).indexOf("recorded-unfiled") === -1 &&
    JSON.stringify(metadata).indexOf("the body of") === -1,
    JSON.stringify(metadata).slice(0, 240));
}

// ---- the retention floor outranks it too ------------------------------------

// A different volume, because the floor is set by the operator's posture
// and the posture is read when the server is composed.
async function theRetentionFloorStopsTheRepair(root) {
  var dataDir = nodePath.join(root, "floor-data");
  var cfg = config.load({
    env: {
      BLAMEPOST_HOSTNAME:           HOSTNAME,
      BLAMEPOST_DATA_DIR:           dataDir,
      BLAMEPOST_VAULT_PASSPHRASE:   VAULT_PASSPHRASE,
      BLAMEPOST_COMPLIANCE_POSTURE: "soc2",
    },
    cwd: root,
  });
  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: DOMAIN });
    var seeded = await seedAccount(handle, "floored@" + DOMAIN, ["inside-the-window"]);

    var repaired = await handle.blobs.repairQuota({ reason: REPAIR_REASON });
    var kept = repaired.kept.filter(function (e) {
      return e.objectid === seeded.unfiled[0];
    })[0];

    count("under a posture the floor keeps a message no mailbox row names, measured on " +
      "the arrival the server stamped rather than on a date a client sent",
      handle.messageStore.fetchByObjectId(seeded.folder, seeded.unfiled[0]) !== null,
      "the repair destroyed a message inside the regulated window");
    count("and it is reported under the floor's own reason",
      kept !== undefined && kept.reason === "retention-floor" && kept.preserved === true,
      JSON.stringify(kept === undefined ? null : kept));
    count("and the mailbox goes on being reported as drifting, because the charge is " +
      "real for as long as the message is kept",
      repaired.driftAfter.some(function (d) { return d.account === seeded.address; }),
      JSON.stringify(repaired.driftAfter));
  } finally {
    if (store.isOpen()) store.close();
  }
}

// ---- the command line -------------------------------------------------------

function theCommandLineCarriesTheVerb(cli) {
  var usage = cli(["blobs"]);
  count("`blamepost blobs` names the repair among its verbs, so an operator finds it " +
    "where the report that named the fault sent them",
    usage.both.indexOf("repair") !== -1, usage.both.slice(0, 600));

  var unconfirmed = cli(["blobs", "repair", "--reason", REPAIR_REASON]);
  count("the repair destroys mail, so it is refused without the confirmation every " +
    "other destructive verb here takes",
    unconfirmed.status !== 0 && /--confirm/.test(unconfirmed.both),
    "exit " + unconfirmed.status + " " + unconfirmed.both.slice(0, 300));

  var unexplained = cli(["blobs", "repair", "--confirm"]);
  count("and without a reason, which is what the audit row carries once the mail is gone",
    unexplained.status !== 0 && /--reason/.test(unexplained.both),
    "exit " + unexplained.status + " " + unexplained.both.slice(0, 300));
}

function theCommandLineRunsTheRepair(cli, address) {
  var before = cli(["blobs", "report"]);
  count("the report an operator reads first names how much of the drift the repair " +
    "would take, so the decision is made on a number rather than on a verb name",
    /is mail the store holds that no row names/.test(before.stdout),
    before.stdout.slice(0, 700));
  count("and sends them to the repair by name, which is what a diagnostic naming a " +
    "fault owes the person reading it",
    /blamepost blobs repair --confirm --reason/.test(before.stdout),
    before.stdout.slice(0, 700));

  var ran = cli(["blobs", "repair", "--confirm", "--reason", REPAIR_REASON, "--json"]);
  count("`blobs repair --confirm --reason` runs and answers",
    ran.status === 0, "exit " + ran.status + " " + ran.both.slice(0, 400));

  var parsed = jsonOf(ran);
  count("and the JSON answer names what it removed",
    parsed !== null && Array.isArray(parsed.removed) && parsed.removed.length === 1 &&
    parsed.removed[0].account === address,
    ran.stdout.slice(0, 400));

  var report = cli(["blobs", "report", "--json"]);
  var parsedReport = jsonOf(report);
  count("and the report the operator was reading no longer names the mailbox",
    parsedReport !== null && parsedReport.quotaDrift.length === 0,
    report.stdout.slice(0, 400));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("quota-drift-repair");
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

    // The command line goes FIRST, on a volume holding one mailbox in
    // the one state the repair closes.
    //
    // The library cases below deliberately leave mailboxes behind that
    // nothing repairs: a counter reading below its rows, and a message a
    // preservation order is keeping. Driving the command after those
    // would measure its exit code on a volume it is documented not to be
    // able to finish, which says nothing about whether it repairs what
    // it claims to. A second volume is not the way out either: the vault
    // is opened once per process and every sealed value takes its key
    // from the volume that opened it, so a volume created beside the
    // first is one no separate process can read.
    var cliAddress;
    var seedHandle = await store.open(cfg);
    try {
      await seedHandle.domains.add({ domain: DOMAIN });
      cliAddress = (await seedAccount(seedHandle, "cli@" + DOMAIN,
        ["left-for-the-command-line"])).address;
    } finally {
      seedHandle.close();
    }

    // One handle per process at a time: the database is encrypted at
    // rest and each process decrypts its own working copy, so a handle
    // held open while the child writes would flush a stale snapshot back
    // over the child's work.
    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });
    theCommandLineCarriesTheVerb(cli);
    theCommandLineRunsTheRepair(cli, cliAddress);

    var handle = await store.open(cfg);
    try {
      var seeded = await seedAccount(handle, "alice@" + DOMAIN, ["the-unfiled-one"]);

      theReportSaysHowMuchOfTheDriftIsRemovable(handle, seeded);
      await theRepairNeedsAReason(handle);
      theReaderTheReportIsBuiltFromNamesTheMail(handle, seeded);
      await aMailboxIsSweptOnItsOwn(handle);
      await theRepairRemovesTheMailNoRowNames(handle, seeded);
      await aSecondRunWritesNothing(handle);
      await aPreservationOrderKeepsTheMessageAndTheDrift(handle);
      await aCounterBelowTheRowsIsReportedRatherThanForced(handle);
      await theRepairLeavesARow(handle);
    } finally {
      handle.close();
    }

    await theRetentionFloorStopsTheRepair(root);

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

module.exports = { name: "quota-drift-repair", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (checks) {
    console.log("CHECKS " + checks);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
