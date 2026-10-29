// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every shape a rewritten audit trail can take, held against the verb an
 * operator runs to find out.
 *
 * SECURITY.md tells an operator to verify the chain on a schedule and to
 * trust what it says during an incident. That is a claim about detection,
 * and detection is not a property of hashing rows together. The row hash
 * is computed from readable columns and needs nothing secret, so anyone
 * who can write to the table can also recompute the sequence and leave it
 * agreeing with itself. What they cannot recompute is a checkpoint
 * signature, and what they cannot silently roll back is the counter the
 * volume recorded on disk the last time it was anchored. The guarantee
 * lives in those two, and this file drives each of them rather than
 * describing them.
 *
 * `cli-audit-chain.test.js` drives one edited row through the operator's
 * report and asserts what the report says. This file is about the family:
 * the same volume, one tamper each, and the refusal each one earns. A
 * chain that catches only the careless edit is not tamper evidence, so
 * the cases here are deletion from the middle, an unlinked row appended
 * at the end, a truncated tail with and without the on-disk anchor, the
 * whole table emptied, two rows exchanged, one row moved onto a
 * different operator, and the signed checkpoint itself rewritten.
 *
 * One case on the list is not a refusal and is here for that reason. A
 * row written by hand and linked onto the tip correctly agrees with
 * every reading this verb makes, and an append is what the trail does
 * all day, so there is nothing in it to refuse. What the verb owes an
 * operator there is a sentence bounded by who could have written the
 * row, and the case reads the sentence.
 *
 * The last three are the ones that matter most and they are the ones the
 * others make you believe cannot happen. Rewrite a row, recompute every
 * hash after it so the chain agrees with itself, and then DELETE the
 * checkpoints rather than trying to forge one. Nothing in the table
 * disagrees with anything else, and the next command to open the volume
 * signs a fresh checkpoint over the rewritten tip. The counter and the
 * hash the volume recorded on disk at its last honest anchoring are the
 * only witnesses left.
 *
 * Then do it once more, aimed at that witness. Delete the row it names
 * rather than editing it, relink what is left, and put the counter back
 * with a row above the gap: the table has not shrunk so nothing reports
 * a rollback, the sequence agrees with itself, and the counter the
 * record names is simply not there to be compared against. A gap is
 * also what an honest retention run leaves, which is why both are here
 * and why the volume records where a purge ended. A check that cannot
 * tell the two apart either passes the rewrite or refuses the boot after
 * every retention run, and the pair of cases is what holds it between
 * them.
 *
 * And the move somebody who has read this far makes: remove the record
 * instead of getting past it, so the one reading a rewrite cannot answer
 * for is never made. Nothing is broken and nothing is proven, and the
 * report has to say the second rather than printing the first.
 *
 * Each case needs a volume of its own, and it has to be built where it
 * will be read. The database encryption key is sealed against the path
 * of the directory holding it, so a volume copied somewhere else does
 * not open at all, which is the protection that stops a lifted data
 * directory being read on another machine. The framework also holds the
 * vault, the database and the audit counter as process state, so one
 * process opens one volume for its whole life.
 *
 * Both of those push the same way: this file orchestrates and opens
 * nothing. Each case gets a child of this file to build its volume
 * (`--seed`) and another to rewrite it (`--tamper`), and every
 * verification is the shipped binary spawned the way an operator runs
 * it. Building the volume is also what anchors it, because opening it
 * signs a checkpoint and records the tip on disk.
 *
 * Run standalone: node test/layer-1-state/audit-chain-tamper.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeProc = require("node:child_process");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// The framework's own chain tables, named here because a tamper case has
// to reach the rows the verb reads.
var AUDIT_TABLE      = "audit_log";
var CHECKPOINT_TABLE = "audit_checkpoints";

// Where the framework records that a range was archived and then deleted
// on purpose. A purge writes it and signs it; the cases below write it
// by hand so the cut lands exactly on the counter the volume recorded,
// and then sign it the same way the shipped verb does.
var PURGE_ANCHOR_TABLE = "_blamejs_audit_purge_anchor";

// The rollback-detection sidecar the framework writes beside the
// database every time it anchors the chain. It records the counter and
// the row hash at that anchoring, in plaintext, outside the encrypted
// database the rows live in.
var ANCHOR_FILE = "audit.tip";

function parseJson(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

// ---- the tamper, run in a child of this file --------------------------------

// Drop the append-only triggers guarding a chain table. This is what
// somebody who can write to the database does first, and doing it here
// rather than describing it is the point: a case that edited the rows
// through a supported call would be testing the supported call.
function dropAppendOnlyTriggers(table) {
  var triggers = b.db.prepare(
    "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?").all(table);
  triggers.forEach(function (t) { b.db.runSql("DROP TRIGGER " + t.name); });
  return triggers.length;
}

function auditCounters() {
  return b.db.prepare("SELECT monotonicCounter AS c FROM " + AUDIT_TABLE +
    " ORDER BY monotonicCounter ASC").all().map(function (r) { return Number(r.c); });
}

// Copy the newest row back into the table under a new counter, with the
// caller's changes applied. Every column travels, so the forged row is
// the shape the reader expects and the case is about the link rather
// than about a column the walk would have tripped over anyway.
function appendCopyOfTip(changes) {
  var last = b.db.prepare("SELECT * FROM " + AUDIT_TABLE +
    " ORDER BY monotonicCounter DESC LIMIT 1").get();
  var columns = Object.keys(last);
  var row = {};
  columns.forEach(function (name) { row[name] = last[name]; });
  Object.keys(changes).forEach(function (name) { row[name] = changes[name]; });
  var statement = b.db.prepare("INSERT INTO " + AUDIT_TABLE + " (" +
    columns.map(function (c) { return '"' + c + '"'; }).join(",") + ") VALUES (" +
    columns.map(function () { return "?"; }).join(",") + ")");
  statement.run.apply(statement, columns.map(function (name) { return row[name]; }));
  return { previous: last, inserted: row };
}

// The hash a row would carry if it followed `prevHash`, computed the way
// the walk computes it: every column except the three the hash covers
// from outside, and the cluster bookkeeping column the chain math leaves
// out so a schema upgrade does not read as a break.
function rowHashFollowing(prevHash, row) {
  var fields = Object.assign({}, row);
  delete fields.prevHash;
  delete fields.rowHash;
  delete fields.nonce;
  delete fields.fencingToken;
  var nonce = Buffer.isBuffer(row.nonce) ? row.nonce : Buffer.from(row.nonce);
  return b.auditChain.computeRowHash(prevHash, fields, nonce);
}

// Rewrite every remaining row's link so the table agrees with itself
// again, walking counter order from the anchor the chain begins at. This
// is the step that makes a rewritten trail indistinguishable from an
// honest one when the walk is the only reader. Hands back the hash the
// tip now carries, so a case that appends after it can link correctly.
function relinkEveryRow() {
  var ids = b.db.prepare("SELECT _id FROM " + AUDIT_TABLE +
    " ORDER BY monotonicCounter ASC").all();
  var previous = b.auditChain.ZERO_HASH;
  for (var i = 0; i < ids.length; i += 1) {
    var row = b.db.prepare("SELECT * FROM " + AUDIT_TABLE + " WHERE _id=?").get(ids[i]._id);
    var hash = rowHashFollowing(previous, row);
    b.db.prepare("UPDATE " + AUDIT_TABLE + ' SET "prevHash"=?, "rowHash"=? WHERE _id=?')
      .run(previous, hash, row._id);
    previous = hash;
  }
  return previous;
}

// The counter the volume recorded outside the database at its last
// anchoring. A case that has to reach exactly that row needs to know
// which one it is, and the file is where that is written down.
function anchorCounterOnDisk(dataDir) {
  var raw = nodeFs.readFileSync(nodePath.join(dataDir, ANCHOR_FILE), "utf8");
  return Number(JSON.parse(raw).atMonotonicCounter);
}

// Append a row that follows the current tip correctly: every column of
// the tip, the caller's changes over it, and both hashes computed
// afterwards so the row the walk reads is properly linked.
function appendLinkedRow(changes) {
  var last = b.db.prepare("SELECT * FROM " + AUDIT_TABLE +
    " ORDER BY monotonicCounter DESC LIMIT 1").get();
  var columns = Object.keys(last);
  var row = {};
  columns.forEach(function (name) { row[name] = last[name]; });
  Object.keys(changes).forEach(function (name) { row[name] = changes[name]; });
  row.prevHash = String(last.rowHash);
  row.rowHash  = rowHashFollowing(row.prevHash, row);
  var statement = b.db.prepare("INSERT INTO " + AUDIT_TABLE + " (" +
    columns.map(function (c) { return '"' + c + '"'; }).join(",") + ") VALUES (" +
    columns.map(function () { return "?"; }).join(",") + ")");
  statement.run.apply(statement, columns.map(function (name) { return row[name]; }));
  return row;
}

// The anchor row the framework's purge writes, in the shape a build that
// predates anchor signing left behind: the five columns that have always
// been there and neither of the two a signature needs.
function writeLegacyPurgeAnchor(cut, rowHash, bundleId) {
  b.db.prepare("INSERT INTO " + PURGE_ANCHOR_TABLE + " " +
    '("scope","lastPurgedCounter","lastPurgedRowHash","archiveBundleId","purgedAt") ' +
    "VALUES (?,?,?,?,?)")
    .run("audit", cut, String(rowHash), String(bundleId), Date.now());
}

// Sign the row that was just written, through the framework's own repair
// verb rather than by assembling a signature here. A fixture that minted
// its own would be asserting against a second implementation of the
// payload, and the layout it covers is the framework's to change.
async function signPurgeAnchor() {
  var signed = await b.auditTools.signExistingPurgeAnchor({ allow: ["unsigned"] });
  if (signed.signed !== true) {
    throw new Error("audit-chain-tamper: the purge anchor was not signed: " +
      String(signed.reason));
  }
  return signed;
}

// The rows and the anchor row a retention run whose cut landed on the
// counter the volume recorded leaves behind, without the signature. The
// three cases that start here differ only in what is done to the anchor
// afterwards, so the rows they leave on disk are identical and the
// signature is the whole of the difference between them.
function _purgeAwayTheAnchoredRow(dataDir) {
  dropAppendOnlyTriggers(AUDIT_TABLE);
  dropAppendOnlyTriggers(CHECKPOINT_TABLE);
  var anchored = anchorCounterOnDisk(dataDir);
  var anchoredRow = b.db.prepare("SELECT rowHash FROM " + AUDIT_TABLE +
    " WHERE monotonicCounter=?").get(anchored);
  // Something has to be left for the next event to attach to, which is
  // what the shipped purge refuses without.
  appendLinkedRow({
    _id:              b.uuid.v7(),
    monotonicCounter: anchored + 1,
    action:           "blamepost.audit.read",
    outcome:          "success",
  });
  b.db.runSql("DELETE FROM " + AUDIT_TABLE + " WHERE monotonicCounter <= " + anchored);
  b.db.runSql("DELETE FROM " + CHECKPOINT_TABLE + " WHERE atMonotonicCounter <= " + anchored);
  writeLegacyPurgeAnchor(anchored, anchoredRow.rowHash, "archive-under-test");
  return anchored;
}

// Move a field the signature covers, leaving the signature and the key
// fingerprint where they are. This is the edit somebody makes to widen
// the range an anchor licenses, and it is the case the row's signature
// exists to catch.
function editSignedPurgeAnchorRange(by) {
  var row = b.db.prepare("SELECT lastPurgedCounter FROM " + PURGE_ANCHOR_TABLE +
    " WHERE scope='audit'").get();
  b.db.prepare("UPDATE " + PURGE_ANCHOR_TABLE +
    ' SET "lastPurgedCounter"=? WHERE scope=?')
    .run(Number(row.lastPurgedCounter) + by, "audit");
}

var TAMPERS = {
  // The careless edit, kept here beside its siblings so the family reads
  // as one list. The operator-facing report for this shape is asserted in
  // cli-audit-chain.test.js; what is asserted here is the refusal class.
  "rewrite-one-row": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    var first = auditCounters()[0];
    b.db.runSql("UPDATE " + AUDIT_TABLE + " SET outcome='denied' WHERE monotonicCounter=" +
      first);
  },

  "delete-middle-row": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    var counters = auditCounters();
    b.db.runSql("DELETE FROM " + AUDIT_TABLE + " WHERE monotonicCounter=" +
      counters[Math.floor(counters.length / 2)]);
  },

  "append-unlinked-row": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    var next = auditCounters().pop() + 1;
    appendCopyOfTip({
      _id:              b.uuid.v7(),
      monotonicCounter: next,
      action:           "blamepost.audit.read",
      prevHash:         b.auditChain.ZERO_HASH,
      rowHash:          b.auditChain.ZERO_HASH,
    });
  },

  "swap-two-rows": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    var counters = auditCounters();
    var first  = counters[1];
    var second = counters[2];
    b.db.runSql("UPDATE " + AUDIT_TABLE + " SET monotonicCounter=-1 WHERE monotonicCounter=" +
      first);
    b.db.runSql("UPDATE " + AUDIT_TABLE + " SET monotonicCounter=" + first +
      " WHERE monotonicCounter=" + second);
    b.db.runSql("UPDATE " + AUDIT_TABLE + " SET monotonicCounter=" + second +
      " WHERE monotonicCounter=-1");
  },

  "truncate-tail": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    var counters = auditCounters();
    b.db.runSql("DELETE FROM " + AUDIT_TABLE + " WHERE monotonicCounter > " +
      counters[counters.length - 3]);
  },

  // The whole table, rather than a tail of it. Every other deletion case
  // leaves a prefix for the walk to agree with; this one leaves the walk
  // nothing to disagree with at all, so a check built around comparing
  // rows has no rows and reports a clean chain over an empty table.
  "truncate-whole-table": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    b.db.runSql("DELETE FROM " + AUDIT_TABLE);
  },

  // A row written into the table by hand and linked onto the tip
  // correctly, which is the append the walk cannot separate from an
  // honest one. Every hash agrees, the counter goes up rather than down,
  // and the row the volume's record names is untouched, so all three
  // readings pass. What this case is for is the sentence the verb prints
  // afterwards rather than the exit code.
  "append-linked-row-at-the-tip": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    appendLinkedRow({
      _id:              b.uuid.v7(),
      monotonicCounter: auditCounters().pop() + 1,
      action:           "account.reinstated",
      outcome:          "success",
      reason:           "a row nobody wrote",
    });
  },

  // One row moved onto a different operator, with nothing else touched.
  //
  // It is the edited-row case aimed at the column an incident asks about
  // first. A trail that proves an account was suspended and lets
  // somebody choose which operator it says suspended it is worse than
  // one naming nobody: the second reads as unattributed and the first is
  // acted on.
  "reattribute-a-row": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    var first = auditCounters()[0];
    b.db.prepare("UPDATE " + AUDIT_TABLE +
      ' SET "actorUserId"=? WHERE monotonicCounter=?')
      .run("cli:somebody-else@another-host", first);
  },

  "alter-checkpoint": function () {
    dropAppendOnlyTriggers(CHECKPOINT_TABLE);
    var newest = b.db.prepare("SELECT _id FROM " + CHECKPOINT_TABLE +
      " ORDER BY atMonotonicCounter DESC LIMIT 1").get();
    b.db.prepare("UPDATE " + CHECKPOINT_TABLE + ' SET "atRowHash"=? WHERE _id=?')
      .run("f".repeat(128), newest._id);
  },

  // The shape the other cases make you believe cannot happen. Rewrite a
  // row, recompute every hash after it, and remove the checkpoints
  // instead of forging one. Nothing left in the database disagrees with
  // anything else in it.
  "launder-through-a-full-recompute": function () {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    dropAppendOnlyTriggers(CHECKPOINT_TABLE);
    b.db.runSql("UPDATE " + AUDIT_TABLE + " SET outcome='denied' WHERE monotonicCounter=" +
      auditCounters()[0]);
    relinkEveryRow();
    b.db.runSql("DELETE FROM " + CHECKPOINT_TABLE);
  },

  // The same laundering, aimed at the one row that would give it away.
  //
  // Every other case leaves the anchored counter occupied, so the record
  // on disk has a row to disagree with. This one takes that row out
  // altogether and then puts the counter back with a forged row above
  // it, so the rollback check sees a table that has not shrunk, the walk
  // sees a sequence that agrees with itself, and the anchored counter is
  // simply not there to be compared. A gap is what an honest purge also
  // leaves behind, and the volume records where a purge ended, so the
  // two are distinguishable, and an anchor check that cannot tell them
  // apart forfeits on exactly the rewrite it exists to catch.
  "erase-the-anchored-row": function (dataDir) {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    dropAppendOnlyTriggers(CHECKPOINT_TABLE);
    var anchored = anchorCounterOnDisk(dataDir);
    b.db.runSql("DELETE FROM " + AUDIT_TABLE + " WHERE monotonicCounter=" + anchored);
    relinkEveryRow();
    appendLinkedRow({
      _id:              b.uuid.v7(),
      monotonicCounter: anchored + 1,
      action:           "blamepost.audit.read",
      outcome:          "success",
    });
    b.db.runSql("DELETE FROM " + CHECKPOINT_TABLE);
  },

  // The one legitimate way a counter loses its row, left in the state a
  // verified archive and purge leaves it in: the rows up to a cut gone,
  // the checkpoints covering them gone with them, and the framework's
  // purge anchor recording where the deletion stopped, what the last
  // deleted row hashed to, and a signature over both.
  //
  // It is here rather than beside the CLI's archive and purge flow
  // because that flow cuts by timestamp, and the case that matters is
  // the one where the cut lands ON the counter the volume recorded. A
  // check strict enough to catch the case above and not this one refuses
  // a boot after an ordinary retention run, which is the failure that
  // gets a check deleted rather than fixed.
  //
  // The signature is what tells this apart from the two cases under it,
  // and all three leave the same rows on disk. Signing an anchor costs
  // the audit-signing key, which is sealed under the vault passphrase,
  // so the three differ in exactly what the row cost whoever wrote it.
  "purge-away-the-anchored-row": async function (dataDir) {
    _purgeAwayTheAnchoredRow(dataDir);
    await signPurgeAnchor();
  },

  // The same gap, held open by an anchor written before the framework
  // signed them. The columns a signature lives in are not filled in,
  // which is the shape a volume purged by an earlier build carries.
  "purge-anchor-left-unsigned": function (dataDir) {
    _purgeAwayTheAnchoredRow(dataDir);
  },

  // The same gap again, held open by an anchor that was signed and then
  // widened. The signature and the key fingerprint are the ones the
  // framework wrote; the range they cover is not the range the row now
  // claims, which is what somebody licensing rows they deleted does to
  // an anchor they cannot re-sign.
  "purge-anchor-signature-edited": async function (dataDir) {
    _purgeAwayTheAnchoredRow(dataDir);
    await signPurgeAnchor();
    editSignedPurgeAnchorRange(1);
  },

  // The same honest retention run, cut where the framework's own two
  // bounds meet.
  //
  // An archive covers itself with the EARLIEST checkpoint standing at or
  // above the last row it archived, and the purge that archive authorizes
  // deletes every checkpoint at or below that same counter. Both bounds
  // are inclusive, so a checkpoint sitting exactly on the cut is named by
  // the archive and deleted by the purge in the one operation. The anchor
  // is then left naming a checkpoint that is not there.
  //
  // Nothing here is a tamper. It is what the shipped verbs leave behind
  // whenever the cut lands on a checkpoint, and the case above cannot
  // stand in for it: that one writes a bundle id no checkpoint ever
  // carried, which is a state an archive could not produce, so a check
  // that reads "the name resolves to nothing" as evidence of a rewrite
  // passes it and fails this one. The difference between the two is the
  // whole reason this case exists.
  "purge-at-the-covering-checkpoint": async function (dataDir) {
    dropAppendOnlyTriggers(AUDIT_TABLE);
    dropAppendOnlyTriggers(CHECKPOINT_TABLE);
    var anchored = anchorCounterOnDisk(dataDir);
    // The archive's own selection, run here rather than described, so the
    // cut is the counter the shipped verb would have chosen.
    var covering = b.db.prepare("SELECT _id, atMonotonicCounter FROM " + CHECKPOINT_TABLE +
      " WHERE atMonotonicCounter >= ? ORDER BY atMonotonicCounter ASC LIMIT 1").get(anchored);
    if (!covering) {
      throw new Error("purge-at-the-covering-checkpoint: no checkpoint stands at or above " +
        "counter " + anchored + ", so the boundary this case is about is not on this volume");
    }
    var cut = Number(covering.atMonotonicCounter);
    var cutRow = b.db.prepare("SELECT rowHash FROM " + AUDIT_TABLE +
      " WHERE monotonicCounter=?").get(cut);
    if (!cutRow) {
      throw new Error("purge-at-the-covering-checkpoint: no audit row stands at counter " +
        cut + ", so there is no purge for the checkpoint there to be covering");
    }
    // Something has to survive the cut for the next event to link onto,
    // which is what the shipped purge refuses without.
    var counters = auditCounters();
    if (cut >= counters[counters.length - 1]) {
      appendLinkedRow({
        _id:              b.uuid.v7(),
        monotonicCounter: counters[counters.length - 1] + 1,
        action:           "blamepost.audit.read",
        outcome:          "success",
      });
    }
    b.db.runSql("DELETE FROM " + AUDIT_TABLE + " WHERE monotonicCounter <= " + cut);
    b.db.runSql("DELETE FROM " + CHECKPOINT_TABLE + " WHERE atMonotonicCounter <= " + cut);
    // The anchor the shipped purge writes, naming the checkpoint the
    // archive covered itself with: the one the line above just deleted,
    // and signed the way the shipped purge signs it.
    writeLegacyPurgeAnchor(cut, cutRow.rowHash, covering._id);
    await signPurgeAnchor();
  },
};

// One volume, with enough rows for a middle to take one out of and
// enough that a truncated tail leaves a prefix behind rather than an
// empty table.
async function seedChild(dataDir, workDir) {
  process.env.BLAMEJS_TMPDIR = workDir;
  var handle = await store.open(configFor(dataDir));
  try {
    await handle.domains.add({ domain: DOMAIN });
    await handle.accounts.create({ address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    await handle.domains.add({ domain: "second.example" });
    await handle.accounts.create({ address: "bob@" + DOMAIN, password: ALICE_PASSWORD });
    await b.audit.flush();
  } finally { handle.close(); }
}

async function tamperChild(name, dataDir, workDir) {
  if (!Object.prototype.hasOwnProperty.call(TAMPERS, name)) {
    throw new Error("audit-chain-tamper: no tamper named " + JSON.stringify(name));
  }
  process.env.BLAMEJS_TMPDIR = workDir;
  var handle = await store.open(configFor(dataDir));
  try { await TAMPERS[name](dataDir); } finally { handle.close(); }
}

function configFor(dataDir) {
  return config.load({
    env: {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    },
    cwd: dataDir,
  });
}

// ---- the harness ------------------------------------------------------------

function _child(what, args) {
  var result = nodeProc.spawnSync(process.execPath, [__filename].concat(args),
    { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error("audit-chain-tamper: " + what + " did not run: " +
      cliHelper.withoutBootLines(String(result.stderr || result.stdout || ""))
        .replace(/\s+/g, " ").slice(0, 400));
  }
}

// A volume of this case's own, built where it will be read and anchored
// by one run of the verb before anything is done to it. That run is what
// signs the first checkpoint and writes the record on disk, so every
// case below starts from a volume that has both.
function anchoredVolume(root, name) {
  var caseRoot = nodePath.join(root, name);
  var dataDir  = nodePath.join(caseRoot, "data");
  var workDir  = nodePath.join(caseRoot, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  _child("the " + name + " seed", ["--seed", dataDir, workDir]);
  var cli = cliHelper.create({
    dataDir:         dataDir,
    workDir:         workDir,
    hostname:        HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
  });
  var anchoring = cli(["audit", "verify-chain"]);
  if (anchoring.status !== 0) {
    throw new Error("audit-chain-tamper: the " + name + " volume did not verify before " +
      "anything was done to it: " + anchoring.both.replace(/\s+/g, " ").slice(0, 400));
  }
  return { dataDir: dataDir, workDir: workDir, cli: cli, anchoring: anchoring };
}

// Build a volume, rewrite it one way, and ask the shipped binary what it
// makes of the result.
function verdictAfter(root, caseName, opts) {
  var options = opts || {};
  var volume = anchoredVolume(root, "case-" + caseName + (options.suffix || ""));
  if (options.removeAnchor === true) {
    nodeFs.rmSync(nodePath.join(volume.dataDir, ANCHOR_FILE), { force: true });
  }
  _child("the " + caseName + " tamper",
    ["--tamper", caseName, volume.dataDir, volume.workDir]);
  var text = volume.cli(["audit", "verify-chain"]);
  var json = volume.cli(["audit", "verify-chain", "--json"]);
  return { text: text, json: json, verdict: parseJson(json.stdout), volume: volume };
}

// The shape every refusal has to have, whatever broke. A verb that
// exited non-zero and said nothing an operator can act on has reported
// the failure without reporting the finding.
function refusalIsUsable(label, seen) {
  count(label + ": the verb exits non-zero", seen.text.status !== 0,
    "exit " + seen.text.status + " " + seen.text.both.slice(0, 200));
  count(label + ": and tells the operator to take a copy of the volume before anything else",
    /copy/i.test(seen.text.both), seen.text.both.slice(0, 300));
}

// A refusal the framework raises before it will hand back the database.
// It reaches the operator as this verb's verdict rather than as a
// command that crashed, so the machine-readable form has to carry the
// code a monitor alerts on.
function chainRefusal(label, seen, code, reason) {
  refusalIsUsable(label, seen);
  count(label + ": the machine-readable verdict reports the chain as broken",
    seen.verdict !== null && seen.verdict.ok === false &&
    seen.verdict.chain && seen.verdict.chain.ok === false,
    seen.json.stdout.slice(0, 300));
  count(label + ": under the code " + code,
    seen.verdict !== null && seen.verdict.chain && seen.verdict.chain.code === code,
    JSON.stringify(seen.verdict && seen.verdict.chain && seen.verdict.chain.code));
  count(label + ": and names why the walk stopped (" + reason + ")",
    reason.test(String(seen.verdict && seen.verdict.chain && seen.verdict.chain.reason)),
    String(seen.verdict && seen.verdict.chain && seen.verdict.chain.reason).slice(0, 300));
}

// ---- the cases --------------------------------------------------------------

function aHealthyVolumeVerifies(volume) {
  count("a volume nobody has touched verifies", volume.anchoring.status === 0,
    "exit " + volume.anchoring.status + " " + volume.anchoring.both.slice(0, 300));

  // The first run on a volume that has never been anchored is the run
  // that anchors it, so it has nothing outside the database to hold the
  // rows against and says so. Asserting that here rather than letting it
  // pass as an ordinary success is the point: this is the reading every
  // case below depends on, and a run that never made it would have
  // reported all eight of them clean.
  count("the first run on a volume that has never been anchored says so rather than " +
    "reporting a trail it held against nothing",
    /not held against anything outside the database/.test(volume.anchoring.stdout),
    volume.anchoring.stdout.slice(0, 600));
  count("and it does not tell the operator the trail is intact on the strength of two " +
    "readings that both come out of the database being asked about",
    !/inserted, altered or removed/.test(volume.anchoring.stdout),
    volume.anchoring.stdout.slice(0, 600));

  var text    = volume.cli(["audit", "verify-chain"]);
  var verdict = parseJson(volume.cli(["audit", "verify-chain", "--json"]).stdout);
  count("a second run, with the record the first one wrote, verifies", text.status === 0,
    "exit " + text.status + " " + text.both.slice(0, 300));
  count("and it carries the signed checkpoint the cases below have to get past",
    verdict !== null && verdict.checkpoints && verdict.checkpoints.checkpointsVerified >= 1,
    JSON.stringify(verdict && verdict.checkpoints));
  count("and it says plainly that nothing has been altered, which is the sentence " +
    "every case below has to stop it printing",
    /inserted, altered or removed/.test(text.stdout), text.stdout.slice(0, 600));
  count("and it scopes that to who could not have done it, because the key signing " +
    "the checkpoints opens under the same passphrase as the database",
    /vault passphrase/.test(text.stdout), text.stdout.slice(0, 800));
  count("and it reports the reading made from outside the database as its own line, " +
    "since that is the only one a rewrite of the database cannot answer for",
    /record of its last anchoring/.test(text.stdout), text.stdout.slice(0, 800));
  count("and the machine-readable verdict carries that reading, so a monitor can tell " +
    "a check that passed from one that could not be made",
    verdict !== null && verdict.anchor && verdict.anchor.checked === true,
    JSON.stringify(verdict && verdict.anchor));
}

// The move somebody who has read this far makes: remove the record
// outside the database, so the one reading a rewrite cannot answer for
// simply is not made. Nothing is broken and nothing is proven, and the
// report has to say the second rather than printing the first.
function anAbsentAnchorIsReportedRatherThanForfeited(root) {
  var volume = anchoredVolume(root, "case-anchor-removed");
  nodeFs.rmSync(nodePath.join(volume.dataDir, ANCHOR_FILE), { force: true });
  var text = volume.cli(["audit", "verify-chain"]);
  var verdict = parseJson(volume.cli(["audit", "verify-chain", "--json"]).stdout);
  count("a volume whose record of its last anchoring is gone is never told the trail " +
    "is intact",
    !/inserted, altered or removed/.test(text.both), text.both.slice(0, 600));
  count("a volume whose record of its last anchoring is gone says the rows were held " +
    "against nothing outside the database they live in",
    /not held against anything outside the database/.test(text.both),
    text.both.slice(0, 600));
  count("and the machine-readable verdict marks the reading as one that was not made",
    verdict !== null && verdict.anchor && verdict.anchor.checked === false,
    JSON.stringify(verdict && verdict.anchor));
}

function theAnchorIsOnDiskBesideTheDatabase(volume) {
  var anchorPath = nodePath.join(volume.dataDir, ANCHOR_FILE);
  count("the volume records its own last anchoring outside the encrypted database",
    nodeFs.existsSync(anchorPath), anchorPath);
  var anchor = nodeFs.existsSync(anchorPath)
    ? parseJson(nodeFs.readFileSync(anchorPath, "utf8"))
    : null;
  count("and the record names the counter it anchored",
    anchor !== null && typeof anchor.atMonotonicCounter === "number" &&
    anchor.atMonotonicCounter > 0, JSON.stringify(anchor));
  count("and the hash the row at that counter carried, which is the part that " +
    "survives a rewrite of the rows themselves",
    anchor !== null && typeof anchor.atRowHash === "string" && anchor.atRowHash.length === 128,
    String(anchor && anchor.atRowHash).slice(0, 32));
}

function anEditedRowIsRefused(root) {
  chainRefusal("an edited row", verdictAfter(root, "rewrite-one-row"),
    "db/audit-chain-break", /rowHash mismatch/);
}

function aRowDeletedFromTheMiddleIsRefused(root) {
  var seen = verdictAfter(root, "delete-middle-row");
  chainRefusal("a row taken out of the middle", seen,
    "db/audit-chain-break", /prevHash mismatch/);
  count("a row taken out of the middle: the report names the row the walk stopped at",
    /break row _id/.test(seen.text.both), seen.text.both.slice(0, 400));
  count("a row taken out of the middle: and carries the two hashes that disagree",
    /expected:/.test(seen.text.both) && /actual:/.test(seen.text.both),
    seen.text.both.slice(0, 500));
}

function aRowAppendedWithoutALinkIsRefused(root) {
  chainRefusal("a row appended with no link to the one before it",
    verdictAfter(root, "append-unlinked-row"),
    "db/audit-chain-break", /prevHash mismatch/);
}

function twoRowsExchangedAreRefused(root) {
  chainRefusal("two rows exchanged", verdictAfter(root, "swap-two-rows"),
    "db/audit-chain-break", /prevHash mismatch/);
}

// A truncated tail leaves a chain that still agrees with itself: every
// remaining row follows the one before it, so the walk alone reports a
// clean prefix. What catches it is the counter the volume recorded on
// disk the last time it anchored.
function aTruncatedTailIsRefused(root) {
  var seen = verdictAfter(root, "truncate-tail");
  chainRefusal("a truncated tail", seen,
    "db/audit-rollback-detected", /rollback detected/);
  count("a truncated tail: the refusal names both counters, so the operator can see " +
    "how many rows are gone",
    /recorded counter: \d+/.test(String(seen.verdict.chain.reason)) &&
    /current DB max counter: \d+/.test(String(seen.verdict.chain.reason)),
    String(seen.verdict.chain.reason).slice(0, 300));
}

// The whole table emptied rather than a tail of it taken off.
//
// It is here beside the tail case because the two fail differently for a
// reader built around comparing rows: a tail leaves a prefix that still
// agrees with itself, and this leaves nothing, so a walk is handed an
// empty table and has nothing to report. The counter the volume recorded
// outside the database is what answers, and the number it is held
// against is zero, which is the one comparison a check reading a count
// as "no rows, nothing to check" would skip.
function anEmptiedTableIsRefused(root) {
  var seen = verdictAfter(root, "truncate-whole-table");
  chainRefusal("every row deleted", seen,
    "db/audit-rollback-detected", /rollback detected/);
  count("every row deleted: the refusal says the table now stands at counter zero, so " +
    "the operator reads how much is gone rather than that something is",
    /current DB max counter: 0\b/.test(String(seen.verdict.chain.reason)),
    String(seen.verdict.chain.reason).slice(0, 300));
  count("every row deleted: and the operator is never told the trail is intact",
    !/inserted, altered or removed/.test(seen.text.both), seen.text.both.slice(0, 400));
}

// A row appended and linked onto the tip correctly, which is the one
// rewrite on this list that nothing here detects.
//
// Every reading the verb makes is a reading about rows that are already
// there. The walk agrees because the forged row's hashes were computed
// the way the walk computes them; the counter went up, so nothing was
// rolled back; and the row the volume's record names is untouched, so
// the record agrees as well. An append is also what the trail does all
// day, so there is nothing about the shape of one to refuse.
//
// What the verb owes the operator is therefore not a refusal but an
// honest sentence, and that is what is read here. The claim it prints is
// bounded by who could have made the change: writing a row into this
// table costs the vault passphrase, and the passphrase unseals the key
// that signs the checkpoints as well. An unbounded version of the same
// sentence would be false on this volume, over a row that is sitting in
// it.
//
// The answer to the case is the fourth trust root rather than anything
// here: a copy of the trail somewhere this server cannot reach, which is
// what the closing sentence sends the operator to.
function anAppendedLinkedRowIsNotDetectedAndIsNotDeniedEither(root) {
  var volume = anchoredVolume(root, "case-append-linked-row");
  _child("the append-linked-row tamper",
    ["--tamper", "append-linked-row-at-the-tip", volume.dataDir, volume.workDir]);

  var text    = volume.cli(["audit", "verify-chain"]);
  var verdict = parseJson(volume.cli(["audit", "verify-chain", "--json"]).stdout);
  var read    = volume.cli(["audit", "read", "--limit", "200"]);

  count("a row written into the table by hand and linked onto the tip is on the volume",
    /a row nobody wrote/.test(read.stdout), read.stdout.slice(0, 400));

  count("and the chain still verifies, because every reading this verb makes is a " +
    "reading of rows that are already there and an append disagrees with none of them",
    text.status === 0, "exit " + text.status + " " + text.both.slice(0, 400));

  count("and the reading against the volume's own record still passes, because the row " +
    "that record names was not the row that moved",
    verdict !== null && verdict.anchor && verdict.anchor.checked === true,
    JSON.stringify(verdict && verdict.anchor));

  count("so what the operator is owed here is a bounded sentence rather than a refusal, " +
    "and the claim names who it excludes",
    /inserted, altered or removed/.test(text.stdout) &&
    /who did not hold/.test(text.stdout) && /vault passphrase/.test(text.stdout),
    text.stdout.slice(0, 900));

  count("and it sends the operator to the copy held where this server cannot reach it, " +
    "which is the only thing that answers an append",
    /somewhere this server cannot reach/.test(text.stdout), text.stdout.slice(0, 900));
}

// One row moved onto a different operator, nothing else touched.
//
// The column is inside the row's own digest, so this is refused as an
// edited row. It is driven through the shipped binary here rather than
// only against the walk, because the column is the one an incident asks
// about first and a refusal that never reached the operator would be no
// refusal at all. Which columns the digest covers, all of them, is
// established next door in `audit-row-digest-coverage.test.js`.
function aReattributedRowIsRefused(root) {
  var seen = verdictAfter(root, "reattribute-a-row");
  chainRefusal("a row moved onto a different operator", seen,
    "db/audit-chain-break", /rowHash mismatch/);
  count("a row moved onto a different operator: the refusal names the row it stopped " +
    "at, so the operator can see which action has been reattributed",
    /break row _id/.test(seen.text.both), seen.text.both.slice(0, 400));
}

// The same truncation with the on-disk record removed as well, which is
// the move somebody who has read this far would make. The signed
// checkpoint anchors a counter that is no longer in the table, and that
// is what is left.
function aTruncatedTailWithoutItsAnchorIsRefused(root) {
  chainRefusal("a truncated tail with the on-disk record removed too",
    verdictAfter(root, "truncate-tail", { removeAnchor: true, suffix: "-no-anchor" }),
    "db/audit-checkpoint-break", /anchored audit_log row missing/);
}

function arewrittenCheckpointIsRefused(root) {
  chainRefusal("the signed checkpoint rewritten",
    verdictAfter(root, "alter-checkpoint"),
    "db/audit-checkpoint-break", /signature failed/);
}

// The case the other seven make you believe cannot happen: the whole
// chain recomputed so it agrees with itself, and the checkpoints deleted
// rather than forged. Nothing inside the database disagrees with
// anything else in it, and the next command to open the volume writes a
// fresh checkpoint over the rewritten tip. Only the record the volume
// left on disk at its last honest anchoring still says otherwise.
function aRecomputedChainWithItsCheckpointsRemovedIsRefused(root) {
  var seen = verdictAfter(root, "launder-through-a-full-recompute");
  chainRefusal("a recomputed chain whose checkpoints were deleted", seen,
    "store/audit-anchor-mismatch", /record of it/);
  count("a recomputed chain whose checkpoints were deleted: and the operator is never " +
    "told the trail is intact",
    !/inserted, altered or removed/.test(seen.text.both),
    seen.text.both.slice(0, 400));
}

// The same laundering with the anchored row deleted rather than edited.
//
// Nothing inside the database disagrees with anything else in it, the
// table has not shrunk, and the counter the volume recorded is a gap
// rather than a row that hashes differently. The record on disk is the
// only witness left and it is the one being stepped around, so a check
// that forfeits on a missing row hands back a clean report over a trail
// that has had a row taken out of it.
function theAnchoredRowErasedIsRefused(root) {
  var seen = verdictAfter(root, "erase-the-anchored-row");
  chainRefusal("the anchored row erased and the counter put back above it", seen,
    "store/audit-anchor-row-missing", /no row at that counter/);
  count("the anchored row erased: the refusal repeats on every later run rather than " +
    "being consumed by the run that found it",
    /audit\.disputed/.test(seen.json.both), seen.json.both.slice(0, 500));
  count("the anchored row erased: and the operator is never told the trail is intact",
    !/inserted, altered or removed/.test(seen.text.both),
    seen.text.both.slice(0, 400));
  count("the anchored row erased: the refusal names the counter that is gone, so the " +
    "operator knows where to look",
    /counter \d+/.test(seen.text.both), seen.text.both.slice(0, 400));
  count("the anchored row erased: and says why a gap is not an ordinary state here, " +
    "since an archive and purge is the one thing that leaves one",
    /purge/i.test(seen.text.both), seen.text.both.slice(0, 600));
}

// The same gap, left behind by the one thing that is allowed to leave
// one. This is the case that decides whether the refusal above is a
// check or a nuisance: a volume that has been through a retention run
// has to keep opening, and the difference between the two is a record
// the framework writes down rather than anything about the rows.
//
// Two runs rather than one, and what the second one is for has changed.
// It used to be unaskable: opening the volume anchors the chain again,
// so the record a second run read was the one the first run wrote, and
// by then the gap was behind the new anchor and the volume read as
// ordinary. That is the shape a finding must not have, so the verdict is
// now written down like the refusals beside it and the second run
// answers from the file rather than from a record that has moved on.
//
// What this case pins is therefore the boot and not the sentence. It
// used to assert that the operator is told the trail is intact, and the
// case below is why that assertion is gone: the rows in the gap were
// never read, so the trail being intact is not something either run
// established. Both properties are real and they are not the same
// property. A retention run must not cost the volume its next boot, and
// that is asserted here. A range nobody read must not be reported as a
// range nothing was removed from, and that is asserted next door. The
// sentence was the only place they collided, and it was the sentence
// that was wrong.
function aPurgedAnchoredRowIsNotARefusal(root) {
  var volume = anchoredVolume(root, "case-purge-away-the-anchored-row");
  _child("the purge-away-the-anchored-row tamper",
    ["--tamper", "purge-away-the-anchored-row", volume.dataDir, volume.workDir]);
  var json    = volume.cli(["audit", "verify-chain", "--json"]);
  var verdict = parseJson(json.stdout);
  count("a counter whose row a verified archive and purge removed is not read as a " +
    "deletion, so a retention run does not cost the volume its next boot",
    json.status === 0, "exit " + json.status + " " + json.both.slice(0, 500));
  count("and the machine-readable verdict marks the reading as one that was made, " +
    "against a counter the purge accounts for",
    verdict !== null && verdict.anchor && verdict.anchor.checked === true &&
    verdict.anchor.purged === true, JSON.stringify(verdict && verdict.anchor));
  var second = volume.cli(["audit", "verify-chain"]);
  count("and the volume goes on opening on the run after the one that found the gap, " +
    "which is what a retention run must not cost it",
    second.status === 0, "exit " + second.status + " " + second.both.slice(0, 400));
  count("and that second run reaches the same verdict rather than an ordinary volume, " +
    "because the reading was written down before the re-anchoring could consume it",
    /a gap this run did not read/.test(second.stdout), second.stdout.slice(0, 600));
}

// The same gap held open by a purge record the framework signed, which
// is what every purge this build performs writes.
//
// The record used to be worth less than everything else read on this
// path: no signature over it, no link into the chain, no checkpoint
// covering it, so writing the row was the whole cost of making a
// deletion read as a retention run. It is signed now, and the signing
// key is sealed under the same passphrase as the database, so writing
// one costs what rewriting the rows costs. A reader that goes on calling
// every anchor unsigned hands the operator the weaker of the two facts
// and hands it to them as the only one.
//
// What does not change is the range. The rows are still gone, this run
// still read none of them, and the archive named is still off the
// volume, so the verdict stays a gap the run did not read. The signature
// moves what is holding the gap open, not what was checked in it.
function aSignedPurgeBoundaryIsNotReportedAsUnsigned(root) {
  var volume = anchoredVolume(root, "case-signed-purge-boundary");
  _child("the purge-away-the-anchored-row tamper",
    ["--tamper", "purge-away-the-anchored-row", volume.dataDir, volume.workDir]);

  // The machine-readable run first and the text run after it, so the
  // second one answers from the file the first wrote. Both have to say
  // the same thing about the boundary: a monitor reading the run that
  // found the gap and an operator reading the run after it are looking
  // at one volume.
  var json    = volume.cli(["audit", "verify-chain", "--json"]);
  var verdict = parseJson(json.stdout);
  var text    = volume.cli(["audit", "verify-chain"]);

  count("a gap held open by a purge record this volume's own audit-signing key signed " +
    "does not cost the volume its next boot",
    text.status === 0, "exit " + text.status + " " + text.both.slice(0, 500));

  count("and the operator is not told the record carries no signature, which is the " +
    "one thing about it that has stopped being true",
    /carries no signature/.test(text.stdout) === false &&
    /unsigned/.test(text.stdout) === false, text.stdout.slice(0, 900));

  count("and the report says what the signature covers, so an operator can tell what " +
    "moving the boundary would have cost whoever moved it",
    /signature covers/.test(text.stdout), text.stdout.slice(0, 900));

  count("and the machine-readable verdict says the boundary is signed, so a monitor " +
    "can tell the two records apart without reading the sentence",
    verdict !== null && verdict.anchor && verdict.anchor.purged === true &&
    verdict.anchor.signed === true, JSON.stringify(verdict && verdict.anchor));

  count("and it still does not answer for the rows it did not read, because a signed " +
    "boundary is a boundary rather than a reading of the range behind it",
    /inserted, altered or removed/.test(text.stdout) === false,
    text.stdout.slice(0, 900));

  count("and it still does not claim the archive was resolved, because nothing here " +
    "resolves one",
    /verified archive/.test(text.stdout) === false, text.stdout.slice(0, 900));
}

// The same gap held open by an anchor written before the framework
// signed them, which is what a volume purged by an earlier build
// carries. The rows on disk are identical to the case above.
//
// It is refused, and what the operator is told is which of the two
// records they have. A refusal that named the wrong one would send them
// to look for an intruder over a volume nobody touched, or leave them
// reading an edit as an upgrade they never made.
function anOldFormatPurgeAnchorIsNamedAsUnsigned(root) {
  var volume = anchoredVolume(root, "case-purge-anchor-left-unsigned");
  _child("the purge-anchor-left-unsigned tamper",
    ["--tamper", "purge-anchor-left-unsigned", volume.dataDir, volume.workDir]);

  var text = volume.cli(["audit", "verify-chain"]);
  var json = volume.cli(["audit", "verify-chain", "--json"]);
  var verdict = parseJson(json.stdout);

  count("a gap held open by an anchor with no signature over it is refused rather than " +
    "read as a retention run",
    text.status !== 0, "exit " + text.status + " " + text.both.slice(0, 500));

  count("and the refusal says the record carries no signature, which is what tells an " +
    "operator it is a record an older build wrote",
    /carries no signature/.test(String(verdict && verdict.chain && verdict.chain.reason)),
    String(verdict && verdict.chain && verdict.chain.reason).slice(0, 400));

  count("and it does not read as a record that was edited, which is the other way an " +
    "anchor fails to verify and needs the opposite response",
    /does not cover its own fields/.test(
      String(verdict && verdict.chain && verdict.chain.reason)) === false,
    String(verdict && verdict.chain && verdict.chain.reason).slice(0, 400));

  count("and the operator is never told the trail is intact over the range that anchor " +
    "claims",
    /inserted, altered or removed/.test(text.both) === false, text.both.slice(0, 600));
}

// The third answer, and the one the reader had no way to give: an anchor
// carrying a signature that does not cover the fields it now holds.
//
// The rows on disk are the same rows again. The signature and the key
// fingerprint are the ones the framework wrote, and the range they cover
// is not the range the row claims, which is what widening a boundary
// looks like to somebody who cannot re-sign it. It must not read as the
// signed retention run and it must not read as the older record, because
// the three call for three different responses: nothing, an upgrade, and
// taking a copy of the volume.
function anEditedPurgeAnchorIsNotReadAsMerelyOld(root) {
  var volume = anchoredVolume(root, "case-purge-anchor-signature-edited");
  _child("the purge-anchor-signature-edited tamper",
    ["--tamper", "purge-anchor-signature-edited", volume.dataDir, volume.workDir]);

  var text = volume.cli(["audit", "verify-chain"]);
  var json = volume.cli(["audit", "verify-chain", "--json"]);
  var verdict = parseJson(json.stdout);

  count("an anchor whose signature no longer covers the range it claims is refused",
    text.status !== 0, "exit " + text.status + " " + text.both.slice(0, 500));

  count("and the refusal says the signature does not cover the anchor's own fields, " +
    "which is the finding rather than the symptom",
    /does not cover its own fields/.test(
      String(verdict && verdict.chain && verdict.chain.reason)),
    String(verdict && verdict.chain && verdict.chain.reason).slice(0, 400));

  count("and it does not read as an anchor an older build left unsigned, which is the " +
    "reading that would turn an edit into an upgrade note",
    /carries no signature/.test(
      String(verdict && verdict.chain && verdict.chain.reason)) === false,
    String(verdict && verdict.chain && verdict.chain.reason).slice(0, 400));

  count("and it does not read as the retention run it was edited to look like",
    /a gap this run did not read/.test(text.both) === false, text.both.slice(0, 600));

  count("and the operator is never told the trail is intact",
    /inserted, altered or removed/.test(text.both) === false, text.both.slice(0, 600));

  count("and the verb tells them to take a copy of the volume before anything else",
    /copy/i.test(text.both), text.both.slice(0, 600));
}

// The same gap read the other way round: not "does the volume still
// boot" but "what has the operator just been told, and is it true".
//
// The gap above and a wholesale deletion are the same bytes on disk. A
// purge writes one row into `_blamejs_audit_purge_anchor`, and a
// signature over that row says who wrote it and says nothing about the
// rows it names: the row sits in no chain, is covered by no checkpoint,
// and is bound to no archive that anything here resolves. So whatever
// the verb decides to DO about the gap, what it may SAY about it is
// bounded by what it checked, and the two things it says here are
// outside that bound.
//
// It reports the gap as one "a verified archive and purge has since
// removed" while having verified no archive: the anchor names one, the
// verb never resolves it, and the sentence states as fact the single
// thing that would separate a retention run from an erasure. And it
// closes with "no row has been inserted, altered or removed", which is
// the sentence an operator carries into an incident review, over a range
// of rows it did not read and cannot account for.
//
// The reading is also the only one that will ever be made. Opening the
// volume anchors the chain again, so the record that named the vanished
// counter is replaced by one naming a surviving row, and every later run
// reports an ordinary volume. The refusals next door survive exactly
// that by writing the finding down; this path writes nothing, so a
// second run cannot reach the question at all.
function aPurgeGapIsNotReportedAsMoreThanWasChecked(root) {
  var volume = anchoredVolume(root, "case-purge-gap-report");

  var before = volume.cli(["audit", "read", "--limit", "200"]);
  count("the volume holds the rows recording who was provisioned on it",
    /account\.created/.test(before.stdout) && /domain\.added/.test(before.stdout),
    before.stdout.slice(0, 300));

  _child("the purge-gap-report tamper",
    ["--tamper", "purge-away-the-anchored-row", volume.dataDir, volume.workDir]);

  var text = volume.cli(["audit", "verify-chain"]);
  var after = volume.cli(["audit", "read", "--limit", "200"]);
  count("the gap really did take them, so what the verb says next is said over rows " +
    "that are gone",
    /account\.created/.test(after.stdout) === false &&
    /domain\.added/.test(after.stdout) === false,
    after.stdout.slice(0, 300));

  count("the verb does not tell the operator an archive was verified, because nothing " +
    "resolved the archive the anchor names and an unresolved archive is the whole of " +
    "the difference between a retention run and an erasure",
    /verified archive/.test(text.stdout) === false, text.stdout.slice(0, 700));

  count("and it does not answer for rows it did not read: a range trusted on a purge " +
    "boundary is a range this verb cannot say nothing was removed from",
    /inserted, altered or removed/.test(text.stdout) === false,
    text.stdout.slice(0, 700));

  count("the reading is written down where the next open cannot reach it, so an " +
    "operator who runs the verb twice is not answered by the record the first run " +
    "wrote",
    nodeFs.existsSync(nodePath.join(volume.dataDir, "audit.disputed")),
    volume.dataDir);
}

// The retention run whose cut lands on a checkpoint, which is the one
// shape of honest purge the anchor cannot resolve afterwards.
//
// Both of the framework's bounds are inclusive and they meet on one
// counter: the archive covers itself with the earliest checkpoint at or
// above its last row, and the purge deletes every checkpoint at or below
// that same counter. So the archive names a checkpoint its own purge
// removes, and the anchor is left pointing at an id nothing carries.
//
// What must not happen is the volume telling the operator that state is
// one no archive it wrote could have left. It is exactly what this
// server's own verbs leave, on a cut that landed one counter differently
// from the case next door, and an operator who has just run a documented
// retention verb is then reading an accusation of forgery about it. The
// reading is genuinely unproven either way, because the rows are gone
// and nothing here read them, so the verdict stays unproven and the volume
// stays open. It is the sentence that has to stop claiming more than the
// reading supports.
function aPurgeAtTheCoveringCheckpointIsNotCalledAForgery(root) {
  var volume = anchoredVolume(root, "case-purge-at-covering-checkpoint");
  _child("the purge-at-the-covering-checkpoint tamper",
    ["--tamper", "purge-at-the-covering-checkpoint", volume.dataDir, volume.workDir]);

  var text    = volume.cli(["audit", "verify-chain"]);
  var json    = volume.cli(["audit", "verify-chain", "--json"]);
  var verdict = parseJson(json.stdout);

  count("a retention run whose cut landed on the checkpoint covering it does not cost " +
    "the volume its next boot",
    text.status === 0, "exit " + text.status + " " + text.both.slice(0, 500));

  count("and the reading is still reported as one that was made against a counter the " +
    "purge accounts for",
    verdict !== null && verdict.anchor && verdict.anchor.checked === true &&
    verdict.anchor.purged === true, JSON.stringify(verdict && verdict.anchor));

  count("and the operator is not told the state is one no archive this server wrote " +
    "would have left, because it is precisely what this server's own archive and purge " +
    "leave whenever the cut lands on a checkpoint",
    /no archive this server wrote would have left/.test(text.stdout) === false,
    text.stdout.slice(0, 900));

  count("and the report names the boundary that explains it, so an operator who has " +
    "just run a retention verb can tell which of the two readings they are looking at",
    /at or below that same counter/.test(text.stdout), text.stdout.slice(0, 900));

  count("and it still does not answer for the rows it did not read, because a cut this " +
    "verb can explain is not a range it checked",
    /inserted, altered or removed/.test(text.stdout) === false,
    text.stdout.slice(0, 900));

  count("and it still does not claim an archive was verified, which is the one thing " +
    "that would separate a retention run from an erasure",
    /verified archive/.test(text.stdout) === false, text.stdout.slice(0, 900));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root = helpers.tempDir("chain-tamper");
  try {
    // The untouched volume, which is also where the two facts every case
    // below depends on are established: that a clean chain reports
    // itself clean, and that the volume leaves a record of its own last
    // anchoring outside the database the rows live in.
    var baseline = anchoredVolume(root, "baseline");
    aHealthyVolumeVerifies(baseline);
    theAnchorIsOnDiskBesideTheDatabase(baseline);

    anEditedRowIsRefused(root);
    aRowDeletedFromTheMiddleIsRefused(root);
    aRowAppendedWithoutALinkIsRefused(root);
    twoRowsExchangedAreRefused(root);
    aReattributedRowIsRefused(root);
    aTruncatedTailIsRefused(root);
    anEmptiedTableIsRefused(root);
    anAppendedLinkedRowIsNotDetectedAndIsNotDeniedEither(root);
    aTruncatedTailWithoutItsAnchorIsRefused(root);
    arewrittenCheckpointIsRefused(root);
    aRecomputedChainWithItsCheckpointsRemovedIsRefused(root);
    theAnchoredRowErasedIsRefused(root);
    aPurgedAnchoredRowIsNotARefusal(root);
    aSignedPurgeBoundaryIsNotReportedAsUnsigned(root);
    anOldFormatPurgeAnchorIsNamedAsUnsigned(root);
    anEditedPurgeAnchorIsNotReadAsMerelyOld(root);
    aPurgeGapIsNotReportedAsMoreThanWasChecked(root);
    aPurgeAtTheCoveringCheckpointIsNotCalledAForgery(root);
    anAbsentAnchorIsReportedRatherThanForfeited(root);

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "audit-chain-tamper", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout, and
// spawns this file with no arguments, so the run above is the default. A
// child carrying `--seed` or `--tamper` is this file building or
// rewriting one volume on behalf of that run, and prints nothing.
function _childMode(e) {
  console.error(helpers.formatErr(e));
  process.exitCode = 1;
}

if (require.main === module) {
  if (process.argv[2] === "--seed") {
    seedChild(process.argv[3], process.argv[4]).catch(_childMode);
  } else if (process.argv[2] === "--tamper") {
    tamperChild(process.argv[3], process.argv[4], process.argv[5]).catch(_childMode);
  } else {
    run().then(function (total) {
      console.log("CHECKS " + total);
    }).catch(function (e) {
      console.error(helpers.formatErr(e));
      process.exitCode = 1;
    });
  }
}
