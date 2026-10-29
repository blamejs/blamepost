// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What an audit row's digest actually binds, column by column.
 *
 * SECURITY.md and the front page both tell an operator that
 * administrative actions write hash-chained rows and that altering one
 * is detectable. `audit-chain-tamper.test.js` drives the shapes a
 * rewritten trail takes and asks the shipped verb what it makes of each.
 * This file asks the question underneath those: what is inside the hash,
 * and what is not.
 *
 * Two ways that claim fails while every tamper case above it still
 * passes.
 *
 * A row can hash its own content and not its predecessor's digest. The
 * sequence then agrees with itself row by row and carries no order, so
 * rows can be exchanged, and a row lifted out of one volume verifies in
 * another. That is a list of signed values rather than a chain, and the
 * difference is one term in the preimage. It is asserted here by
 * recomputing a row's hash under a predecessor that is not its own and
 * showing the value moves.
 *
 * And the digest can cover some columns and not others. Whatever it
 * leaves out is editable in place with the walk still reporting a clean
 * chain, which is worse than an uncovered row: the row is still there,
 * still linked, still carrying a counter and a timestamp, and it now
 * says something else. The column an incident asks about first is
 * `actorUserId`, because a row that names the wrong operator is worse
 * than a row that names none. So every column the table holds is edited
 * in place here, one at a time, and the walk has to refuse each one.
 *
 * The restore between the edits is half the evidence. A walk that
 * refused everything would pass an edited-column assertion without
 * reading the column, so each column is put back and the chain has to
 * verify again before the next one is touched. That also pins the edit
 * as the cause: the only thing that changed between the refusal and the
 * clean walk is that one value.
 *
 * The rows are the rows this server writes, through the store verbs an
 * operator drives, and the walk is `b.audit.verify`, which is the call
 * `blamepost audit verify-chain` makes and the same walk the framework
 * runs before it will hand back a database at all. The operator-facing
 * end of it, a reattributed row refused by the shipped binary, is driven
 * next door in `audit-chain-tamper.test.js`.
 *
 * Run standalone: node test/layer-1-state/audit-row-digest-coverage.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var b          = require("../../lib/vendor/blamejs");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var auditActor = require("../../lib/store/actor");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// The framework's own chain table, named here because the reads below
// are the only ones in this repository that touch its columns directly.
var AUDIT_TABLE = "audit_log";

// The three columns that carry the hash rather than being covered by it.
// A digest cannot cover its own output, and the nonce is the third term
// of the preimage rather than one of the fields.
var HASH_CARRIERS = ["prevHash", "rowHash", "nonce"];

// The one column the walk leaves out on purpose. It is cluster
// coordination bookkeeping, and excluding it is what lets a volume
// upgraded from a schema that had no such column verify identically
// before and after the change. It is named here rather than inferred, so
// a second column quietly joining it is a failure in this file.
var UNCOVERED_COLUMN = "fencingToken";

// SHA3-512 renders as 128 hexadecimal characters. SHA-256 renders as 64,
// so the width alone separates the two.
var SHA3_512_HEX_CHARS = 128;

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

// Enough administrative work to leave a chain with rows on both sides of
// a middle one, written through the verbs an operator drives rather than
// inserted here.
//
// The work runs inside an identity scope, which is what the command line
// opens around a subcommand. Without one the rows are written correctly
// and name nobody, and the column an incident asks about first would
// then be empty on every row on the volume.
async function seed(handle) {
  return auditActor.runAs(auditActor.forCommandLine(), async function () {
    await handle.domains.add({ domain: DOMAIN });
    var alice = await handle.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    await handle.accounts.suspend({ id: alice.id, reason: "a credential reported reused" });
    await handle.accounts.reinstate({ id: alice.id });
    await handle.domains.add({ domain: "second.example" });
    await b.audit.flush();
  });
}

// Drop the append-only triggers guarding the chain table. Somebody who
// can write to the database does this first, and doing it rather than
// describing it is the point: an edit made through a supported call
// would be testing the supported call.
function dropAppendOnlyTriggers() {
  var triggers = b.db.prepare(
    "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?").all(AUDIT_TABLE);
  triggers.forEach(function (t) { b.db.runSql("DROP TRIGGER " + t.name); });
  return triggers.length;
}

function everyRow() {
  return b.db.prepare("SELECT * FROM " + AUDIT_TABLE +
    " ORDER BY monotonicCounter ASC").all();
}

// The logical fields of a row: every column except the three that carry
// the hash and the one the walk leaves out.
function fieldsOf(row) {
  var fields = Object.assign({}, row);
  HASH_CARRIERS.forEach(function (name) { delete fields[name]; });
  delete fields[UNCOVERED_COLUMN];
  return fields;
}

function nonceOf(row) {
  return Buffer.isBuffer(row.nonce) ? row.nonce : Buffer.from(row.nonce);
}

// ---- the chain is a chain ---------------------------------------------------

// Each row carries the digest of the one before it, and the first is
// anchored at a value no row can produce. Without this the sequence has
// no order at all: two rows exchange without either failing its own
// hash, and a row lifted out of another volume verifies here.
function theRowsAreLinkedToTheirPredecessors(rows) {
  count("the volume holds a chain long enough for a middle row to have rows on " +
    "both sides of it", rows.length >= 5, String(rows.length));

  count("the first row is anchored at the value the chain begins from, so the walk " +
    "has a fixed point rather than believing whatever the first row names",
    rows[0].prevHash === b.auditChain.ZERO_HASH,
    String(rows[0].prevHash).slice(0, 32));

  var linked = 0;
  for (var i = 1; i < rows.length; i += 1) {
    if (rows[i].prevHash === rows[i - 1].rowHash) linked += 1;
  }
  count("and every row after it names the digest of the row before it, which is what " +
    "makes the sequence a chain rather than a list of separately hashed rows",
    linked === rows.length - 1, linked + " of " + (rows.length - 1));
}

// The predecessor's digest is genuinely an input to the hash rather than
// a column stored beside it. Recomputing one row's own fields under
// somebody else's predecessor has to move the value; if it does not, the
// link is decoration and the order it appears to impose is not real.
function thePredecessorIsInsideTheDigest(rows) {
  var subject = rows[rows.length - 1];
  var ownPlace = b.auditChain.computeRowHash(
    subject.prevHash, fieldsOf(subject), nonceOf(subject));
  count("a row recomputed where it stands reproduces the digest it carries",
    ownPlace === subject.rowHash, String(ownPlace).slice(0, 32) + " vs " +
    String(subject.rowHash).slice(0, 32));

  var elsewhere = b.auditChain.computeRowHash(
    b.auditChain.ZERO_HASH, fieldsOf(subject), nonceOf(subject));
  count("and the same row recomputed after a different predecessor does not, so the " +
    "predecessor's digest is an input to the hash rather than a column stored beside it",
    elsewhere !== subject.rowHash, String(elsewhere).slice(0, 32));
}

// Which digest, held against the framework's own SHA3-512 rather than
// against the function that produced it. Hard rule 2 puts the choice of
// digest under this project's control wherever the choice is ours, and a
// vendor refresh that moved the chain onto SHA-256 would leave every
// other reading in this file passing.
function theDigestIsSha3(rows) {
  var subject = rows[rows.length - 1];
  count("a row's digest is the width SHA3-512 produces, which is twice what SHA-256 " +
    "produces and so separates the two on sight",
    typeof subject.rowHash === "string" && subject.rowHash.length === SHA3_512_HEX_CHARS,
    String(subject.rowHash).length + " characters");

  count("and it is lowercase hexadecimal throughout, so a reader comparing two digests " +
    "is comparing values rather than renderings",
    /^[0-9a-f]+$/.test(String(subject.rowHash)), String(subject.rowHash).slice(0, 32));

  // The preimage rebuilt here rather than taken from the function under
  // reading: the predecessor's digest as bytes, the canonical form of
  // the row's logical fields, and the row's nonce, in that order.
  var preimage = Buffer.concat([
    Buffer.from(subject.prevHash, "hex"),
    Buffer.from(b.auditChain.canonicalize(fieldsOf(subject)), "utf8"),
    nonceOf(subject),
  ]);
  count("and SHA3-512 over the predecessor's digest, the row's canonical fields and " +
    "its nonce reproduces it, so the digest is that function over that preimage",
    b.crypto.sha3Hash(preimage) === subject.rowHash,
    b.crypto.sha3Hash(preimage).slice(0, 32) + " vs " + String(subject.rowHash).slice(0, 32));
}

// ---- every column, one at a time --------------------------------------------

// A value for a column that is different from the one it holds and of a
// shape the column takes. A counter has to stay the largest on the
// volume so the edit is a rewritten value rather than a reordering,
// which is a separate case and is driven as one next door.
function _replacementFor(column, held, rows) {
  if (column === "monotonicCounter") {
    return Number(rows[rows.length - 1].monotonicCounter) + 1000;
  }
  if (typeof held === "number") return held + 1;
  return "rewritten-" + column;
}

// Edit one column in place, ask the walk, put it back, ask again.
//
// The row is addressed by its own digest rather than by its primary key.
// The primary key is one of the columns being edited, so a restore that
// looked the row up by it would not find the row it had just moved, and
// every column after that one would report a refusal the earlier edit
// had already caused.
async function _columnIsCovered(column, rows) {
  var subject = rows[Math.floor(rows.length / 2)];
  var held    = subject[column];
  var written = _replacementFor(column, held, rows);
  var where   = ' WHERE "rowHash"=?';

  b.db.prepare("UPDATE " + AUDIT_TABLE + ' SET "' + column + '"=?' + where)
    .run(written, subject.rowHash);
  var edited = await b.audit.verify();

  b.db.prepare("UPDATE " + AUDIT_TABLE + ' SET "' + column + '"=?' + where)
    .run(held, subject.rowHash);
  var restored = await b.audit.verify();

  return { edited: edited, restored: restored, held: held, written: written };
}

// Every column the table holds, less the three that carry the hash. A
// column the digest does not cover is a column somebody who can write to
// the database edits in place with the walk still reporting a clean
// chain, and the walk is what the operator is told to trust.
async function everyColumnIsInsideTheDigest(rows) {
  var columns = Object.keys(rows[0]).filter(function (name) {
    return HASH_CARRIERS.indexOf(name) === -1;
  });

  count("the sweep below reaches every column the chain table holds, which is what " +
    "keeps a column added by a later schema out of the set nobody reads",
    columns.length >= 16, columns.length + ": " + columns.join(", "));

  for (var i = 0; i < columns.length; i += 1) {
    var column = columns[i];
    var seen   = await _columnIsCovered(column, rows);

    if (column === UNCOVERED_COLUMN) {
      count("the walk leaves " + column + " out, which is the one column it is meant " +
        "to leave out, so a volume upgraded across the schema that added it verifies " +
        "the same before and after",
        seen.edited.ok === true, JSON.stringify({ ok: seen.edited.ok,
          reason: seen.edited.reason }));
    } else {
      count("a rewritten " + column + " is refused, so the digest covers it and the " +
        "column cannot be edited in place with the walk still reporting a clean chain",
        seen.edited.ok === false, JSON.stringify({ ok: seen.edited.ok,
          reason: seen.edited.reason, held: String(seen.held).slice(0, 40) }));
    }

    count("and the chain verifies again once " + column + " is put back, which is what " +
      "makes the reading above about that column rather than about a walk that had " +
      "already stopped refusing to agree with anything",
      seen.restored.ok === true, JSON.stringify({ ok: seen.restored.ok,
        reason: seen.restored.reason }));
  }
}

// The column an incident asks about first, read on its own because the
// sweep above would pass with it absent from the table entirely.
//
// A trail that proves an account was suspended and lets somebody choose
// which operator it says suspended it is worse than one that names
// nobody: the second is read as unattributed and the first is acted on.
async function reattributingARowIsRefused(rows) {
  var attributed = rows.filter(function (row) {
    return typeof row.actorUserId === "string" && row.actorUserId.length > 0;
  });
  count("the volume holds rows naming who acted, so there is an attribution here to " +
    "try to move",
    attributed.length >= 1, String(attributed.length) + " of " + rows.length);
  if (attributed.length === 0) return;

  var subject = attributed[0];
  b.db.prepare("UPDATE " + AUDIT_TABLE + ' SET "actorUserId"=? WHERE "rowHash"=?')
    .run("cli:somebody-else@another-host", subject.rowHash);
  var edited = await b.audit.verify();
  b.db.prepare("UPDATE " + AUDIT_TABLE + ' SET "actorUserId"=? WHERE "rowHash"=?')
    .run(subject.actorUserId, subject.rowHash);
  var restored = await b.audit.verify();

  count("a row pointed at a different operator is refused, and the walk names the " +
    "row's own digest as what disagrees rather than the link to its neighbor",
    edited.ok === false && /rowHash mismatch/.test(String(edited.reason)),
    JSON.stringify({ ok: edited.ok, reason: edited.reason }));
  count("and the chain verifies again once the operator is put back",
    restored.ok === true, JSON.stringify({ ok: restored.ok, reason: restored.reason }));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("audit-row-digest");
  var workDir = nodePath.join(root, "work");
  var dataDir = nodePath.join(root, "data");
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.mkdirSync(dataDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside the run's own temporary tree keeps the encrypted-at-rest
  // path exactly as it ships rather than opting this file out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    var handle = await store.open(configFor(dataDir));
    await seed(handle);

    var opened = await b.audit.verify();
    count("the volume this file reads verifies before anything is done to it, so every " +
      "refusal below is one this run caused",
      opened.ok === true, JSON.stringify({ ok: opened.ok, rows: opened.rowsVerified }));

    count("the chain table is guarded by append-only triggers, which is what a rewrite " +
      "has to remove first and what this file removes to reach the rows at all",
      dropAppendOnlyTriggers() >= 1, "triggers");

    var rows = everyRow();
    theRowsAreLinkedToTheirPredecessors(rows);
    thePredecessorIsInsideTheDigest(rows);
    theDigestIsSha3(rows);
    await everyColumnIsInsideTheDigest(rows);
    await reattributingARowIsRefused(rows);

    return helpers.getChecks();
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "audit-row-digest-coverage",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
