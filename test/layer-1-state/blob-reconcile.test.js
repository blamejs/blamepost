// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The sealed message octets on disk, held against the rows that are
 * supposed to reference them.
 *
 * A message is two writes to two different places. The octets go under
 * `blobs/`, named by the SHA3-512 of their content, and a row goes in
 * the database pointing at that name. Nothing spans the pair: the
 * filesystem write cannot join the database transaction, so a process
 * that stops between them leaves one half without the other, and both
 * halves are silent about it.
 *
 * A blob with no row is storage nobody can reach and nothing reclaims,
 * because the reference-counted release only ever runs for a message
 * that still has a row to delete. A row with no blob is worse: the
 * message is listed by every protocol and then fails to return its
 * body. And a blob whose octets no longer hash to the name they are
 * filed under is the same outage plus a reason to look at the volume,
 * which existence alone cannot tell anybody.
 *
 * Every vector here drives the command line an operator runs, in a
 * child process, against a real data directory, a real vault and a real
 * encrypted database. What is asserted is what the operator is told and
 * the exit code they can branch on.
 *
 * The safety property has its own vectors, because getting it wrong
 * deletes mail that was arriving normally. On a server that is running,
 * a blob with no row is indistinguishable from a blob whose row is
 * still being inserted, so nothing is reclaimed until it has been on
 * disk long enough that no append could still be in flight. A fresh
 * orphan is held back and said so; an aged one goes. Neither vector
 * sleeps: the age is set on the file.
 *
 * Run standalone: node test/layer-1-state/blob-reconcile.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blobs     = require("../../lib/store/blobs");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// Older than the settle window by a clear margin, so a filesystem whose
// timestamp resolution is coarse cannot land the file back inside it.
var WELL_AGED_MS = blobs.SETTLE_MS + b.constants.TIME.hours(6);

function message(subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: " + ADDRESS + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "The body of " + subject + ".\r\n", "utf8");
}

// Read a verb's JSON answer. The framework's boot lines are already off
// both streams by the time this sees them, and a verb printing JSON
// pretty prints it, so what is left parses.
function jsonOf(result) {
  try { return JSON.parse(result.stdout); }
  catch (_e) { return null; }
}

function digestsIn(list) {
  return (list || []).map(function (entry) { return entry.digest; });
}

// ---- fixture ---------------------------------------------------------------

// Four messages, because four different things are done to them, and a
// fifth body that is never appended so its octets can stand in for a
// blob whose row never landed.
var SUBJECTS = ["kept intact", "octets deleted", "octets corrupted", "row deleted"];

async function seed(cfg) {
  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: DOMAIN });
    var owner = await handle.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });

    var appended = {};
    for (var i = 0; i < SUBJECTS.length; i += 1) {
      var stored = handle.mailbox.appendMessage("INBOX", message(SUBJECTS[i]), {
        actor: { id: owner.id },
      });
      appended[SUBJECTS[i]] = stored.objectid;
    }

    var described = handle.mailbox.describe();
    var digests = {};
    var rows = b.db.from("blamepost_mailbox_messages").all();
    for (var r = 0; r < rows.length; r += 1) {
      digests[rows[r].objectid] = rows[r].blobDigest;
    }

    return {
      accountId: owner.id,
      blobDir:   described.blobDir,
      objectIds: appended,
      digestOf:  function (subject) { return digests[appended[subject]]; },
    };
  } finally {
    handle.close();
  }
}

// Everything that needs the vault open happens in one pass, so the
// database is decrypted once rather than once per divergence.
async function breakThings(cfg, fixture) {
  var handle = await store.open(cfg);
  var planted = {};
  try {
    // A blob whose row never landed, written the way the append path
    // writes one: sealed, base64 inside the seal, at its own
    // content-addressed path.
    function plantOrphan(bodyText, ageMs) {
      var raw = Buffer.from(bodyText, "utf8");
      var digest = b.crypto.sha3Hash(raw);
      var target = blobs.pathFor(fixture.blobDir, digest);
      b.atomicFile.ensureDir(nodePath.dirname(target), 0o700);
      b.atomicFile.writeSync(target, b.vault.seal(raw.toString("base64")),
        { fileMode: 0o600 });
      if (ageMs > 0) {
        var when = new Date(Date.now() - ageMs);
        nodeFs.utimesSync(target, when, when);
      }
      return { digest: digest, path: target };
    }

    planted.aged  = plantOrphan("an orphan old enough that no append is still in flight",
      WELL_AGED_MS);
    planted.fresh = plantOrphan("an orphan written moments ago", 0);

    // A file under `blobs/` that is not a blob. Nothing may reclaim it,
    // because nothing here knows what it is.
    planted.unexpected = nodePath.join(fixture.blobDir, "NOTES.txt");
    b.atomicFile.writeSync(planted.unexpected, "left here by somebody", { fileMode: 0o600 });

    // A row whose octets are gone: the message is listed and cannot be
    // read.
    planted.missingDigest = fixture.digestOf("octets deleted");
    nodeFs.rmSync(blobs.pathFor(fixture.blobDir, planted.missingDigest), { force: true });

    // A row whose octets are present, seal intact, and no longer the
    // octets the digest names. Existence alone cannot see this.
    planted.corruptDigest = fixture.digestOf("octets corrupted");
    b.atomicFile.writeSync(blobs.pathFor(fixture.blobDir, planted.corruptDigest),
      b.vault.seal(Buffer.from("different octets entirely", "utf8").toString("base64")),
      { fileMode: 0o600 });

    // The other half of an interrupted append: the store row and its
    // quota counter landed, the row binding it to a folder did not. The
    // octets are now referenced by nothing, and the owner is charged for
    // a message no protocol can list.
    planted.strandedDigest = fixture.digestOf("row deleted");
    nodeFs.utimesSync(blobs.pathFor(fixture.blobDir, planted.strandedDigest),
      new Date(Date.now() - WELL_AGED_MS), new Date(Date.now() - WELL_AGED_MS));
    b.db.from("blamepost_mailbox_messages")
      .where({ objectid: fixture.objectIds["row deleted"] }).deleteOne();

    planted.keptDigest = fixture.digestOf("kept intact");
    return planted;
  } finally {
    handle.close();
  }
}

// ---- a store that reconciles says so ---------------------------------------

function aCleanVolumeReportsClean(run, fixture) {
  var plain = run(["blobs", "report"]);
  count("`blobs report` on a store whose octets match its rows exits zero",
    plain.status === 0, "exit " + plain.status + " " + plain.both.slice(0, 200));
  count("and says both directions hold rather than printing a bare count",
    /every message body on disk is referenced/i.test(plain.stdout) &&
    /every row has its body/i.test(plain.stdout), plain.stdout.slice(0, 300));

  var report = jsonOf(run(["blobs", "report", "--json"]));
  count("the JSON answer parses", report !== null && typeof report === "object",
    JSON.stringify(report));
  count("and reports the volume as reconciled",
    report.ok === true, JSON.stringify(report && report.ok));
  count("with every divergence list empty",
    report.orphans.length === 0 && report.missing.length === 0 &&
    report.unexpected.length === 0 && report.quotaDrift.length === 0,
    JSON.stringify({
      orphans: report.orphans.length, missing: report.missing.length,
      unexpected: report.unexpected.length, quotaDrift: report.quotaDrift.length,
    }));
  count("and it counted the octets it walked, so a walk that found nothing " +
    "cannot read as a clean volume",
    report.blobsOnDisk === SUBJECTS.length && report.digestsReferenced === SUBJECTS.length,
    JSON.stringify({ onDisk: report.blobsOnDisk, referenced: report.digestsReferenced }));

  var verified = jsonOf(run(["blobs", "report", "--verify", "--json"]));
  count("unsealing every blob and hashing it back finds nothing wrong either",
    verified !== null && verified.ok === true && verified.corrupt.length === 0,
    JSON.stringify(verified && { ok: verified.ok, corrupt: verified.corrupt }));
  count("and the answer records that the octets were checked rather than counted",
    verified.verified === true, JSON.stringify(verified.verified));

  var doctor = jsonOf(run(["doctor", "--json"]));
  var finding = ((doctor && doctor.local) || []).filter(function (f) {
    return /message bodies/i.test(f.check);
  });
  count("`doctor` carries the same reconciliation as one of its local checks",
    finding.length === 1, JSON.stringify((doctor && doctor.local || []).map(function (f) {
      return f.check;
    })));
  count("and it passes on a volume that reconciles", finding[0].ok === true,
    JSON.stringify(finding[0]));

  return fixture;
}

// ---- every way the two can disagree ----------------------------------------

function everyDivergenceIsNamed(run, planted) {
  var report = jsonOf(run(["blobs", "report", "--json"]));
  count("`blobs report --json` still answers once the volume has diverged",
    report !== null && typeof report === "object", JSON.stringify(report));

  count("a diverged volume is not reported as reconciled", report.ok === false,
    JSON.stringify(report.ok));

  var orphanDigests = digestsIn(report.orphans);
  count("the blob whose row never landed is reported as unreferenced",
    orphanDigests.indexOf(planted.aged.digest) !== -1, orphanDigests.join(","));
  count("and so is the one written moments ago, because reporting is not deleting",
    orphanDigests.indexOf(planted.fresh.digest) !== -1, orphanDigests.join(","));
  count("and so are the octets of the message whose row was lost",
    orphanDigests.indexOf(planted.strandedDigest) !== -1, orphanDigests.join(","));

  var missingDigests = digestsIn(report.missing);
  count("a row whose octets are gone is reported as a message that cannot be read",
    missingDigests.indexOf(planted.missingDigest) !== -1, missingDigests.join(","));
  count("and the entry names the folder and message rather than only the digest",
    report.missing.some(function (m) {
      return typeof m.folder === "string" && m.folder.length > 0 &&
        typeof m.objectid === "string" && m.objectid.length > 0;
    }), JSON.stringify(report.missing));

  count("a file under blobs/ that is not a blob is reported rather than ignored",
    report.unexpected.some(function (u) { return /NOTES\.txt$/.test(u.path); }),
    JSON.stringify(report.unexpected));

  count("the quota the owner is charged is reported as disagreeing with the rows",
    report.quotaDrift.length >= 1, JSON.stringify(report.quotaDrift));
  count("and the drift is quantified in bytes rather than only flagged",
    report.quotaDrift.every(function (d) {
      return typeof d.storeBytes === "number" && typeof d.rowBytes === "number" &&
        d.storeBytes > d.rowBytes;
    }), JSON.stringify(report.quotaDrift));

  // The digest check is the half existence cannot do, so it has to be
  // absent without --verify and present with it. A report that flagged
  // it either way would not be verifying anything.
  count("octets that no longer match their digest are invisible to a presence check",
    digestsIn(report.corrupt).indexOf(planted.corruptDigest) === -1,
    JSON.stringify(report.corrupt));

  var verified = jsonOf(run(["blobs", "report", "--verify", "--json"]));
  count("and --verify finds them",
    digestsIn(verified.corrupt).indexOf(planted.corruptDigest) !== -1,
    JSON.stringify(verified.corrupt));
  count("and says why, rather than only that something is wrong",
    verified.corrupt.every(function (c) {
      return typeof c.reason === "string" && c.reason.length > 0;
    }), JSON.stringify(verified.corrupt));

  var plain = run(["blobs", "report"]);
  count("a diverged volume exits non-zero, so a scheduled run is not silent",
    plain.status === 1, "exit " + plain.status);
  count("and the text answer names the verb that resolves the unreferenced octets",
    /blobs reclaim/.test(plain.stdout), plain.stdout.slice(0, 400));

  var doctor = run(["doctor", "--json"]);
  var parsed = jsonOf(doctor);
  var finding = ((parsed && parsed.local) || []).filter(function (f) {
    return /message bodies/i.test(f.check);
  });
  count("`doctor` fails its message-body check on the same volume",
    finding.length === 1 && finding[0].ok === false, JSON.stringify(finding));
  count("and doctor exits non-zero because of it", doctor.status === 1,
    "exit " + doctor.status);
}

// ---- deletion is explicit, and never deletes an arriving message -----------

function reclaimingIsGatedAndAgeBound(run, planted) {
  var bare = run(["blobs", "reclaim"]);
  count("`blobs reclaim` with no confirmation is refused",
    bare.status === 2 && /--confirm/.test(bare.both),
    "exit " + bare.status + " " + bare.both.slice(0, 240));

  var noReason = run(["blobs", "reclaim", "--confirm"]);
  count("and confirming without saying why is refused too",
    noReason.status === 2 && /--reason/.test(noReason.both),
    "exit " + noReason.status + " " + noReason.both.slice(0, 240));

  count("nothing was deleted by either refusal",
    nodeFs.existsSync(planted.aged.path) && nodeFs.existsSync(planted.fresh.path),
    planted.aged.path + " ; " + planted.fresh.path);

  var done = run(["blobs", "reclaim", "--confirm",
    "--reason", "reclaiming octets stranded by the crash on 2026-08-22", "--json"]);
  count("with both flags it runs", done.status === 0,
    "exit " + done.status + " " + done.both.slice(0, 240));

  var result = jsonOf(done);
  count("the answer parses", result !== null && typeof result === "object",
    JSON.stringify(result));

  var reclaimed = digestsIn(result.reclaimed);
  count("the orphan that has been on disk longer than an append could take is gone",
    reclaimed.indexOf(planted.aged.digest) !== -1 &&
    nodeFs.existsSync(planted.aged.path) === false, reclaimed.join(","));
  count("and so are the octets of the message whose row was lost",
    reclaimed.indexOf(planted.strandedDigest) !== -1, reclaimed.join(","));

  // The vector this whole gate exists for. A blob written moments ago
  // is what an append in flight looks like from outside, and deleting
  // it destroys a message that was arriving normally.
  count("the orphan written moments ago is NOT deleted",
    reclaimed.indexOf(planted.fresh.digest) === -1 &&
    nodeFs.existsSync(planted.fresh.path), reclaimed.join(","));
  count("and it is reported as held back rather than passed over in silence",
    digestsIn(result.heldBack).indexOf(planted.fresh.digest) !== -1,
    JSON.stringify(result.heldBack));
  count("and the answer says when it becomes reclaimable, so the operator " +
    "knows to come back rather than to reach for a flag",
    typeof result.nextReclaimableAt === "number" && result.nextReclaimableAt > Date.now(),
    JSON.stringify(result.nextReclaimableAt));

  count("a file under blobs/ that is not a blob survives the reclaim",
    nodeFs.existsSync(planted.unexpected), planted.unexpected);
  count("and so do the octets of every message that still has a row",
    nodeFs.existsSync(planted.keptPath), planted.keptPath);

  count("the bytes actually freed are reported rather than estimated",
    typeof result.reclaimedBytes === "number" && result.reclaimedBytes > 0,
    JSON.stringify(result.reclaimedBytes));
}

// Read back through the verb an operator reads the trail with, rather
// than through a query in this process. The trail is the only record
// that the octets were here, so what matters is that it answers the
// operator, not that a row exists somewhere.
function theReclaimIsRecorded(run) {
  var read = run(["audit", "read", "--action", "blamepost.store.blobs.reclaimed", "--json"]);
  count("`audit read` answers for the reclaim", read.status === 0,
    "exit " + read.status + " " + read.both.slice(0, 200));

  var rows = jsonOf(read);
  count("reclaiming left a row in the audit chain",
    Array.isArray(rows) && rows.length >= 1,
    Array.isArray(rows) ? rows.length + " row(s)" : String(rows));

  var withReason = (rows || []).filter(function (r) {
    return String((r && r.reason) || "").indexOf("crash on 2026-08-22") !== -1;
  });
  count("and the reason is in the row's own column, where an auditor can filter on it",
    withReason.length >= 1, withReason.length + " of " + (rows || []).length);
  count("and the row names the body store it emptied",
    withReason.some(function (r) { return r.resourceKind === "blob_store"; }),
    JSON.stringify(withReason.map(function (r) { return r.resourceKind; })));
}

// The command line and the library have to describe one volume the same
// way. `blamepost.store.blobs.reconcile` is what the verb prints and
// what `doctor` reads, so a second answer from the same call is the
// cheapest proof that neither is rendering something of its own.
async function theLibraryAgreesWithTheCommandLine(cfg, run, planted) {
  var printed = jsonOf(run(["blobs", "report", "--verify", "--json"]));
  var handle = await store.open(cfg);
  try {
    var direct = handle.blobs.reconcile({ verify: true });
    count("blamepost.store.blobs.reconcile answers what the verb printed",
      direct.ok === printed.ok &&
      direct.orphans.length === printed.orphans.length &&
      direct.missing.length === printed.missing.length &&
      direct.corrupt.length === printed.corrupt.length,
      JSON.stringify({
        direct: [direct.ok, direct.orphans.length, direct.missing.length, direct.corrupt.length],
        printed: [printed.ok, printed.orphans.length, printed.missing.length,
          printed.corrupt.length],
      }));
    count("and the reclaimed octets are gone from both",
      digestsIn(direct.orphans).indexOf(planted.aged.digest) === -1,
      digestsIn(direct.orphans).join(","));
    var refusal = null;
    try { await handle.blobs.reclaim({}); }
    catch (e) { refusal = e; }
    count("and blamepost.store.blobs.reclaim refuses without a reason to record",
      refusal !== null && refusal.code === "store/bad-argument",
      refusal === null ? "nothing was thrown" : refusal.code + ": " + refusal.message);
  } finally {
    handle.close();
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("blob-reconcile");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    process.env.BLAMEJS_TMPDIR = workDir;
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    // One handle per process at a time: the database is encrypted at
    // rest and each process decrypts its own working copy, so a handle
    // held open while the child writes would flush a stale snapshot back
    // over the child's work.
    var fixture = await seed(cfg);
    aCleanVolumeReportsClean(cli, fixture);

    var planted = await breakThings(cfg, fixture);
    planted.keptPath = blobs.pathFor(fixture.blobDir, planted.keptDigest);

    everyDivergenceIsNamed(cli, planted);
    reclaimingIsGatedAndAgeBound(cli, planted);
    theReclaimIsRecorded(cli);
    await theLibraryAgreesWithTheCommandLine(cfg, cli, planted);
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

module.exports = { name: "blob-reconcile", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
