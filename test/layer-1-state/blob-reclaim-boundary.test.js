// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The boundary a reclaim draws around each body it removes, driven
 * rather than argued.
 *
 * A message body is content-addressed, so a delivery of bytes already on
 * disk reuses that file instead of writing it again. That is what makes
 * the moment before an unlink dangerous. `reclaim` re-reads the message
 * rows immediately before removing a body precisely because of it, and
 * the question this file answers is whether that re-read closes the gap
 * or merely shrinks it.
 *
 * Inside one process it closes it. The walk, the row re-read, the
 * re-stat and the unlink are one synchronous run with nothing awaited
 * between them, and this server has no worker threads, so a delivery has
 * only two places it can be. Wholly before, where the re-read finds the
 * row and the body stays. Or wholly after, where the delivery finds the
 * path empty and writes the bytes back. There is no third ordering, so
 * both sides are asserted here rather than a race being staged and hoped
 * for. A test that tried to land a delivery inside the run would be
 * asserting a coin toss.
 *
 * What that argument never covered is a SECOND process, whose delivery
 * genuinely can land between this one's re-read and its unlink and leave
 * a row naming a body that has just been removed. That is a message that
 * exists and cannot be read, and narrowing the window again would not
 * fix it. It is closed by refusing the second opener outright, which
 * test/layer-1-state/store-single-opener.test.js drives.
 *
 * The fixture here is its own, deliberately. The reconciliation cases
 * next door corrupt theirs on purpose, and appending fresh mail into a
 * mailbox whose quota counters have been damaged tests the damage rather
 * than the boundary.
 *
 * Run standalone: node test/layer-1-state/blob-reclaim-boundary.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var blobs   = require("../../lib/store/blobs");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// Older than the settle window by a clear margin, so a filesystem whose
// timestamp resolution is coarse cannot land the file back inside it.
var WELL_AGED_MS = blobs.SETTLE_MS + b.constants.TIME.hours(6);

var MESSAGES = "blamepost_mailbox_messages";

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

function digestsIn(list) {
  return (list || []).map(function (entry) { return entry.digest; });
}

// Take the row away and put the file back by a given age, so what is
// left is a body with nothing naming it and a chosen amount of time
// behind it. This is the half of an interrupted delivery that leaves
// octets nothing names.
function strandAt(objectid, bodyPath, ageMs) {
  b.db.from(MESSAGES).where({ objectid: objectid }).deleteOne();
  var aged = new Date(Date.now() - ageMs);
  nodeFs.utimesSync(bodyPath, aged, aged);
}

// The same, aged clear of the settle window, which is what the cases
// about the row rather than the clock want.
function strand(objectid, bodyPath) {
  strandAt(objectid, bodyPath, WELL_AGED_MS);
}

// How long a body has to have been unreferenced before a reclaim will
// remove it, as the operator guide promises it.
//
// Written here rather than read from the module. Every other case in
// this file ages its fixtures at `blobs.SETTLE_MS` plus a margin, which
// is right for them: what they are about is the row, and a fixture that
// tracks the window cannot fall inside it as the window moves. But it
// makes all of them silent about the window's WIDTH, and the width is
// the part the guide promises and the part an operator schedules a
// reclaim around. Narrowed to an hour, every case here still passes and the
// verb starts removing bodies whose delivery is still being written,
// which is the one thing the wait exists to prevent.
var DOCUMENTED_SETTLE_MS = b.constants.TIME.hours(24);

// The sentence that promises it, so a document edited to say something
// else fails here rather than leaving the number above describing
// nothing.
var SETTLE_PROMISE_RE = /only removed once it has been unreferenced for a day/;
var SETTLE_REFERENCE  = "docs/operator-guide.md";

// Either side of the documented window by an hour. Coarse enough that a
// filesystem storing timestamps to the second cannot round a fixture
// across the boundary it was placed on.
var MARGIN_MS      = b.constants.TIME.hours(1);
var JUST_INSIDE_MS = DOCUMENTED_SETTLE_MS - MARGIN_MS;
var JUST_PAST_MS   = DOCUMENTED_SETTLE_MS + MARGIN_MS;

// One file the volume will not give up, for the length of one call.
//
// A removal that fails is ordinary rather than exotic: a body held open,
// a mount that has gone read-only, a permission an operator changed. The
// `force` flag on the removal covers a file that is already gone and
// nothing else, so every one of those still raises.
//
// The SYNCHRONOUS removal, which is the one the blob release reaches
// for. Its asynchronous sibling in the same helper module faults
// `fs.promises.rm` instead, and the two are not interchangeable here:
// faulting the promise form against this caller refuses nothing and
// leaves the reclaim reporting a clean run over a file it never tried
// to remove.
//
// Matched on the digest rather than on the whole path, because the
// caller knows which body it wants refused and not where the fan-out
// filed it.
var installSyncRemovalFault = helpers.installSyncRemovalFault;

// ---- cases -----------------------------------------------------------------

async function bothSidesOfTheBoundary(handle, accountId, blobDir) {
  var bytes = message("delivered twice with the same body");

  var first = handle.mailbox.appendMessage("INBOX", bytes, { actor: { id: accountId } });
  var digest = b.db.from(MESSAGES).where({ objectid: first.objectid }).first().blobDigest;
  var bodyPath = blobs.pathFor(blobDir, digest);
  count("a delivered body is on disk under its own digest",
    nodeFs.existsSync(bodyPath), bodyPath);

  strand(first.objectid, bodyPath);

  // Before. A second delivery of the same bytes reuses the file and
  // writes the row, so the re-read finds it and the body stays. This is
  // the only ordering the re-read can act on, and it acts.
  var early = handle.mailbox.appendMessage("INBOX", bytes, { actor: { id: accountId } });
  count("the repeated delivery reused the body already on disk",
    b.db.from(MESSAGES).where({ objectid: early.objectid }).first().blobDigest === digest,
    digest.slice(0, 24));

  var withRow = await handle.blobs.reclaim({
    reason: "octets stranded by an interrupted delivery",
  });
  count("a body that gained a row before the unlink is left where it is",
    digestsIn(withRow.reclaimed).indexOf(digest) === -1,
    JSON.stringify(withRow.reclaimed));
  count("and the message that names it can still be read",
    nodeFs.existsSync(bodyPath), bodyPath);

  // It was the walk that saved it, not the re-read, and that is the
  // whole point. A delivery inside one process always lands before the
  // walk or after the unlink, so the body is either never a candidate,
  // as here, or already gone. Nothing in this process can put a row on a
  // body between the walk and the unlink, so the re-read never has
  // anything to catch and reports nothing skipped. The re-read earns its
  // place only against a second process, and that is the one this server
  // now refuses rather than races.
  count("nothing had to be caught between the walk and the unlink",
    withRow.skipped.length === 0, JSON.stringify(withRow.skipped));

  // After. With the row gone again the body is removed, and a delivery
  // of the same bytes afterwards writes them back rather than inheriting
  // a path with nothing at it.
  strand(early.objectid, bodyPath);
  var withoutRow = await handle.blobs.reclaim({
    reason: "octets stranded by an interrupted delivery",
  });
  count("a body nothing references is removed once it has settled",
    digestsIn(withoutRow.reclaimed).indexOf(digest) !== -1,
    JSON.stringify(withoutRow.reclaimed));
  count("and it is gone from disk", nodeFs.existsSync(bodyPath) === false, bodyPath);

  handle.mailbox.appendMessage("INBOX", bytes, { actor: { id: accountId } });
  count("a delivery of the same body after the removal writes it back",
    nodeFs.existsSync(bodyPath), bodyPath);

  var after = handle.blobs.reconcile({ verify: false });
  count("so no message row is left naming a body that is not on disk",
    after.missing.length === 0, JSON.stringify(after.missing));
}

// One body the volume refuses, and every body behind it in the same run.
//
// A reclaim is a set of separate removals, and the audit row it writes
// afterwards is the only record that any of these octets were here. A
// removal allowed to raise takes that row with it and abandons every
// candidate after the one that raised, so the operator is handed an
// exception describing one file and nothing at all about the ones that
// went or the ones that never got a turn.
async function oneFileTheVolumeWillNotGiveUp(handle, accountId, blobDir) {
  var stranded = [];
  for (var i = 0; i < 3; i += 1) {
    var stored = handle.mailbox.appendMessage("INBOX",
      message("stranded body " + i), { actor: { id: accountId } });
    var digest = b.db.from(MESSAGES).where({ objectid: stored.objectid }).first().blobDigest;
    var bodyPath = blobs.pathFor(blobDir, digest);
    strand(stored.objectid, bodyPath);
    stranded.push({ digest: digest, path: bodyPath });
  }
  count("three bodies are stranded on the volume and all three are reclaimable",
    handle.blobs.reconcile({ verify: false }).orphans.filter(function (o) {
      return o.reclaimable;
    }).length === 3, JSON.stringify(digestsIn(handle.blobs.reconcile().orphans)));

  // The one the walk reaches FIRST, so at least one candidate is behind
  // it and the abandonment is what the run is measuring rather than a
  // property of which file happened to be last.
  var order = handle.blobs.reconcile({ verify: false }).orphans;
  var refusedDigest = order[0].digest;
  var behind = order.slice(1).map(function (o) { return o.digest; });

  var fault = installSyncRemovalFault(refusedDigest);
  var thrown = null;
  var result = null;
  try {
    result = await handle.blobs.reclaim({ reason: "octets stranded by an interrupted delivery" });
  } catch (e) { thrown = e; }
  finally { fault.remove(); }

  count("a removal the volume refuses answers with a report rather than raising",
    thrown === null && result !== null,
    thrown === null ? "nothing was thrown" : helpers.formatErr(thrown));
  count("and the refusal was actually met, so the run is measuring the volume refusing " +
    "rather than a fault that was never in the way",
    fault.calls === 1, JSON.stringify({ calls: fault.calls }));

  var reclaimedDigests = digestsIn(result && result.reclaimed);
  count("every body behind the one that was refused is still reclaimed, so one failure " +
    "does not abandon the rest of the set",
    behind.every(function (d) { return reclaimedDigests.indexOf(d) !== -1; }),
    JSON.stringify({ reclaimed: reclaimedDigests, behind: behind }));
  count("and those bodies are gone from disk",
    stranded.filter(function (entry) {
      return behind.indexOf(entry.digest) !== -1 && nodeFs.existsSync(entry.path) === false;
    }).length === behind.length,
    JSON.stringify(stranded.map(function (e) { return nodeFs.existsSync(e.path); })));

  var failed = (result && result.failed) || [];
  count("the body the volume would not remove is named in the report with what the " +
    "volume said, because nothing else on this volume records that it is still here",
    failed.length === 1 && failed[0].digest === refusedDigest &&
    /refused to remove/.test(String(failed[0].detail)), JSON.stringify(failed));
  count("it is not counted as reclaimed, so the byte count describes what actually went",
    reclaimedDigests.indexOf(refusedDigest) === -1 && nodeFs.existsSync(
      blobs.pathFor(blobDir, refusedDigest)), JSON.stringify(reclaimedDigests));

  var rows = b.db.from("audit_log").all().filter(function (r) {
    return r.action === "blamepost.store.blobs.reclaimed";
  });
  count("the run filed its audit row even though one removal was refused, which is the " +
    "only record the bodies that went were ever on the volume",
    rows.length >= 1, JSON.stringify(rows.map(function (r) { return r.action; })));
  count("and the row records the run as a failure, because octets this server was asked " +
    "to free are still here",
    rows.length >= 1 && rows[rows.length - 1].outcome === "failure",
    JSON.stringify(rows.length >= 1 ? rows[rows.length - 1].outcome : null));

  // The remediation is a rerun, so it has to reach what was left.
  var again = await handle.blobs.reclaim({ reason: "the volume released the file" });
  count("running it again once the volume releases the file frees what was left behind",
    digestsIn(again.reclaimed).indexOf(refusedDigest) !== -1 &&
    nodeFs.existsSync(blobs.pathFor(blobDir, refusedDigest)) === false,
    JSON.stringify(digestsIn(again.reclaimed)));
}

// The width of the wait, driven from both sides.
//
// A body that nothing references and a body whose row is still being
// written look identical on the volume, and time is the only thing that
// separates them. The guide tells an operator the separation is a day
// and that no flag shortens it, so the width is a promise rather than an
// implementation detail: too narrow and a reclaim removes mail that was
// arriving normally, too wide and the octets an operator ran the verb to
// free stay where they are with no way to reach them.
//
// Both edges are placed with an hour to spare and neither reads the
// module's own constant, so a window moved in either direction fails
// here.
async function theSettleWindowIsTheWidthTheGuidePromises(handle, accountId, blobDir) {
  var guide = nodeFs.readFileSync(
    nodePath.join(helpers.REPO_ROOT, SETTLE_REFERENCE), "utf8");
  count("the operator guide promises a settle window, so this is comparing something",
    SETTLE_PROMISE_RE.test(guide), SETTLE_REFERENCE);

  function strandedAt(subject, ageMs) {
    var bytes  = message(subject);
    var stored = handle.mailbox.appendMessage("INBOX", bytes, { actor: { id: accountId } });
    var digest = b.db.from(MESSAGES).where({ objectid: stored.objectid }).first().blobDigest;
    var bodyPath = blobs.pathFor(blobDir, digest);
    strandAt(stored.objectid, bodyPath, ageMs);
    return { digest: digest, path: bodyPath };
  }

  var young = strandedAt("stranded an hour inside the window", JUST_INSIDE_MS);
  var old   = strandedAt("stranded an hour past the window", JUST_PAST_MS);

  var seen = handle.blobs.reconcile({ verify: false });
  count("the window the reclaim reports is the day the guide promises, so an operator " +
    "reading when a body becomes reclaimable is reading the number they were given",
    seen.settleMs === DOCUMENTED_SETTLE_MS,
    "reports " + seen.settleMs + "ms against the documented " + DOCUMENTED_SETTLE_MS + "ms");

  function verdictFor(report, digest) {
    var matched = (report.orphans || []).filter(function (o) { return o.digest === digest; });
    return matched.length === 1 ? matched[0].reclaimable : null;
  }
  count("a body unreferenced for an hour less than the window is not yet reclaimable, so " +
    "a delivery still being written is not read as octets to free",
    verdictFor(seen, young.digest) === false, JSON.stringify(digestsIn(seen.orphans)));
  count("and one unreferenced an hour longer is, so the wait ends when the guide says it " +
    "ends rather than at some later width nobody was told about",
    verdictFor(seen, old.digest) === true, JSON.stringify(digestsIn(seen.orphans)));

  var run = await handle.blobs.reclaim({ reason: "the width of the settle window" });
  count("the reclaim removes the body past the window",
    digestsIn(run.reclaimed).indexOf(old.digest) !== -1 &&
    nodeFs.existsSync(old.path) === false, JSON.stringify(digestsIn(run.reclaimed)));
  var held = (run.heldBack || []).filter(function (e) { return e.digest === young.digest; });
  count("and leaves the one inside it where it is, named as held back rather than passed " +
    "over in silence",
    held.length === 1 && nodeFs.existsSync(young.path),
    JSON.stringify(digestsIn(run.heldBack)) + ", still on disk " +
      nodeFs.existsSync(young.path));
  count("and the moment it names as the one that body becomes reclaimable is its own age " +
    "plus the documented window, which is what an operator schedules the next run against",
    held.length === 1 &&
    held[0].reclaimableAt ===
      nodeFs.statSync(young.path).mtimeMs + DOCUMENTED_SETTLE_MS,
    held.length === 1
      ? "names " + held[0].reclaimableAt + " against " +
        (nodeFs.statSync(young.path).mtimeMs + DOCUMENTED_SETTLE_MS)
      : "nothing was held back");
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("reclaim-boundary");
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
    var alice = await handle.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
    var blobDir = handle.mailbox.describe().blobDir;
    await bothSidesOfTheBoundary(handle, alice.id, blobDir);
    await oneFileTheVolumeWillNotGiveUp(handle, alice.id, blobDir);
    await theSettleWindowIsTheWidthTheGuidePromises(handle, alice.id, blobDir);

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

module.exports = { name: "blob-reclaim-boundary", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
