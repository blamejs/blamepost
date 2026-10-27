// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `restore apply` and `restore rollback` do to the live data volume
 * when something other than the bundle goes wrong.
 *
 *   - The data directory is a volume mount point, as it is in the shipped
 *     container. Linux refuses to rename a mount point and refuses to
 *     rename across two filesystems, and `helpers/rename-fault.js` gives
 *     the spawned binary exactly those two answers.
 *   - Another process holds the volume. Both verbs replace every file on
 *     it, and a server still running keeps writing the files it opened.
 *   - The process is killed after the old files have been set aside and
 *     before the new ones are all in place. The next command that opens
 *     the volume has to say so rather than open whatever is there, and
 *     `restore rollback` has to put the volume back.
 *   - `--point` names a directory that is not one of this volume's
 *     rollback points.
 *   - The rollback point does not open. The volume that was live before
 *     the rollback has to be left in place.
 *   - A bundle taken of a volume that has been restored carries neither
 *     the volume lock nor the rollback points.
 *
 * Every case runs even when an earlier one fails, and the failures are
 * reported together.
 *
 * Run standalone: node test/layer-1-state/cli-restore-volume-safety.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers     = require("../helpers");
var bundles     = require("../helpers/bundle");
var renameFault = require("../helpers/rename-fault");
var store       = require("../../lib/store");

var count = helpers.count;

function restoreArgs(vol, bundleId, extra) {
  return ["restore", "apply", "--storage", vol.storageDir, "--bundle", bundleId,
    "--passphrase-file", vol.passFile, "--confirm", "--reason", "a restore under test"]
    .concat(extra || []);
}

function rollbackPoints(cli) {
  var run = cli(["restore", "list-rollbacks", "--json"]);
  var text = run.stdout;
  var start = text.indexOf("[");
  var end = text.lastIndexOf("]");
  try { return JSON.parse(text.slice(start, end + 1)); } catch (_e) { return null; }
}

async function ensureAccounts(ctx, wanted) {
  var listed = bundles.accountsListed(ctx.cli);
  var have = listed.addresses || [];
  for (var i = 0; i < wanted.length; i += 1) {
    if (have.indexOf(wanted[i] + "@" + bundles.DOMAIN) === -1) {
      await bundles.addAccount(ctx.cfg, wanted[i]);
    }
  }
}

// ---- cases ------------------------------------------------------------------

async function aRestoreOntoAMountedVolume(ctx) {
  await ensureAccounts(ctx, ["alice", "bob"]);
  var childTmp = nodePath.join(ctx.vol.root, "child-tmp");
  nodeFs.mkdirSync(childTmp, { recursive: true });
  var mounted = bundles.cliFor(ctx.vol, {
    execArgv: ["--require", renameFault.PRELOAD],
    env: {
      BLAMEPOST_RENAME_FAULT:        "mount",
      BLAMEPOST_RENAME_FAULT_VOLUME: ctx.vol.dataDir,
      TMPDIR: childTmp, TMP: childTmp, TEMP: childTmp,
    },
  });

  var run = mounted(restoreArgs(ctx.vol, ctx.bundle.bundleId));
  count("a restore succeeds when the data directory cannot be renamed and the temp " +
    "directory is on another filesystem", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 600));
  var listed = bundles.accountsListed(ctx.cli);
  count("and the restored volume answers for the account the bundle held",
    listed.addresses !== null && listed.addresses.join(",") === ctx.alice,
    JSON.stringify(listed.addresses) + " " + listed.run.both.slice(0, 200));
  var left = nodeFs.readdirSync(childTmp).filter(function (name) {
    return /restore|bundle/i.test(name);
  });
  count("and no decrypted copy of the volume was left in the temp directory",
    left.length === 0, left.join(", "));
}

async function aHeldVolumeIsRefused(ctx) {
  var handle = await store.open(ctx.cfg);
  try {
    var before = bundles.volumeFiles(ctx.vol.dataDir);
    var points = JSON.stringify(rollbackPoints(ctx.cli));

    var apply = ctx.cli(restoreArgs(ctx.vol, ctx.bundle.bundleId));
    count("a restore while another process holds the volume is refused",
      apply.status !== 0, "exit " + apply.status + " " + apply.both.slice(0, 500));
    count("and the refusal says the volume is open elsewhere",
      /already open|store\/volume-in-use/i.test(apply.both), apply.both.slice(0, 500));

    var rollback = ctx.cli(["restore", "rollback", "--confirm", "--reason", "while held"]);
    count("a rollback while another process holds the volume is refused",
      rollback.status !== 0, "exit " + rollback.status + " " + rollback.both.slice(0, 500));
    count("and that refusal says the volume is open elsewhere too",
      /already open|store\/volume-in-use/i.test(rollback.both), rollback.both.slice(0, 500));

    var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
    count("and no file on the held volume changed", changed.length === 0, changed.join(", "));
    count("and no rollback point was added or removed",
      JSON.stringify(rollbackPoints(ctx.cli)) === points, points.slice(0, 300));
  } finally {
    handle.close();
  }
}

async function aPointThatIsNotARollbackPointIsRefused(ctx) {
  var before = bundles.volumeFiles(ctx.vol.dataDir);
  var elsewhere = nodePath.join(ctx.vol.root, "not-a-rollback-point");
  nodeFs.mkdirSync(elsewhere, { recursive: true });
  nodeFs.writeFileSync(nodePath.join(elsewhere, "db.enc"), "not a database\n");

  [elsewhere, ctx.vol.storageDir, ctx.vol.dataDir].forEach(function (point) {
    var run = ctx.cli(["restore", "rollback", "--point", point,
      "--confirm", "--reason", "naming a directory by hand"]);
    count("`--point " + point + "` is refused because it is not one of this volume's " +
      "rollback points", run.status === 2, "exit " + run.status + " " + run.both.slice(0, 400));
  });
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and no file on the live volume changed", changed.length === 0, changed.join(", "));
  count("and the directory named is still where it was",
    nodeFs.existsSync(nodePath.join(elsewhere, "db.enc")), "gone");
}

async function anInterruptedRestoreIsReportedAndUndone(ctx) {
  await ensureAccounts(ctx, ["alice", "bob"]);
  var expected = bundles.accountsListed(ctx.cli).addresses;
  var interrupted = bundles.cliFor(ctx.vol, {
    execArgv: ["--require", renameFault.PRELOAD],
    env: {
      BLAMEPOST_RENAME_FAULT:        "interrupt",
      BLAMEPOST_RENAME_FAULT_VOLUME: ctx.vol.dataDir,
    },
  });

  var run = interrupted(restoreArgs(ctx.vol, ctx.bundle.bundleId));
  count("the restore under test was killed partway, so this case tests what it claims to",
    run.status !== 0, "exit " + run.status + " " + run.both.slice(0, 300));

  var opened = ctx.cli(["account", "list"]);
  count("the next command that opens the volume refuses rather than reading a half-restored " +
    "volume", opened.status !== 0, "exit " + opened.status + " " + opened.both.slice(0, 500));
  count("and the refusal names the interrupted restore and the command that undoes it",
    /restore/i.test(opened.both) && /restore rollback/.test(opened.both),
    opened.both.slice(0, 500));

  var recordPath = nodePath.join(ctx.vol.dataDir, ".restore", "in-flight.json");
  count("the interrupted restore left its record on the volume", nodeFs.existsSync(recordPath),
    recordPath);
  var recorded = nodeFs.readFileSync(recordPath);

  // The rollback killed partway too: it has taken the restored entries
  // back out and is putting the original ones back when it stops. A
  // second rollback has to finish the job from there.
  var interruptedLater = bundles.cliFor(ctx.vol, {
    execArgv: ["--require", renameFault.PRELOAD],
    env: {
      BLAMEPOST_RENAME_FAULT:        "interrupt-second",
      BLAMEPOST_RENAME_FAULT_VOLUME: ctx.vol.dataDir,
    },
  });
  var stopped = interruptedLater(["restore", "rollback", "--confirm", "--reason",
    "an undo that is interrupted"]);
  count("the rollback under test was killed partway as well",
    stopped.status !== 0, "exit " + stopped.status + " " + stopped.both.slice(0, 300));

  var undone = ctx.cli(["restore", "rollback", "--confirm", "--reason", "undoing the interruption"]);
  count("`restore rollback` puts the volume back", undone.status === 0,
    "exit " + undone.status + " " + undone.both.slice(0, 600));
  var listed = bundles.accountsListed(ctx.cli);
  count("and the volume answers for the accounts it held before the restore started",
    listed.addresses !== null && listed.addresses.join(",") === expected.join(","),
    JSON.stringify(listed.addresses) + " vs " + JSON.stringify(expected) + " " +
    listed.run.both.slice(0, 200));

  // The record describing a move that has already been undone, put back
  // as a crash between the undo and the record's removal would leave it.
  // Undoing it a second time would move the volume that is now in place.
  var before = bundles.volumeFiles(ctx.vol.dataDir);
  nodeFs.writeFileSync(recordPath, recorded);
  var again = ctx.cli(["restore", "rollback", "--confirm", "--reason", "undoing it twice"]);
  count("undoing a move that was already undone is refused", again.status !== 0,
    "exit " + again.status + " " + again.both.slice(0, 500));
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and no file on the volume moved", changed.length === 0, changed.join(", "));
  nodeFs.rmSync(recordPath);
  var afterwards = bundles.accountsListed(ctx.cli);
  count("and once the stale record is deleted the volume opens with the same accounts",
    afterwards.addresses !== null && afterwards.addresses.join(",") === expected.join(","),
    JSON.stringify(afterwards.addresses) + " " + afterwards.run.both.slice(0, 200));
}

async function aRollbackPointThatDoesNotOpenIsNotLeftInPlace(ctx) {
  await ensureAccounts(ctx, ["alice", "bob"]);
  var applied = ctx.cli(restoreArgs(ctx.vol, ctx.bundle.bundleId, ["--json"]));
  count("a restore to create a rollback point succeeds", applied.status === 0,
    "exit " + applied.status + " " + applied.both.slice(0, 400));
  var report = bundles.parsed(applied.stdout) || {};
  var pointDb = nodePath.join(String(report.rollbackPath), "db.enc");
  count("and the rollback point holds a database to damage", nodeFs.existsSync(pointDb), pointDb);
  var bytes = nodeFs.readFileSync(pointDb);
  for (var i = 64; i < Math.min(bytes.length, 4096); i += 1) bytes[i] = bytes[i] ^ 0xff;
  nodeFs.writeFileSync(pointDb, bytes);

  var restoredAccounts = bundles.accountsListed(ctx.cli).addresses;
  var before = bundles.volumeFiles(ctx.vol.dataDir);

  var run = ctx.cli(["restore", "rollback", "--confirm", "--reason", "a point that will not open"]);
  count("rolling back to a point that does not open reports failure", run.status === 1,
    "exit " + run.status + " " + run.both.slice(0, 500));
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and the volume that was live is back in place, byte for byte",
    changed.length === 0, changed.join(", "));
  var listed = bundles.accountsListed(ctx.cli);
  count("and it still opens and answers for its accounts",
    listed.addresses !== null && listed.addresses.join(",") === restoredAccounts.join(","),
    JSON.stringify(listed.addresses) + " " + listed.run.both.slice(0, 200));
  var points = rollbackPoints(ctx.cli) || [];
  count("and the point that did not open is still listed",
    points.some(function (p) { return p.rollbackPath === report.rollbackPath; }),
    JSON.stringify(points).slice(0, 300));
}

async function aBundleCarriesNeitherTheLockNorTheRollbackPoints(ctx) {
  var taken = bundles.takeBundle(ctx.cli, ctx.vol);
  var manifest = bundles.readManifest(bundles.bundleDir(ctx.vol, taken.bundleId));
  var paths = manifest.files.map(function (entry) { return entry.relativePath; });
  count("a bundle does not carry the volume lock of the process that took it",
    paths.indexOf("blamepost.lock") === -1, paths.join(", "));
  count("and does not carry the rollback points a restore kept on the volume",
    paths.every(function (p) { return p.indexOf(".restore") !== 0; }),
    paths.filter(function (p) { return p.indexOf(".restore") === 0; }).join(", "));
  count("and a rollback point does exist on this volume, so the second check means something",
    nodeFs.existsSync(nodePath.join(ctx.vol.dataDir, ".restore")), "no .restore directory");
}

// ---- runner -----------------------------------------------------------------

var CASES = [
  aRestoreOntoAMountedVolume,
  aHeldVolumeIsRefused,
  aPointThatIsNotARollbackPointIsRefused,
  anInterruptedRestoreIsReportedAndUndone,
  aRollbackPointThatDoesNotOpenIsNotLeftInPlace,
  aBundleCarriesNeitherTheLockNorTheRollbackPoints,
];

async function run() {
  var vol = bundles.volume("restore-safety");
  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  try {
    process.env.BLAMEJS_TMPDIR = vol.workDir;
    var cfg = bundles.configFor(vol);
    var cli = bundles.cliFor(vol);

    var alice = await bundles.addAccount(cfg, "alice");
    var bundle = bundles.takeBundle(cli, vol);

    var ctx = { vol: vol, cfg: cfg, cli: cli, bundle: bundle, alice: alice };

    var failures = [];
    for (var i = 0; i < CASES.length; i += 1) {
      try {
        await CASES[i](ctx);
      } catch (e) {
        failures.push(CASES[i].name + ": " + ((e && e.message) || String(e)));
      }
    }
    if (failures.length > 0) {
      throw new Error(failures.length + " of " + CASES.length + " case(s) failed:\n  " +
        failures.join("\n  "));
    }
    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(vol.root);
  }
}

module.exports = { name: "cli-restore-volume-safety", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
