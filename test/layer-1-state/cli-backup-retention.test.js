// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which bundles `backup run --keep` and `backup purge --keep` delete.
 *
 * Both keep the newest bundles and delete the rest, and the bundles they
 * delete are the only copies there are. A bundle that cannot be restored
 * is not a copy, so it must not be counted as one of the bundles kept, and
 * a directory in storage that nobody can verify must not be deleted on the
 * strength of its name. Each case uses a storage directory of its own.
 *
 *   - A directory with a bundle id from the future and no bundle in it.
 *     Ids sort by time, so counting it keeps it and deletes a real one.
 *   - A bundle whose files were cut short in storage.
 *   - Bundles written under another passphrase, which this passphrase
 *     cannot open and so cannot vouch for.
 *   - A passphrase that opens nothing in storage at all.
 *
 * Every case runs even when an earlier one fails, and the failures are
 * reported together.
 *
 * Run standalone: node test/layer-1-state/cli-backup-retention.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var bundles = require("../helpers/bundle");

var count = helpers.count;

function inStorage(storageDir) {
  var names;
  try { names = nodeFs.readdirSync(storageDir); } catch (_e) { names = []; }
  return names.sort();
}

// A copy of the volume description whose bundles land in their own
// directory, so one case's deletions cannot decide another's.
function storageFor(ctx, name) {
  return Object.assign({}, ctx.vol, { storageDir: nodePath.join(ctx.vol.root, "storage-" + name) });
}

function purge(ctx, vol, keep, passFile) {
  return ctx.cli(["backup", "purge", "--storage", vol.storageDir, "--keep", String(keep),
    "--confirm", "--reason", "retention under test", "--passphrase-file", passFile || vol.passFile]);
}

// ---- cases ------------------------------------------------------------------

async function aDirectoryNamedFromTheFutureIsNotCounted(ctx) {
  var vol = storageFor(ctx, "future");
  var oldest = bundles.takeBundle(ctx.cli, vol);
  var middle = bundles.takeBundle(ctx.cli, vol);
  var future = bundles.bundleIdAt(new Date(Date.UTC(2099, 0, 1)));
  nodeFs.mkdirSync(nodePath.join(vol.storageDir, future), { recursive: true });
  nodeFs.writeFileSync(nodePath.join(vol.storageDir, future, "left-here"), "not a bundle\n");

  var run = ctx.cli(["backup", "run", "--storage", vol.storageDir,
    "--passphrase-file", vol.passFile, "--keep", "2", "--json"]);
  count("a run keeping two bundles succeeds", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 500));
  var report = bundles.parsed(run.stdout) || {};
  var left = inStorage(vol.storageDir);
  count("and the bundle it wrote is kept", left.indexOf(report.bundleId) !== -1, left.join(", "));
  count("and so is the newest bundle before it, because the directory from the future is " +
    "not a bundle", left.indexOf(middle.bundleId) !== -1, left.join(", "));
  count("and the oldest bundle is the one deleted", left.indexOf(oldest.bundleId) === -1,
    left.join(", "));
  count("and the directory nothing could verify is left where it was",
    left.indexOf(future) !== -1, left.join(", "));
  count("and the run names it as a directory it did not count",
    run.both.indexOf(future) !== -1, run.both.slice(0, 800));
}

async function aBundleCutShortIsNotCounted(ctx) {
  var vol = storageFor(ctx, "short");
  var older = bundles.takeBundle(ctx.cli, vol);
  var newer = bundles.takeBundle(ctx.cli, vol);
  var dir = bundles.bundleDir(vol, newer.bundleId);
  var manifest = bundles.readManifest(dir);
  var largest = manifest.files.slice().sort(function (a, b) {
    return b.encryptedSize - a.encryptedSize;
  })[0];
  var blob = nodePath.join(dir, largest.encryptedPath);
  var bytes = nodeFs.readFileSync(blob);
  nodeFs.writeFileSync(blob, bytes.subarray(0, Math.floor(bytes.length / 2)));

  var run = purge(ctx, vol, 1);
  var left = inStorage(vol.storageDir);
  count("purging down to one bundle keeps the older bundle, because the newer one was cut " +
    "short in storage", left.indexOf(older.bundleId) !== -1,
    "exit " + run.status + " left " + left.join(", ") + " " + run.both.slice(0, 400));
  count("and does not delete the bundle it could not verify either",
    left.indexOf(newer.bundleId) !== -1, left.join(", "));
  count("and names that bundle as one it did not count",
    run.both.indexOf(newer.bundleId) !== -1, run.both.slice(0, 800));
}

async function bundlesUnderAnotherPassphraseAreLeftAlone(ctx) {
  var vol = storageFor(ctx, "passphrases");
  var otherPass = nodePath.join(ctx.vol.root, "other-bundle.pass");
  nodeFs.writeFileSync(otherPass, "yet another passphrase for other bundles\n", { mode: 0o600 });
  var mine = bundles.takeBundle(ctx.cli, vol);
  var theirs = bundles.takeBundle(ctx.cli, Object.assign({}, vol, { passFile: otherPass }));
  var mineAgain = bundles.takeBundle(ctx.cli, vol);

  var run = purge(ctx, vol, 1);
  var left = inStorage(vol.storageDir);
  count("purging down to one bundle succeeds", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 500));
  count("and keeps the newest bundle this passphrase opens",
    left.indexOf(mineAgain.bundleId) !== -1, left.join(", "));
  count("and deletes the older bundle this passphrase opens",
    left.indexOf(mine.bundleId) === -1, left.join(", "));
  count("and leaves the bundle written under another passphrase",
    left.indexOf(theirs.bundleId) !== -1, left.join(", "));
}

async function aPassphraseThatOpensNothingDeletesNothing(ctx) {
  var vol = storageFor(ctx, "nothing-opens");
  bundles.takeBundle(ctx.cli, vol);
  bundles.takeBundle(ctx.cli, vol);
  var before = inStorage(vol.storageDir);
  var wrongPass = nodePath.join(ctx.vol.root, "wrong-bundle.pass");
  nodeFs.writeFileSync(wrongPass, "a passphrase no bundle here was written under\n", { mode: 0o600 });

  var run = purge(ctx, vol, 1, wrongPass);
  count("a purge whose passphrase opens no bundle in storage fails", run.status === 1,
    "exit " + run.status + " " + run.both.slice(0, 500));
  count("and deletes nothing", inStorage(vol.storageDir).join(",") === before.join(","),
    inStorage(vol.storageDir).join(", "));
}

// ---- runner -----------------------------------------------------------------

var CASES = [
  aDirectoryNamedFromTheFutureIsNotCounted,
  aBundleCutShortIsNotCounted,
  bundlesUnderAnotherPassphraseAreLeftAlone,
  aPassphraseThatOpensNothingDeletesNothing,
];

async function run() {
  var vol = bundles.volume("backup-retention");
  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  try {
    process.env.BLAMEJS_TMPDIR = vol.workDir;
    var cfg = bundles.configFor(vol);
    var cli = bundles.cliFor(vol);
    await bundles.addAccount(cfg, "alice");

    var ctx = { vol: vol, cfg: cfg, cli: cli };
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

module.exports = { name: "cli-backup-retention", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
