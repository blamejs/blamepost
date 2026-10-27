// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which bundles the verbs that vouch for a bundle are willing to vouch
 * for, held against the one verb that has to put it back.
 *
 * A bundle's manifest records the id it was written as, the data
 * directory it was taken from and the server it was taken on. `restore
 * apply` reads all three before it moves a file and refuses when any of
 * them disagrees with this server, because a restore is the only thing
 * that finds out the hard way: the id says the bundle is another
 * bundle's files under a new name, the data directory decides whether
 * the database key unseals at all, and the hostname decides whose
 * accounts and signing keys come back.
 *
 * Three other verbs read the same manifest and answer questions about
 * the same bundle. `backup verify` decrypts every file and says whether
 * the bundle opens. `backup inspect` describes it without a passphrase.
 * `backup run --keep` and `backup purge --keep` decide which bundles are
 * copies worth keeping and delete the rest.
 *
 * The property driven here is that those four answers agree. A bundle
 * `restore apply` refuses is a bundle that cannot be restored, so a
 * verify that calls it good sends an operator away believing they have a
 * copy, and a sweep that counts it as one of the newest N deletes a
 * bundle that would have worked in order to keep one that will not. The
 * sweep is the case with teeth: the bundles it deletes are the only
 * copies there are.
 *
 * Each case uses a storage directory of its own, so one case's deletions
 * cannot decide another's, and each plants its fault by re-signing the
 * manifest with the volume's own audit signing key. That key needs the
 * vault passphrase, so these are bundles this server wrote rather than
 * bundles an attacker forged: the forged ones are driven next door in
 * cli-restore-hostile-bundle.test.js, and they are refused on the
 * signature long before the origin is read.
 *
 * The last case is the control. A bundle whose three fields agree has to
 * pass every one of these verbs, or a refusal that covers everything
 * would satisfy the cases above while leaving no working backup at all.
 *
 * Every case runs even when an earlier one fails, and the failures are
 * reported together.
 *
 * Run standalone: node test/layer-1-state/cli-bundle-origin-agreement.test.js
 */

var nodeFs   = require("node:fs");

var helpers = require("../helpers");
var bundles = require("../helpers/bundle");

var count = helpers.count;

function inStorage(storageDir) {
  var names;
  try { names = nodeFs.readdirSync(storageDir); } catch (_e) { names = []; }
  return names.sort();
}

// A copy of the volume description whose bundles land in their own
// directory.
function storageFor(ctx, name) {
  return Object.assign({}, ctx.vol, {
    storageDir: helpers.path.join(ctx.vol.root, "storage-" + name),
  });
}

function verify(ctx, vol, bundleId) {
  return ctx.cli(["backup", "verify", "--storage", vol.storageDir,
    "--bundle", bundleId, "--passphrase-file", vol.passFile]);
}

function inspect(ctx, vol, bundleId) {
  return ctx.cli(["backup", "inspect", "--storage", vol.storageDir, "--bundle", bundleId]);
}

function purge(ctx, vol, keep) {
  return ctx.cli(["backup", "purge", "--storage", vol.storageDir, "--keep", String(keep),
    "--confirm", "--reason", "origin agreement under test",
    "--passphrase-file", vol.passFile]);
}

// A moment far enough ahead that a planted bundle sorts newer than every
// bundle the run takes, without depending on how long the run takes.
function laterThanThisRun(hours) {
  return new Date(Date.now() + hours * 60 * 60 * 1000);
}

// ---- cases ------------------------------------------------------------------

async function aBundleCopiedUnderAnotherIdIsNotVouchedFor(ctx) {
  var vol = storageFor(ctx, "copied-id");
  var real = bundles.takeBundle(ctx.cli, vol);
  // The manifest is copied unchanged, so it still names the id it was
  // written as. Nothing needs either passphrase to do this: copying a
  // directory in storage is enough.
  var copied = bundles.cloneBundle(vol, real.bundleId, laterThanThisRun(1));

  var refused = verify(ctx, vol, copied);
  count("`backup verify` refuses a bundle copied under another id", refused.status !== 0,
    "exit " + refused.status + " " + refused.both.slice(0, 600));
  count("and says which id it was written as",
    refused.both.indexOf(real.bundleId) !== -1, refused.both.slice(0, 600));

  var swept = purge(ctx, vol, 1);
  var left = inStorage(vol.storageDir);
  count("a sweep keeping one bundle keeps the bundle that restores",
    left.indexOf(real.bundleId) !== -1,
    "exit " + swept.status + " left " + left.join(", ") + " " + swept.both.slice(0, 600));
  count("and leaves the copy where it is rather than deleting it",
    left.indexOf(copied) !== -1, left.join(", "));
  count("and names the copy as one it did not count",
    swept.both.indexOf(copied) !== -1, swept.both.slice(0, 900));
}

async function aBundleRecordingAnotherServerIsNotVouchedFor(ctx) {
  var vol = storageFor(ctx, "other-server");
  var real = bundles.takeBundle(ctx.cli, vol);
  var planted = bundles.cloneBundle(vol, real.bundleId, laterThanThisRun(2));
  await bundles.resignAsVolume(ctx.cfg, bundles.bundleDir(vol, planted), function (manifest) {
    manifest.metadata.bundleId = planted;
    manifest.metadata.hostname = "someone-else.example.net";
  });

  var refused = verify(ctx, vol, planted);
  count("`backup verify` refuses a bundle recording another server", refused.status !== 0,
    "exit " + refused.status + " " + refused.both.slice(0, 600));
  count("and names the server it records",
    refused.both.indexOf("someone-else.example.net") !== -1, refused.both.slice(0, 600));

  var described = inspect(ctx, vol, planted);
  count("`backup inspect` reports it as a bundle that cannot be restored here",
    described.status !== 0, "exit " + described.status + " " + described.both.slice(0, 600));

  var swept = purge(ctx, vol, 1);
  var left = inStorage(vol.storageDir);
  count("a sweep keeping one bundle keeps the bundle taken on this server",
    left.indexOf(real.bundleId) !== -1,
    "exit " + swept.status + " left " + left.join(", ") + " " + swept.both.slice(0, 600));
  count("and leaves the one recording another server where it is",
    left.indexOf(planted) !== -1, left.join(", "));
}

async function aBundleRecordingAnotherDataDirectoryIsNotVouchedFor(ctx) {
  var vol = storageFor(ctx, "other-data-dir");
  var real = bundles.takeBundle(ctx.cli, vol);
  var planted = bundles.cloneBundle(vol, real.bundleId, laterThanThisRun(3));
  await bundles.resignAsVolume(ctx.cfg, bundles.bundleDir(vol, planted), function (manifest) {
    manifest.metadata.bundleId = planted;
    manifest.metadata.dataDir = "/var/lib/somewhere-this-server-is-not";
  });

  var refused = verify(ctx, vol, planted);
  count("`backup verify` refuses a bundle recording another data directory",
    refused.status !== 0, "exit " + refused.status + " " + refused.both.slice(0, 600));
  count("and names the directory it records",
    refused.both.indexOf("/var/lib/somewhere-this-server-is-not") !== -1,
    refused.both.slice(0, 600));

  var described = inspect(ctx, vol, planted);
  count("`backup inspect` reports it as a bundle that cannot be restored here",
    described.status !== 0, "exit " + described.status + " " + described.both.slice(0, 600));

  var swept = purge(ctx, vol, 1);
  var left = inStorage(vol.storageDir);
  count("a sweep keeping one bundle keeps the bundle taken from this directory",
    left.indexOf(real.bundleId) !== -1,
    "exit " + swept.status + " left " + left.join(", ") + " " + swept.both.slice(0, 600));
  count("and leaves the one recording another directory where it is",
    left.indexOf(planted) !== -1, left.join(", "));
}

// The second caller of the same sweep. `backup run --keep` writes a
// bundle and then deletes the older ones, so a bundle it counts wrongly
// is deleted on the strength of a copy taken in the same command.
async function aRunKeepingBundlesDoesNotCountOneARestoreRefuses(ctx) {
  var vol = storageFor(ctx, "run-keep");
  var real = bundles.takeBundle(ctx.cli, vol);
  var copied = bundles.cloneBundle(vol, real.bundleId, laterThanThisRun(4));

  var run = ctx.cli(["backup", "run", "--storage", vol.storageDir,
    "--passphrase-file", vol.passFile, "--keep", "2", "--json"]);
  count("a run keeping two bundles succeeds", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 600));
  var report = bundles.parsed(run.stdout) || {};
  var left = inStorage(vol.storageDir);
  count("the bundle the run wrote is kept", left.indexOf(report.bundleId) !== -1,
    left.join(", "));
  count("and so is the bundle before it, because the copy is not one of the two",
    left.indexOf(real.bundleId) !== -1, left.join(", ") + " " + run.both.slice(0, 900));
  count("and the copy is named as one the run did not count",
    run.both.indexOf(copied) !== -1, run.both.slice(0, 900));
}

// The control. A refusal that covered every bundle would satisfy each
// case above and leave this server with no backup it could use.
async function aBundleWhoseOriginAgreesIsVouchedForAsBefore(ctx) {
  var vol = storageFor(ctx, "agrees");
  var older = bundles.takeBundle(ctx.cli, vol);
  var newer = bundles.takeBundle(ctx.cli, vol);

  var verified = verify(ctx, vol, newer.bundleId);
  count("`backup verify` still passes a bundle this server took", verified.status === 0,
    "exit " + verified.status + " " + verified.both.slice(0, 600));
  var described = inspect(ctx, vol, newer.bundleId);
  count("`backup inspect` still passes it", described.status === 0,
    "exit " + described.status + " " + described.both.slice(0, 600));

  var swept = purge(ctx, vol, 1);
  var left = inStorage(vol.storageDir);
  count("a sweep keeping one bundle succeeds", swept.status === 0,
    "exit " + swept.status + " " + swept.both.slice(0, 600));
  count("and keeps the newest of them", left.indexOf(newer.bundleId) !== -1, left.join(", "));
  count("and deletes the older one, so the sweep still sweeps",
    left.indexOf(older.bundleId) === -1, left.join(", "));
}

// ---- runner -----------------------------------------------------------------

var CASES = [
  aBundleCopiedUnderAnotherIdIsNotVouchedFor,
  aBundleRecordingAnotherServerIsNotVouchedFor,
  aBundleRecordingAnotherDataDirectoryIsNotVouchedFor,
  aRunKeepingBundlesDoesNotCountOneARestoreRefuses,
  aBundleWhoseOriginAgreesIsVouchedForAsBefore,
];

async function run() {
  var vol = bundles.volume("bundle-origin-agreement");
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

module.exports = {
  name:      "cli-bundle-origin-agreement",
  run:       run,
  getChecks: helpers.getChecks,
};

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
