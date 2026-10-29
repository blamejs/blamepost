// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `restore apply` against bundles somebody else has been able to change.
 *
 * The attacker here can write to the backup location and does not know
 * either passphrase. Each case builds one altered bundle out of a real one
 * and drives `restore apply` against it through the binary, and each
 * asserts what the operator is left with: the exit status, what the
 * refusal says, whether any file outside `.restore` on the live volume
 * changed, and which accounts the volume answers for afterwards.
 *
 *   - A manifest re-signed with a key the attacker made, after dropping the
 *     message bodies and the audit anchor from it. The signature checks
 *     out against the key the manifest carries, so only a comparison with
 *     the signing key sealed inside the bundle refuses it.
 *   - A bundle copied under a newer id. The manifest still names the id it
 *     was written as.
 *   - A bundle taken on a server with a different hostname.
 *   - Entries whose paths leave the data directory, in every spelling the
 *     manifest format can carry.
 *   - A vault passphrase that does not open the bundle's keys.
 *   - A `--fingerprint` pin the manifest does not satisfy.
 *   - An older bundle, which is a legitimate restore that rewinds the
 *     volume, and has to say how far.
 *   - A bundle written by an older release, which carries the volume lock
 *     of the process that took it and a file under `.restore`.
 *
 * Every case runs even when an earlier one fails, and the failures are
 * reported together, because the cases share one volume and one failing
 * case says nothing about the next.
 *
 * Run standalone: node test/layer-1-state/cli-restore-hostile-bundle.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var bundles = require("../helpers/bundle");

var count = helpers.count;

var OTHER_FINGERPRINT = "1".repeat(128);

// ---- readings ---------------------------------------------------------------

// The directories a restore sets a replaced volume aside in, under either
// layout this repository has had: inside the volume, and beside it.
function rollbackPoints(vol) {
  var found = [];
  [nodePath.join(vol.dataDir, ".restore"), vol.dataDir + ".rollbacks"].forEach(function (dir) {
    var names;
    try { names = nodeFs.readdirSync(dir); } catch (_e) { names = []; }
    names.forEach(function (name) {
      if (/^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/.test(name)) found.push(name);
    });
  });
  return found.sort();
}

function restoreArgs(vol, bundleId, extra) {
  return ["restore", "apply", "--storage", vol.storageDir, "--bundle", bundleId,
    "--passphrase-file", vol.passFile, "--confirm", "--reason", "a restore under test"]
    .concat(extra || []);
}

// ---- cases ------------------------------------------------------------------

async function aResignedManifestIsRefused(ctx) {
  var id = bundles.cloneBundle(ctx.vol, ctx.older.bundleId, new Date());
  bundles.resign(bundles.bundleDir(ctx.vol, id), function (manifest) {
    manifest.metadata.bundleId = id;
    manifest.files = manifest.files.filter(function (entry) {
      return entry.relativePath.indexOf("blobs/") !== 0 && entry.relativePath !== "audit.tip";
    });
  });
  var before = bundles.volumeFiles(ctx.vol.dataDir);

  var run = ctx.cli(restoreArgs(ctx.vol, id));
  count("a manifest re-signed with a key the attacker made is refused",
    run.status !== 0, "exit " + run.status + " " + run.both.slice(0, 500));
  count("and the refusal says the signing key is not the one the bundle carries",
    /signing key|signed by/i.test(run.both), run.both.slice(0, 500));
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and no file on the live volume changed", changed.length === 0, changed.join(", "));
  var listed = bundles.accountsListed(ctx.cli);
  count("and the volume still answers for both accounts",
    listed.addresses !== null && listed.addresses.join(",") === ctx.both.join(","),
    JSON.stringify(listed.addresses) + " " + listed.run.both.slice(0, 200));
}

async function aBundleCopiedUnderAnotherIdIsRefused(ctx) {
  var id = bundles.cloneBundle(ctx.vol, ctx.newer.bundleId, new Date());
  var before = bundles.volumeFiles(ctx.vol.dataDir);
  var points = rollbackPoints(ctx.vol);

  var run = ctx.cli(restoreArgs(ctx.vol, id));
  count("a bundle stored under an id other than the one it was written as is refused",
    run.status !== 0, "exit " + run.status + " " + run.both.slice(0, 500));
  count("and the refusal names both ids",
    run.both.indexOf(id) !== -1 && run.both.indexOf(ctx.newer.bundleId) !== -1,
    run.both.slice(0, 500));
  count("and nothing was set aside, because the refusal came before anything moved",
    rollbackPoints(ctx.vol).join(",") === points.join(","),
    JSON.stringify(rollbackPoints(ctx.vol)));
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and no file on the live volume changed", changed.length === 0, changed.join(", "));
}

async function aBundleFromAnotherHostnameIsRefused(ctx) {
  var elsewhere = bundles.cliFor(ctx.vol, { env: { BLAMEPOST_HOSTNAME: "mx.elsewhere.example" } });
  var before = bundles.volumeFiles(ctx.vol.dataDir);
  var points = rollbackPoints(ctx.vol);

  var run = elsewhere(restoreArgs(ctx.vol, ctx.newer.bundleId));
  count("a bundle taken on a server with another hostname is refused",
    run.status !== 0, "exit " + run.status + " " + run.both.slice(0, 500));
  count("and the refusal names both hostnames",
    run.both.indexOf("mx.elsewhere.example") !== -1 && run.both.indexOf(bundles.HOSTNAME) !== -1,
    run.both.slice(0, 500));
  count("and nothing was set aside",
    rollbackPoints(ctx.vol).join(",") === points.join(","),
    JSON.stringify(rollbackPoints(ctx.vol)));
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and no file on the live volume changed", changed.length === 0, changed.join(", "));
}

// Every spelling of a path outside the data directory the manifest's JSON
// can carry. The first four are refused by the manifest validator, the NUL
// byte and the overlong name by the path resolver the extraction writes
// through. Each lands in its own bundle, so one refusal cannot stand in
// for another.
var ESCAPES = [
  { label: "a parent-directory traversal",  path: "../escape-parent.txt" },
  { label: "an absolute path",               path: "/escape-absolute.txt" },
  { label: "a drive letter",                 path: "C:/escape-drive.txt" },
  { label: "a traversal written with backslashes", path: "keys\\..\\..\\escape-backslash.txt" },
  { label: "a UNC path",                     path: "\\\\server\\share\\escape-unc.txt" },
  { label: "a NUL byte",                     path: "escape\u0000nul.txt" },
  { label: "a name longer than any filesystem takes", path: "e".repeat(4096) },
];

async function pathsOutsideTheVolumeAreRefused(ctx) {
  for (var i = 0; i < ESCAPES.length; i += 1) {
    var vector = ESCAPES[i];
    var id = bundles.cloneBundle(ctx.vol, ctx.newer.bundleId, new Date());
    var dir = bundles.bundleDir(ctx.vol, id);
    bundles.resign(dir, function (manifest) {
      manifest.metadata.bundleId = id;
      var template = manifest.files.filter(function (entry) {
        return entry.relativePath === "db.key.enc";
      })[0];
      var copy = Object.assign({}, template, {
        relativePath:  vector.path,
        encryptedPath: "files/escape-" + i + ".enc",
      });
      nodeFs.copyFileSync(nodePath.join(dir, template.encryptedPath),
        nodePath.join(dir, copy.encryptedPath));
      manifest.files.push(copy);
    });
    var before = bundles.volumeFiles(ctx.vol.dataDir);
    var points = rollbackPoints(ctx.vol);

    var run = ctx.cli(restoreArgs(ctx.vol, id));
    count("an entry naming " + vector.label + " is refused",
      run.status !== 0, "exit " + run.status + " " + run.both.slice(0, 400));
    var target = vector.path.indexOf("\u0000") === -1 && vector.path.length < 256
      ? nodePath.resolve(ctx.vol.dataDir, vector.path.replace(/\\/g, "/"))
      : null;
    count("and nothing was written where " + vector.label + " points",
      target === null || !nodeFs.existsSync(target), String(target));
    count("and nothing was set aside for " + vector.label,
      rollbackPoints(ctx.vol).join(",") === points.join(","),
      JSON.stringify(rollbackPoints(ctx.vol)));
    var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
    count("and no file on the live volume changed for " + vector.label,
      changed.length === 0, changed.join(", "));
  }
}

async function anotherVaultPassphraseLeavesTheVolumeAlone(ctx) {
  var wrongVault = bundles.cliFor(ctx.vol, {
    env: { BLAMEPOST_VAULT_PASSPHRASE: "some other vault passphrase entirely, long enough" },
  });
  var before = bundles.volumeFiles(ctx.vol.dataDir);

  var run = wrongVault(restoreArgs(ctx.vol, ctx.newer.bundleId));
  count("a vault passphrase that does not open the bundle's keys fails the restore",
    run.status !== 0, "exit " + run.status + " " + run.both.slice(0, 500));
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and no file on the live volume changed", changed.length === 0, changed.join(", "));
  var listed = bundles.accountsListed(ctx.cli);
  count("and the volume still opens with its own passphrase and answers for both accounts",
    listed.addresses !== null && listed.addresses.join(",") === ctx.both.join(","),
    JSON.stringify(listed.addresses) + " " + listed.run.both.slice(0, 200));
}

async function aFingerprintPinIsEnforcedBeforeAnythingMoves(ctx) {
  var before = bundles.volumeFiles(ctx.vol.dataDir);
  var points = rollbackPoints(ctx.vol);

  var run = ctx.cli(restoreArgs(ctx.vol, ctx.newer.bundleId, ["--fingerprint", OTHER_FINGERPRINT]));
  count("a restore pinned to a key that did not sign the bundle is refused",
    run.status !== 0, "exit " + run.status + " " + run.both.slice(0, 500));
  count("and nothing was set aside",
    rollbackPoints(ctx.vol).join(",") === points.join(","),
    JSON.stringify(rollbackPoints(ctx.vol)));
  var changed = bundles.differences(before, bundles.volumeFiles(ctx.vol.dataDir));
  count("and no file on the live volume changed", changed.length === 0, changed.join(", "));
}

async function anOlderBundleSaysWhatItRewinds(ctx) {
  var manifest = bundles.readManifest(bundles.bundleDir(ctx.vol, ctx.older.bundleId));

  var run = ctx.cli(restoreArgs(ctx.vol, ctx.older.bundleId, ["--json"]));
  count("restoring the older bundle succeeds", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 600));
  var report = bundles.parsed(run.stdout) || {};
  count("and the report says when the bundle was taken",
    report.bundleCreatedAt === manifest.createdAt,
    JSON.stringify(report.bundleCreatedAt) + " vs " + manifest.createdAt);
  count("and where the replaced volume's audit trail had reached, which is past the bundle's",
    typeof report.replacedAnchor === "number" && typeof report.restoredAnchor === "number" &&
    report.replacedAnchor > report.restoredAnchor,
    JSON.stringify({ replaced: report.replacedAnchor, restored: report.restoredAnchor }));
  count("and that storage holds bundles newer than the one restored",
    typeof report.newerBundles === "number" && report.newerBundles >= 1,
    JSON.stringify(report.newerBundles));
  count("and which key signed it, which is the key the restored volume holds",
    typeof report.signedBy === "string" && report.signedBy === ctx.newer.signature.fingerprint,
    JSON.stringify(report.signedBy));

  var human = ctx.cli(["restore", "list-rollbacks"]);
  count("the rollback point for that restore is listed", human.status === 0 &&
    rollbackPoints(ctx.vol).length >= 1, human.both.slice(0, 300));

  var listed = bundles.accountsListed(ctx.cli);
  count("the restored volume answers for the one account the older bundle held",
    listed.addresses !== null && listed.addresses.join(",") === ctx.first,
    JSON.stringify(listed.addresses) + " " + listed.run.both.slice(0, 200));

  var back = ctx.cli(["restore", "rollback", "--confirm", "--reason", "putting the newer volume back"]);
  count("rolling back afterwards succeeds", back.status === 0,
    "exit " + back.status + " " + back.both.slice(0, 500));
  var again = bundles.accountsListed(ctx.cli);
  count("and the volume answers for both accounts again",
    again.addresses !== null && again.addresses.join(",") === ctx.both.join(","),
    JSON.stringify(again.addresses) + " " + again.run.both.slice(0, 200));
}

async function aBundleFromAnOlderReleaseRestores(ctx) {
  var dir = bundles.bundleDir(ctx.vol, ctx.newer.bundleId);
  // The lock a server records names its process and its process
  // namespace. This one names a namespace no process here belongs to,
  // which is what a lock taken inside one container looks like to the
  // next container that opens the volume.
  await bundles.sealEntry(ctx.cfg, dir, "blamepost.lock",
    Buffer.from("4294967294\nnot-a-namespace-on-this-machine\n", "utf8"));
  await bundles.sealEntry(ctx.cfg, dir, ".restore/left-by-an-older-release.txt",
    Buffer.from("this file is not part of any volume\n", "utf8"));

  var run = ctx.cli(restoreArgs(ctx.vol, ctx.newer.bundleId));
  count("a bundle carrying another process's volume lock restores", run.status === 0,
    "exit " + run.status + " " + run.both.slice(0, 600));
  count("and the file it carried under .restore is not on the volume",
    !nodeFs.existsSync(nodePath.join(ctx.vol.dataDir, ".restore", "left-by-an-older-release.txt")),
    "present");
  var listed = bundles.accountsListed(ctx.cli);
  count("and the restored volume opens, so the lock it carried is not the one it holds",
    listed.addresses !== null && listed.addresses.join(",") === ctx.both.join(","),
    JSON.stringify(listed.addresses) + " " + listed.run.both.slice(0, 300));
}

// ---- runner -----------------------------------------------------------------

var CASES = [
  aResignedManifestIsRefused,
  aBundleCopiedUnderAnotherIdIsRefused,
  aBundleFromAnotherHostnameIsRefused,
  pathsOutsideTheVolumeAreRefused,
  anotherVaultPassphraseLeavesTheVolumeAlone,
  aFingerprintPinIsEnforcedBeforeAnythingMoves,
  anOlderBundleSaysWhatItRewinds,
  aBundleFromAnOlderReleaseRestores,
];

async function run() {
  var vol = bundles.volume("restore-hostile");
  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  try {
    process.env.BLAMEJS_TMPDIR = vol.workDir;
    var cfg = bundles.configFor(vol);
    var cli = bundles.cliFor(vol);

    var alice = await bundles.addAccount(cfg, "alice");
    var older = bundles.takeBundle(cli, vol);
    var bob = await bundles.addAccount(cfg, "bob");
    var newer = bundles.takeBundle(cli, vol);

    var ctx = {
      vol: vol, cfg: cfg, cli: cli, older: older, newer: newer,
      first: alice, both: [alice, bob].sort(),
    };

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

module.exports = { name: "cli-restore-hostile-bundle", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
