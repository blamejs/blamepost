// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A backup taken and restored in the shipped image, the way the operator
 * guide runs it: each command in a fresh `docker run --rm` against the
 * named data volume, as the image's unprivileged user.
 *
 * Two facts about that deployment decide whether a restore can work at
 * all, and neither exists outside a container. The data directory is the
 * mount point of a volume, which Linux will not rename, and nothing else
 * on that filesystem is writable, so a restore that stages under the
 * operating system temp directory or sets the old directory aside beside
 * it cannot move a file. And every command runs in a new PID namespace,
 * so a lock recorded by the process that took a bundle names a namespace
 * the restoring process cannot probe.
 *
 * The run hosts a domain, creates one account, takes a bundle, creates a
 * second account, restores the bundle, and rolls the restore back. After
 * each step it asks the volume which accounts it answers for.
 *
 * Run standalone: node test/layer-2-integration/container-backup-restore.test.js
 */

var helpers = require("../helpers");
var harness = require("./container-harness");

var count = helpers.count;

var HOSTNAME          = "mx.example.com";
var DOMAIN            = "example.com";
var VAULT_PASSPHRASE  = "a long enough vault passphrase for one container run";
var BUNDLE_PASSPHRASE = "a different passphrase that only the bundle uses";
var PASSWORD          = "quiet lantern bicycle 4291";

var STORAGE_PATH = "/srv/backups";
var BUNDLES_PATH = STORAGE_PATH + "/bundles";
var PASS_PATH    = STORAGE_PATH + "/bundle.pass";

// The runtime user the image declares. The storage volume is handed to it
// once, by a root run of node inside the same image, because a fresh named
// volume mounted where the image has no directory belongs to root.
var RUNTIME_UID = 65532;

function env() {
  return [
    "BLAMEPOST_HOSTNAME=" + HOSTNAME,
    "BLAMEPOST_VAULT_PASSPHRASE=" + VAULT_PASSPHRASE,
    "BLAMEPOST_LOG_LEVEL=warn",
  ];
}

function listedAccounts(result) {
  var text = result.stdout;
  var start = text.indexOf("[");
  var end = text.lastIndexOf("]");
  try {
    return JSON.parse(text.slice(start, end + 1))
      .map(function (row) { return row.address; }).sort().join(",");
  } catch (_e) {
    return null;
  }
}

async function run() {
  await harness.requireStack("container-backup-restore.test.js");
  var image = await harness.buildImage();

  var data = await harness.createVolume("blamepost-br-data");
  var storage = await harness.createVolume("blamepost-br-storage");
  var withStorage = { extra: ["--volume", storage + ":" + STORAGE_PATH] };

  function cli(argv) {
    return harness.runCli(image, data, env(), ["bin/blamepost.js"].concat(argv), withStorage);
  }

  try {
    await harness.nodeInImage(image, [
      "var fs=require('node:fs');",
      "fs.writeFileSync('" + PASS_PATH + "',process.env.PASS+'\\n',{mode:0o600});",
      "fs.chownSync('" + STORAGE_PATH + "'," + RUNTIME_UID + "," + RUNTIME_UID + ");",
      "fs.chownSync('" + PASS_PATH + "'," + RUNTIME_UID + "," + RUNTIME_UID + ");",
      "fs.chmodSync('" + STORAGE_PATH + "',0o700);",
      "process.stdout.write(JSON.stringify({ok:true}));",
    ].join(""), {
      env:   ["PASS=" + BUNDLE_PASSPHRASE],
      extra: ["--user", "0", "--volume", storage + ":" + STORAGE_PATH],
    });

    var hosted = await cli(["domain", "add", DOMAIN]);
    count("the domain is hosted on a fresh volume", hosted.code === 0,
      hosted.stderr.trim().slice(-400));
    var alice = await cli(["account", "add", "alice@" + DOMAIN, "--password", PASSWORD]);
    count("the first account is created", alice.code === 0, alice.stderr.trim().slice(-400));

    var taken = await cli(["backup", "run", "--storage", BUNDLES_PATH,
      "--passphrase-file", PASS_PATH, "--json"]);
    count("a bundle is taken", taken.code === 0,
      (taken.stdout + taken.stderr).trim().slice(-600));
    var opened = taken.stdout.indexOf("{");
    var report = JSON.parse(taken.stdout.slice(opened, taken.stdout.lastIndexOf("}") + 1));

    var bob = await cli(["account", "add", "bob@" + DOMAIN, "--password", PASSWORD]);
    count("a second account is created after the bundle", bob.code === 0,
      bob.stderr.trim().slice(-400));

    var restored = await cli(["restore", "apply", "--storage", BUNDLES_PATH,
      "--bundle", report.bundleId, "--passphrase-file", PASS_PATH,
      "--confirm", "--reason", "a restore drill in the shipped image"]);
    count("the restore succeeds on the mounted data volume", restored.code === 0,
      (restored.stdout + restored.stderr).trim().slice(-900), { limit: 900 });

    var afterRestore = await cli(["account", "list", "--json"]);
    count("the restored volume opens in a new container and answers for the one account " +
      "the bundle held", listedAccounts(afterRestore) === "alice@" + DOMAIN,
      JSON.stringify(listedAccounts(afterRestore)) + " " +
      afterRestore.stderr.trim().slice(-400));

    var rolledBack = await cli(["restore", "rollback", "--confirm",
      "--reason", "putting the newer volume back"]);
    count("rolling the restore back succeeds", rolledBack.code === 0,
      (rolledBack.stdout + rolledBack.stderr).trim().slice(-600));

    var afterRollback = await cli(["account", "list", "--json"]);
    count("and the volume answers for both accounts again",
      listedAccounts(afterRollback) === ["alice@" + DOMAIN, "bob@" + DOMAIN].sort().join(","),
      JSON.stringify(listedAccounts(afterRollback)) + " " +
      afterRollback.stderr.trim().slice(-400));
  } finally {
    await harness.cleanup();
  }

  return helpers.getChecks();
}

module.exports = { name: "container-backup-restore", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
