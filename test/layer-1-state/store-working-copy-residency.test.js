// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Where the decrypted copy of the database is allowed to live, and what
 * happens when there is nowhere it is allowed to live.
 *
 * The volume is encrypted at rest, so reading it means writing a
 * decrypted copy somewhere. That somewhere has to be memory. A copy on
 * disk is captured by the next backup, survives the process that made it,
 * and turns an encrypted volume into an encrypted volume beside a
 * readable one, which is the weaker of the two.
 *
 * The refusal that enforces this had a structural detector and no
 * behavioral test, which is the wrong way round for a property about
 * what the server does rather than about how it is written. A detector
 * matches one lexical shape and goes quiet the day the shape changes; it
 * cannot see a refusal that stopped firing. So the checks here open the
 * store, or fail to, and read the filesystem afterwards.
 *
 * The mount test itself reads `/proc/mounts` and compares the filesystem
 * TYPE, because a directory somebody created at `/dev/shm` satisfies a
 * path check while being ordinary disk. This run cannot reach that
 * comparison: off Linux the platform branch answers first and returns
 * before anything is read. What this run covers is the refusal, its
 * wording, and the residency of the copy when a directory is named. On
 * Linux the same file additionally covers the mount comparison, and the
 * check below that names the platform is what says which of the two
 * happened rather than leaving the reader to assume the stronger one.
 *
 * Run standalone: node test/layer-1-state/store-working-copy-residency.test.js
 */

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var store     = require("../../lib/store");
var configMod = require("../../lib/config");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var HOSTNAME         = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The refusal's own code. A frozen contract: it survives a rename of the
// function that throws it and disappears if the throw is deleted, which
// is what makes it worth anchoring on.
var NO_MOUNT = "store/no-working-copy-mount";

// The name the framework gives a working copy. Matched as a shape rather
// than in full, because the hash in the middle is per volume.
var WORKING_COPY = /^blamejs-[0-9a-f]+\.db(-shm|-wal|\.owner)?$/;

// Anything under the data volume that a backup would capture and a
// reader could open. The volume is allowed to hold sealed material and
// nothing else.
function plaintextDatabasesUnder(dir) {
  var found = [];
  (function walk(here) {
    var entries;
    try { entries = fs.readdirSync(here, { withFileTypes: true }); } catch (_e) { return; }
    entries.forEach(function (entry) {
      var full = path.join(here, entry.name);
      if (entry.isDirectory()) { walk(full); return; }
      if (WORKING_COPY.test(entry.name)) found.push(full);
    });
  })(dir);
  return found;
}

// The two questions this file answers, printed as the unit examined: a
// run that only drove the refusal and a run that drove both otherwise
// report the same check total and neither says which happened.
var RESIDENCY_QUESTIONS_EXAMINED = 2;

function freshVolume(prefix) {
  var root    = helpers.tempDir(prefix);
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  return { root: root, dataDir: dataDir, workDir: workDir };
}

// ---------------------------------------------------------------------------

// With nowhere named and nothing mounted, an operator's command has to
// stop rather than decrypt onto disk. Driven as a spawned command,
// because the question is what an operator meets: a refusal raised inside
// a handle nobody reached is not the same guarantee.
function withNowhereToDecryptTheCommandRefuses(volume) {
  var run = cliHelper.create({
    dataDir:  volume.dataDir,
    workDir:  volume.workDir,
    hostname: HOSTNAME,
    // Emptied rather than absent: the helper sets this for every other
    // file, and an empty value is what an operator who unset it in a unit
    // file arrives with.
    env:      { BLAMEJS_TMPDIR: "" },
  });
  var result = run(["account", "list"]);

  count("a command that has to read the volume refuses rather than opening it",
    result.status !== 0, "exit " + result.status + ": " + result.both);
  count("and says the copy would have to be memory backed",
    /memory backed/.test(result.both), result.both);
  count("and names the variable that fixes it",
    result.both.indexOf("BLAMEJS_TMPDIR") !== -1, result.both);

  // Which of the two branches answered. On Linux the refusal names the
  // mount; elsewhere it names the platform. Asserting the wording holds
  // either way keeps this file honest about what it covered.
  var namedLinuxMount = /\/dev\/shm is not a tmpfs mount/.test(result.both);
  var namedPlatform   = /which has no tmpfs/.test(result.both);
  count("the refusal says which branch reached it, rather than a general sentence",
    namedLinuxMount || namedPlatform,
    "platform " + process.platform + ": " + result.both);

  // The point of the refusal. A run that refused and wrote a copy anyway
  // would satisfy every check above.
  var leaked = plaintextDatabasesUnder(volume.root);
  count("and no decrypted copy was written anywhere while refusing",
    leaked.length === 0, leaked.join(", "));
}

// With a directory named, the operator is taken at their word, and the
// copy has to be in that directory and nowhere else. In process, because
// the copy is removed when the handle closes and a spawned run has
// already cleaned up by the time anything could look.
async function aNamedDirectoryHoldsTheCopyAndTheVolumeHoldsNone(volume) {
  var saved = {
    hostname:   process.env.BLAMEPOST_HOSTNAME,
    dataDir:    process.env.BLAMEPOST_DATA_DIR,
    passphrase: process.env.BLAMEPOST_VAULT_PASSPHRASE,
    tmpDir:     process.env.BLAMEJS_TMPDIR,
  };
  var handle = null;
  try {
    process.env.BLAMEPOST_HOSTNAME         = HOSTNAME;
    process.env.BLAMEPOST_DATA_DIR         = volume.dataDir;
    process.env.BLAMEPOST_VAULT_PASSPHRASE = VAULT_PASSPHRASE;
    process.env.BLAMEJS_TMPDIR             = volume.workDir;

    handle = await store.open(configMod.load());
    count("a named directory opens the volume", handle !== null &&
      handle !== undefined);

    var inWork = fs.readdirSync(volume.workDir).filter(function (name) {
      return WORKING_COPY.test(name);
    });
    count("the decrypted copy is in the directory the operator named",
      inWork.length > 0, JSON.stringify(fs.readdirSync(volume.workDir)));

    // The security property, and the reason the refusal above exists: a
    // backup of the data volume captures nothing a reader can open.
    var inVolume = plaintextDatabasesUnder(volume.dataDir);
    count("and the data volume holds no decrypted copy while the store is open",
      inVolume.length === 0, inVolume.join(", "));

    await handle.close();
    handle = null;

    var leftBehind = fs.readdirSync(volume.workDir).filter(function (name) {
      return WORKING_COPY.test(name);
    });
    count("and the copy does not outlive the handle that needed it",
      leftBehind.length === 0, leftBehind.join(", "));
  } finally {
    if (handle !== null) { try { await handle.close(); } catch (_e) { /* already reported */ } }
    Object.keys(saved).forEach(function (key) {
      var name = { hostname: "BLAMEPOST_HOSTNAME", dataDir: "BLAMEPOST_DATA_DIR",
        passphrase: "BLAMEPOST_VAULT_PASSPHRASE", tmpDir: "BLAMEJS_TMPDIR" }[key];
      if (saved[key] === undefined) delete process.env[name];
      else process.env[name] = saved[key];
    });
  }
}

// ---------------------------------------------------------------------------

async function run() {
  var volumes = [];
  function fresh(prefix) {
    var volume = freshVolume(prefix);
    volumes.push(volume);
    return volume;
  }
  try {
    await helpers.withTestTimeout(
      "working copy: with nowhere to decrypt, the command refuses",
      function () { return withNowhereToDecryptTheCommandRefuses(fresh("wc-refuse")); });
    await helpers.withTestTimeout(
      "working copy: a named directory holds the copy and the volume holds none",
      function () {
        return aNamedDirectoryHoldsTheCopyAndTheVolumeHoldsNone(fresh("wc-named"));
      });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < volumes.length; i += 1) helpers.removeTempDir(volumes[i].root);
  }
}

module.exports = {
  name:      "store-working-copy-residency",
  run:       run,
  getChecks: helpers.getChecks,
  NO_MOUNT:  NO_MOUNT,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// question and a run that drove both otherwise report the same total.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + RESIDENCY_QUESTIONS_EXAMINED + " residency-question");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
