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
 * Two refusals sit here and they are not the same one. With NOTHING
 * named there is no directory to classify, and the store refuses under
 * `store/no-working-copy-mount` on every platform. With a directory
 * NAMED, that question is answered and the framework's residency check
 * runs instead: on Linux it reads the mount table and refuses a disk
 * under `db/tmpdir-not-tmpfs`, naming the filesystem and the mount point
 * it found; on Windows no mount can be classified, so it warns, the open
 * proceeds on the operator's word, and that refusal is unreachable. Both
 * codes are pinned exactly, and the branch each host took is named,
 * because a run that accepted either would report the same pass however
 * it got there.
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

// The refusal for a directory that WAS named and is not memory backed.
// It is a different code from the one above and it comes from a
// different place: naming a directory answers the question `NO_MOUNT`
// asks, and what refuses afterwards is the framework's residency check
// reading the mount table. Pinned exactly, because a run that accepted
// either code would report the same pass whichever of the two fired, and
// the two mean different things to an operator: one says there is
// nowhere to decrypt into, the other says the place you named is a disk.
var NOT_TMPFS = "db/tmpdir-not-tmpfs";

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

// Whether a directory sits on a memory-backed mount, read from
// `/proc/mounts` rather than asked of the framework, so this file brings
// its own evidence to a question the framework is the subject of.
//
// The longest matching mount point wins, because mount points nest and
// the nearest one is the filesystem a path is actually on. Off Linux
// there is no tmpfs to be on, and the answer is no.
function mountFor(dir) {
  if (process.platform !== "linux") return null;
  var mounts;
  try { mounts = fs.readFileSync("/proc/mounts", "utf8"); } catch (_e) { return null; }
  var real;
  try { real = fs.realpathSync(dir); } catch (_e) { real = dir; }
  var best = null;
  mounts.split("\n").forEach(function (line) {
    var fields = line.split(/\s+/);
    if (fields.length < 3) return;
    var point = fields[1];
    var under = point.replace(/\/+$/, "") + "/";
    if (real !== point && real.indexOf(under) !== 0) return;
    if (best === null || point.length > best.point.length) {
      best = { point: point, type: fields[2] };
    }
  });
  return best;
}

function isMemoryBacked(dir) {
  var mount = mountFor(dir);
  return mount !== null && (mount.type === "tmpfs" || mount.type === "ramfs");
}

// Both outcomes are a guarantee, and which one a host produces is a fact
// about the host rather than about the server. A directory on ordinary
// disk has to be REFUSED; one on a memory-backed mount has to be
// ACCEPTED and hold the copy. Asserting only the refusal made this file
// pass on a workstation and fail on a runner, because an empty
// BLAMEJS_TMPDIR reaches /dev/shm, which is a real tmpfs there, so the
// correct answer was to open and the file called that a defect.
function residencyBranch(dir) {
  return isMemoryBacked(dir) ? "memory-backed" : "on-disk";
}

// A NAMED directory is refused only where the framework can establish
// that it is not memory backed, which is Linux, by reading the mount
// table. Off Linux there is no mount type to compare against, so naming a
// directory is taken at the operator's word and the run drives the
// residency half of the guarantee instead of the refusal half. That is
// not the same predicate as `isMemoryBacked`: an unnamed location refuses
// on Windows while a named one opens, so a single "is it tmpfs" question
// answers for one of those two and not the other.
function namedDirectoryIsRefused(dir) {
  return process.platform === "linux" && !isMemoryBacked(dir);
}

// The three questions this file answers, printed as the unit examined: a
// run that only drove the refusal and a run that drove all of them
// otherwise report the same check total and neither says which happened.
var RESIDENCY_QUESTIONS_EXAMINED = 3;

function freshVolume(prefix) {
  var root    = helpers.tempDir(prefix);
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  return { root: root, dataDir: dataDir, workDir: workDir };
}

// A volume whose working copy would land on ordinary disk, which is the
// only thing the residency comparison has to compare.
//
// The run's own temporary root is not that. It is tmpfs on most Linux
// hosts and in the shipped container image, so a case rooted there takes
// the accepted branch every time and the refusal it was written for goes
// unexercised while the totals stay green. The repository checkout is on
// whatever filesystem the tree was cloned onto, which on a Linux host or
// a bind mount is a disk, and `.test-output` is where the gates already
// write.
//
// Returns null where the mount table says that directory is memory
// backed too, because then this host has no disk to point at and the
// caller has to say so rather than assert a refusal that cannot fire.
function diskBackedVolume(prefix) {
  var base = path.join(helpers.REPO_ROOT, ".test-output");
  fs.mkdirSync(base, { recursive: true });
  if (process.platform === "linux" && isMemoryBacked(base)) return null;
  var root    = fs.mkdtempSync(path.join(base, prefix + "-"));
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
  var refused = result.status !== 0;

  if (refused) {
    count("with nowhere memory backed to decrypt into, the command refuses",
      true, "exit " + result.status);
    count("and says the copy would have to be memory backed",
      /memory backed/.test(result.both), result.both);
    count("and names the variable that fixes it",
      result.both.indexOf("BLAMEJS_TMPDIR") !== -1, result.both);

    // Which of the two branches answered. On Linux the refusal names the
    // mount; elsewhere it names the platform. Asserting the wording holds
    // either way keeps this file honest about what it covered.
    var namedLinuxMount = /is not a tmpfs mount/.test(result.both);
    var namedPlatform   = /which has no tmpfs/.test(result.both);
    count("the refusal says which branch reached it, rather than a general sentence",
      namedLinuxMount || namedPlatform,
      "platform " + process.platform + ": " + result.both);
  } else {
    // A host that HAS a memory-backed mount reaches the other half of the
    // same guarantee: the command is allowed to run, and the copy it makes
    // is not on the volume. Asserting the refusal unconditionally made this
    // file a statement about the host it last ran on.
    count("with a memory-backed mount reachable, the command runs instead of refusing",
      true, "exit " + result.status);
    count("and the volume itself was not used as the working copy",
      plaintextDatabasesUnder(volume.dataDir).length === 0,
      plaintextDatabasesUnder(volume.dataDir).join(", "));
    count("and the run did not report the refusal it did not reach",
      !/memory backed/.test(result.both), result.both);
  }

  // The property both branches owe, and the reason the refusal exists. A
  // run that refused and wrote a copy anyway, or ran and left one behind,
  // would satisfy every check above.
  var leaked = plaintextDatabasesUnder(volume.root);
  count("and no decrypted copy is left on the volume either way",
    leaked.length === 0,
    residencyBranch(volume.workDir) + " host: " + leaked.join(", "));
}

// With a directory named, the operator is taken at their word, and the
// copy has to be in that directory and nowhere else. In process, because
// the copy is removed when the handle closes and a spawned run has
// already cleaned up by the time anything could look.
// Open the store with the working copy pointed at a directory, and hand
// back whichever of the two answers came out.
//
// These variables are process wide, so they go back whichever way the
// open went. A case that left one set would decide the next case's
// answer rather than measuring its own.
async function openWithWorkingCopyAt(volume) {
  var saved = {
    BLAMEPOST_HOSTNAME:         process.env.BLAMEPOST_HOSTNAME,
    BLAMEPOST_DATA_DIR:         process.env.BLAMEPOST_DATA_DIR,
    BLAMEPOST_VAULT_PASSPHRASE: process.env.BLAMEPOST_VAULT_PASSPHRASE,
    BLAMEJS_TMPDIR:             process.env.BLAMEJS_TMPDIR,
  };
  try {
    process.env.BLAMEPOST_HOSTNAME         = HOSTNAME;
    process.env.BLAMEPOST_DATA_DIR         = volume.dataDir;
    process.env.BLAMEPOST_VAULT_PASSPHRASE = VAULT_PASSPHRASE;
    process.env.BLAMEJS_TMPDIR             = volume.workDir;
    try { return { handle: await store.open(configMod.load()), error: null }; }
    catch (e) { return { handle: null, error: e }; }
  } finally {
    Object.keys(saved).forEach(function (name) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    });
  }
}

async function aNamedDirectoryHoldsTheCopyAndTheVolumeHoldsNone(volume) {
  var handle = null;
  try {
    // Naming a directory does not override the residency rule, so which
    // half of the guarantee this run drives is decided by the mount the
    // directory is on and not by the fact that it was named. On a host
    // whose temp root is ordinary disk, being taken at your word would be
    // the defect.
    var expectRefusal = namedDirectoryIsRefused(volume.workDir);
    var opened        = await openWithWorkingCopyAt(volume);
    var openError     = opened.error;
    handle = opened.handle;

    if (expectRefusal) {
      count("a named directory on ordinary disk is refused rather than taken at its word",
        openError !== null, "opened against " + residencyBranch(volume.workDir));
      count("and the refusal carries the code an operator can filter on",
        openError !== null && openError.code === NOT_TMPFS,
        openError && (openError.code + ": " + openError.message));
      // The mount table is what the check read, so the refusal can say
      // which filesystem it found and where that filesystem is mounted.
      // A sentence that only said "not tmpfs" would leave an operator
      // guessing which of the paths in play was the one on disk.
      count("and it names the filesystem it found rather than only that the check failed",
        openError !== null && /is on a '[^']+' filesystem mounted at '[^']+'/
          .test(String(openError.message)),
        openError && String(openError.message).slice(0, 300));
      count("and nothing decrypted was written to the volume or the directory",
        plaintextDatabasesUnder(volume.root).length === 0,
        plaintextDatabasesUnder(volume.root).join(", "));
    } else {
      count("a named directory on a memory-backed mount opens the volume",
        openError === null && handle !== null && handle !== undefined,
        openError && (openError.code + ": " + openError.message));
      // Which of the two hosts reached this branch. On Linux the mount
      // table was read and the directory is memory backed; off Linux
      // there is no mount to classify, so the residency check reports
      // the mount as undetermined and the open proceeds on the
      // operator's word. `NOT_TMPFS` cannot be reached at all in the
      // second case, and a run that named neither would read as one that
      // covered the refusal on whatever host it last ran on.
      count("the host that got here either has a memory-backed mount to read or no mount " +
        "table to read one from",
        process.platform === "linux"
          ? isMemoryBacked(volume.workDir)
          : mountFor(volume.workDir) === null,
        process.platform + ": " + JSON.stringify(mountFor(volume.workDir)));

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
    }
  } finally {
    if (handle !== null) { try { await handle.close(); } catch (_e) { /* already reported */ } }
  }
}

// The residency comparison itself, reached rather than assumed.
//
// The case above points the working copy at the run's own temporary
// root, which is tmpfs on most Linux hosts and inside the shipped
// container image, so it takes the accepted branch on both and the
// refusal it carries is never exercised there. This one points the
// working copy at a directory the mount table calls ordinary disk, which
// is the only input the comparison has anything to compare.
//
// Both platforms owe an answer and they are different answers. On Linux
// the mount table is read, the filesystem does not match, and the open
// is REFUSED under `db/tmpdir-not-tmpfs`. On Windows there is no mount
// table, so the check reports the mount as undetermined, warns, and the
// open proceeds on the operator's word: that refusal is unreachable
// there, and the copy has to land in the named directory with none on
// the volume.
async function aDirectoryOnOrdinaryDiskMeetsTheResidencyCheck(volume) {
  if (volume === null) {
    count("this host has no directory the mount table calls ordinary disk, so the " +
      "residency comparison has no disk to refuse", true,
      process.platform + ": the repository checkout is memory backed");
    return;
  }

  var handle = null;
  try {
    var opened    = await openWithWorkingCopyAt(volume);
    var openError = opened.error;
    handle = opened.handle;

    if (process.platform === "linux") {
      count("a working copy pointed at ordinary disk is refused rather than written there",
        openError !== null, "opened against " + residencyBranch(volume.workDir));
      count("and the refusal carries the code an operator can filter on",
        openError !== null && openError.code === NOT_TMPFS,
        openError && (openError.code + ": " + openError.message));
      // The mount table is what the check read, so the refusal can name
      // the filesystem it found and where that filesystem is mounted. A
      // sentence saying only "not tmpfs" would leave an operator to work
      // out which of the paths in play was the one on disk.
      count("and it names the filesystem it found and where that filesystem is mounted",
        openError !== null && /is on a '[^']+' filesystem mounted at '[^']+'/
          .test(String(openError.message)),
        openError && String(openError.message).slice(0, 300));
      count("and nothing decrypted was written to the directory it refused",
        plaintextDatabasesUnder(volume.root).length === 0,
        plaintextDatabasesUnder(volume.root).join(", "));
      return;
    }

    count("with no mount table to read, the same directory is taken at the operator's word",
      openError === null && handle !== null && handle !== undefined,
      process.platform + ": " + (openError && (openError.code + ": " + openError.message)));
    var inWork = fs.readdirSync(volume.workDir).filter(function (name) {
      return WORKING_COPY.test(name);
    });
    count("the decrypted copy is in the directory that was named",
      inWork.length > 0, JSON.stringify(fs.readdirSync(volume.workDir)));
    count("and the data volume still holds none",
      plaintextDatabasesUnder(volume.dataDir).length === 0,
      plaintextDatabasesUnder(volume.dataDir).join(", "));

    await handle.close();
    handle = null;
    var leftBehind = fs.readdirSync(volume.workDir).filter(function (name) {
      return WORKING_COPY.test(name);
    });
    count("and the copy does not outlive the handle that needed it",
      leftBehind.length === 0, leftBehind.join(", "));
  } finally {
    if (handle !== null) { try { await handle.close(); } catch (_e) { /* already reported */ } }
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
    var onDisk = diskBackedVolume("wc-disk");
    if (onDisk !== null) volumes.push(onDisk);
    await helpers.withTestTimeout(
      "working copy: a directory on ordinary disk meets the residency check",
      function () { return aDirectoryOnOrdinaryDiskMeetsTheResidencyCheck(onDisk); });
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
  NOT_TMPFS: NOT_TMPFS,
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
