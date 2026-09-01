// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a second WRITER does to a mail server that is already running.
 *
 * The database is encrypted at rest, so opening it for writing is not a
 * read. The framework decrypts the whole file into a working copy of its
 * own on a memory backed directory, serves every query from that copy,
 * and writes the copy back over the encrypted file on a timer and again
 * at shutdown. That design is sound for one writer and destructive for
 * two, and nothing in the shape of a command tells an operator which
 * they are about to be.
 *
 * The two writers cannot see each other's work. Each holds a separate
 * decrypted copy, and each writes the whole volume back, so whichever
 * writes last replaces the other's copy entirely: every message the
 * loser accepted since it started is gone, and the window is not bounded
 * by how long either process ran. What is left on disk is one process's
 * view of the volume, internally consistent and simply missing the
 * other's mail, so nothing downstream reports it either.
 *
 * The verbs that reach this are not the ones an operator would guard.
 * `audit read` and `account sieve` read and report; neither changes
 * anything an operator asked to change. What sends them here is that
 * each is recorded as it runs, and leaving that row is a write.
 *
 * So the claim under test is that the volume has exactly one writer at a
 * time, and that a second one is refused rather than served. The refusal
 * happens before the database is touched, it names the process that
 * holds the volume, and it exits non zero.
 *
 * The verbs that only report now answer while the server runs, from a
 * read-only open of the same volume. That is a different claim with its
 * own case in `store-snapshot-reporting`, and it does not weaken this
 * one: a reader takes no lock, writes nothing back, and so has nothing
 * to lose the race with. What is left here is every verb that still has
 * to write to do its job, and the proof that a second writer is refused.
 *
 * Everything here spawns the real binary. The status comes from the
 * spawn, never from a pipeline, because a pipeline reports the last
 * command's status and would make a correct refusal read as success.
 * The spawned process and this one share BLAMEJS_TMPDIR, which is what
 * the container shares as /dev/shm between the server and anything
 * reached with `docker exec`.
 *
 * Run standalone: node test/layer-1-state/store-single-opener.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// The verbs that report and still have to open the volume for WRITING
// to do it, so the refusal is what an operator meets.
//
// Both are recorded as they run: `audit read` leaves a row saying the
// trail was read, and `account sieve` leaves one saying an administrator
// opened somebody's filter scripts. That row is a write, so a read-only
// open cannot make it, and a read that claims to be recorded and is not
// is worse than a read that refuses. Both report rather than change,
// which is the point: what disqualifies a verb is needing to write on
// the way to its answer, never how the command sounds.
var REPORTING_VERBS = [
  ["audit", "read"],
  ["account", "sieve", ADDRESS, "--reason", "checking a delivery complaint"],
];

// A verb that reads the outbound spool off disk and never opens the
// database. It is the control on the rule: the guard is about the
// volume, not about how a command sounds, so a command that genuinely
// touches nothing has to keep answering while the server runs. A guard
// that refused this one would be a guard nobody could work around
// except by stopping the server, which is the posture this exists to
// avoid.
var VERB_THAT_NEVER_OPENS_THE_VOLUME = ["queue", "list"];

// Verbs that change something, so the refusal is not read as a rule
// about read-only commands. It is a rule about opening the volume.
//
// `blobs reclaim` is here for a second reason. It re-reads the message
// rows immediately before removing a body, which closes the window
// against anything appending inside this process, because the walk, the
// re-read and the unlink are one synchronous run that nothing can
// interleave with. Across two processes that argument does not hold: a
// delivery landing in the running server between this process's re-read
// and its unlink leaves a row naming a body that has just been removed,
// which is a message that exists and cannot be read. Refusing the
// second opener is what closes it, rather than narrowing the window
// again.
var MUTATING_VERBS = [
  ["domain", "add", "second.example"],
  ["blobs", "reclaim", "--confirm", "--reason", "clearing stranded octets"],
];

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

// The encrypted volume as a digest, so "was it written" is a fact about
// bytes rather than about a timestamp a filesystem may round.
function encryptedVolumeDigest(dataDir) {
  var encPath = nodePath.join(dataDir, "db.enc");
  if (!nodeFs.existsSync(encPath)) return "<absent>";
  return nodeCrypto.createHash("sha512").update(nodeFs.readFileSync(encPath)).digest("hex");
}

// The working copies on the shared memory backed directory. The running
// server's copy is one of these, and each carries a record naming the
// process it belongs to, so a copy is never reclaimed on the strength of
// its name alone. The count is what says a refused command decrypted
// nothing of its own.
function workingCopies(workDir) {
  try {
    return nodeFs.readdirSync(workDir)
      .filter(function (name) { return name.indexOf("blamejs-") === 0 && /\.db$/.test(name); })
      .sort();
  } catch (_e) { return []; }
}

// ---- cases -----------------------------------------------------------------

// Every reporting verb, run against a volume another process holds
// open. The refusal has to name what holds it, because an operator who
// is told only "busy" has nothing to act on.
function aSecondOpenerIsRefused(cli) {
  var all = REPORTING_VERBS.concat(MUTATING_VERBS);
  for (var i = 0; i < all.length; i += 1) {
    var verb = all[i];
    var label = verb.join(" ");
    var result = cli(verb);
    count("`" + label + "` is refused while another process holds the volume",
      result.status !== 0, "exit " + result.status + " " + result.both.slice(0, 200));
    count("`" + label + "` says the volume is already open",
      /already open|another process|single opener|store\/volume-in-use/i.test(result.both),
      result.both.slice(0, 300));
    count("`" + label + "` names the process holding it",
      /\b\d{2,}\b/.test(result.both), result.both.slice(0, 300));
  }

  var spool = cli(VERB_THAT_NEVER_OPENS_THE_VOLUME);
  count("`" + VERB_THAT_NEVER_OPENS_THE_VOLUME.join(" ") +
    "` still answers, because it never opens the volume",
    spool.status === 0, "exit " + spool.status + " " + spool.both.slice(0, 200));
}

// The refusal is worth nothing if the refused process still wrote. This
// is the assertion that fails loudest on the shipped container, where
// the second open removes the server's working copy before anything
// else happens.
function theVolumeIsUntouched(before, after, copiesBefore, copiesAfter) {
  count("the encrypted volume is byte identical after every refused verb",
    before === after, "before " + before.slice(0, 24) + " after " + after.slice(0, 24));
  count("the running server's working copy is still where it was",
    copiesBefore.length > 0 && copiesBefore.every(function (name) {
      return copiesAfter.indexOf(name) !== -1;
    }), "before " + JSON.stringify(copiesBefore) + " after " + JSON.stringify(copiesAfter));
}

// The operator visible consequence. Mail that arrived before the verb
// ran and mail that arrived after it ran are both still there once the
// server has been restarted, which is the only moment the loss would
// otherwise become visible.
async function noMailIsLostAcrossTheVerb(cfg, accountId, expected) {
  var handle = await store.open(cfg);
  try {
    var selected = handle.mailbox.selectFolder({ id: accountId }, "INBOX", {});
    count("every message delivered around the refused verb survived the restart",
      selected.exists === expected,
      "found " + selected.exists + " of " + expected);
    var rows = b.db.from("blamepost_mailbox_messages").all();
    count("and the rows carrying them are the same count",
      rows.length === expected, "rows " + rows.length + " of " + expected);
  } finally {
    handle.close();
  }
}

// The guard is a single opener rule, not a refusal to work. With the
// volume closed the same verbs answer normally, so an operator who has
// stopped the server is not locked out of their own data.
function theVerbsWorkWhenNothingHoldsTheVolume(cli) {
  var listed = cli(["account", "list"]);
  count("`account list` answers once the volume is free",
    listed.status === 0, "exit " + listed.status + " " + listed.both.slice(0, 200));
  count("and it answers with the account that is there",
    listed.both.indexOf(ADDRESS) !== -1, listed.both.slice(0, 200));
}

// A lock left behind by a process that is gone must not outlive it. An
// operator whose server was killed has no way to hand the lock back,
// so a stale one that refuses forever is an outage this guard caused.
function aLockLeftByADeadProcessIsReaped(cli, dataDir) {
  var lockPath = nodePath.join(dataDir, "blamepost.lock");
  // A PID that is not running. High numbers above the system maximum are
  // never allocated, so this names nothing on any platform.
  nodeFs.writeFileSync(lockPath, "4294967294\n");
  // A verb with nowhere else to go. One that can answer from a private
  // copy would exit zero whether the lock was reaped or not, so it would
  // report this as working on the day reaping stopped.
  var verified = cli(["audit", "verify-chain"]);
  count("a lock naming a process that is gone does not lock the operator out",
    verified.status === 0, "exit " + verified.status + " " + verified.both.slice(0, 240));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("single-opener");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The same memory backed directory for this process and every process
  // it spawns. In the container that sharing is /dev/shm and it is not
  // optional, so a case that gave each process its own would be testing
  // a deployment nobody runs.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;

  try {
    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    // The volume as an operator creates it, through the binary.
    var seeded = await store.open(cfg);
    await seeded.domains.add({ domain: DOMAIN });
    var alice = await seeded.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
    var accountId = alice.id;
    seeded.mailbox.appendMessage("INBOX", message("before the operator looked"), {
      actor: { id: accountId },
    });
    seeded.close();

    // The server: one process, holding the volume for as long as it
    // serves. Mail arrives, and a flush lands the way the periodic one
    // does, so the encrypted volume is current before the verb runs.
    identity = await store.open(cfg);
    identity.mailbox.appendMessage("INBOX", message("while the server was up"), {
      actor: { id: accountId },
    });
    b.db.flushToDisk();

    var digestBefore = encryptedVolumeDigest(dataDir);
    var copiesBefore = workingCopies(workDir);

    aSecondOpenerIsRefused(cli);

    theVolumeIsUntouched(digestBefore, encryptedVolumeDigest(dataDir),
      copiesBefore, workingCopies(workDir));

    // Mail keeps arriving after the operator has been and gone. This is
    // the message the shipped container loses, because by now the
    // server's flush has nothing left to write to.
    identity.mailbox.appendMessage("INBOX", message("after the operator looked"), {
      actor: { id: accountId },
    });

    identity.close();
    identity = null;

    await noMailIsLostAcrossTheVerb(cfg, accountId, 3);

    theVerbsWorkWhenNothingHoldsTheVolume(cli);
    aLockLeftByADeadProcessIsReaped(cli, dataDir);

    return helpers.getChecks();
  } finally {
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "store-single-opener", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
