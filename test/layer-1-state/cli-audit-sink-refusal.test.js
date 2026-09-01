// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a command-line verb tells the operator when the audit sink cannot
 * write.
 *
 * The store side of this question is settled in
 * `audit-sink-refusal.test.js`: a verb performs its change and then
 * records it, the change is on disk by the time the second write runs,
 * and letting the sink's error out hands the caller a refusal for an
 * operation that succeeded. The command line has the same two writes and
 * one thing the store does not, which is why it is measured separately:
 * an exit status. A shell reads that status, a runbook branches on it,
 * and a scheduled run treats it as the whole answer.
 *
 * Two verbs make the consequence concrete rather than theoretical.
 *
 * `restore apply` puts the bundle in place, opens the volume it just
 * wrote, verifies the chain and then records what it found. The recording
 * ran inside the same guard as the opening, so a sink refusal read as a
 * volume that would not open, and the verb did what that state calls for:
 * it rolled the restore back and exited non-zero. An operator restoring
 * after an outage got their restore undone because the audit sink was
 * down.
 *
 * `queue remove` erases a message and tells the sender nothing, which is
 * the point of the verb. It reported the sink's refusal for a message
 * that was already gone, so an operator cancelling mail a stolen
 * credential sent read "the audit sink is unavailable" and had no way to
 * tell that from the message still sitting in the spool.
 *
 * The fault arrives through `b.audit.useStore` in the mode where a store
 * failure reaches whoever called `record`, loaded into the spawned
 * process ahead of the binary. That is the framework's own seam and it
 * refuses every event, so no verb here is running against a sink that was
 * never in its way. `test/helpers/audit-sink-fault.js` holds it, and each
 * refused event is written to a file this run reads back afterwards:
 * a verb that quietly stopped emitting would otherwise satisfy every
 * check below without the sink ever being reached.
 *
 * Everything spawns the real binary. The status comes from the spawn and
 * never from a pipeline, because a pipeline reports the last command's
 * status and a correct refusal would read as silent success.
 *
 * Run standalone: node test/layer-1-state/cli-audit-sink-refusal.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var fault     = require("../helpers/audit-sink-fault");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var SPARE    = "example.net";
var ADDRESS  = "alice@" + DOMAIN;

var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var BUNDLE_PASSPHRASE = "a different passphrase that only the bundle uses";
var ALICE_PASSWORD    = "quiet lantern bicycle 4291";

// The rows the verbs in this run write. Named rather than counted: a
// total says how many were attempted and not which, so a verb that
// stopped emitting keeps the total whole as long as another emitted
// twice.
var COMMAND_LINE_ACTIONS = [
  "account.sieve_read",
  "blamepost.mail.queue.message_removed",
  "blamepost.audit.purged",
  "blamepost.backup.written",
  "blamepost.backup.purged",
  "blamepost.restore.applied",
  "blamepost.restore.rolled_back",
];

// A spooled outbound message, written the way the delivery composer
// writes one: a JSON descriptor beside the RFC 822 body, both named for
// the entry's id. The id is minted the way the spool mints its own,
// because an id outside that alphabet is refused before the removal
// looks for the message and would exercise the shape check instead.
var SPOOL_ID = b.crypto.generateToken(12);

function parseJson(text) {
  try { return JSON.parse(text); } catch (_e) { return null; }
}

// ---- the run's own state ------------------------------------------------------

async function seedSpool(dataDir) {
  var spoolDir = nodePath.join(dataDir, "queue");
  b.atomicFile.ensureDir(spoolDir, 0o700);
  await b.atomicFile.write(nodePath.join(spoolDir, SPOOL_ID + ".eml"),
    "From: " + ADDRESS + "\r\n" +
    "To: victim@" + SPARE + "\r\n" +
    "Subject: sent while the credential was stolen\r\n" +
    "\r\n" +
    "body\r\n", { fileMode: 0o600 });
  await b.atomicFile.writeJson(nodePath.join(spoolDir, SPOOL_ID + ".json"), {
    id:            SPOOL_ID,
    from:          ADDRESS,
    recipient:     "victim@" + SPARE,
    attempt:       1,
    nextAttemptAt: Date.now() + 60000,
    reason:        "451 4.7.1 try again later",
    reasonCode:    "4.7.1",
    requireTls:    false,
    queuedAt:      Date.now(),
  }, { fileMode: 0o600 });
}

function spoolFilesPresent(dataDir) {
  var spoolDir = nodePath.join(dataDir, "queue");
  return nodeFs.existsSync(nodePath.join(spoolDir, SPOOL_ID + ".json")) ||
    nodeFs.existsSync(nodePath.join(spoolDir, SPOOL_ID + ".eml"));
}

// ---- the shared assertions ----------------------------------------------------

// Whether a transcript carries the sink's refusal. Checked on both
// streams and by the sink's own words, because the claim is not that the
// verb exited zero but that the operator was never handed an error about
// a sink they did not ask about.
function saysTheSinkRefused(outcome) {
  return outcome.both.indexOf(fault.REFUSAL) !== -1;
}

// The one assertion every verb here makes. A verb that performed its
// change reports its own outcome and exits on its own result; an
// operator who reads the sink's refusal instead cannot tell a change
// that did not happen from one that did.
function reportsItsOwnOutcome(label, outcome) {
  count(label + " reports its own outcome rather than the audit sink's error",
    outcome.status === 0 && !saysTheSinkRefused(outcome),
    "exit " + outcome.status + " " + outcome.both.slice(0, 400));
  return outcome;
}

// ---- the verbs ----------------------------------------------------------------

function readingAFilterScript(broken) {
  var read = reportsItsOwnOutcome("`account sieve`",
    broken(["account", "sieve", ADDRESS, "--reason", "abuse report 4471"]));
  // The emit sits before the read, so a sink refusal that escaped took
  // the answer with it: the operator was told about a sink and never
  // told what the account filters.
  count("and the operator gets the answer they asked for, which the emit sits in front of",
    /filter scripts/.test(read.stdout), read.stdout.slice(0, 300));
}

function abandoningAQueuedMessage(broken, dataDir) {
  var gone = reportsItsOwnOutcome("`queue remove`",
    broken(["queue", "remove", SPOOL_ID, "--reason", "cancelling mail a stolen credential sent"]));
  count("and says which message it abandoned",
    gone.stdout.indexOf(SPOOL_ID) !== -1, gone.stdout.slice(0, 300));
  count("and the message really is off the spool, so the report was not the optimistic one",
    !spoolFilesPresent(dataDir), "spool files still present");
}

function purgingTheAuditTrail(broken, archiveOut, passFile) {
  var purged = reportsItsOwnOutcome("`audit purge`",
    broken(["audit", "purge", "--archive", archiveOut, "--passphrase-file", passFile,
      "--confirm", "--reason", "quarterly retention run", "--json"]));
  var result = parseJson(purged.stdout);
  count("and reports how many rows it deleted, which is the only account of a " +
    "deletion the trail cannot describe itself",
    result !== null && result.rowsDeleted > 0, purged.stdout.slice(0, 300));
}

function takingAndSweepingBundles(broken, storageDir, passFile, firstBundleId) {
  var written = reportsItsOwnOutcome("`backup run`",
    broken(["backup", "run", "--storage", storageDir, "--passphrase-file", passFile, "--json"]));
  var summary = parseJson(written.stdout);
  count("and reports the bundle it wrote and that the manifest is signed",
    summary !== null && typeof summary.bundleId === "string" &&
    summary.signature && summary.signature.ok === true,
    written.stdout.slice(0, 300));

  var swept = reportsItsOwnOutcome("`backup purge`",
    broken(["backup", "purge", "--storage", storageDir, "--passphrase-file", passFile,
      "--keep", "1", "--confirm", "--reason", "quarterly retention run"]));
  // Both halves. The line has to name what it deleted, and the bundle it
  // named has to be off storage, because a sweep that reported a deletion
  // it did not perform is the other way this verb can lie.
  var remaining = nodeFs.existsSync(storageDir) ? nodeFs.readdirSync(storageDir) : [];
  count("and the sweep names the older bundle it deleted, which is off storage now",
    swept.stdout.indexOf(firstBundleId) !== -1 &&
    !remaining.some(function (name) { return name.indexOf(firstBundleId) !== -1; }),
    swept.stdout.slice(0, 200) + " | left: " + JSON.stringify(remaining));

  return summary === null ? null : summary.bundleId;
}

// The verb this file exists for. A restore that landed, opened and
// verified is a restore that must stay in place; undoing it because the
// row describing it could not be written is the audit sink deciding what
// happens to the operator's data.
function restoringABundle(broken, storageDir, passFile, bundleId) {
  var applied = reportsItsOwnOutcome("`restore apply`",
    broken(["restore", "apply", "--storage", storageDir, "--bundle", bundleId,
      "--passphrase-file", passFile, "--confirm",
      "--reason", "restoring after the sink went down", "--json"]));

  var report = parseJson(applied.stdout);
  count("and the restore is still in place rather than rolled back, because a row that " +
    "could not be written is not a volume that could not be opened",
    report !== null && report.ok === true && report.verified === true &&
    report.bundleId === bundleId,
    applied.stdout.slice(0, 400));
  count("and it kept the directory it replaced, so the operator still has a way back",
    report !== null && typeof report.rollbackPath === "string" && report.rollbackPath.length > 0,
    JSON.stringify(report && report.rollbackPath));

  // Silence is the wrong answer here and so is a refusal. The volume an
  // operator just replaced has no entry for the replacement, and they
  // are standing at a terminal where one line costs nothing.
  count("and the operator is told the volume was restored and the trail did not record it",
    /restor/i.test(applied.stderr) && /audit/i.test(applied.stderr),
    JSON.stringify(applied.stderr.slice(0, 400)));

  return report;
}

function rollingBackAgain(broken, report) {
  var rolled = reportsItsOwnOutcome("`restore rollback`",
    broken(["restore", "rollback", "--confirm", "--reason", "putting the earlier volume back"]));
  count("and names the directory it put back",
    rolled.stdout.indexOf(nodePath.basename(report.rollbackPath)) !== -1,
    rolled.stdout.slice(0, 300));
  count("and the operator is told the volume was rolled back and the trail did not record it",
    /roll/i.test(rolled.stderr) && /audit/i.test(rolled.stderr),
    JSON.stringify(rolled.stderr.slice(0, 400)));
}

// ---- the sink was in the way --------------------------------------------------

function everyVerbRanAgainstASinkThatCouldNotWrite(logPath) {
  var refused = nodeFs.existsSync(logPath)
    ? nodeFs.readFileSync(logPath, "utf8").split("\n").filter(function (l) { return l !== ""; })
    : [];
  var missed = COMMAND_LINE_ACTIONS.filter(function (action) {
    return refused.indexOf(action) === -1;
  });
  count("every verb above ran against a sink that really could not write, rather than " +
    "against one that was never reached", missed.length === 0, JSON.stringify(missed));
}

// ---- runner -------------------------------------------------------------------

async function run() {
  var root       = helpers.tempDir("cli-audit-sink");
  var dataDir    = nodePath.join(root, "data");
  var workDir    = nodePath.join(root, "work");
  var storageDir = nodePath.join(root, "backups");
  var passFile   = nodePath.join(root, "bundle.pass");
  var archiveOut = nodePath.join(root, "archive-bundle");
  var refusedLog = nodePath.join(root, "refused-actions.log");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.writeFileSync(passFile, BUNDLE_PASSPHRASE + "\n", { mode: 0o600 });

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

    // Early activity, a cut, then later activity, so an archive of the
    // early half leaves rows behind the way a retention run does. A
    // purge that took the last row would be refused for that reason and
    // would prove nothing about the sink.
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await b.audit.flush();
    identity.close();
    var cutIso = new Date(Date.now() + 1).toISOString();
    await helpers.passiveObserve(25, "letting the archive cut fall between two events");

    identity = await store.open(cfg);
    await identity.accounts.create({ address: ADDRESS, password: ALICE_PASSWORD });
    await identity.domains.add({ domain: SPARE });
    await b.audit.flush();
    identity.close();

    await seedSpool(dataDir);

    // Two runners over the same volume. The first has a working sink and
    // builds what the second needs; the second carries the fault. They
    // are separate processes, so the fault is armed for exactly the runs
    // that are being measured.
    var working = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });
    var brokenEnv = {};
    brokenEnv[fault.ARMED_VAR] = "1";
    brokenEnv[fault.LOG_VAR]   = refusedLog;
    var broken = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      execArgv:        ["--require", fault.PRELOAD],
      env:             brokenEnv,
    });

    // The control. A run whose sink works is what says the fixture drives
    // a working verb, so a broken-sink run that fails is the sink and not
    // the setup.
    var control = working(["account", "sieve", ADDRESS, "--reason", "checking the fixture"]);
    count("the same verb succeeds when the sink works, so the fixture drives a working verb",
      control.status === 0 && /filter scripts/.test(control.stdout),
      "exit " + control.status + " " + control.both.slice(0, 300));

    var firstRun = working(["backup", "run", "--storage", storageDir,
      "--passphrase-file", passFile, "--json"]);
    var firstSummary = parseJson(firstRun.stdout);
    count("a bundle is taken while the sink works, so the sweep below has an older one " +
      "to delete", firstRun.status === 0 && firstSummary !== null,
      "exit " + firstRun.status + " " + firstRun.both.slice(0, 300));

    var archived = working(["audit", "archive", "--out", archiveOut, "--before", cutIso,
      "--passphrase-file", passFile]);
    count("and a cut of the trail is archived while the sink works, so the purge below " +
      "has verified evidence to purge against",
      archived.status === 0, "exit " + archived.status + " " + archived.both.slice(0, 300));

    readingAFilterScript(broken);
    abandoningAQueuedMessage(broken, dataDir);
    purgingTheAuditTrail(broken, archiveOut, passFile);
    var bundleId = takingAndSweepingBundles(broken, storageDir, passFile,
      firstSummary === null ? "" : firstSummary.bundleId);

    if (bundleId !== null) {
      var report = restoringABundle(broken, storageDir, passFile, bundleId);
      if (report !== null && report.rollbackPath) rollingBackAgain(broken, report);
    }

    everyVerbRanAgainstASinkThatCouldNotWrite(refusedLog);

    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-audit-sink-refusal", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
