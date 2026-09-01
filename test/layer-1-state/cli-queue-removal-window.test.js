// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `blamepost queue remove` reports, and when it decides it.
 *
 * Abandoning a queued message is final and quiet: the body and the
 * descriptor are erased and the sender is never told. The verb is
 * reached for in an incident, on mail a stolen credential sent, which is
 * exactly the moment somebody asks later what was cancelled. So the one
 * thing it may never do is report a cancellation that did not happen.
 *
 * Between reading the queue and erasing the entry, the verb opens the
 * data volume. That is the longest suspension it has: the vault is
 * unsealed and the encrypted database is decrypted into a working copy.
 * The spool is a directory on disk that other things are working on
 * while it happens. `blamepost queue flush` opens no volume at all, and
 * the running server retries on a schedule of its own. Either can
 * deliver the message, or give up on it, and unlink the pair.
 *
 * A reading taken before that suspension describes the spool as it stood
 * rather than as it stands. Acting on it is not the harm here, because
 * the entry is already gone and the erasure erases nothing. Reporting it
 * is: the operator is told the message was stopped, and the row filed
 * under their name says the same, while the message is with the
 * receiver.
 *
 * So the reading the removal is decided on is taken with nothing
 * suspending between it and the erasure. The earlier reading stays where
 * it is, because an id that names nothing is worth refusing before the
 * volume is opened at all: on a running server that open is refused by
 * the process holding the volume, and meeting that refusal for a typo
 * would answer a question the operator did not ask.
 *
 * The interleaving is arranged rather than raced. The message leaves the
 * spool during the volume open, exactly once, from inside the run under
 * test, so the ordering is a fact. Every command below is the shipped
 * binary in a child process, because a handle called directly proves
 * what the handle does and not what an operator meets.
 *
 * Run standalone: node test/layer-1-state/cli-queue-removal-window.test.js
 */

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var departure = require("../helpers/spool-departure");
var blamepost = require("../../lib");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var HOSTNAME = "mx.example.com";

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n" +
  "Subject: waiting to go out\r\n\r\nbody\r\n";

// The row the removal files, under the name every surface files it
// under. A frozen contract: an auditor filters on it.
var QUEUE_REMOVED = "blamepost.mail.queue.message_removed";

// Ids in the shape the spool mints: lowercase hex, long enough that
// nothing an operator mistypes reaches a file.
var WAITING_ID  = "0123456789abcdef0123456789abcdef";
var STRANDED_ID = "fedcba9876543210fedcba98";

// An id of the same shape that names nothing at all.
var ABSENT_ID = "aaaabbbbccccddddaaaabbbbccccdddd";

// And one whose message body the data volume will not release.
var HELD_ID = "11112222333344445555666677778888";

// The two kinds of thing this verb takes an id for, printed at the end
// as the unit examined. A run that drove one of them and a run that
// drove both otherwise report the same check total and neither says
// which happened.
var QUEUE_ENTRY_KINDS_EXAMINED = 2;

// ---------------------------------------------------------------------------
// The spool
// ---------------------------------------------------------------------------

function queueDir(dataDir) { return path.join(dataDir, "queue"); }

function spoolPath(dataDir, name) { return path.join(queueDir(dataDir), name); }

// One waiting recipient, written the way the spool writes it. Planting
// the pair rather than driving a send keeps the run off the network and
// keeps the id known, which is what the assertions name. The next
// attempt is an hour out, so nothing retries it and every change to the
// spool in this file is one this file arranged.
function plantWaiting(dataDir, id) {
  fs.mkdirSync(queueDir(dataDir), { recursive: true });
  fs.writeFileSync(spoolPath(dataDir, id + ".eml"), MESSAGE, "utf8");
  fs.writeFileSync(spoolPath(dataDir, id + ".json"), JSON.stringify({
    id:               id,
    from:             "alice@example.com",
    recipient:        "bob@example.net",
    attempt:          1,
    nextAttemptAt:    Date.now() + 3600000,
    reason:           "451 4.7.0 the receiver asked for this to be tried later",
    reasonCode:       "4.7.0",
    requireTls:       false,
    queuedAt:         Date.now(),
    attemptsRecorded: 1,
    history:          [],
  }, null, 2), "utf8");
}

// A message body whose descriptor never landed. Nothing lists it and
// nothing sends it, and the room it holds is room the ceiling weighs, so
// this verb takes its id too. Aged past the window in which a descriptor
// write could still be in flight, so it reads as stranded rather than as
// arriving; the age is set on the file and nothing here sleeps.
function plantStranded(dataDir, id) {
  fs.mkdirSync(queueDir(dataDir), { recursive: true });
  var target = spoolPath(dataDir, id + ".eml");
  fs.writeFileSync(target, MESSAGE, { mode: 0o600 });
  var when = new Date(Date.now() - (blamepost.mail.delivery.SPOOL_SETTLE_MS + 60000));
  fs.utimesSync(target, when, when);
}

// A waiting message whose body the volume will not release. The body is
// planted as a non-empty directory under the name the spool gave it,
// which draws a real refusal out of the filesystem rather than a
// stand-in for one: a removal that is not recursive will not take a
// directory, on either platform this server runs on. What it stands in
// for is what actually happens on a running server, which is a backup or
// a scanner holding the file open while the operator cancels.
function plantHeldBody(dataDir, id) {
  plantWaiting(dataDir, id);
  fs.rmSync(spoolPath(dataDir, id + ".eml"), { force: true });
  fs.mkdirSync(spoolPath(dataDir, id + ".eml"), { recursive: true });
  fs.writeFileSync(path.join(spoolPath(dataDir, id + ".eml"), "held"), "held", "utf8");
}

function spooled(dataDir, id) {
  return fs.existsSync(spoolPath(dataDir, id + ".json")) ||
         fs.existsSync(spoolPath(dataDir, id + ".eml"));
}

// ---------------------------------------------------------------------------
// Readings
// ---------------------------------------------------------------------------

function freshVolume(prefix) {
  var root    = helpers.tempDir(prefix);
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  return { root: root, dataDir: dataDir, workDir: workDir };
}

// A runner whose spool loses the named entry during the first volume
// open, and a log naming every volume open the run made.
function runnerLosing(volume, id) {
  var env = {};
  env[departure.LOG_VAR] = path.join(volume.root, "opens.log");
  if (id !== null) {
    env[departure.ID_VAR]  = id;
    env[departure.DIR_VAR] = queueDir(volume.dataDir);
  }
  return {
    cli: cliHelper.create({
      dataDir:  volume.dataDir,
      workDir:  volume.workDir,
      hostname: HOSTNAME,
      env:      env,
      execArgv: ["--require", departure.PRELOAD],
    }),
    opens: function () {
      var log = path.join(volume.root, "opens.log");
      if (!fs.existsSync(log)) return 0;
      return fs.readFileSync(log, "utf8").split("\n").filter(Boolean).length;
    },
  };
}

function plainRunner(volume) {
  return cliHelper.create({
    dataDir:  volume.dataDir,
    workDir:  volume.workDir,
    hostname: HOSTNAME,
  });
}

// Every row the trail holds for one queued message, read back through
// the shipped verb rather than through a handle, because the question is
// what an auditor finds.
function rowsFor(cli, id) {
  var read = cli(["audit", "read", "--action", QUEUE_REMOVED, "--json"]);
  var rows;
  try { rows = JSON.parse(read.stdout); }
  catch (_e) { return { error: read.both.slice(0, 240), rows: [] }; }
  if (!Array.isArray(rows)) return { error: read.stdout.slice(0, 240), rows: [] };
  return { error: null, rows: rows.filter(function (row) { return row.resourceId === id; }) };
}

function verdicts(found) {
  return found.rows.map(function (row) { return row.outcome; }).sort().join(", ") || "(none)";
}

// ---------------------------------------------------------------------------
// A waiting message that leaves while the volume is opening
// ---------------------------------------------------------------------------

async function aWaitingMessageThatLeavesIsNotReportedAsCancelled(volume) {
  plantWaiting(volume.dataDir, WAITING_ID);
  var runner = runnerLosing(volume, WAITING_ID);

  var removed = runner.cli([
    "queue", "remove", WAITING_ID, "--reason", "sent by a credential that was taken",
  ]);

  count("the entry really did leave the spool while the volume was opening",
    !spooled(volume.dataDir, WAITING_ID) && runner.opens() === 1,
    "still spooled: " + spooled(volume.dataDir, WAITING_ID) +
      "; volume opens: " + runner.opens());

  count("the removal does not report a cancellation it did not make",
    removed.status !== 0 && !/Abandoned/.test(removed.both),
    "exit " + removed.status + " " + removed.both.slice(0, 300));

  count("and says the message is no longer in the queue, naming it",
    /no longer in the queue/.test(removed.both) &&
      removed.both.indexOf(WAITING_ID) !== -1,
    removed.both.slice(0, 300));

  count("and says nothing was removed, because nothing was",
    /nothing was removed/.test(removed.both), removed.both.slice(0, 300));

  var found = rowsFor(plainRunner(volume), WAITING_ID);
  count("the trail holds no row saying the message was cancelled",
    found.error === null && found.rows.every(function (row) {
      return row.outcome !== "success";
    }),
    "verdicts: " + verdicts(found) + (found.error ? "; " + found.error : ""));
  count("and holds one saying an operator asked and it had already gone",
    found.error === null && found.rows.length === 1 &&
      found.rows[0].outcome === "failure" &&
      String(found.rows[0].reason || "").indexOf("credential that was taken") !== -1,
    "verdicts: " + verdicts(found) + "; rows: " + found.rows.length);
}

// ---------------------------------------------------------------------------
// A stranded body that leaves while the volume is opening
// ---------------------------------------------------------------------------

// The other kind of id this verb takes. A message body whose descriptor
// never landed is in none of the listings, so `queue list` and `doctor`
// name it and send the operator here, and the same window stands between
// that reading and the erasure.
async function aStrandedBodyThatLeavesIsNotReportedAsCleared(volume) {
  plantStranded(volume.dataDir, STRANDED_ID);
  var runner = runnerLosing(volume, STRANDED_ID);

  var removed = runner.cli([
    "queue", "remove", STRANDED_ID, "--reason", "clearing a body with no descriptor",
  ]);

  count("the stranded body really did leave while the volume was opening",
    !spooled(volume.dataDir, STRANDED_ID) && runner.opens() === 1,
    "still spooled: " + spooled(volume.dataDir, STRANDED_ID) +
      "; volume opens: " + runner.opens());

  count("the removal does not report clearing something that had already gone",
    removed.status !== 0 && !/^Removed /m.test(removed.stdout),
    "exit " + removed.status + " " + removed.both.slice(0, 300));

  count("and names it and says nothing was removed",
    removed.both.indexOf(STRANDED_ID) !== -1 && /nothing was removed/.test(removed.both),
    removed.both.slice(0, 300));

  var found = rowsFor(plainRunner(volume), STRANDED_ID);
  count("the trail holds no row saying that body was cleared",
    found.error === null && found.rows.every(function (row) {
      return row.outcome !== "success";
    }),
    "verdicts: " + verdicts(found) + (found.error ? "; " + found.error : ""));
}

// ---------------------------------------------------------------------------
// The refusal that costs nothing
// ---------------------------------------------------------------------------

// An id that names nothing is refused before the data volume is opened,
// and that ordering is worth pinning. On a running server the open is
// refused by the process already holding the volume, so a verb that
// opened first would answer a typo with a lock rather than with the
// mistake, and an operator cancelling a compromised account's mail would
// have to work out which of the two they were looking at.
async function anIdThatNamesNothingIsRefusedBeforeTheVolumeOpens(volume) {
  plantWaiting(volume.dataDir, WAITING_ID);
  var runner = runnerLosing(volume, null);

  var refused = runner.cli([
    "queue", "remove", ABSENT_ID, "--reason", "an id read off the wrong screen",
  ]);

  count("an id that names nothing is refused as the argument problem it is",
    refused.status === 2 && refused.both.indexOf(ABSENT_ID) !== -1,
    "exit " + refused.status + " " + refused.both.slice(0, 300));
  count("and the refusal costs nothing, because the data volume was never opened",
    runner.opens() === 0, "volume opens: " + runner.opens());
  count("and the message that is waiting is untouched",
    spooled(volume.dataDir, WAITING_ID), "spooled: " + spooled(volume.dataDir, WAITING_ID));
}

// ---------------------------------------------------------------------------
// The ordinary path
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A message the volume will not release
// ---------------------------------------------------------------------------

// The state no reading can see, and the reason the erasure's own answer
// is the authority rather than the reading beside it. The message is
// there before the run, there while it runs, and there afterwards: the
// entry was never erased. Reporting it as cancelled would tell an
// operator working through a compromised account's outbound mail to stop
// looking for a message the running server is about to attempt again.
async function aMessageTheVolumeWillNotReleaseIsNotReportedAsCancelled(volume) {
  plantHeldBody(volume.dataDir, HELD_ID);
  var cli = plainRunner(volume);

  var removed = cli([
    "queue", "remove", HELD_ID, "--reason", "sent by a credential that was taken",
  ]);

  count("the removal refuses rather than reporting a cancellation it did not make",
    removed.status !== 0 && !/Abandoned/.test(removed.both),
    "exit " + removed.status + " " + removed.both.slice(0, 300));
  count("and it says the message is still queued, naming the part the volume kept",
    /still in the queue/.test(removed.both) && /body/.test(removed.both),
    removed.both.slice(0, 400));
  count("the entry is still on the spool, which is what the refusal said",
    spooled(volume.dataDir, HELD_ID) &&
      fs.existsSync(spoolPath(volume.dataDir, HELD_ID + ".json")),
    JSON.stringify(fs.readdirSync(queueDir(volume.dataDir))));
  var listed = cli(["queue", "list"]);
  count("and it is still in the listing an operator reads",
    listed.both.indexOf(HELD_ID) !== -1, listed.both.slice(0, 300));

  var found = rowsFor(cli, HELD_ID);
  count("the attempt is on the trail as a failure rather than as a cancellation",
    found.error === null && found.rows.length === 1 &&
      found.rows[0].outcome === "failure",
    "verdicts: " + verdicts(found) + (found.error ? "; " + found.error : ""));
}

// So the refusals above read as the window closing rather than as the
// verb refusing every removal it is shown. A message that is still there
// when the erasure runs is abandoned, and the row says so.
async function anUncontestedRemovalStillAbandonsTheMessage(volume) {
  plantWaiting(volume.dataDir, WAITING_ID);
  plantStranded(volume.dataDir, STRANDED_ID);
  var cli = plainRunner(volume);

  var removed = cli([
    "queue", "remove", WAITING_ID, "--reason", "undeliverable, sender told by hand",
  ]);
  count("an uncontested removal abandons the message",
    removed.status === 0 && /Abandoned/.test(removed.stdout),
    "exit " + removed.status + " " + removed.both.slice(0, 300));
  count("and the pair leaves the spool",
    !spooled(volume.dataDir, WAITING_ID), "spooled: " + spooled(volume.dataDir, WAITING_ID));

  var cleared = cli([
    "queue", "remove", STRANDED_ID, "--reason", "a body with no descriptor",
  ]);
  count("and a stranded body is cleared by the same verb",
    cleared.status === 0 && /no descriptor/.test(cleared.stdout),
    "exit " + cleared.status + " " + cleared.both.slice(0, 300));
  count("and it leaves the spool too",
    !spooled(volume.dataDir, STRANDED_ID), "spooled: " + spooled(volume.dataDir, STRANDED_ID));

  var found = rowsFor(cli, WAITING_ID);
  count("and the trail says the message was cancelled, with the reason it was given",
    found.error === null && found.rows.length === 1 &&
      found.rows[0].outcome === "success" &&
      String(found.rows[0].reason || "").indexOf("sender told by hand") !== -1,
    "verdicts: " + verdicts(found) + (found.error ? "; " + found.error : ""));
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
      "queue remove: a waiting message that leaves is not reported as cancelled",
      function () {
        return aWaitingMessageThatLeavesIsNotReportedAsCancelled(fresh("queue-rm-waiting"));
      });
    await helpers.withTestTimeout(
      "queue remove: a stranded body that leaves is not reported as cleared",
      function () {
        return aStrandedBodyThatLeavesIsNotReportedAsCleared(fresh("queue-rm-stranded"));
      });
    await helpers.withTestTimeout(
      "queue remove: an id that names nothing is refused before the volume opens",
      function () {
        return anIdThatNamesNothingIsRefusedBeforeTheVolumeOpens(fresh("queue-rm-absent"));
      });
    await helpers.withTestTimeout(
      "queue remove: a message the volume will not release is not reported as cancelled",
      function () {
        return aMessageTheVolumeWillNotReleaseIsNotReportedAsCancelled(fresh("queue-rm-held"));
      });
    await helpers.withTestTimeout(
      "queue remove: an uncontested removal still abandons the message",
      function () {
        return anUncontestedRemovalStillAbandonsTheMessage(fresh("queue-rm-plain"));
      });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < volumes.length; i += 1) helpers.removeTempDir(volumes[i].root);
  }
}

module.exports = {
  name:      "cli-queue-removal-window",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// kind of queue entry and a run that drove both otherwise report the
// same total and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + QUEUE_ENTRY_KINDS_EXAMINED + " queue-entry-kind");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
