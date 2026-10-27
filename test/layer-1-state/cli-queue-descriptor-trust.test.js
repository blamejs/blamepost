// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a spool descriptor may decide once it is back off the volume.
 *
 * `lib/mail/delivery.js` writes one waiting recipient as a pair of files
 * under `<dataDir>/queue`, and reads the descriptor back on every
 * listing, every `queue show`, every `queue held` and every sweep. The
 * module says in its own comment above `_storedText` that an entry
 * written before any screening existed is still read, still printed, and
 * still able to forge a row, and that the descriptor keeps what arrived
 * so every read path is what is safe. The spool is a directory on the
 * data volume, so the bytes it reads back are whatever the volume holds:
 * an operator with a shell, a restore, a backup rolled back to an older
 * shape, a build that is not this one.
 *
 * So the descriptor is untrusted input with a trust boundary in front of
 * it, and the four things it must not be able to do are:
 *
 *   - name a file. An id becomes `<id>.json`, `<id>.eml` and
 *     `<id>.claim`, and the sweep unlinks the first two when it gives up
 *     on an entry. An id read out of the file's own content addresses a
 *     path nobody chose;
 *   - name another entry. The id printed beside a message is what an
 *     operator retypes into `queue remove`, so one the file chose sends
 *     the cancellation at a different message;
 *   - reach a terminal unscreened. `b.guardText`'s balanced profile
 *     leaves the C1 range at U+0080 to U+009F alone, and U+009B is the
 *     single byte form of CSI, the escape introducer a terminal acts on;
 *   - stop the verb. `queue list` and `queue show` are what an operator
 *     runs while mail is not moving, and the sweep runs on a timer
 *     forever.
 *
 * Each check drives the shipped binary in a child process against a
 * planted spool, because the screening and the id are only worth
 * anything at the surface an operator meets.
 *
 * No network: the sweep vector plants an entry whose message body is not
 * beside it, which the sweep settles before it looks up an MX.
 *
 * Run standalone: node test/layer-1-state/cli-queue-descriptor-trust.test.js
 */

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var HOSTNAME = "mx.example.com";

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n" +
  "Subject: waiting to go out\r\n\r\nbody\r\n";

// Ids of the shape the spool mints: lowercase hex, 32 characters.
var FILE_ID     = "0123456789abcdef0123456789abcdef";
var SECOND_ID   = "fedcba9876543210fedcba9876543210";
var CLAIMED_ID  = "aaaabbbbccccddddaaaabbbbccccdddd";

// The file the traversing descriptor addresses. It sits beside the spool
// rather than inside it, which is where `keys/`, `blobs/` and the
// encrypted database live on a real volume.
var SENTINEL = "sentinel-outside-the-spool";

// The single byte form of CSI, built here rather than written into this
// file: a C1 code point does not survive being typed into a source file.
var CSI = String.fromCharCode(0x9b);
var NEL = String.fromCharCode(0x85);

// The vectors this file drives, printed as the unit examined. A run that
// drove one of them and a run that drove all five otherwise report the
// same check total and neither says which happened.
var TRUST_VECTORS_EXAMINED = 5;

// ---------------------------------------------------------------------------
// The spool
// ---------------------------------------------------------------------------

function queueDir(dataDir) { return path.join(dataDir, "queue"); }

// One pair written the way `_spool` writes it, with the descriptor's own
// fields overridden by the vector. Planting rather than sending keeps the
// run off the network and keeps the file name known, which is the whole
// of what the id checks below compare against.
function plant(dataDir, fileId, descriptor, opts) {
  fs.mkdirSync(queueDir(dataDir), { recursive: true });
  if (!opts || opts.withBody !== false) {
    fs.writeFileSync(path.join(queueDir(dataDir), fileId + ".eml"), MESSAGE, "utf8");
  }
  fs.writeFileSync(path.join(queueDir(dataDir), fileId + ".json"),
    typeof descriptor === "string" ? descriptor : JSON.stringify(Object.assign({
      id:               fileId,
      from:             "alice@example.com",
      recipient:        "bob@example.net",
      attempt:          0,
      nextAttemptAt:    Date.now() + 3600000,
      reason:           "",
      reasonCode:       "",
      requireTls:       false,
      held:             false,
      heldBecause:      "",
      queuedAt:         Date.now(),
      attemptsRecorded: 0,
      history:          [],
    }, descriptor || {}), null, 2), "utf8");
}

function freshVolume(prefix) {
  var root    = helpers.tempDir(prefix);
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  return { root: root, dataDir: dataDir, workDir: workDir };
}

function runnerOn(volume) {
  return cliHelper.create({
    dataDir:  volume.dataDir,
    workDir:  volume.workDir,
    hostname: HOSTNAME,
  });
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

// The id beside a message is the id of the file that message is in. An
// operator reads it off a listing and types it into `queue remove`, so an
// id the file chose for itself cancels a different message, or none.
function theIdAnOperatorReadsIsTheIdOfTheFile(volume) {
  plant(volume.dataDir, FILE_ID, { id: CLAIMED_ID });
  plant(volume.dataDir, SECOND_ID, { id: "../" + SENTINEL });
  var run = runnerOn(volume);

  var listed = run(["queue", "list"]);
  count("the listing is printed rather than refused",
    listed.status === 0, "exit " + listed.status + ": " + listed.both);
  count("each waiting message is named by the file it is in",
    listed.stdout.indexOf(FILE_ID) !== -1 && listed.stdout.indexOf(SECOND_ID) !== -1,
    listed.stdout);
  count("and never by the id the descriptor wrote for itself",
    listed.stdout.indexOf(CLAIMED_ID) === -1, listed.stdout);
  count("and never by a path a descriptor put in the id field",
    listed.stdout.indexOf("../") === -1 && listed.stdout.indexOf(SENTINEL) === -1,
    listed.stdout);

  var shown = run(["queue", "show", FILE_ID, "--json"]);
  count("`queue show` answers about the entry that was asked for",
    shown.status === 0, "exit " + shown.status + ": " + shown.both);
  var parsed;
  try { parsed = JSON.parse(shown.stdout); } catch (_e) { parsed = null; }
  var entry = parsed && parsed.result ? parsed.result : parsed;
  count("and the machine-readable answer carries the id of the file it read",
    entry !== null && entry.id === FILE_ID, JSON.stringify(entry && entry.id));
}

// The sweep unlinks both files of a pair when it gives up on an entry.
// The id it builds those two paths from must not be one the file chose,
// because the spool sits inside the data volume beside the sealed keys,
// the blobs and the database.
function aDescriptorNamesNoFileOutsideTheSpool(volume) {
  var sentinelPath = path.join(volume.dataDir, SENTINEL + ".json");
  fs.writeFileSync(sentinelPath, "{\"kept\":\"a file the spool does not own\"}\n", "utf8");

  // No body beside it, and a moment already past: the sweep settles this
  // entry on the missing message before it looks up an MX, so nothing
  // here reaches the network.
  plant(volume.dataDir, FILE_ID, {
    id:            "../" + SENTINEL,
    nextAttemptAt: 0,
  }, { withBody: false });

  var run = runnerOn(volume);
  var flushed = run(["queue", "flush", "--force"]);
  count("the sweep runs rather than refusing",
    flushed.status === 0, "exit " + flushed.status + ": " + flushed.both);
  count("a file beside the spool is still there after the sweep",
    fs.existsSync(sentinelPath), sentinelPath + " was removed by `queue flush`");
  count("and the sweep left no claim file beside it either",
    !fs.existsSync(path.join(volume.dataDir, SENTINEL + ".claim")),
    "a claim was created outside the spool");
  count("the sweep row names the entry it read rather than the path the file asked for",
    flushed.stdout.indexOf(SENTINEL) === -1 && flushed.stdout.indexOf("../") === -1,
    flushed.stdout);
}

// Every value handed out of the delivery module for display goes through
// `b.guardText`, whose balanced profile leaves the C1 range behind. The
// module strips that range itself for the four fields it knows about; a
// descriptor puts its bytes wherever it likes.
function nothingAnOperatorReadsCarriesAC1Control(volume) {
  plant(volume.dataDir, FILE_ID, {
    held:             true,
    heldBecause:      "waiting" + CSI + "2J" + CSI + "31mon nothing" + NEL + "delivered",
    attempt:          "0" + CSI + "31m of 35",
    attemptsRecorded: 1,
    reason:           "451 4.7.1 " + CSI + "41mgreylisted",
    history: [{
      at:         Date.now() - 3600000,
      outcome:    "delivered" + CSI + "32m",
      attempt:    1,
      mxHost:     "mx1.example.net" + CSI + "0m",
      reason:     "250 2.0.0 accepted" + CSI,
      reasonCode: "2.0.0",
      requireTls: false,
      held:       true,
    }],
    route: "mx1.example.net" + CSI + "7m",
  });

  var run = runnerOn(volume);
  var readings = [
    { label: "queue list",          result: run(["queue", "list"]) },
    { label: "queue list --json",   result: run(["queue", "list", "--json"]) },
    { label: "queue show",          result: run(["queue", "show", FILE_ID]) },
    { label: "queue show --json",   result: run(["queue", "show", FILE_ID, "--json"]) },
    { label: "queue held",          result: run(["queue", "held"]) },
    { label: "queue held --json",   result: run(["queue", "held", "--json"]) },
  ];

  var carrying = readings.filter(function (reading) {
    return reading.result.both.indexOf(CSI) !== -1 || reading.result.both.indexOf(NEL) !== -1;
  }).map(function (reading) { return reading.label; });

  count("every reading of the queue is printed rather than refused",
    readings.every(function (reading) { return reading.result.status === 0; }),
    readings.map(function (r) { return r.label + " exit " + r.result.status; }).join(", "));
  count("no reading of the queue carries a C1 control to the operator's terminal",
    carrying.length === 0, carrying.join(", "));

  // The record is still on disk as it arrived. Screening on the way out
  // is what makes the record safe to read; screening on the way in would
  // lose the bytes the far side actually sent.
  var onDisk = fs.readFileSync(path.join(queueDir(volume.dataDir), FILE_ID + ".json"), "utf8");
  count("the descriptor on the volume still holds what arrived",
    onDisk.indexOf(CSI) !== -1, "the bytes on disk were rewritten by a read");
}

// A descriptor that is valid JSON and is not an object. Every reader
// projects a row from it, and the listing is what an operator runs to
// find the entry they then clear by hand.
function aDescriptorThatIsNotAnObjectDoesNotStopTheListing(volume) {
  plant(volume.dataDir, FILE_ID, {});
  plant(volume.dataDir, SECOND_ID, "null\n");
  plant(volume.dataDir, CLAIMED_ID, "[1, 2, 3]\n");
  var run = runnerOn(volume);

  var listed = run(["queue", "list"]);
  count("the listing answers rather than stopping on a descriptor that is not an object",
    listed.status === 0, "exit " + listed.status + ": " + listed.both);
  count("the entry that reads is still listed beside the ones that do not",
    listed.stdout.indexOf(FILE_ID) !== -1, listed.stdout);
  count("and each one that does not read is reported as an entry needing a person",
    (listed.stdout.match(/unreadable/g) || []).length >= 2, listed.stdout);
  count("every row names the file it was read from",
    listed.stdout.indexOf(SECOND_ID) !== -1 && listed.stdout.indexOf(CLAIMED_ID) !== -1,
    listed.stdout);

  var flushed = run(["queue", "flush", "--force"]);
  count("and the sweep runs over the same spool rather than stopping on one of them",
    flushed.status === 0, "exit " + flushed.status + ": " + flushed.both);
}

// The attempt record is a list of rows. A row that is not one is read by
// the same screen every other row goes through.
function aHistoryRowThatIsNotOneDoesNotStopTheEntryBeingShown(volume) {
  plant(volume.dataDir, FILE_ID, { attempt: 1, attemptsRecorded: 1, history: [null] });
  plant(volume.dataDir, SECOND_ID, {
    attempt: 3, attemptsRecorded: 3, history: ["deferred at mx1.example.net", 7, true],
  });
  var run = runnerOn(volume);

  var first = run(["queue", "show", FILE_ID]);
  count("an entry whose attempt record holds an empty row is still shown",
    first.status === 0, "exit " + first.status + ": " + first.both);
  count("and it is shown as the entry it is rather than as one no longer waiting",
    first.stdout.indexOf(FILE_ID) !== -1 &&
    /Nothing by that id is waiting/.test(first.stdout) === false, first.stdout);

  var second = run(["queue", "show", SECOND_ID]);
  count("an entry whose attempt record holds values that are not rows is still shown",
    second.status === 0, "exit " + second.status + ": " + second.both);

  var listed = run(["queue", "list"]);
  count("and both are still listed",
    listed.status === 0 && listed.stdout.indexOf(FILE_ID) !== -1 &&
    listed.stdout.indexOf(SECOND_ID) !== -1, "exit " + listed.status + ": " + listed.both);
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
      "queue descriptor: the id an operator reads is the id of the file",
      function () { return theIdAnOperatorReadsIsTheIdOfTheFile(fresh("qd-id")); });
    await helpers.withTestTimeout(
      "queue descriptor: a descriptor names no file outside the spool",
      function () { return aDescriptorNamesNoFileOutsideTheSpool(fresh("qd-path")); });
    await helpers.withTestTimeout(
      "queue descriptor: nothing an operator reads carries a C1 control",
      function () { return nothingAnOperatorReadsCarriesAC1Control(fresh("qd-c1")); });
    await helpers.withTestTimeout(
      "queue descriptor: a descriptor that is not an object does not stop the listing",
      function () {
        return aDescriptorThatIsNotAnObjectDoesNotStopTheListing(fresh("qd-shape"));
      });
    await helpers.withTestTimeout(
      "queue descriptor: a history row that is not one does not stop the entry being shown",
      function () {
        return aHistoryRowThatIsNotOneDoesNotStopTheEntryBeingShown(fresh("qd-history"));
      });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < volumes.length; i += 1) helpers.removeTempDir(volumes[i].root);
  }
}

module.exports = {
  name:      "cli-queue-descriptor-trust",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// vector and a run that drove all five otherwise report the same total
// and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + TRUST_VECTORS_EXAMINED + " queue-descriptor-trust-vector");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
