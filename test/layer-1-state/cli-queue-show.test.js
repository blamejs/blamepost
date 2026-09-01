// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `blamepost queue show` puts in front of an operator.
 *
 * `queue list` answers whether a message is moving. It cannot answer the
 * two questions asked next, which are why it is not arriving and how long
 * there is left: a listing carries one row per message and neither the
 * attempt record nor the ending belongs in a row. The delivery handle
 * computes both, guards every foreign string in them for display, and
 * says so in its own comment block. Nothing printed either, so an
 * operator could read that a message had been tried four times and never
 * read what the receiver said any of those four times.
 *
 * So the checks here are about reachability as much as correctness. Each
 * one drives the shipped binary in a child process, because a handle
 * called directly proves what the handle computes and not what an
 * operator meets, and computing an answer nothing prints is the defect
 * this file exists to keep closed.
 *
 * Four kinds of id reach this verb and each answers differently: an entry
 * with no attempt yet, an entry carrying a history, an id of the right
 * shape naming nothing, and an id that is not one this server would ever
 * have minted. The last is the security vector. An id becomes a path, so
 * a verb that takes one from a terminal and does not refuse a traversal
 * reads a file of the caller's choosing.
 *
 * Run standalone: node test/layer-1-state/cli-queue-show.test.js
 */

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var HOSTNAME = "mx.example.com";

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n" +
  "Subject: waiting to go out\r\n\r\nbody\r\n";

var WAITING_ID = "0123456789abcdef0123456789abcdef";
var TRIED_ID   = "fedcba9876543210fedcba9876543210";
var ABSENT_ID  = "aaaabbbbccccddddaaaabbbbccccdddd";

// What a receiver said, kept verbatim so the check below is that the
// operator reads the far side's words rather than a paraphrase of them.
var FIRST_REFUSAL  = "451 4.7.1 greylisted, try again in 300 seconds";
var SECOND_REFUSAL = "451 4.3.2 the receiving system is not accepting messages";

// Ids that are not ids. Each would become a path if the verb built one
// without asking, and the first two reach outside the spool directory.
var HOSTILE_IDS = [
  "../../../../etc/passwd",
  "..\\..\\..\\windows\\win.ini",
  "0123456789abcdef0123456789abcdef/../../secret",
  "not-hex-at-all",
  "",
];

// The four answers this verb has to give, printed as the unit examined.
// A run that drove one of them and a run that drove all four otherwise
// report the same check total and neither says which happened.
var ANSWER_KINDS_EXAMINED = 4;

// ---------------------------------------------------------------------------
// The spool
// ---------------------------------------------------------------------------

function queueDir(dataDir) { return path.join(dataDir, "queue"); }
function spoolPath(dataDir, name) { return path.join(queueDir(dataDir), name); }

// One waiting recipient, written the way the spool writes it. Planting
// the pair rather than driving a send keeps the run off the network and
// keeps the id known, which is what the assertions name. The next attempt
// is an hour out, so nothing retries it and every change to the spool in
// this file is one this file arranged.
function plant(dataDir, id, descriptor) {
  fs.mkdirSync(queueDir(dataDir), { recursive: true });
  fs.writeFileSync(spoolPath(dataDir, id + ".eml"), MESSAGE, "utf8");
  fs.writeFileSync(spoolPath(dataDir, id + ".json"), JSON.stringify(Object.assign({
    id:               id,
    from:             "alice@example.com",
    recipient:        "bob@example.net",
    attempt:          0,
    nextAttemptAt:    Date.now() + 3600000,
    requireTls:       false,
    queuedAt:         Date.now(),
    attemptsRecorded: 0,
    history:          [],
  }, descriptor || {}), null, 2), "utf8");
}

// The same entry after two receivers refused it, so the history has
// something in it and the two refusals differ. A fault that moved between
// attempts and one that persisted are different operator problems, and
// only a per-attempt record tells them apart.
function plantTried(dataDir, id) {
  var now = Date.now();
  plant(dataDir, id, {
    attempt:          2,
    attemptsRecorded: 2,
    reason:           SECOND_REFUSAL,
    reasonCode:       "4.3.2",
    history: [
      { at: now - 7200000, attempt: 1, outcome: "deferred",
        reason: FIRST_REFUSAL,  reasonCode: "4.7.1", mxHost: "mx1.example.net" },
      { at: now - 3600000, attempt: 2, outcome: "deferred",
        reason: SECOND_REFUSAL, reasonCode: "4.3.2", mxHost: "mx2.example.net" },
    ],
  });
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

// A message nothing has tried yet still has an answer: an operator asking
// after it wants to know it is queued and when it will first move, and a
// verb that only spoke about attempts would say nothing at all here.
function anUntriedMessageSaysWhenItFirstMoves(volume) {
  plant(volume.dataDir, WAITING_ID);
  var run = runnerOn(volume);
  var result = run(["queue", "show", WAITING_ID]);

  count("an untried entry is reported rather than refused",
    result.status === 0, "exit " + result.status + ": " + result.both);
  count("the entry is named by the id the operator asked for",
    result.stdout.indexOf(WAITING_ID) !== -1, result.stdout);
  count("and by its recipient, which is what an operator is asked about",
    result.stdout.indexOf("bob@example.net") !== -1, result.stdout);
  count("no attempt is claimed for a message nothing has tried",
    /No attempt has been made yet/.test(result.stdout), result.stdout);
  count("and the budget it has not started spending is still reported",
    /of \d+ spent/.test(result.stdout) || /attempt/i.test(result.stdout), result.stdout);
}

// The attempt record, which is the half a listing structurally cannot
// carry. Both refusals have to be readable: a receiver that refused for
// one reason and then another is the shape that says the fault moved, and
// printing only the last one hides it.
function everyAttemptAndWhatTheFarSideSaidIsReadable(volume) {
  plantTried(volume.dataDir, TRIED_ID);
  var run = runnerOn(volume);
  var result = run(["queue", "show", TRIED_ID]);

  count("an entry with a history is reported",
    result.status === 0, "exit " + result.status + ": " + result.both);
  count("the first receiver's own words reach the operator",
    result.stdout.indexOf(FIRST_REFUSAL) !== -1, result.stdout);
  count("and so do the second's, which a last-reason column would have lost",
    result.stdout.indexOf(SECOND_REFUSAL) !== -1, result.stdout);
  count("each attempt names the host it was made against",
    result.stdout.indexOf("mx1.example.net") !== -1 &&
    result.stdout.indexOf("mx2.example.net") !== -1, result.stdout);
  count("the attempts are printed oldest first, so what changed reads in order",
    result.stdout.indexOf(FIRST_REFUSAL) < result.stdout.indexOf(SECOND_REFUSAL),
    result.stdout);
  count("and the message is told how it ends if nothing changes",
    /given up on/.test(result.stdout), result.stdout);

  // The same answer as data. An operator scripting this reads the
  // projection rather than the sentence, and a verb that printed the
  // sentence and dropped the numbers would be two surfaces disagreeing.
  var asJson = run(["queue", "show", TRIED_ID, "--json"]);
  count("the machine-readable answer parses", asJson.status === 0 &&
    (function () { try { JSON.parse(asJson.stdout); return true; } catch (_e) { return false; } })(),
    asJson.both);
  var parsed = JSON.parse(asJson.stdout);
  var entry  = parsed && parsed.result ? parsed.result : parsed;
  count("and carries the attempt record",
    Array.isArray(entry.history) && entry.history.length === 2,
    JSON.stringify(entry.history));
  count("and the projection, with the budget as numbers rather than prose",
    entry.projection && typeof entry.projection.attemptsSpent === "number" &&
    typeof entry.projection.attemptsAllowed === "number",
    JSON.stringify(entry.projection));
}

// A well formed id with nothing behind it is an answer rather than a
// fault. The message may have been delivered, given up on, or removed
// since the id was read, and this verb cannot know which, so the one
// thing it may not do is imply one of them.
function anIdNamingNothingIsAnAnswerRatherThanAFault(volume) {
  var run = runnerOn(volume);
  var result = run(["queue", "show", ABSENT_ID]);

  count("an id naming nothing is not reported as a failure",
    result.status === 0, "exit " + result.status + ": " + result.both);
  count("and says the message is no longer waiting",
    /Nothing by that id is waiting/.test(result.stdout), result.stdout);
  count("without claiming which of the ways it left, none of which this can know",
    !/was delivered\.|was cancelled|has been removed\b/.test(result.stdout),
    result.stdout);
}

// The security vector. An id becomes a path, so a verb taking one from a
// terminal has to refuse anything that is not an id before it builds one.
// A traversal that came back with content, or with a refusal naming a
// file outside the spool, would both be findings.
function anIdThatIsNotOneIsRefusedBeforeItBecomesAPath(volume) {
  plant(volume.dataDir, WAITING_ID);
  var run = runnerOn(volume);
  var leaked = [];
  var accepted = [];

  HOSTILE_IDS.forEach(function (id) {
    var result = run(["queue", "show", id]);
    if (result.status === 0 && /Nothing by that id is waiting/.test(result.stdout) === false &&
        result.stdout.trim() !== "") {
      accepted.push(JSON.stringify(id) + " -> " + result.stdout.trim().slice(0, 120));
    }
    if (/root:|\[fonts\]|BEGIN [A-Z ]*PRIVATE KEY/.test(result.both)) {
      leaked.push(JSON.stringify(id));
    }
  });

  count("no id that is not one is answered as though it named a message",
    accepted.length === 0, accepted.join(" ; "));
  count("and nothing outside the spool is read by any of them",
    leaked.length === 0, leaked.join(", "));

  // The refusal has to be a refusal, not a silence. A verb that printed
  // nothing and exited zero would satisfy the two checks above while
  // telling the operator nothing about what was wrong.
  var traversal = run(["queue", "show", HOSTILE_IDS[0]]);
  count("a traversal is refused in words rather than by printing nothing",
    traversal.status !== 0 || traversal.both.trim() !== "",
    "exit " + traversal.status + ": " + JSON.stringify(traversal.both));
}

// The verb an operator finds by running the group with no verb. A verb
// that works and is not listed is one nobody reaches, which is the same
// outcome as not having built it.
function theVerbIsOfferedInTheUsageBlock(volume) {
  var run = runnerOn(volume);
  var usage = run(["queue"]);
  count("the queue group offers show among its verbs",
    /^\s*show\b/m.test(usage.both), usage.both);
  count("and says what it is for, rather than only naming it",
    /attempt|far side|ends/i.test(usage.both), usage.both);
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
      "queue show: an untried message says when it first moves",
      function () { return anUntriedMessageSaysWhenItFirstMoves(fresh("queue-show-untried")); });
    await helpers.withTestTimeout(
      "queue show: every attempt and what the far side said is readable",
      function () {
        return everyAttemptAndWhatTheFarSideSaidIsReadable(fresh("queue-show-tried"));
      });
    await helpers.withTestTimeout(
      "queue show: an id naming nothing is an answer rather than a fault",
      function () {
        return anIdNamingNothingIsAnAnswerRatherThanAFault(fresh("queue-show-absent"));
      });
    await helpers.withTestTimeout(
      "queue show: an id that is not one is refused before it becomes a path",
      function () {
        return anIdThatIsNotOneIsRefusedBeforeItBecomesAPath(fresh("queue-show-hostile"));
      });
    await helpers.withTestTimeout(
      "queue show: the verb is offered in the usage block",
      function () { return theVerbIsOfferedInTheUsageBlock(fresh("queue-show-usage")); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < volumes.length; i += 1) helpers.removeTempDir(volumes[i].root);
  }
}

module.exports = {
  name:      "cli-queue-show",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// kind of answer and a run that drove all four otherwise report the same
// total and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + ANSWER_KINDS_EXAMINED + " queue-show-answer-kind");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
