// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The server-wide settings an operator changes while the server runs,
 * driven through the same calls the administration console makes: a real
 * temporary data directory, a real vault, a real encrypted database and
 * the real sealed column the actor is written into.
 *
 * Four properties, each written as the failure it prevents:
 *
 *   - A setting nobody has touched answers null rather than false. The
 *     caller lays the configuration file's value under that answer, and
 *     a false standing in for an absent row would pin the first boot's
 *     configuration permanently: every later edit of the file would be
 *     overridden by a row the operator never wrote.
 *   - An answer the operator gave survives the process that recorded it.
 *     A switch that goes back to the file's value on the next restart is
 *     a switch an operator sets once and then finds off again, with
 *     nothing on the volume saying what happened to it.
 *   - A name outside the closed list and a value that is not a boolean
 *     are refused at the call. The console posts both, and a table that
 *     accepts an arbitrary name holds rows nothing reads and nothing
 *     removes, while a truthy reading of a string stores a typo as an
 *     answer.
 *   - The change is filed, with the value before it and the value after
 *     it. `from` is null on the first write rather than false, because a
 *     trail that recorded false there would say an operator turned
 *     something off that had never been on.
 *
 * Run standalone: node test/layer-1-state/server-settings.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var store   = require("../../lib/store");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var HOSTNAME         = "mx.example.com";

// The one name this server reads today. Written out rather than taken
// from the module, so a name silently dropped from the list is a failure
// here instead of a run that asserts about whatever is left.
var PUBLIC_SITE = "publicSiteEnabled";

var OPERATOR = "operator@example.com";

// Assert a call refuses with a TypeError. Both readers here are entry
// points: the console picks the name from a fixed set and the value from
// a checkbox, so either arriving wrong is a caller defect rather than
// something an operator typed, and it is refused at the call rather than
// stored.
async function refusesWithTypeError(label, fn) {
  var thrown = null;
  try {
    await fn();
  } catch (e) {
    thrown = e;
  }
  count(label, thrown instanceof TypeError,
    thrown === null ? "nothing was thrown" : String(thrown.name) + ": " + String(thrown.message));
}

// ---- a setting nobody has set answers null ---------------------------------

function testAnUntouchedSettingAnswersNull(handle) {
  var answer = handle.settings.get(PUBLIC_SITE);
  count("blamepost.store.settings.get answers null for a setting no operator has written, " +
    "so the caller falls through to the configuration file rather than to a stored false",
    answer === null, JSON.stringify(answer));
}

// ---- the answer round-trips in both directions ------------------------------

async function testBothAnswersRoundTrip(handle) {
  var turnedOn = await handle.settings.set({
    name:      PUBLIC_SITE,
    value:     true,
    changedBy: OPERATOR,
    reason:    "publishing the front page",
  });
  count("blamepost.store.settings.set answers with the row it wrote",
    turnedOn !== null && turnedOn.name === PUBLIC_SITE && turnedOn.value === true,
    JSON.stringify(turnedOn));
  count("and the reader answers true rather than null once a row is there",
    handle.settings.get(PUBLIC_SITE) === true,
    JSON.stringify(handle.settings.get(PUBLIC_SITE)));

  var turnedOff = await handle.settings.set({
    name:      PUBLIC_SITE,
    value:     false,
    changedBy: OPERATOR,
    reason:    "taking the front page down again",
  });
  count("setting it back replaces the row rather than adding a second one",
    turnedOff !== null && turnedOff.value === false, JSON.stringify(turnedOff));
  count("and a stored false reads as false rather than as a setting nobody has touched, " +
    "which is the distinction the caller lays the configuration file under",
    handle.settings.get(PUBLIC_SITE) === false,
    JSON.stringify(handle.settings.get(PUBLIC_SITE)));

  count("the operator who made the change is recorded on the row",
    turnedOff.changedBy === OPERATOR, String(turnedOff.changedBy));
  count("and so is when they made it",
    typeof turnedOff.changedAt === "number" && turnedOff.changedAt > 0,
    String(turnedOff.changedAt));
}

// ---- a name the server reads nowhere, and a value that is not one -----------

async function testTheClosedListAndTheBooleanAreEnforced(handle) {
  await refusesWithTypeError("a setting name this server reads nowhere is refused by " +
    "blamepost.store.settings.set rather than written as a row nothing acts on",
    function () {
      return handle.settings.set({
        name: "publicSiteEnabledd", value: true, reason: "a typed name" });
    });

  await refusesWithTypeError("the reader refuses the same name, rather than answering null " +
    "and leaving the caller following the configuration file forever",
    function () { return handle.settings.get("publicSiteEnabledd"); });

  await refusesWithTypeError("a value that is a string is refused rather than stored by " +
    "whether it is truthy",
    function () {
      return handle.settings.set({ name: PUBLIC_SITE, value: "true", reason: "a checkbox" });
    });

  await refusesWithTypeError("and so is a value that is absent",
    function () { return handle.settings.set({ name: PUBLIC_SITE, reason: "nothing posted" }); });

  await refusesWithTypeError("a call with no options object at all is refused",
    function () { return handle.settings.set(); });

  count("none of the refusals left a row behind",
    handle.settings.get(PUBLIC_SITE) === false,
    JSON.stringify(handle.settings.get(PUBLIC_SITE)));
}

// ---- the change is filed, with both values ----------------------------------

async function testTheChangeIsFiledWithBothValues(handle) {
  var capture = helpers.auditCapture();
  try {
    await handle.settings.set({
      name:      PUBLIC_SITE,
      value:     true,
      changedBy: OPERATOR,
      reason:    "publishing the front page again",
    });
  } finally { capture.release(); }

  var rows = capture.forAction("blamepost.store.settings.changed");
  count("blamepost.store.settings.set files one row for the change",
    rows.length === 1, String(rows.length));
  if (rows.length !== 1) return;

  var row = rows[0];
  count("and the row names the setting as its resource, so an auditor filtering on that " +
    "column reaches every change to one setting",
    row.resourceKind === "setting" && row.resourceId === PUBLIC_SITE,
    String(row.resourceKind) + "/" + String(row.resourceId));
  count("it carries the operator's reason in the column an auditor filters on",
    row.reason === "publishing the front page again", String(row.reason));

  var metadata = helpers.metadataOf(row);
  count("and it carries the setting with the value before the change and the value after it",
    metadata.setting === PUBLIC_SITE && metadata.from === false && metadata.to === true,
    JSON.stringify(metadata));
}

// The first write of a setting has no previous value, and the trail says
// so rather than reporting the false the column would have held. A row
// claiming a change from false to true describes an operator turning
// something off and back on, which is not what happened.
async function testTheFirstWriteReportsNoPreviousValue(handle) {
  var capture = helpers.auditCapture();
  try {
    await handle.settings.set({
      name:      PUBLIC_SITE,
      value:     true,
      changedBy: OPERATOR,
      reason:    "the first answer this volume has held",
    });
  } finally { capture.release(); }

  var rows = capture.forAction("blamepost.store.settings.changed");
  count("the first write of a setting files a row", rows.length === 1, String(rows.length));
  if (rows.length !== 1) return;

  var metadata = helpers.metadataOf(rows[0]);
  count("and the value it reports as the previous one is null rather than false, because " +
    "there was no answer before it",
    metadata.from === null && metadata.to === true, JSON.stringify(metadata));
}

// ---- the answer outlives the process that recorded it -----------------------

async function testTheAnswerSurvivesAReopen(cfg) {
  var first = await store.open(cfg);
  await first.settings.set({
    name:      PUBLIC_SITE,
    value:     true,
    changedBy: OPERATOR,
    reason:    "publishing the front page",
  });
  count("the answer is readable on the handle that wrote it",
    first.settings.get(PUBLIC_SITE) === true,
    JSON.stringify(first.settings.get(PUBLIC_SITE)));
  store.close();

  var second = await store.open(cfg);
  count("and it is still there after the volume is re-encrypted, closed and opened again, " +
    "so a restart does not put the switch back where the configuration file had it",
    second.settings.get(PUBLIC_SITE) === true,
    JSON.stringify(second.settings.get(PUBLIC_SITE)));

  // Writing again on the reopened volume reads what the first process
  // stored as the previous value. The sealed actor column is read on
  // this path, so a row that came back unopenable would surface here
  // rather than as a reader answering correctly off a row nothing can
  // use again.
  var capture = helpers.auditCapture();
  try {
    await second.settings.set({
      name: PUBLIC_SITE, value: false, changedBy: OPERATOR, reason: "after the restart" });
  } finally { capture.release(); }

  var rows = capture.forAction("blamepost.store.settings.changed");
  count("and a change made after the restart reports the value the earlier process stored " +
    "as the one it replaced",
    rows.length === 1 && helpers.metadataOf(rows[0]).from === true,
    rows.length === 1 ? JSON.stringify(helpers.metadataOf(rows[0])) : String(rows.length));
  store.close();
}

// ---- runner ----------------------------------------------------------------

// One volume per group, because the questions need opposite starting
// states: the first group is about a table with no row in it, the second
// about a table that already holds one, and a single volume would make
// each group's answer depend on the order the groups ran in.
async function run() {
  var root    = helpers.tempDir("server-settings");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside the run's own temporary tree keeps the encrypted-at-rest
  // path exactly as it ships rather than opting the test out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  function configFor(name) {
    var dataDir = nodePath.join(root, name);
    return config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
  }

  try {
    var handle = await store.open(configFor("verbs"));

    testAnUntouchedSettingAnswersNull(handle);
    await testTheFirstWriteReportsNoPreviousValue(handle);
    await testBothAnswersRoundTrip(handle);
    await testTheClosedListAndTheBooleanAreEnforced(handle);
    await testTheChangeIsFiledWithBothValues(handle);
    store.close();

    await testTheAnswerSurvivesAReopen(configFor("restart"));
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "server-settings",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
