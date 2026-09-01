// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * interop-gate-contract: the release gate that proves nothing says so.
 *
 * `scripts/test-integration.js` runs the interop suite: files that drive
 * a running server from the outside with clients that are not this
 * codebase. `node scripts/release.js` runs it inside the smoke and push
 * phases and treats a failure as a hard stop.
 *
 * Three states, and only one of them is green.
 *
 *   - Files exist and pass. The gate ran and proved something.
 *   - Files exist and one fails. A hard stop, or an audited override
 *     that prints the reason it was overridden.
 *   - No file exists. Nothing was proven, and that is neither of the
 *     above. It has its own exit code, it is printed as nothing proven,
 *     and the release flow publishes it as a gate that did not run. The
 *     directory is tracked and wired up, so its absence stays a broken
 *     tree rather than collapsing into the empty case.
 *
 * The state worth guarding is the third one, because the easy way to
 * make a release command pass is to report an empty suite as "OK, 0
 * checks passed" and the easy way to make it fail is to hard stop
 * forever, which trains an operator to pass the override on every cut
 * until the override stops meaning anything.
 *
 * The other thing asserted here is where the runner points. The layered
 * suites build the server inside the test process on ephemeral loopback
 * ports; they prove nothing about what another implementation makes of
 * the bytes, and pointing this runner at them would report a green
 * interop gate for a suite that has no interop in it.
 *
 * No sockets and no database. It spawns the two gate scripts and reads
 * what they say.
 *
 * Run standalone: node test/layer-0-primitives/interop-gate-contract.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var INTEGRATION_DIR = nodePath.join(helpers.REPO_ROOT, "test", "integration");
var RUN_CEILING_MS  = 60000;

function runNode(argv) {
  return spawnRun.runNodeScript(argv, {
    cwd:       helpers.REPO_ROOT,
    ceilingMs: RUN_CEILING_MS,
  });
}

function theSuiteDirectoryIsTracked() {
  count("interop suite: the directory the runner reads exists in the tree",
    nodeFs.existsSync(INTEGRATION_DIR), INTEGRATION_DIR);

  var entries = nodeFs.readdirSync(INTEGRATION_DIR);
  count("interop suite: it carries the contract a file has to meet",
    entries.indexOf("README.md") !== -1, entries.join(", "));
}

async function anEmptySuiteReportsNothingProven() {
  var files = nodeFs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); });

  // Everything below describes the empty state. Once an interop file
  // lands, the runner takes a different path and these cases stop being
  // the ones that matter, so say which state was observed rather than
  // asserting the empty one is permanent.
  if (files.length > 0) {
    helpers.skip("the interop suite now holds " + files.length + " file(s), so the " +
      "empty-suite path is not the one this run exercises; a run of the suite itself " +
      "is what covers it from here");
    return;
  }

  var rv = await runNode(["scripts/test-integration.js"]);

  count("empty suite: it exits with the code that means nothing was proven",
    rv.code === 4, "exit " + rv.code);
  count("empty suite: it says so in as many words",
    /nothing was proven/i.test(rv.out) && /not a pass/i.test(rv.out), rv.out.trim());
  count("empty suite: it never reports checks passing",
    !/checks passed/i.test(rv.out), rv.out.trim());
  count("empty suite: it names the directory an interop file belongs in",
    rv.out.indexOf("test/integration/") !== -1, rv.out.trim());

  // The service gate probes real mail ports and prints a table of what
  // is down. Running it for a suite with nothing in it would report a
  // stack that is not up as the reason, which is a true statement about
  // the machine and the wrong answer to the question asked.
  count("empty suite: it does not probe listeners for a suite with nothing in it",
    rv.out.indexOf("[check-services]") === -1, rv.out.trim());
}

async function theReleaseFlowPublishesTheGateAsNotRun() {
  var files = nodeFs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); });
  if (files.length > 0) {
    helpers.skip("the interop suite now holds " + files.length + " file(s), so the release " +
      "flow runs the gate rather than reporting it as not run");
    return;
  }

  var rv = await runNode(["scripts/release.js", "interop"]);

  count("release flow: an empty suite does not stop the flow",
    rv.code === 0, "exit " + rv.code + ": " + tail(rv.out, 4));
  count("release flow: it prints that the gate did not run",
    /did not run/i.test(rv.out), tail(rv.out, 6));
  count("release flow: it never calls the gate green",
    !/interop green/i.test(rv.out), tail(rv.out, 6));
  count("release flow: it says the state is not a pass",
    /not a pass/i.test(rv.out), tail(rv.out, 6));
}

// The runner and the layered suites answer different questions, and the
// cheap way to make this command pass is to point it at the suite that
// already runs. That would report a green interop gate for files that
// never speak to anything outside this codebase, and would run them
// twice.
async function theRunnerIsNotPointedAtTheLayeredSuites() {
  var rv = await runNode(["scripts/test-integration.js"]);
  var namesALayer = /layer-\d+-/.test(rv.out);
  count("suite target: the runner does not read a layered suite directory",
    namesALayer === false, rv.out.trim());

  var layered = nodeFs.readdirSync(nodePath.join(helpers.REPO_ROOT, "test"), { withFileTypes: true })
    .filter(function (e) { return e.isDirectory() && /^layer-\d+-/.test(e.name); })
    .map(function (e) { return e.name; });
  // Canary: a scan that finds no layered suite would agree with anything.
  count("suite target: the layered suites are still where they were",
    layered.length >= 3, layered.join(", "));
  count("suite target: the interop suite is not one of them",
    layered.indexOf("integration") === -1, layered.join(", "));
}

async function run() {
  theSuiteDirectoryIsTracked();
  await anEmptySuiteReportsNothingProven();
  await theReleaseFlowPublishesTheGateAsNotRun();
  await theRunnerIsNotPointedAtTheLayeredSuites();
  return helpers.getChecks();
}

module.exports = { name: "interop-gate-contract", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
