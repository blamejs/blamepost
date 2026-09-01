// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * smoke-runner-contract: what the orchestrator owes a run it reports on.
 *
 * The contract every test file in this repository is written against,
 * stated once so it can be read rather than reconstructed from the
 * runner. A file:
 *
 *   - exports `run()`, sync or async, returning its check count;
 *   - has a CLI entry under `require.main === module` that prints
 *     `CHECKS <n>` when invoked directly;
 *   - and is spawned by the orchestrator as its own process, which reads
 *     that line out of the child's COMBINED output, stdout and stderr
 *     together, and adds the count to the run total.
 *
 * A change to any one of those three breaks every test file at once, so
 * all three are asserted here: the first two against the files that
 * ship, the third against a fixture that prints its count on the stream
 * a runner reading stdout alone would miss.
 *
 * `test/smoke.js` is the only thing that decides whether a change is
 * green, and every way it can be wrong looks identical to being right.
 * A file that hangs holds the run until the job's wall clock ends it, at
 * which point nothing says which file. A file that exits clean having
 * asserted nothing counts as a passing file. A file that needs a
 * container engine and cannot find one disappears from the totals
 * entirely. All three report the same summary as a run that actually
 * proved something.
 *
 * So the runner's own behavior is asserted here, against fixture files
 * written into a temporary directory and run through the real
 * orchestrator. Each case is one thing the runner must do:
 *
 *   - A file that never exits is killed at the per-file budget, named in
 *     the output, and fails the run. This is the case the parent has to
 *     get right, because the alternative is a multi-hour hang nobody can
 *     attribute.
 *   - A file that exits non-zero is named and fails.
 *   - A file that exits zero having reported neither a check nor a skip
 *     fails. Silence is not a pass: a missing self-invocation and a
 *     guard that returned early both land there, and both are invisible
 *     in a total.
 *   - A file that reports a skip is not a failure and is not a pass
 *     either. The skip is counted apart from the checks, so no total is
 *     inflated by a check that could not run.
 *   - A file that needs a container engine is run when one answers,
 *     reported BY NAME when one does not, and never counted as passing
 *     in either case. Under `SMOKE_REQUIRE_CONTAINER=1` an absent engine
 *     refuses the whole run up front instead, which is what a release or
 *     a CI runner wants: the tool being missing is the finding.
 *   - A malformed per-file budget refuses at startup rather than falling
 *     back to a default, so an operator who mistyped the variable is
 *     told instead of quietly getting a budget they did not choose.
 *
 * The last two cases also run against the REAL tree, in the runner's
 * listing mode, so the classification is proven on the files that ship
 * rather than on fixtures alone: every integration file that gates
 * itself on a container engine has to be one the runner already knows
 * needs one, or the runner would spawn it and read the engine's absence
 * as a defect in the server. That scan carries a canary, so a matcher
 * that has stopped matching fails here rather than reporting agreement.
 *
 * No sockets and no database. It writes fixture files to a temporary
 * directory and spawns the orchestrator over them.
 *
 * Run standalone: node test/layer-0-primitives/smoke-runner-contract.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var spawnRun  = require("../helpers/spawn");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var SMOKE_JS   = nodePath.join(helpers.REPO_ROOT, "test", "smoke.js");
var LAYER_2_DIR = nodePath.join(helpers.REPO_ROOT, "test", "layer-2-integration");

// A command name nothing on any machine resolves, so the engine probe
// answers "absent" the same way on a laptop that has docker and on a
// runner that does not. Simulating absence by uninstalling anything is
// not an option, and reading the real answer would make the case pass
// or fail by accident of the host.
var ABSENT_ENGINE = "blamepost-no-such-container-engine";

// Every spawn of the orchestrator gets a ceiling well above what a
// two-file fixture run costs. It exists so a runner that does NOT reap
// its children fails this file in seconds instead of inheriting the hang
// it was supposed to prevent.
var RUN_CEILING_MS = 30000;

// The fixture layer directory has to match the runner's discovery shape
// (`layer-<n>-<name>`) without colliding with a real layer number.
var FIXTURE_LAYER = "layer-9-runner-fixtures";

// The helpers module, by absolute path, for the fixtures that have to
// load the real one. A fixture lives in a temporary directory, so the
// relative require every shipped file uses does not resolve from there,
// and a fixture that quietly failed to load the module under test would
// prove nothing while looking like it had. JSON quoting is what makes a
// Windows path a valid string literal in the generated file.
var HELPERS_PATH = JSON.stringify(
  nodePath.join(helpers.REPO_ROOT, "test", "helpers", "index.js"));

// ---------------------------------------------------------------------------
// Fixture files
// ---------------------------------------------------------------------------
//
// Each one is the smallest program that produces the shape under test.
// They are written at run time rather than committed, because a file
// that hangs on purpose sitting inside a real layer directory would be
// discovered by every other run of the suite.

var FIXTURES = {
  "passes.test.js":
    '"use strict";\n' +
    'console.log("fixture: three checks");\n' +
    'console.log("CHECKS 3");\n',

  "hangs.test.js":
    '"use strict";\n' +
    'console.log("fixture: holding the event loop open on purpose");\n' +
    'setInterval(function () { /* never exits */ }, 1000);\n',

  "crashes.test.js":
    '"use strict";\n' +
    'console.error("fixture: failing on purpose");\n' +
    'process.exit(1);\n',

  "asserts-nothing.test.js":
    '"use strict";\n' +
    'console.log("fixture: exiting clean having asserted nothing");\n',

  "only-skips.test.js":
    '"use strict";\n' +
    'console.log("  SKIP: fixture: the endpoint this would check is not present here");\n' +
    'console.log("CHECKS 0");\n',

  // Reports its count on stderr. A runner reading stdout alone would
  // score this file zero and then fail it for asserting nothing, so the
  // combined-output half of the contract is what this fixture pins.
  "checks-on-stderr.test.js":
    '"use strict";\n' +
    'console.error("CHECKS 5");\n',

  // Opens with the harness's engine gate, the way every file that drives
  // the shipped image does. There is no such module beside it, so
  // running this file throws. That is the point: the case asserts it is
  // never run.
  "needs-container.test.js":
    '"use strict";\n' +
    'var harness = require("./container-harness");\n' +
    'harness.requireStack("needs-container.test.js");\n' +
    'console.log("CHECKS 1");\n',

  // Names the harness without ever asking it for an engine, which is
  // what a file that compares itself against the harness does. It has to
  // run with no engine anywhere: classifying on the mention rather than
  // on the gate would silently drop a case that needs nothing installed.
  "names-the-harness.test.js":
    '"use strict";\n' +
    'var note = "container-harness";\n' +
    'console.log("fixture: mentions " + note + " and asks it for nothing");\n' +
    'console.log("CHECKS 1");\n',

  // A run that had already decided its verdict, with a rejection
  // arriving on the way out. Both halves are real: the check that failed
  // is the finding, and the rejection is what a store closed under a
  // write in flight produces during teardown.
  //
  // The exit code is set rather than the process exited, because
  // `process.exit()` inside the rejection callback ends the process
  // during the same microtask drain the unhandled rejection is decided
  // in, so the case would turn on scheduling instead of on the handler.
  "leaks-and-fails.test.js":
    '"use strict";\n' +
    'var helpers = require(' + HELPERS_PATH + ');\n' +
    'async function run() {\n' +
    '  Promise.reject(new Error("fixture: a store closed under a write in flight"));\n' +
    '  helpers.check("fixture: the assertion this run actually decided on", false);\n' +
    '  return helpers.getChecks();\n' +
    '}\n' +
    'if (require.main === module) {\n' +
    '  Promise.resolve().then(run).then(\n' +
    '    function (n) { console.log("CHECKS " + n); },\n' +
    '    function (e) { console.error(helpers.formatErr(e)); process.exitCode = 1; }\n' +
    '  );\n' +
    '}\n',

  // The same rejection with nothing else wrong. This is the half that
  // decides whether a crashing file can contribute zero checks to a
  // green total: the file reports its count and would otherwise pass.
  "leaks-but-passes.test.js":
    '"use strict";\n' +
    'var helpers = require(' + HELPERS_PATH + ');\n' +
    'async function run() {\n' +
    '  helpers.check("fixture: the check this run did make", true);\n' +
    '  helpers.check("fixture: and the second one", true);\n' +
    '  Promise.reject(new Error("fixture: a spool entry landed after the volume went away"));\n' +
    '  return helpers.getChecks();\n' +
    '}\n' +
    'if (require.main === module) {\n' +
    '  Promise.resolve().then(run).then(\n' +
    '    function (n) { console.log("CHECKS " + n); },\n' +
    '    function (e) { console.error(helpers.formatErr(e)); process.exitCode = 1; }\n' +
    '  );\n' +
    '}\n',
};

// Each case gets the layer directory holding exactly the fixtures it
// named. Leaving the previous case's files behind would quietly change
// what the next one is asserting about, which is the same class of
// mistake this whole file exists to catch.
function writeFixtures(root, names) {
  var layerDir = nodePath.join(root, FIXTURE_LAYER);
  nodeFs.rmSync(layerDir, { recursive: true, force: true });
  nodeFs.mkdirSync(layerDir, { recursive: true });
  names.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(FIXTURES, name)) {
      throw new Error("writeFixtures: no fixture named " + name);
    }
    nodeFs.writeFileSync(nodePath.join(layerDir, name), FIXTURES[name]);
  });
  return layerDir;
}

// ---------------------------------------------------------------------------
// Running the orchestrator
// ---------------------------------------------------------------------------

function runSmoke(env) {
  return spawnRun.runNodeScript([SMOKE_JS], {
    cwd:       helpers.REPO_ROOT,
    env:       Object.assign({}, process.env, env),
    ceilingMs: RUN_CEILING_MS,
  });
}

// The environment a fixture run needs: the discovery root and the log
// destination both point at the temporary directory, so a nested run
// cannot overwrite the log of the run that started it.
function fixtureEnv(root, extra) {
  return Object.assign({
    SMOKE_ROOT:       nodePath.join(root, "layers"),
    SMOKE_OUTPUT_DIR: nodePath.join(root, "output"),
    SMOKE_PARALLEL:   "2",
  }, extra || {});
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

async function aFileThatNeverExitsIsKilledAndNamed(root) {
  writeFixtures(nodePath.join(root, "layers"), ["passes.test.js", "hangs.test.js"]);
  var rv = await runSmoke(fixtureEnv(root, { SMOKE_FILE_TIMEOUT_MS: "2000" }));

  count("hanging file: the run ended on its own rather than hitting this file's ceiling",
    rv.ceilingHit === false, rv.ms + "ms");
  count("hanging file: the run FAILED", rv.code !== 0 && rv.code !== null, "exit " + rv.code);
  count("hanging file: the output NAMES the file that hung",
    rv.out.indexOf("hangs.test.js") !== -1, tail(rv.out, 6));
  count("hanging file: the output says it was killed after the budget rather than merely failing",
    /2000\s*ms/.test(rv.out) || rv.out.indexOf("2000ms") !== -1, tail(rv.out, 6));
  count("hanging file: a killed file is not counted as a passing one",
    rv.out.indexOf("OK: ") === -1, tail(rv.out, 4));
  count("hanging file: the file beside it still ran and reported its checks",
    rv.out.indexOf("passes.test.js") !== -1, tail(rv.out, 8));
}

async function aFileThatExitsNonZeroIsNamedAndFails(root) {
  writeFixtures(nodePath.join(root, "layers"), ["passes.test.js", "crashes.test.js"]);
  var rv = await runSmoke(fixtureEnv(root));

  count("failing file: the run FAILED", rv.code !== 0 && rv.code !== null, "exit " + rv.code);
  count("failing file: the output NAMES the file that failed",
    rv.out.indexOf("crashes.test.js") !== -1, tail(rv.out, 6));
  count("failing file: the failing file's own output is carried into the report",
    rv.out.indexOf("failing on purpose") !== -1, tail(rv.out, 6));
}

async function aFileThatAssertsNothingIsNotAPass(root) {
  writeFixtures(nodePath.join(root, "layers"), ["asserts-nothing.test.js"]);
  var rv = await runSmoke(fixtureEnv(root));

  count("silent file: the run FAILED rather than reporting a passing file",
    rv.code !== 0 && rv.code !== null, "exit " + rv.code);
  count("silent file: the output NAMES the file that asserted nothing",
    rv.out.indexOf("asserts-nothing.test.js") !== -1, tail(rv.out, 6));
  count("silent file: the reason says it exercised nothing",
    /asserted nothing/i.test(rv.out), tail(rv.out, 6));
}

async function aSkipIsCountedApartFromTheChecks(root) {
  writeFixtures(nodePath.join(root, "layers"), ["passes.test.js", "only-skips.test.js"]);
  var rv = await runSmoke(fixtureEnv(root));

  count("reported skip: a file that reported a skip and no check is not a failure",
    rv.code === 0, "exit " + rv.code + ": " + tail(rv.out, 4));
  count("reported skip: the totals carry the three checks the other file reported",
    /\b3 checks passed\b/.test(rv.out), tail(rv.out, 4));
  count("reported skip: the skip is reported separately rather than folded into the checks",
    /1 check\(s\) skipped/.test(rv.out), tail(rv.out, 4));
}

async function aContainerFileIsNamedWhenNoEngineAnswers(root) {
  writeFixtures(nodePath.join(root, "layers"),
    ["passes.test.js", "needs-container.test.js", "names-the-harness.test.js"]);
  var rv = await runSmoke(fixtureEnv(root, { BLAMEPOST_DOCKER_BIN: ABSENT_ENGINE }));

  count("engine absent: the run still reports on the files that need no engine",
    rv.code === 0, "exit " + rv.code + ": " + tail(rv.out, 6));
  count("engine absent: the file that needs one is NAMED rather than vanishing",
    rv.out.indexOf("needs-container.test.js") !== -1, tail(rv.out, 8));
  count("engine absent: the reason names the engine that did not answer",
    rv.out.indexOf(ABSENT_ENGINE) !== -1, tail(rv.out, 8));
  count("engine absent: it is counted as skipped, not as a passing file",
    /1 file\(s\) skipped/.test(rv.out), tail(rv.out, 6));
  count("engine absent: a file that only names the harness is not held behind an engine",
    /\b4 checks passed across 2 file\(s\)/.test(rv.out), tail(rv.out, 6));
  count("engine absent: the skipped file was never spawned",
    rv.out.indexOf("Cannot find module") === -1, tail(rv.out, 8));
}

async function requiringTheEngineRefusesUpFront(root) {
  writeFixtures(nodePath.join(root, "layers"), ["passes.test.js", "needs-container.test.js"]);
  var rv = await runSmoke(fixtureEnv(root, {
    BLAMEPOST_DOCKER_BIN:     ABSENT_ENGINE,
    SMOKE_REQUIRE_CONTAINER:  "1",
  }));

  count("engine required: an absent engine FAILS the run", rv.code !== 0 && rv.code !== null,
    "exit " + rv.code);
  count("engine required: the refusal names the variable that demanded the engine",
    rv.out.indexOf("SMOKE_REQUIRE_CONTAINER") !== -1, tail(rv.out, 6));
  count("engine required: the refusal names the file that needs one",
    rv.out.indexOf("needs-container.test.js") !== -1, tail(rv.out, 6));
  count("engine required: it refuses before running anything rather than after",
    rv.out.indexOf("CHECKS 3") === -1 && !/checks passed/.test(rv.out), tail(rv.out, 6));
}

async function aMalformedBudgetRefusesAtStartup(root) {
  writeFixtures(nodePath.join(root, "layers"), ["passes.test.js"]);
  var rv = await runSmoke(fixtureEnv(root, { SMOKE_FILE_TIMEOUT_MS: "nine hundred seconds" }));

  count("bad budget: the run refused rather than falling back to a default",
    rv.code !== 0 && rv.code !== null, "exit " + rv.code);
  count("bad budget: the refusal names the variable",
    rv.out.indexOf("SMOKE_FILE_TIMEOUT_MS") !== -1, tail(rv.out, 6));
  count("bad budget: nothing ran", !/checks passed/.test(rv.out), tail(rv.out, 6));
}

async function theCountIsReadFromCombinedOutput(root) {
  writeFixtures(nodePath.join(root, "layers"), ["checks-on-stderr.test.js"]);
  var rv = await runSmoke(fixtureEnv(root));

  count("combined output: a file reporting its count on stderr is not a failure",
    rv.code === 0, "exit " + rv.code + ": " + tail(rv.out, 6));
  count("combined output: its checks reach the total",
    /\b5 checks passed\b/.test(rv.out), tail(rv.out, 4));
}

// ---------------------------------------------------------------------------
// A rejection nobody handled, reported under the verdict rather than over it
// ---------------------------------------------------------------------------
//
// Requiring the helpers installs a handler for `unhandledRejection`, and
// what it replaces is Node's default policy: the process is torn down
// where it stands and the rejection's stack is the last thing anybody
// reads. During teardown that is the wrong error, and it is the one that
// costs the most, because the check count the parent reads is lost with
// the process that died before printing it. A file that crashes that way
// contributes zero checks to a total that still says OK.
//
// The handler was written and proven against scratch fixtures, which is
// exactly the coverage that disappears: nothing in the suite drove it,
// so a change that stopped it firing, or a second handler installed
// anywhere in the tree taking these rejections first, would leave it
// looking installed and reporting nothing. These two cases drive the
// REAL runner over fixture files that leak on purpose, one on each
// branch, because the branches say opposite things and only one of them
// can be checked at a time.

async function aLateRejectionIsReportedUnderTheRunsOwnFailure(root) {
  writeFixtures(nodePath.join(root, "layers"), ["leaks-and-fails.test.js"]);
  var rv = await runSmoke(fixtureEnv(root));

  count("late rejection, run already failed: the run FAILED",
    rv.code !== 0 && rv.code !== null, "exit " + rv.code);
  count("late rejection, run already failed: the file is named",
    rv.out.indexOf("leaks-and-fails.test.js") !== -1, tail(rv.out, 12));

  var verdict  = rv.out.indexOf("the assertion this run actually decided on");
  var reported = rv.out.indexOf("LATE REJECTION");
  count("late rejection, run already failed: the run's own failure survived rather than " +
    "being replaced by the teardown's error",
    verdict !== -1, tail(rv.out, 12));
  count("late rejection, run already failed: the rejection is reported as well, so it is " +
    "not swallowed either",
    reported !== -1, tail(rv.out, 12));
  count("late rejection, run already failed: and it is reported UNDER the verdict, which is " +
    "the half that decides which file a reader opens next",
    verdict !== -1 && reported !== -1 && reported > verdict,
    "verdict at " + verdict + ", rejection at " + reported);
  count("late rejection, run already failed: the report says which of the two to read",
    /is the one to read/.test(rv.out), tail(rv.out, 12));
  count("late rejection, run already failed: and quotes what leaked, so the reader is not " +
    "sent looking for it",
    rv.out.indexOf("a store closed under a write in flight") !== -1, tail(rv.out, 12));
}

async function aLateRejectionIsTheFindingWhenNothingElseFailed(root) {
  writeFixtures(nodePath.join(root, "layers"), ["leaks-but-passes.test.js"]);
  var rv = await runSmoke(fixtureEnv(root));

  count("late rejection, run otherwise green: the run FAILED rather than reporting the " +
    "checks and exiting zero",
    rv.code !== 0 && rv.code !== null, "exit " + rv.code);
  count("late rejection, run otherwise green: nothing is summarized as passing",
    rv.out.indexOf("OK: ") === -1 && !/checks passed/.test(rv.out), tail(rv.out, 12));
  count("late rejection, run otherwise green: the file that leaked is named",
    rv.out.indexOf("leaks-but-passes.test.js") !== -1, tail(rv.out, 12));
  count("late rejection, run otherwise green: the report says the rejection IS the finding " +
    "rather than noise beside one",
    /IS the finding/.test(rv.out), tail(rv.out, 12));
  count("late rejection, run otherwise green: and quotes it",
    rv.out.indexOf("a spool entry landed after the volume went away") !== -1,
    tail(rv.out, 12));
}

// ---------------------------------------------------------------------------
// The real tree
// ---------------------------------------------------------------------------

// The three-part contract, read off the files that ship. Every one of
// them is spawned by the orchestrator and scored on what it prints, so a
// file that drifts from any part of it either scores zero or fails, and
// a change to the contract itself breaks all of them at once.
function everyTestFileMeetsTheContract() {
  var testRoot = nodePath.join(helpers.REPO_ROOT, "test");
  var seen = [];
  nodeFs.readdirSync(testRoot, { withFileTypes: true })
    .filter(function (e) { return e.isDirectory() && /^layer-\d+-/.test(e.name); })
    .forEach(function (e) {
      var dir = nodePath.join(testRoot, e.name);
      nodeFs.readdirSync(dir)
        .filter(function (f) { return f.endsWith(".test.js"); })
        .forEach(function (f) {
          seen.push({
            name:   e.name + " / " + f,
            source: nodeFs.readFileSync(nodePath.join(dir, f), "utf8"),
          });
        });
    });

  // Canary: a scan that found no test file would agree with every claim
  // made about them.
  count("contract: the scan still finds the test files", seen.length > 0,
    seen.length + " file(s)");

  var noRun = seen.filter(function (t) {
    return !/module\.exports\s*=\s*\{[\s\S]{0,200}?\brun\s*:/.test(t.source);
  });
  count("contract: every test file exports run()", noRun.length === 0,
    noRun.map(function (t) { return t.name; }).join(", "));

  var noCli = seen.filter(function (t) {
    return t.source.indexOf("require.main === module") === -1;
  });
  count("contract: every test file has a CLI entry, so it runs on its own",
    noCli.length === 0, noCli.map(function (t) { return t.name; }).join(", "));

  var noChecks = seen.filter(function (t) {
    return !/console\.log\(\s*"CHECKS "/.test(t.source);
  });
  count("contract: every test file prints the CHECKS line the parent reads",
    noChecks.length === 0, noChecks.map(function (t) { return t.name; }).join(", "));
}

// The runner's listing mode answers which files it would run and which
// it would skip, without running any of them, so the classification can
// be asserted against the shipped integration layer in a second rather
// than by standing up thirty listeners.
async function theShippedIntegrationLayerIsClassifiedCorrectly(root) {
  var rv = await runSmoke({
    SMOKE_LIST:           "1",
    SMOKE_OUTPUT_DIR:     nodePath.join(root, "output-list"),
    BLAMEPOST_DOCKER_BIN: ABSENT_ENGINE,
  });

  count("listing: the runner answered", rv.code === 0, "exit " + rv.code + ": " + tail(rv.out, 6));

  // Every integration file that opens with the harness's engine gate is
  // a file the runner has to recognize as needing an engine. One that it
  // spawns anyway reports the engine's absence as a failed assertion
  // about the server, which is the wrong finding entirely.
  var gated = nodeFs.readdirSync(LAYER_2_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .filter(function (f) {
      var src = nodeFs.readFileSync(nodePath.join(LAYER_2_DIR, f), "utf8");
      return src.indexOf("requireStack(") !== -1;
    });

  // Canary: a scan that has stopped matching agrees with everything.
  count("listing: the scan still finds the files that gate themselves on an engine",
    gated.length > 0, gated.length + " file(s)");

  var listed = rv.out.split(/\r?\n/);
  function lineFor(name) {
    return listed.filter(function (l) { return l.indexOf(name) !== -1; }).join(" | ");
  }
  gated.forEach(function (name) {
    var line = lineFor(name);
    count("listing: " + name + " is named as needing a container engine",
      /skip/i.test(line), line || "(not listed at all)");
  });

  // And the counterpart: an integration file that builds the server in
  // process is planned to RUN with no engine anywhere, which is the
  // coverage this gating exists to unlock.
  var inProcess = nodeFs.readdirSync(LAYER_2_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .filter(function (f) { return gated.indexOf(f) === -1; });
  count("listing: the scan still finds the files that need no engine",
    inProcess.length > 0, inProcess.length + " file(s)");
  var wronglySkipped = inProcess.filter(function (name) {
    return /skip/i.test(lineFor(name));
  });
  count("listing: no file that builds the server in process is held behind an engine",
    wronglySkipped.length === 0, wronglySkipped.join(", "));

  // A file can import the harness to compare itself against it and never
  // ask it for an engine. Classifying on the import rather than on the
  // gate call would drop that file from every run on a machine with no
  // engine, and it needs nothing installed at all.
  var borrowers = [];
  nodeFs.readdirSync(nodePath.join(helpers.REPO_ROOT, "test"), { withFileTypes: true })
    .filter(function (e) { return e.isDirectory() && /^layer-\d+-/.test(e.name); })
    .forEach(function (e) {
      var dir = nodePath.join(helpers.REPO_ROOT, "test", e.name);
      nodeFs.readdirSync(dir)
        .filter(function (f) { return f.endsWith(".test.js"); })
        .forEach(function (f) {
          var src = nodeFs.readFileSync(nodePath.join(dir, f), "utf8");
          if (src.indexOf("container-harness") !== -1 && src.indexOf("requireStack(") === -1) {
            borrowers.push(f);
          }
        });
    });
  count("listing: the scan still finds a file that imports the harness without gating on it",
    borrowers.length > 0, borrowers.join(", "));
  var borrowersHeldBack = borrowers.filter(function (name) {
    return /skip/i.test(lineFor(name));
  });
  count("listing: a file that imports the harness without asking for an engine still runs",
    borrowersHeldBack.length === 0, borrowersHeldBack.join(", "));

  // This file writes the gate call into a fixture and quotes its name in
  // an assertion, so a classifier reading source text alone can mistake
  // writing about the gate for making it. A test held behind an engine
  // it never touches stops running on every machine without one, which
  // is the failure this gating exists to prevent rather than to cause.
  var self = nodePath.basename(__filename);
  count("listing: a file that only writes about the gate is not held behind an engine",
    !/skip/i.test(lineFor(self)), lineFor(self) || "(not listed at all)");
}

// ---------------------------------------------------------------------------

async function run() {
  var root = helpers.tempDir("runner");
  try {
    nodeFs.mkdirSync(nodePath.join(root, "layers"), { recursive: true });

    everyTestFileMeetsTheContract();
    await theCountIsReadFromCombinedOutput(root);
    await aFileThatNeverExitsIsKilledAndNamed(root);
    await aFileThatExitsNonZeroIsNamedAndFails(root);
    await aFileThatAssertsNothingIsNotAPass(root);
    await aSkipIsCountedApartFromTheChecks(root);
    await aContainerFileIsNamedWhenNoEngineAnswers(root);
    await requiringTheEngineRefusesUpFront(root);
    await aMalformedBudgetRefusesAtStartup(root);
    await aLateRejectionIsReportedUnderTheRunsOwnFailure(root);
    await aLateRejectionIsTheFindingWhenNothingElseFailed(root);
    await theShippedIntegrationLayerIsClassifiedCorrectly(root);
  } finally {
    helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "smoke-runner-contract", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
