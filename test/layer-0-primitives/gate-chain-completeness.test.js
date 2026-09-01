// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * gate-chain-completeness: a gate that did not run is not a gate that
 * passed, and the direction a count moved is not evidence about what the
 * count means.
 *
 * Two failures, one shape. Both are a verdict that was never reached being
 * presented as though it were a clean one.
 *
 *   - THE CHAIN. The static gates used to be joined with `&&`, which stops
 *     at the first failing link. Everything after it does not run, and the
 *     output says nothing about them at all: the transcript simply ends.
 *     Measured on this tree, one failing first link hid seven gates, and
 *     the only way to learn they were green was to run each by hand. This
 *     is the `EXAMINED <n> <unit>` contract failing from the other side. A
 *     gate that examined an empty set answers for no part of the tree, and
 *     so does one that never started; the second is quieter, because it
 *     publishes nothing to notice.
 *
 *   - THE ARRAY. An exported array's change used to be classified by the
 *     DIRECTION of its length: shorter meant members were lost and
 *     therefore breaking. That is right for a list of what the package
 *     OFFERS and exactly backwards for a list of what it REQUIRES, or of
 *     what it cannot yet do. A limitation lifted shortens such a list, and
 *     the gate called the removal of a defect a removal of surface. Both
 *     misreadings have been seen here: a required-method list reported
 *     breaking when a requirement MOVED to a sibling list, and the
 *     certificate-rotation exception list reported breaking when its last
 *     entry was fixed. A count has no polarity, so no rule over a count can
 *     have one either.
 *
 * WHAT IS DRIVEN. The runner is driven the way a workflow drives it: a
 * child process, a declared list, an exit code and a transcript. The gate
 * stand-ins are written to a temporary directory rather than into the
 * working tree, because a fixture gate committed beside the real ones is a
 * gate the real chain would then have to explain. The classifier is driven
 * through its exported compare, and the source declarations through the
 * reader that finds them, against fixture sources on disk.
 *
 * Nothing here reaches into either module's internals. What was wrong in
 * both cases was an answer, so the answer is what is asserted.
 *
 * No sockets and no database. It spawns node processes and reads files.
 *
 * Run standalone:
 * node test/layer-0-primitives/gate-chain-completeness.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");
var snap     = require("../../scripts/refresh-api-snapshot.js");
var sourcePrimitives = require("../../scripts/source-primitives.js");
var examinedCounts   = require("../../scripts/examined-counts.js");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var REPO_ROOT    = helpers.REPO_ROOT;
var RUN_GATES_JS = nodePath.join(REPO_ROOT, "scripts", "run-gates.js");
var PACKAGE_JSON = nodePath.join(REPO_ROOT, "package.json");

// The npm key the workflow invokes, and the runner it has to reach. Both
// are frozen contracts: the key is what package.json publishes and CI types
// `npm run gates`, and the runner is the file that key names.
var CHAIN_KEY   = "gates";
var RUNNER_PATH = "scripts/run-gates.js";

var RUN_CEILING_MS = 60000;

// ---------------------------------------------------------------------------
// Gate stand-ins
// ---------------------------------------------------------------------------

// Each stand-in prints one line naming itself, publishes what it examined,
// and exits with the code the vector asked for. The naming line is the
// evidence that a gate RAN, which under the old chain is exactly what was
// missing for everything behind the first failure. The count is the evidence
// that it looked at anything, which is the other half of the same question:
// a gate that ran and examined an empty set answers for no part of the tree
// either, and it is the quieter of the two because it does print something.
//
// `publishes` overrides the count lines outright, which is how a vector
// spells the ways a gate stops answering: a zero, no line at all, or one
// empty unit among several. Passing an empty array is the second of those,
// and it has to be distinguishable from passing nothing, so the default is
// applied only when the argument is absent.
function _standInGate(dir, name, exitCode, publishes) {
  var lines = ['console.log("' + name + ': this gate ran");'];
  var published = publishes === undefined ? ["EXAMINED 7 fixture-units"] : publishes;
  published.forEach(function (line) { lines.push('console.log("' + line + '");'); });
  var file = nodePath.join(dir, name + ".js");
  nodeFs.writeFileSync(file,
    '"use strict";\n' + lines.join("\n") + "\n" +
    "process.exit(" + exitCode + ");\n");
  return file;
}

// A gate command as the declared list writes them: `node <path>`. The path
// is made relative to the repository root so the token carries no space on
// any tree layout, and the runner resolves it the same way it resolves the
// real ones.
function _gateCommand(file) {
  var rel = nodePath.relative(REPO_ROOT, file).split(nodePath.sep).join("/");
  return "node " + rel;
}

// Every run here is pointed at a summary log of its own. The runner
// persists its verdicts so a failing chain leaves them on disk, and these
// cases drive it dozens of times: without the override they would each
// overwrite the summary of the last real `npm run gates`, leaving the log
// the failure discipline says to read first describing stand-in gates from
// a temporary directory.
var _runnerLogDir = null;

function _runnerLog() {
  if (_runnerLogDir === null) _runnerLogDir = helpers.tempDir("gateslog");
  return nodePath.join(_runnerLogDir, "gates.log");
}

async function _runRunner(commands) {
  var env = Object.assign({}, process.env, { BLAMEPOST_GATES_LOG: _runnerLog() });
  return spawnRun.runNodeScript([RUN_GATES_JS].concat(commands), {
    cwd:       REPO_ROOT,
    env:       env,
    ceilingMs: RUN_CEILING_MS,
  });
}

// The override is a fixture affordance, so it is held to being one: the
// runner still writes its summary, and it writes it where it was told.
async function theVerdictSummaryIsPersistedWhereItWasTold() {
  var dir = helpers.tempDir("gatelogged");
  await _runRunner([_gateCommand(_standInGate(dir, "logged", 0))]);
  var written = nodeFs.readFileSync(_runnerLog(), "utf8");
  count("the runner persists its verdict summary, so a failing run leaves it on disk",
    /logged\.js\s+passed/.test(written) && /EXAMINED 1 published-counts/.test(written),
    written.slice(-200));
  helpers.removeTempDir(dir);
}

// ---------------------------------------------------------------------------
// The chain: every gate runs, whatever the ones before it did
// ---------------------------------------------------------------------------

// The live defect, reproduced. An early gate fails and four gates sit
// behind it. Under the shape this replaces, none of the four leave a trace:
// no output, no verdict, no mention. The reader is handed one red and four
// silences, and a silence reads as a red.
async function anEarlyFailureDoesNotHideTheGatesBehindIt() {
  var dir = helpers.tempDir("gatechain");
  var commands = [
    _gateCommand(_standInGate(dir, "cheap-first", 0)),
    _gateCommand(_standInGate(dir, "the-one-that-fails", 1)),
    _gateCommand(_standInGate(dir, "behind-it-one", 0)),
    _gateCommand(_standInGate(dir, "behind-it-two", 0)),
    _gateCommand(_standInGate(dir, "behind-it-three", 0)),
  ];
  var run = await _runRunner(commands);

  count("early failure: every gate behind the failing one still ran",
    run.out.indexOf("behind-it-one: this gate ran") !== -1 &&
    run.out.indexOf("behind-it-two: this gate ran") !== -1 &&
    run.out.indexOf("behind-it-three: this gate ran") !== -1,
    tail(run.out, 12));

  count("early failure: each gate behind it reports a verdict of its own",
    /behind-it-one\.js\s+passed/.test(run.out) &&
    /behind-it-two\.js\s+passed/.test(run.out) &&
    /behind-it-three\.js\s+passed/.test(run.out),
    tail(run.out, 14));

  count("early failure: the failing gate is named as failed",
    /the-one-that-fails\.js\s+FAILED/.test(run.out), tail(run.out, 14));

  count("early failure: the failure still reaches the exit code",
    run.code === 1, "exit " + run.code + ": " + tail(run.out, 6));

  count("early failure: the summary names the failing gate and only it",
    /FAILED \(1\): .*the-one-that-fails/.test(run.out) &&
    run.out.indexOf("NOT RUN (") === -1,
    tail(run.out, 10));

  count("early failure: it never reports the run as clean",
    run.out.indexOf("ran and passed") === -1, tail(run.out, 10));

  helpers.removeTempDir(dir);
}

// Declared order is what "cheapest first" means, and it has to survive the
// change that stopped a failure from ending the run. Cheapest-first is
// about how soon a failure is SEEN; it was never a reason for the expensive
// gates to go unmeasured.
async function theDeclaredOrderIsKept() {
  var dir = helpers.tempDir("gateorder");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "first", 0)),
    _gateCommand(_standInGate(dir, "second", 0)),
    _gateCommand(_standInGate(dir, "third", 0)),
  ]);
  var at = ["first", "second", "third"].map(function (n) {
    return run.out.indexOf(n + ": this gate ran");
  });
  count("declared order: the gates ran in the order they were declared",
    at[0] !== -1 && at[0] < at[1] && at[1] < at[2], JSON.stringify(at));
  helpers.removeTempDir(dir);
}

// The other way a gate stops answering. Absence is how a gate is got past
// without anyone deciding to get past it, so it is a finding rather than a
// skip, and the gate is NAMED rather than folded into the count of what
// ran.
async function anAbsentGateIsNamedAsNotRun() {
  var dir = helpers.tempDir("gateabsent");
  var missing = nodePath.join(dir, "never-written.js");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "present-one", 0)),
    _gateCommand(missing),
    _gateCommand(_standInGate(dir, "present-two", 0)),
  ]);

  count("absent gate: the run does not exit clean",
    run.code === 1, "exit " + run.code + ": " + tail(run.out, 6));
  count("absent gate: it is named as NOT RUN rather than passed",
    /never-written\.js\s+NOT RUN/.test(run.out), tail(run.out, 12));
  count("absent gate: the summary says a gate that did not run is not a pass",
    /NOT RUN \(1\)/.test(run.out) && /not a pass/.test(run.out), tail(run.out, 10));
  count("absent gate: the gate after it still ran",
    run.out.indexOf("present-two: this gate ran") !== -1, tail(run.out, 12));
  count("absent gate: the count of gates that ran excludes it",
    /EXAMINED 3 declared-gates/.test(run.out) && /EXAMINED 2 gates-run/.test(run.out),
    tail(run.out, 6));

  helpers.removeTempDir(dir);
}

// A declared list that arrived empty would run nothing and, without this,
// exit clean: a perfect score over no gates, which is the verdict the whole
// counted-gate discipline exists to refuse.
async function anEmptyDeclaredListIsRefused() {
  var run = await _runRunner([]);
  count("empty list: the run is refused rather than reported clean",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 4));
  count("empty list: it says where the list is supposed to come from",
    run.out.indexOf("scripts.gates") !== -1, tail(run.out, 6));
  count("empty list: both counts are published as zero rather than omitted",
    /EXAMINED 0 declared-gates/.test(run.out) && /EXAMINED 0 gates-run/.test(run.out),
    tail(run.out, 6));
}

// A gate the runner cannot read is the short-circuit reached by another
// door: skipping it would shrink the declared list silently, which is the
// one outcome none of this may produce. So an unreadable list stops the
// run rather than running the part of it that parsed.
async function aGateThatCannotBeParsedStopsTheRun() {
  var dir = helpers.tempDir("gateparse");
  var good = _gateCommand(_standInGate(dir, "would-have-run", 0));

  var notNode = await _runRunner([good, "bash scripts/something.sh"]);
  count("unparseable gate: a command that is not a node invocation is refused",
    notNode.code === 1 && /does not parse/.test(notNode.out), tail(notNode.out, 6));
  count("unparseable gate: the run does not proceed with the links that did parse",
    notNode.out.indexOf("would-have-run: this gate ran") === -1, tail(notNode.out, 8));
  count("unparseable gate: it publishes what it was handed and that it ran none",
    /EXAMINED 2 declared-gates/.test(notNode.out) && /EXAMINED 0 gates-run/.test(notNode.out),
    tail(notNode.out, 6));

  var quoted = await _runRunner([good, 'node scripts/x.js --flag="a b"']);
  count("unparseable gate: a quoted argument is refused rather than mis-split",
    quoted.code === 1 && /carries a quote/.test(quoted.out), tail(quoted.out, 6));

  helpers.removeTempDir(dir);
}

// The control. Without it a runner that refused everything would satisfy
// every vector above.
async function aCleanRunReportsEveryGatePassed() {
  var dir = helpers.tempDir("gateclean");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "alpha", 0)),
    _gateCommand(_standInGate(dir, "beta", 0)),
  ]);
  count("clean run: it exits clean", run.code === 0,
    "exit " + run.code + ": " + tail(run.out, 6));
  count("clean run: every gate is named as passed",
    /alpha\.js\s+passed/.test(run.out) && /beta\.js\s+passed/.test(run.out),
    tail(run.out, 10));
  count("clean run: it says so once, over the gates it actually ran",
    run.out.indexOf("all 2 declared gates ran, answered, and passed") !== -1, tail(run.out, 10));
  count("clean run: the three counts agree",
    /EXAMINED 2 declared-gates/.test(run.out) && /EXAMINED 2 gates-run/.test(run.out) &&
    /EXAMINED 2 published-counts/.test(run.out),
    tail(run.out, 8));
  helpers.removeTempDir(dir);
}

// Several failures at once. An operator wants every failing gate out of ONE
// pass; reporting the first and stopping is the defect this file is about,
// arriving one layer up.
async function everyFailingGateIsReportedFromOnePass() {
  var dir = helpers.tempDir("gatemany");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "fails-early", 1)),
    _gateCommand(_standInGate(dir, "passes-between", 0)),
    _gateCommand(_standInGate(dir, "fails-late", 2)),
  ]);
  count("several failures: both are named in one summary",
    /FAILED \(2\)/.test(run.out) &&
    run.out.indexOf("fails-early") !== -1 && run.out.indexOf("fails-late") !== -1,
    tail(run.out, 12));
  count("several failures: each carries the exit code it produced",
    /fails-early\.js\s+FAILED\s+\(exit 1\)/.test(run.out) &&
    /fails-late\.js\s+FAILED\s+\(exit 2\)/.test(run.out), tail(run.out, 14));
  count("several failures: the gate between them is still reported passed",
    /passes-between\.js\s+passed/.test(run.out), tail(run.out, 14));
  count("several failures: the run exits non-zero",
    run.code === 1, "exit " + run.code);
  helpers.removeTempDir(dir);
}

// ---------------------------------------------------------------------------
// The count, read where the gates are actually run
// ---------------------------------------------------------------------------

// The live defect. The project's contract says a gate exiting clean over an
// empty set stops the cut, and that refusal lived in scripts/release.js
// alone. So a gate publishing `EXAMINED 0` passed `npm run gates`, passed
// CI, and was caught only if somebody happened to run a release. Measured on
// this runner before the fix: exit 0, and the summary line "all 2 declared
// gates ran and passed".
async function aGateThatExaminedNothingIsRefused() {
  var dir = helpers.tempDir("gatecount");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "looked-at-things", 0)),
    _gateCommand(_standInGate(dir, "looked-at-nothing", 0, ["EXAMINED 0 scanned-files"])),
  ]);

  count("empty count: the run does not exit clean",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("empty count: the gate that examined nothing is named",
    /looked-at-nothing\.js\s+UNANSWERED/.test(run.out), tail(run.out, 12));
  count("empty count: the unit it published as zero is named",
    /published 0 scanned-files/.test(run.out), tail(run.out, 12));
  count("empty count: it says an empty set is not a pass",
    /not a pass/.test(run.out) && /empty set/.test(run.out), tail(run.out, 12));
  count("empty count: the gate that did look at something still passes",
    /looked-at-things\.js\s+passed/.test(run.out), tail(run.out, 12));
  count("empty count: it never reports the run as clean",
    run.out.indexOf("ran, answered, and passed") === -1, tail(run.out, 12));

  helpers.removeTempDir(dir);
}

// The other way to stop answering, and the reason there is no exemption
// list: a gate that publishes no count has not said what it looked at, so
// nothing distinguishes its clean exit from a clean exit over nothing.
async function aGateThatPublishesNoCountIsRefused() {
  var dir = helpers.tempDir("gatesilent");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "answers", 0)),
    _gateCommand(_standInGate(dir, "says-nothing", 0, [])),
  ]);

  count("no count: the run does not exit clean",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("no count: the silent gate is named UNANSWERED rather than passed",
    /says-nothing\.js\s+UNANSWERED/.test(run.out), tail(run.out, 12));
  count("no count: the reason distinguishes it from a published zero",
    /published no EXAMINED or CHECKS count/.test(run.out), tail(run.out, 12));
  count("no count: the gate that answered still passes",
    /answers\.js\s+passed/.test(run.out), tail(run.out, 12));

  helpers.removeTempDir(dir);
}

// The unit is load-bearing rather than decoration. A gate that opened its
// files and extracted nothing from them publishes a healthy first number,
// and a reader that stopped at it would call the run measured.
async function oneEmptyUnitAmongSeveralIsRefused() {
  var dir = helpers.tempDir("gateunits");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "opened-but-read-nothing", 0,
      ["EXAMINED 22 lib-source-files", "EXAMINED 0 primitive-blocks"])),
  ]);

  count("one empty unit: a healthy first number does not carry the second",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("one empty unit: the refusal names the unit that was empty",
    /published 0 primitive-blocks/.test(run.out), tail(run.out, 10));
  count("one empty unit: it does not name the unit that was not",
    run.out.indexOf("0 lib-source-files") === -1, tail(run.out, 10));

  helpers.removeTempDir(dir);
}

// The detector suite answers in `CHECKS <n>`, frozen in that spelling
// because test/smoke.js reads it too. A runner that accepted only EXAMINED
// would report the one gate carrying every structural rule in the tree as
// the gate that never answered.
async function theDetectorSuitesCountWordIsAccepted() {
  var dir = helpers.tempDir("gatechecks");
  var ok = await _runRunner([
    _gateCommand(_standInGate(dir, "detector-shaped", 0, ["CHECKS 878"])),
  ]);
  count("CHECKS is accepted as a published count",
    ok.code === 0 && /detector-shaped\.js\s+passed/.test(ok.out),
    "exit " + ok.code + ": " + tail(ok.out, 10));

  var zero = await _runRunner([
    _gateCommand(_standInGate(dir, "asserted-nothing", 0, ["CHECKS 0"])),
  ]);
  count("a suite that asserted nothing is refused in its own vocabulary",
    zero.code !== 0 && /asserted-nothing\.js\s+UNANSWERED/.test(zero.out),
    "exit " + zero.code + ": " + tail(zero.out, 10));

  helpers.removeTempDir(dir);
}

// A failing gate has a finding to act on, and burying it under a complaint
// about its accounting would send the reader to the wrong place. The count
// rule is a rule about a CLEAN verdict.
async function aFailingGateIsReportedAsFailedNotUnanswered() {
  var dir = helpers.tempDir("gatefailcount");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "failed-and-said-nothing", 1, [])),
  ]);
  count("a failing gate that published nothing is FAILED, not UNANSWERED",
    /failed-and-said-nothing\.js\s+FAILED/.test(run.out) &&
    run.out.indexOf("UNANSWERED (") === -1, tail(run.out, 10));
  count("and the exit code still reaches the caller",
    run.code === 1, "exit " + run.code);
  helpers.removeTempDir(dir);
}

// The runner's own answer to the question it now asks of everything else. A
// reader that stopped reaching the published lines would take this to zero
// while `declared-gates` and `gates-run` both stayed healthy, which is
// exactly the shape of the bug that made this reader necessary: the first
// version of it broke on the trailing newline and read a perfectly good
// count as none.
async function theRunnerPublishesWhatItReadBack() {
  var dir = helpers.tempDir("gatepublished");
  var run = await _runRunner([
    _gateCommand(_standInGate(dir, "one-unit", 0)),
    _gateCommand(_standInGate(dir, "two-units", 0,
      ["EXAMINED 22 lib-source-files", "EXAMINED 118 primitive-blocks"])),
  ]);
  count("the runner publishes how many count lines it read back",
    /EXAMINED 3 published-counts/.test(run.out), tail(run.out, 8));
  count("and the run is clean, so the number came off gates that passed",
    run.code === 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("each gate's counts are echoed beside its verdict",
    /one-unit\.js\s+passed\s+\(7 fixture-units\)/.test(run.out) &&
    /two-units\.js\s+passed\s+\(22 lib-source-files, 118 primitive-blocks\)/.test(run.out),
    tail(run.out, 10));
  helpers.removeTempDir(dir);
}

// The reader itself, driven directly, because every vector above would pass
// on a reader that returned a fixed answer.
function theCountReaderFindsAndMissesTheRightLines() {
  count("counts are read from the end of stdout, past the human report",
    JSON.stringify(examinedCounts.publishedCounts(
      "[gate] OK, no findings.\nEXAMINED 22 files\nEXAMINED 118 blocks\n")) ===
    JSON.stringify([{ token: "EXAMINED", n: 22, unit: "files" },
      { token: "EXAMINED", n: 118, unit: "blocks" }]),
    JSON.stringify(examinedCounts.publishedCounts(
      "[gate] OK.\nEXAMINED 22 files\nEXAMINED 118 blocks\n")));

  // The defect the reader shipped with. A gate's stdout ends in a newline,
  // so the last element of a raw split is the empty string, and a scan that
  // starts at the end and stops at the first non-count line stops on it
  // having read nothing.
  count("a trailing newline does not stop the scan before it starts",
    examinedCounts.publishedCounts("EXAMINED 5 things\n").length === 1,
    JSON.stringify(examinedCounts.publishedCounts("EXAMINED 5 things\n")));

  count("a gate that prints its counts and then says something else is not counted",
    examinedCounts.publishedCounts("EXAMINED 5 things\n[gate] and one more thing\n").length === 0);

  count("a count word this caller does not accept reads as no answer",
    examinedCounts.publishedCounts("CHECKS 12\n").length === 0 &&
    examinedCounts.publishedCounts("CHECKS 12\n", ["CHECKS"]).length === 1);

  count("a zero is read as a count and reported as an empty unit",
    JSON.stringify(examinedCounts.emptyUnits(
      examinedCounts.publishedCounts("EXAMINED 22 files\nEXAMINED 0 blocks\n"))) ===
    JSON.stringify(["blocks"]));

  count("nothing published reads as no counts rather than as a zero",
    examinedCounts.publishedCounts("[gate] OK, no findings.\n").length === 0 &&
    examinedCounts.emptyUnits([]).length === 0);
}

// ---------------------------------------------------------------------------
// The declared list stays where CI reads it
// ---------------------------------------------------------------------------

function _declaredGates() {
  var pkg   = JSON.parse(nodeFs.readFileSync(PACKAGE_JSON, "utf8"));
  var chain = String((pkg.scripts && pkg.scripts[CHAIN_KEY]) || "");
  // The list is written as one quoted command per gate, so the quoted
  // spans ARE the links. Reading them back is what proves package.json is
  // still the authority rather than a description of one.
  var found = chain.match(/"[^"]+"/g) || [];
  return {
    chain: chain,
    gates: found.map(function (s) { return s.slice(1, -1); }),
  };
}

function theChainIsStillDeclaredInPackageJson() {
  var declared = _declaredGates();

  count("the chain still invokes the runner rather than joining links itself",
    declared.chain.indexOf(RUNNER_PATH) !== -1, declared.chain);

  // Canary. A read that came back empty would agree with every claim below.
  count("the declared list still reads as a set of gates",
    declared.gates.length > 1, declared.gates.length + " gate(s)");

  // The short-circuit, refused at the source. A `&&` between two gates is
  // the shape this whole file exists to remove, and it would reintroduce it
  // silently: the runner would receive one argument holding two commands.
  count("no two gates are joined by a shell operator that would hide one",
    declared.gates.every(function (g) {
      return g.indexOf("&&") === -1 && g.indexOf(";") === -1 && g.indexOf("||") === -1;
    }), declared.gates.join(" | "));

  var missing = declared.gates.filter(function (g) {
    var script = g.split(/\s+/)[1];
    return !script || !nodeFs.existsSync(nodePath.join(REPO_ROOT, script));
  });
  count("every declared gate names a file that exists", missing.length === 0,
    missing.join(", "));

  // The two gates that assert their own membership read `scripts.gates` as
  // one string, so the list has to keep NAMING them there. A runner that
  // took the list from a file of its own would leave those assertions
  // reading a string that no longer mentions them.
  count("the chain still names the gates that assert their own membership in it",
    declared.chain.indexOf("check-node-floor.js") !== -1 &&
    declared.chain.indexOf("check-vendor-integrity.js") !== -1,
    declared.chain);
}

// ---------------------------------------------------------------------------
// The array classifier
// ---------------------------------------------------------------------------

// Two snapshots differing in one exported array, in the shape capture
// produces them.
function _snapshotWithArray(pathName, members) {
  var surface = { mail: { kind: "object", members: {} } };
  surface.mail.members[pathName] = {
    kind:    "array",
    length:  members.length,
    members: members.slice(),
  };
  return { surface: surface };
}

var LIST_PATH = "blamepost.mail.THE_LIST";

function _diff(before, after, membership) {
  return snap.compare(
    _snapshotWithArray("THE_LIST", before),
    _snapshotWithArray("THE_LIST", after),
    membership ? { membership: membership } : undefined);
}

// The RED, stated as the rule rather than as one constant. An undeclared
// list is read strictly, so a shrink is breaking whatever the list means.
// That is the correct DEFAULT and it is not the fix: it is what makes a
// list of limitations read as a list of offerings until it says otherwise.
function anUndeclaredListIsReadStrictlyInBothDirections() {
  var shrank = _diff(["one"], []);
  count("undeclared: a shrink is breaking",
    shrank.breaking.length === 1 && shrank.additive.length === 0,
    JSON.stringify(shrank));
  count("undeclared: the finding names the member that left, not the count",
    shrank.breaking[0].indexOf('"one"') !== -1 &&
    shrank.breaking[0].indexOf("removed") !== -1, shrank.breaking[0]);

  var grew = _diff([], ["one"]);
  count("undeclared: a growth is additive",
    grew.additive.length === 1 && grew.breaking.length === 0, JSON.stringify(grew));
}

// The fix. The same shrink, on a list that says what its membership
// asserts, is a limitation lifted rather than surface lost.
function aDeclaredConstraintListRunsTheOtherWay() {
  var membership = {};
  membership[LIST_PATH] = "constraint";

  var lifted = _diff(["managesieve"], [], membership);
  count("constraint list: emptying it is not breaking",
    lifted.breaking.length === 0, JSON.stringify(lifted));
  count("constraint list: the lifted limitation is reported, not swallowed",
    lifted.additive.length === 1 &&
    lifted.additive[0].indexOf("lifted") !== -1 &&
    lifted.additive[0].indexOf('"managesieve"') !== -1, JSON.stringify(lifted));

  // The half that matters more, and the one a length rule gets wrong in the
  // dangerous direction: a limitation ADDED takes a capability away, and
  // under the count rule it read as additive and passed.
  var imposed = _diff([], ["managesieve"], membership);
  count("constraint list: growing it IS breaking",
    imposed.breaking.length === 1 && imposed.additive.length === 0,
    JSON.stringify(imposed));
  count("constraint list: the imposed limitation is named",
    imposed.breaking[0].indexOf("imposed") !== -1 &&
    imposed.breaking[0].indexOf('"managesieve"') !== -1, imposed.breaking[0]);
}

// A capability list is unchanged by any of this, which is what keeps the
// declaration from being a way to quieten the gate generally.
function aDeclaredCapabilityListKeepsTheStrictReading() {
  var membership = {};
  membership[LIST_PATH] = "capability";
  var shrank = _diff(["a", "b"], ["a"], membership);
  count("capability list: a shrink is still breaking",
    shrank.breaking.length === 1 && shrank.breaking[0].indexOf('"b"') !== -1,
    JSON.stringify(shrank));
}

// The blind spot a count carries whichever way it is classified. Members in,
// members out, count unchanged: the old rule compared lengths and reported a
// surface that had not changed at all.
function aSwapThatKeepsTheCountIsStillFound() {
  var swapped = _diff(["was-here"], ["is-here-now"]);
  count("same-length swap: it is not reported as unchanged",
    swapped.breaking.length + swapped.additive.length === 2, JSON.stringify(swapped));
  count("same-length swap: the member that left is breaking",
    swapped.breaking.length === 1 && swapped.breaking[0].indexOf('"was-here"') !== -1,
    JSON.stringify(swapped.breaking));
  count("same-length swap: the member that arrived is additive",
    swapped.additive.length === 1 && swapped.additive[0].indexOf('"is-here-now"') !== -1,
    JSON.stringify(swapped.additive));

  // A reorder moves no member and is not a change of membership.
  var reordered = _diff(["a", "b"], ["b", "a"]);
  count("a reorder is not reported as a membership change",
    reordered.breaking.length === 0 && reordered.additive.length === 0,
    JSON.stringify(reordered));
}

// The one edit that removes the ability to see any of the above, and the
// one that used to produce no finding at all.
//
// `_scalarMembers` returns null for an array that is not wholly scalar, so
// the descriptor falls back to a length; the length rule then returns
// silently whenever the two lengths agree. Rewriting one of the seven
// exported arrays from strings to objects therefore reported ZERO findings,
// the refresh froze a length-only descriptor, and from that commit onward
// every same-length membership change to that array was invisible forever.
// The members lists are what make a length-preserving swap detectable, and
// this is the edit that deletes them without complaint.
function aMembershipListThatDisappearsIsAFinding() {
  // The descriptor the capture produces for an array of objects, taken from
  // the capture rather than hand-written, so the vector cannot drift from
  // what the walk actually records.
  var lengthOnly = snap.capture({ mail: { THE_LIST: [{ n: "a" }, { n: "b" }] } }, {})
    .surface.mail.members.THE_LIST;
  count("the capture really does record a length alone for a non-scalar array",
    lengthOnly.kind === "array" && lengthOnly.length === 2 &&
    !Array.isArray(lengthOnly.members), JSON.stringify(lengthOnly));

  var before = _snapshotWithArray("THE_LIST", ["a", "b"]);
  var after  = { surface: { mail: { kind: "object", members: { THE_LIST: lengthOnly } } } };

  var lost = snap.compare(before, after);
  count("a members list that disappears is breaking rather than silent",
    lost.breaking.length === 1 && lost.additive.length === 0, JSON.stringify(lost));
  count("the finding says the list lost its membership and names the array",
    lost.breaking[0].indexOf(LIST_PATH) === 0 && /membership list lost/.test(lost.breaking[0]),
    lost.breaking[0]);
  count("it says why that is a change and not only a loss of visibility",
    /comparable by identity/.test(lost.breaking[0]), lost.breaking[0]);

  // Polarity decides which DIRECTION of a membership change takes something
  // away. This is not a change of membership: it is a change of what the
  // elements ARE, so a constraint list loses its members just as breakingly.
  var asConstraint = {};
  asConstraint[LIST_PATH] = "constraint";
  var lostToo = snap.compare(before, after, { membership: asConstraint });
  count("declaring the list a constraint does not make losing its members harmless",
    lostToo.breaking.length === 1 && /membership list lost/.test(lostToo.breaking[0]),
    JSON.stringify(lostToo));

  // An array that NEVER had a members list is a different case, and the one
  // the length rule was always right about.
  var neverHad = snap.compare(
    { surface: { mail: { kind: "object", members: { THE_LIST: lengthOnly } } } },
    { surface: { mail: { kind: "object", members: { THE_LIST: lengthOnly } } } });
  count("an array that never had a members list is not reported as having lost one",
    neverHad.breaking.length === 0 && neverHad.additive.length === 0,
    JSON.stringify(neverHad));

  // And the other direction: a list that becomes nameable is reported, so a
  // refresh records the members rather than freezing another length.
  var gained = snap.compare(
    { surface: { mail: { kind: "object", members: { THE_LIST: lengthOnly } } } },
    _snapshotWithArray("THE_LIST", ["a", "b"]));
  count("a list that becomes comparable is additive rather than breaking",
    gained.breaking.length === 0 && gained.additive.length === 1 &&
    /became comparable/.test(gained.additive[0]), JSON.stringify(gained));
}

// ---------------------------------------------------------------------------
// The polarity, which is the one word that can turn a loss into a gain
// ---------------------------------------------------------------------------

// `checkMembership` already refuses a declaration that names no array and an
// array that declares nothing, so every exported array says what kind of
// list it is. Neither asks whether it still says the same thing it said last
// time, and the polarity is a single word in a comment. RATE_LIMIT_KEYS is
// this tree's only `capability` list: re-declaring it a constraint makes
// dropping a rate-limit key report as additive, and until the snapshot
// recorded the word there was no earlier value anywhere to contradict.
function aDeclaredPolarityIsImmutable() {
  var recorded = { "blamepost.mail.THE_LIST": "capability" };

  count("an unchanged polarity is clean",
    snap.checkMembershipFrozen(recorded, recorded).length === 0);

  var flipped = snap.checkMembershipFrozen(recorded,
    { "blamepost.mail.THE_LIST": "constraint" });
  count("a one-word re-declaration is refused",
    flipped.length === 1 && /@membership changed capability -> constraint/.test(flipped[0]),
    JSON.stringify(flipped));
  count("the refusal says what the word decides, so the fix is not to edit it back blindly",
    /limitation lifted/.test(flipped[0]), flipped[0]);

  // The same hole checkSinceUntracked closed for introduction versions: a
  // declaration the record never held is frozen by nothing, so the first
  // value it gets is whatever source says on the day somebody looks.
  var untracked = snap.checkMembershipFrozen({},
    { "blamepost.mail.THE_LIST": "constraint" });
  count("a polarity the snapshot never recorded is refused as frozen by nothing",
    untracked.length === 1 && /frozen by nothing/.test(untracked[0]),
    JSON.stringify(untracked));

  // A tree with no record at all is the bootstrap, which the gate refuses
  // earlier and with its own message. Reporting every array here would bury
  // it.
  count("an absent record is left to the gate's own refusal",
    snap.checkMembershipFrozen(null, recorded).length === 0);
}

// The tree's own record, so the vectors above are not the only thing holding
// the word. Whatever this repository declares today is what the committed
// snapshot recorded.
function theTreesOwnPolaritiesAgreeWithTheRecord() {
  var frozen = JSON.parse(nodeFs.readFileSync(
    nodePath.join(REPO_ROOT, "api-snapshot.json"), "utf8")).membershipByArray;

  count("the committed snapshot records a polarity for every exported array",
    frozen && Object.keys(frozen).length > 0,
    JSON.stringify(frozen && Object.keys(frozen).length));

  var declared = sourcePrimitives.membershipMap(sourcePrimitives.collectMembership());
  count("no exported array declares a polarity the record disagrees with",
    snap.checkMembershipFrozen(frozen, declared).length === 0,
    JSON.stringify(snap.checkMembershipFrozen(frozen, declared)));

  // The specific list the freeze exists for. A capability list is the strict
  // reading, so this is the one whose re-declaration would make a removal
  // read as additive.
  count("the rate-limit key list is still recorded as the capability list it is",
    frozen["blamepost.mail.listeners.RATE_LIMIT_KEYS"] === "capability",
    JSON.stringify(frozen["blamepost.mail.listeners.RATE_LIMIT_KEYS"]));
}

// A baseline written before members were recorded still has to be read. It
// carries a length and nothing else, so the count is all that is claimed,
// and it is still classified by what the list says it is rather than by the
// direction alone.
function aLengthOnlyBaselineIsStillClassifiedByPolarity() {
  function lengthOnly(n) {
    return { surface: { mail: { kind: "object", members: {
      THE_LIST: { kind: "array", length: n },
    } } } };
  }
  var membership = {};
  membership[LIST_PATH] = "constraint";

  var strict = snap.compare(lengthOnly(1), lengthOnly(0));
  count("length-only baseline, undeclared: a shrink is breaking",
    strict.breaking.length === 1, JSON.stringify(strict));

  var declared = snap.compare(lengthOnly(1), lengthOnly(0), { membership: membership });
  count("length-only baseline, declared a constraint: the same shrink is not breaking",
    declared.breaking.length === 0 && declared.additive.length === 1,
    JSON.stringify(declared));
}

// ---------------------------------------------------------------------------
// The declarations themselves
// ---------------------------------------------------------------------------

function _fixtureSource(body) {
  var dir  = helpers.tempDir("membership");
  var file = nodePath.join(dir, "table.js");
  nodeFs.writeFileSync(file, body);
  return { dir: dir, file: file };
}

// The reader, in both comment styles, because a table declared with a line
// comment and one declared with a block comment are the same declaration and
// a reader that saw only one would silently govern half of them.
function theDeclarationIsReadFromEitherCommentStyle() {
  var fx = _fixtureSource([
    "// The listeners a renewed certificate does not reach.",
    "//",
    "// @membership blamepost.mail.listeners.STALE_AFTER_ROTATION constraint",
    "var STALE_AFTER_ROTATION = Object.freeze([]);",
    "",
    "/**",
    " * The handle methods a store must carry.",
    " * @membership blamepost.web.REQUIRED_STORE constraint",
    " */",
    "var REQUIRED_STORE = Object.freeze([]);",
    "",
    "// An ordinary sentence that merely mentions membership is not one.",
    "var OTHER = 1;",
    "",
  ].join("\n"));

  var records = sourcePrimitives.collectMembership([fx.file]);
  var map     = sourcePrimitives.membershipMap(records);

  count("both comment styles are read", records.length === 2,
    JSON.stringify(records.map(function (r) { return r.path + "=" + r.polarity; })));
  count("the line-comment declaration is read",
    map["blamepost.mail.listeners.STALE_AFTER_ROTATION"] === "constraint",
    JSON.stringify(map));
  count("the block-comment declaration is read",
    map["blamepost.web.REQUIRED_STORE"] === "constraint", JSON.stringify(map));
  count("prose that merely mentions the word is not a declaration",
    Object.keys(map).length === 2, JSON.stringify(map));
  // A finding an author cannot jump to costs a search, so the record
  // carries the line the declaration actually sits on rather than the line
  // the block began.
  var byPath = {};
  records.forEach(function (r) { byPath[r.path] = r.line; });
  count("each record points at the line the declaration sits on",
    byPath["blamepost.mail.listeners.STALE_AFTER_ROTATION"] === 3 &&
    byPath["blamepost.web.REQUIRED_STORE"] === 8,
    JSON.stringify(byPath));

  helpers.removeTempDir(fx.dir);
}

// The declaration is the only input here that can make the gate quieter, so
// each way it can outlive what it was written about is refused. The rename
// case is the one §3 is about: rename the array and leave the declaration
// behind, and it governs nothing. That is refused loudly, not silently
// obeyed and not silently ignored.
function aDeclarationThatGovernsNothingIsRefused() {
  var live = _snapshotWithArray("THE_LIST", ["a"]);
  // The live array's own declaration, carried into every vector so the only
  // finding each one can produce is the defect it is about.
  var governsTheList =
    { path: LIST_PATH, polarity: "constraint", file: "lib/live.js", line: 1 };

  var stale = snap.checkMembership([governsTheList,
    { path: "blamepost.mail.RENAMED_AWAY", polarity: "constraint", file: "lib/x.js", line: 4 },
  ], live);
  count("a declaration naming no exported array is refused",
    stale.length === 1 && /governs nothing/.test(stale[0]), JSON.stringify(stale));
  count("the refusal points at the declaration's own file and line",
    stale[0].indexOf("lib/x.js:4") !== -1, stale[0]);

  var unknown = snap.checkMembership(
    [{ path: LIST_PATH, polarity: "harmless", file: "lib/x.js", line: 9 }], live);
  count("a declaration carrying an unknown polarity is refused",
    unknown.length === 1 && /is not one of/.test(unknown[0]), JSON.stringify(unknown));

  var twice = snap.checkMembership([
    { path: LIST_PATH, polarity: "constraint", file: "lib/x.js", line: 4 },
    { path: LIST_PATH, polarity: "capability", file: "lib/y.js", line: 7 },
  ], live);
  count("one table declared twice is refused rather than resolved by walk order",
    twice.length === 1 && /more than once/.test(twice[0]), JSON.stringify(twice));

  // The control. A declaration that names a live array and a known polarity
  // is accepted, or every vector above would pass on a checker that refused
  // everything.
  var clean = snap.checkMembership([governsTheList], live);
  count("a declaration naming a live array and a known polarity is accepted",
    clean.length === 0, JSON.stringify(clean));
}

// The other direction, and the one that was missing. The strict default is
// the right DEFAULT and it is not a license to leave the question
// unanswered: an array nothing declares is classified by a rule nobody
// chose, which happens to be right for a capability list and wrong for every
// other kind. This tree's own measurement is what says so: two requirement
// lists that GREW read as additive under the default, which is the direction
// that hides a handle the package no longer accepts.
//
// The gate already refuses a declaration that governs nothing. This is the
// same rule read the other way round: an array nothing governs.
function anExportedArrayThatDeclaresNothingIsRefused() {
  var live = _snapshotWithArray("THE_LIST", ["a"]);

  var none = snap.checkMembership([], live);
  count("an exported array nothing declares is refused rather than silently defaulted",
    none.length === 1 && /no @membership/.test(none[0]), JSON.stringify(none));
  count("the refusal names the array whose kind was never decided",
    none[0].indexOf(LIST_PATH) === 0, none[0]);

  // A declaration for a DIFFERENT array does not answer for this one, or the
  // requirement would be satisfied tree-wide by one line, which is the
  // shape the sibling defect on the `@originated` tag had.
  var elsewhere = _snapshotWithArray("THE_LIST", ["a"]);
  elsewhere.surface.mail.members.OTHER_LIST = { kind: "array", length: 0, members: [] };
  var partial = snap.checkMembership(
    [{ path: LIST_PATH, polarity: "constraint", file: "lib/x.js", line: 4 }], elsewhere);
  count("declaring one array does not answer for a second one",
    partial.length === 1 && partial[0].indexOf("blamepost.mail.OTHER_LIST") === 0,
    JSON.stringify(partial));
}

// The tree, swept. Seven arrays are exported today and the classification of
// every one of them was previously decided by the default rather than by
// anybody.
function everyExportedArrayInThisTreeSaysWhatKindOfListItIs() {
  var current = snap.capture(require("../../lib/index.js"), {});
  var paths   = snap.arrayPaths(current);

  // Canary. An empty set would satisfy the claim below without governing
  // anything, which is the failure the EXAMINED counts exist to refuse.
  count("the tree still exports arrays for the rule to govern",
    paths.length > 0, paths.length + " exported array(s)");

  var violations = snap.checkMembership(sourcePrimitives.collectMembership(), current);
  count("every exported array in this tree declares what kind of list it is",
    violations.length === 0, JSON.stringify(violations));
}

// The requirement lists specifically, because they are the ones whose
// misreading is dangerous rather than merely noisy. A list of the methods a
// caller's handle MUST carry takes something away when it grows: a handle
// that satisfied the last release stops being accepted. Under a strict
// capability reading that growth reports as additive and a refresh freezes
// it that way.
function aListOfRequirementsIsDeclaredAsOne() {
  var map = sourcePrimitives.membershipMap(sourcePrimitives.collectMembership());
  var required = Object.keys(map).filter(function (p) {
    return /\.REQUIRED_[A-Z0-9_]+$/.test(p);
  });
  count("the tree still exports requirement lists", required.length > 0,
    required.length + " list(s)");

  var misdeclared = required.filter(function (p) { return map[p] !== "constraint"; });
  count("every list of requirements is declared a constraint, so growing one reads " +
    "as the refusal it is rather than as a capability gained",
  misdeclared.length === 0, misdeclared.join(", "));
}

// The path reader the check holds declarations against. A reader that found
// no arrays would refuse every declaration, and a reader that found
// everything would accept every stale one.
function theArrayPathReaderFindsTheExportedArrays() {
  var found = snap.arrayPaths({ surface: {
    mail: { kind: "object", members: {
      LIST:   { kind: "array", length: 0, members: [] },
      nested: { kind: "object", members: { DEEP: { kind: "array", length: 1, members: ["x"] } } },
      fn:     { kind: "function", arity: 2 },
    } },
    version: { kind: "string" },
  } });
  count("the array-path reader finds arrays at any depth and nothing else",
    JSON.stringify(found) ===
      JSON.stringify(["blamepost.mail.LIST", "blamepost.mail.nested.DEEP"]),
    JSON.stringify(found));
}

// ---------------------------------------------------------------------------

async function run() {
  // The controls lead, so a run that stops at the first failure has already
  // shown the vectors below are asking live questions.
  await aCleanRunReportsEveryGatePassed();
  theChainIsStillDeclaredInPackageJson();

  await anEarlyFailureDoesNotHideTheGatesBehindIt();
  await everyFailingGateIsReportedFromOnePass();
  await theDeclaredOrderIsKept();
  await anAbsentGateIsNamedAsNotRun();
  await anEmptyDeclaredListIsRefused();
  await aGateThatCannotBeParsedStopsTheRun();

  theCountReaderFindsAndMissesTheRightLines();
  await theVerdictSummaryIsPersistedWhereItWasTold();
  await theRunnerPublishesWhatItReadBack();
  await aGateThatExaminedNothingIsRefused();
  await aGateThatPublishesNoCountIsRefused();
  await oneEmptyUnitAmongSeveralIsRefused();
  await theDetectorSuitesCountWordIsAccepted();
  await aFailingGateIsReportedAsFailedNotUnanswered();

  anUndeclaredListIsReadStrictlyInBothDirections();
  aDeclaredConstraintListRunsTheOtherWay();
  aDeclaredCapabilityListKeepsTheStrictReading();
  aSwapThatKeepsTheCountIsStillFound();
  aMembershipListThatDisappearsIsAFinding();
  aLengthOnlyBaselineIsStillClassifiedByPolarity();
  aDeclaredPolarityIsImmutable();
  theTreesOwnPolaritiesAgreeWithTheRecord();

  theDeclarationIsReadFromEitherCommentStyle();
  aDeclarationThatGovernsNothingIsRefused();
  anExportedArrayThatDeclaresNothingIsRefused();
  everyExportedArrayInThisTreeSaysWhatKindOfListItIs();
  aListOfRequirementsIsDeclaredAsOne();
  theArrayPathReaderFindsTheExportedArrays();

  return helpers.getChecks();
}

module.exports = { name: "gate-chain-completeness", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
