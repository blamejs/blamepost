// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * release-gate-verdicts: the release flow reads the verdicts it asks for.
 *
 * `scripts/release.js` carries every gate a cut passes through, and it is
 * the one file in the tree that nothing drives from the outside. Two ways
 * of failing follow from that, and both are the same failure: a gate that
 * runs and then throws away the answer gates nothing, and neither does a
 * gate whose script is absent.
 *
 *   - `watch` runs the checks and then reads the review threads. The
 *     checks are watched to completion because an operator wants the
 *     failing checks AND the unresolved findings out of one pass, so the
 *     run is allowed to continue past a failure. Continuing past it is
 *     not the same as forgetting it: the verdict has to reach the exit
 *     code, or a red build walks into `merge`.
 *   - The static battery routes several gates through one helper. A gate
 *     whose script is not on disk checked nothing, and reporting that as
 *     a pass turns deleting a file into the way past it.
 *
 * Both are driven the way an operator drives them: `node
 * scripts/release.js <subcommand>` in a child process, with `gh` and
 * `git` answered by a stand-in on PATH, asserting on the exit code and
 * the transcript. Nothing here reaches into the script's internals,
 * because the internals were never the part that was wrong. What was
 * wrong was an exit code.
 *
 * HOW THE STAND-IN IS REACHED. `release.js` spawns `gh` and `git` without
 * a shell, so on Windows neither a `.cmd` shim nor an extensionless file
 * can answer: the first is refused outright and the second is not
 * resolved at all. The only shape that resolves is a real executable, so
 * the stand-in directory holds a copy of the running node binary named
 * `gh.exe`, with `git.exe` linked to it, and a preload named through
 * NODE_OPTIONS decides which tool it is standing in for from its own
 * argv. The preload no-ops for every other node process that inherits
 * it, which is every gate the flow runs. Elsewhere the same source runs
 * from a shebang and none of that applies.
 *
 * WHAT THE STAND-IN ANSWERS is data, not code: a plan of replies matched
 * on the argument tokens, so a vector reads as the situation it describes
 * rather than as a program. An unplanned call is refused loudly instead
 * of answered with a default, because a default is how a vector passes
 * without driving the path it names.
 *
 * No sockets and no database. It spawns node processes and reads what
 * they printed.
 *
 * Run standalone: node test/layer-0-primitives/release-gate-verdicts.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var RELEASE_JS     = nodePath.join(helpers.REPO_ROOT, "scripts", "release.js");
var RUN_CEILING_MS = 60000;

// What release.js requires from beside itself, copied into every fixture
// tree. `examined-counts.js` is the one reader of the published-count
// contract, shared with scripts/run-gates.js so the two cannot drift about
// what a gate said it examined.
var RELEASE_SIBLINGS = ["examined-counts.js"];

// The PR the stand-in answers for. Any number would do; a fixed one keeps
// the transcript assertions readable.
var PR_NUMBER = "77";

// What `watch` reports when it refuses to advance. Read as a contract
// rather than restated: a caller that cannot tell a red build from an
// open finding cannot pick its next move, and both at once is a third
// answer rather than either one.
var WATCH_EXIT_THREADS = 3;
var WATCH_EXIT_CHECKS  = 5;
var WATCH_EXIT_BOTH    = 6;

// ---------------------------------------------------------------------------
// The stand-in tool
// ---------------------------------------------------------------------------

// Kept as source text rather than as a file in the tree: it is one
// fixture belonging to one case, and a second copy of it is how two
// vectors start disagreeing about what a tool said.
var STAND_IN_SOURCE = [
  '"use strict";',
  'var standInFs   = require("node:fs");',
  'var standInPath = require("node:path");',
  'function _asTool(token) {',
  '  var name = standInPath.basename(String(token || "")).toLowerCase().replace(/\\.(?:exe|js)$/, "");',
  '  return (name === "gh" || name === "git") ? name : null;',
  '}',
  'var _tool = _asTool(process.argv[0]);',
  'var _argv = process.argv.slice(1);',
  'if (_tool === null) {',
  '  _tool = _asTool(process.argv[1]);',
  '  _argv = process.argv.slice(2);',
  '} else if (_argv.length) {',
  '  _argv[0] = standInPath.basename(_argv[0]);',
  '}',
  'if (_tool !== null) {',
  '  var _plan = JSON.parse(standInFs.readFileSync(process.env.BLAMEPOST_TOOL_STAND_IN, "utf8"));',
  '  standInFs.appendFileSync(_plan.log, _tool + " " + _argv.join(" ") + "\\n");',
  '  var _reply = null;',
  '  for (var _i = 0; _i < _plan.replies.length && _reply === null; _i += 1) {',
  '    var _candidate = _plan.replies[_i];',
  '    if (_candidate.tool !== _tool) continue;',
  '    var _missed = _candidate.match.filter(function (t) { return _argv.indexOf(t) === -1; });',
  '    if (_missed.length === 0) _reply = _candidate;',
  '  }',
  '  if (_reply === null) {',
  '    standInFs.writeSync(2, "tool stand-in: nothing planned for " + _tool + " " + _argv.join(" ") + "\\n");',
  '    process.exit(66);',
  '  }',
  '  if (_reply.stdout) standInFs.writeSync(1, _reply.stdout + "\\n");',
  '  if (_reply.stderr) standInFs.writeSync(2, _reply.stderr + "\\n");',
  '  process.exit(_reply.exit);',
  '}',
  '',
].join("\n");

// One copy of the node binary per run of this file, reused by every
// vector. It is the price of a tool a shell-free spawn can resolve on
// Windows; a link would cost nothing but the installed binary refuses
// one, measured rather than assumed.
var _standInDir = null;

function _standInDirectory() {
  if (_standInDir !== null) return _standInDir;
  var dir = helpers.tempDir("tool-stand-in");
  if (process.platform === "win32") {
    nodeFs.writeFileSync(nodePath.join(dir, "stand-in.js"), STAND_IN_SOURCE);
    var gh = nodePath.join(dir, "gh.exe");
    nodeFs.copyFileSync(process.execPath, gh);
    try { nodeFs.linkSync(gh, nodePath.join(dir, "git.exe")); }
    catch (_e) { nodeFs.copyFileSync(gh, nodePath.join(dir, "git.exe")); }
    nodeFs.writeFileSync(nodePath.join(dir, "npx.cmd"),
      "@echo off\r\necho npx stand-in: nothing installed, nothing run\r\nexit /b 0\r\n");
  } else {
    ["gh", "git"].forEach(function (name) {
      var file = nodePath.join(dir, name);
      nodeFs.writeFileSync(file, "#!/usr/bin/env node\n" + STAND_IN_SOURCE);
      nodeFs.chmodSync(file, 0o755);
    });
    var npx = nodePath.join(dir, "npx");
    nodeFs.writeFileSync(npx, "#!/bin/sh\necho \"npx stand-in: nothing installed, nothing run\"\nexit 0\n");
    nodeFs.chmodSync(npx, 0o755);
  }
  _standInDir = dir;
  return dir;
}

// The child's environment, with the stand-in directory ahead of
// everything else. The existing path variable is dropped by name rather
// than overwritten, because Windows reports it as `Path` and adding
// `PATH` beside it leaves the child holding two of them.
function _standInEnv(planPath, extra) {
  var dir = _standInDirectory();
  var env = {};
  Object.keys(process.env).forEach(function (k) {
    if (k.toLowerCase() === "path" || k.toLowerCase() === "node_options") return;
    env[k] = process.env[k];
  });
  env.PATH = dir + nodePath.delimiter + (process.env.PATH || "");
  env.BLAMEPOST_TOOL_STAND_IN = planPath;
  if (process.platform === "win32") {
    // Forward slashes: this variable is parsed with backslash as an
    // escape, so a Windows path written as it comes arrives with its
    // separators eaten and the preload is never found.
    env.NODE_OPTIONS = "--require " + nodePath.join(dir, "stand-in.js").replace(/\\/g, "/");
  }
  Object.keys(extra || {}).forEach(function (k) { env[k] = extra[k]; });
  return env;
}

// Write a reply plan and return the paths the caller reads back.
function _plan(replies) {
  var dir      = helpers.tempDir("toolplan");
  var logPath  = nodePath.join(dir, "calls.log");
  var planPath = nodePath.join(dir, "plan.json");
  nodeFs.writeFileSync(logPath, "");
  nodeFs.writeFileSync(planPath, JSON.stringify({ log: logPath, replies: replies }, null, 2));
  return { planPath: planPath, logPath: logPath };
}

function _calls(logPath) {
  return nodeFs.readFileSync(logPath, "utf8");
}

// ---------------------------------------------------------------------------
// watch
// ---------------------------------------------------------------------------

// The GraphQL envelope `_unresolvedThreads` reads, in the shape GitHub
// returns it. The pagination fields are load-bearing: the reader refuses
// a payload with no connection rather than treating it as an empty
// thread list.
function _threadsPayload(threads) {
  return JSON.stringify({
    data: {
      repository: {
        pullRequest: {
          reviewThreads: {
            pageInfo: { hasNextPage: false, endCursor: null },
            nodes:    threads,
          },
        },
      },
    },
  });
}

// The login is the connector that actually posts findings on a release
// PR, spelled the way GitHub returns it. A made-up reviewer would model
// the situation less closely for no gain, and the wait this same file's
// sibling gate performs recognizes threads by exactly this handle.
var OPEN_FINDING = {
  id:         "PRRT_kwDOtestthread1",
  isResolved: false,
  path:       "lib/mail/submission.js",
  line:       118,
  comments:   { nodes: [{
    author: { login: "chatgpt-codex-connector" },
    body:   "The identity binding is widened for one desktop client.",
  }] },
};

var CHECKS_FAILING_OUTPUT = [
  "X  gates      1m12s  https://github.com/blamejs/blamepost/actions/runs/1",
  "*  container  2m03s  https://github.com/blamejs/blamepost/actions/runs/2",
  "Some checks were not successful",
].join("\n");

var CHECKS_PASSING_OUTPUT = "All checks were successful";

async function _runWatch(opts) {
  var plan = _plan([
    { tool: "gh", match: ["pr", "list"],      stdout: PR_NUMBER, exit: 0 },
    { tool: "gh", match: ["pr", "checks"],
      stdout: opts.checksExit === 0 ? CHECKS_PASSING_OUTPUT : CHECKS_FAILING_OUTPUT,
      exit:   opts.checksExit },
    { tool: "gh", match: ["api", "graphql"], stdout: _threadsPayload(opts.threads), exit: 0 },
  ]);
  var rv = await spawnRun.runNodeScript([RELEASE_JS, "watch"], {
    cwd:       helpers.REPO_ROOT,
    ceilingMs: RUN_CEILING_MS,
    env:       _standInEnv(plan.planPath, { RELEASE_SKIP_CODEX_WAIT: "1" }),
  });
  rv.calls = _calls(plan.logPath);
  return rv;
}

// The stand-in has to have been asked, or a vector proves only that the
// command exits.
function _drovePrChecks(label, run) {
  count(label + ": it ran the checks it is named for",
    run.calls.indexOf("gh pr checks " + PR_NUMBER + " --watch") !== -1, run.calls.trim());
  count(label + ": it read the review threads",
    run.calls.indexOf("gh api graphql") !== -1, run.calls.trim());
}

// The live defect. The checks conclude FAILING and there is nothing else
// wrong, so the only thing standing between a red build and `merge` is
// whether this command remembered what it watched.
async function failingChecksAloneRefuseToAdvance() {
  var run = await _runWatch({ checksExit: 1, threads: [] });
  _drovePrChecks("failing checks", run);

  count("failing checks: the command does not exit clean",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 4));
  count("failing checks: the exit code says the checks failed",
    run.code === WATCH_EXIT_CHECKS, "exit " + run.code + ", expected " + WATCH_EXIT_CHECKS);
  count("failing checks: it says so in the transcript",
    run.out.indexOf("checks: FAILED") !== -1, tail(run.out, 8));
  count("failing checks: it does not hand the operator on to merge",
    run.out.indexOf("next: node scripts/release.js merge") === -1, tail(run.out, 8));
}

// The control. Without it a command that always refused would pass every
// other vector in this file.
async function cleanChecksAndCleanThreadsAdvance() {
  var run = await _runWatch({ checksExit: 0, threads: [] });
  _drovePrChecks("clean run", run);

  count("clean run: the command exits clean",
    run.code === 0, "exit " + run.code + ": " + tail(run.out, 4));
  count("clean run: it hands the operator on to merge",
    run.out.indexOf("next: node scripts/release.js merge") !== -1, tail(run.out, 8));
  count("clean run: it records that the checks passed",
    /required checks passed/i.test(run.out), tail(run.out, 8));
}

// Both wrong at once. An operator wants the failing build and the open
// finding out of ONE pass, so reporting the first and stopping is its
// own defect: the second round then discovers what the first already
// knew.
async function failingChecksAndOpenThreadsBothReport() {
  var run = await _runWatch({ checksExit: 1, threads: [OPEN_FINDING] });
  _drovePrChecks("both wrong", run);

  count("both wrong: the exit code is neither of the single answers",
    run.code === WATCH_EXIT_BOTH,
    "exit " + run.code + ", expected " + WATCH_EXIT_BOTH +
    " (checks alone is " + WATCH_EXIT_CHECKS + ", threads alone is " + WATCH_EXIT_THREADS + ")");
  count("both wrong: the failing checks are reported",
    run.out.indexOf("checks: FAILED") !== -1, tail(run.out, 10));
  count("both wrong: the open finding is reported too",
    run.out.indexOf(OPEN_FINDING.path) !== -1 && /unresolved review thread/i.test(run.out),
    tail(run.out, 10));
}

// The path that already worked, held still. A change that teaches the
// command about failing checks must not renumber the answer a caller
// already keys on.
async function openThreadsAloneKeepTheirCode() {
  var run = await _runWatch({ checksExit: 0, threads: [OPEN_FINDING] });
  _drovePrChecks("open finding", run);

  count("open finding: the exit code is the one it has always been",
    run.code === WATCH_EXIT_THREADS, "exit " + run.code + ", expected " + WATCH_EXIT_THREADS);
  count("open finding: the checks are reported as passing",
    /required checks passed/i.test(run.out), tail(run.out, 10));
  count("open finding: the thread is named with its file",
    run.out.indexOf(OPEN_FINDING.path) !== -1, tail(run.out, 10));
}

// ---------------------------------------------------------------------------
// The static battery, in a tree of its own
// ---------------------------------------------------------------------------

// Every gate script the battery runs, in the order it runs them. The
// fixture writes all of them and then removes the one the vector is
// about, so a missing gate is the only difference between two runs.
var GATE_SCRIPTS = [
  "test/layer-0-primitives/codebase-patterns.test.js",
  "scripts/validate-source-comment-blocks.js",
  "scripts/check-api-snapshot.js",
  "scripts/check-spelling-consistency.js",
  "scripts/check-status-lifecycle.js",
  "scripts/consolidate-release-notes.js",
  "scripts/generate-changelog-entry.js",
  "scripts/pin-all.js",
  "scripts/check-vendor-currency.js",
];

// The artifact regeneration `prepare` runs before it reaches the battery.
// Not gates, and not the subject of anything here: they exist so the one
// subcommand that reaches the vendor-currency gate can get that far.
var REGEN_SCRIPTS = [
  "scripts/gen-migrating.js",
  "scripts/refresh-api-snapshot.js",
  "scripts/check-changelog-extract.js",
];

var DETECTOR_GATE = "test/layer-0-primitives/codebase-patterns.test.js";

// What each gate publishes about what it examined, in the shape the real
// gate publishes it. The detector suite froze `CHECKS <n>` for
// test/smoke.js and keeps it; the rest publish `EXAMINED <n> <unit>`, one
// line per unit they answer for, and the numbers here are the ones those
// gates print against this repository today.
//
// A gate absent from this map publishes nothing, which is how release.js
// runs the ones it does not route through the counted helper. Keeping
// those in the fixture is what proves the battery still tolerates a gate
// that makes no such claim, rather than demanding a count from everything
// that happens to be a script.
var GATE_COUNTS = {
  "test/layer-0-primitives/codebase-patterns.test.js": ["CHECKS 12"],
  "scripts/validate-source-comment-blocks.js": [
    "EXAMINED 22 lib-source-files",
    "EXAMINED 115 primitive-blocks",
  ],
  "scripts/check-api-snapshot.js": [
    "EXAMINED 22 lib-source-files",
    "EXAMINED 115 frozen-primitives",
  ],
  "scripts/check-spelling-consistency.js": ["EXAMINED 282 scanned-files"],
  "scripts/check-status-lifecycle.js": [
    "EXAMINED 22 lib-source-files",
    "EXAMINED 115 primitive-blocks",
  ],
  // The notes gate publishes a third unit, `cross-checked-releases`, only when
  // there is a hand-written release left to compare. Between cuts the fold has
  // pruned it, so the gate states that zero in prose and publishes these two.
  // The fixture carries what the gate prints in that state, which is the state
  // every `--check` in the flow runs in.
  "scripts/consolidate-release-notes.js": [
    "EXAMINED 1 series-files",
    "EXAMINED 1 series-releases",
  ],
  "scripts/check-vendor-currency.js": [
    "EXAMINED 1 manifest-packages",
    "EXAMINED 1 measured-packages",
  ],
};

var FIXTURE_VERSION = "0.1.0";
var PREPARED_VERSION = "0.1.1";

// A gate stand-in that passes, publishing the examined-count its real
// counterpart publishes. Three ways to make one stop answering, because
// they are different defects and the flow has to refuse all of them:
//
//   opts.inertGate   the named gate publishes EVERY count as ZERO. Its
//                    discovery still ran and matched an empty set, which
//                    is the shape a broken glob or a moved directory
//                    leaves behind.
//   opts.silentGate  the named gate publishes no count line at all, which
//                    is the shape a gate that never learned to answer
//                    leaves behind.
//   opts.publishes   the named gate publishes exactly these lines. This is
//                    for the case that matters most on a gate answering in
//                    several units and is the one the two above cannot
//                    express: SOME of them zero and the rest not. A gate
//                    that opened its files and extracted nothing from them
//                    reports a healthy first number, and a reader that
//                    stopped at it would call the run measured.
function _gateStandInSource(rel, opts) {
  opts = opts || {};
  var lines = ['console.log("' + rel + ': gate stand-in");'];
  var overridden = opts.publishes && opts.publishes[rel];
  if (overridden) {
    overridden.forEach(function (line) { lines.push('console.log("' + line + '");'); });
  } else if (rel !== opts.silentGate) {
    (GATE_COUNTS[rel] || []).forEach(function (published) {
      var line = rel === opts.inertGate ? published.replace(/\s\d+\s?/, " 0 ").trimEnd() : published;
      lines.push('console.log("' + line + '");');
    });
  }
  return '"use strict";\n' + lines.join("\n") + "\n";
}

// A tree with the shape release.js reads and nothing else: the script
// itself, a manifest, notes for the version in it, and the gate scripts.
// The real repository is never the subject here, because `commit` writes
// a branch and a commit into whatever tree it is pointed at.
function _fixtureTree(opts) {
  opts = opts || {};
  var root = helpers.tempDir("releasetree");
  ["scripts", "release-notes", "test", "test/layer-0-primitives"].forEach(function (d) {
    nodeFs.mkdirSync(nodePath.join(root, d), { recursive: true });
  });
  nodeFs.writeFileSync(nodePath.join(root, "package.json"), JSON.stringify({
    name:       "@blamejs/blamepost",
    version:    FIXTURE_VERSION,
    repository: { url: "https://github.com/blamejs/blamepost.git" },
  }, null, 2) + "\n");
  // Notes for the version in the manifest AND for the one a bump lands on,
  // so `commit` and `prepare` each find the release they read.
  [FIXTURE_VERSION, PREPARED_VERSION].forEach(function (version) {
    nodeFs.writeFileSync(nodePath.join(root, "release-notes", "v" + version + ".json"),
      JSON.stringify({
        version:  version,
        date:     "2026-01-01",
        headline: "a fixture release",
        summary:  "Nothing ships from this tree; it exists so the flow has notes to read.",
        sections: [{ heading: "Fixed", items: [{ title: "a fixture item", body: "a fixture body." }] }],
      }, null, 2) + "\n");
  });
  nodeFs.copyFileSync(RELEASE_JS, nodePath.join(root, "scripts", "release.js"));
  // The modules release.js requires from beside itself. A fixture tree
  // missing one of them fails as a module-resolution error rather than as
  // the situation the vector describes, so they are listed rather than
  // assumed: adding a require to release.js and forgetting this line makes
  // every case in this file fail for a reason none of them is about.
  RELEASE_SIBLINGS.forEach(function (name) {
    nodeFs.copyFileSync(nodePath.join(helpers.REPO_ROOT, "scripts", name),
      nodePath.join(root, "scripts", name));
  });
  GATE_SCRIPTS.concat(REGEN_SCRIPTS).forEach(function (rel) {
    if (rel === opts.omit) return;
    nodeFs.writeFileSync(nodePath.join(root, rel), _gateStandInSource(rel, opts));
  });
  return root;
}

// `commit` is the cheapest subcommand that reaches the battery: it
// selects a branch and then runs every gate before anything is written.
// The stand-in git answers the questions it asks on the way in, and
// records the rest so a vector can assert that no commit was ever made.
async function _runCommit(opts) {
  var root = _fixtureTree(opts);
  var plan = _plan([
    { tool: "git", match: ["rev-parse", "--abbrev-ref"], stdout: "main", exit: 0 },
    { tool: "git", match: ["rev-parse", "--verify"],     stdout: "",     exit: 1 },
    { tool: "git", match: ["checkout"],                  stdout: "",     exit: 0 },
    { tool: "git", match: ["log", "--pretty=%s"],        stdout: "",     exit: 0 },
    { tool: "git", match: ["log"],                       stdout: "abc1234 G maintainer@example.com", exit: 0 },
    { tool: "git", match: ["add"],                       stdout: "",     exit: 0 },
    { tool: "git", match: ["commit"],                    stdout: "",     exit: 0 },
    { tool: "git", match: ["verify-commit"],             stdout: "",     exit: 0 },
    { tool: "git", match: ["status", "--porcelain"],     stdout: "",     exit: 0 },
  ]);
  var rv = await spawnRun.runNodeScript([nodePath.join(root, "scripts", "release.js"), "commit"], {
    cwd:       root,
    ceilingMs: RUN_CEILING_MS,
    env:       _standInEnv(plan.planPath),
  });
  rv.calls = _calls(plan.logPath);
  rv.root  = root;
  return rv;
}

// `prepare` is the only subcommand that reaches the vendor-currency gate,
// which sits after the static battery rather than inside it, so the arm
// that refuses an unmeasured vendored pin can only be driven from here.
// It bumps the manifest and regenerates artifacts on the way, which is
// why the fixture carries notes for the bumped version and stand-ins for
// the regeneration scripts.
async function _runPrepare(opts) {
  var root = _fixtureTree(opts);
  var plan = _plan([
    { tool: "git", match: ["rev-parse", "--abbrev-ref"], stdout: "main", exit: 0 },
    { tool: "git", match: ["status", "--porcelain"],     stdout: "",     exit: 0 },
  ]);
  var rv = await spawnRun.runNodeScript([nodePath.join(root, "scripts", "release.js"), "prepare"], {
    cwd:       root,
    ceilingMs: RUN_CEILING_MS,
    env:       _standInEnv(plan.planPath),
  });
  rv.calls = _calls(plan.logPath);
  rv.root  = root;
  return rv;
}

function _assertGateStoppedTheCut(label, run, named) {
  count(label + ": the cut stops",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 4));
  count(label + ": it names the gate",
    run.out.indexOf(named) !== -1, tail(run.out, 8));
  count(label + ": it says the gate checked nothing and that is not a pass",
    /not a pass/i.test(run.out), tail(run.out, 8));
  count(label + ": it never reports the gate as absent but tolerated",
    !/gate not configured/i.test(run.out) && run.out.indexOf("skip: " + named) === -1,
    tail(run.out, 8));
  count(label + ": no commit was made",
    run.calls.indexOf("git commit") === -1, run.calls.trim());
}

// The latent defect, on the gate whose absence is easiest to miss: a
// validator nobody watches run.
async function anAbsentGateScriptStopsTheCut() {
  var run = await _runCommit({ omit: "scripts/validate-source-comment-blocks.js" });
  _assertGateStoppedTheCut("absent validator", run, "scripts/validate-source-comment-blocks.js");
}

// The same question on the detector suite. It is the gate that carries
// every structural rule in the tree, so its absence is the one that
// silences the most, and it went through the same tolerant helper.
async function anAbsentDetectorSuiteStopsTheCut() {
  var run = await _runCommit({ omit: DETECTOR_GATE });
  _assertGateStoppedTheCut("absent detector suite", run, DETECTOR_GATE);
}

// Absence is one way for a gate to stop gating. The other is a gate that
// still runs, still exits clean, and asserted nothing on the way, which
// reads as a clean bill of health for every rule it carries.
async function anInertDetectorSuiteStopsTheCut() {
  var run = await _runCommit({ silentGate: DETECTOR_GATE });
  count("inert detector suite: the cut stops",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 6));
  count("inert detector suite: it names the gate",
    run.out.indexOf(DETECTOR_GATE) !== -1, tail(run.out, 8));
  count("inert detector suite: it says nothing was asserted",
    /asserted nothing/i.test(run.out), tail(run.out, 8));
  count("inert detector suite: no commit was made",
    run.calls.indexOf("git commit") === -1, run.calls.trim());
}

// The same defect on each of the gates that publish an examined-count.
// A count of zero is the whole point: the gate ran, exited clean and
// printed the line it always prints, and the only thing that says its
// discovery matched nothing is the number. `OK, no findings` over an
// empty file set is byte-identical to `OK, no findings` over the tree.
//
// Driven per gate rather than once, because a helper that read only the
// first gate's count would satisfy a single vector while every gate
// behind it went unread.
var COUNTED_STATIC_GATES = [
  "scripts/validate-source-comment-blocks.js",
  "scripts/check-api-snapshot.js",
  "scripts/check-spelling-consistency.js",
  "scripts/check-status-lifecycle.js",
];

async function anEmptyExaminedCountStopsTheCut() {
  for (var i = 0; i < COUNTED_STATIC_GATES.length; i += 1) {
    var gate = COUNTED_STATIC_GATES[i];
    var run = await _runCommit({ inertGate: gate });
    count(gate + " examining nothing: the cut stops",
      run.code !== 0, "exit " + run.code + ": " + tail(run.out, 6));
    count(gate + " examining nothing: it names the gate",
      run.out.indexOf(gate) !== -1, tail(run.out, 8));
    count(gate + " examining nothing: it says the discovery matched an empty set",
      /examined nothing/i.test(run.out) && /empty set/i.test(run.out), tail(run.out, 8));
    count(gate + " examining nothing: it says that is not a pass",
      /not a pass/i.test(run.out), tail(run.out, 8));
    count(gate + " examining nothing: no commit was made",
      run.calls.indexOf("git commit") === -1, run.calls.trim());
  }
}

// The unit is load-bearing, not decoration. A gate that opened files and
// extracted no block from any of them proved as little as one that opened
// none, so a gate publishing several units has to be refused on ANY of
// them being zero rather than on the first one it prints.
async function oneEmptyUnitAmongSeveralStopsTheCut() {
  var gate = "scripts/validate-source-comment-blocks.js";
  var publishes = {};
  publishes[gate] = ["EXAMINED 22 lib-source-files", "EXAMINED 0 primitive-blocks"];
  var run = await _runCommit({ publishes: publishes });

  count("one empty unit: a non-zero first unit does not carry the second",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 6));
  count("one empty unit: the refusal names the unit that was empty",
    run.out.indexOf("primitive-blocks") !== -1, tail(run.out, 8));
  count("one empty unit: it does not name the unit that was not",
    run.out.indexOf("0 lib-source-files") === -1, tail(run.out, 8));
  count("one empty unit: no commit was made",
    run.calls.indexOf("git commit") === -1, run.calls.trim());
}

// The vendored pin, on the one subcommand that measures it. Its gate is
// the closest of the battery to self-proving, because it names every
// package it looked at, and it is still the one whose success line can be
// printed over nothing: every entry resolving to a skip prints a package
// count and then reports that every checked package matches upstream.
async function anUnmeasuredVendoredPinStopsTheCut() {
  var gate = "scripts/check-vendor-currency.js";
  // The shape the real gate prints when every manifest entry resolves to a
  // skip: the manifest still has a package in it, and nothing was measured.
  // The count it already printed before any of this was the first number.
  var publishes = {};
  publishes[gate] = ["EXAMINED 1 manifest-packages", "EXAMINED 0 measured-packages"];
  var run = await _runPrepare({ publishes: publishes });
  count("unmeasured vendored pin: the cut stops",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 6));
  count("unmeasured vendored pin: it names the gate",
    run.out.indexOf(gate) !== -1, tail(run.out, 8));
  count("unmeasured vendored pin: it says nothing was measured",
    /measured-packages/.test(run.out) && /empty set/i.test(run.out), tail(run.out, 10));
  count("unmeasured vendored pin: it never reports the bundles as current",
    run.out.indexOf("vendored bundles current") === -1, tail(run.out, 10));
}

// The control for the three above: the same tree with every gate present
// and live runs the battery to the end. Without it a helper that refused
// everything would satisfy all of them.
async function aCompleteBatteryRunsToTheCommit() {
  var run = await _runCommit({});
  count("complete battery: every gate ran",
    run.out.indexOf("gate stand-in") !== -1, tail(run.out, 8));
  count("complete battery: the cut reaches the commit",
    run.calls.indexOf("git commit") !== -1, run.calls.trim());
  count("complete battery: it exits clean",
    run.code === 0, "exit " + run.code + ": " + tail(run.out, 6));
  count("complete battery: nothing was tolerated as absent",
    !/gate not configured/i.test(run.out), tail(run.out, 8));
  count("complete battery: each counted gate's examined-count is read back",
    /validate-source-comment-blocks\.js: 22 lib-source-files, 115 primitive-blocks/.test(run.out) &&
    /check-api-snapshot\.js: 22 lib-source-files, 115 frozen-primitives/.test(run.out) &&
    /check-spelling-consistency\.js: 282 scanned-files/.test(run.out),
    tail(run.out, 24));
  // The other half of the same rule. Not every script in the battery
  // answers in a unit, and the ones that only round-trip a generated
  // artifact are compared against the artifact itself rather than over a
  // set that could come back empty. The battery has to keep running those
  // rather than demanding a number from anything shaped like a script.
  count("complete battery: a gate that publishes no count is still tolerated",
    run.out.indexOf("scripts/generate-changelog-entry.js: gate stand-in") !== -1, tail(run.out, 24));
}

// The control for the vendor-currency vector, on its own subcommand.
async function aMeasuredVendoredPinReachesTheEndOfPrepare() {
  var run = await _runPrepare({});
  count("measured vendored pin: prepare exits clean",
    run.code === 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("measured vendored pin: the count is read back",
    /check-vendor-currency\.js: 1 manifest-packages, 1 measured-packages/.test(run.out),
    tail(run.out, 12));
  count("measured vendored pin: only then are the bundles reported current",
    run.out.indexOf("vendored bundles current") !== -1, tail(run.out, 12));
}

async function run() {
  // The controls lead. A run that stops at the first failure has then
  // already shown that the vectors below it are asking a live question
  // rather than failing for a reason of their own.
  await cleanChecksAndCleanThreadsAdvance();
  await aCompleteBatteryRunsToTheCommit();
  await aMeasuredVendoredPinReachesTheEndOfPrepare();

  await failingChecksAloneRefuseToAdvance();
  await failingChecksAndOpenThreadsBothReport();
  await openThreadsAloneKeepTheirCode();

  await anAbsentGateScriptStopsTheCut();
  await anAbsentDetectorSuiteStopsTheCut();
  await anInertDetectorSuiteStopsTheCut();

  await anEmptyExaminedCountStopsTheCut();
  await oneEmptyUnitAmongSeveralStopsTheCut();
  await anUnmeasuredVendoredPinStopsTheCut();

  return helpers.getChecks();
}

module.exports = { name: "release-gate-verdicts", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
