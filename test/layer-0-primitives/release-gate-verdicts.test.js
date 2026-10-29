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
 * WHAT THE STAND-IN ANSWERS is data, not code: a table of replies matched
 * on the argument tokens, so a vector reads as the situation it describes
 * rather than as a program. A call no reply matches is refused loudly
 * instead of answered with a default, because a default is how a vector passes
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
// what a gate said it examined. `run-gates.js` is the runner that executes
// the declared chain, and release.js reads two things from it: the count
// words a gate may answer in, and `scripts.gates` out of package.json, which
// is the one authority for WHICH gates the static battery runs.
var RELEASE_SIBLINGS = ["examined-counts.js", "run-gates.js"];

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
  'var STAND_IN_TOOLS = ["gh", "git", "npm", "docker"];',
  'function _asTool(token) {',
  '  var name = standInPath.basename(String(token || "")).toLowerCase().replace(/\\.(?:exe|js)$/, "");',
  '  return STAND_IN_TOOLS.indexOf(name) === -1 ? null : name;',
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
  '  var _table = JSON.parse(standInFs.readFileSync(process.env.BLAMEPOST_TOOL_STAND_IN, "utf8"));',
  '  standInFs.appendFileSync(_table.log, _tool + " " + _argv.join(" ") + "\\n");',
  '  var _reply = null;',
  '  for (var _i = 0; _i < _table.replies.length && _reply === null; _i += 1) {',
  '    var _candidate = _table.replies[_i];',
  '    if (_candidate.tool !== _tool) continue;',
  '    var _missed = _candidate.match.filter(function (t) { return _argv.indexOf(t) === -1; });',
  '    if (_missed.length === 0) _reply = _candidate;',
  '  }',
  '  if (_reply === null) {',
  '    standInFs.writeSync(2, "tool stand-in: no reply for " + _tool + " " + _argv.join(" ") + "\\n");',
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
    ["git.exe", "docker.exe"].forEach(function (name) {
      try { nodeFs.linkSync(gh, nodePath.join(dir, name)); }
      catch (_e) { nodeFs.copyFileSync(gh, nodePath.join(dir, name)); }
    });
    nodeFs.writeFileSync(nodePath.join(dir, "npx.cmd"),
      "@echo off\r\necho npx stand-in: nothing installed, nothing run\r\nexit /b 0\r\n");
    // `npm` is the one tool release.js reaches through a shell, so it
    // resolves a .cmd shim rather than an executable. The shim runs node
    // against a file named for the tool, which is what the preload reads
    // the tool name off; the file itself is only reached if the preload
    // did not fire, and it refuses loudly rather than answering.
    nodeFs.writeFileSync(nodePath.join(dir, "npm.cmd"),
      "@echo off\r\nnode \"%~dp0npm.js\" %*\r\n");
    nodeFs.writeFileSync(nodePath.join(dir, "npm.js"),
      '"use strict";\n' +
      'process.stderr.write("npm stand-in: the preload did not answer\\n");\n' +
      "process.exit(67);\n");
  } else {
    ["gh", "git", "npm", "docker"].forEach(function (name) {
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
function _standInEnv(repliesPath, extra) {
  var dir = _standInDirectory();
  var env = {};
  Object.keys(process.env).forEach(function (k) {
    if (k.toLowerCase() === "path" || k.toLowerCase() === "node_options") return;
    env[k] = process.env[k];
  });
  env.PATH = dir + nodePath.delimiter + (process.env.PATH || "");
  env.BLAMEPOST_TOOL_STAND_IN = repliesPath;
  if (process.platform === "win32") {
    // Forward slashes: this variable is parsed with backslash as an
    // escape, so a Windows path written as it comes arrives with its
    // separators eaten and the preload is never found.
    env.NODE_OPTIONS = "--require " + nodePath.join(dir, "stand-in.js").replace(/\\/g, "/");
  }
  Object.keys(extra || {}).forEach(function (k) { env[k] = extra[k]; });
  return env;
}

// Write a reply table and return the paths the caller reads back.
function _replyTable(replies) {
  var dir         = helpers.tempDir("tool-replies");
  var logPath     = nodePath.join(dir, "calls.log");
  var repliesPath = nodePath.join(dir, "replies.json");
  nodeFs.writeFileSync(logPath, "");
  nodeFs.writeFileSync(repliesPath, JSON.stringify({ log: logPath, replies: replies }, null, 2));
  return { repliesPath: repliesPath, logPath: logPath };
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
  var table = _replyTable([
    { tool: "gh", match: ["pr", "list"],      stdout: PR_NUMBER, exit: 0 },
    { tool: "gh", match: ["pr", "checks"],
      stdout: opts.checksExit === 0 ? CHECKS_PASSING_OUTPUT : CHECKS_FAILING_OUTPUT,
      exit:   opts.checksExit },
    { tool: "gh", match: ["api", "graphql"], stdout: _threadsPayload(opts.threads), exit: 0 },
  ]);
  var rv = await spawnRun.runNodeScript([RELEASE_JS, "watch"], {
    cwd:       helpers.REPO_ROOT,
    ceilingMs: RUN_CEILING_MS,
    env:       _standInEnv(table.repliesPath, { RELEASE_SKIP_CODEX_WAIT: "1" }),
  });
  rv.calls = _calls(table.logPath);
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
// publish
// ---------------------------------------------------------------------------

// `publish` is the last subcommand of the flow, so its exit code is the
// whole cut's verdict, and the two artifacts it answers for are published by
// two different workflows. The npm side has always had a second reading: it
// watches the run, and then it asks the registry what version is there, so a
// run that could not be found does not decide anything on its own.
//
// The container side had only the first half. When `gh run list` came back
// empty it printed a note and carried on, and an empty answer is what a
// renamed workflow, a token without the scope to list runs, and an API
// hiccup all produce. Each of those read as a published image.
//
// Driven the way an operator drives it: the subcommand in a child process
// with `gh`, `npm` and `docker` answered by the stand-in, asserting on the
// exit code and the transcript.
var PUBLISHED_DIGEST = "sha256:" + "ab12cd34".repeat(8);

// The image the fixture manifest resolves to. The tag carries no `v`: the
// git tag is `vX.Y.Z` and the image published from it is `X.Y.Z`. Built
// when it is read rather than at load, because the version it is composed
// from is declared with the fixture tree further down.
function fixtureImage() {
  return "ghcr.io/blamejs/blamepost:" + FIXTURE_VERSION;
}

async function _runPublish(opts) {
  opts = opts || {};
  var root    = _fixtureTree({});
  var replies = [
    { tool: "gh", match: ["run", "list", "--workflow=npm-publish.yml"],
      stdout: opts.npmRunId || "", exit: 0 },
    { tool: "gh", match: ["run", "list", "--workflow=release-container.yml"],
      stdout: opts.containerRunId || "", exit: 0 },
    { tool: "npm", match: ["view"],
      stdout: opts.npmVersion === undefined ? FIXTURE_VERSION : opts.npmVersion, exit: 0 },
    { tool: "docker", match: ["imagetools", "inspect"],
      stdout: opts.imageDigest === undefined ? "" : opts.imageDigest,
      exit:   opts.imageExit === undefined ? 1 : opts.imageExit },
  ];
  if (opts.npmRunId) {
    replies.push({ tool: "gh", match: ["run", "watch", opts.npmRunId],
      stdout: "", exit: opts.npmWatchExit || 0 });
  }
  if (opts.containerRunId) {
    replies.push({ tool: "gh", match: ["run", "watch", opts.containerRunId],
      stdout: "", exit: opts.containerWatchExit || 0 });
  }
  var table = _replyTable(replies);
  var rv = await spawnRun.runNodeScript([nodePath.join(root, "scripts", "release.js"), "publish"], {
    cwd:       root,
    ceilingMs: RUN_CEILING_MS,
    env:       _standInEnv(table.repliesPath),
  });
  rv.calls = _calls(table.logPath);
  rv.root  = root;
  return rv;
}

// The live defect. No container run is found, nothing was ever asked of the
// registry, and the npm side is healthy, so the flow reported a clean
// publish for a tag whose image may not exist.
async function anAbsentContainerRunIsNotAPublishedImage() {
  var run = await _runPublish({ containerRunId: "", imageExit: 1 });

  count("absent container run: the registry is asked about the image anyway",
    run.calls.indexOf("docker buildx imagetools inspect " + fixtureImage()) !== -1,
    run.calls.trim());
  count("absent container run: the cut does not exit clean",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("absent container run: the refusal names the image an operator would pull",
    run.out.indexOf(fixtureImage()) !== -1, tail(run.out, 10));
  count("absent container run: it never reports the image as published",
    !/container image published/i.test(run.out), tail(run.out, 10));
}

// The same question with the run found and green. A watch that passed says
// the workflow concluded, not that the registry serves the tag, so the
// second reading has to happen either way.
async function aPassingContainerRunStillHasToShowTheImage() {
  var run = await _runPublish({ containerRunId: "4242", imageExit: 1 });

  count("passing container run: it was watched to completion",
    run.calls.indexOf("gh run watch 4242") !== -1, run.calls.trim());
  count("passing container run: the registry is still asked",
    run.calls.indexOf("docker buildx imagetools inspect") !== -1, run.calls.trim());
  count("passing container run: an unservable image still stops the cut",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
}

// An answer that is not a digest is not an answer. A command that exits
// clean having printed a warning, or nothing at all, would otherwise read as
// a published image.
async function anAnswerThatIsNotADigestIsRefused() {
  var run = await _runPublish({ imageExit: 0, imageDigest: "unauthorized" });
  count("no digest: a clean exit with no digest in it is refused",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("no digest: the refusal quotes what came back instead",
    run.out.indexOf("unauthorized") !== -1, tail(run.out, 10));
}

// Both artifacts missing at once. An operator wants one pass to say what is
// wrong with the release rather than two rounds, and the npm arm reporting
// first must not hide the container arm behind it.
async function bothSidesAreReportedFromOnePass() {
  var run = await _runPublish({ npmVersion: "0.0.9", imageExit: 1 });
  count("both missing: the cut stops",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 10));
  count("both missing: the registry version it found is reported",
    run.out.indexOf("0.0.9") !== -1, tail(run.out, 12));
  count("both missing: the image is reported in the same pass",
    run.out.indexOf(fixtureImage()) !== -1, tail(run.out, 12));
}

// The control. Without it a command that refused everything would satisfy
// every vector above.
async function aPublishedReleaseOnBothSidesExitsClean() {
  var run = await _runPublish({
    npmRunId:       "11",
    containerRunId: "22",
    imageExit:      0,
    imageDigest:    PUBLISHED_DIGEST,
  });
  count("published: the cut exits clean",
    run.code === 0, "exit " + run.code + ": " + tail(run.out, 10));
  count("published: the npm version is read back",
    /npm matches 0\.1\.0/.test(run.out), tail(run.out, 12));
  count("published: the image digest is read back",
    run.out.indexOf(PUBLISHED_DIGEST) !== -1, tail(run.out, 12));
  count("published: both workflow runs were watched",
    run.calls.indexOf("gh run watch 11") !== -1 &&
    run.calls.indexOf("gh run watch 22") !== -1, run.calls.trim());
}

// A failing container workflow keeps the answer it already had: the watch
// decides, and the registry reading below it never runs, because the image
// that is there is the previous release's.
async function aFailingContainerRunStillStopsTheCut() {
  var run = await _runPublish({
    npmRunId:             "11",
    containerRunId:       "22",
    containerWatchExit:   1,
    imageExit:            0,
    imageDigest:          PUBLISHED_DIGEST,
  });
  count("failing container run: the cut stops",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 10));
  count("failing container run: the refusal is about the workflow rather than the registry",
    /release-container workflow run concluded FAILED/.test(run.out), tail(run.out, 12));
}

// ---------------------------------------------------------------------------
// The static battery, in a tree of its own
// ---------------------------------------------------------------------------

// The fixture's own declared chain, written into its package.json as
// `scripts.gates` the way the real one is. release.js no longer holds a list
// of gates: it reads this one. So a fixture tree that declared nothing would
// run no gate at all, and the vectors below would pass over a battery that
// never happened.
//
// It carries a gate release.js has never named anywhere in its source,
// `check-node-floor.js`, because that is the property the change is about: the
// hand-written battery in release.js had drifted three gates behind the chain,
// and a release cut therefore ran a weaker battery than `npm run gates`.
// Nothing about this list is copied from the real package.json; the vector
// below asserts that whatever it says is what runs.
var CHAIN_GATES = [
  "node test/layer-0-primitives/codebase-patterns.test.js",
  "node scripts/validate-source-comment-blocks.js",
  "node scripts/check-api-snapshot.js",
  "node scripts/check-spelling-consistency.js",
  "node scripts/check-status-lifecycle.js",
  "node scripts/check-node-floor.js",
  "node scripts/pin-all.js --check",
];

// The gates the battery runs BESIDE the chain: the release-artifact
// round-trips, which compare a generated document against the notes it derives
// from rather than sweeping a set of the tree.
var BESIDE_CHAIN_GATES = [
  "scripts/consolidate-release-notes.js",
  "scripts/generate-changelog-entry.js",
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
// Every gate the battery runs is in this map, because every one of them now
// goes through the counted helper. A gate absent from it publishes nothing and
// is refused, which is the shape `aGateThatPublishesNoCountStopsTheCut` drives.
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
  "scripts/generate-changelog-entry.js": [
    "EXAMINED 2 rendered-releases",
    "EXAMINED 9 swept-prose-strings",
    "EXAMINED 40 rendered-artifact-lines",
  ],
  "scripts/check-node-floor.js": [
    "EXAMINED 26 workflow-floor-references",
    "EXAMINED 4 container-floor-references",
    "EXAMINED 8 document-floor-references",
    "EXAMINED 3 floor-documents",
  ],
  "scripts/pin-all.js": [
    "EXAMINED 2 lockfile-manifests",
    "EXAMINED 3 pinned-specs",
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
    (GATE_COUNTS[rel] || DEFAULT_GATE_COUNT).forEach(function (published) {
      var line = rel === opts.inertGate ? published.replace(/\s\d+\s?/, " 0 ").trimEnd() : published;
      lines.push('console.log("' + line + '");');
    });
  }
  return '"use strict";\n' + lines.join("\n") + "\n";
}

// What a gate with no entry of its own publishes. Every gate the battery runs
// goes through the counted helper, so a stand-in that published nothing would
// be refused for that rather than for whatever the vector is about. Silence is
// spelled by `opts.silentGate` alone.
var DEFAULT_GATE_COUNT = ["EXAMINED 5 fixture-units"];

// A tree with the shape release.js reads and nothing else: the script
// itself, a manifest, notes for the version in it, and the gate scripts.
// The real repository is never the subject here, because `commit` writes
// a branch and a commit into whatever tree it is pointed at.
// The declared chain as package.json spells it: the runner's path followed by
// one quoted command per gate. `opts.omitChain` writes a manifest with no
// `scripts.gates` at all, and `opts.extraChainGate` appends a link release.js
// names nowhere in its own source.
function _chainScript(opts) {
  var links = CHAIN_GATES.slice();
  if (opts.extraChainGate) links.push("node " + opts.extraChainGate);
  return "node scripts/run-gates.js " +
    links.map(function (l) { return '"' + l + '"'; }).join(" ");
}

// Every gate script a fixture tree carries. The fixture writes all of them and
// then removes the one the vector is about, so a missing gate is the only
// difference between two runs. `check-vendor-currency.js` sits after the
// battery in `prepare` rather than inside it, and is carried for the one
// subcommand that reaches it.
function _fixtureGates(opts) {
  return CHAIN_GATES
    .concat(opts.extraChainGate ? ["node " + opts.extraChainGate] : [])
    .map(function (link) { return link.split(/\s+/)[1]; })
    .concat(BESIDE_CHAIN_GATES, ["scripts/check-vendor-currency.js"]);
}

function _fixtureTree(opts) {
  opts = opts || {};
  var root = helpers.tempDir("releasetree");
  ["scripts", "release-notes", "test", "test/layer-0-primitives"].forEach(function (d) {
    nodeFs.mkdirSync(nodePath.join(root, d), { recursive: true });
  });
  var manifest = {
    name:       "@blamejs/blamepost",
    version:    FIXTURE_VERSION,
    repository: { url: "https://github.com/blamejs/blamepost.git" },
  };
  if (!opts.omitChain) manifest.scripts = { gates: _chainScript(opts) };
  nodeFs.writeFileSync(nodePath.join(root, "package.json"),
    JSON.stringify(manifest, null, 2) + "\n");
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
  _fixtureGates(opts).concat(REGEN_SCRIPTS).forEach(function (rel) {
    if (rel === opts.omit) return;
    nodeFs.mkdirSync(nodePath.join(root, nodePath.dirname(rel)), { recursive: true });
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
  var table = _replyTable([
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
    env:       _standInEnv(table.repliesPath),
  });
  rv.calls = _calls(table.logPath);
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
  var table = _replyTable([
    { tool: "git", match: ["rev-parse", "--abbrev-ref"], stdout: "main", exit: 0 },
    { tool: "git", match: ["status", "--porcelain"],     stdout: "",     exit: 0 },
  ]);
  var rv = await spawnRun.runNodeScript([nodePath.join(root, "scripts", "release.js"), "prepare"], {
    cwd:       root,
    ceilingMs: RUN_CEILING_MS,
    env:       _standInEnv(table.repliesPath),
  });
  rv.calls = _calls(table.logPath);
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
    tail(run.out, 30));
  // The gate the hand-written battery had drifted away from. It is declared in
  // the chain and named nowhere in release.js, so it runs only because the
  // battery reads the chain.
  count("complete battery: a gate the chain declares and release.js never names is run",
    /check-node-floor\.js: 26 workflow-floor-references/.test(run.out), tail(run.out, 30));
  // The other half of the same rule, and the half that used to be discarded.
  // The CHANGELOG round-trip publishes both of its units and the battery ran it
  // for the exit code alone, which is the same hole as a gate that says nothing
  // reached from the caller's side.
  count("complete battery: the CHANGELOG round-trip's published count is read back too",
    /generate-changelog-entry\.js: 2 rendered-releases, 9 swept-prose-strings, 40 rendered-artifact-lines/
      .test(run.out), tail(run.out, 30));
  count("complete battery: the battery says how many gates the chain declared",
    /declared gate chain: 7 gate\(s\) from package\.json scripts\.gates/.test(run.out),
    tail(run.out, 30));
}

// The property the change is for, driven rather than described: a gate added
// to `scripts.gates` runs in the release cut with no edit to release.js. The
// link below names a script this test file invented and release.js has never
// heard of.
async function aGateAddedToTheChainRunsInTheReleaseBattery() {
  var added = "scripts/check-something-nobody-named.js";
  var run = await _runCommit({ extraChainGate: added });

  count("added gate: the battery ran a gate release.js does not name",
    run.out.indexOf(added + ": gate stand-in") !== -1, tail(run.out, 30));
  count("added gate: and read the count it published",
    run.out.indexOf(added + ": 5 fixture-units") !== -1, tail(run.out, 30));
  count("added gate: and counted it among the gates the chain declared",
    /declared gate chain: 8 gate\(s\)/.test(run.out), tail(run.out, 30));
  count("added gate: and the cut still reaches the commit",
    run.calls.indexOf("git commit") !== -1, run.calls.trim());
}

// The same gate, made inert. A gate that only runs because the chain names it
// still has to be refused for examining nothing, or reading the chain would
// have bought a longer battery and a weaker one.
async function aGateAddedToTheChainIsHeldToTheCountContract() {
  var added = "scripts/check-something-nobody-named.js";
  var publishes = {};
  publishes[added] = ["EXAMINED 0 fixture-units"];
  var run = await _runCommit({ extraChainGate: added, publishes: publishes });

  count("added gate examining nothing: the cut stops",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("added gate examining nothing: it names the gate",
    run.out.indexOf(added) !== -1, tail(run.out, 10));
  count("added gate examining nothing: no commit was made",
    run.calls.indexOf("git commit") === -1, run.calls.trim());
}

// The read that decides the whole battery, blinded. A manifest with no
// `scripts.gates` leaves release.js with no list at all, and the outcome that
// must not happen is the quiet one: a battery of zero gates reported as a
// battery that passed.
async function aTreeDeclaringNoGateChainStopsTheCut() {
  var run = await _runCommit({ omitChain: true });

  count("no declared chain: the cut stops",
    run.code !== 0, "exit " + run.code + ": " + tail(run.out, 8));
  count("no declared chain: it says where the list is supposed to come from",
    /scripts\.gates/.test(run.out), tail(run.out, 10));
  count("no declared chain: it says an absent chain would score over nothing",
    /over nothing/i.test(run.out), tail(run.out, 10));
  count("no declared chain: no gate was reported as passing",
    run.out.indexOf("gate stand-in") === -1, tail(run.out, 10));
  count("no declared chain: no commit was made",
    run.calls.indexOf("git commit") === -1, run.calls.trim());
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
  await aPublishedReleaseOnBothSidesExitsClean();

  await failingChecksAloneRefuseToAdvance();
  await failingChecksAndOpenThreadsBothReport();
  await openThreadsAloneKeepTheirCode();

  await anAbsentContainerRunIsNotAPublishedImage();
  await aPassingContainerRunStillHasToShowTheImage();
  await anAnswerThatIsNotADigestIsRefused();
  await bothSidesAreReportedFromOnePass();
  await aFailingContainerRunStillStopsTheCut();

  await anAbsentGateScriptStopsTheCut();
  await anAbsentDetectorSuiteStopsTheCut();
  await anInertDetectorSuiteStopsTheCut();

  await anEmptyExaminedCountStopsTheCut();
  await oneEmptyUnitAmongSeveralStopsTheCut();
  await anUnmeasuredVendoredPinStopsTheCut();

  await aGateAddedToTheChainRunsInTheReleaseBattery();
  await aGateAddedToTheChainIsHeldToTheCountContract();
  await aTreeDeclaringNoGateChainStopsTheCut();

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
