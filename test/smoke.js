// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Smoke test: the orchestrator.
 *
 * Run: `npm test`, or `node test/smoke.js`.
 *
 * Tests run in dependency order, lowest layer first. Each layer is a
 * `test/layer-N-<name>/` directory of per-primitive `*.test.js` files,
 * and the walker picks up any directory matching `layer-*-*`:
 *
 *   Layer 0, pure primitives      test/layer-0-primitives/*.test.js
 *   Layer 1, state                test/layer-1-state/*.test.js
 *   Layer 2, integration          test/layer-2-integration/*.test.js
 *
 * Per-file layout:
 *   - One file per primitive, named `<thing>.test.js`.
 *   - Exports `run()`, sync or async.
 *   - Has a CLI entry, so `node test/layer-0-primitives/<thing>.test.js`
 *     runs that file on its own and prints `CHECKS <n>`.
 *
 * The orchestrator forks each file as its own process, so a crash or a
 * leaked handle is contained to one file, aggregates the per-file check
 * counts, and reports per-file timing. `SMOKE_PARALLEL=N` runs up to N
 * files at once; the default is serial.
 *
 * Three ways a run can lie, and what this file does about each.
 *
 * A file that never exits would hold the run until the job's wall clock
 * ends it, and nothing would say which file. Every child gets a
 * watchdog: past `SMOKE_FILE_TIMEOUT_MS` it is SIGKILLed and reported BY
 * NAME as a failure, which turns an unattributable multi-hour hang into
 * a diagnosable one. The likely causes are a leaked handle, a listener
 * that never released its port, or a first-run key stretch stalled on a
 * starved runner.
 *
 * A file that exits clean having reported neither a check nor a skip is
 * a file that ran and exercised nothing: a missing self-invocation, a
 * fixture loop that fell through, a guard that returned early. In a
 * total it is indistinguishable from a passing file, so it fails here
 * and names itself.
 *
 * A check that could not run is counted apart from the checks that did.
 * `helpers.skip` prints a `SKIP:` line, this file counts those lines,
 * and they are reported on their own rather than folded into the pass
 * count. A skip is never a pass.
 *
 * Layer 2 builds real listeners on real ports, and almost all of it does
 * that inside the test process on ephemeral loopback ports, so it needs
 * nothing installed. The few files that drive the SHIPPED CONTAINER
 * IMAGE say so themselves, by calling the integration harness's engine
 * gate, and those are the only ones held behind a container engine. The
 * engine is probed once, through that same harness, so the runner and
 * the files agree about what "no engine" means. When none answers, each
 * file that needed one is named and counted as skipped, never as passed.
 * Set `SMOKE_REQUIRE_CONTAINER=1` and an absent engine refuses the whole
 * run up front instead, which is what a release or a CI runner wants:
 * the tool being missing is the finding, not something to route around.
 *
 * Environment:
 *   SMOKE_PARALLEL           files to run at once. Default 1 (serial).
 *   SMOKE_FILE_TIMEOUT_MS    per-file watchdog budget. Default 300000.
 *                            A file that drives the container image gets
 *                            that budget plus the harness's own image
 *                            build and health-wait ceilings, because a
 *                            cold build is minutes before the test body
 *                            has started.
 *   SMOKE_REQUIRE_CONTAINER  1 to make an absent container engine refuse
 *                            the run rather than skip the files needing
 *                            one.
 *   SMOKE_ROOT               directory to discover layers under. Default
 *                            this file's directory. It exists so the
 *                            runner's own behavior can be driven over
 *                            fixture files; a root with no layer
 *                            directory in it exits non-zero rather than
 *                            reporting a quiet green.
 *   SMOKE_OUTPUT_DIR         where the log is written. Default
 *                            `.test-output/` at the repository root.
 *   SMOKE_LIST               1 to print the plan (which files would run,
 *                            which would be skipped and why) and exit
 *                            without running anything.
 *
 * A malformed value for any of the numeric variables refuses at startup
 * rather than falling back to a default, so a mistyped budget is a thing
 * the operator is told about instead of a budget they did not choose.
 *
 * Every line of output is persisted through synchronous fd writes, so a
 * failing run's detail is on disk even if the process dies mid-run. Read
 * the log rather than re-running.
 *
 * It goes to TWO files. `<output dir>/smoke.log` is the shared name, and
 * for a single run it is the whole log exactly as it has always been.
 * `<output dir>/smoke-<pid>.log` belongs to this run alone. The second one
 * exists because the first cannot answer for two runs at once: several
 * agents running the suite against one working tree previously left only
 * the last starter's log intact, and the earlier runs wrote into an inode
 * whose directory entry had already been removed, so their output was not
 * merely interleaved but gone. Both paths are printed at startup. Prefer
 * the per-run one whenever more than one run could have been in flight.
 *
 * `SMOKE_OUTPUT_DIR` moves both, which is the other way to keep concurrent
 * runs apart.
 *
 * Separating the logs does not separate the CPU. This runner is serial
 * per run, so several full runs at once do not interleave politely: they
 * starve each other, and a run can sit on its banner for minutes while
 * the others finish. Measured with four in flight at once, none of them
 * completed in the time one alone would have taken.
 *
 * So when more than one person or process is working the same tree, run
 * the files that cover the change rather than the whole suite, and take
 * the full run when the tree is otherwise idle. A full run is the last
 * word on a tree that has stopped moving; started against a tree three
 * other writers are still editing, it is neither fast nor final, because
 * the thing it measured changed while it measured it.
 */

var fs   = require("node:fs");
var path = require("node:path");
var os   = require("node:os");
var { spawn } = require("node:child_process");
var helpers = require("./helpers");

// The engine probe belongs to the integration harness, and the files
// that need an engine already gate themselves on it. Importing it here
// rather than restating a `docker version` call keeps one answer to
// "is there an engine": two would drift, and the run would then disagree
// with the files it is running about whether the thing they need exists.
var containerHarness = require("./layer-2-integration/container-harness");

var REPO_ROOT  = helpers.REPO_ROOT;
var PKG        = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));

// A file that drives the shipped image calls the harness's engine gate.
// That call is the file's own declaration that it needs one, which is
// where the decision belongs: the runner reads it rather than inferring
// a requirement from a directory name, so a file that builds the server
// in process is never held behind an engine it does not use. Anchored on
// the gate CALL and not on the harness import, because a file may import
// the harness to compare against it without ever needing an engine.
//
// The line must reach the call without passing a quote, so a file that
// only WRITES about the gate is not read as making it. A test that
// generates a fixture calling the gate, or an assertion quoting its
// name, would otherwise be held behind an engine it never touches, and
// a test that silently stops running is the failure this gating is here
// to prevent rather than to introduce.
var ENGINE_GATE_RE = /^[^'"\n]*\brequireStack\s*\(/m;

// ---- Environment ----

// Config-time reader: a present but unusable value THROWS. Falling back
// to a default here would hand the operator a budget or a parallelism
// they did not ask for and never tell them.
function _envInt(name, dflt, min) {
  var raw = process.env[name];
  if (raw === undefined || raw === "") return dflt;
  var trimmed = String(raw).trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new TypeError(name + ": expected a whole number, got " + JSON.stringify(raw));
  }
  var n = parseInt(trimmed, 10);
  if (!isFinite(n) || n < min) {
    throw new RangeError(name + ": must be at least " + min + ", got " + JSON.stringify(raw));
  }
  return n;
}

function _envFlag(name) {
  return process.env[name] === "1";
}

var ROOT_DIR = process.env.SMOKE_ROOT
  ? path.resolve(process.env.SMOKE_ROOT)
  : __dirname;
var OUTPUT_DIR = process.env.SMOKE_OUTPUT_DIR
  ? path.resolve(process.env.SMOKE_OUTPUT_DIR)
  : path.join(REPO_ROOT, ".test-output");

// ---- Persistent output ----

try { fs.mkdirSync(OUTPUT_DIR, { recursive: true }); }
catch (_e) { /* drop-silent by design: a missing log must not fail the run */ }
// Two logs, because one fixed path cannot survive two runs at once.
//
// `smoke.log` is the shared name every gate, document and habit points at,
// and for a single run it behaves exactly as it always has. `smoke-<pid>.log`
// is this run's own, and nothing else ever writes to it.
//
// The shared name is NOT unlinked first. Unlinking is what made concurrent
// runs lose their output entirely rather than merely interleave it: the
// second run removed the directory entry while the first still held a
// descriptor on that inode, so every subsequent line the first run wrote
// went to a file with no name, invisible to the very "read the log rather
// than re-running" step it was being written for. Truncating on open gives
// a fresh log for the ordinary case without pulling an inode out from under
// somebody else. Concurrent runs then interleave in the shared log, which is
// recoverable, while each per-run log stays whole and readable.
var LOG_PATH     = path.join(OUTPUT_DIR, "smoke.log");
var RUN_LOG_PATH = path.join(OUTPUT_DIR, "smoke-" + process.pid + ".log");
var _logFd;
var _runLogFd;
try { _logFd = fs.openSync(LOG_PATH, "w"); }
catch (_e) { _logFd = null; /* drop-silent by design: the console still carries the line */ }
try { _runLogFd = fs.openSync(RUN_LOG_PATH, "w"); }
catch (_e) { _runLogFd = null; /* drop-silent by design: same reason */ }
function _writeTo(fd, buf) {
  if (fd === null) return;
  try { fs.writeSync(fd, buf, 0, buf.length, null); }
  catch (_e) { /* drop-silent by design: the console still carries the line */ }
}
function _logWrite(chunk) {
  var buf;
  try { buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8"); }
  catch (_e) { return; }
  _writeTo(_logFd, buf);
  _writeTo(_runLogFd, buf);
}

// One line the SHARED log carries and the per-run log does not.
//
// Keeping a run's output rather than losing it was only half the problem.
// Two runs at once still truncate and interleave here, so a total read out
// of this file can belong to either of them, and that has already happened:
// a run reported its count from this log and was two checks out, because a
// concurrent run's lines were mixed into it. The count was wrong in the
// harmless direction that time. It will not always be.
//
// The banner below names both paths on every run, but a reader arriving at
// this file directly never saw it, so the caution belongs in the file
// rather than only in the thing that opened it.
_writeTo(_logFd, Buffer.from(
  "# Shared log. Concurrent runs interleave here and each truncates it on\n" +
  "# start, so a verdict read from this file may belong to another run.\n" +
  "# Read smoke-<pid>.log instead whenever more than one run could be live;\n" +
  "# the banner below names this run's own file.\n", "utf8"));

var _origStdoutWrite = process.stdout.write.bind(process.stdout);
var _origStderrWrite = process.stderr.write.bind(process.stderr);
process.stdout.write = function (chunk, encoding, cb) { _logWrite(chunk); return _origStdoutWrite(chunk, encoding, cb); };
process.stderr.write = function (chunk, encoding, cb) { _logWrite(chunk); return _origStderrWrite(chunk, encoding, cb); };
process.on("exit", function () {
  try { if (_logFd !== null) fs.closeSync(_logFd); }
  catch (_e) { /* drop-silent by design: the fd goes with the process */ }
  try { if (_runLogFd !== null) fs.closeSync(_runLogFd); }
  catch (_e) { /* drop-silent by design: same reason */ }
});

console.log(PKG.name + " v" + PKG.version + ": smoke test");
console.log("output: " + LOG_PATH);
console.log("this run: " + RUN_LOG_PATH);

var PARALLEL;
var FILE_TIMEOUT_MS;
try {
  PARALLEL        = _envInt("SMOKE_PARALLEL", 1, 1);
  FILE_TIMEOUT_MS = _envInt("SMOKE_FILE_TIMEOUT_MS", 300000, 1000);
} catch (e) {
  console.error("smoke: " + ((e && e.message) || e));
  console.error("smoke: refusing to run on a value nobody chose.");
  process.exit(2);
}

var REQUIRE_CONTAINER = _envFlag("SMOKE_REQUIRE_CONTAINER");
var LIST_ONLY         = _envFlag("SMOKE_LIST");

// A file that drives the image spends most of its budget before its own
// body starts: a cold build pulls base images, and the container's
// health probe has a start period the image declares. Both ceilings
// belong to the harness, so they are read from it rather than guessed at
// again here.
var CONTAINER_TIMEOUT_MS = FILE_TIMEOUT_MS +
  containerHarness.BUILD_TIMEOUT_MS + containerHarness.HEALTHY_TIMEOUT_MS;

// ---- Discovery ----

function _discover() {
  var found = [];
  var entries;
  try {
    entries = fs.readdirSync(ROOT_DIR, { withFileTypes: true });
  } catch (e) {
    console.error("smoke: cannot read the discovery root " + ROOT_DIR + ": " +
      ((e && e.message) || e));
    process.exit(1);
  }
  entries
    .filter(function (e) { return e.isDirectory() && /^layer-\d+-/.test(e.name); })
    .map(function (e) { return e.name; })
    .sort()
    .forEach(function (dir) {
      var full = path.join(ROOT_DIR, dir);
      fs.readdirSync(full)
        .filter(function (f) { return f.endsWith(".test.js"); })
        .sort()
        .forEach(function (f) {
          var file = path.join(full, f);
          var source = "";
          try { source = fs.readFileSync(file, "utf8"); }
          catch (_e) { /* an unreadable file fails when it is spawned, and says why */ }
          found.push({
            layer:          dir,
            file:           file,
            name:           f,
            needsContainer: ENGINE_GATE_RE.test(source),
          });
        });
    });
  return found;
}

// ---- Running one file ----

function _skipLineCount(out) {
  var m = out.match(/^[^\S\r\n]*SKIP:/gm);
  return m ? m.length : 0;
}

function _runOne(entry) {
  return new Promise(function (resolve) {
    var started = Date.now();
    var budget  = entry.needsContainer ? CONTAINER_TIMEOUT_MS : FILE_TIMEOUT_MS;
    var child = spawn(process.execPath, [entry.file], {
      cwd:   REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    var out = "";
    var settled  = false;
    var watchdog = null;
    function settle(result) {
      if (settled) return;
      settled = true;
      if (watchdog !== null) clearTimeout(watchdog);
      resolve(result);
    }
    // Past the budget the child is reaped and the file reported by name.
    // The timer is unref'd so it can never be the thing holding the
    // parent open once every file has settled.
    watchdog = setTimeout(function () {
      try { child.kill("SIGKILL"); }
      catch (_e) { /* drop-silent by design: the verdict below is the result */ }
      settle({
        entry:  entry,
        code:   null,
        checks: 0,
        skips:  0,
        ms:     Date.now() - started,
        out:    out,
        reason: "killed after " + budget + "ms with no exit. A file that does not " +
                "exit is a leaked handle, a listener that never released its port, " +
                "or work that stalled; it is not a pass.",
      });
    }, budget);
    if (typeof watchdog.unref === "function") watchdog.unref();
    child.stdout.on("data", function (d) { out += d.toString(); });
    child.stderr.on("data", function (d) { out += d.toString(); });
    child.on("close", function (code) {
      var m = /CHECKS\s+(\d+)/.exec(out);
      var checks = m ? parseInt(m[1], 10) : 0;
      var skips  = _skipLineCount(out);
      var reason = null;
      // Exited clean having asserted nothing. The skip counter is the
      // honest answer when something could not be checked, so silence
      // here means the file ran and exercised nothing.
      if (code === 0 && checks === 0 && skips === 0) {
        code   = 1;
        reason = "exited 0 having asserted nothing: no CHECKS and no SKIP line. " +
                 "The file ran and exercised nothing.";
      }
      settle({
        entry:  entry,
        code:   code,
        checks: checks,
        skips:  skips,
        ms:     Date.now() - started,
        out:    out,
        reason: reason,
      });
    });
    child.on("error", function (e) {
      settle({
        entry:  entry,
        code:   1,
        checks: 0,
        skips:  0,
        ms:     Date.now() - started,
        out:    out + String((e && e.stack) || e),
        reason: "could not be spawned",
      });
    });
  });
}

async function _pool(items, worker, concurrency) {
  var results = new Array(items.length);
  var next = 0;
  async function lane() {
    for (;;) {
      var i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }
  var lanes = [];
  for (var k = 0; k < Math.min(concurrency, items.length); k++) lanes.push(lane());
  await Promise.all(lanes);
  return results;
}

function _qualified(entry) {
  return entry.layer + " / " + entry.name;
}

(async function main() {
  var discovered = _discover();

  if (!discovered.length) {
    console.error("no test files discovered under " + ROOT_DIR + "/layer-*-*/");
    process.exit(1);
    return;
  }

  // The engine is asked about once, before anything runs, rather than
  // inferred from a file's failure. A file that needs one and is spawned
  // without one reports the engine's absence as a failed assertion about
  // the server, which is the wrong finding entirely.
  var needing = discovered.filter(function (e) { return e.needsContainer; });
  var engine  = { ok: true, reason: "not needed by any discovered file" };
  if (needing.length) {
    engine = await containerHarness.preflight();
  }

  var files   = discovered;
  var skipped = [];
  if (needing.length && !engine.ok) {
    if (REQUIRE_CONTAINER) {
      console.error("");
      console.error("REFUSED: SMOKE_REQUIRE_CONTAINER=1 and no container engine answered.");
      console.error("  " + engine.reason);
      console.error("  " + needing.length + " file(s) drive the shipped image and need one:");
      needing.forEach(function (e) { console.error("    " + _qualified(e)); });
      console.error("Start a container engine, or unset SMOKE_REQUIRE_CONTAINER to have " +
        "those files reported as skipped instead.");
      process.exit(1);
      return;
    }
    files   = discovered.filter(function (e) { return !e.needsContainer; });
    skipped = needing;
  }

  if (LIST_ONLY) {
    console.log("plan: " + files.length + " file(s) to run, " + skipped.length + " to skip");
    files.forEach(function (e) { console.log("  run   " + _qualified(e)); });
    skipped.forEach(function (e) {
      console.log("  skip  " + _qualified(e) + "  (needs a container engine: " +
        engine.reason + ")");
    });
    return;
  }

  if (skipped.length) {
    console.log("");
    console.log("SKIPPED " + skipped.length + " file(s) that drive the shipped container " +
      "image, because no container engine answered:");
    console.log("  " + engine.reason);
    skipped.forEach(function (e) { console.log("  " + _qualified(e)); });
    console.log("A skipped file is not a passing one. Set SMOKE_REQUIRE_CONTAINER=1 to " +
      "make an absent engine fail the run instead.");
  }

  console.log("");
  console.log("running " + files.length + " file(s), parallelism " + PARALLEL + " on " + os.type());
  var results = await _pool(files, _runOne, PARALLEL);

  var totalChecks  = 0;
  var totalSkips   = 0;
  var failures     = [];
  var currentLayer = "";
  results.forEach(function (r) {
    if (r.entry.layer !== currentLayer) {
      currentLayer = r.entry.layer;
      console.log("\n" + currentLayer);
    }
    var status = r.code === 0 ? "ok " : (r.code === null ? "KILL" : "FAIL");
    var detail = r.ms + "ms, " + r.checks + " checks" +
      (r.skips > 0 ? ", " + r.skips + " skipped" : "");
    console.log("  " + status + "  " + r.entry.name + "  (" + detail + ")");
    if (r.code === 0) {
      totalChecks += r.checks;
      totalSkips  += r.skips;
    } else {
      failures.push(r);
    }
  });

  if (failures.length) {
    console.error("\n" + failures.length + " file(s) FAILED:");
    failures.forEach(function (r) {
      console.error("\n=== " + _qualified(r.entry) + " (" +
        (r.code === null ? "no exit" : "exit " + r.code) + ") ===");
      if (r.reason) console.error(r.reason);
      // The console shows the tail; the log takes the failed child's
      // full combined output, so the on-disk record is complete without
      // a re-run.
      _logWrite("\n--- full output: " + _qualified(r.entry) + " ---\n" +
        (r.reason ? r.reason + "\n" : "") +
        r.out + "\n--- end full output ---\n");
      console.error(r.out.trim().split("\n").slice(-25).join("\n"));
    });
    process.exit(1);
    return;
  }

  var summary = "\nOK: " + totalChecks + " checks passed across " + files.length + " file(s)";
  if (skipped.length) {
    summary += ", " + skipped.length + " file(s) skipped (no container engine: " +
      engine.reason + ")";
  }
  if (totalSkips) {
    summary += ", " + totalSkips + " check(s) skipped";
  }
  console.log(summary);
})().catch(function (e) {
  // The orchestrator's own failure has to be a failure. Without this the
  // rejection prints a warning and the process still exits zero, which
  // is a run that decided nothing reporting the same code as a run that
  // passed.
  console.error("smoke: the orchestrator itself failed: " + ((e && e.stack) || e));
  process.exit(1);
});
