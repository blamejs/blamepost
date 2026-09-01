// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test/helpers: shared infrastructure for the per-file test layout.
 *
 * One require covers the common case:
 *
 *   var helpers = require("../helpers");
 *   var check   = helpers.check;
 *   var b       = helpers.b;
 *
 * What lives here:
 *
 *   - `b`, the vendored framework handle. It loads on first property
 *     access, so a file that only reads source text (the structural
 *     detectors, the vendor manifest gate) never pays the load cost.
 *   - `check(label, condition)`, the assertion. Every passing check
 *     increments a per-process counter. A test file's CLI entry prints
 *     `CHECKS <n>` from `getChecks()`, and test/smoke.js parses that
 *     line out of the forked child's stdout to aggregate the run total.
 *     It takes two arguments and refuses a third: a detail passed here
 *     has nowhere to go, and a call that dropped one printed a bare
 *     label on the day it failed. `count` is where a detail belongs.
 *   - `count(label, condition, detail, opts)`, the same assertion with
 *     the value that produced the verdict quoted in the failure message.
 *     Anything reading a wire transcript, a rendered page or a spawned
 *     process wants this one, because a bare "expected true" leaves
 *     nothing to read and sends the reader back for another run.
 *     `opts.limit` sets how much of the value is quoted. Bind it as
 *     `var count = helpers.count` rather than redefining it locally: a
 *     private copy is a second assertion with its own idea of how much
 *     of the failing value to keep.
 *   - `skip(reason)`, for a check that could not run because a
 *     precondition the test does not control was absent. A skip is not
 *     a pass: it lands in its own counter so a run that skipped a
 *     cross-check never reports the same total as one that ran it.
 *   - `waitUntil(predicate, opts)`, which polls a condition to a
 *     deadline. A fixed-budget sleep is the flake a loaded runner
 *     finds, so the `test-promise-settimeout-sleep` detector refuses
 *     that shape outright and this is the replacement.
 *   - `tempDir(prefix)`, a data directory under the operating system
 *     temp root, removed when the process exits. Store tests need real
 *     files on disk and must not write into the working tree.
 *   - `closeWithTempDir(dir, handle)`, which ties a handle's close to
 *     that directory's removal. A store left open while its directory
 *     goes is a locked file on one platform and a teardown rejection on
 *     the other, and it is the line a `finally` block loses first.
 *
 * Requiring this module also installs the late-rejection report, which
 * keeps a rejection arriving during teardown from replacing the failure
 * the run had already decided. It needs no call: every file here
 * requires this module, so every file is covered. The reasoning is
 * written above the handler itself.
 *
 * Validation posture: these are entry points a test author calls
 * directly, so bad input throws rather than degrading to a default.
 * The cleanup paths are the exception and drop silent by design: a
 * failure to remove a temp directory must never mask the assertion
 * failure that left it behind. The late-rejection report enforces that
 * same rule for the async case.
 */

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");

// Repository root, resolved from this file rather than from the process
// working directory, so a test forked with any cwd finds the same tree.
var REPO_ROOT   = path.resolve(__dirname, "..", "..");
var VENDOR_ROOT = path.join(REPO_ROOT, "lib", "vendor", "blamejs");

// ---------------------------------------------------------------------------
// Framework handle
// ---------------------------------------------------------------------------

// Loaded on first access. The vendored tree costs a few hundred
// milliseconds to require, which is worth paying once in the tests that
// compose against it and worth skipping entirely in the ones that read
// source text.
var _b = null;
function frameworkHandle() {
  if (_b === null) _b = require(VENDOR_ROOT);
  return _b;
}

// ---------------------------------------------------------------------------
// Assertion + counters
// ---------------------------------------------------------------------------

var _checks = 0;
var _skips  = [];

// Whether any assertion in this process has failed. Read only by the
// late-rejection report at the bottom of this file.
var _assertionFailed = false;

function check(label, condition) {
  if (typeof label !== "string" || label.length === 0) {
    throw new TypeError("check: label (non-empty string) required");
  }
  // A third argument here is a detail the caller meant to be quoted in
  // the failure, and this function has nowhere to put it: it would be
  // evaluated, dropped, and the failure would print the label with
  // nothing beside it. Refusing is what makes the mistake visible at
  // the call site instead of on the day the assertion fails, which is
  // the day the value is gone and the only way back to it is another
  // run with a print statement added.
  if (arguments.length > 2) {
    throw new TypeError("check: takes (label, condition). Use count(label, condition, " +
      "detail) to quote the value that produced the verdict.");
  }
  if (!condition) {
    // Remembered so the late-rejection report below can say whether the
    // run had a verdict of its own, rather than leaving the reader to
    // search above for a failure that may not be there.
    _assertionFailed = true;
    throw new Error("FAIL: " + label);
  }
  _checks += 1;
}

/**
 * count(label, condition, detail, opts) is `check` with the value that
 * produced the verdict quoted in the failure.
 *
 * A bare "expected true" on a wire transcript, a rendered page or a
 * spawned process leaves nothing to read, and the usual next move is to
 * re-run with a print statement added, which is the cycle drift rule
 * six exists to stop. The detail is collapsed onto one line and bounded
 * so a fixture's bytes cannot forge extra log rows.
 *
 * opts.limit  characters of `detail` quoted, default 400. Raise it for a
 *             value whose interesting part is at the end, such as a long
 *             container transcript. Copies of this function carrying
 *             their own bound are what this parameter replaces: the two
 *             bounds that existed in the tree differed by accident, not
 *             because any caller had decided anything.
 */
var DEFAULT_DETAIL_LIMIT = 400;

function count(label, condition, detail, opts) {
  opts = opts || {};
  var limit = opts.limit === undefined ? DEFAULT_DETAIL_LIMIT : opts.limit;
  if (typeof limit !== "number" || !isFinite(limit) || limit <= 0) {
    throw new TypeError("count: opts.limit must be a positive finite number");
  }
  var suffix = detail === undefined
    ? ""
    : " (" + String(detail).replace(/[\r\n]+/g, " ").slice(0, limit) + ")";
  check(label + suffix, condition);
}

// A skip records a check that COULD NOT run. Never write `check(reason,
// true)` to stand in for one: that reports a missing cross-check as a
// pass, which is the failure this counter exists to make visible.
function skip(reason) {
  if (typeof reason !== "string" || reason.length === 0) {
    throw new TypeError("skip: reason (non-empty string) required");
  }
  _skips.push(reason);
  console.log("  SKIP: " + reason);
}

function getChecks()      { return _checks; }
function getSkips()       { return _skips.length; }
function getSkipReasons() { return _skips.slice(); }

// formatErr: render a thrown error as one bounded line for a runner's
// failure catch. A test fixture's bytes can reach the message or the
// stack verbatim, so collapsing CR and LF keeps the failure on a single
// row and stops a fixture value forging extra log lines. The tab and
// run collapsing and the length bound are cosmetic.
function formatErr(e) {
  var raw = (e && typeof e.stack === "string" && e.stack) ||
            (e && typeof e.message === "string" && e.message) ||
            String(e);
  var oneLine = raw
    .replace(/[\r\n]+/g, " ")
    .replace(/\t+/g, " ")
    .replace(/ {2,}/g, " ");
  return oneLine.length > 2000 ? oneLine.slice(0, 2000) + "..." : oneLine;
}

// ---------------------------------------------------------------------------
// A late rejection is reported UNDER the failure, never over it
// ---------------------------------------------------------------------------

/**
 * A rejection nobody handled arrives with Node's default policy behind
 * it: the process is torn down where it stands, and the rejection's own
 * stack is the last thing anybody reads. During teardown that is the
 * wrong error. A store closed while a write it started is still in
 * flight, a listener stopping under a request in progress, a spool entry
 * landing after the volume went away: each of those rejects with
 * something that describes the shutdown, and by then the run had
 * ALREADY decided its verdict. The assertion that decided it ends up
 * buried under a fatal dump about the teardown, and the check count the
 * parent reads is lost with it, because the process died before
 * printing it.
 *
 * That is the one moment the log has to be right. The rule is to read
 * the log rather than re-run, and a log whose last error names the wrong
 * subsystem sends the reader to the wrong file. That costs exactly the
 * diagnostic cycle the rule exists to save.
 *
 * So a rejection is recorded here rather than allowed to tear the
 * process down, and reported at exit BELOW the run's own output instead
 * of over it. It is never swallowed: the exit code goes non-zero the
 * moment one arrives, so a run that would otherwise have reported a
 * clean pass fails and says why. What changes is only which error is the
 * verdict, and which is the thing that happened afterwards.
 *
 * Installed on require, so every file gets it without an edit of its
 * own. It is the only handler of its kind in the tree; a second one
 * anywhere would take these rejections first and this report would go
 * quiet while still looking installed.
 *
 * The report goes out through a synchronous fd write for the reason the
 * runner persists its log the same way: at exit a buffered write can be
 * dropped on the floor, and a report nobody receives is the failure this
 * exists to prevent.
 */
var _lateRejections = [];

// Counted apart from the list, which is bounded. A run that rejects in a
// loop still reports how many arrived rather than how many were quoted.
var _lateRejectionCount = 0;

// Bounded so a fixture's bytes cannot flood the report, and so a run
// that rejects in a loop still ends with something readable.
var MAX_REPORTED_REJECTIONS = 20;

function _recordLateRejection(reason) {
  _lateRejectionCount += 1;
  if (_lateRejections.length < MAX_REPORTED_REJECTIONS) {
    var code = (reason && typeof reason.code === "string") ? reason.code + ": " : "";
    _lateRejections.push(code + formatErr(reason));
  }
  // Non-zero the moment one arrives rather than at exit, because a
  // handler that only reports leaves a rejecting run exiting zero.
  if (process.exitCode === undefined || process.exitCode === 0) process.exitCode = 1;
}

function _reportLateRejections() {
  if (_lateRejectionCount === 0) return;
  var lines = [];
  lines.push("");
  lines.push("LATE REJECTION: " + _lateRejectionCount +
    " rejection(s) nobody handled arrived during this run.");
  lines.push(_assertionFailed
    ? "  The run's own failure is printed above and is the one to read. What follows " +
      "happened afterwards, on the way out."
    : "  The run reported no failure of its own, so this IS the finding rather than " +
      "noise beside one.");
  lines.push("  A rejection reaching here means something was still in flight when the " +
    "thing it needed went away: a store closed under a write, a listener stopped under " +
    "a request, a queue drained after the volume. Await it, or drain it before the " +
    "teardown closes what it uses.");
  for (var i = 0; i < _lateRejections.length; i += 1) {
    lines.push("    " + (i + 1) + ". " + _lateRejections[i]);
  }
  if (_lateRejectionCount > _lateRejections.length) {
    lines.push("    (" + (_lateRejectionCount - _lateRejections.length) +
      " more not quoted)");
  }
  lines.push("");
  // Through `process.stderr.write` rather than a raw write to fd 2, because
  // the runner tees that function into `.test-output/smoke.log` and its own
  // per-run log, and a raw fd write goes around the tee.
  //
  // Which matters most for exactly this report. It is the one that fires
  // when the run found nothing else, so a run can exit non-zero while the
  // log a reader is told to open first reads completely clean. That sends
  // them to re-run the suite to see the error, which is the cycle the
  // read-the-log rule exists to stop.
  //
  // Safe at exit: the runner's tee is a synchronous `writeSync` to files it
  // opened, and it registers its own fd-closing exit handler after this
  // module is required, so the logs are still open when this runs.
  try { process.stderr.write(lines.join("\n") + "\n"); }
  catch (_e) { /* drop-silent by design: the exit code still carries the verdict */ }
}

process.on("unhandledRejection", _recordLateRejection);
process.on("exit", _reportLateRejections);

// ---------------------------------------------------------------------------
// Poll, do not sleep
// ---------------------------------------------------------------------------

var DEFAULT_TIMEOUT_MS      = 5000;
var DEFAULT_INTERVAL_MS     = 25;
var DEFAULT_TEST_TIMEOUT_MS = 10000;

/**
 * waitUntil(predicate, opts) polls a synchronous or async predicate
 * every `intervalMs` until it returns a truthy value or `timeoutMs`
 * elapses. A throw inside the predicate counts as "not ready yet" and
 * the next poll re-checks; the last throw is quoted in the timeout
 * message so a predicate that was broken all along reads as broken
 * rather than as slow.
 *
 * Returns the truthy value the predicate produced, so a test can chain
 * assertions on it. Throws `waitUntil timeout: <label>` otherwise.
 *
 * opts.timeoutMs   total budget, default 5000
 * opts.intervalMs  poll cadence, default 25
 * opts.label       named in the timeout error, so a failure log says
 *                  which condition ran out of time
 */
async function waitUntil(predicate, opts) {
  opts = opts || {};
  if (typeof predicate !== "function") {
    throw new TypeError("waitUntil: predicate must be a function");
  }
  var timeoutMs  = typeof opts.timeoutMs  === "number" ? opts.timeoutMs  : DEFAULT_TIMEOUT_MS;
  var intervalMs = typeof opts.intervalMs === "number" ? opts.intervalMs : DEFAULT_INTERVAL_MS;
  if (!isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("waitUntil: timeoutMs must be a positive finite number");
  }
  if (!isFinite(intervalMs) || intervalMs <= 0) {
    throw new TypeError("waitUntil: intervalMs must be a positive finite number");
  }
  var label     = typeof opts.label === "string" && opts.label.length ? opts.label : "condition";
  var deadline  = Date.now() + timeoutMs;
  var lastError = null;
  while (Date.now() < deadline) {
    var rv;
    try { rv = await predicate(); lastError = null; }
    catch (e) { lastError = e; rv = false; }
    if (rv) return rv;
    await new Promise(function (r) { setTimeout(r, intervalMs); });
  }
  // One last evaluation right at the deadline, for a predicate whose
  // latency to truthy is exactly the budget.
  try {
    var finalRv = await predicate();
    if (finalRv) return finalRv;
  } catch (e2) { lastError = e2; }
  var msg = "waitUntil timeout: " + label + " (after " + timeoutMs + "ms)";
  if (lastError) {
    msg += "; last predicate threw: " + ((lastError && lastError.message) || String(lastError));
  }
  throw new Error(msg);
}

/**
 * waitUntilEqual(getter, expected, opts) covers the most common case,
 * "wait until this value equals that value". Primitives compare with
 * `===`; objects compare by JSON shape.
 *
 * It resolves to `{ value: <the matched value> }` rather than to the
 * value itself, so waiting for a falsy target (a counter returning to
 * zero, a flag clearing) resolves instead of polling until the budget
 * runs out.
 */
async function waitUntilEqual(getter, expected, opts) {
  opts = opts || {};
  if (typeof getter !== "function") {
    throw new TypeError("waitUntilEqual: getter must be a function");
  }
  var merged = Object.assign({}, opts);
  if (!merged.label) merged.label = "value equals " + JSON.stringify(expected);
  return waitUntil(function () {
    var v = getter();
    if (v === expected) return { value: v };
    if (v && expected && typeof v === "object" && typeof expected === "object" &&
        JSON.stringify(v) === JSON.stringify(expected)) return { value: v };
    return false;
  }, merged);
}

/**
 * passiveObserve(ms, label) lets real time elapse so a test can assert
 * the ABSENCE of an event across a window: no bounce generated, no
 * retry fired, no audit row written. That assertion cannot be phrased
 * as a predicate, because the claim is precisely that nothing changed.
 *
 * It always burns its full budget, so reach for `waitUntil` whenever
 * there is an observable condition to poll.
 */
function passiveObserve(ms, label) {
  if (typeof ms !== "number" || !isFinite(ms) || ms <= 0) {
    throw new TypeError("passiveObserve: ms must be a positive finite number");
  }
  if (typeof label !== "string" || label.length === 0) {
    throw new TypeError("passiveObserve: label (non-empty string) required");
  }
  return new Promise(function (r) { setTimeout(r, ms); });
}

/**
 * withTestTimeout(label, fn, opts) puts a wall-clock ceiling on an
 * async test body, so a hang surfaces as `test timed out: <label>` in
 * seconds instead of consuming the whole job budget. Default ceiling is
 * 10000ms; a test that genuinely needs longer passes `timeoutMs` with
 * the reason written beside the call.
 */
function withTestTimeout(label, fn, opts) {
  opts = opts || {};
  if (typeof label !== "string" || label.length === 0) {
    throw new TypeError("withTestTimeout: label (non-empty string) required");
  }
  if (typeof fn !== "function") {
    throw new TypeError("withTestTimeout: fn (function) required");
  }
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_TEST_TIMEOUT_MS;
  return new Promise(function (resolve, reject) {
    var settled = false;
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      reject(new Error("test timed out: " + label + " (after " + timeoutMs + "ms)"));
    }, timeoutMs);
    Promise.resolve().then(fn).then(function (v) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(v);
    }, function (e) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(e);
    });
  });
}

// ---------------------------------------------------------------------------
// Temporary data directories
// ---------------------------------------------------------------------------

// Every directory handed out is remembered here and removed at process
// exit, so a test that throws mid-way still leaves the machine clean.
var _tempDirs = [];

/**
 * tempDir(prefix) creates a fresh directory under the operating system
 * temp root and returns its absolute path. Store tests point their data
 * directory at one of these; nothing writes into the working tree.
 *
 * The prefix is restricted to letters, digits, dot, dash and underscore
 * so a caller cannot walk out of the temp root with a separator.
 */
function tempDir(prefix) {
  if (prefix !== undefined && prefix !== null) {
    if (typeof prefix !== "string" || !/^[A-Za-z0-9._-]{1,40}$/.test(prefix)) {
      throw new TypeError("tempDir: prefix must match /^[A-Za-z0-9._-]{1,40}$/");
    }
  }
  var base = path.join(os.tmpdir(), "blamepost-test-" + (prefix || "data") + "-");
  var dir  = fs.mkdtempSync(base);
  _tempDirs.push(dir);
  return dir;
}

// Handles whose close() has to run before a directory is removed, keyed
// by the directory. See closeWithTempDir.
var _tempDirCloses = new Map();

/**
 * closeWithTempDir(dir, handle) ties a handle's lifetime to a temp
 * directory's: `handle.close()` runs immediately before `dir` is
 * removed, whichever way the run ends.
 *
 * The pairing is the point. A store opened on a temp directory and never
 * closed leaves the database handle open while the directory is removed
 * underneath it, which is a file lock on Windows, a deleted file the
 * process is still writing into on Linux, and on both a rejection that
 * arrives during teardown and lands on top of whatever verdict the run
 * had already reached. Every file that opens one has to remember to
 * close it in a `finally` that also has a listener to stop, an
 * environment variable to put back and a directory to remove, and the
 * one line that goes missing is this one: seven files in this tree had
 * lost it. Registering at the OPEN, one line below it, is a thing a
 * reader can see is absent.
 *
 * The close must be SYNCHRONOUS. The removal it hangs off is, including
 * the one at process exit, where there is nothing left to await into.
 * The identity store's close is synchronous for the same reason: it is
 * what a shutdown path calls. A close that hands back a promise is not
 * waited on, so a handle that needs one is closed by its own caller
 * before the directory goes.
 *
 * Registering the same handle twice is harmless, because close is
 * idempotent on every handle this is for. Registering against a
 * directory that was never handed out is refused, because it reads as
 * done and never runs.
 */
function closeWithTempDir(dir, handle) {
  if (typeof dir !== "string" || _tempDirs.indexOf(dir) === -1) {
    throw new TypeError("closeWithTempDir: dir must be a directory tempDir() handed out and " +
      "has not removed yet; a close registered against anything else never runs");
  }
  if (!handle || typeof handle.close !== "function") {
    throw new TypeError("closeWithTempDir: handle must expose close()");
  }
  var registered = _tempDirCloses.get(dir);
  if (registered === undefined) {
    registered = [];
    _tempDirCloses.set(dir, registered);
  }
  registered.push(handle);
  return handle;
}

// removeTempDir: drop-silent by design. Cleanup runs on the failure
// path too, where a Windows file lock or a still-open handle is common,
// and throwing here would replace the real assertion failure with a
// filesystem one. The registered closes are drop-silent for the same
// reason, and they run in reverse order of registration, because a
// handle opened over another one is given back first.
function removeTempDir(dir) {
  var i = _tempDirs.indexOf(dir);
  if (i !== -1) _tempDirs.splice(i, 1);
  var closes = _tempDirCloses.get(dir);
  if (closes !== undefined) {
    _tempDirCloses.delete(dir);
    for (var k = closes.length - 1; k >= 0; k -= 1) {
      try { closes[k].close(); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a test failure */ }
    }
  }
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }); }
  catch (_e) { /* drop-silent by design: cleanup must not mask a test failure */ }
}

function cleanupTempDirs() {
  while (_tempDirs.length) removeTempDir(_tempDirs[_tempDirs.length - 1]);
}

/**
 * withTempDir(prefix, fn) hands `fn` a fresh directory and removes it
 * when `fn` settles, whichever way it settles. Use it when the
 * directory belongs to one test rather than to the whole file.
 */
async function withTempDir(prefix, fn) {
  if (typeof fn !== "function") {
    throw new TypeError("withTempDir: fn (function) required");
  }
  var dir = tempDir(prefix);
  try { return await fn(dir); }
  finally { removeTempDir(dir); }
}

process.on("exit", function () {
  try { cleanupTempDirs(); }
  catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
});

// ---------------------------------------------------------------------------
// Faults the volume can raise
// ---------------------------------------------------------------------------

/**
 * installRemovalFault(fragment, opts) makes the volume refuse to unlink
 * any path carrying `fragment`, until the returned handle is removed.
 *
 * A removal that cannot happen is the state an operator is least likely
 * to be told about and most likely to be hurt by: the verb reports the
 * thing is gone and it is still there. Reproducing it needs a real
 * refusal from the filesystem rather than a stand-in for the code under
 * test, so this wraps `fs.promises.rm` itself and leaves every other
 * path alone.
 *
 * `attempts` records the paths that were refused, in the order they
 * were reached, which is how a caller pins the ORDER a multi-part
 * removal takes its parts in.
 *
 * The code is EBUSY: a volume holding a file open, which is the ordinary
 * shape of this on a running server rather than a permission fault an
 * operator would have hit at boot.
 *
 * opts.times   how many attempts to refuse before letting them through,
 *              default every one of them. A fault that refuses once is
 *              the transient shape, and it is the only one that reaches
 *              a caller which recovers from the refusal and then finds
 *              the volume willing again.
 * opts.before  awaited BEFORE each refusal is handed back, and given the
 *              path. It is what lets a test drive a second caller at the
 *              exact moment a multi-part change is half made, with one
 *              part of a pair already off the volume and the other still
 *              on it, so an interleaving is a fact rather than a hope.
 *              Its own failures are recorded in `beforeErrors` and never
 *              replace the refusal: a hook that threw would otherwise
 *              arrive at the code under test as the unlink's error, and
 *              a fixture that broke would read as the fault it was
 *              written to install.
 */
function installRemovalFault(fragment, opts) {
  if (typeof fragment !== "string" || fragment.length === 0) {
    throw new TypeError("installRemovalFault: fragment (non-empty string) required");
  }
  opts = opts || {};
  var times = opts.times === undefined ? Infinity : opts.times;
  if (times !== Infinity && (typeof times !== "number" || !isFinite(times) ||
      times < 1 || Math.floor(times) !== times)) {
    throw new TypeError("installRemovalFault: opts.times must be a whole count of one or more");
  }
  if (opts.before !== undefined && typeof opts.before !== "function") {
    throw new TypeError("installRemovalFault: opts.before must be a function");
  }
  var real = fs.promises.rm;
  var attempts = [];
  var beforeErrors = [];
  var refused = 0;
  fs.promises.rm = function (target) {
    if (String(target).indexOf(fragment) !== -1 && refused < times) {
      refused += 1;
      attempts.push(String(target));
      var e = new Error("the volume refused to remove " + target);
      e.code = "EBUSY";
      if (opts.before === undefined) return Promise.reject(e);
      return Promise.resolve()
        .then(function () { return opts.before(String(target)); })
        .catch(function (hookErr) { beforeErrors.push(hookErr); })
        .then(function () { return Promise.reject(e); });
    }
    return real.apply(fs.promises, arguments);
  };
  return {
    attempts:     attempts,
    beforeErrors: beforeErrors,
    remove:       function () { fs.promises.rm = real; },
  };
}

/**
 * installSyncRemovalFault(fragment) is the same fault for the other
 * removal, `fs.rmSync`.
 *
 * The two are separate on purpose and the name says which is which,
 * because the shipped code reaches for both and a fixture patching the
 * wrong one refuses nothing while reporting green. The blob release and
 * the message body release are synchronous; the spool removal and the
 * key erasure are not. A test that faults `rm` against a caller that
 * uses `rmSync` proves only that the code ran.
 *
 * `calls` counts the refusals and `attempts` records the paths, so a
 * caller can pin both how many times the volume was asked and in what
 * order.
 *
 * The code is EPERM: a permission the operator changed, which is the
 * ordinary shape of a synchronous unlink refusing.
 */
function installSyncRemovalFault(fragment) {
  if (typeof fragment !== "string" || fragment.length === 0) {
    throw new TypeError("installSyncRemovalFault: fragment (non-empty string) required");
  }
  var real = fs.rmSync;
  var state = { calls: 0, attempts: [] };
  fs.rmSync = function (target) {
    if (String(target).indexOf(fragment) !== -1) {
      state.calls += 1;
      state.attempts.push(String(target));
      var e = new Error("the volume refused to remove " + target);
      e.code = "EPERM";
      throw e;
    }
    return real.apply(fs, arguments);
  };
  state.remove = function () { fs.rmSync = real; };
  return state;
}

/**
 * installWriteFault(fragment) makes the volume refuse to take a write of
 * any path carrying `fragment`, until the returned handle is removed.
 *
 * The third fault, and the one the two above cannot stand in for. A
 * removal that will not happen leaves the volume as it was; a WRITE that
 * will not happen is what turns a partly-finished change into a
 * permanent one, because it is the write that would have put back what
 * the removal already took. Nothing else reproduces the state where one
 * half of a pair is gone and the other half cannot be restored.
 *
 * It patches `fs.renameSync`, which is the last step of an atomic write:
 * the bytes go to a temporary name first and the rename is what makes
 * them the file. Faulting the rename therefore refuses the write as a
 * whole and leaves nothing behind under either name, which is what a
 * volume that will not take a write actually does. Patching the byte
 * write instead would leave a temporary file the caller never learns
 * about.
 *
 * `attempts` records the paths that were refused, in the order they were
 * reached.
 *
 * The code is EROFS: a volume that has gone read-only underneath a
 * running server. It is deliberately NOT one of the transient codes an
 * atomic write retries on, so the refusal is the answer rather than five
 * backoffs and then the answer.
 */
function installWriteFault(fragment) {
  if (typeof fragment !== "string" || fragment.length === 0) {
    throw new TypeError("installWriteFault: fragment (non-empty string) required");
  }
  var real = fs.renameSync;
  var attempts = [];
  fs.renameSync = function (from, to) {
    if (String(from).indexOf(fragment) !== -1 || String(to).indexOf(fragment) !== -1) {
      attempts.push(String(to));
      var e = new Error("the volume refused to take a write of " + to);
      e.code = "EROFS";
      throw e;
    }
    return real.apply(fs, arguments);
  };
  return {
    attempts: attempts,
    remove:   function () { fs.renameSync = real; },
  };
}

// ---------------------------------------------------------------------------
// Stand-in handles
// ---------------------------------------------------------------------------

/**
 * standInDelivery(overrides) is a delivery handle for a test that
 * composes the listeners without wanting a real outbound path.
 *
 * It exists because the listeners require the whole handle, not just
 * `send` and `bounce`: they take outbound queue room for a message
 * before committing any of it, and a handle that cannot answer that
 * composes listeners which accept mail into a queue with no bottom. That
 * contract is refused at construction, so every stand-in has to carry
 * it, and four hand-written copies of one is four places to fix the next
 * time the handle grows a method.
 *
 * The queue answers "there is room" every time and hands back a hold
 * that releases into nothing, which is what a test not about the ceiling
 * wants. A test that IS about the ceiling drives the real handle
 * instead, because a stand-in cannot be its own oracle.
 *
 * `overrides` replaces any top-level key, so a file recording what it
 * was asked to send passes its own `send` and keeps the rest.
 */
function standInDelivery(overrides) {
  var handle = {
    send:   function () { return Promise.resolve({ delivered: [], deferred: [], failed: [] }); },
    bounce: function () { return Promise.resolve({}); },
    queue:  {
      // null is the answer that means the message may proceed.
      admits:   function () { return null; },
      // `taken` is the answer that means the room is this caller's until
      // it releases. Releasing a stand-in hold gives back nothing,
      // because nothing was counted.
      reserve:  function () {
        return { taken: true, refusal: null, release: function () {} };
      },
      capacity: function () {
        return {
          messages: 0, bytes: 0,
          maxMessages: Number.MAX_SAFE_INTEGER, maxBytes: Number.MAX_SAFE_INTEGER,
          refused: 0,
        };
      },
    },
  };
  if (overrides === undefined || overrides === null) return handle;
  if (typeof overrides !== "object" || Array.isArray(overrides)) {
    throw new TypeError("standInDelivery: overrides must be an object of handle keys");
  }
  Object.keys(overrides).forEach(function (k) { handle[k] = overrides[k]; });
  return handle;
}

// ---------------------------------------------------------------------------

module.exports = {
  // Node stdlib re-exports, so a test file needs one require for the
  // ordinary case.
  fs:   fs,
  os:   os,
  path: path,

  // Stand-in handles.
  standInDelivery: standInDelivery,

  // Faults the volume can raise. Two removals and one write, each with
  // its own helper, named for the call it patches: a fixture faulting
  // the wrong one refuses nothing while reporting green.
  installRemovalFault:     installRemovalFault,
  installSyncRemovalFault: installSyncRemovalFault,
  installWriteFault:       installWriteFault,

  // Tree anchors.
  REPO_ROOT:   REPO_ROOT,
  VENDOR_ROOT: VENDOR_ROOT,

  // Assertion + counters.
  check:          check,
  count:          count,
  skip:           skip,
  getChecks:      getChecks,
  getSkips:       getSkips,
  getSkipReasons: getSkipReasons,
  formatErr:      formatErr,

  // Poll, do not sleep.
  waitUntil:       waitUntil,
  waitUntilEqual:  waitUntilEqual,
  passiveObserve:  passiveObserve,
  withTestTimeout: withTestTimeout,

  // Temporary data directories, and the handles that have to be given
  // back before one is removed.
  tempDir:           tempDir,
  withTempDir:       withTempDir,
  closeWithTempDir:  closeWithTempDir,
  removeTempDir:     removeTempDir,
  cleanupTempDirs:   cleanupTempDirs,
};

// The framework handle is a getter so the require cost lands only on
// the files that touch it.
Object.defineProperty(module.exports, "b", {
  enumerable:   true,
  configurable: false,
  get:          frameworkHandle,
});
