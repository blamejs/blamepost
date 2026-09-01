// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One way to run a script and read what it said.
 *
 * A few cases in this suite assert on the gates themselves: the smoke
 * orchestrator, the interop runner, the release flow's view of them.
 * All of them are node scripts whose whole answer is an exit code and
 * some lines, and every one of those cases needs the same three things.
 *
 * The output has to be COMBINED. A script's verdict and its detail are
 * split across stdout and stderr by whoever wrote it, and a case that
 * reads one stream asserts on half an answer.
 *
 * The run has to have a ceiling. These cases exist because a gate can
 * hang, and a case that waits forever for a gate that hangs inherits the
 * exact failure it was written to catch. The ceiling is the case's own,
 * separate from any budget the script under test carries, and hitting it
 * is reported as a distinct outcome rather than as an exit code, because
 * "it never finished" and "it exited non-zero" call for different
 * fixes.
 *
 * And the process has to be killed when the ceiling fires, so a run that
 * gave up does not leave a child holding a port behind it.
 *
 * A second copy of this would differ from the first by accident: one
 * would read a stream the other does not, or lose its ceiling, and the
 * case built on it would pass for a reason nobody chose.
 *
 * No sockets and no disk. It spawns a node process and buffers what it
 * writes.
 */

var { spawn } = require("node:child_process");

var DEFAULT_CEILING_MS = 60000;

/**
 * @primitive test.helpers.spawn.runNodeScript
 * @signature runNodeScript(argv, opts?) -> Promise<{ code, ceilingHit, ms, out }>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: combined output, own ceiling, child reaped)
 *
 * Runs `node <argv>` and resolves with what it did. `code` is the exit
 * code, or null when the ceiling fired; `ceilingHit` says which of those
 * happened; `out` is stdout and stderr in arrival order.
 *
 * @opts
 *   cwd         working directory. Default the repository root, which is
 *               what a gate script expects to be run from.
 *   env         the child's environment. Default this process's.
 *   ceilingMs   how long the caller waits. Default 60000.
 */
function runNodeScript(argv, opts) {
  opts = opts || {};
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new TypeError("runNodeScript: argv must be a non-empty array");
  }
  argv.forEach(function (a) {
    if (typeof a !== "string") throw new TypeError("runNodeScript: every argument must be a string");
  });
  var ceilingMs = opts.ceilingMs === undefined ? DEFAULT_CEILING_MS : opts.ceilingMs;
  if (typeof ceilingMs !== "number" || !isFinite(ceilingMs) || ceilingMs <= 0) {
    throw new TypeError("runNodeScript: opts.ceilingMs must be a positive finite number");
  }

  return new Promise(function (resolve) {
    var started = Date.now();
    var child = spawn(process.execPath, argv, {
      cwd:   opts.cwd,
      env:   opts.env || process.env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });
    var out = "";
    var settled = false;
    function settle(result) {
      if (settled) return;
      settled = true;
      clearTimeout(ceiling);
      resolve(result);
    }
    var ceiling = setTimeout(function () {
      try { child.kill("SIGKILL"); }
      catch (_e) { /* drop-silent by design: the verdict below is the result */ }
      settle({ code: null, ceilingHit: true, ms: Date.now() - started, out: out });
    }, ceilingMs);
    child.stdout.on("data", function (d) { out += d.toString(); });
    child.stderr.on("data", function (d) { out += d.toString(); });
    child.on("close", function (code) {
      settle({ code: code, ceilingHit: false, ms: Date.now() - started, out: out });
    });
    child.on("error", function (e) {
      settle({
        code:       -1,
        ceilingHit: false,
        ms:         Date.now() - started,
        out:        out + String((e && e.stack) || e),
      });
    });
  });
}

/**
 * @primitive test.helpers.spawn.lastLines
 * @signature lastLines(out, n?) -> string
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: a failure detail that fits on one row)
 *
 * The last `n` non-empty lines of a captured run, joined onto one row so
 * a check's detail carries the end of the transcript without breaking
 * the report into pieces.
 */
function lastLines(out, n) {
  return String(out).trim().split(/\r?\n/).slice(-(n || 3)).join(" | ");
}

module.exports = {
  DEFAULT_CEILING_MS: DEFAULT_CEILING_MS,
  runNodeScript:      runNodeScript,
  lastLines:          lastLines,
};
