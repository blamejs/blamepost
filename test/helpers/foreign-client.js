// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Finding and running a client that is not this codebase.
 *
 * The interop suite exists to put a foreign parser on the other end of
 * the socket, which means the program it drives cannot come from here.
 * It also cannot become a dependency: hard rule one is zero npm runtime
 * dependencies and dev tooling never ships, so a client is LOCATED at
 * run time the way `scripts/check-operator-prose.js` locates its prose
 * checker, and never installed, vendored or postinstalled.
 *
 * Three properties of this file are load bearing.
 *
 * PRESENCE IS DECIDED BY WHETHER THE PROGRAM COULD BE STARTED, never by
 * what it said once it had. "It exited non-zero, so it must not be
 * installed" is how a genuine regression in a client reads as absence
 * and the interop gate quietly stops gating. A spawn that fails with
 * ENOENT is absence. Any spawn that succeeded is presence, whatever the
 * exit code, and a present client that cannot do the job is its own
 * outcome with its own reason attached.
 *
 * ABSENCE IS REPORTED, never passed over and never folded into a pass.
 * `locate` returns a reason on every negative answer, and the caller
 * turns that into `helpers.skip`, which lands in the skip counter rather
 * than the check counter. A run that could not find a client and a run
 * that found one and proved something must never print the same total.
 *
 * AND THE PROBE ASKS FOR THE CAPABILITY, not just the name. A curl built
 * without IMAP is on the path, answers `--version`, and cannot open a
 * mailbox. Accepting it because the file exists would turn every check
 * behind it into a failure about the wrong thing, so `requireInOutput`
 * reads the capability out of the program's own self-description.
 *
 * Nothing here is shipped. It lives beside the other shared helpers so
 * the interop suite keeps one way of locating a client instead of one
 * per file, each with its own idea of what "not installed" looks like.
 *
 * `spawn.js` is the neighboring runner and is not this: it hardcodes
 * `process.execPath` because every gate it drives is a node script, so
 * it can neither run another program nor report one as missing.
 *
 * Validation posture: these are entry points a test author calls
 * directly, so bad input throws rather than degrading to a default.
 */

var { spawn } = require("node:child_process");

var DEFAULT_PROBE_MS = 15000;
var DEFAULT_RUN_MS   = 60000;

// How much of a program's own output is kept when it is quoted back in a
// reason. A client's `--version` can be several lines and the useful
// part is the first.
var REASON_CHARS = 200;

function _firstLine(text) {
  return String(text).split(/\r?\n/)[0].slice(0, REASON_CHARS);
}

/**
 * @primitive test.helpers.foreignClient.run
 * @signature run(bin, args, opts?) -> Promise<{ started, code, stdout, stderr, timedOut }>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: an argument array, a ceiling, and octets kept as octets)
 *
 * One invocation of an external program. Resolves rather than rejects,
 * so a caller that expects a refusal reads it as data.
 *
 * `started` is false only when the program could not be started at all,
 * which is the one condition that means absence. `stdout` and `stderr`
 * are Buffers: a client asked for the octets of a message must not have
 * them decoded on the way back, because a decode is exactly the
 * transformation the interop cases are looking for.
 *
 * The argument array is passed with no shell. On Windows a shell
 * rewrites a POSIX-looking argument into a drive-letter path before the
 * program sees it, so a URL or a path handed through one arrives as
 * something else; an array has nothing for that rewrite to act on.
 *
 * @opts
 *   cwd         working directory for the child
 *   env         the child's environment. Default this process's.
 *   timeoutMs   how long the caller waits, default 60000. Hitting it is
 *               reported as `timedOut` rather than as an exit code,
 *               because "it never finished" and "it exited non-zero"
 *               call for different fixes.
 */
function run(bin, args, opts) {
  opts = opts || {};
  if (typeof bin !== "string" || bin.length === 0) {
    throw new TypeError("foreign-client.run: bin (non-empty string) required");
  }
  if (!Array.isArray(args)) {
    throw new TypeError("foreign-client.run: args must be an array");
  }
  args.forEach(function (a) {
    if (typeof a !== "string") {
      throw new TypeError("foreign-client.run: every argument must be a string");
    }
  });
  var timeoutMs = opts.timeoutMs === undefined ? DEFAULT_RUN_MS : opts.timeoutMs;
  if (typeof timeoutMs !== "number" || !isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("foreign-client.run: opts.timeoutMs must be a positive finite number");
  }

  return new Promise(function (resolve) {
    var child;
    try {
      child = spawn(bin, args, {
        cwd:   opts.cwd,
        env:   opts.env || process.env,
        stdio: ["ignore", "pipe", "pipe"],
        shell: false,
      });
    } catch (e) {
      resolve({
        started:  false,
        code:     null,
        stdout:   Buffer.alloc(0),
        stderr:   Buffer.from(String((e && e.message) || e), "utf8"),
        timedOut: false,
      });
      return;
    }

    var outChunks = [];
    var errChunks = [];
    var settled   = false;
    var timedOut  = false;

    function settle(result) {
      if (settled) return;
      settled = true;
      clearTimeout(ceiling);
      resolve(result);
    }
    var ceiling = setTimeout(function () {
      timedOut = true;
      try { child.kill("SIGKILL"); }
      catch (_e) { /* drop-silent by design: the settle below carries the verdict */ }
      settle({
        started:  true,
        code:     null,
        stdout:   Buffer.concat(outChunks),
        stderr:   Buffer.concat(errChunks),
        timedOut: true,
      });
    }, timeoutMs);

    child.stdout.on("data", function (d) { outChunks.push(d); });
    child.stderr.on("data", function (d) { errChunks.push(d); });
    child.on("close", function (code) {
      settle({
        started:  true,
        code:     code,
        stdout:   Buffer.concat(outChunks),
        stderr:   Buffer.concat(errChunks),
        timedOut: timedOut,
      });
    });
    // An ENOENT here is the program not being there. Every other spawn
    // error is a program that exists and could not be started, which is
    // a different answer and is reported as one.
    child.on("error", function (e) {
      settle({
        started:  (e && e.code) !== "ENOENT",
        code:     null,
        stdout:   Buffer.concat(outChunks),
        stderr:   Buffer.from(String((e && e.message) || e), "utf8"),
        timedOut: timedOut,
      });
    });
  });
}

/**
 * @primitive test.helpers.foreignClient.locate
 * @signature locate(spec) -> Promise<{ found, bin, detail, reason }>
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: presence is whether it started, and the probe asks for the capability)
 *
 * Finds a usable client, or says in one sentence why there is not one.
 *
 * `found` true carries `bin`, the name the caller invokes, and `detail`,
 * the first line the program said about itself, so a failure later can
 * be read against the version that produced it. `found` false carries
 * `reason`, which is written to be printed straight into
 * `helpers.skip`.
 *
 * The environment override is tried first and ALONE. A machine that
 * names a client explicitly and names a broken one has said something,
 * and falling through to whatever is on the path would run a different
 * program than the operator asked for and report the result as theirs.
 *
 * @opts
 *   name             what the client is called in a reason, such as "curl"
 *   envVar           environment variable naming an explicit path
 *   candidates       names to try in order when the variable is unset
 *   probeArgs        arguments that make the program describe itself,
 *                    such as ["--version"]
 *   requireInOutput  optional RegExp the self-description has to match
 *                    for the client to count as usable, which is how a
 *                    build lacking the protocol under test is rejected
 *                    as unusable rather than accepted as present
 *   timeoutMs        ceiling on the probe, default 15000
 */
async function locate(spec) {
  if (typeof spec !== "object" || spec === null || Array.isArray(spec)) {
    throw new TypeError("foreign-client.locate: spec must be an object");
  }
  if (typeof spec.name !== "string" || spec.name.length === 0) {
    throw new TypeError("foreign-client.locate: spec.name (non-empty string) required");
  }
  if (typeof spec.envVar !== "string" || spec.envVar.length === 0) {
    throw new TypeError("foreign-client.locate: spec.envVar (non-empty string) required");
  }
  if (!Array.isArray(spec.candidates) || spec.candidates.length === 0) {
    throw new TypeError("foreign-client.locate: spec.candidates must be a non-empty array");
  }
  if (!Array.isArray(spec.probeArgs) || spec.probeArgs.length === 0) {
    throw new TypeError("foreign-client.locate: spec.probeArgs must be a non-empty array");
  }
  if (spec.requireInOutput !== undefined && !(spec.requireInOutput instanceof RegExp)) {
    throw new TypeError("foreign-client.locate: spec.requireInOutput must be a RegExp when supplied");
  }

  var named      = process.env[spec.envVar];
  var overridden = typeof named === "string" && named.length > 0;
  var tries      = overridden ? [named] : spec.candidates.slice();
  var timeoutMs  = spec.timeoutMs === undefined ? DEFAULT_PROBE_MS : spec.timeoutMs;

  var lastReason = null;
  for (var i = 0; i < tries.length; i += 1) {
    var bin = tries[i];
    var rv  = await run(bin, spec.probeArgs, { timeoutMs: timeoutMs });

    if (!rv.started) {
      lastReason = spec.name + " is not on this machine: " + bin + " could not be started" +
        (overridden ? " and " + spec.envVar + " names it" : "");
      continue;
    }
    if (rv.timedOut) {
      lastReason = spec.name + " did not answer " + spec.probeArgs.join(" ") +
        " within " + timeoutMs + "ms, so it was not used";
      continue;
    }

    // Everything the program said about itself. Some clients write the
    // version banner to stderr, and reading only stdout would reject a
    // working one for where it chose to print.
    var described = rv.stdout.toString("utf8") + rv.stderr.toString("utf8");
    if (spec.requireInOutput && !spec.requireInOutput.test(described)) {
      lastReason = spec.name + " is present at " + bin + " and this build cannot do the job: " +
        "its own description does not match " + String(spec.requireInOutput) + ". It said: " +
        JSON.stringify(_firstLine(described));
      continue;
    }
    return { found: true, bin: bin, detail: _firstLine(described), reason: null };
  }

  return {
    found:  false,
    bin:    null,
    detail: null,
    reason: lastReason || (spec.name + " was not found among " + tries.join(", ")),
  };
}

module.exports = {
  DEFAULT_PROBE_MS: DEFAULT_PROBE_MS,
  DEFAULT_RUN_MS:   DEFAULT_RUN_MS,
  locate:           locate,
  run:              run,
};
