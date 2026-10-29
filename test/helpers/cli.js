// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The command line as an operator drives it: the real binary, in a child
 * process, against the run's own data directory.
 *
 * Calling a subcommand's internals proves nothing about this surface,
 * because the internals were never the part that was wrong. What has
 * gone wrong, repeatedly, is a flag that is declared and never read, a
 * verb a document invented, and an exit code that reported a refusal as
 * success. Only a spawned process sees any of those.
 *
 * Two details are load-bearing and both cost a wrong turn to establish.
 * The framework writes JSON log lines around every command, so they are
 * stripped before anything is asserted: otherwise a log line can satisfy
 * a check about what the operator was told. Measured against the shipped
 * binary, those lines arrive on STDOUT, interleaved with the verb's own
 * output, and not on stderr where a reader would expect logging. Both
 * streams are cleaned for that reason and neither is assumed innocent.
 * And a shell pipeline reports the LAST command's status, so a run piped
 * into `grep` reports grep's zero and a correct refusal reads as silent
 * success. That is why the status here comes from the spawn itself and
 * never from a pipe.
 *
 * This lives beside the other shared helpers because several files now
 * need it, and `withoutBootLines` is exported for the callers that
 * cannot use the spawner itself: a run driven inside a container reaches
 * the same framework through a different door and needs the same filter
 * on the way back. A private copy is how two transcripts start
 * disagreeing about what a refusal looks like.
 */

var nodePath = require("node:path");
var nodeProc = require("node:child_process");

var helpers = require("./index");
var spawnHelper = require("./spawn");

var BIN = nodePath.join(helpers.REPO_ROOT, "bin", "blamepost.js");

// Every framework boot line is a JSON object opening with this key.
var BOOT_LINE_PREFIX = "{\"timestamp\"";

/**
 * withoutBootLines(text) removes the framework's log lines from a
 * captured stream and returns what the operator would have read.
 *
 * WHAT IT REMOVES: every line beginning with the framework's JSON log
 * prefix, on whichever stream it arrived. The framework emits one per
 * boot step around any command that opens the store, and they land on
 * stdout, mixed in with the verb's own output.
 *
 * WHY: without this, a log line can satisfy a check about what the
 * operator was told, so the assertion passes on output the operator
 * never sees. A test asserting that a refusal names the offending
 * address is the easy case to get wrong, because the framework logs the
 * address too.
 *
 * The rule is a prefix match rather than a JSON parse, and both halves
 * of that matter. A boot line always starts at column zero with the
 * prefix, and no line an operator reads starts that way. A verb that
 * prints JSON pretty prints it, so its first line is a bare brace and
 * survives untouched; parsing instead would delete the verb's answer.
 *
 * Absent or empty input returns an empty string rather than throwing:
 * a command that wrote nothing to a stream is ordinary, not a fault.
 *
 * Exported because more than one caller needs it and only one of them
 * can use the spawner below. A container-driven run reaches the same
 * binary through docker and reads the same lines back, so it imports
 * this rather than restating it.
 */
function withoutBootLines(text) {
  return String(text || "").split("\n")
    .filter(function (line) { return line.indexOf(BOOT_LINE_PREFIX) !== 0; })
    .join("\n");
}

/**
 * Build a runner bound to one data directory.
 *
 * `dataDir` and `workDir` are the run's own temporary directories, and
 * `workDir` becomes BLAMEJS_TMPDIR so the child's working copy of the
 * encrypted database lands there rather than in the source tree.
 *
 * `execArgv` and `env` are for a run that has to be broken in some way
 * the command line itself has no flag for, such as a fault loaded ahead
 * of the binary with `--require`. They are passed as arguments rather
 * than folded into the environment string, because a path in this tree
 * holds spaces and brackets and a quoted NODE_OPTIONS is one more thing
 * that can be wrong about a run that is already testing a failure. Both
 * default to nothing, so an ordinary caller is unaffected and a broken
 * run is visibly a second runner beside the working one.
 *
 * `coverage: false` starts each child without `NODE_V8_COVERAGE`, so a
 * coverage run collects nothing from it. Every process that collects
 * writes a report of every script it loaded when it exits, and a runner
 * that starts hundreds of them, as the sweep of the documented command
 * surface does, multiplies the run's time and the report's size. It
 * defaults to on.
 */
// The environment a child starts with: this process's, the runner's own
// bindings over it, and no coverage directory when the runner asked for
// none.
function _childEnv(env, opts) {
  var out = Object.assign({}, process.env, env);
  if (opts.coverage === false) delete out.NODE_V8_COVERAGE;
  return out;
}
// The environment one runner binds, settled in one place because two
// runners bind it. A second copy would let the blocking runner and the
// non-blocking one disagree about which volume a run reads, which is the
// one thing about a run that must not depend on how it was started.
function _envFor(label, opts) {
  if (!opts || typeof opts.dataDir !== "string" || typeof opts.workDir !== "string") {
    throw new TypeError("helpers/cli." + label + ": dataDir and workDir are required");
  }
  return Object.assign({
    BLAMEPOST_HOSTNAME:         opts.hostname || "mx.example.com",
    BLAMEPOST_DATA_DIR:         opts.dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: opts.vaultPassphrase ||
      "a long enough vault passphrase for one test run",
    BLAMEJS_TMPDIR:             opts.workDir,
  }, opts.env || {});
}

function create(opts) {
  var env = _envFor("create", opts);
  var execArgv = opts.execArgv || [];
  return function run(args) {
    var result = nodeProc.spawnSync(process.execPath, execArgv.concat([BIN]).concat(args), {
      encoding: "utf8",
      env:      _childEnv(env, opts),
    });
    var stdout = withoutBootLines(result.stdout);
    var stderr = withoutBootLines(result.stderr);
    return {
      status: result.status,
      stdout: stdout,
      stderr: stderr,
      both:   stdout + "\n" + stderr,
      // The same two streams with the framework's log lines still in
      // them. Nearly every caller wants them gone, for the reason in the
      // header above, but a caller asserting on the logging itself needs
      // the lines the filter exists to remove, and reaching for a private
      // spawner to get them is how two transcripts start disagreeing
      // about what a run looks like.
      rawStdout: String(result.stdout || ""),
      rawStderr: String(result.stderr || ""),
    };
  };
}

/**
 * The same runner, awaited rather than blocking.
 *
 * `create` above uses `spawnSync`, which stops this process's event loop
 * until the child exits. That is the right shape for every case whose
 * fixture is on disk, and the wrong one for a case whose fixture answers
 * a socket in THIS process: the child asks, the parent cannot reply
 * because it is blocked in the spawn, and the run deadlocks until
 * something kills it. A stand-in server bound on loopback is exactly
 * that fixture.
 *
 * The two differ in what they can hand back, and the difference is
 * reported rather than papered over. `runNodeScript` merges the child's
 * streams in arrival order, which is what a caller wants from a run
 * whose verdict and detail are split across the two, so there is no
 * separate `stdout` here to offer. Callers that need the streams apart
 * take `create`.
 *
 * The ceiling is the caller's own, so a command that hangs is reported
 * as a run that never finished rather than waiting for whatever budget
 * the binary carries.
 */
function createAsync(opts) {
  var env = _envFor("createAsync", opts);
  var execArgv = opts.execArgv || [];
  var ceilingMs = opts.ceilingMs;
  return async function run(args) {
    var result = await spawnHelper.runNodeScript(execArgv.concat([BIN]).concat(args), {
      env:       _childEnv(env, opts),
      ceilingMs: ceilingMs,
    });
    return {
      status:     result.code,
      ceilingHit: result.ceilingHit,
      both:       withoutBootLines(result.out),
      // The transcript with the framework's own lines still in it, for a
      // caller asserting on the logging rather than on what the operator
      // read.
      raw:        result.out,
    };
  };
}

module.exports = {
  BIN:              BIN,
  create:           create,
  createAsync:      createAsync,
  withoutBootLines: withoutBootLines,
  // The prefix the filter above matches on, exported for the callers
  // that want the boot lines rather than the transcript without them. A
  // test asserting on the logging itself has to select those lines, and
  // spelling the prefix a second time is the thing this module exists to
  // prevent: two spellings that disagree let a log line satisfy a check
  // about what the operator was told.
  BOOT_LINE_PREFIX: BOOT_LINE_PREFIX,
  // A check whose failure message carries the output that produced it.
  // It is not specific to the command line, so it lives with the other
  // assertions and is re-exported here for the files that reach for it
  // through this module.
  count:            helpers.count,
};
