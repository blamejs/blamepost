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
 */
function create(opts) {
  if (!opts || typeof opts.dataDir !== "string" || typeof opts.workDir !== "string") {
    throw new TypeError("helpers/cli.create: dataDir and workDir are required");
  }
  var env = Object.assign({
    BLAMEPOST_HOSTNAME:         opts.hostname || "mx.example.com",
    BLAMEPOST_DATA_DIR:         opts.dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: opts.vaultPassphrase ||
      "a long enough vault passphrase for one test run",
    BLAMEJS_TMPDIR:             opts.workDir,
  }, opts.env || {});
  var execArgv = opts.execArgv || [];
  return function run(args) {
    var result = nodeProc.spawnSync(process.execPath, execArgv.concat([BIN]).concat(args), {
      encoding: "utf8",
      env:      Object.assign({}, process.env, env),
    });
    var stdout = withoutBootLines(result.stdout);
    var stderr = withoutBootLines(result.stderr);
    return {
      status: result.status,
      stdout: stdout,
      stderr: stderr,
      both:   stdout + "\n" + stderr,
    };
  };
}

module.exports = {
  BIN:              BIN,
  create:           create,
  withoutBootLines: withoutBootLines,
  // A check whose failure message carries the output that produced it.
  // It is not specific to the command line, so it lives with the other
  // assertions and is re-exported here for the files that reach for it
  // through this module.
  count:            helpers.count,
};
