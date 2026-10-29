// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `logLevel` actually changes, driven through the shipped binary.
 *
 * The setting is declared in the configuration schema, validated, given a
 * default and documented, and for a while nothing read it. A level of
 * `debug` written into the configuration file left the run identical to
 * one that said nothing, and the one place the command line did read a
 * level read the environment variable alone, so the file was an origin
 * the documentation named and the code ignored.
 *
 * Two observable effects are measured here, both from a spawned process
 * because both are lines an operator reads on a terminal:
 *
 *   - the framework's boot logger writes its `debug` entries, which is
 *     where it reports what it recovered from on its own;
 *   - a command that fails prints the stack rather than the offer to
 *     re-run for one.
 *
 * The third case is the limit, and it is asserted rather than left to a
 * document. `info`, `warn` and `error` are written by that logger
 * whatever the level says, so a level above `info` makes a run no
 * quieter. A test that pinned only the debug half would let a document
 * grow a claim about filtering that the code has never made.
 *
 * Run standalone: node test/layer-1-state/cli-log-level.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The debug entry the command line writes once the level is applied. It
// names the file that was read and the volume that was settled on, which
// is the first question behind a command that behaved as though it had
// read something else.
var DEBUG_MESSAGE = "configuration resolved";

// A framework log line carries its level as a field. Matching on the
// field rather than on a message keeps the assertion about which
// severities were written rather than about any one line's wording. The
// prefix that says a line is one of the framework's comes from the
// helper that owns the filter, because a second spelling of it here
// would be a second answer to what a boot line looks like.
var LEVEL_FIELD = "\"level\":";

function linesAtLevel(text, level) {
  return String(text || "").split("\n").filter(function (line) {
    return line.indexOf(cliHelper.BOOT_LINE_PREFIX) === 0 &&
      line.indexOf(LEVEL_FIELD + JSON.stringify(level)) !== -1;
  });
}

// A command that fails once the configuration has been read, so the run
// reaches the failure reporter with the level already applied.
//
// It has to be a failure the command raises rather than one its argument
// readers do. A name that cannot be read is answered on the line, before
// the file is opened and before the reporter is reached, so a malformed
// address or domain measures neither the level nor the reporter. An
// identifier this server never minted is shaped like one and is not on
// the volume, so the refusal comes from the layer that went and looked.
//
// The same identifier drives both halves of the pair below, so the two
// runs differ in the level and in nothing else.
var REFUSED_QUEUE_ID = "no-such-entry";

// A stack trace, as the reporter writes it: the frame lines under the
// message. Matching on the frame shape rather than on a file name keeps
// this from turning into an assertion about where the throw came from.
function hasStackFrames(text) {
  return /\n\s+at\s+/.test(String(text || ""));
}

function writeConfig(root, body) {
  var file = nodePath.join(root, "blamepost.config.json");
  nodeFs.writeFileSync(file, JSON.stringify(body), "utf8");
  return file;
}

// ---- cases --------------------------------------------------------------------

// The file is an origin the documentation names, so it has to reach the
// logger. This is the case that failed: the level was resolved correctly
// and then read by nothing.
function aLevelInTheFileReachesTheLogger(run, configPath) {
  var said = run(["domain", "list", "--config", configPath]);
  var debug = linesAtLevel(said.rawStdout, "debug");
  count("a level written in the configuration file turns on the framework's debug entries",
    debug.length > 0, said.rawStdout.slice(0, 400));
  count("and the entry names the file the run read, which is what an operator asks first " +
    "when a command behaved as though it had read another one",
    debug.some(function (line) {
      return line.indexOf(DEBUG_MESSAGE) !== -1 && line.indexOf("configPath") !== -1;
    }),
    debug.join(" | ").slice(0, 400));
}

// The environment variable is the other documented origin, and it worked
// for the failure reporter and nowhere else. It has to reach the same
// place the file now does.
function aLevelInTheEnvironmentReachesTheLogger(runDebugEnv) {
  var said = runDebugEnv(["domain", "list"]);
  count("the environment variable turns on the same entries the file does",
    linesAtLevel(said.rawStdout, "debug").length > 0, said.rawStdout.slice(0, 400));
}

// The default has to stay silent, or the level is not a level: an
// operator who never set it would be reading recovery diagnostics on
// every command and would learn to skip past them.
function theDefaultWritesNoDebugEntry(run) {
  var said = run(["domain", "list"]);
  count("a run that sets no level writes no debug entry",
    linesAtLevel(said.rawStdout, "debug").length === 0,
    said.rawStdout.slice(0, 400));
}

// The limit, asserted so a document cannot grow a claim the code does not
// make. The boot logger gates `debug` and writes everything above it
// unconditionally, so naming a higher level selects nothing.
function aLevelAboveInfoSilencesNothing(runQuietEnv, run) {
  var quiet = runQuietEnv(["domain", "list"]);
  var ordinary = run(["domain", "list"]);
  count("the run at the default level writes info entries, so there is something a " +
    "higher level could have suppressed",
    linesAtLevel(ordinary.rawStdout, "info").length > 0,
    ordinary.rawStdout.slice(0, 200));
  count("and a level above info suppresses none of them, which is what this server " +
    "documents rather than a fault to route around",
    linesAtLevel(quiet.rawStdout, "info").length > 0,
    quiet.rawStdout.slice(0, 400));
}

// The failure reporter read the environment variable directly, so an
// operator who set the level in the file got the offer to set it in the
// environment instead of the trace they had already asked for.
function aFailingCommandPrintsTheStackWhenTheFileAsks(run, configPath) {
  var said = run(["queue", "show", REFUSED_QUEUE_ID, "--config", configPath]);
  count("the command refused, so there is a failure to report",
    said.status !== 0, "exit " + said.status);
  count("a level of debug written in the configuration file prints the stack",
    hasStackFrames(said.stderr), said.stderr.slice(0, 400));
  count("and the run does not offer a variable for something it has already done",
    said.stderr.indexOf("Re-run with") === -1, said.stderr.slice(0, 400));
}

function aFailingCommandOffersTheVariableWhenNoLevelAsks(run) {
  var said = run(["queue", "show", REFUSED_QUEUE_ID]);
  count("a command that failed without a level asked for prints no stack",
    !hasStackFrames(said.stderr), said.stderr.slice(0, 400));
  count("and names the variable that would produce one",
    said.stderr.indexOf("BLAMEPOST_LOG_LEVEL=debug") !== -1, said.stderr.slice(0, 400));
}

// ---- runner -------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-log-level");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  try {
    var debugConfig = writeConfig(root, { logLevel: "debug" });

    var base = {
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    };
    var plain = cliHelper.create(base);
    var debugEnv = cliHelper.create(Object.assign({}, base, {
      env: { BLAMEPOST_LOG_LEVEL: "debug" },
    }));
    var quietEnv = cliHelper.create(Object.assign({}, base, {
      env: { BLAMEPOST_LOG_LEVEL: "error" },
    }));

    aLevelInTheFileReachesTheLogger(plain, debugConfig);
    aLevelInTheEnvironmentReachesTheLogger(debugEnv);
    theDefaultWritesNoDebugEntry(plain);
    aLevelAboveInfoSilencesNothing(quietEnv, plain);
    aFailingCommandPrintsTheStackWhenTheFileAsks(plain, debugConfig);
    aFailingCommandOffersTheVariableWhenNoLevelAsks(plain);

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-log-level", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
