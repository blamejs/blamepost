// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A command-line run whose audit sink cannot write.
 *
 * The claim this exists to test is about a spawned process: what an
 * operator is told, and what the shell reads back as the exit status.
 * Neither can be reached by installing a fault in the test's own process,
 * because the binary runs in a different one. So the fault is loaded into
 * that process instead, with `--require`, before the binary starts.
 *
 * The seam is `b.audit.useStore` in the mode where a store failure
 * reaches whoever called `record`. It is the framework's own published
 * surface for putting a sink in front of the chain, so the fault arrives
 * through something this server already composes and nothing is
 * monkey-patched. It refuses every event rather than a chosen namespace:
 * a sink scoped to one name is a sink that proves the verbs it let
 * through were never in its way.
 *
 * Nothing under `lib/` or `bin/` reads the variable below, and the run
 * takes the shipped code path in full: the fault is a broken sink, which
 * is a thing that happens to a working server, rather than a branch that
 * skips work when it sees a test. The guard is here so a caller can read
 * the refusal text out of this file without arming its own process by
 * doing so, which is the only reason it is a condition rather than an
 * unconditional install.
 */

var nodeFs = require("node:fs");

var b = require("../../lib/vendor/blamejs");

// What the sink says when it refuses. Callers check for it by name,
// because the whole claim is that this text never reaches an operator
// who asked for something else.
var REFUSAL = "the audit sink is unavailable";

// The variable the spawner sets on the run under test. Read here and
// nowhere else in the repository.
var ARMED_VAR = "BLAMEPOST_AUDIT_SINK_FAULT";

// Where the sink writes the name of each event it refused, one per line.
// The caller lives in another process and can see the run only through
// its output, so without this a verb that quietly stopped emitting would
// pass every check: the sink it was supposed to be running against was
// never in its way, and nothing about the transcript says so.
var LOG_VAR = "BLAMEPOST_AUDIT_SINK_FAULT_LOG";

if (process.env[ARMED_VAR] === "1") {
  b.audit.useStore({
    replaceChain: true,
    record:       function (row) {
      var log = process.env[LOG_VAR];
      // Appended before the refusal, and synchronously, because the
      // throw on the next line is what ends this call.
      if (log) nodeFs.appendFileSync(log, String((row && row.action) || "") + "\n");
      throw new Error(REFUSAL);
    },
  });
}

module.exports = {
  // The path to hand `--require`, so a caller names this file by asking
  // it rather than by rebuilding the path and drifting from it.
  PRELOAD:   __filename,
  REFUSAL:   REFUSAL,
  ARMED_VAR: ARMED_VAR,
  LOG_VAR:   LOG_VAR,
};
