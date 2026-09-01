// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A command-line run whose queued message leaves the spool while the
 * data volume is opening.
 *
 * The claim this exists to test is about a spawned process: what an
 * operator is told when the message they asked to cancel is no longer
 * there, and what the shell reads back as the exit status. Neither can
 * be reached by arranging the interleaving in the test's own process,
 * because the binary runs in a different one. So the arrangement is
 * loaded into that process instead, with `--require`, before the binary
 * starts.
 *
 * The moment is the volume open, which is the longest suspension the
 * removal verb has: the vault is unsealed and the encrypted database is
 * decrypted into a working copy. Anything can happen to the spool
 * meanwhile, and in production two things routinely do. One is a
 * `queue flush` running beside this one, which opens no volume at all;
 * the other is the running server's own retry sweep. Both end the same
 * way: the body and the descriptor are unlinked and nothing is told.
 *
 * That is what this does, and it does it exactly once, so the ordering
 * is a fact rather than a hope. The run under test takes the shipped
 * code path in full: the message leaving the spool is a thing that
 * happens to a working server, rather than a branch that skips work when
 * it sees a test.
 *
 * The volume open is also written down, one line per call, because a
 * caller in another process can see the run only through its output.
 * Without it a verb that opened the volume before deciding whether the
 * id names anything would pass every check about what it printed, while
 * having moved the refusal an operator meets for a typo from an argument
 * problem to a lock the running server is holding.
 *
 * Nothing under `lib/` or `bin/` reads the variables below. The guard is
 * here so a caller can read the names out of this file without arranging
 * anything in its own process by doing so.
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var storeModule = require("../../lib/store");

// The spool id whose body and descriptor leave during the first volume
// open of the run. Read here and nowhere else in the repository.
var ID_VAR = "BLAMEPOST_SPOOL_DEPARTURE_ID";

// The queue directory the pair sits in. Named by the caller rather than
// derived, because deriving it here would be a second answer to where
// the spool lives.
var DIR_VAR = "BLAMEPOST_SPOOL_DEPARTURE_DIR";

// Where each volume open is written down, one line per call.
var LOG_VAR = "BLAMEPOST_SPOOL_DEPARTURE_LOG";

function _record() {
  var log = process.env[LOG_VAR];
  if (log) nodeFs.appendFileSync(log, "open\n");
}

function _leaveTheSpool() {
  var dir = process.env[DIR_VAR];
  var id  = process.env[ID_VAR];
  if (!dir || !id) return;
  nodeFs.rmSync(nodePath.join(dir, id + ".json"), { force: true });
  nodeFs.rmSync(nodePath.join(dir, id + ".eml"), { force: true });
}

if (process.env[ID_VAR] || process.env[LOG_VAR]) {
  var real  = storeModule.open;
  var taken = false;
  storeModule.open = function (cfg) {
    _record();
    // Once. A verb that opened the volume twice would otherwise have the
    // message leave on each, and the second departure would be about
    // nothing.
    if (!taken) { taken = true; _leaveTheSpool(); }
    return real.call(storeModule, cfg);
  };
}

module.exports = {
  // The path to hand `--require`, so a caller names this file by asking
  // it rather than by rebuilding the path and drifting from it.
  PRELOAD: __filename,
  ID_VAR:  ID_VAR,
  DIR_VAR: DIR_VAR,
  LOG_VAR: LOG_VAR,
};
