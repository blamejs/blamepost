// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A command-line run whose resolver has gone quiet.
 *
 * The posture check reads DNS through the resolver `blamepost.resolver()`
 * builds, and that resolver fetches over DoH from whatever endpoint
 * `b.network.dns.useDnsOverHttps` names. Pointing the endpoint at an
 * address nothing answers on is therefore the whole fault: every lookup
 * fails to complete, through the shipped transport, with no handle
 * replaced and nothing patched.
 *
 * It has to be loaded into the spawned process, because the claim under
 * test is what `blamepost doctor` prints and what it exits with, and both
 * belong to a process the caller does not share.
 *
 * The address is the loopback discard port. A connection refused is a
 * lookup that failed in a few milliseconds, which is the same verdict a
 * silent nameserver produces at the end of a budget and costs no wall
 * clock to reach. Callers check the port is closed before they rely on
 * it, since a machine that has something listening there would be
 * measuring a different failure.
 *
 * Nothing under `lib/` or `bin/` reads the variable below, and the run
 * takes the shipped code path in full. The guard is here so a caller can
 * read the endpoint out of this file without pointing its own resolver
 * at a dead port by doing so.
 */

var nodeNet = require("node:net");

var b = require("../../lib/vendor/blamejs");

// Where the resolver is sent. Port 9 is the discard service, which
// nothing runs, so a connection to it is refused rather than accepted
// and left hanging.
var QUIET_HOST = "127.0.0.1";
var QUIET_PORT = 9;
var QUIET_ENDPOINT = "https://" + QUIET_HOST + ":" + QUIET_PORT + "/dns-query";

// The variable the spawner sets on the run under test. Read here and
// nowhere else in the repository.
var ARMED_VAR = "BLAMEPOST_DNS_QUIET";

if (process.env[ARMED_VAR] === "1") {
  b.network.dns.useDnsOverHttps({ url: QUIET_ENDPOINT });
}

/**
 * Whether the endpoint above is really refusing connections.
 *
 * It is the precondition for every run armed with this file, and it
 * lives here rather than in each caller for the reason a shared reader
 * always does: a machine with something listening on that port measures
 * a lookup that is accepted and never answered, which is a different
 * failure and one that burns the caller's whole budget instead of
 * failing in a few milliseconds.
 *
 * Resolves true when the connection is refused, which is the state a
 * caller needs before it arms a run.
 */
function endpointIsRefusing() {
  return new Promise(function (resolve) {
    var socket = nodeNet.connect({ host: QUIET_HOST, port: QUIET_PORT });
    var settled = false;
    function done(closed) {
      if (settled) return;
      settled = true;
      try { socket.destroy(); }
      catch (_e) { /* drop-silent by design: the verdict is already decided */ }
      resolve(closed);
    }
    socket.once("connect", function () { done(false); });
    socket.once("error", function () { done(true); });
  });
}

module.exports = {
  // The path to hand `--require`, so a caller names this file by asking
  // it rather than by rebuilding the path and drifting from it.
  PRELOAD:   __filename,
  ARMED_VAR: ARMED_VAR,
  HOST:      QUIET_HOST,
  PORT:      QUIET_PORT,
  ENDPOINT:  QUIET_ENDPOINT,
  endpointIsRefusing: endpointIsRefusing,
};
