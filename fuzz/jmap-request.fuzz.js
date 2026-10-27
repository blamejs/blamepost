// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The JMAP request reader, driven with the bytes a client puts in a POST
 * to `/jmap/api` or in a WebSocket text frame.
 *
 * `b.guardJmap.validate` is the envelope reader on both transports, and
 * it reaches them by two different routes. The HTTP handler passes the
 * request body straight through, and the guard takes a Buffer: it caps
 * the byte length before parsing and runs `b.safeJson.parse` itself, so
 * the raw octets go in undecoded. The WebSocket handler parses the frame
 * first with `b.safeJson.parse` and hands `dispatch` an object, which
 * reaches the same guard by its pre-parsed branch. Both routes run here,
 * because the byte cap and the JSON reader are on one of them only.
 *
 * The capabilities are the two this server advertises in
 * `lib/web/index.js`. A `using` entry outside that set is refused with
 * `urn:ietf:params:jmap:error:unknownCapability`, so a harness carrying
 * a wider set would be reading a server nobody runs.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js jmap-request '{"using":[],"methodCalls":[]}'
 */

var b       = require("../lib/vendor/blamejs");
var harness = require("./harness");

var SERVER_CAPABILITIES = {
  "urn:ietf:params:jmap:mail":       {},
  "urn:ietf:params:jmap:submission": {},
};

var ENVELOPE_OPTS = {
  profile:            "strict",
  serverCapabilities: SERVER_CAPABILITIES,
};

var ENVELOPE_REFUSALS = [b.guardJmap.GuardJmapError];
var JSON_REFUSALS     = [b.safeJson.SafeJsonError];

module.exports.fuzz = function (data) {
  // The HTTP route: raw octets, capped and parsed inside the guard.
  harness.read(ENVELOPE_REFUSALS, function () {
    return b.guardJmap.validate(data, ENVELOPE_OPTS);
  });

  // The WebSocket route: the frame decoded as UTF-8 and parsed before
  // the guard sees it.
  var parsed = harness.read(JSON_REFUSALS, function () {
    return b.safeJson.parse(data.toString("utf8"));
  });
  if (parsed === null || typeof parsed !== "object") return;

  harness.read(ENVELOPE_REFUSALS, function () {
    return b.guardJmap.validate(parsed, ENVELOPE_OPTS);
  });
};

// The readers above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at each one.
module.exports.targets = function () {
  return [
    { name: "b.guardJmap.validate", of: b.guardJmap, call: "validate" },
    { name: "b.safeJson.parse", of: b.safeJson, call: "parse" },
  ];
};
