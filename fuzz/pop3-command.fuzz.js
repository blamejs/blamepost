// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The POP3 command reader, driven with the bytes a client puts on port
 * 110.
 *
 * `b.guardPop3Command.validate` runs on every line the listener frames,
 * before the verb reaches a handler. The listener passes the server's
 * profile and whether the connection has completed the RFC 2595 STLS
 * upgrade, and the guard uses that to decide which verbs are available:
 * the credential verbs are refused in the clear. Both states are on the
 * wire, so both are read here.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js pop3-command "RETR 1"
 */

var b       = require("../lib/vendor/blamejs");
var harness = require("./harness");

var REFUSALS = [b.guardPop3Command.GuardPop3CommandError];

function _validate(line, tls) {
  return harness.read(REFUSALS, function () {
    return b.guardPop3Command.validate(line, { profile: "strict", tls: tls });
  });
}

module.exports.fuzz = function (data) {
  var lines = harness.lines(data);
  for (var i = 0; i < lines.length; i += 1) {
    _validate(lines[i], false);
    _validate(lines[i], true);
  }
};

// The reader above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at it.
module.exports.targets = function () {
  return [
    { name: "b.guardPop3Command.validate", of: b.guardPop3Command, call: "validate" },
  ];
};
