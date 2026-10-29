// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The ManageSieve reader, driven with the bytes a client puts on port
 * 4190.
 *
 * Three readers sit on that path and all three run here.
 *
 * `b.guardManageSieveCommand.validate` runs on every line the listener
 * frames, before the verb reaches a handler, with the server's profile
 * and whether the RFC 5804 STARTTLS upgrade has completed. Both TLS
 * states are on the wire, so both are read.
 *
 * `b.guardManageSieveCommand.parseQuotedString` reads the RFC 5804
 * section 1.2 string production. The listener needs it for the client's
 * reply to a SASL challenge, which arrives as a bare string on its own
 * line rather than as a command argument, so it never reaches
 * `validate`.
 *
 * `b.safeSieve.validate` reads the script body a `PUTSCRIPT` literal
 * carries. RFC 5804 section 2.3 requires the server to verify a script
 * before accepting it, and the listener does that on the literal decoded
 * as UTF-8, so the whole input is read that way here as well.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js managesieve-command LISTSCRIPTS
 */

var b       = require("../lib/vendor/blamejs");
var harness = require("./harness");

var COMMAND_REFUSALS = [b.guardManageSieveCommand.GuardManageSieveCommandError];
var SCRIPT_REFUSALS  = [b.safeSieve.SafeSieveError];

function _validate(line, tls) {
  return harness.read(COMMAND_REFUSALS, function () {
    return b.guardManageSieveCommand.validate(line, {
      profile: "strict",
      tls:     tls,
    });
  });
}

module.exports.fuzz = function (data) {
  var lines = harness.lines(data);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    _validate(line, false);
    _validate(line, true);
    // The SASL continuation reading. It returns null on a string it will
    // not take rather than throwing, so any throw from it is a finding.
    harness.read(COMMAND_REFUSALS, function () {
      return b.guardManageSieveCommand.parseQuotedString(line);
    });
  }

  // The PUTSCRIPT literal. The listener decodes the literal body as
  // UTF-8 before handing it to the validator, so the decode happens here
  // in the same place rather than earlier.
  harness.read(SCRIPT_REFUSALS, function () {
    return b.safeSieve.validate(data.toString("utf8"), { profile: "strict" });
  });
};

// The readers above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at each one.
module.exports.targets = function () {
  return [
    { name: "b.guardManageSieveCommand.validate",
      of: b.guardManageSieveCommand, call: "validate" },
    { name: "b.guardManageSieveCommand.parseQuotedString",
      of: b.guardManageSieveCommand, call: "parseQuotedString" },
    { name: "b.safeSieve.validate", of: b.safeSieve, call: "validate" },
  ];
};
