// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The IMAP command reader, driven with the bytes a client puts on port
 * 143.
 *
 * `b.guardImapCommand.validate` runs on every line the listener frames,
 * before the verb reaches a handler. The listener passes the server's
 * profile and whether the session has an actor yet, so both
 * authentication states are read here: a line refused for an
 * unauthenticated session may be accepted for an authenticated one, and
 * the verb table differs between them.
 *
 * The same guard runs a second time on the line that opened a literal.
 * `_completeLiteralCommand` strips the trailing `{N}` or `{N+}` once the
 * literal body has arrived and validates what is left, so a line
 * carrying an opener reaches the guard twice in two different spellings.
 * Both are driven here.
 *
 * `detectLiteralSmuggling` reads the same line for an opener that is not
 * at the end of it, which is the RFC 9051 section 2.2.2 shape that lets a
 * second command ride inside a literal's byte count.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js imap-command "a1 SELECT INBOX"
 */

var b       = require("../lib/vendor/blamejs");
var harness = require("./harness");

var REFUSALS = [b.guardImapCommand.GuardImapCommandError];

// The listener's own strip, matched byte for byte so the second reading
// of a literal-opening line is the one the server performs rather than a
// second spelling of it.
var LITERAL_OPENER = /\{[0-9]+\+?\}$/;

function _validate(line, authenticated) {
  return harness.read(REFUSALS, function () {
    return b.guardImapCommand.validate(line, {
      profile:       "strict",
      authenticated: authenticated,
    });
  });
}

module.exports.fuzz = function (data) {
  var lines = harness.lines(data);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];

    harness.read(REFUSALS, function () {
      return b.guardImapCommand.detectLiteralSmuggling(line);
    });

    _validate(line, false);
    _validate(line, true);

    // The literal-completion reading. Only a line that actually opened a
    // literal reaches it, so the strip is applied where the listener
    // applies it and skipped where the listener does not.
    if (LITERAL_OPENER.test(line)) {
      var stripped = line.replace(LITERAL_OPENER, "").trim();
      _validate(stripped, false);
      _validate(stripped, true);
    }
  }
};

// The readers above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at each one.
module.exports.targets = function () {
  return [
    { name: "b.guardImapCommand.detectLiteralSmuggling",
      of: b.guardImapCommand, call: "detectLiteralSmuggling" },
    { name: "b.guardImapCommand.validate", of: b.guardImapCommand, call: "validate" },
  ];
};
