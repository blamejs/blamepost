// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The SMTP command reader, driven with the bytes an unauthenticated peer
 * puts on port 25.
 *
 * Three readers sit on that path and all three run here.
 *
 * `b.guardSmtpCommand.detectBodySmuggling` reads the DATA body octets.
 * `lib/mail/listeners.js` calls it on every assembled body before
 * anything is stored or relayed, because a body carrying a non-canonical
 * end-of-data sequence is read as two messages by a receiver that honors
 * it (CVE-2023-51764 Postfix, CVE-2023-51765 Sendmail, CVE-2023-51766
 * Exim).
 *
 * `b.guardSmtpCommand.validate` reads one command line. The MX and
 * submission listeners both call it before the state machine sees the
 * verb, with the caps this server leaves at the framework defaults: the
 * strict profile, a 1 KiB line, and no SMTPUTF8, since blamepost passes
 * neither `maxLineBytes` nor `allowSmtpUtf8` to `b.mail.server.mx.create`.
 *
 * `lib/store/address.js` reads the path out of an accepted `MAIL FROM`
 * or `RCPT TO`, and the domain out of an accepted `EHLO` or `HELO`. Both
 * entry points used here are documented never to throw, because the
 * listener holding their result answers a bad address with a protocol
 * code rather than with an exception, so a throw from either is a
 * finding on its own.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js smtp-command "EHLO example.com"
 */

var b       = require("../lib/vendor/blamejs");
var address = require("../lib/store/address");
var harness = require("./harness");

// What the MX and submission listeners hand the guard. `profile` is the
// server default from `lib/config/index.js`; the other two are the
// framework defaults that apply because this server sets neither.
var COMMAND_OPTS = {
  profile:       "strict",
  maxLineBytes:  1024,
  allowSmtpUtf8: false,
};

var REFUSALS = [b.guardSmtpCommand.GuardSmtpCommandError];

function _readPath(parsed) {
  // `_validatePath` returns the path with its angle brackets on, which
  // is the form `address.parse` takes off an SMTP forward path.
  var raw = parsed.args && parsed.args[0];
  if (typeof raw !== "string") return;
  harness.neverThrows("blamepost.store.address.parse", function () {
    return address.parse(raw);
  });
}

function _readHeloName(parsed) {
  var raw = parsed.args && parsed.args[0];
  if (typeof raw !== "string") return;
  harness.neverThrows("blamepost.store.address.parseDomain", function () {
    return address.parseDomain(raw);
  });
}

module.exports.fuzz = function (data) {
  // The DATA-phase screen, on the raw octets. A body is 8-bit (RFC 6152)
  // and this reader is defined on bytes, so the buffer goes in whole and
  // undecoded.
  harness.read(REFUSALS, function () {
    return b.guardSmtpCommand.detectBodySmuggling(data);
  });

  var lines = harness.lines(data);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    var parsed = harness.read(REFUSALS, function () {
      return b.guardSmtpCommand.validate(line, COMMAND_OPTS);
    });
    if (parsed === null) continue;
    switch (parsed.verb) {
      case "MAIL":
      case "RCPT":
        _readPath(parsed);
        break;
      case "EHLO":
      case "HELO":
        _readHeloName(parsed);
        break;
      default:
        break;
    }
  }
};

// The readers above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at each one.
module.exports.targets = function () {
  return [
    { name: "b.guardSmtpCommand.detectBodySmuggling",
      of: b.guardSmtpCommand, call: "detectBodySmuggling" },
    { name: "b.guardSmtpCommand.validate", of: b.guardSmtpCommand, call: "validate" },
    { name: "blamepost.store.address.parse", of: address, call: "parse" },
    { name: "blamepost.store.address.parseDomain", of: address, call: "parseDomain" },
  ];
};
