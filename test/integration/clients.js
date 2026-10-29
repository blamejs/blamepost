// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * test/integration/clients.js
 *
 * The foreign clients this suite drives, in one table.
 *
 * Two readers need the same answer to "what does this suite need on the
 * machine, and is it here". The interop FILES need it to decide whether to
 * drive a case or record a skip. The RUNNER needs it to say, before it spawns
 * anything, how many of those clients it actually located and which ones it
 * did not. A runner holding its own copy of the specs would answer a question
 * about a different set of programs than the one the files went on to use,
 * which is the whole failure this table exists to prevent: a report about
 * something adjacent to the thing being reported on.
 *
 * An entry is keyed by a CAPABILITY, not by a program. `python` alone is not
 * an answer: the submission cases need an interpreter whose standard library
 * has `smtplib` and the mailbox cases need one with `imaplib`, and a build
 * carrying one and not the other is present for one id and absent for the
 * other. Same for curl, which reports the protocols it was compiled with and
 * ships in builds that have SMTP and no IMAP.
 *
 * HOW A FILE CLAIMS AN ENTRY. It passes the id to `spec`, which is also how
 * the runner discovers what that file needs: the runner reads the file's
 * source and takes every id in this table that appears in it as a quoted
 * string. The id is the anchor rather than the name of the variable it lands
 * in or the module it was reached through, so renaming either changes
 * nothing. `spec` throws on an id this table does not carry, so a typo is a
 * failure at the first call rather than a client nobody looked for.
 *
 * `timeoutMs` here is the ceiling on the PROBE, which is the one invocation
 * that decides presence. What a case then allows the client for the work
 * itself is the case's own budget and lives with the case.
 *
 * Validation posture: these are entry points a test author calls directly, so
 * bad input throws rather than degrading to a default.
 */

// The probe ceiling for a client the mailbox files drive. A cold interpreter
// on a starved runner takes seconds to import its standard library.
var MAILBOX_PROBE_MS = 30000;

// The submission file's clients get longer, because it drives them over
// sessions that hold a socket open and its ceiling is set for that.
var SUBMISSION_PROBE_MS = 60000;

// One entry per capability. `name` is what a refusal calls the program, and
// it stays the program's ordinary name so a reason reads as a sentence about
// something the operator can install.
var CLIENTS = Object.freeze({
  // The submission sessions. `smtplib` stays on the socket after a refusal,
  // which is what the survival cases read.
  "python-smtplib": Object.freeze({
    id:              "python-smtplib",
    name:            "python",
    envVar:          "BLAMEPOST_PYTHON_BIN",
    candidates:      Object.freeze(["python3", "python", "py"]),
    probeArgs:       Object.freeze(["-c", "import smtplib;print('SMTPLIB ' + smtplib.__name__)"]),
    requireInOutput: /^SMTPLIB smtplib/m,
    timeoutMs:       SUBMISSION_PROBE_MS,
  }),

  // A C parser sharing no code with the interpreter, reading the same
  // refusals off the same listener.
  "curl-smtp": Object.freeze({
    id:              "curl-smtp",
    name:            "curl",
    envVar:          "BLAMEPOST_CURL_BIN",
    candidates:      Object.freeze(["curl"]),
    probeArgs:       Object.freeze(["--version"]),
    requireInOutput: /^Protocols:.*\bsmtps?\b/m,
    timeoutMs:       SUBMISSION_PROBE_MS,
  }),

  // The mailbox session. `imaplib` names the revisions it will speak, which
  // is what the capability case reads.
  "python-imaplib": Object.freeze({
    id:              "python-imaplib",
    name:            "python",
    envVar:          "BLAMEPOST_PYTHON_BIN",
    candidates:      Object.freeze(["python3", "python", "py"]),
    probeArgs:       Object.freeze([
      "-c", "import imaplib;print('IMAPLIB ' + ' '.join(imaplib.AllowedVersions))",
    ]),
    requireInOutput: /^IMAPLIB \S/m,
    timeoutMs:       MAILBOX_PROBE_MS,
  }),

  // The octet walk, which addresses a message by an RFC 5092 URL and needs a
  // curl whose build carries IMAP.
  "curl-imap": Object.freeze({
    id:              "curl-imap",
    name:            "curl",
    envVar:          "BLAMEPOST_CURL_BIN",
    candidates:      Object.freeze(["curl"]),
    probeArgs:       Object.freeze(["--version"]),
    requireInOutput: /^Protocols:.*\bimaps?\b/m,
    timeoutMs:       MAILBOX_PROBE_MS,
  }),
});

var IDS = Object.freeze(Object.keys(CLIENTS));

/**
 * @primitive test.integration.clients.spec
 * @signature spec(id) -> { name, envVar, candidates, probeArgs, requireInOutput, timeoutMs }
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one table, claimed by id, read by both the files and the runner)
 *
 * The locate specification for one capability, ready to hand to
 * `test/helpers/foreign-client.locate`. An id this table does not carry
 * throws, naming the ids it does, because a client nobody can look for is a
 * case that silently stops running.
 */
function spec(id) {
  if (typeof id !== "string" || !Object.prototype.hasOwnProperty.call(CLIENTS, id)) {
    throw new TypeError("integration clients: no client is registered under " +
      JSON.stringify(id) + ". Registered: " + IDS.join(", "));
  }
  return CLIENTS[id];
}

/**
 * @primitive test.integration.clients.claimedBy
 * @signature claimedBy(source) -> [ "<id>" ]
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the id string is the anchor, so no symbol can be renamed out of it)
 *
 * The ids an interop file claims, read out of its source. The anchor is the
 * quoted id itself rather than the call that consumes it, so a file that
 * reaches this table through a differently named binding is still discovered.
 */
function claimedBy(source) {
  if (typeof source !== "string") {
    throw new TypeError("integration clients: claimedBy(source) needs the file's source text");
  }
  return IDS.filter(function (id) {
    return source.indexOf(JSON.stringify(id)) !== -1;
  });
}

module.exports = {
  IDS:       IDS,
  spec:      spec,
  claimedBy: claimedBy,
};
