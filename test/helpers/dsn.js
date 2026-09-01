// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The bytes a peer's mail server sends when it is telling this one what
 * happened to a message.
 *
 * Written out here rather than produced with the framework's own DSN
 * generator, and the difference matters. What the reader has to survive
 * is what a stranger's MTA puts on the wire, including the shapes RFC
 * 3464 forbids and real software emits anyway; a fixture built by the
 * writer this project ships would only ever prove that the writer and
 * the reader agree with each other.
 *
 * It lives beside the other shared helpers because two files need it,
 * one driving the MX port and one driving the reader directly, and a
 * second copy is how two files start disagreeing about what a report
 * looks like while both report green.
 *
 * Validation posture: these are entry points a test author calls
 * directly, so a malformed call throws rather than quietly producing a
 * message that tests something else.
 */

var CRLF = "\r\n";

/**
 * report(opts) builds one multipart/report message.
 *
 * opts.to                  the address it is addressed to
 * opts.recipients          per recipient groups, each
 *                          `{ address, action, status, diagnostic }`.
 *                          `address: null` omits Final-Recipient and
 *                          `action: null` omits Action, which are the
 *                          two omissions RFC 3464 section 2.3 forbids
 *                          and which a reader still has to meet.
 * opts.messageId           local part of the report's own Message-ID
 * opts.boundary            MIME boundary
 * opts.originalEnvelopeId  the per message Original-Envelope-Id, if any
 * opts.topContentType      replaces the whole top level Content-Type,
 *                          for a message that carries a delivery status
 *                          part without declaring itself a report
 * opts.omitRecipientGroups drops every per recipient group, leaving a
 *                          delivery status part that says nothing about
 *                          any address
 */
function report(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("helpers/dsn.report: opts object is required");
  }
  if (typeof opts.to !== "string" || opts.to.length === 0) {
    throw new TypeError("helpers/dsn.report: opts.to is required");
  }
  if (!Array.isArray(opts.recipients)) {
    throw new TypeError("helpers/dsn.report: opts.recipients must be an array of groups");
  }
  var boundary = opts.boundary || "rpt-boundary-1";
  var topContentType = opts.topContentType ||
    'multipart/report; report-type=delivery-status; boundary="' + boundary + '"';

  var lines = [
    "From: MAILER-DAEMON@relay.example.net",
    "To: " + opts.to,
    "Subject: Undelivered Mail Returned to Sender",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + (opts.messageId || "dsn-probe") + "@relay.example.net>",
    "MIME-Version: 1.0",
    "Content-Type: " + topContentType,
    "",
    "--" + boundary,
    "Content-Type: text/plain; charset=us-ascii",
    "",
    "The message could not be delivered.",
    "",
    "--" + boundary,
    "Content-Type: message/delivery-status",
    "",
    "Reporting-MTA: dns; relay.example.net",
    "Arrival-Date: Mon, 24 Aug 2026 08:59:00 +0000",
  ];
  if (opts.originalEnvelopeId) {
    lines.push("Original-Envelope-Id: " + opts.originalEnvelopeId);
  }
  if (opts.omitRecipientGroups !== true) {
    for (var i = 0; i < opts.recipients.length; i += 1) {
      var r = opts.recipients[i];
      lines.push("");
      if (r.address !== null && r.address !== undefined) {
        lines.push("Final-Recipient: rfc822; " + r.address);
      }
      if (r.action !== null && r.action !== undefined) lines.push("Action: " + r.action);
      if (r.status) lines.push("Status: " + r.status);
      if (r.diagnostic) lines.push("Diagnostic-Code: smtp; " + r.diagnostic);
    }
  }
  lines.push("");
  lines.push("--" + boundary);
  lines.push("Content-Type: message/rfc822");
  lines.push("");
  lines.push("To: " + ((opts.recipients[0] && opts.recipients[0].address) || opts.to));
  lines.push("Subject: the message this report is about");
  lines.push("");
  lines.push("--" + boundary + "--");
  lines.push("");
  return lines.join(CRLF);
}

/**
 * plainMessage(to, subject, body?) is ordinary mail. Most of what
 * arrives at the operator's own address is this, and a reader that
 * recorded one of these as a report would bury the reports it exists to
 * surface.
 */
function plainMessage(to, subject, body) {
  if (typeof to !== "string" || to.length === 0) {
    throw new TypeError("helpers/dsn.plainMessage: to is required");
  }
  if (typeof subject !== "string" || subject.length === 0) {
    throw new TypeError("helpers/dsn.plainMessage: subject is required");
  }
  return [
    "From: someone@example.net",
    "To: " + to,
    "Subject: " + subject,
    "Date: Mon, 24 Aug 2026 09:05:00 +0000",
    "Message-ID: <plain-probe@example.net>",
    "",
    body || "Not a report at all.",
    "",
  ].join(CRLF);
}

module.exports = {
  report:       report,
  plainMessage: plainMessage,
  CRLF:         CRLF,
};
