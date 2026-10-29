// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What every harness in this directory shares: the framing a listener
 * puts in front of a guard, and the line between a refusal and a
 * finding.
 *
 * A wire-protocol reader in this server is specified to refuse malformed
 * input loudly, with the protocol's own error code, at the point of
 * parse. So a fuzz run over one of those readers produces refusals
 * constantly, and a harness that reported every refusal would report
 * nothing anyone reads. `read` below draws the line: an error of the
 * guard's own class carrying a code is the reader doing its job and the
 * iteration continues, and anything else leaves the harness as a throw,
 * which is what libFuzzer records with a reproducer.
 *
 * The class and the code are the anchor rather than the message text. A
 * guard's message wording changes; the error class it throws and the
 * `<guard>/<reason>` code the listener puts in its protocol reply are
 * the contract the listener reads, and a refusal that arrives without
 * one leaves the listener with nothing to answer.
 */

var CRLF = Buffer.from("\r\n", "ascii");

/**
 * The lines a line-oriented listener will hand its guard, given these
 * bytes on the socket.
 *
 * The order of the two operations is the point. Every listener in the
 * framework finds the CRLF in the BYTES and only then decodes the
 * segment in front of it, and a harness that decoded first would be
 * reading a different input than the server does: `toString("utf8")`
 * replaces an invalid sequence with U+FFFD, which is three bytes that
 * were never on the wire, and mail is allowed to be 8-bit (RFC 6152), so
 * those sequences arrive legitimately.
 *
 * The bytes after the last CRLF are read as a line too. The listener
 * holds them until the terminator arrives and then calls the guard with
 * exactly them, so they are a line the guard reads rather than input
 * this function invented.
 */
function lines(bytes) {
  var out  = [];
  var rest = bytes;
  var at;
  while ((at = rest.indexOf(CRLF)) !== -1) {
    out.push(rest.subarray(0, at).toString("utf8"));
    rest = rest.subarray(at + 2);
  }
  out.push(rest.toString("utf8"));
  return out;
}

// Whether this error is one of the refusals the caller declared.
function _declared(err, classes) {
  for (var i = 0; i < classes.length; i += 1) {
    if (err instanceof classes[i]) return true;
  }
  return false;
}

/**
 * Run one reader over one input.
 *
 * Returns what the reader returned, or `null` when the reader refused.
 * `classes` lists the error classes that count as a refusal for this
 * reader. Anything the reader throws that is not one of them is a
 * finding and leaves this function.
 */
function read(classes, fn) {
  try {
    return fn();
  } catch (err) {
    if (!_declared(err, classes)) throw err;
    if (typeof err.code !== "string" || err.code.length === 0) {
      throw new Error("a guard refused without a code, so the listener has " +
        "nothing to put in its protocol reply: " +
        ((err && err.message) || String(err)));
    }
    return null;
  }
}

/**
 * Run something that is documented never to throw.
 *
 * `lib/store/address.js` says so of `parse` and `parseDomain`, because
 * every caller on the network side is holding an address a stranger
 * wrote and answers a bad one with a verdict rather than with an
 * exception. A throw from one of them reaches the listener as an
 * unhandled error rather than as a protocol reply, so it is reported
 * with the label naming which contract broke.
 */
function neverThrows(label, fn) {
  try {
    return fn();
  } catch (err) {
    throw new Error(label + " is documented never to throw and it threw: " +
      ((err && err.stack) || String(err)));
  }
}

/**
 * State one guarantee about what a reader returned.
 *
 * Throws a finding naming the guarantee when `condition` is false.
 * `detail` is quoted as JSON, bounded, so the reproducer's own values are
 * in the report libFuzzer prints.
 */
var MAX_DETAIL_CHARS = 600;

function holds(label, condition, detail) {
  if (condition) return;
  var quoted;
  try { quoted = JSON.stringify(detail); }
  catch (_e) { quoted = String(detail); }
  if (quoted === undefined) quoted = String(detail);
  throw new Error(label + " did not hold: " + quoted.slice(0, MAX_DETAIL_CHARS));
}

module.exports = {
  lines:       lines,
  read:        read,
  neverThrows: neverThrows,
  holds:       holds,
};
