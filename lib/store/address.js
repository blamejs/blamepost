// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.address
 *
 * Address handling for the identity layer: one place that decides what
 * an address means, so the SMTP, IMAP, JMAP, POP3 and web paths cannot
 * disagree about it.
 *
 * Four decisions live here and nowhere else.
 *
 * The absolute form. A domain may be written with the DNS root's
 * trailing dot, which RFC 1035 section 2.3.1 makes the absolute form of
 * the same name, and both spellings arrive on the wire and in operator
 * input. One is folded to the other here, so the hosted-domain row, the
 * sealed key file named for a domain and the cache keyed on one are all
 * keyed on a name rather than on a spelling of it.
 *
 * Case. RFC 5321 section 2.4 leaves the local part case sensitive and
 * hands the meaning to the destination host. This server is that host,
 * and it folds the local part to lower case, because two mailboxes that
 * differ only in capitalization are a phishing surface rather than a
 * feature. The domain folds too, which RFC 4343 already requires.
 *
 * Tags. A plus sign splits the local part into the mailbox that owns it
 * and a tag the sender chose (RFC 5233 subaddressing). Routing uses the
 * mailbox, and the tag rides along so Sieve rules and per-sender
 * filtering can read it. A local part that starts with a plus has no
 * mailbox in front of it, so it is taken whole.
 *
 * Shape. Both halves go through the framework guards before anything
 * touches the database, so an IP literal, a second at sign, a comment,
 * a Punycode homograph or a control character is refused at the parse.
 *
 * Parsing returns a verdict and never throws, because the wire
 * listeners call it on hostile input and answer with their own protocol
 * code. The `canonical` entry point throws instead, for the command
 * line and the admin views where a bad address is an operator mistake.
 */

var b      = require("../vendor/blamejs");
var errors = require("./errors");

var err = errors.err;

// RFC 5321 section 4.5.3.1.3 bounds a forward path at 256 octets with
// its angle brackets, so the address inside them cannot exceed 254.
var MAX_ADDRESS_CHARS = 254;

var TAG_SEPARATOR = "+";

// One guard profile for every address this server reads. Strict refuses
// the address forms that exist to confuse parsers rather than to carry
// mail: IP literals, address comments, a second at sign, Punycode and
// mixed-script labels.
var GUARD_OPTS = { profile: "strict" };

// The normalize function the sealed-column derived hashes use. It has to
// agree byte for byte with what `parse` writes, or a lookup misses a row
// that is sitting right there.
function fold(value) {
  return String(value).trim().toLowerCase();
}

function _refuse(reason, detail) {
  return { ok: false, reason: reason, detail: detail || null };
}

/**
 * @primitive blamepost.store.address.parse
 * @signature blamepost.store.address.parse(input)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 5321 section 4.1.2, RFC 5233, RFC 4343
 * @related   blamepost.store.address.canonical, blamepost.store.resolve
 *
 * Read one address and return what it routes to. On success the verdict
 * carries the folded mailbox address, its local part and domain, and
 * the plus tag when the sender used one. On refusal it carries a reason
 * a wire listener can map onto its own reply code, and it never throws,
 * because every caller on the network side is holding attacker input.
 *
 * Angle brackets around the address are accepted and stripped, so an
 * SMTP forward path can be handed over as it arrived.
 *
 * @example
 *   var address = require("./lib/store/address");
 *   var v = address.parse("Alice+Receipts@Example.COM");
 *   v.address;
 *   // "alice@example.com"
 *   v.tag;
 *   // "receipts"
 */
function parse(input) {
  if (typeof input !== "string") return _refuse("not-a-string");

  var text = input.trim();
  if (text.length === 0) return _refuse("empty");

  if (text.charAt(0) === "<" && text.charAt(text.length - 1) === ">") {
    text = text.slice(1, -1).trim();
    if (text.length === 0) return _refuse("empty");
  }
  // An absolute domain carries a trailing dot, which is a legitimate
  // wire form and which the domain guard normalizes away. The address
  // guard reads the whole string against the RFC 5321 shape and refuses
  // it there, so the dot comes off first. Exactly one comes off: a
  // second is still a malformed domain and still refused.
  if (text.charAt(text.length - 1) === "." && text.indexOf("@") > 0) {
    text = text.slice(0, -1);
  }
  if (text.length > MAX_ADDRESS_CHARS) return _refuse("too-long");

  var shape = b.guardEmail.validateAddress(text, GUARD_OPTS);
  if (!shape.ok) return _refuse("address-refused", shape.issues);

  var at = text.lastIndexOf("@");
  if (at <= 0 || at === text.length - 1) return _refuse("address-refused");

  var domainVerdict = b.guardDomain.validate(text.slice(at + 1), GUARD_OPTS);
  if (!domainVerdict.ok) return _refuse("domain-refused", domainVerdict.issues);
  var domain = b.guardDomain.sanitize(text.slice(at + 1), GUARD_OPTS);

  var written = text.slice(0, at).toLowerCase();
  var localPart = written;
  var tag = null;
  var plus = written.indexOf(TAG_SEPARATOR);
  if (plus > 0) {
    localPart = written.slice(0, plus);
    var rest = written.slice(plus + 1);
    if (rest.length > 0) tag = rest;
  }

  return {
    ok:        true,
    address:   localPart + "@" + domain,
    localPart: localPart,
    domain:    domain,
    tag:       tag,
    // The address as written, folded but with the tag still attached.
    // Delivery keeps it for the Delivered-To header a forwarding loop
    // detector reads.
    written:   written + "@" + domain,
  };
}

/**
 * @primitive blamepost.store.address.canonical
 * @signature blamepost.store.address.canonical(input, label?)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 5321 section 4.1.2, RFC 5233
 * @related   blamepost.store.address.parse
 *
 * The parse above, for the operator-facing paths. Returns the verdict on
 * a good address and throws a `StoreError` on a bad one, naming what was
 * wrong so the mistake is visible at the command line rather than at the
 * first message that fails to route. `label` names the argument the
 * address arrived in.
 *
 * @example
 *   var address = require("./lib/store/address");
 *   address.canonical("alice@example.com").address;
 *   // "alice@example.com"
 */
function canonical(input, label) {
  var verdict = parse(input);
  if (verdict.ok) return verdict;
  var what = label || "address";
  if (verdict.reason === "not-a-string") {
    throw err("store/bad-address", what + " must be a string.");
  }
  if (verdict.reason === "empty") {
    throw err("store/bad-address", what + " is empty.");
  }
  if (verdict.reason === "too-long") {
    throw err("store/bad-address",
      what + " is longer than the " + MAX_ADDRESS_CHARS + " characters an address may carry.");
  }
  throw err("store/bad-address",
    what + " " + JSON.stringify(String(input)) + " is not a usable mailbox address" +
    _detailSuffix(verdict.detail) + ".");
}

function _detailSuffix(issues) {
  var kinds = errors.issueKinds(issues);
  return kinds === "" ? "" : " (refused for: " + kinds + ")";
}

// Which domain a bare name means. This is the single derivation every
// surface folds a domain through, and it exists because a name arrives
// in more than one spelling and all of them are legitimate.
//
// `example.com.` carries the DNS root's trailing dot, which RFC 1035
// section 2.3.1 makes the absolute form of the same name; `EXAMPLE.COM`
// differs only in case, which RFC 4343 says is not a difference. The
// framework's domain guard answers those in two halves, and only one of
// them yields a name: `validate` says the string may be a domain and
// admits the trailing dot as the valid form it is, while `sanitize` is
// the half that removes it and folds the case. A caller that asks only
// the first question is holding a spelling, and everything it goes on
// to key is keyed on that spelling rather than on the domain: a store
// row, a sealed key file, a cache entry.
//
// Both halves are asked here, under the strict profile, so a raw
// Unicode label, an `xn--` A-label and a mixed-script label are refused
// outright rather than folded into a name that renders like a hosted
// domain and is a different string.
//
// It never throws, for the reason `parse` above does not: every caller
// on the network side is holding a name an untrusted peer supplied, and
// the answer to a bad one is a verdict the listener turns into its own
// protocol code. `canonicalDomain` below is the throwing sibling, and
// it is the documented entry point; this is the half of it the readers
// that must not throw compose instead.
function parseDomain(input) {
  if (typeof input !== "string") return _refuse("not-a-string");
  var text = input.trim();
  if (text.length === 0) return _refuse("empty");
  var verdict = b.guardDomain.validate(text, GUARD_OPTS);
  if (!verdict.ok) return _refuse("domain-refused", verdict.issues);
  return { ok: true, domain: b.guardDomain.sanitize(text, GUARD_OPTS) };
}

/**
 * @primitive blamepost.store.address.canonicalDomain
 * @signature blamepost.store.address.canonicalDomain(input, label?)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 1035 section 2.3.1, RFC 4343
 * @related   blamepost.store.domains.add, blamepost.store.address.canonical
 *
 * The derivation above, for the operator-facing paths. Returns the
 * folded name on a good one and throws a `StoreError` on a bad one,
 * naming the rule that refused it, so an IPv4 address, a single label,
 * a homograph or a special-use suffix cannot become a hosted domain by
 * typo. `label` names the argument the name arrived in.
 *
 * @example
 *   var address = require("./lib/store/address");
 *   address.canonicalDomain("Example.COM.");
 *   // "example.com"
 */
function canonicalDomain(input, label) {
  var what = label || "domain";
  var verdict = parseDomain(input);
  if (verdict.ok) return verdict.domain;
  if (verdict.reason === "not-a-string" || verdict.reason === "empty") {
    throw err("store/bad-domain", what + " must be a non-empty string.");
  }
  throw err("store/bad-domain",
    what + " " + JSON.stringify(String(input).trim()) + " is not a usable domain name" +
    _detailSuffix(verdict.detail) + ".");
}

/**
 * @primitive blamepost.store.address.catchAllFor
 * @signature blamepost.store.address.catchAllFor(domain)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (the identity and routing layer above the message store)
 * @related   blamepost.store.aliases.add, blamepost.store.resolve
 *
 * The stored form of a catch-all rule for one domain, written as an at
 * sign followed by the domain. It is deliberately not a valid mailbox
 * address, so it can never collide with one an account or an alias
 * holds, and it keeps the catch-all in the same sealed and indexed
 * column as every other alias rather than in a second lookup path.
 *
 * @example
 *   var address = require("./lib/store/address");
 *   address.catchAllFor("example.com");
 *   // "@example.com"
 */
function catchAllFor(domain) {
  return "@" + canonicalDomain(domain);
}

module.exports = {
  parse:             parse,
  canonical:         canonical,
  parseDomain:       parseDomain,
  canonicalDomain:   canonicalDomain,
  catchAllFor:       catchAllFor,
  fold:              fold,
  MAX_ADDRESS_CHARS: MAX_ADDRESS_CHARS,
  TAG_SEPARATOR:     TAG_SEPARATOR,
};
