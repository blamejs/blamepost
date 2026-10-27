// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.dns
 * @nav    DNS and domain authentication
 * @title  Hosted DNS publishing
 * @order  60
 *
 * The write gate over hosted DNS. An operator who has given this server
 * a credential that can edit their zone has handed it the ability to
 * take delivery away from itself, and everything in this file exists to
 * make that ability narrow, visible and reversible in that order.
 *
 * It is a domain of its own because it is none of the others. It speaks
 * no mail protocol, it is not the store, it is not the browser surface,
 * and it is the only place in this process holding a credential for a
 * third party. A credential with that reach does not belong in a file
 * whose subject is something else.
 *
 * There is one provider, and `blamepost.dns.cloudflare` names it. This
 * layer is not an abstraction over several: it is the policy that would
 * be identical whichever one was underneath, kept apart from the client
 * that knows one provider's envelope, paging and identifiers.
 *
 * Five things stand between a caller and a zone.
 *
 * The credential is sealed at rest and opened for one request at a
 * time. A stored value that is not sealed is refused rather than used,
 * because opening a seal passes an unsealed value straight through, and
 * a plaintext credential left where a sealed one belongs would
 * otherwise work exactly as well as the real thing while being readable
 * to anyone who can read the volume. The seal is bound to its purpose
 * through `b.vault.aad`, so a value this volume sealed for something
 * else, a DKIM private key among them, does not open as the credential,
 * and the credential's seal does not open anywhere else.
 *
 * Only a named set of record types, at a named set of addresses, may be
 * written. The set is the mail posture this server is responsible for
 * and nothing else, so a defect here cannot reach the operator's web
 * records. MX is in the set only when the operator turns it on, because
 * MX is the one record whose rewrite stops mail arriving here at all.
 * Four of the TXT addresses belong to one kind of record each, named by
 * its version tag: `v=spf1` at the apex, `v=DMARC1` at `_dmarc`,
 * `v=STSv1` at `_mta-sts` and `v=TLSRPTv1` at `_smtp._tls`. A value
 * without that tag is not written there, and a record without it is
 * never replaced or removed from there, so a verification record
 * sharing the apex with the sender policy is left as it is.
 *
 * Nothing is written by the call that computes it. `preview` reads the
 * zone and renders what would change; `apply` takes that preview back
 * and performs it. Between the two, the zone is read again and compared
 * against what the preview saw, so a record that moved after the
 * preview was taken is refused rather than overwritten. `apply` builds
 * every write from what it reads itself: each record is checked again,
 * each change has to sit at an address the preview read, each record
 * replaced or removed has to be one the zone holds at that address now,
 * and the zone has to be the one the provider holds for the domain.
 *
 * Every write carries a reason the operator wrote down, and preview,
 * apply, verification and every refusal each leave an audit row.
 *
 * After a write the record is read back twice: from the provider, which
 * says what the zone holds, and through a resolver, which says what the
 * rest of the world can see. A write the provider accepted and a
 * resolver cannot find is the case an operator most needs told about,
 * and it is invisible to either read on its own.
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var b          = require("../vendor/blamejs");
var cloudflare = require("./cloudflare");
var configModule = require("../config");
var auditActor = require("../store/actor");
var address    = require("../store/address");
var posture    = require("../mail/posture");
// The screen between text somebody else wrote and a person reading it.
// A record value, a record address and a record type all come out of the
// provider's response, and the diff built from them is printed into a
// terminal and rendered in the browser console.
var displayText = require("../text");

var AUDIT_NAMESPACE = "blamepost";

// The refusal vocabulary of this layer, named once each and published
// as `CODES` below, so a caller branching on a code and the set that
// describes the codes cannot come apart. Renaming one is a breaking
// change.
var WRITE_NOT_ALLOWED   = "zone/write-not-allowed";
var MX_WRITE_DISABLED   = "zone/mx-write-not-enabled";
var RECORD_DRIFT        = "zone/record-drift";
var REASON_REQUIRED     = "zone/reason-required";
var CONFIRM_REQUIRED    = "zone/confirm-required";
var PREVIEW_REQUIRED    = "zone/preview-required";
var PREVIEW_FOREIGN     = "zone/preview-foreign";
var TOKEN_NOT_SEALED    = "zone/token-not-sealed";
var TOKEN_SEAL_UNOPENED = "zone/token-seal-unopened";
var TOO_MANY_CHANGES    = "zone/too-many-changes";
var BAD_RECORD          = "zone/bad-record";
var WRITE_INCOMPLETE    = "zone/write-incomplete";
var NO_PROVIDER         = "zone/no-provider";
var NO_TOKEN            = "zone/no-token";
var TOKEN_TWO_SOURCES   = "zone/token-two-sources";

var GateError = b.frameworkError.defineClass("DnsGateError", { alwaysPermanent: true });
var err = GateError.factory;

// The record types this server is ever responsible for. MX is listed
// here and gated separately below; it is not a type an operator adds by
// widening this set.
var SUPPORTED_TYPES = ["TXT", "CNAME", "TLSA", "MX"];

// How many records one change set may touch before it needs saying
// again. A posture rollout for one domain is a handful of records; a
// set larger than this is either a mistake or something an operator
// should be looking at directly.
var DEFAULT_MAX_CHANGES = 25;

// The longest a record value may be before this layer stops treating it
// as a value and starts treating it as a mistake. A TXT string is
// bounded at 255 octets per RFC 1035 and a record may carry several, so
// this leaves room for a long DKIM key without leaving room for a body.
var MAX_CONTENT_CHARS = 4096;
var MAX_NAME_CHARS    = 253;
var MAX_LABEL_CHARS   = 63;

// The length an operator's reason is allowed to run to. It is recorded,
// read later by whoever is asking what happened, and it is not a place
// to put a document.
var MAX_REASON_CHARS = 1000;

// Where the sealed provider token is kept on the data volume: the same
// folder the sealed DKIM private keys are written to, under a name of
// its own. One folder, one file mode, one thing to back up and one thing
// to destroy, and a credential this server holds is not put anywhere a
// credential this server holds does not already live.
var TOKEN_FOLDER = "keys";
var TOKEN_FILE   = "zone-token.sealed";

// A sealed token file is small. Anything larger on disk is corruption
// rather than a credential, and the read stops there rather than pulling
// whatever is under the name into memory.
var MAX_TOKEN_FILE_BYTES = b.constants.BYTES.kib(64);

// The longest raw token this server will seal. Provider tokens run to a
// few tens of characters; a file longer than this is a file that is not
// a token, and sealing it would store it anyway.
var MAX_TOKEN_CHARS = 1024;

// The additional authenticated data the provider token is sealed under.
// Changing it leaves every stored token unable to open.
var TOKEN_SEAL_CONTEXT = Object.freeze({ purpose: "blamepost.dns.provider-token" });

// A bearer credential as RFC 6750 section 2.1 writes one (b64token):
// letters, digits and - . _ ~ + /, then any number of = signs.
var BEARER_TOKEN_RE = /^[A-Za-z0-9._~+/-]+=*$/;

// One label of a record address. Underscore is admitted because the
// names this gate writes are service names rather than hostnames:
// `_dmarc`, `_domainkey`, `_mta-sts` and `_tcp` are all underscore
// labels and all legitimate. An asterisk is not admitted, so a wildcard
// record is not something this gate can be asked to write.
var RECORD_LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

// A record address folded to the one spelling this layer compares on.
// The trailing root marker is walked off rather than matched off: a
// pattern anchoring a repeat to the end of the string costs time
// proportional to the square of a run of that character, and the names
// reaching here include the ones a provider put in its response, which
// is remote input this process does not control.
function _normalizeName(value) {
  var text = String(value).trim().toLowerCase();
  var end  = text.length;
  while (end > 0 && text.charAt(end - 1) === ".") end -= 1;
  return text.slice(0, end);
}

function _validRecordName(name) {
  if (name.length === 0 || name.length > MAX_NAME_CHARS) return false;
  var labels = name.split(".");
  if (labels.length < 2) return false;
  for (var i = 0; i < labels.length; i += 1) {
    if (labels[i].length > MAX_LABEL_CHARS) return false;
    if (!RECORD_LABEL_RE.test(labels[i])) return false;
  }
  return true;
}

// The version tag a TXT value opens with: `v`, optional whitespace, `=`,
// optional whitespace, then the tag's value up to the first semicolon,
// space or tab. Null when the value does not open with one.
function _versionTag(content) {
  var text = typeof content === "string" ? content : "";
  var first = text.charAt(0);
  if (first !== "v" && first !== "V") return null;
  var i = 1;
  var spaced = false;
  while (text.charAt(i) === " " || text.charAt(i) === "\t") { i += 1; spaced = true; }
  if (text.charAt(i) !== "=") return null;
  i += 1;
  while (text.charAt(i) === " " || text.charAt(i) === "\t") { i += 1; spaced = true; }
  var start = i;
  while (i < text.length && text.charAt(i) !== ";" && text.charAt(i) !== " " &&
      text.charAt(i) !== "\t") {
    i += 1;
  }
  return { lowercase: first === "v", spaced: spaced, value: text.slice(start, i),
    next: text.charAt(i) };
}

// The record kind each dedicated TXT address holds, recognized by its
// version tag as the specification that defines the record writes it.
// A sender policy opens with exactly `v=spf1` followed by a space or the
// end of the value (RFC 7208 section 4.5, ABNF case-insensitive). A
// DMARC policy opens with `v`, `=` and `DMARC1` with optional whitespace
// around the equals sign (RFC 7489 section 6.4). An MTA-STS identifier
// and a TLS reporting record open with the case-sensitive literals
// `v=STSv1` and `v=TLSRPTv1` (RFC 8461 section 3.1, RFC 8460 section 3).
function _isSenderPolicy(content) {
  var tag = _versionTag(content);
  return tag !== null && !tag.spaced && tag.value.toLowerCase() === "spf1" &&
    (tag.next === "" || tag.next === " ");
}

function _isDmarcPolicy(content) {
  var tag = _versionTag(content);
  return tag !== null && tag.value === "DMARC1" &&
    (tag.next === "" || tag.next === ";" || tag.next === " " || tag.next === "\t");
}

function _literalVersion(expected) {
  return function (content) {
    var tag = _versionTag(content);
    return tag !== null && tag.lowercase && !tag.spaced && tag.value === expected &&
      (tag.next === "" || tag.next === ";" || tag.next === " " || tag.next === "\t");
  };
}

// Whether a rule admits a record already in the zone: every record at the
// address when the rule names no kind, and only records of its kind when
// it does.
function _admits(rule, record) {
  return typeof rule.recognizes !== "function" || rule.recognizes(record.content);
}

// The addresses this server may write, derived from the domain it is
// governing. Each entry pairs a record type with the one address shape
// that type is legitimate at, because a type allowed everywhere in the
// zone is most of the way back to no restriction at all: a TXT write
// loose in the zone can replace a domain verification record, and a
// CNAME loose in the zone can move a hostname somewhere else entirely.
// A TXT rule at an address that holds one kind of record carries
// `recognizes`, the test for that kind, and `tag`, how its version tag
// is written.
function _allowedWrites(domain, allowMx, additionalNames) {
  var suffix = "." + domain;
  var rules = [
    { type: "TXT", label: "the sender policy record at the domain apex",
      tag: "v=spf1", recognizes: _isSenderPolicy,
      match: function (name) { return name === domain; } },
    { type: "TXT", label: "the DMARC policy record",
      tag: "v=DMARC1", recognizes: _isDmarcPolicy,
      match: function (name) { return name === "_dmarc" + suffix; } },
    { type: "TXT", label: "a DKIM selector record",
      match: function (name) {
        var tail = "._domainkey" + suffix;
        return name.length > tail.length && name.slice(-tail.length) === tail;
      } },
    { type: "TXT", label: "the MTA-STS policy identifier",
      tag: "v=STSv1", recognizes: _literalVersion("STSv1"),
      match: function (name) { return name === "_mta-sts" + suffix; } },
    { type: "TXT", label: "the TLS reporting address",
      tag: "v=TLSRPTv1", recognizes: _literalVersion("TLSRPTv1"),
      match: function (name) { return name === "_smtp._tls" + suffix; } },
    { type: "CNAME", label: "the MTA-STS policy host",
      match: function (name) { return name === "mta-sts" + suffix; } },
    { type: "TLSA", label: "a DANE association under a transport label",
      match: function (name) {
        if (name.indexOf("_") !== 0) return false;
        var cut = name.indexOf("._tcp.");
        if (cut === -1) return false;
        var host = name.slice(cut + "._tcp.".length);
        return host === domain || (host.length > suffix.length &&
          host.slice(-suffix.length) === suffix);
      } },
  ];
  if (allowMx) {
    rules.push({ type: "MX", label: "the mail exchanger at the domain apex",
      match: function (name) { return name === domain; } });
  }
  additionalNames.forEach(function (entry) {
    rules.push({
      type:  entry.type,
      label: "an address the operator added to the write allowlist",
      match: function (name) { return name === entry.name; },
    });
  });
  return rules;
}

function _requireReason(value, verb) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err(REASON_REQUIRED,
      "blamepost.dns." + verb + " needs a reason. It is written into the audit row, and a " +
      "row with no reason answers nothing later about why a zone was changed.");
  }
  var reason = value.trim();
  if (reason.length > MAX_REASON_CHARS) {
    throw err(REASON_REQUIRED,
      "blamepost.dns." + verb + ": the reason runs to " + reason.length + " characters, and " +
      MAX_REASON_CHARS + " is the most that is recorded. Say what changed and why in a " +
      "sentence; the change set itself is already in the row.");
  }
  return reason;
}

// A record value as a diff shows it, screened for display controls. The
// value an address is holding came out of the provider's response, and a
// diff is printed to a terminal, where a line feed inside one value
// turns one change into what reads as two and a tab moves the value out
// from under the column it belongs to. The administration console
// screens the same values through the same reader.
function _displayText(value) {
  return displayText.forDisplay(value);
}

function _renderValue(record) {
  if (!record) return "nothing";
  var out = "";
  if (typeof record.priority === "number") out += record.priority + " ";
  out += JSON.stringify(_displayText(record.content));
  if (typeof record.ttl === "number") out += " ttl=" + record.ttl;
  return out;
}

// One line of a rendered change, in a fixed column order so two
// previews of the same zone read the same way and a reader comparing
// them is comparing the records rather than the layout.
function _renderChange(change) {
  var mark = change.action === "create" ? "+"
    : change.action === "delete" ? "-" : "~";
  // The address and the type come out of the provider's response beside
  // the value, and the value on the same line is screened. A record
  // address carrying a line feed splits one change into what reads as
  // two, which is the reading an operator confirms before a write.
  var line = "  " + mark + " " + _displayText(change.type) + " " +
    _displayText(change.name);
  if (change.action === "create") {
    return line + "  " + _renderValue(change.after);
  }
  if (change.action === "delete") {
    return line + "  " + _renderValue(change.before);
  }
  return line + "  " + _renderValue(change.after) +
    "  (holding " + _renderValue(change.before) + ")";
}

// What the zone held for the addresses a change set touches, reduced to
// one value. Apply re-reads the same addresses and compares this, so a
// record that changed underneath the preview stops the write rather
// than being overwritten by it.
//
// Every field is quoted before it is run together with the next, so a
// value carrying the separator cannot be arranged to fingerprint as a
// different set of records that happens to concatenate the same way.
function _fingerprint(records) {
  var rows = records.map(function (record) {
    var ttl  = record.ttl === null ? "none" : String(record.ttl);
    var pref = typeof record.priority === "number" ? String(record.priority) : "none";
    return JSON.stringify(record.type) + "," +
      JSON.stringify(record.name) + "," +
      JSON.stringify(record.content) + "," +
      ttl + "," + pref + "," +
      JSON.stringify(record.id) + ";";
  });
  rows.sort();
  var joined = "";
  for (var i = 0; i < rows.length; i += 1) joined += rows[i];
  return b.crypto.sha3Hash(joined);
}

// The resolver reader for a record type. Named per type rather than
// reached through one generic query, so the shape each answer arrives
// in is the shape this file already reads.
var RESOLVER_READERS = {
  TXT:   "queryTxt",
  MX:    "queryMx",
  CNAME: "queryCname",
  TLSA:  "queryTlsa",
};

// What a resolver answered, reduced to one string per record in the
// form the provider stores. A TXT record arrives as its decoded
// segments, which the provider stores as one string, so the segments
// are run together. An MX record arrives as `{ preference, exchange }`
// and is written `<preference> <exchange>`. A TLSA record arrives as
// `{ usage, selector, matchingType, certData }` and is written in the
// RFC 6698 section 2.2 presentation form with the data in hex.
function _resolverValues(answer) {
  var rrs = (answer && Array.isArray(answer.rrs)) ? answer.rrs : [];
  return rrs.map(function (rr) {
    var decoded = rr && rr.decoded;
    if (Array.isArray(decoded)) {
      var text = "";
      for (var i = 0; i < decoded.length; i += 1) text += String(decoded[i]);
      return text;
    }
    if (decoded !== null && typeof decoded === "object") {
      if (typeof decoded.exchange === "string") {
        return String(decoded.preference) + " " + decoded.exchange;
      }
      if (typeof decoded.usage === "number" && decoded.certData !== undefined) {
        return decoded.usage + " " + decoded.selector + " " + decoded.matchingType + " " +
          Buffer.from(decoded.certData).toString("hex");
      }
      return "";
    }
    return decoded === undefined || decoded === null ? "" : String(decoded);
  });
}

// Whether one resolver value is the record written. TXT values compare
// whole, so a longer record that contains the written text is a
// different record. Host names compare without case or a trailing dot.
// An MX value compares its exchange, and its preference too when the
// written record carries one. A TLSA value compares its four fields with
// the data in hex taken without case.
function _resolverValueIs(type, value, content, priority) {
  if (type === "CNAME") return _normalizeName(value) === _normalizeName(content);
  if (type === "MX") {
    var cut = value.indexOf(" ");
    var preference = cut === -1 ? "" : value.slice(0, cut);
    var exchange = cut === -1 ? value : value.slice(cut + 1);
    if (_normalizeName(exchange) !== _normalizeName(content)) return false;
    return typeof priority !== "number" || preference === String(priority);
  }
  if (type === "TLSA") {
    return value.trim().toLowerCase().split(/\s+/).join(" ") ===
      String(content).trim().toLowerCase().split(/\s+/).join(" ");
  }
  return value === content;
}

/**
 * @primitive blamepost.dns.sealToken
 * @signature blamepost.dns.sealToken(token, vault?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the provider credential is sealed the way a signing key is)
 * @related   blamepost.dns.create
 *
 * Seal a provider API token for storage, through the vault's
 * authenticated-data seal, bound to the provider token's purpose. The
 * returned string is what `create` takes as `sealedToken`, and it is the
 * only form of the credential that should reach disk or a configuration
 * file. A value the vault sealed for any other purpose does not open as
 * the token, and the token's seal does not open under any other purpose.
 *
 * Sealing is refused for an empty token, for a value that is already
 * sealed, because re-sealing a sealed value produces something that opens
 * to a sealed string rather than to a credential, for a value longer than
 * 1024 characters, and for a value that is not a bearer credential as
 * RFC 6750 section 2.1 writes one: letters, digits and `- . _ ~ + /`,
 * then any `=` signs, on one line. A value outside that set cannot be
 * sent in an authorization header.
 *
 * @example
 *   var dns = require("./lib/dns");
 *   var sealed = dns.sealToken(apiToken);
 *   var gate = dns.create({ domain: "example.com", sealedToken: sealed });
 */
function sealToken(token, vault) {
  var store = _requireVault(vault || b.vault, "blamepost.dns.sealToken: vault");
  if (typeof token !== "string" || token.trim().length === 0) {
    throw new TypeError("blamepost.dns.sealToken: token must be a non-empty string");
  }
  var value = token.trim();
  if (value.indexOf(b.constants.VAULT_PREFIX) === 0 || b.vault.aad.isAadSealed(value)) {
    throw new TypeError("blamepost.dns.sealToken: this value is already sealed. Sealing it " +
      "again produces something that opens to a sealed string rather than to a token.");
  }
  if (value.length > MAX_TOKEN_CHARS) {
    throw new TypeError("blamepost.dns.sealToken: the token runs to " + value.length +
      " characters, and " + MAX_TOKEN_CHARS + " is the most this server stores. A provider " +
      "token is a few tens of characters, so a value this long is a file that is not a token.");
  }
  if (!BEARER_TOKEN_RE.test(value)) {
    throw new TypeError("blamepost.dns.sealToken: the token holds a character a bearer " +
      "credential cannot carry. A provider API token is one line of letters, digits and " +
      "the characters - . _ ~ + /, with any = signs at the end. Check that the file holds " +
      "the token and nothing else.");
  }
  return store.aad.seal(value, TOKEN_SEAL_CONTEXT);
}

// The vault a sealed token is opened with. It has to carry the framework's
// authenticated-data seal, which is the seal the token is written under.
function _requireVault(vault, label) {
  if (!vault || typeof vault !== "object" || !vault.aad || typeof vault.aad !== "object" ||
      typeof vault.aad.seal !== "function" || typeof vault.aad.unseal !== "function") {
    throw new TypeError(label + " must expose aad.seal and aad.unseal (pass b.vault, which " +
      "is what the running server uses)");
  }
  return vault;
}

// The refusal for a stored value that carries the vault's plain seal
// rather than the provider token's. It is sealed, so it is not exposed;
// it is something else this volume sealed.
function _sealedForAnotherPurpose(where) {
  return err(TOKEN_NOT_SEALED,
    "the provider token " + where + " carries this vault's seal, but not the seal a provider " +
    "token is written under, so it is some other value this volume sealed, such as a signing " +
    "key. Nothing opens it as a credential. Seal the provider token with `blamepost zone " +
    "token set --token-file <path> --reason <text>`.");
}

// Opens the sealed credential, once per request, and hands back nothing
// the caller can hold afterwards. Both things that build a provider
// client take this rather than each opening the seal itself: the refusal
// below is what an operator reads when a volume's vault key has moved
// under a token that is still on disk, and two copies of it would be two
// places to correct when that sentence is wrong.
function _tokenReader(sealedToken, vault) {
  return function readToken() {
    try {
      return vault.aad.unseal(sealedToken, TOKEN_SEAL_CONTEXT);
    } catch (_sealError) {
      throw err(TOKEN_SEAL_UNOPENED,
        "the sealed provider token did not open. It was written under a different volume's " +
        "vault key, it was sealed for a purpose other than the provider token, or its bytes " +
        "have been damaged where they lie. Seal the token on this volume with `blamepost " +
        "zone token set --token-file <path> --reason <text>`, and issue a replacement at " +
        "the provider first if the sealed value may have been copied.");
    }
  };
}

/**
 * @primitive blamepost.dns.create
 * @signature blamepost.dns.create(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: a narrow, previewed, audited write path over one zone)
 * @related   blamepost.dns.preview, blamepost.dns.apply, blamepost.dns.verify
 *
 * Build the write gate for one hosted domain. Every option is checked
 * here and a bad one throws, so a wrong domain or an unsealed token is
 * found when the server starts rather than at the moment a zone is
 * being edited.
 *
 * The returned handle carries `preview`, `apply`, `verify`, an
 * `allowlist` reader that reports exactly what this gate will write,
 * and `close`.
 *
 * `allowMxWrites` defaults to false and is the only way MX becomes
 * writable. Repointing MX takes delivery away from this server, which
 * is the one change that cannot be reported by the server it was made
 * on, so it is a decision an operator makes rather than a capability
 * that arrives with the credential.
 *
 * @opts
 *   domain:          string,    // required, the hosted domain this gate governs
 *   sealedToken:     string,    // required, the vault-sealed provider API token
 *   vault:           object,    // exposes aad.seal and aad.unseal, default b.vault
 *   client:          object,    // a provider client, default one built over the sealed token
 *   clientOptions:   object,    // passed to the provider client when this builds one
 *   resolver:        object,    // a resolver handle, default b.network.dns.resolver.create
 *   allowMxWrites:   boolean,   // default false, permit writes to the apex MX record
 *   allowedTypes:    string[],  // default TXT, CNAME and TLSA, narrowing only
 *   additionalNames: object[],  // [{ type, name }] added to the write allowlist
 *   maxChanges:      number,    // default 25, ceiling on one change set
 *   dnsBudgetMs:     number,    // default the posture budget, bound on each resolver read
 *
 * @example
 *   var gate = dns.create({
 *     domain:      "example.com",
 *     sealedToken: sealed,
 *   });
 *   var preview = await gate.preview({ desired: records, reason: "publish DMARC" });
 *   await gate.apply(preview, { reason: "publish DMARC", confirm: true });
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.dns.create: opts object is required");
  }
  if (typeof opts.domain !== "string" || opts.domain.trim().length === 0) {
    throw new TypeError("blamepost.dns.create: opts.domain is required (the hosted domain " +
      "this gate governs, and the only zone it will write)");
  }
  // The store's reader, rather than a second one here: it folds the
  // case and drops a trailing dot the same way every row, sealed key
  // file and cache entry in this server is keyed, and a gate holding a
  // different spelling of the same domain governs a different zone from
  // the one the operator hosted.
  var parsedDomain = address.parseDomain(opts.domain);
  if (!parsedDomain.ok) {
    throw new TypeError("blamepost.dns.create: opts.domain is not a domain name (" +
      parsedDomain.reason + ")");
  }
  var domain = parsedDomain.domain;

  var vault = _requireVault(opts.vault || b.vault, "blamepost.dns.create: opts.vault");

  if (typeof opts.sealedToken !== "string" || opts.sealedToken.length === 0) {
    throw new TypeError("blamepost.dns.create: opts.sealedToken is required. Seal the " +
      "provider API token with blamepost.dns.sealToken and store that; the token itself is " +
      "never a configuration value.");
  }
  // A value carrying the vault's plain seal is sealed, and is some other
  // value this volume sealed rather than the token.
  if (opts.sealedToken.indexOf(b.constants.VAULT_PREFIX) === 0) {
    throw _sealedForAnotherPurpose("handed to blamepost.dns.create");
  }
  // Opening a seal passes a value that is not sealed straight through,
  // so the prefix is checked before anything is opened. Without this a
  // plaintext token in the configuration works exactly as well as a
  // sealed one, while being readable to anyone who can read the file.
  if (!b.vault.aad.isAadSealed(opts.sealedToken)) {
    throw err(TOKEN_NOT_SEALED,
      "blamepost.dns.create: the provider token is not sealed. This server seals every " +
      "credential it stores, so nothing authenticates with a value that is not, and whatever " +
      "that value holds has been readable to anyone who can read it where it is written. " +
      "Treat the token as exposed: issue a replacement at the provider, seal it with " +
      "blamepost.dns.sealToken, and store the sealed form.");
  }
  var sealedToken = opts.sealedToken;

  if (opts.allowMxWrites !== undefined && typeof opts.allowMxWrites !== "boolean") {
    throw new TypeError("blamepost.dns.create: opts.allowMxWrites must be a boolean. It " +
      "decides whether this server may repoint the record that decides where mail for " +
      domain + " arrives, and a value that is neither true nor false leaves that undecided.");
  }
  var allowMxWrites = opts.allowMxWrites === true;

  var allowedTypes = ["TXT", "CNAME", "TLSA"];
  if (opts.allowedTypes !== undefined) {
    if (!Array.isArray(opts.allowedTypes) || opts.allowedTypes.length === 0) {
      throw new TypeError("blamepost.dns.create: opts.allowedTypes must be a non-empty " +
        "array of record types when supplied");
    }
    opts.allowedTypes.forEach(function (type) {
      if (typeof type !== "string" || SUPPORTED_TYPES.indexOf(type.toUpperCase()) === -1) {
        throw new TypeError("blamepost.dns.create: opts.allowedTypes may name only " +
          SUPPORTED_TYPES.join(", ") + ", and " + JSON.stringify(String(type)) +
          " is not one of them. This list narrows what this gate writes; it does not extend " +
          "what it knows how to write.");
      }
    });
    allowedTypes = opts.allowedTypes.map(function (type) { return type.toUpperCase(); });
  }
  if (allowedTypes.indexOf("MX") !== -1 && !allowMxWrites) {
    throw new TypeError("blamepost.dns.create: opts.allowedTypes names MX, but " +
      "allowMxWrites is not set. MX is behind its own switch rather than the type list, so " +
      "that repointing delivery is never something a type list quietly turned on.");
  }

  var additionalNames = [];
  if (opts.additionalNames !== undefined) {
    if (!Array.isArray(opts.additionalNames)) {
      throw new TypeError("blamepost.dns.create: opts.additionalNames must be an array of " +
        "{ type, name } entries when supplied");
    }
    opts.additionalNames.forEach(function (entry, index) {
      if (!entry || typeof entry !== "object" ||
          typeof entry.type !== "string" || typeof entry.name !== "string") {
        throw new TypeError("blamepost.dns.create: opts.additionalNames[" + index +
          "] must be { type, name }");
      }
      var name = _normalizeName(entry.name);
      if (!_validRecordName(name)) {
        throw new TypeError("blamepost.dns.create: opts.additionalNames[" + index +
          "] names " + JSON.stringify(name) + ", which is not a record address this gate " +
          "can write. A wildcard is not among them.");
      }
      if (name !== domain && name.slice(-(domain.length + 1)) !== "." + domain) {
        throw new TypeError("blamepost.dns.create: opts.additionalNames[" + index +
          "] names " + JSON.stringify(name) + ", which is outside " + domain +
          ". This gate writes one zone.");
      }
      var type = entry.type.trim().toUpperCase();
      if (type === "MX" ? !allowMxWrites : allowedTypes.indexOf(type) === -1) {
        throw new TypeError("blamepost.dns.create: opts.additionalNames[" + index +
          "] names a " + JSON.stringify(type) + " record, and this gate writes " +
          allowedTypes.join(", ") + (allowMxWrites ? " and MX" : "") + ". An added name " +
          "extends the addresses a type is written at; it does not add a type, and MX is " +
          "added only with allowMxWrites set.");
      }
      additionalNames.push({ type: type, name: name });
    });
  }

  var maxChanges = DEFAULT_MAX_CHANGES;
  if (opts.maxChanges !== undefined) {
    if (typeof opts.maxChanges !== "number" || !isFinite(opts.maxChanges) ||
        (opts.maxChanges % 1) !== 0 || opts.maxChanges < 1 || opts.maxChanges > 500) {
      throw new TypeError("blamepost.dns.create: opts.maxChanges must be a whole number " +
        "between 1 and 500");
    }
    maxChanges = opts.maxChanges;
  }

  var dnsBudgetMs = posture.DNS_ANSWER_BUDGET_MS;
  if (opts.dnsBudgetMs !== undefined) {
    if (typeof opts.dnsBudgetMs !== "number" || !isFinite(opts.dnsBudgetMs) ||
        opts.dnsBudgetMs < 1000 || opts.dnsBudgetMs > 120000) {
      throw new TypeError("blamepost.dns.create: opts.dnsBudgetMs must be a number of " +
        "milliseconds between 1000 and 120000. It bounds each read of a resolver this " +
        "server does not own, and there is no value that turns the bound off.");
    }
    dnsBudgetMs = opts.dnsBudgetMs;
  }

  b.audit.registerNamespace(AUDIT_NAMESPACE);

  // The credential is opened per request and the opened value is not
  // held anywhere this function can reach afterwards.
  var readToken = _tokenReader(sealedToken, vault);

  var ownsClient = !opts.client;
  var client = opts.client || cloudflare.create(Object.assign({}, opts.clientOptions || {}, {
    readToken: readToken,
  }));

  var resolver = opts.resolver || b.network.dns.resolver.create({ profile: "strict" });

  var writeRules = _allowedWrites(domain, allowMxWrites, additionalNames);

  // The fields every row from this layer carries. The action is not one
  // of them: each verb writes its own as a literal, because an action
  // assembled from pieces is one no reader can resolve to a name, and
  // an action under a namespace nothing registered is refused by the
  // audit layer and dropped without a word.
  function rowFor(reason, metadata) {
    return {
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: domain },
      metadata: metadata || {},
    };
  }

  function recordRefusal(reason, metadata) {
    return auditActor.record(Object.assign({
      action:  "blamepost.dns.refused",
      outcome: "denied",
    }, rowFor(reason, metadata)));
  }

  function recordPreviewed(reason, metadata) {
    return auditActor.record(Object.assign({
      action:  "blamepost.dns.previewed",
      outcome: "success",
    }, rowFor(reason, metadata)));
  }

  function recordApplied(outcome, reason, metadata) {
    return auditActor.record(Object.assign({
      action:  "blamepost.dns.applied",
      outcome: outcome,
    }, rowFor(reason, metadata)));
  }

  function recordVerified(outcome, reason, metadata) {
    return auditActor.record(Object.assign({
      action:  "blamepost.dns.verified",
      outcome: outcome,
    }, rowFor(reason, metadata)));
  }

  // A refusal recorded before it is raised, so the row exists whether or
  // not the caller catches it.
  async function refuse(code, message, reason, metadata) {
    await recordRefusal(reason, Object.assign({ code: code }, metadata || {}));
    throw err(code, message);
  }

  // One record to be written, checked for shape and then against the
  // allowlist. Shape first: a value that is not a record cannot be
  // meaningfully reported as outside the allowlist. `label` names where
  // the record came from, such as `desired[0]`.
  function readDesired(entry, label) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw err(BAD_RECORD, label + " must be a record object.");
    }
    if (typeof entry.type !== "string" || entry.type.trim().length === 0) {
      throw err(BAD_RECORD, label + " names no record type.");
    }
    if (typeof entry.name !== "string" || entry.name.trim().length === 0) {
      throw err(BAD_RECORD, label + " names no record address.");
    }
    if (typeof entry.content !== "string" || entry.content.length === 0) {
      throw err(BAD_RECORD, label + " carries no value.");
    }
    if (entry.content.length > MAX_CONTENT_CHARS) {
      throw err(BAD_RECORD, label + " carries a value of " +
        entry.content.length + " characters, and " + MAX_CONTENT_CHARS + " is the most this " +
        "gate writes.");
    }
    var name = _normalizeName(entry.name);
    if (!_validRecordName(name)) {
      throw err(BAD_RECORD, label + " names " + JSON.stringify(_displayText(name)) +
        ", which is not a record address this gate can write. Every label must be letters, " +
        "digits, hyphen or underscore, and a wildcard is not a record this gate writes.");
    }
    var record = {
      type:    entry.type.trim().toUpperCase(),
      name:    name,
      content: entry.content,
      ttl:     entry.ttl === undefined ? null : entry.ttl,
    };
    if (record.ttl !== null &&
        (typeof record.ttl !== "number" || !isFinite(record.ttl) || (record.ttl % 1) !== 0 ||
         record.ttl < 60 || record.ttl > 86400)) {
      throw err(BAD_RECORD, label + " names a lifetime of " +
        String(entry.ttl) + ". It must be a whole number of seconds between 60 and 86400.");
    }
    if (entry.priority !== undefined) {
      if (typeof entry.priority !== "number" || !isFinite(entry.priority) ||
          (entry.priority % 1) !== 0 || entry.priority < 0 || entry.priority > 65535) {
        throw err(BAD_RECORD, label + " names a preference of " +
          String(entry.priority) + ". It must be a whole number between 0 and 65535.");
      }
      record.priority = entry.priority;
    }
    if (record.type === "MX" && record.priority === undefined) {
      throw err(BAD_RECORD, label + " is an MX record with no preference. " +
        "A mail exchanger without one cannot be ordered against the others.");
    }
    return record;
  }

  // The allowlist verdict for one record. Returns the rule it matched,
  // or throws naming what is wrong and what would clear it. A record
  // carrying a value is held to the kind of record its address is for; a
  // record named by type and address alone is held to the address.
  function checkAllowed(record) {
    var rule = ruleFor(record);
    if (typeof record.content === "string" && typeof rule.recognizes === "function" &&
        !rule.recognizes(record.content)) {
      throw err(WRITE_NOT_ALLOWED,
        "the " + record.type + " record at " + JSON.stringify(record.name) + " is " +
        rule.label + ", and this value does not open with the " + rule.tag + " version tag " +
        "that record carries. This gate writes that record there and nothing else; publish " +
        "any other record at that address yourself.");
    }
    return rule;
  }

  function ruleFor(record) {
    if (record.type === "MX" && !allowMxWrites) {
      throw err(MX_WRITE_DISABLED,
        "this gate will not write the MX record for " + domain + ". Repointing MX moves " +
        "delivery away from this server, which is the one change this server cannot report " +
        "on afterwards, so it is off unless an operator turns it on. Set allowMxWrites when " +
        "that is the intention.");
    }
    if (record.type !== "MX" && allowedTypes.indexOf(record.type) === -1) {
      throw err(WRITE_NOT_ALLOWED,
        "this gate does not write " + record.type + " records. It writes " +
        allowedTypes.join(", ") + ", which is the mail posture this server is responsible " +
        "for. A record outside that set is the operator's to publish.");
    }
    if (record.name !== domain &&
        record.name.slice(-(domain.length + 1)) !== "." + domain) {
      throw err(WRITE_NOT_ALLOWED,
        "the address " + JSON.stringify(record.name) + " is outside " + domain +
        ". This gate writes one zone, and a credential that can reach others is not a " +
        "reason to.");
    }
    for (var i = 0; i < writeRules.length; i += 1) {
      var rule = writeRules[i];
      if (rule.type === record.type && rule.match(record.name)) return rule;
    }
    throw err(WRITE_NOT_ALLOWED,
      "this gate does not write a " + record.type + " record at " +
      JSON.stringify(record.name) + ". The addresses it writes are the ones this server's " +
      "own mail posture lives at: the apex, _dmarc, a DKIM selector under _domainkey, " +
      "_mta-sts, mta-sts, _smtp._tls, and a DANE association under _tcp. Publish anything " +
      "else yourself, or name it in additionalNames when this server should own it.");
  }

  // A record in the shape the provider takes. The identifier and the
  // observed fields are not sent back; only what the change asks for.
  function wireRecord(record) {
    var out = { type: record.type, name: record.name, content: record.content };
    if (typeof record.ttl === "number") out.ttl = record.ttl;
    if (typeof record.priority === "number") out.priority = record.priority;
    return out;
  }

  // The addresses a change set touches, read one at a time, so a zone
  // with thousands of records is not pulled through to answer a
  // question about five of them.
  async function observe(zone, touched) {
    var observed = [];
    for (var i = 0; i < touched.length; i += 1) {
      var found = await client.listRecords(zone, {
        type: touched[i].type,
        name: touched[i].name,
      });
      for (var j = 0; j < found.length; j += 1) observed.push(found[j]);
    }
    return observed;
  }

  // A preview's change set, rebuilt into records this gate has checked.
  // Each change performs one of the three actions, sits at an address the
  // allowlist admits and the preview read, and writes, for a create or an
  // update, a record that passes the same checks a desired record does and
  // sits at the address the change names. A replacement or removal names
  // one record, and no record is named twice. Nothing is read from the
  // provider here; the records named are bound to the zone by `apply`.
  function checkedChangeSet(previewResult) {
    var touched = [];
    var touchedKeys = Object.create(null);
    previewResult.touched.forEach(function (entry, index) {
      if (!entry || typeof entry !== "object" || typeof entry.type !== "string" ||
          typeof entry.name !== "string") {
        throw err(PREVIEW_REQUIRED, "touched[" + index + "] is not an address. Hand back " +
          "the result of preview as it was returned.");
      }
      var address = { type: entry.type.trim().toUpperCase(), name: _normalizeName(entry.name) };
      if (!_validRecordName(address.name)) {
        throw err(PREVIEW_REQUIRED, "touched[" + index + "] is not a record address this " +
          "gate reads. Hand back the result of preview as it was returned.");
      }
      var key = address.type + " " + address.name;
      if (touchedKeys[key] === true) return;
      touchedKeys[key] = true;
      touched.push(address);
    });

    var namedIds = Object.create(null);
    var checked = previewResult.changes.map(function (change, index) {
      var label = "changes[" + index + "]";
      if (!change || typeof change !== "object" || Array.isArray(change)) {
        throw err(PREVIEW_REQUIRED, label + " is not a change.");
      }
      if (change.action !== "create" && change.action !== "update" &&
          change.action !== "delete") {
        throw err(PREVIEW_REQUIRED, label + " names an action this gate does not perform. " +
          "A change creates, updates or deletes one record.");
      }
      if (typeof change.type !== "string" || typeof change.name !== "string") {
        throw err(PREVIEW_REQUIRED, label + " names no record type or address.");
      }
      var type = change.type.trim().toUpperCase();
      var name = _normalizeName(change.name);
      if (!_validRecordName(name)) {
        throw err(BAD_RECORD, label + " names " + JSON.stringify(_displayText(name)) +
          ", which is not a record address this gate can write.");
      }
      var rule = checkAllowed({ type: type, name: name });

      var after = null;
      if (change.action !== "delete") {
        after = readDesired(change.after, label + ".after");
        if (after.type !== type || after.name !== name) {
          throw err(BAD_RECORD, label + " writes a " + after.type + " record at " + after.name +
            " under a change naming a " + type + " record at " + name + ". A change writes " +
            "the record at the address it names.");
        }
        checkAllowed(after);
      }

      if (touchedKeys[type + " " + name] !== true) {
        throw err(PREVIEW_REQUIRED, label + " is at " + type + " " + name + ", an address " +
          "the preview did not read, so nothing this apply reads again covers it. Run " +
          "preview with the record named, and apply what it returns.");
      }

      var recordId = null;
      if (change.action !== "create") {
        if (typeof change.recordId !== "string" || change.recordId.length === 0) {
          throw err(PREVIEW_REQUIRED, label + " is a " + change.action + " naming no record.");
        }
        if (namedIds[change.recordId] === true) {
          throw err(PREVIEW_REQUIRED, label + " names a record another change in the set " +
            "already names.");
        }
        namedIds[change.recordId] = true;
        recordId = change.recordId;
      }

      return { index: index, action: change.action, type: type, name: name, after: after,
        recordId: recordId, rule: rule, before: null };
    });
    return { touched: touched, changes: checked };
  }

  /**
   * @primitive blamepost.dns.preview
   * @signature await gate.preview(request)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: nothing is written by the call that computes it)
   * @related   blamepost.dns.apply, blamepost.dns.create
   *
   * Read the zone, work out what would change to reach the records
   * asked for, and render it. Nothing is written. The result is what
   * `apply` takes back, and it carries what the zone held at the moment
   * it was read, so applying can tell whether that is still true.
   *
   * Every desired record is checked against the allowlist before the
   * zone is read, so a request that would not be written is refused
   * without a provider call. A refusal here leaves an audit row like
   * any other.
   *
   * A record already holding the value asked for produces no change.
   * The comparison covers the value, the lifetime and, for MX, the
   * preference, so a lifetime correction is a change and is shown as
   * one.
   *
   * At the apex, `_dmarc`, `_mta-sts` and `_smtp._tls`, a desired value
   * has to open with the version tag of the record that address is for,
   * or the request is refused with `zone/write-not-allowed`. Only records
   * carrying that tag are compared, replaced or pruned there, so a
   * verification record at the apex is never the record a sender policy
   * replaces or removes.
   *
   * `maxChanges` bounds both the records asked for and the changes they
   * come to. Pruning removes every extra record of the named kind at each
   * address the set names, so one desired record at a crowded address is
   * one write and a removal for each extra, and a set past the ceiling
   * either way is refused with `zone/too-many-changes`.
   *
   * The diff screens every record value for display controls before
   * showing it: bidirectional overrides, zero-width characters, and C0
   * and C1 controls are removed, and every writing system is left alone.
   *
   * @opts
   *   desired: object[],   // required, [{ type, name, content, ttl?, priority? }]
   *   reason:  string,     // required, recorded in the audit row
   *   prune:   boolean,    // default false, remove extra records at the addresses desired names
   *
   * @example
   *   var preview = await gate.preview({
   *     desired: [{ type: "TXT", name: "_dmarc.example.com", content: "v=DMARC1; p=reject" }],
   *     reason:  "publish the DMARC policy",
   *   });
   *   preview.diff;
   */
  async function preview(request) {
    if (!request || typeof request !== "object" || Array.isArray(request)) {
      throw new TypeError("blamepost.dns.preview: request object is required");
    }
    var reason = _requireReason(request.reason, "preview");
    if (!Array.isArray(request.desired)) {
      throw new TypeError("blamepost.dns.preview: request.desired must be an array of records");
    }
    var prune = request.prune === true;

    var desired;
    var rules;
    try {
      desired = request.desired.map(function (entry, index) {
        return readDesired(entry, "desired[" + index + "]");
      });
      rules = desired.map(checkAllowed);
    } catch (refusal) {
      await recordRefusal(reason, {
        code:  refusal && refusal.code ? refusal.code : null,
        stage: "preview",
      });
      throw refusal;
    }

    if (desired.length > maxChanges) {
      await refuse(TOO_MANY_CHANGES,
        "this change set names " + desired.length + " records, and this gate takes at most " +
        maxChanges + " at a time. Split it, or raise maxChanges if a set this large is " +
        "ordinary here.", reason, { stage: "preview", requested: desired.length });
    }

    var zone = await client.zoneId(domain);

    var touched = [];
    var seenKey = Object.create(null);
    desired.forEach(function (record) {
      var key = record.type + " " + record.name;
      if (seenKey[key] === true) return;
      seenKey[key] = true;
      touched.push({ type: record.type, name: record.name });
    });
    var observed = await observe(zone, touched);

    var changes = [];
    var matchedIds = Object.create(null);

    // A record at a desired address is one this set may replace only when
    // it is the kind of record the address is for: at the apex a sender
    // policy, and never the verification record beside it.
    //
    // Each existing record answers for at most one desired record. Exact
    // matches are claimed first, across the whole set, so a record that
    // already holds what is asked for is kept rather than taken as the
    // update target of a record listed before it. Every desired record
    // left over then takes an unclaimed record at its address as its
    // update target, or is created when none is left.
    function holdingFor(want, index) {
      return observed.filter(function (record) {
        return matchedIds[record.id] !== true && record.type === want.type &&
          _normalizeName(record.name) === want.name && _admits(rules[index], record);
      });
    }
    var settled = desired.map(function (want, index) {
      var same = holdingFor(want, index).filter(function (record) {
        return record.content === want.content &&
          (want.ttl === null || record.ttl === want.ttl) &&
          (want.priority === undefined || record.priority === want.priority);
      });
      if (same.length === 0) return false;
      matchedIds[same[0].id] = true;
      return true;
    });
    desired.forEach(function (want, index) {
      if (settled[index]) return;
      var holding = holdingFor(want, index);
      if (holding.length === 0) {
        changes.push({ action: "create", type: want.type, name: want.name,
          before: null, after: want, recordId: null });
        return;
      }
      var target = holding[0];
      matchedIds[target.id] = true;
      changes.push({ action: "update", type: want.type, name: want.name,
        before: target, after: want, recordId: target.id });
    });

    if (prune) {
      // Pruning removes the records of the named kind an address is
      // holding BEYOND what the change set names for it, and it reaches
      // no address the change set is silent about. An apex holding a
      // domain verification record nobody here put there keeps it, while
      // an apex holding two sender policies, which is a permanent error to
      // every receiver that reads it, is reduced to the one asked for.
      observed.forEach(function (record) {
        if (matchedIds[record.id] === true) return;
        var name = _normalizeName(record.name);
        var declared = desired.some(function (want, index) {
          return want.type === record.type && want.name === name &&
            _admits(rules[index], record);
        });
        if (!declared) return;
        changes.push({ action: "delete", type: record.type, name: name,
          before: record, after: null, recordId: record.id });
      });
    }

    // The ceiling again, over what the set actually DOES. The check above
    // reads the records the caller asked for, and pruning turns one of
    // those into a write plus a removal for every extra the address is
    // holding, so a set naming a single record can carry any number of
    // changes and pass a bound that only ever read the one.
    if (changes.length > maxChanges) {
      await refuse(TOO_MANY_CHANGES,
        "this change set makes " + changes.length + " changes to " + desired.length +
        " record address(es), and this gate takes at most " + maxChanges + " changes at a " +
        "time. Pruning removes every extra record at each address the set names, so a " +
        "crowded address turns one record into many changes. Nothing was written. Narrow " +
        "the set, remove the extras at the provider first, or raise maxChanges if a set " +
        "this large is ordinary here.",
        reason, { stage: "preview", changes: changes.length, requested: desired.length });
    }

    var result = {
      previewId:   b.crypto.generateToken(),
      domain:      domain,
      zone:        zone,
      observedAt:  new Date().toISOString(),
      changes:     changes,
      fingerprint: _fingerprint(observed),
      touched:     touched,
      diff:        changes.length === 0
        ? "  no change: the zone already holds every record named"
        : changes.map(_renderChange).join("\n"),
    };

    await recordPreviewed(reason, {
      previewId: result.previewId,
      changes:   changes.length,
      creates:   changes.filter(function (c) { return c.action === "create"; }).length,
      updates:   changes.filter(function (c) { return c.action === "update"; }).length,
      deletes:   changes.filter(function (c) { return c.action === "delete"; }).length,
    });

    return result;
  }

  /**
   * @primitive blamepost.dns.apply
   * @signature await gate.apply(preview, opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a preview is performed only while it is still true)
   * @related   blamepost.dns.preview, blamepost.dns.verify
   *
   * Perform a change set that `preview` computed. The zone is read
   * again first and compared against what the preview saw; a record
   * that moved in between refuses the whole set with
   * `zone/record-drift` rather than overwriting whatever is there now.
   *
   * Writes run as creates, then updates, then deletes. That order is
   * what keeps a replacement from leaving an address holding nothing:
   * the new record exists before the old one goes.
   *
   * A write that fails partway is reported as itself. Nothing is rolled
   * back, because undoing a DNS write is another DNS write, and a zone
   * half changed by a failure is safer than one half changed twice. The
   * refusal names what was written and what was not.
   *
   * The allowlist and the `maxChanges` ceiling are both checked again
   * here rather than taken from the preview. A preview is an ordinary
   * object a caller can build or edit, so a rule enforced only where a
   * set is computed is a rule the write path never applies. Every write
   * is built from the change set as this call checks it: a record written
   * is checked the way a desired record is and has to sit at the address
   * its change names, which has to be one the preview read. A replacement
   * or removal has to name a record the zone holds at that address when
   * this call reads it, of the kind the address is for. The zone is the
   * one the provider holds for the domain at this call. A change set that
   * breaks any of these is refused before anything is written, with
   * `zone/preview-required`, `zone/bad-record`, `zone/write-not-allowed`,
   * `zone/preview-foreign` or `zone/record-drift`.
   *
   * @opts
   *   reason:  string,   // required, recorded in the audit row
   *   confirm: boolean,  // required when the set is more than one change or removes a record
   *
   * @example
   *   var applied = await gate.apply(preview, {
   *     reason:  "publish the DMARC policy",
   *     confirm: true,
   *   });
   */
  async function apply(previewResult, applyOpts) {
    applyOpts = applyOpts || {};
    var reason = _requireReason(applyOpts.reason, "apply");

    if (!previewResult || typeof previewResult !== "object" ||
        typeof previewResult.previewId !== "string" ||
        !Array.isArray(previewResult.changes) ||
        typeof previewResult.fingerprint !== "string" ||
        !Array.isArray(previewResult.touched)) {
      await refuse(PREVIEW_REQUIRED,
        "apply takes the result of preview, which is what carries the change set and what " +
        "the zone held when it was computed. Call preview first and hand its result back.",
        reason, { stage: "apply" });
    }
    if (previewResult.domain !== domain) {
      await refuse(PREVIEW_FOREIGN,
        "this preview was computed for " + JSON.stringify(String(previewResult.domain)) +
        " and this gate governs " + domain + ". Nothing was written.",
        reason, { stage: "apply" });
    }

    var changes = previewResult.changes;
    if (changes.length === 0) {
      await recordApplied("success", reason,
        { previewId: previewResult.previewId, changes: 0, written: 0 });
      return { applyId: b.crypto.generateToken(), previewId: previewResult.previewId,
        domain: domain, zone: previewResult.zone, written: [], changes: 0 };
    }

    // The ceiling, measured here as well as where the set was computed. A
    // preview is an ordinary object a caller can build or edit, so a
    // bound enforced only on the path that computes a set is a bound the
    // write path never applies. Before the confirmation below, so an
    // oversized set is refused for its size rather than for a missing
    // confirmation it was never going to be allowed to give.
    if (changes.length > maxChanges) {
      await refuse(TOO_MANY_CHANGES,
        "this change set makes " + changes.length + " changes and this gate takes at most " +
        maxChanges + " at a time. Nothing was written. `preview` refuses the same ceiling, " +
        "so a set this size did not come from one: split the change, or raise maxChanges if " +
        "a set this large is ordinary here.",
        reason, { stage: "apply", changes: changes.length,
          previewId: previewResult.previewId });
    }

    var removes = changes.filter(function (c) { return c.action === "delete"; }).length;
    if ((changes.length > 1 || removes > 0) && applyOpts.confirm !== true) {
      await refuse(CONFIRM_REQUIRED,
        "this change set makes " + changes.length + " changes" +
        (removes > 0 ? ", " + removes + " of them removals" : "") +
        ", so it takes confirm. Read the preview's diff, then apply again with confirm set.",
        reason, { stage: "apply", changes: changes.length, removes: removes });
    }

    // Every change is rebuilt here from records this gate validates itself,
    // rather than trusted from the preview. A preview is an ordinary object
    // a caller can build or edit, and a gate that checks only on the path
    // that computes the set is one that does not check at all.
    var changeSet;
    try {
      changeSet = checkedChangeSet(previewResult);
    } catch (refusal) {
      await recordRefusal(reason,
        { code: refusal && refusal.code ? refusal.code : null, stage: "apply" });
      throw refusal;
    }

    // The zone is the one the provider holds for this domain now, rather
    // than whichever identifier the preview carries.
    var zone = await client.zoneId(domain);
    if (previewResult.zone !== zone) {
      await refuse(PREVIEW_FOREIGN,
        "this preview names a different zone from the one the provider holds for " + domain +
        ". Nothing was written. Run preview again against this domain.",
        reason, { stage: "apply", previewId: previewResult.previewId });
    }

    var observed = await observe(zone, changeSet.touched);
    if (_fingerprint(observed) !== previewResult.fingerprint) {
      await refuse(RECORD_DRIFT,
        "the zone changed between the preview and this apply, so the change set was computed " +
        "against records that are no longer what is there. Nothing was written. Run preview " +
        "again and read the new diff: something else edited this zone, which is worth " +
        "knowing before repeating the change.",
        reason, { stage: "apply", previewId: previewResult.previewId });
    }

    // Each replacement and removal names a record the zone holds now, at
    // the address the change names, of the kind that address is for.
    for (var p = 0; p < changeSet.changes.length; p += 1) {
      var entry = changeSet.changes[p];
      if (entry.recordId === null) continue;
      var held = null;
      for (var h = 0; h < observed.length; h += 1) {
        if (observed[h].id === entry.recordId) { held = observed[h]; break; }
      }
      if (held === null || held.type !== entry.type ||
          _normalizeName(held.name) !== entry.name) {
        await refuse(RECORD_DRIFT,
          "changes[" + entry.index + "] is a " + entry.action + " of a record the zone " +
          "does not hold as a " + entry.type + " record at " + entry.name + ". Nothing " +
          "was written. Run preview again and read the new diff.",
          reason, { stage: "apply", previewId: previewResult.previewId });
      }
      if (!_admits(entry.rule, held)) {
        await refuse(WRITE_NOT_ALLOWED,
          "changes[" + entry.index + "] is a " + entry.action + " of a record at " +
          entry.name + " that is not " + entry.rule.label + ". This gate replaces and " +
          "removes that record there and nothing else. Nothing was written.",
          reason, { stage: "apply", previewId: previewResult.previewId });
      }
      entry.before = held;
    }

    var ordered = changeSet.changes.filter(function (c) { return c.action === "create"; })
      .concat(changeSet.changes.filter(function (c) { return c.action === "update"; }))
      .concat(changeSet.changes.filter(function (c) { return c.action === "delete"; }));

    var written = [];
    for (var i = 0; i < ordered.length; i += 1) {
      var change = ordered[i];
      try {
        if (change.action === "create") {
          written.push({ action: "create",
            record: await client.createRecord(zone, wireRecord(change.after)) });
        } else if (change.action === "update") {
          written.push({ action: "update",
            record: await client.updateRecord(zone, change.recordId,
              wireRecord(change.after)) });
        } else {
          await client.deleteRecord(zone, change.recordId);
          var removedRecord = { type: change.type, name: change.name, id: change.recordId,
            content: change.before.content };
          if (typeof change.before.priority === "number") {
            removedRecord.priority = change.before.priority;
          }
          written.push({ action: "delete", record: removedRecord });
        }
      } catch (writeError) {
        await recordApplied("failure", reason, {
          previewId: previewResult.previewId,
          changes:   ordered.length,
          written:   written.length,
          failedAt:  i,
          code:      writeError && writeError.code ? writeError.code : null,
        });
        throw err(WRITE_INCOMPLETE,
          (written.length === 0
            ? "the change set stopped at its first change."
            : "the change set stopped after " + written.length + " of " + ordered.length +
              " changes were performed, so the zone holds part of what was asked for.") +
          " The write that failed was a " + change.action + " of the " + change.type +
          " record at " + change.name + ", and it refused with " +
          (writeError && writeError.code ? writeError.code : "no code") + ": " +
          (writeError && writeError.message ? writeError.message : "") +
          " Run preview again to read what the zone holds now before repeating anything.");
      }
    }

    var result = {
      applyId:   b.crypto.generateToken(),
      previewId: previewResult.previewId,
      domain:    domain,
      zone:      zone,
      written:   written,
      changes:   ordered.length,
    };
    await recordApplied("success", reason, {
      previewId: previewResult.previewId,
      applyId:   result.applyId,
      changes:   ordered.length,
      written:   written.length,
    });
    return result;
  }

  /**
   * @primitive blamepost.dns.verify
   * @signature await gate.verify(applied, opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the provider and a resolver are asked separately and compared)
   * @related   blamepost.dns.apply, blamepost.dns.create
   *
   * Read every record a change set wrote, twice: from the provider,
   * which reports what the zone holds, and through a resolver, which
   * reports what the rest of the world can see. The two are compared
   * and the disagreements are reported.
   *
   * It reports rather than throws, because the two disagreeing is
   * ordinary for as long as a previous answer is still cached
   * somewhere, and a call that threw on that would make a normal
   * condition read as a failure. The report separates the two cases
   * that matter. A verdict of `pending` is a resolver with no answer
   * yet, which time fixes. A verdict of `conflict` is a resolver
   * answering with something else, which time does not: on an MX or a
   * policy record it means mail is being routed or judged by a value
   * this server did not write.
   *
   * Each resolver read is held to a budget, so a nameserver that
   * accepts the question and never answers ends the read rather than
   * the caller.
   *
   * @opts
   *   reason: string,   // required, recorded in the audit row
   *
   * @example
   *   var report = await gate.verify(applied, { reason: "confirm the DMARC publish" });
   *   report.ok;
   */
  async function verify(applied, verifyOpts) {
    verifyOpts = verifyOpts || {};
    var reason = _requireReason(verifyOpts.reason, "verify");
    if (!applied || typeof applied !== "object" || !Array.isArray(applied.written)) {
      throw new TypeError("blamepost.dns.verify: pass the result of apply");
    }

    var checks = [];
    for (var i = 0; i < applied.written.length; i += 1) {
      var entry    = applied.written[i];
      var record   = entry.record;
      var removed  = entry.action === "delete";
      var expected = removed ? null : record.content;
      var gone     = removed ? record.content : null;

      var providerValues = [];
      var providerIds    = [];
      var providerError  = null;
      try {
        var held = await client.listRecords(applied.zone, {
          type: record.type,
          name: record.name,
        });
        providerValues = held.map(function (row) { return row.content; });
        providerIds = held.map(function (row) { return row.id; });
      } catch (readError) {
        providerError = readError && readError.code ? readError.code : "read-failed";
      }

      var resolverValues = [];
      var resolverError  = null;
      var reader = RESOLVER_READERS[record.type];
      if (typeof reader !== "string" || typeof resolver[reader] !== "function") {
        resolverError = "no-reader";
      } else {
        try {
          var answer = await posture.withinDnsBudget(
            resolver[reader](record.name), dnsBudgetMs,
            "dns verify " + record.type + " " + record.name);
          resolverValues = _resolverValues(answer);
        } catch (lookupError) {
          resolverError = lookupError && lookupError.code ? lookupError.code : "lookup-failed";
        }
      }

      // A removal is confirmed by absence on both sides; a write is
      // confirmed by the value being present on both.
      // A removal is confirmed at the provider by the removed record's
      // identifier being gone. Another record there may hold the same
      // content, as two MX records naming one exchanger at different
      // priorities do.
      var providerAgrees = removed
        ? (typeof record.id === "string"
          ? providerIds.indexOf(record.id) === -1
          : (gone.length === 0 || providerValues.indexOf(gone) === -1))
        : providerValues.indexOf(expected) !== -1;
      var resolverAgrees = removed
        ? (gone.length === 0 || !resolverValues.some(function (value) {
          return _resolverValueIs(record.type, value, gone, record.priority);
        }))
        : resolverValues.some(function (value) {
          return _resolverValueIs(record.type, value, expected, record.priority);
        });

      var verdict;
      if (providerError !== null) {
        verdict = "provider-unread";
      } else if (!providerAgrees) {
        verdict = "provider-missing";
      } else if (resolverError !== null && resolverError !== "resolver/nxdomain") {
        verdict = "resolver-unread";
      } else if (resolverAgrees) {
        verdict = "agrees";
      } else if (resolverValues.length === 0) {
        verdict = "pending";
      } else {
        verdict = "conflict";
      }

      checks.push({
        action:         entry.action,
        type:           record.type,
        name:           record.name,
        expected:       expected,
        providerValues: providerValues,
        resolverValues: resolverValues,
        providerError:  providerError,
        resolverError:  resolverError,
        verdict:        verdict,
        agrees:         verdict === "agrees",
      });
    }

    function countOf(name) {
      return checks.filter(function (check) { return check.verdict === name; }).length;
    }
    var conflicts = countOf("conflict");
    var pending   = countOf("pending");
    var unread    = countOf("provider-unread") + countOf("resolver-unread") +
      countOf("provider-missing");
    var ok = conflicts === 0 && pending === 0 && unread === 0;

    await recordVerified(ok ? "success" : "failure", reason, {
      applyId:   applied.applyId || null,
      checked:   checks.length,
      conflicts: conflicts,
      pending:   pending,
      unread:    unread,
    });

    return {
      ok:        ok,
      domain:    domain,
      applyId:   applied.applyId || null,
      checks:    checks,
      conflicts: conflicts,
      pending:   pending,
      unread:    unread,
    };
  }

  /**
   * @primitive blamepost.dns.allowlist
   * @signature gate.allowlist()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the gate reports its own reach without being asked to use it)
   * @related   blamepost.dns.create
   *
   * Exactly what this gate will write: the record types, whether the MX
   * switch is on, the ceiling on one change set, and the addresses each
   * type is permitted at, each with the sentence that says what it is
   * for. An operator deciding what a credential is being trusted with
   * reads this rather than the source.
   *
   * @example
   *   var gate = dns.create({ domain: "example.com", sealedToken: sealed });
   *   var reach = gate.allowlist();
   *   reach.types;
   *   // ["TXT", "CNAME", "TLSA"]
   *   reach.allowMxWrites;
   *   // false
   *   reach.addresses[0].describes;
   *   // "the sender policy record at the domain apex"
   */
  function allowlist() {
    return {
      domain:        domain,
      types:         allowedTypes.slice(),
      allowMxWrites: allowMxWrites,
      maxChanges:    maxChanges,
      addresses:     writeRules.map(function (rule) {
        return { type: rule.type, describes: rule.label };
      }),
    };
  }

  /**
   * @primitive blamepost.dns.close
   * @signature gate.close()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a gate that built its own client closes it)
   * @related   blamepost.dns.create
   *
   * Release what this gate built. A gate handed a client through
   * `opts.client` does not close it, because the caller that supplied
   * it owns its lifetime and may still be using it.
   *
   * @example
   *   var gate = dns.create({ domain: "example.com", sealedToken: sealed });
   *   try {
   *     var preview = await gate.preview({ desired: records, reason: "publish DMARC" });
   *     await gate.apply(preview, { reason: "publish DMARC", confirm: true });
   *   } finally {
   *     gate.close();
   *   }
   */
  function close() {
    if (ownsClient && client && typeof client.close === "function") client.close();
  }

  return {
    preview:   preview,
    apply:     apply,
    verify:    verify,
    allowlist: allowlist,
    close:     close,
  };
}

/**
 * @primitive blamepost.dns.tokenPath
 * @signature blamepost.dns.tokenPath(config)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the credential lives where the other sealed credentials live)
 * @related   blamepost.dns.storeToken, blamepost.dns.clearToken
 *
 * The file on the data volume that holds the sealed provider token. It
 * sits in the keys folder beside the sealed DKIM private keys, so a
 * backup that carries one carries the other and an operator destroying
 * a volume's credentials has one folder to look in.
 *
 * The path is derived rather than settable. A second place a credential
 * could be is a second place to look for one that is missing, and the
 * answer to "where is it" has to be one sentence.
 *
 * @example
 *   var dns = require("./lib/dns");
 *   dns.tokenPath(config);
 *   // "/var/lib/blamepost/keys/zone-token.sealed"
 */
function tokenPath(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new TypeError("blamepost.dns.tokenPath: pass the object config.load returned");
  }
  var keyDir = (config.paths && config.paths.keys) || null;
  if (keyDir === null) {
    configModule.assertAbsoluteDataDir("blamepost.dns.tokenPath: config.dataDir",
      config.dataDir);
    if (typeof config.dataDir !== "string" || config.dataDir.length === 0) {
      throw new TypeError("blamepost.dns.tokenPath: config carries neither paths.keys nor " +
        "dataDir, so there is no volume to look on");
    }
    keyDir = nodePath.join(config.dataDir, TOKEN_FOLDER);
  }
  return nodePath.join(keyDir, TOKEN_FILE);
}

// The sealed token this volume holds, or null when it holds none. The
// bound is on the READ rather than on a size measured beforehand,
// because a size and a later read of the same path are two lookups and
// what satisfied the limit need not be what comes back.
function _tokenOnVolume(config) {
  var path = tokenPath(config);
  if (!b.atomicFile.exists(path)) return null;
  var text;
  try {
    text = b.atomicFile.fdSafeReadSync(path,
      { maxBytes: MAX_TOKEN_FILE_BYTES, encoding: "utf8" });
  } catch (readError) {
    throw err(NO_TOKEN,
      "the sealed provider token at " + path + " could not be read: " +
      ((readError && readError.message) || String(readError)) + ". The process that runs " +
      "this server has to be able to read the keys folder on its own volume.");
  }
  var value = String(text).trim();
  return value.length === 0 ? null : value;
}

/**
 * @primitive blamepost.dns.storeToken
 * @signature await blamepost.dns.storeToken(config, token, opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: a credential is sealed before it reaches disk)
 * @related   blamepost.dns.clearToken, blamepost.dns.sealToken
 *
 * Seal a raw provider API token and write it to the data volume. The
 * raw value is sealed before anything touches the filesystem, so the
 * only form that reaches disk is the sealed one, and the file is
 * written readable to this process alone.
 *
 * A token already carrying a seal is refused rather than sealed again,
 * because a doubly sealed value opens to a sealed string rather than to
 * a credential and authenticates with nothing. So is a value
 * `blamepost.dns.sealToken` refuses: one longer than 1024 characters, or
 * one that is not a bearer credential, such as a file holding more than
 * the token.
 *
 * The volume has to be writable, which is what makes this a verb an
 * operator runs with the server stopped.
 *
 * @opts
 *   vault: object,   // exposes aad.seal and aad.unseal, default b.vault
 *
 * @example
 *   var dns = require("./lib/dns");
 *   await dns.storeToken(config, rawToken);
 */
async function storeToken(config, token, opts) {
  opts = opts || {};
  var path = tokenPath(config);
  if (typeof token !== "string" || token.trim().length === 0) {
    throw new TypeError("blamepost.dns.storeToken: the token must be a non-empty string");
  }
  var sealed = sealToken(token, opts.vault);
  b.atomicFile.ensureDir(nodePath.dirname(path), 0o700);
  await b.atomicFile.write(path, sealed, { fileMode: 0o600 });
  return { path: path };
}

/**
 * @primitive blamepost.dns.clearToken
 * @signature blamepost.dns.clearToken(config)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: withdrawing a credential is a volume write)
 * @related   blamepost.dns.storeToken
 *
 * Erase the sealed provider token from the data volume, and report
 * whether there was one. Removing it stops this server from editing any
 * zone; it does not revoke anything at the provider, which is a separate
 * act only the provider can perform, and the one that decides whether a
 * copy taken from a backup is still live.
 *
 * @example
 *   var dns = require("./lib/dns");
 *   dns.clearToken(config).removed;
 */
function clearToken(config) {
  var path = tokenPath(config);
  var held = b.atomicFile.exists(path);
  if (held) nodeFs.rmSync(path, { force: true });
  return { path: path, removed: held };
}

/**
 * @primitive blamepost.dns.fromConfig
 * @signature blamepost.dns.fromConfig(config, opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the zone writer exists or it does not)
 * @related   blamepost.dns.create, blamepost.dns.storeToken
 *
 * Build the zone writer this configuration asks for, or answer `null`
 * when it asks for none.
 *
 * `null` is the whole of what `zoneProvider: "none"` means, and it is a
 * property rather than an accident: no client is built, no credential is
 * opened and nothing in this process makes a request to a DNS provider.
 * A caller holding null has nothing to call, which is what keeps a
 * configuration that names no provider from reaching a zone through some
 * later branch that forgot to check.
 *
 * When a provider IS named, everything the writer needs is settled here
 * and anything missing throws, so a server whose credential is absent,
 * unsealed, sealed for another purpose or supplied twice refuses to start
 * rather than starting with the writer quietly inert. The provider client
 * for account questions is built here too, when the caller supplies none,
 * so an endpoint the client refuses at construction stops the start as
 * well. Building it opens no seal and sends nothing.
 *
 * The credential has exactly one source per run. It is either the sealed
 * value in the configuration, for a deployment that injects secrets, or
 * the sealed file on the data volume that `blamepost zone token set`
 * writes. Both at once is refused rather than resolved by precedence: an
 * operator who rotates the one that is not being read gets a server
 * still authenticating with the old credential and nothing that says so.
 *
 * The returned handle carries five members: `provider`, the provider
 * name the configuration set; `forDomain`, which builds a gate for one
 * hosted domain; `verifyToken`, which asks the provider whether the
 * credential is live and names no domain because the answer is about the
 * account behind it; `describe`; and `close`, which releases every gate
 * the handle built and the client `verifyToken` built.
 *
 * @opts
 *   vault:    object,   // exposes aad.seal and aad.unseal, default b.vault
 *   resolver: object,   // a shared DNS resolver, passed to every gate
 *   client:   object,   // a provider client, for a caller that built one
 *
 * @example
 *   var dns = require("./lib/dns");
 *   var zone = dns.fromConfig(config);
 *   if (zone !== null) {
 *     var gate = zone.forDomain("example.com");
 *   }
 */
function fromConfig(config, opts) {
  opts = opts || {};
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new TypeError("blamepost.dns.fromConfig: pass the object config.load returned");
  }
  var provider = config.zoneProvider === undefined || config.zoneProvider === null
    ? configModule.ZONE_PROVIDER_NONE
    : config.zoneProvider;
  if (provider === configModule.ZONE_PROVIDER_NONE) return null;
  if (configModule.ZONE_PROVIDERS.indexOf(provider) === -1) {
    throw err(NO_PROVIDER,
      "blamepost.dns.fromConfig: " + JSON.stringify(String(provider)) + " is not a hosted " +
      "DNS provider this server speaks to. The ones it does are " +
      configModule.ZONE_PROVIDERS.join(", ") + ".");
  }

  var vault = _requireVault(opts.vault || b.vault, "blamepost.dns.fromConfig: opts.vault");
  var fromSetting = typeof config.zoneApiToken === "string" && config.zoneApiToken.length > 0
    ? config.zoneApiToken
    : null;
  var onVolume = _tokenOnVolume(config);
  var path = tokenPath(config);

  if (fromSetting !== null && onVolume !== null) {
    throw err(TOKEN_TWO_SOURCES,
      "the provider token is supplied twice: BLAMEPOST_ZONE_API_TOKEN carries one and " +
      path + " holds another. This server reads one credential, so the second would be the " +
      "one an operator rotates while the first goes on authenticating. Keep one: erase the " +
      "file with `blamepost zone token clear`, or unset the variable.");
  }
  var sealedToken = fromSetting !== null ? fromSetting : onVolume;
  if (sealedToken === null) {
    throw err(NO_TOKEN,
      "BLAMEPOST_ZONE_PROVIDER names " + provider + " and no provider token is available. " +
      "Seal one onto this volume with `blamepost zone token set --token-file <path> " +
      "--reason <text>`, or supply the sealed value as BLAMEPOST_ZONE_API_TOKEN. Set the " +
      "provider back to none to leave the records to be published by hand.");
  }
  // Checked here rather than at the first write, so an unsealed value on
  // the volume is a refusal to start rather than a refusal at the moment
  // a zone was being edited. Opening a seal passes an unsealed value
  // straight through, which is what makes the prefix the only thing
  // separating a credential from whatever somebody put under the name.
  var where = fromSetting !== null ? "in BLAMEPOST_ZONE_API_TOKEN" : "at " + path;
  if (sealedToken.indexOf(b.constants.VAULT_PREFIX) === 0) {
    throw _sealedForAnotherPurpose(where);
  }
  if (!b.vault.aad.isAadSealed(sealedToken)) {
    throw err(TOKEN_NOT_SEALED,
      "the provider token " + where + " is not sealed. This server seals every credential " +
      "it stores, so " +
      "nothing authenticates with a value that is not, and whatever that value holds has " +
      "been readable to anyone who can read it where it is written. Treat the token as " +
      "exposed: issue a replacement at the provider and seal it with `blamepost zone token " +
      "set --token-file <path> --reason <text>`.");
  }

  var clientOptions = {};
  if (typeof config.zoneEndpoint === "string" && config.zoneEndpoint.length > 0) {
    clientOptions.baseUrl = config.zoneEndpoint;
  }
  if (config.zoneAllowInternalEndpoint === true) clientOptions.allowInternalEndpoint = true;

  var allowMxWrites = config.zoneAllowMxWrites === true;
  var opened = [];

  // A client for the questions that name no domain. The gates each build
  // their own against one zone; asking whether the credential is live is
  // a question about the account behind it, so it would be answered by
  // whichever gate happened to exist and by none when no domain has been
  // named yet. It is built here, so the endpoint it refuses stops the
  // assembly, built again if it is asked for after `close`, and closed
  // with the handle.
  var accountClient = null;
  var ownsAccountClient = false;

  function _accountClient() {
    if (opts.client) return opts.client;
    if (accountClient === null) {
      accountClient = cloudflare.create(Object.assign({}, clientOptions, {
        readToken: _tokenReader(sealedToken, vault),
      }));
      ownsAccountClient = true;
    }
    return accountClient;
  }
  _accountClient();

  async function verifyToken() {
    return await _accountClient().verifyToken();
  }

  function forDomain(domain) {
    var gate = create({
      domain:          domain,
      sealedToken:     sealedToken,
      vault:           vault,
      client:          opts.client,
      clientOptions:   clientOptions,
      resolver:        opts.resolver,
      allowMxWrites:   allowMxWrites,
    });
    opened.push(gate);
    return gate;
  }

  // Where requests actually go, asked of the client that is going to make
  // them. A caller may hand in a client it built itself, and `_accountClient`
  // takes that one as it stands, so the endpoint options held here shaped
  // nothing: reporting them would name an endpoint no request goes to. The
  // client answers for itself through `state()`, which carries the base URL
  // it resolved at construction.
  function _endpointInForce() {
    if (opts.client && typeof opts.client.state === "function") {
      var reported = opts.client.state();
      if (reported && typeof reported.endpoint === "string") return reported.endpoint;
    }
    return clientOptions.baseUrl === undefined
      ? cloudflare.DEFAULT_BASE_URL
      : clientOptions.baseUrl;
  }

  function describe() {
    return {
      provider:      provider,
      allowMxWrites: allowMxWrites,
      endpoint:      _endpointInForce(),
      // Null rather than false when a caller supplied its own client: the
      // policy that client was built under is its own, and answering false
      // would report a refusal this handle never made.
      allowInternalEndpoint: opts.client
        ? null
        : clientOptions.allowInternalEndpoint === true,
      tokenSource:   fromSetting !== null ? "configuration" : "volume",
      tokenPath:     fromSetting !== null ? null : path,
      gatesOpen:     opened.length,
    };
  }

  function close() {
    while (opened.length > 0) {
      var gate = opened.pop();
      if (gate && typeof gate.close === "function") gate.close();
    }
    if (ownsAccountClient && accountClient && typeof accountClient.close === "function") {
      accountClient.close();
    }
    accountClient = null;
    ownsAccountClient = false;
  }

  return {
    provider:    provider,
    forDomain:   forDomain,
    verifyToken: verifyToken,
    describe:    describe,
    close:       close,
  };
}

module.exports = {
  create:     create,
  sealToken:  sealToken,
  fromConfig: fromConfig,
  tokenPath:  tokenPath,
  storeToken: storeToken,
  clearToken: clearToken,
  GateError:  GateError,
  cloudflare: cloudflare,
  CODES: Object.freeze({
    writeNotAllowed:   WRITE_NOT_ALLOWED,
    mxWriteDisabled:   MX_WRITE_DISABLED,
    recordDrift:       RECORD_DRIFT,
    reasonRequired:    REASON_REQUIRED,
    confirmRequired:   CONFIRM_REQUIRED,
    previewRequired:   PREVIEW_REQUIRED,
    previewForeign:    PREVIEW_FOREIGN,
    tokenNotSealed:    TOKEN_NOT_SEALED,
    tokenSealUnopened: TOKEN_SEAL_UNOPENED,
    tooManyChanges:    TOO_MANY_CHANGES,
    badRecord:         BAD_RECORD,
    writeIncomplete:   WRITE_INCOMPLETE,
    noProvider:        NO_PROVIDER,
    noToken:           NO_TOKEN,
    tokenTwoSources:   TOKEN_TWO_SOURCES,
  }),
};
