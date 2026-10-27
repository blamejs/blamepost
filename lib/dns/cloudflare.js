// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.dns.cloudflare
 * @nav    DNS and domain authentication
 * @title  Cloudflare DNS client
 * @order  70
 *
 * The provider client for one hosted DNS API: Cloudflare's version 4
 * REST endpoints for zones and records. It reads zones, lists records,
 * and creates, updates and deletes them. It holds no policy of its own.
 * `blamepost.dns` decides what may be written, and this file carries
 * that decision to the wire.
 *
 * This is not a pluggable provider interface, and it does not pretend
 * to be one. There is one provider here, named in the module. An
 * abstraction over a single implementation describes a shape nobody has
 * tested against a second one, and the parts that differ between
 * providers are exactly the parts such a shape gets wrong: the error
 * envelope, the paging fields, the identity a record is addressed by,
 * and the scopes a credential carries. A second provider arrives as a
 * second file whose differences are visible, rather than as the
 * discovery that the interface never fit.
 *
 * The credential is never a stored field. The caller supplies
 * `readToken`, which yields the token for the duration of one request;
 * this file builds an authorization header from it and keeps no
 * reference afterwards. What it does retain is a SHA3-512 digest, which
 * backs an outbound check: every request is classified before it
 * leaves, and a body or header carrying the token's own bytes is
 * refused rather than sent. The digest is kept because a comparison
 * needs one. The token is not, because a comparison does not need that.
 * The same digest removes the credential from any text the provider
 * sends back before a refusal quotes that text.
 *
 * Every response is untrusted remote input. The transport caps the
 * body, `b.safeJson` caps the parse and strips prototype-poisoning
 * keys, and each field this file reads is checked for the shape it must
 * have. A response that does not match is refused by name. No branch
 * accepts an unexpected shape and carries on. A zone or record
 * identifier goes into a request path only when it is letters, digits,
 * hyphens and underscores, so no identifier reads as a dot segment or
 * carries a separator. An envelope reporting success while carrying
 * errors is refused. Provider text in a refusal is screened for display
 * controls and bounded in length.
 *
 * Every refusal ends by saying what the provider did. A read changes
 * nothing. A write the provider refused was not performed. A write
 * whose answer was a server error, a lost connection or an unreadable
 * body may have been performed, and the refusal says so.
 *
 * Requests are paced against the provider's published ceiling before
 * they are sent, retried with backoff when the failure is transient,
 * and cut off by a circuit breaker when the provider stops answering. A
 * `Retry-After` on a throttled response is waited out as written, and
 * the retry schedule runs after that wait rather than in place of it,
 * so the client never returns before the provider said it may.
 */

var b = require("../vendor/blamejs");
// The screen between text somebody else wrote and a person reading it.
// A provider's error body is whatever that provider returned, and a
// refusal quoting it is printed into a terminal on one line.
var displayText = require("../text");

// The public endpoint. An operator running an egress proxy points this
// elsewhere; the address is validated either way.
var DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4";

// The provider documents 1200 requests per five minutes. The bucket
// below paces against that ceiling, so a large zone read waits rather
// than collecting throttled responses.
var RATE_LIMIT_REQUESTS  = 1200;
var RATE_LIMIT_WINDOW_MS = 300000;

var DEFAULT_TIMEOUT_MS      = 15000;
var DEFAULT_MAX_ATTEMPTS    = 4;
var DEFAULT_PER_PAGE        = 100;
var DEFAULT_MAX_PAGES       = 200;
var DEFAULT_MAX_RESPONSE    = 1048576;
var RETRY_AFTER_CAP_MS      = 60000;
var BREAKER_FAILURES        = 5;
var BREAKER_COOLDOWN_MS     = 30000;

// Ceilings on the numeric options. A value above one of these is a
// mistyped setting rather than an intention: a timeout of an hour holds
// a request open past every caller above it, and a page size the
// provider caps anyway only makes the refusal harder to read.
var MAX_TIMEOUT_MS      = 120000;
var MAX_ATTEMPTS_CAP    = 10;
var MAX_PER_PAGE        = 5000;
var MAX_PAGES_CAP       = 10000;
var MAX_RESPONSE_CAP    = 16777216;

// The longest string the outbound scanner will walk looking for the
// credential. The walk is proportional to the string's length, so this
// is what keeps a large payload from putting an unbounded cost on the
// request path. Nothing this client sends approaches it.
var TOKEN_SCAN_MAX_CHARS = 4096;

// Provider prose reaches operators through refusal messages and audit
// rows. It is scrubbed for embedded credentials and cut to a bounded
// length first: the provider decides what is in that string, and an
// unbounded one becomes the log line.
var MAX_PROVIDER_MESSAGE = 300;

// The shape a zone or record identifier has to have before it is placed
// in a request path. The provider's identifiers are 32 hexadecimal
// characters; this admits any run of letters, digits, hyphens and
// underscores up to 64, and nothing a URL parser reads as a dot segment,
// a separator or an escape.
var IDENTIFIER_RE = /^[A-Za-z0-9_-]{1,64}$/;

// The closing sentence of a refusal, by what the provider may have done.
var NOTHING_WRITTEN   = " Nothing was written.";
var MAY_HAVE_WRITTEN  = " The provider may have performed this write. Read the zone before " +
  "repeating it.";
var EARLIER_MAY_HAVE_WRITTEN = " This attempt was not performed, and an earlier attempt at the " +
  "same write ended without a readable answer, so the provider may have performed that one. " +
  "Read the zone before repeating it.";

// The refusal vocabulary of this layer, named once each. Every throw
// below raises one of these by name, and the exported set holds exactly
// these, so a caller branching on a code and the set describing the
// codes cannot come apart. Renaming one is a breaking change.
var TOKEN_UNVERIFIED     = "zone/token-unverified";
var TOKEN_SCOPE_MISSING  = "zone/token-scope-missing";
var ZONE_NOT_FOUND       = "zone/zone-not-found";
var ZONE_AMBIGUOUS       = "zone/zone-ambiguous";
var RECORD_NOT_FOUND     = "zone/record-not-found";
var RECORD_CONFLICT      = "zone/record-conflict";
var MALFORMED_RESPONSE   = "zone/malformed-response";
var ENDPOINT_NOT_ALLOWED = "zone/endpoint-not-allowed";
var BAD_REQUEST          = "zone/bad-request";
var RATE_LIMITED         = "zone/rate-limited";
var PROVIDER_UNAVAILABLE = "zone/provider-unavailable";
var REQUEST_FAILED       = "zone/request-failed";
var CREDENTIAL_EGRESS    = "zone/credential-egress-refused";

// Refusals whose verdict is about the request rather than the moment.
// Nothing retries these: the credential is wrong, the zone is absent,
// the response did not parse. Retrying repeats the same answer and
// spends the provider's ceiling doing it.
var PERMANENT_CODES = [
  TOKEN_UNVERIFIED,
  TOKEN_SCOPE_MISSING,
  ZONE_NOT_FOUND,
  ZONE_AMBIGUOUS,
  RECORD_NOT_FOUND,
  RECORD_CONFLICT,
  MALFORMED_RESPONSE,
  ENDPOINT_NOT_ALLOWED,
  BAD_REQUEST,
  CREDENTIAL_EGRESS,
];

// Provider error numbers this file recognizes, each mapped onto the
// refusal a caller acts on. An unrecognized number falls through to the
// HTTP status, which is why the table can be short without guessing.
// The two authorization failures are deliberately kept apart. A token
// the provider does not recognize is a different thing from one it
// recognizes and will not let near this zone, and they need opposite
// answers from an operator: the first is replaced, the second is
// granted a scope it is missing.
var PROVIDER_ERROR_CODES = {
  1049:  ZONE_NOT_FOUND,
  7000:  ZONE_NOT_FOUND,
  7003:  ZONE_NOT_FOUND,
  9106:  TOKEN_UNVERIFIED,
  10000: TOKEN_UNVERIFIED,
  9109:  TOKEN_SCOPE_MISSING,
  81044: RECORD_NOT_FOUND,
  81053: RECORD_CONFLICT,
  81057: RECORD_CONFLICT,
};

function _isPermanent(code, statusCode) {
  if (PERMANENT_CODES.indexOf(code) !== -1) return true;
  if (typeof statusCode === "number" && statusCode >= 400 && statusCode < 500) {
    // A throttled response is the one four hundred class answer that
    // says "later" rather than "no".
    return statusCode !== 429;
  }
  return false;
}

// One error class for this layer, so a caller can tell a refusal from
// here apart from a framework error with a single check. `permanent` is
// derived from the code and the status at every construction rather
// than passed in, so the same refusal classifies identically whichever
// call site built it, and the retry loop reads that one field instead
// of deciding again.
var DnsProviderError = b.frameworkError.defineClass("DnsProviderError", {
  permanentClassifier: _isPermanent,
});

var err = DnsProviderError.factory;

function _isIdentifier(value) {
  return typeof value === "string" && IDENTIFIER_RE.test(value);
}

// The text a TXT record carries, from the content the provider answers
// with. Content that does not open with a double quote is the text
// itself. Content that does is one or more RFC 1035 section 5.1
// character-strings separated by whitespace, each quoted, with `\"`,
// `\\` and `\DDD` escapes inside; their text is joined with nothing
// between, which is how a receiver reads a TXT record split into
// strings. Answers null when the quoting does not close.
function _txtText(content) {
  if (content.charAt(0) !== "\"") return content;
  var out = "";
  var i = 0;
  while (i < content.length) {
    var ch = content.charAt(i);
    if (ch === " " || ch === "\t") { i += 1; continue; }
    if (ch !== "\"") return null;
    i += 1;
    var closed = false;
    while (i < content.length) {
      var c = content.charAt(i);
      if (c === "\"") { closed = true; i += 1; break; }
      if (c === "\\") {
        var digits = content.slice(i + 1, i + 4);
        if (/^[0-9]{3}$/.test(digits)) {
          out += String.fromCharCode(parseInt(digits, 10));
          i += 4;
          continue;
        }
        if (i + 1 >= content.length) return null;
        out += content.charAt(i + 1);
        i += 2;
        continue;
      }
      out += c;
      i += 1;
    }
    if (!closed) return null;
  }
  return out;
}

// Every window of the credential's length in `text` whose digest matches
// the credential's, replaced. `credential` is `{ digest, length }`, or
// null before any token has been read.
function _withoutCredential(text, credential) {
  if (!credential || credential.length === 0 || text.length < credential.length) return text;
  var out = "";
  var i = 0;
  while (i <= text.length - credential.length) {
    var candidate = text.slice(i, i + credential.length);
    if (b.crypto.timingSafeEqual(b.crypto.sha3Hash(candidate), credential.digest)) {
      out += "[redacted]";
      i += credential.length;
    } else {
      out += text.charAt(i);
      i += 1;
    }
  }
  return out + text.slice(i);
}

// Provider text as a refusal may quote it. The text is cut to the quoted
// length plus the credential's length before the credential is removed,
// so a credential straddling the cut is removed whole rather than left
// in part.
function _safeMessage(text, credential) {
  if (typeof text !== "string" || text.length === 0) return "";
  var slack = credential ? credential.length : 0;
  var head = text.length > MAX_PROVIDER_MESSAGE + slack
    ? text.slice(0, MAX_PROVIDER_MESSAGE + slack)
    : text;
  var scrubbed = b.redact.redactText(_withoutCredential(head, credential));
  if (typeof scrubbed !== "string") return "";
  var shown = displayText.forDisplay(scrubbed);
  return shown.length > MAX_PROVIDER_MESSAGE
    ? shown.slice(0, MAX_PROVIDER_MESSAGE) + "..."
    : shown;
}

// Whether a request that did not succeed may still have been performed.
// A refusal the provider answered with a four hundred class status, or
// with a success status and a success field of false, was not. Anything
// else, a server error, a lost connection or a body that could not be
// read, leaves it open.
function _mayHavePerformed(statusCode, reportedFailure) {
  if (typeof statusCode === "number" && statusCode >= 400 && statusCode < 500) return false;
  if (typeof statusCode === "number" && statusCode >= 200 && statusCode < 300 &&
      reportedFailure) {
    return false;
  }
  return true;
}

// A token bucket over the provider's published ceiling. `take` resolves
// when a request may go out, waiting for the refill when the window is
// spent. It paces rather than refuses, because the caller's alternative
// to waiting is a throttled response that costs the same wall time and
// a retry as well.
function _rateLimiter(limit, windowMs) {
  var tokens = limit;
  var last   = Date.now();

  function refill() {
    var now = Date.now();
    if (now <= last) return;
    var gained = ((now - last) / windowMs) * limit;
    if (gained > 0) {
      tokens = Math.min(limit, tokens + gained);
      last = now;
    }
  }

  return {
    take: async function take() {
      for (;;) {
        refill();
        if (tokens >= 1) { tokens -= 1; return; }
        var waitMs = Math.ceil(((1 - tokens) / limit) * windowMs) + 1;
        await b.safeAsync.sleep(waitMs);
      }
    },
    available: function () { refill(); return Math.floor(tokens); },
  };
}

function _requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("blamepost.dns.cloudflare: " + label +
      " must be a non-empty string, got " + (value === null ? "null" : typeof value));
  }
  return value;
}

// A zone or record identifier a caller hands in, checked before it is
// placed in a request path. The value is not quoted back.
function _requireIdentifier(value, label) {
  if (!_isIdentifier(value)) {
    throw new TypeError("blamepost.dns.cloudflare: " + label + " must be a provider " +
      "identifier: 1 to 64 letters, digits, hyphens or underscores");
  }
  return value;
}

function _boundedInt(value, fallback, floor, ceiling, label) {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !isFinite(value) || (value % 1) !== 0) {
    throw new TypeError("blamepost.dns.cloudflare.create: " + label +
      " must be a whole number, got " + String(value));
  }
  if (value < floor || value > ceiling) {
    throw new TypeError("blamepost.dns.cloudflare.create: " + label + " must be between " +
      floor + " and " + ceiling + ", got " + value + ". Leave it out to get " + fallback + ".");
  }
  return value;
}

// The closing sentences for one attempt. A read changes nothing whatever
// happened to it. A write names what the provider may have done, and an
// attempt that follows an unanswered one says so even when this attempt
// itself was refused outright.
function _outcomeSentences(method, earlierUnanswered) {
  if (method === "GET") return { refused: NOTHING_WRITTEN, unknown: NOTHING_WRITTEN };
  return {
    refused: earlierUnanswered ? EARLIER_MAY_HAVE_WRITTEN : NOTHING_WRITTEN,
    unknown: MAY_HAVE_WRITTEN,
  };
}

// The provider's envelope, checked field by field. Every branch either
// returns a value of the shape the caller expects or throws. `settled` is
// the closing sentence for a response whose body could not be read.
function _readEnvelope(parsed, statusCode, settled) {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw err(MALFORMED_RESPONSE,
      "the provider's response was not a JSON object." + settled + " Either the " +
      "provider answered with something other than its documented envelope, or a proxy " +
      "answered in its place; check the endpoint this client is pointed at.", statusCode);
  }
  if (typeof parsed.success !== "boolean") {
    throw err(MALFORMED_RESPONSE,
      "the provider's response carried no boolean success field." + settled + " The " +
      "envelope is not the one this client reads; check the endpoint and the API version.",
      statusCode);
  }
  if (parsed.errors !== undefined && parsed.errors !== null && !Array.isArray(parsed.errors)) {
    throw err(MALFORMED_RESPONSE,
      "the provider's response carried a non-array errors field." + settled, statusCode);
  }
  if (parsed.success === true && Array.isArray(parsed.errors) && parsed.errors.length > 0) {
    throw err(MALFORMED_RESPONSE,
      "the provider's response reported success and carried " + parsed.errors.length +
      " error(s) in the same envelope, so it does not say whether the request succeeded." +
      settled, statusCode);
  }
  return parsed;
}

function _firstProviderError(envelope, credential) {
  var errors = Array.isArray(envelope.errors) ? envelope.errors : [];
  for (var i = 0; i < errors.length; i += 1) {
    var entry = errors[i];
    if (entry && typeof entry === "object") {
      return {
        code:    typeof entry.code === "number" ? entry.code : null,
        message: _safeMessage(typeof entry.message === "string" ? entry.message : "",
          credential),
      };
    }
  }
  return { code: null, message: "" };
}

function _refusalFor(envelope, statusCode, outcome, credential) {
  var first  = _firstProviderError(envelope, credential);
  var mapped = first.code !== null &&
    Object.prototype.hasOwnProperty.call(PROVIDER_ERROR_CODES, first.code)
    ? PROVIDER_ERROR_CODES[first.code]
    : null;
  var detail   = first.message.length > 0 ? " The provider said: " + first.message : "";
  var numbered = first.code !== null ? " (provider code " + first.code + ")" : "";
  var settled  = _mayHavePerformed(statusCode, envelope.success === false)
    ? outcome.unknown
    : outcome.refused;

  // The two statuses that mean "later" are read before the body's error
  // number, and not after it. A throttled or failing response carries
  // whatever number the provider happened to attach, and several of
  // those numbers map to permanent refusals; reading the number first
  // turns a request that should be retried into one that never is, and
  // the symptom is a write that stops on the provider's busiest minute
  // and reports the credential as the problem.
  if (statusCode === 429) {
    return err(RATE_LIMITED,
      "the provider throttled this request (HTTP 429)" + numbered + "." + detail +
      settled + " This client waits out the interval the provider names and " +
      "tries again; this refusal means the attempts were spent before it cleared.",
      statusCode);
  }
  if (typeof statusCode === "number" && statusCode >= 500) {
    return err(PROVIDER_UNAVAILABLE,
      "the provider returned HTTP " + statusCode + numbered + "." + detail +
      settled + " This is the provider failing rather than the request being " +
      "wrong, so it is retried.", statusCode);
  }

  if (mapped === TOKEN_UNVERIFIED) {
    return err(TOKEN_UNVERIFIED,
      "the provider refused the API token" + numbered + "." + detail + settled +
      " Check that the token is current: a token that has been revoked reports " +
      "the same way as one that was mistyped. Issue a replacement and reseal it.",
      statusCode);
  }
  if (mapped === ZONE_NOT_FOUND) {
    return err(ZONE_NOT_FOUND,
      "the provider holds no zone matching this request" + numbered + "." + detail +
      settled + " Confirm the domain is on this provider account, and that the " +
      "token's scope covers it: a zone outside the scope is not listed and reads as absent.",
      statusCode);
  }
  if (mapped === RECORD_NOT_FOUND) {
    return err(RECORD_NOT_FOUND,
      "the record this request named no longer exists at the provider" + numbered + "." +
      detail + settled + " Run the preview again: the record was removed or " +
      "replaced after the change you are applying was computed.", statusCode);
  }
  if (mapped === RECORD_CONFLICT) {
    return err(RECORD_CONFLICT,
      "the provider already holds a record that conflicts with this one" + numbered + "." +
      detail + settled + " Run the preview again so the change is computed " +
      "against what the zone holds now.", statusCode);
  }
  if (mapped === TOKEN_SCOPE_MISSING) {
    return err(TOKEN_SCOPE_MISSING,
      "the provider recognizes this API token and will not let it reach this zone" +
      numbered + "." + detail + settled + " The token is valid, so replacing " +
      "it changes nothing: grant it the edit scope for this zone at the provider.",
      statusCode);
  }

  if (statusCode === 401 || statusCode === 403) {
    return err(TOKEN_SCOPE_MISSING,
      "the provider refused this request as unauthorized (HTTP " + statusCode + ")" +
      numbered + "." + detail + settled + " A token that can read a zone but " +
      "not edit it reports this on the first write. Grant the edit scope for this zone, " +
      "or reduce the change to reads.", statusCode);
  }
  if (statusCode === 404) {
    return err(RECORD_NOT_FOUND,
      "the provider has no such zone or record (HTTP 404)" + numbered + "." + detail +
      settled, statusCode);
  }
  return err(BAD_REQUEST,
    "the provider refused this request (HTTP " + String(statusCode) + ")" + numbered + "." +
    detail + settled, statusCode);
}

// The retry interval the provider asked for, in milliseconds, written
// either as seconds or as an HTTP date. An absent or unreadable value
// returns null and the caller falls back to its own backoff.
function _retryAfterMs(headers) {
  if (!headers || typeof headers !== "object") return null;
  var raw = headers["retry-after"];
  if (raw === undefined) raw = headers["Retry-After"];
  if (Array.isArray(raw)) raw = raw[0];
  if (typeof raw !== "string" && typeof raw !== "number") return null;
  var text = String(raw).trim();
  if (/^[0-9]{1,9}$/.test(text)) {
    var seconds = parseInt(text, 10);
    if (!isFinite(seconds) || seconds < 0) return null;
    return Math.min(b.constants.TIME.seconds(seconds), RETRY_AFTER_CAP_MS);
  }
  var at = Date.parse(text);
  if (isNaN(at)) return null;
  var delta = at - Date.now();
  if (delta <= 0) return 0;
  return Math.min(delta, RETRY_AFTER_CAP_MS);
}

/**
 * @primitive blamepost.dns.cloudflare.create
 * @signature blamepost.dns.cloudflare.create(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one named provider over its version 4 REST API)
 * @related   blamepost.dns.cloudflare.verifyToken, blamepost.dns.cloudflare.listRecords
 *
 * Build the provider client. Every option is validated here and a bad
 * one throws, so a mistyped endpoint or a missing token accessor is
 * found when the server starts rather than the first time a record is
 * written.
 *
 * The returned handle carries `verifyToken`, `zoneId`, `listRecords`,
 * `createRecord`, `updateRecord`, `deleteRecord`, a `state` reader for
 * the breaker and the remaining request budget, and `close`, which
 * removes the outbound scanner this client installed.
 *
 * The endpoint must be an https address with no credentials written
 * into it, and there is no option that relaxes the scheme: a token
 * travels on every one of these requests, and a cleartext endpoint
 * would put it on the wire in the clear. A private, loopback or link
 * local address is refused unless `allowInternalEndpoint` says
 * otherwise, which is how a client is pointed at an egress proxy on
 * purpose and cannot be pointed at one by accident. Cloud metadata
 * addresses are refused whatever that option says. An address literal
 * or the loopback name in the endpoint is refused by this call; a name
 * that resolves to such an address is refused on each request.
 *
 * @opts
 *   readToken:             function,  // required, () => string | Promise<string>, one request's token
 *   baseUrl:               string,    // default https://api.cloudflare.com/client/v4
 *   timeoutMs:             number,    // default 15000, per request, 1 to 120000
 *   maxAttempts:           number,    // default 4 including the first, 1 to 10
 *   perPage:               number,    // default 100 records per page, 1 to 5000
 *   maxPages:              number,    // default 200 pages per listing, 1 to 10000
 *   maxResponseBytes:      number,    // default 1048576, 1024 to 16777216
 *   allowInternalEndpoint: boolean,   // default false, permit a private range endpoint
 *   agent:                 object,    // an http agent, for an endpoint with a private authority
 *   onEvent:               function,  // ({ event, detail }) => void, drop-silent
 *
 * @example
 *   var client = cloudflare.create({
 *     readToken: function () { return vault.unseal(sealedToken); },
 *   });
 *   var zone = await client.zoneId("example.com");
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.dns.cloudflare.create: opts object is required");
  }
  if (typeof opts.readToken !== "function") {
    throw new TypeError("blamepost.dns.cloudflare.create: opts.readToken must be a function " +
      "returning the API token for one request, got " + typeof opts.readToken +
      ". The token is sealed at rest, so this client asks for it per call rather than " +
      "holding it.");
  }

  var baseText = opts.baseUrl === undefined ? DEFAULT_BASE_URL : opts.baseUrl;
  _requireString(baseText, "opts.baseUrl");

  var baseUrl;
  try {
    baseUrl = b.safeUrl.parse(baseText);
  } catch (parseError) {
    throw new TypeError("blamepost.dns.cloudflare.create: opts.baseUrl was refused (" +
      (parseError && parseError.code ? parseError.code : "unknown") + "). It must be an " +
      "https address with no credentials embedded in it.");
  }

  var allowInternalEndpoint = opts.allowInternalEndpoint === true;
  if (opts.allowInternalEndpoint !== undefined &&
      typeof opts.allowInternalEndpoint !== "boolean") {
    throw new TypeError("blamepost.dns.cloudflare.create: opts.allowInternalEndpoint must be " +
      "a boolean. It decides whether the endpoint may resolve to a private address, and a " +
      "value that is neither true nor false leaves that undecided at the point where the " +
      "answer is the difference between reaching the provider and reaching the operator's " +
      "own network.");
  }

  // An endpoint written as an address literal, or as the loopback name,
  // is classified here with the outbound guard's own classifier, so the
  // refusal arrives when the client is built, under the same code the
  // guard's refusal carries on a request. A name that resolves to an
  // internal address is refused by the guard on each request instead.
  var endpointHost = baseUrl.hostname;
  if (endpointHost.charAt(0) === "[" && endpointHost.charAt(endpointHost.length - 1) === "]") {
    endpointHost = endpointHost.slice(1, -1);
  }
  var endpointClass = b.ssrfGuard.classify(endpointHost);
  if (endpointClass === "cloud-metadata") {
    throw err(ENDPOINT_NOT_ALLOWED, "blamepost.dns.cloudflare.create: opts.baseUrl names " +
      endpointHost + ", a cloud metadata address. It is refused whatever " +
      "allowInternalEndpoint says. Point the client at the provider's public API or at the " +
      "address of the proxy in front of it.", null);
  }
  if (!allowInternalEndpoint &&
      (endpointClass !== null || b.ssrfGuard.isLoopbackHost(endpointHost))) {
    throw err(ENDPOINT_NOT_ALLOWED, "blamepost.dns.cloudflare.create: opts.baseUrl names " +
      endpointHost + ", a " + (endpointClass || "loopback") + " address, and " +
      "allowInternalEndpoint is not set. Point the client at the provider's public API, or " +
      "set allowInternalEndpoint when a proxy on this address is deliberate.", null);
  }

  var timeoutMs   = _boundedInt(opts.timeoutMs, DEFAULT_TIMEOUT_MS, 1, MAX_TIMEOUT_MS,
    "opts.timeoutMs");
  var maxAttempts = _boundedInt(opts.maxAttempts, DEFAULT_MAX_ATTEMPTS, 1, MAX_ATTEMPTS_CAP,
    "opts.maxAttempts");
  var perPage     = _boundedInt(opts.perPage, DEFAULT_PER_PAGE, 1, MAX_PER_PAGE,
    "opts.perPage");
  var maxPages    = _boundedInt(opts.maxPages, DEFAULT_MAX_PAGES, 1, MAX_PAGES_CAP,
    "opts.maxPages");
  var maxResponseBytes = _boundedInt(opts.maxResponseBytes, DEFAULT_MAX_RESPONSE, 1024,
    MAX_RESPONSE_CAP, "opts.maxResponseBytes");

  if (opts.onEvent !== undefined && typeof opts.onEvent !== "function") {
    throw new TypeError("blamepost.dns.cloudflare.create: opts.onEvent must be a function " +
      "when supplied");
  }
  var onEvent = opts.onEvent || null;

  function emit(event, detail) {
    if (!onEvent) return;
    try {
      onEvent({ event: event, detail: detail || {} });
    } catch (_e) {
      /* drop-silent by design: this is an observability hook on the
         request path, and a throwing hook must not take the request
         with it. */
    }
  }

  // The digest and length of the credential, filled the first time a
  // token is read. Together they let the scanner find the token inside
  // a longer string without the token itself being retained.
  var tokenDigest = null;
  var tokenLength = 0;

  function noteTokenDigest(token) {
    // A rotated credential replaces these rather than accumulating, so
    // the scanner always describes the token now in use.
    tokenDigest = b.crypto.sha3Hash(token);
    tokenLength = token.length;
  }

  // Does this string carry the credential anywhere inside it? By the
  // time a request is scanned its body is JSON, so a token that leaked
  // into a record value sits inside a longer string rather than being
  // one, and a check that hashed only whole values would not see it.
  // Every window of the credential's length is hashed and compared,
  // which finds it wherever it sits while keeping only the digest.
  function carriesToken(value) {
    if (tokenDigest === null || tokenLength === 0) return false;
    if (typeof value !== "string") return false;
    if (value.length < tokenLength || value.length > TOKEN_SCAN_MAX_CHARS) return false;
    var last = value.length - tokenLength;
    for (var i = 0; i <= last; i += 1) {
      if (b.crypto.timingSafeEqual(
        b.crypto.sha3Hash(value.slice(i, i + tokenLength)), tokenDigest)) {
        return true;
      }
    }
    return false;
  }

  // The generic credential shapes, from the framework's own detectors.
  // Only patterns whose action is a refusal are asked for: a detector
  // that rewrites the body would silently change a record an operator
  // asked to publish, and a DKIM public key is exactly the kind of long
  // opaque string such a detector is prone to.
  var genericClassifier = b.redact.classifyDefaults({
    patterns: ["pem", "ssh-private", "aws-access-key"],
  });

  // The outbound check, written here rather than taken from the
  // framework's default for one reason: the authorization header has to
  // be left out of it. The credential belongs in that header and
  // nowhere else, so a scan that read it would refuse every request
  // this client makes. Everything else is scanned, and a credential
  // found in a body, an address or any other header refuses the request
  // instead of sending it.
  function classifier(input) {
    var source  = (input && input.headers) || {};
    var headers = {};
    Object.keys(source).forEach(function (name) {
      if (String(name).toLowerCase() === "authorization") return;
      headers[name] = source[name];
    });
    var scanned = { body: input && input.body, url: input && input.url, headers: headers };

    var verdict = genericClassifier(scanned);
    if (verdict && verdict.verdict === "refuse") return verdict;

    var suspect = [scanned.body, scanned.url];
    Object.keys(headers).forEach(function (name) { suspect.push(headers[name]); });
    for (var i = 0; i < suspect.length; i += 1) {
      if (carriesToken(suspect[i])) {
        return {
          verdict: "refuse",
          hits:    [{ label: "provider-api-token", action: "refuse", where: "outbound" }],
        };
      }
    }
    return verdict;
  }

  // The scanner wraps an instance's own request method, so this client
  // gets its own object rather than the shared module. Two clients then
  // scan independently, and one closing does not unwrap the other.
  var transport = {
    request: function (requestOpts) { return b.httpClient.request(requestOpts); },
  };

  var dlp = b.redact.installOutboundDlp({
    httpClient: transport,
    classifier: classifier,
    onRefuse:   function (info) {
      emit("dns.provider.egress_refused", {
        labels: info && info.verdict && Array.isArray(info.verdict.hits)
          ? info.verdict.hits.map(function (hit) { return hit.label; })
          : [],
      });
    },
  });

  var breaker = b.circuitBreaker.create({
    name:             "dns-provider",
    failureThreshold: BREAKER_FAILURES,
    cooldownMs:       BREAKER_COOLDOWN_MS,
    successThreshold: 1,
    onStateChange:    function (change) {
      emit("dns.provider.breaker", { from: change.from, to: change.to });
    },
  });

  var limiter = _rateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_MS);

  // The endpoint path with any trailing separator walked off, settled
  // once here rather than per request. It is walked rather than matched
  // because a pattern anchoring a repeat to the end of a string costs
  // time proportional to the square of a run of that character.
  var basePath = baseUrl.pathname;
  while (basePath.length > 0 && basePath.charAt(basePath.length - 1) === "/") {
    basePath = basePath.slice(0, -1);
  }

  function urlFor(pathText, query) {
    var target = new URL(baseUrl.toString());
    target.pathname = basePath + pathText;
    target.search = "";
    if (query) {
      Object.keys(query).forEach(function (key) {
        var value = query[key];
        if (value === undefined || value === null || value === "") return;
        target.searchParams.set(key, String(value));
      });
    }
    return target.toString();
  }

  // The credential's digest and length, for removing it from provider
  // text. Null until a token has been read.
  function credential() {
    return tokenDigest === null ? null : { digest: tokenDigest, length: tokenLength };
  }

  // The refusals from a write attempt that may have been performed. The
  // retry wrapper reads this to tell a later attempt at the same write
  // that an earlier one ended without a readable answer.
  var unanswered = new WeakSet();

  function unansweredWrite(method, failure) {
    if (method !== "GET") unanswered.add(failure);
    return failure;
  }

  // One attempt at one request. Everything above this decides whether to
  // call it again; nothing below it retries. `earlierUnanswered` says an
  // earlier attempt at the same write may have been performed.
  async function attempt(method, pathText, query, body, earlierUnanswered) {
    var outcome = _outcomeSentences(method, earlierUnanswered);
    await limiter.take();

    var token = await opts.readToken();
    if (typeof token !== "string" || token.length === 0) {
      throw err(TOKEN_UNVERIFIED,
        "no API token was available for this request." + outcome.refused + " The token is " +
        "sealed at rest and opened for each call, so this is what a wrong volume passphrase " +
        "or a missing sealed file looks like.", null);
    }
    noteTokenDigest(token);

    var requestOpts = {
      method:           method,
      url:              urlFor(pathText, query),
      headers:          {
        "authorization": "Bearer " + token,
        "accept":        "application/json",
      },
      timeoutMs:        timeoutMs,
      responseMode:     "always-resolve",
      maxResponseBytes: maxResponseBytes,
    };
    if (allowInternalEndpoint) requestOpts.allowInternal = true;
    if (opts.agent) requestOpts.agent = opts.agent;
    if (body !== undefined && body !== null) {
      requestOpts.headers["content-type"] = "application/json";
      requestOpts.body = JSON.stringify(body);
    }

    var response;
    try {
      response = await transport.request(requestOpts);
    } catch (transportError) {
      if (transportError && transportError.code === "redact-dlp/refused") {
        throw err(CREDENTIAL_EGRESS,
          "the outbound scanner found the API token inside the request payload and refused " +
          "to send it." + outcome.refused + " This is a defect in the caller: the credential " +
          "belongs in the authorization header and nowhere else.", null);
      }
      if (transportError && typeof transportError.code === "string" &&
          transportError.code.indexOf("ssrf-guard/") === 0) {
        throw err(ENDPOINT_NOT_ALLOWED,
          "the endpoint resolved to an address the outbound guard refuses (" +
          transportError.code + ")." + outcome.refused + " Point this client at the " +
          "provider's public API, or set allowInternalEndpoint when an egress proxy on a " +
          "private address is deliberate.", null);
      }
      throw unansweredWrite(method, err(REQUEST_FAILED,
        "the request to the provider did not complete (" +
        (transportError && transportError.code ? transportError.code : "no code") + "): " +
        _safeMessage(transportError && transportError.message ? transportError.message : "",
          credential()) +
        outcome.unknown, null));
    }

    var statusCode = response.statusCode;

    // The provider named an interval. Wait it out here, before the
    // refusal reaches the retry schedule, so the next attempt cannot go
    // out earlier than the provider said it may.
    if (statusCode === 429) {
      var waitMs = _retryAfterMs(response.headers);
      if (waitMs !== null) {
        emit("dns.provider.throttled", { waitMs: waitMs });
        await b.safeAsync.sleep(waitMs);
      }
    }

    // The closing sentence for a body this attempt could not read.
    var unreadable = _mayHavePerformed(statusCode, false);
    var settled    = unreadable ? outcome.unknown : outcome.refused;

    var text = response.body ? response.body.toString("utf8") : "";
    if (text.length === 0) {
      var empty = err(MALFORMED_RESPONSE,
        "the provider returned an empty body at HTTP " + statusCode + " where an envelope " +
        "was expected." + settled, statusCode);
      throw unreadable ? unansweredWrite(method, empty) : empty;
    }

    var parsed;
    try {
      parsed = b.safeJson.parse(text, { maxBytes: maxResponseBytes });
    } catch (parseError) {
      var unparsed = err(MALFORMED_RESPONSE,
        "the provider's response did not parse as JSON (" +
        (parseError && parseError.code ? parseError.code : "unknown") + ") at HTTP " +
        statusCode + "." + settled, statusCode);
      throw unreadable ? unansweredWrite(method, unparsed) : unparsed;
    }

    var envelope;
    try {
      envelope = _readEnvelope(parsed, statusCode, settled);
    } catch (shapeError) {
      throw unreadable ? unansweredWrite(method, shapeError) : shapeError;
    }
    if (envelope.success !== true || statusCode < 200 || statusCode >= 300) {
      var refusal = _refusalFor(envelope, statusCode, outcome, credential());
      throw _mayHavePerformed(statusCode, envelope.success === false)
        ? unansweredWrite(method, refusal)
        : refusal;
    }
    return envelope;
  }

  // The retry and breaker wrapper. `withRetry` owns the backoff. The
  // classifier is this layer's own, because the framework's default
  // reads network-shaped errors and these are refusals carrying a
  // derived permanent field.
  function call(method, pathText, query, body) {
    var earlierUnanswered = false;
    return breaker.wrap(function () {
      return b.retry.withRetry(async function () {
        try {
          return await attempt(method, pathText, query, body, earlierUnanswered);
        } catch (failure) {
          if (failure !== null && typeof failure === "object" && unanswered.has(failure)) {
            earlierUnanswered = true;
          }
          throw failure;
        }
      }, {
        maxAttempts: maxAttempts,
        isRetryable: function (candidate) { return candidate && candidate.permanent === false; },
        onRetry:     function (info) {
          emit("dns.provider.retry", {
            attempt: info.attempt,
            delay:   info.delay,
            code:    info.error && info.error.code ? info.error.code : null,
          });
        },
      });
    });
  }

  function requireArray(value, label, statusCode) {
    if (!Array.isArray(value)) {
      throw err(MALFORMED_RESPONSE,
        "the provider's " + label + " was not an array. Nothing was written.", statusCode);
    }
    return value;
  }

  // A record as this client hands it on. Only the fields the gate acts
  // on are carried, and each is checked: a record missing an identifier
  // or a name cannot be compared against a preview or addressed for
  // deletion, so it is a refusal rather than a partly filled object.
  // `settled` is the closing sentence: a listing wrote nothing, and a
  // record read out of a write's answer is one the provider reported
  // performing.
  function readRecord(raw, settled) {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw err(MALFORMED_RESPONSE,
        "the provider returned a record that was not an object." + settled, null);
    }
    if (typeof raw.id !== "string" || raw.id.length === 0) {
      throw err(MALFORMED_RESPONSE,
        "the provider returned a record with no identifier." + settled + " A record " +
        "without one cannot be matched to the change that was previewed.", null);
    }
    if (!_isIdentifier(raw.id)) {
      throw err(MALFORMED_RESPONSE,
        "the provider returned a record whose identifier is not 1 to 64 letters, digits, " +
        "hyphens or underscores." + settled + " An identifier of any other shape is not " +
        "placed in a request path.", null);
    }
    if (typeof raw.type !== "string" || raw.type.length === 0) {
      throw err(MALFORMED_RESPONSE,
        "the provider returned a record with no type." + settled, null);
    }
    if (typeof raw.name !== "string" || raw.name.length === 0) {
      throw err(MALFORMED_RESPONSE,
        "the provider returned a record with no name." + settled, null);
    }
    var content = typeof raw.content === "string" ? raw.content : "";
    if (raw.type === "TXT") {
      var text = _txtText(content);
      if (text === null) {
        throw err(MALFORMED_RESPONSE,
          "the provider returned a TXT record whose quoting does not close." + settled, null);
      }
      content = text;
    }
    var record = {
      id:      raw.id,
      type:    raw.type,
      name:    raw.name,
      content: content,
      ttl:     typeof raw.ttl === "number" ? raw.ttl : null,
    };
    if (typeof raw.priority === "number") record.priority = raw.priority;
    return record;
  }

  /**
   * @primitive blamepost.dns.cloudflare.verifyToken
   * @signature await client.verifyToken()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the credential answers for itself before a write)
   * @related   blamepost.dns.cloudflare.create
   *
   * Ask the provider whether the credential is live, and refuse with
   * `zone/token-unverified` when it is not. This runs before a write so
   * a revoked or mistyped token is reported as itself, rather than as
   * whatever the first record call happens to fail with.
   *
   * A token that verifies is not a token that may write. Scope is not
   * reported by this endpoint and is discoverable only by attempting
   * the write, which comes back as `zone/token-scope-missing`.
   *
   * @example
   *   var verified = await client.verifyToken();
   *   verified.active;
   *   // true
   */
  async function verifyToken() {
    var envelope = await call("GET", "/user/tokens/verify", null, undefined);
    var result = envelope.result;
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
      throw err(MALFORMED_RESPONSE,
        "the token verification response carried no result object. Nothing was written.",
        null);
    }
    if (result.status !== "active") {
      throw err(TOKEN_UNVERIFIED,
        "the provider reports this API token is not active (status: " +
        _safeMessage(String(result.status), credential()) + "). Nothing was written. Issue " +
        "a replacement token and reseal it.", null);
    }
    return { active: true, id: _isIdentifier(result.id) ? result.id : null };
  }

  /**
   * @primitive blamepost.dns.cloudflare.zoneId
   * @signature await client.zoneId(domain)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: a domain names a zone, the provider addresses it by identifier)
   * @related   blamepost.dns.cloudflare.create
   *
   * Resolve a hosted domain to the provider's zone identifier. Refuses
   * with `zone/zone-not-found` when the account holds no such zone, and
   * with `zone/zone-ambiguous` when it holds more than one by that
   * name, which is a state no write should guess its way through.
   *
   * @example
   *   var zone = await client.zoneId("example.com");
   *   var records = await client.listRecords(zone, { name: "_dmarc.example.com" });
   */
  async function zoneId(domain) {
    _requireString(domain, "domain");
    var envelope = await call("GET", "/zones", { name: domain, per_page: 50 }, undefined);
    var zones = requireArray(envelope.result, "zone list", null);
    var matches = zones.filter(function (zone) {
      return zone && typeof zone === "object" && zone.name === domain;
    });
    if (matches.some(function (zone) { return !_isIdentifier(zone.id); })) {
      throw err(MALFORMED_RESPONSE,
        "the provider listed a zone named " + JSON.stringify(domain) + " whose identifier is " +
        "not 1 to 64 letters, digits, hyphens or underscores. Nothing was written. An " +
        "identifier of any other shape is not placed in a request path.", null);
    }
    if (matches.length === 0) {
      throw err(ZONE_NOT_FOUND,
        "the provider account holds no zone named " + JSON.stringify(domain) + ". Nothing " +
        "was written. Add the domain at the provider, or check that the token's scope " +
        "includes it: a zone outside the scope is not listed and reads as absent.", null);
    }
    if (matches.length > 1) {
      throw err(ZONE_AMBIGUOUS,
        "the provider returned " + matches.length + " zones named " + JSON.stringify(domain) +
        ". Nothing was written. Name the zone identifier directly rather than letting this " +
        "client pick one.", null);
    }
    return matches[0].id;
  }

  /**
   * @primitive blamepost.dns.cloudflare.listRecords
   * @signature await client.listRecords(zone, filter?)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 1035 section 3.2 for the record types, provider API v4 for the paging
   * @related   blamepost.dns.cloudflare.create
   *
   * Every record in a zone, following the provider's paging to the end.
   * `filter` narrows by `type` and `name` at the provider rather than
   * afterwards, so a large zone is not fetched whole to answer a
   * question about one name.
   *
   * Paging is bounded, and the walk refuses rather than truncates. A
   * provider that repeats a record across pages, or that reports a page
   * count it does not honor, stops the listing with
   * `zone/malformed-response`. The listing is what a preview is
   * computed against, so one that was truncated but read as complete
   * would produce a change set silently missing records.
   *
   * @opts
   *   type:  string,   // narrow to one record type at the provider
   *   name:  string,   // narrow to one record name at the provider
   *
   * @example
   *   var mx = await client.listRecords(zone, { type: "MX" });
   */
  async function listRecords(zone, filter) {
    _requireIdentifier(zone, "zone");
    filter = filter || {};
    var out  = [];
    var seen = Object.create(null);
    var page = 1;

    // Every turn of this loop is a read: it issues one GET and appends
    // to a local array, and the refusals below abandon that array.
    // allow:loop-that-acts-before-it-has-refused no earlier turn changed anything outside this function, so a refusal leaves no partly-done work to reconcile
    for (;;) {
      if (page > maxPages) {
        throw err(MALFORMED_RESPONSE,
          "the provider's record listing ran past " + maxPages + " pages. Nothing was " +
          "written. Raise maxPages if the zone is genuinely this large; otherwise the " +
          "provider is paging without advancing.", null);
      }
      var envelope = await call("GET", "/zones/" + encodeURIComponent(zone) + "/dns_records", {
        page:     page,
        per_page: perPage,
        type:     filter.type,
        name:     filter.name,
      }, undefined);

      var batch = requireArray(envelope.result, "record listing", null);
      for (var i = 0; i < batch.length; i += 1) {
        var record = readRecord(batch[i], NOTHING_WRITTEN);
        if (seen[record.id] === true) {
          throw err(MALFORMED_RESPONSE,
            "the provider returned record " + JSON.stringify(record.id) + " on more than " +
            "one page. Nothing was written. The listing cannot be read as a picture of the " +
            "zone, and a change computed from it would count that record twice.", null);
        }
        seen[record.id] = true;
        out.push(record);
      }

      var info = envelope.result_info;
      if (info === undefined || info === null) break;
      if (typeof info !== "object" || Array.isArray(info)) {
        throw err(MALFORMED_RESPONSE,
          "the provider's paging block was not an object. Nothing was written.", null);
      }
      if (typeof info.total_pages !== "number") break;
      if (page >= info.total_pages) break;
      page += 1;
    }
    return out;
  }

  /**
   * @primitive blamepost.dns.cloudflare.createRecord
   * @signature await client.createRecord(zone, record)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 1035 section 3.2, provider API v4 dns_records
   * @related   blamepost.dns.cloudflare.create
   *
   * Add one record to a zone and return it as the provider stored it.
   * The returned record is read out of the response rather than echoed
   * from the request, so what a caller verifies against is the
   * provider's own account of what it now holds.
   *
   * @example
   *   var stored = await client.createRecord(zone, {
   *     type:    "TXT",
   *     name:    "_mta-sts.example.com",
   *     content: "v=STSv1; id=20260917",
   *     ttl:     3600,
   *   });
   *   stored.content;
   *   // "v=STSv1; id=20260917"
   */
  async function createRecord(zone, record) {
    _requireIdentifier(zone, "zone");
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new TypeError("blamepost.dns.cloudflare.createRecord: record must be an object");
    }
    var envelope = await call("POST", "/zones/" + encodeURIComponent(zone) + "/dns_records",
      null, record);
    return readRecord(envelope.result, MAY_HAVE_WRITTEN);
  }

  /**
   * @primitive blamepost.dns.cloudflare.updateRecord
   * @signature await client.updateRecord(zone, recordId, record)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 1035 section 3.2, provider API v4 dns_records
   * @related   blamepost.dns.cloudflare.create
   *
   * Replace one record, addressed by the provider's identifier, and
   * return it as the provider stored it. Addressing by identifier
   * rather than by name is what lets the layer above refuse a record
   * that changed underneath a preview: the identifier names the row
   * that was read, and a different row carries a different one.
   *
   * @example
   *   var replaced = await client.updateRecord(zone, stored.id, {
   *     type:    "TXT",
   *     name:    "_mta-sts.example.com",
   *     content: "v=STSv1; id=20260918",
   *     ttl:     3600,
   *   });
   *   replaced.id === stored.id;
   *   // true
   */
  async function updateRecord(zone, recordId, record) {
    _requireIdentifier(zone, "zone");
    _requireIdentifier(recordId, "recordId");
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new TypeError("blamepost.dns.cloudflare.updateRecord: record must be an object");
    }
    var envelope = await call("PUT",
      "/zones/" + encodeURIComponent(zone) + "/dns_records/" + encodeURIComponent(recordId),
      null, record);
    return readRecord(envelope.result, MAY_HAVE_WRITTEN);
  }

  /**
   * @primitive blamepost.dns.cloudflare.deleteRecord
   * @signature await client.deleteRecord(zone, recordId)
   * @since     0.1.0
   * @status    experimental
   * @spec      provider API v4 dns_records
   * @related   blamepost.dns.cloudflare.create
   *
   * Remove one record, addressed by the provider's identifier. The
   * identifier the provider reports having deleted is checked against
   * the one that was asked for, so a provider answering about a
   * different row is refused rather than reported as a success.
   *
   * @example
   *   var removed = await client.deleteRecord(zone, stored.id);
   *   removed.id === stored.id;
   *   // true
   */
  async function deleteRecord(zone, recordId) {
    _requireIdentifier(zone, "zone");
    _requireIdentifier(recordId, "recordId");
    var envelope = await call("DELETE",
      "/zones/" + encodeURIComponent(zone) + "/dns_records/" + encodeURIComponent(recordId),
      null, undefined);
    var result = envelope.result;
    if (result === null || typeof result !== "object" || Array.isArray(result) ||
        typeof result.id !== "string") {
      throw err(MALFORMED_RESPONSE,
        "the provider's delete response named no record identifier. The record may or may " +
        "not have been removed; list the zone before acting on this.", null);
    }
    if (result.id !== recordId) {
      throw err(MALFORMED_RESPONSE,
        "the provider reported deleting " + (_isIdentifier(result.id)
          ? "record " + JSON.stringify(result.id)
          : "a record under an identifier of another shape") + " when " +
        JSON.stringify(recordId) + " was asked for. List the zone before acting on this.",
        null);
    }
    return { id: result.id };
  }

  /**
   * @primitive blamepost.dns.cloudflare.state
   * @signature client.state()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the client reports its own posture without a request)
   * @related   blamepost.dns.cloudflare.create
   *
   * What the client will do next, without asking the provider: the
   * breaker's state, how many requests remain in the paced budget, and
   * the endpoint it is pointed at. The endpoint is reported as origin
   * and path only, because a client built with a query or a fragment on
   * its base address should not have either quoted back into a report.
   *
   * @example
   *   var posture = client.state();
   *   posture.breaker;
   *   // "closed"
   *   posture.endpoint;
   *   // "https://api.cloudflare.com/client/v4"
   */
  function state() {
    return {
      breaker:           breaker.getState(),
      requestsAvailable: limiter.available(),
      endpoint:          baseUrl.origin + baseUrl.pathname,
    };
  }

  /**
   * @primitive blamepost.dns.cloudflare.close
   * @signature client.close()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the outbound scanner is installed per client and removed with it)
   * @related   blamepost.dns.cloudflare.create
   *
   * Remove the outbound scanner this client installed on its own
   * transport. A client that is discarded without closing leaves the
   * framework counting an interceptor that nothing will use again,
   * which is what makes a later posture check report outbound scanning
   * as wired when it is not.
   *
   * @example
   *   var client = cloudflare.create({ readToken: readToken });
   *   try {
   *     await client.verifyToken();
   *   } finally {
   *     client.close();
   *   }
   */
  function close() {
    dlp.uninstall();
  }

  return {
    verifyToken:  verifyToken,
    zoneId:       zoneId,
    listRecords:  listRecords,
    createRecord: createRecord,
    updateRecord: updateRecord,
    deleteRecord: deleteRecord,
    state:        state,
    close:        close,
  };
}

module.exports = {
  create:               create,
  DnsProviderError:     DnsProviderError,
  DEFAULT_BASE_URL:     DEFAULT_BASE_URL,
  RATE_LIMIT_REQUESTS:  RATE_LIMIT_REQUESTS,
  RATE_LIMIT_WINDOW_MS: RATE_LIMIT_WINDOW_MS,
  CODES: Object.freeze({
    tokenUnverified:     TOKEN_UNVERIFIED,
    tokenScopeMissing:   TOKEN_SCOPE_MISSING,
    zoneNotFound:        ZONE_NOT_FOUND,
    zoneAmbiguous:       ZONE_AMBIGUOUS,
    recordNotFound:      RECORD_NOT_FOUND,
    recordConflict:      RECORD_CONFLICT,
    malformedResponse:   MALFORMED_RESPONSE,
    endpointNotAllowed:  ENDPOINT_NOT_ALLOWED,
    badRequest:          BAD_REQUEST,
    rateLimited:         RATE_LIMITED,
    providerUnavailable: PROVIDER_UNAVAILABLE,
    requestFailed:       REQUEST_FAILED,
    credentialEgress:    CREDENTIAL_EGRESS,
  }),
};
