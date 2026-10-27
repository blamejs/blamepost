// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The message reader, driven with the octets a stranger puts in a DATA
 * body.
 *
 * `b.safeMime.parse` is the entry point, and it is the one reader in
 * this server that a message reaches on every path there is: the
 * submission author check in `lib/mail/listeners.js`, the reply and
 * forward builders in `lib/mail/compose.js`, the IMAP `ENVELOPE`
 * response in `lib/mail/mailbox.js`, the arriving-report reader in
 * `lib/mail/delivery.js`, and the browser rendering in
 * `lib/web/index.js`. The bytes go in undecoded, because a message is
 * 8-bit (RFC 6152) and `toString("utf8")` would put a replacement
 * character where an octet the sender chose used to be.
 *
 * Everything below the parse follows one of those callers.
 *
 * `extractText` and `extractAttachments` are what the reply builder and
 * the browser run over a parsed tree. Both extractions fall back to
 * whatever body the message has when the type asked for is absent, so
 * `lib/mail/compose.js` keeps each only when it is the type it claims,
 * and the same test is applied here. The HTML half then goes into
 * `b.guardHtml.sanitize` at both profiles that file uses, and the
 * decoded subject and sender go through `b.guardText.sanitize` at the
 * profile `lib/web/index.js` renders them under. All three read text the
 * sender chose.
 *
 * `b.guardMessageId.validate` reads the `Message-Id`, `In-Reply-To` and
 * `References` headers, which is what the reply builder does before it
 * threads anything.
 *
 * `b.guardEnvelope.check` reads the `From` header domain against the
 * signing domains the message claims, which is the DMARC identifier
 * alignment the inbound path performs.
 *
 * `b.mailBounce.dsn.parse` reads a report. `lib/mail/delivery.js` runs
 * it only on a message carrying a `message/delivery-status` part whose
 * octets really are UTF-8, and refuses the rest rather than decoding
 * them into characters nobody sent, so both conditions are checked here
 * in the same order. The addresses the report names then go through
 * `lib/store/address.js`, which is documented never to throw.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js mime-message @fuzz/mime-message_seed_corpus/plain.eml
 */

var nodeBuffer = require("node:buffer");

var b       = require("../lib/vendor/blamejs");
var address = require("../lib/store/address");
var harness = require("./harness");

var MIME_REFUSALS       = [b.safeMime.SafeMimeError];
var MESSAGE_ID_REFUSALS = [b.guardMessageId.GuardMessageIdError];
var ENVELOPE_REFUSALS   = [b.guardEnvelope.GuardEnvelopeError];
var HTML_REFUSALS       = [b.guardHtml.GuardHtmlError];
var TEXT_REFUSALS       = [b.guardText.GuardTextError];
var BOUNCE_REFUSALS     = [b.mailBounce.MailBounceError];

// The profile `lib/web/index.js` renders a decoded subject and sender
// under. It strips bidi overrides, zero-width and control characters and
// leaves every script alone.
var HEADER_TEXT_GUARD = { profile: "balanced" };

// The `d=` tag of a DKIM-Signature, which names the domain the signature
// claims. Bounded so a header line of tag characters cannot make the
// match cost grow faster than the line does.
var DKIM_SIGNING_DOMAIN = /(?:^|;)\s*d=([^;]{1,255})/;

function _headerValues(tree, name) {
  var raw = tree && tree.headers && tree.headers.raw;
  var values = raw ? raw[name] : null;
  return Array.isArray(values) ? values : [];
}

function _readMessageIds(tree) {
  var names = ["message-id", "in-reply-to", "references"];
  for (var n = 0; n < names.length; n += 1) {
    var values = _headerValues(tree, names[n]);
    for (var i = 0; i < values.length; i += 1) {
      var value = values[i];
      harness.read(MESSAGE_ID_REFUSALS, function () {
        return b.guardMessageId.validate(value);
      });
      harness.read(MESSAGE_ID_REFUSALS, function () {
        return b.guardMessageId.validateList(value);
      });
    }
  }
}

function _signingDomains(tree) {
  var out = [];
  var values = _headerValues(tree, "dkim-signature");
  for (var i = 0; i < values.length; i += 1) {
    var hit = DKIM_SIGNING_DOMAIN.exec(String(values[i]));
    if (hit) out.push({ result: "pass", signingDomain: hit[1].trim() });
  }
  return out;
}

function _readAlignment(tree) {
  var from = _headerValues(tree, "from");
  if (from.length === 0) return;
  var author = harness.neverThrows("blamepost.store.address.parse", function () {
    return address.parse(from[0]);
  });
  if (!author.ok) return;
  var dkimResults = _signingDomains(tree);
  harness.read(ENVELOPE_REFUSALS, function () {
    return b.guardEnvelope.check({
      fromHeaderDomain: author.domain,
      spfResult:        { result: "pass", domain: author.domain },
      dkimResults:      dkimResults,
    }, { profile: "strict" });
  });
}

// `extractText` returns `{ contentType, charset, body }` or null, and it
// falls back to a body of another type when the one asked for is
// missing, so the type is checked before the body is taken.
function _bodyOfType(extracted, contentType) {
  if (!extracted || extracted.contentType !== contentType) return "";
  return typeof extracted.body === "string" ? extracted.body : "";
}

function _readHtml(html) {
  if (html.length === 0) return;
  // The plain-text rendering of an html-only message, from
  // `lib/mail/compose.js`: every tag comes off, then the character
  // references it left behind are resolved.
  var stripped = harness.read(HTML_REFUSALS, function () {
    return b.guardHtml.sanitize(html, { profile: "strict", allowedTags: [] });
  });
  if (typeof stripped === "string") {
    b.codepointClass.decodeMarkupEntities(stripped);
  }
  // The quoted rendering of the same markup, which keeps tags.
  harness.read(HTML_REFUSALS, function () {
    return b.guardHtml.sanitize(html, { profile: "balanced" });
  });
}

function _readHeaderText(tree) {
  var names = ["subject", "from", "to", "cc", "reply-to", "date"];
  for (var i = 0; i < names.length; i += 1) {
    var value = tree.headers.get ? tree.headers.get(names[i]) : null;
    if (typeof value !== "string" || value.length === 0) continue;
    harness.read(TEXT_REFUSALS, function () {
      return b.guardText.sanitize(value, HEADER_TEXT_GUARD);
    });
  }
}

function _carriesDeliveryStatus(tree) {
  return b.safeMime.findFirst(tree, function (part) {
    return !!part.leaf && part.leaf.contentType === "message/delivery-status";
  }) !== null;
}

function _readReport(data, tree) {
  if (!_carriesDeliveryStatus(tree)) return;
  // The same precondition `lib/mail/delivery.js` puts in front of this
  // reader. RFC 6533 defines the internationalized form of these fields
  // as UTF-8, so a report carrying anything else has no defined reading
  // and is refused rather than decoded.
  if (!nodeBuffer.isUtf8(data)) return;
  var parsed = harness.read(BOUNCE_REFUSALS, function () {
    return b.mailBounce.dsn.parse(data.toString("utf8"));
  });
  if (parsed === null) return;
  var groups = (parsed.raw && parsed.raw.allRecipients) || [];
  for (var i = 0; i < groups.length; i += 1) {
    var named = groups[i]["final-recipient"] || groups[i]["original-recipient"] || "";
    harness.neverThrows("blamepost.store.address.parse", function () {
      return address.parse(String(named));
    });
  }
}

module.exports.fuzz = function (data) {
  var tree = harness.read(MIME_REFUSALS, function () {
    return b.safeMime.parse(data);
  });
  if (tree === null) return;

  harness.read(MIME_REFUSALS, function () {
    return b.safeMime.extractText(tree, { prefer: "plain" });
  });
  var html = harness.read(MIME_REFUSALS, function () {
    return b.safeMime.extractText(tree, { prefer: "html" });
  });
  harness.read(MIME_REFUSALS, function () {
    return b.safeMime.extractAttachments(tree);
  });

  _readHtml(_bodyOfType(html, "text/html"));
  _readHeaderText(tree);
  _readMessageIds(tree);
  _readAlignment(tree);
  _readReport(data, tree);
};

// The readers above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at each one. Four of them sit behind a test on what the
// parsed message turned out to carry, so the corpus has to hold a
// message of each shape for them to be reached at all.
module.exports.targets = function () {
  return [
    { name: "b.safeMime.parse", of: b.safeMime, call: "parse" },
    { name: "b.safeMime.extractText", of: b.safeMime, call: "extractText" },
    { name: "b.safeMime.extractAttachments", of: b.safeMime, call: "extractAttachments" },
    { name: "b.guardHtml.sanitize", of: b.guardHtml, call: "sanitize" },
    { name: "b.guardText.sanitize", of: b.guardText, call: "sanitize" },
    { name: "b.guardMessageId.validate", of: b.guardMessageId, call: "validate" },
    { name: "b.guardMessageId.validateList", of: b.guardMessageId, call: "validateList" },
    { name: "b.guardEnvelope.check", of: b.guardEnvelope, call: "check" },
    { name: "b.mailBounce.dsn.parse", of: b.mailBounce.dsn, call: "parse" },
    { name: "blamepost.store.address.parse", of: address, call: "parse" },
  ];
};
