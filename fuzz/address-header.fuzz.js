// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Address headers and the addresses in them, driven with the text a
 * stranger writes into `From`, `Sender`, `To` or `Reply-To`, and with
 * the addresses an account and its aliases are stored under.
 *
 * Every reader here belongs to this server rather than to the framework.
 *
 * `lib/store/address.js` decides what an address means for routing, for
 * the author binding and for every sealed column keyed on one. `parse`
 * and `parseDomain` are documented never to throw, and each canonical
 * form they return is held to reading back as itself: an address that
 * canonicalizes to a spelling which then canonicalizes to something else
 * keys one mailbox under two names. `canonical` and `canonicalDomain`
 * are the throwing siblings, and they have to agree with the verdicts
 * they wrap and refuse with a coded `StoreError`. `fold` is the
 * normalization the sealed-column hashes use, and it has to be
 * idempotent.
 *
 * `lib/mail/compose.js` splits a header into entries, counts the angle
 * addresses in each, and cuts the address out of an entry. The submission
 * listener and the reply builder both compose those three. The split
 * neither invents an angle address nor loses one, and the address cut out
 * of an entry is text that entry carries.
 *
 * The listener's author binding measures every entry of `From`. It is
 * modeled here in the order `lib/mail/listeners.js` applies it, over the
 * header value the MIME reader decodes, which is the value the listener
 * reads: an entry with more than one angle address is refused, an entry
 * whose address does not parse is refused, and every other entry's
 * address is measured. For a header written in plain ASCII with no
 * quoted string, comment, group, backslash or encoded word, the mailboxes
 * RFC 5322 section 3.4 reads out of it are unambiguous, and each of them
 * that parses has to be one the binding measured. A mailbox a receiver
 * displays that the binding never measured is a message this server
 * signs under a name nobody checked.
 *
 * `permittedAuthors` and `permittedAuthor` in `lib/mail/listeners.js`
 * are driven over a stand-in store built from the input, one address per
 * line: the first line is the account's own address, a line starting
 * with `@` is a catch-all alias row, a line starting with `#` names a
 * mailbox holding the operator role, a line starting with `!` names a
 * local part on a sending credential's refusal list, and every other
 * line is an alias row. The list is canonical and free of duplicates,
 * starts with the account's own address, and holds nothing a catch-all
 * granted. The decision agrees with the list for an account, and for a
 * sending credential it holds the domain scope, the refusal list and the
 * operator-role floor. A plus tag never changes either answer.
 *
 * Run one input by hand:
 *   node fuzz/run-once.js address-header "Alice <alice@example.com>, bob@example.net"
 */

var b         = require("../lib/vendor/blamejs");
var address   = require("../lib/store/address");
var errors    = require("../lib/store/errors");
var compose   = require("../lib/mail/compose");
var listeners = require("../lib/mail/listeners");
var mailbox   = require("../lib/mail/mailbox");
var harness   = require("./harness");

var holds       = harness.holds;
var neverThrows = harness.neverThrows;

var MIME_REFUSALS  = [b.safeMime.SafeMimeError];

var FROM_PREFIX = Buffer.from("From: ", "ascii");
var HEADER_END  = Buffer.from("\r\n\r\n", "ascii");

// RFC 5321 section 4.1.2 atext and a DNS domain are printable ASCII with
// no space, and the strict guard profile refuses everything else.
var CANONICAL_TEXT_RE = /^[\x21-\x7e]+$/;

// A header this harness can read the mailboxes out of without a full RFC
// 5322 parser: printable ASCII with no quoted string, backslash, comment,
// group syntax or encoded word.
var PLAIN_HEADER_RE = /^[\x20-\x7e]*$/;
var NOT_PLAIN_RE    = /["\\():;]|=\?/;

var CATCH_ALL_PREFIX = "@";
var OPERATOR_PREFIX  = "#";
var REFUSED_PREFIX   = "!";

var TAG_PROBE = "fuzztag";

function _parse(text) {
  return neverThrows("blamepost.store.address.parse", function () {
    return address.parse(text);
  });
}

function _parseDomain(text) {
  return neverThrows("blamepost.store.address.parseDomain", function () {
    return address.parseDomain(text);
  });
}

// A throwing sibling, which either returns or refuses with the coded
// store error its documentation names.
function _throwing(label, code, fn) {
  try {
    return { returned: true, value: fn() };
  } catch (err) {
    holds(label + " refuses with a coded StoreError",
      err instanceof errors.StoreError && err.code === code,
      { code: err && err.code, message: err && err.message });
    return { returned: false, value: null };
  }
}

// ---- lib/store/address.js --------------------------------------------------

function _addressReadsBackAsItself(text) {
  var v = _parse(text);
  var thrown = _throwing("address.canonical", "store/bad-address", function () {
    return address.canonical(text);
  });
  holds("address.canonical returns exactly when parse accepts", thrown.returned === v.ok,
    { input: text, parsed: v });
  if (!v.ok) return;

  holds("parse: the address is its local part and domain joined",
    v.address === v.localPart + "@" + v.domain, v);
  holds("parse: the tag is absent or non-empty", v.tag === null ||
    (typeof v.tag === "string" && v.tag.length > 0), v);
  holds("parse: the mailbox local part carries no tag separator past its first character",
    v.localPart.indexOf(address.TAG_SEPARATOR) <= 0, v);
  holds("parse: the canonical address and the written form are printable ASCII",
    CANONICAL_TEXT_RE.test(v.address) && CANONICAL_TEXT_RE.test(v.written), v);
  holds("parse: fold leaves the canonical address unchanged", address.fold(v.address) === v.address, v);
  holds("address.canonical agrees with parse", thrown.value.address === v.address, thrown.value);

  var again = _parse(v.address);
  holds("parse: the canonical address reads back as itself, with no tag",
    again.ok && again.address === v.address && again.tag === null, { first: v, again: again });

  var written = _parse(v.written);
  holds("parse: the written form reads back to the same mailbox and the same tag",
    written.ok && written.address === v.address && written.written === v.written &&
    written.tag === v.tag, { first: v, written: written });

  var domain = _parseDomain(v.domain);
  holds("parseDomain: the domain of a canonical address reads back as itself",
    domain.ok && domain.domain === v.domain, { parsed: v, domain: domain });
}

function _domainReadsBackAsItself(text) {
  var v = _parseDomain(text);
  var thrown = _throwing("address.canonicalDomain", "store/bad-domain", function () {
    return address.canonicalDomain(text);
  });
  holds("address.canonicalDomain returns exactly when parseDomain accepts",
    thrown.returned === v.ok, { input: text, parsed: v });
  if (!v.ok) return;
  holds("parseDomain: the canonical domain is printable ASCII",
    CANONICAL_TEXT_RE.test(v.domain), v);
  holds("address.canonicalDomain agrees with parseDomain", thrown.value === v.domain,
    { parsed: v, canonical: thrown.value });
  holds("parseDomain: fold leaves the canonical domain unchanged",
    address.fold(v.domain) === v.domain, v);
  var again = _parseDomain(v.domain);
  holds("parseDomain: the canonical domain reads back as itself",
    again.ok && again.domain === v.domain, { first: v, again: again });
}

function _foldIsIdempotent(text) {
  var once = address.fold(text);
  holds("fold is idempotent", address.fold(once) === once, { input: text, once: once });
}

// ---- lib/mail/compose.js ---------------------------------------------------

// Every character a regular expression gives a meaning to, so a cut
// address can be looked for as the literal text it is.
var REGEXP_SPECIAL_RE = /[.*+?^${}()|[\]\\]/g;

function _escapeForRegExp(text) {
  return String(text).replace(REGEXP_SPECIAL_RE, "\\$&");
}

// Whether `part` is `whole` with zero or more characters taken out.
function _isSubsequence(part, whole) {
  var at = 0;
  for (var i = 0; i < whole.length && at < part.length; i += 1) {
    if (whole[i] === part[at]) at += 1;
  }
  return at === part.length;
}

function _angleCount(text) {
  var n = neverThrows("blamepost.mail.compose.angleAddressCount", function () {
    return compose.angleAddressCount(text);
  });
  holds("angleAddressCount returns a whole number", Number.isInteger(n) && n >= 0, n);
  return n;
}

function _entries(text) {
  var entries = neverThrows("blamepost.mail.compose.splitAddressHeader", function () {
    return compose.splitAddressHeader(text);
  });
  holds("splitAddressHeader returns an array", Array.isArray(entries), entries);
  entries.forEach(function (entry) {
    holds("splitAddressHeader: every entry is non-empty trimmed text",
      typeof entry === "string" && entry.length > 0 && entry === entry.trim(), entry);
  });
  holds("splitAddressHeader: no entry is shorter than a comma-separated segment",
    entries.length <= text.split(",").length, { segments: text.split(",").length, entries: entries.length });

  var total = _angleCount(text);
  var carried = 0;
  entries.forEach(function (entry) { carried += _angleCount(entry); });
  holds("splitAddressHeader neither invents nor loses an angle address",
    carried === total, { header: total, entries: carried });
  return entries;
}

function _addressOfEntry(entry) {
  var cut = neverThrows("blamepost.mail.compose.normalizeAddress", function () {
    return compose.normalizeAddress(entry, "fuzz: address header entry");
  });
  holds("normalizeAddress returns a name and an address as text",
    cut && typeof cut.name === "string" && typeof cut.address === "string", cut);
  // A comment around a bare address is taken out of it, so an entry
  // carrying `(` gives an address made of its own characters in their own
  // order rather than one piece of it.
  holds("normalizeAddress takes the address out of the entry rather than inventing one",
    entry.indexOf("(") === -1
      ? entry.indexOf(cut.address) !== -1
      : _isSubsequence(cut.address, entry),
    { entry: entry, address: cut.address });
  // The two readers of one entry, held against each other. A `<` inside
  // a quoted display name and a `>` that closes nothing are not a pair,
  // and the counter already reads the entry that way, so an entry it
  // counts no angle address in is an addr-spec on its own and nothing is
  // cut out of it. A third answer, neither the entry nor the contents of
  // a pair, is a span running from inside somebody's name to past the end
  // of the mailbox.
  //
  // Stated against the counter rather than against the last `<` and the
  // last `>` in the text, because those two are not a pair either, and a
  // quoted display name is allowed to hold brackets of its own inside an
  // address that really was cut at one.
  //
  // The pairs the address is cut from are the ones outside every comment.
  // A pair inside a comment, `a@example.com (see <x>)`, is counted by the
  // ambiguity count and is not one the cut reads, and a comment that never
  // closes holds every pair after its opening.
  var pairs = _angleCount(entry);
  var cutFrom = compose.angleAddressCount(entry, { inComments: false });
  holds("angleAddressCount: the pairs outside comments are a part of all the pairs",
    Number.isInteger(cutFrom) && cutFrom >= 0 && cutFrom <= pairs,
    { cutFrom: cutFrom, pairs: pairs });
  if (cutFrom === 0) {
    // RFC 5322 §3.2.2 comments around a bare addr-spec are not part of
    // it, so they are the one thing taken out: an entry with no `(` is
    // the address whole, and any other entry gives an address made of
    // its own characters in their own order.
    var whole = entry.trim();
    holds("normalizeAddress: an entry carrying no angle address is cut at none",
      entry.indexOf("(") === -1 ? cut.address === whole : _isSubsequence(cut.address, whole),
      { entry: entry, address: cut.address });
  } else {
    // The address has to sit between a `<` and a `>` somewhere in the
    // entry, allowing the whitespace the cut trims off either end.
    // Searched for as a bracketed whole rather than by looking at what
    // follows the first occurrence of the text: a short address is a
    // substring of the display name as often as not, and `<b>` beside a
    // name holding `bob` would be measured at the wrong `b`.
    holds("normalizeAddress: an address cut from a pair sits inside that pair",
      new RegExp("<\\s*" + _escapeForRegExp(cut.address) + "\\s*>").test(entry),
      { entry: entry, address: cut.address, pairs: pairs, cutFrom: cutFrom });
  }
  return cut.address;
}

// ---- the author binding in lib/mail/listeners.js ---------------------------

// The addresses the listener measures for one `From` value, or null when
// it refuses the header before measuring anything. The order and the
// three refusals follow `lib/mail/listeners.js`.
function _measuredAuthors(value) {
  var entries = _entries(value);
  if (entries.length === 0) return null;
  for (var i = 0; i < entries.length; i += 1) {
    if (_angleCount(entries[i]) > 1) return null;
  }
  var measured = [];
  for (var j = 0; j < entries.length; j += 1) {
    var parsed = _parse(_addressOfEntry(entries[j]));
    if (!parsed.ok) return null;
    measured.push(parsed.address);
  }
  return measured;
}

// The `From` value the listener reads: the header block parsed by the
// MIME reader, which decodes encoded words, and exactly one `From`.
function _decodedFrom(data) {
  var tree = harness.read(MIME_REFUSALS, function () {
    return b.safeMime.parse(Buffer.concat([FROM_PREFIX, data, HEADER_END]),
      mailbox.MESSAGE_PARSE_CAPS);
  });
  if (tree === null) return null;
  var values = (tree.headers && tree.headers.raw && tree.headers.raw.from) || [];
  return values.length === 1 && typeof values[0] === "string" ? values[0] : null;
}

// The mailboxes RFC 5322 section 3.4 reads out of a plain header: every
// comma separates two of them, and a mailbox is the last angle address in
// its segment or the segment itself. Segments that name no address the
// store accepts are left out.
function _mailboxesOfPlainHeader(value) {
  var out = [];
  value.split(",").forEach(function (segment) {
    var text = segment.trim();
    var lt = text.lastIndexOf("<");
    var gt = text.lastIndexOf(">");
    var spec = lt !== -1 && gt > lt ? text.slice(lt + 1, gt).trim() : text;
    var parsed = _parse(spec);
    if (parsed.ok) out.push(parsed.address);
  });
  return out;
}

function _everyDisplayedAuthorIsMeasured(data, text) {
  var decoded = _decodedFrom(data);
  if (decoded === null) return;
  var measured = _measuredAuthors(decoded);
  if (measured === null) return;
  if (!PLAIN_HEADER_RE.test(text) || NOT_PLAIN_RE.test(text)) return;
  _mailboxesOfPlainHeader(text).forEach(function (mailboxAddress) {
    holds("author binding: every mailbox a plain From header names is one the binding measured",
      measured.indexOf(mailboxAddress) !== -1,
      { header: text, decoded: decoded, displayed: mailboxAddress, measured: measured });
  });
}

// ---- permittedAuthors and permittedAuthor ----------------------------------

function _identityFixture(text) {
  var lines = text.split("\n").map(function (line) { return line.replace(/\r$/, ""); });
  var own = lines[0];
  var rows = [];
  var operators = [];
  var refusedLocalParts = [];
  lines.slice(1).forEach(function (line) {
    if (line.charAt(0) === OPERATOR_PREFIX) {
      var op = _parse(line.slice(1));
      if (op.ok) operators.push(op.address);
      return;
    }
    if (line.charAt(0) === REFUSED_PREFIX) {
      refusedLocalParts.push(line.slice(1));
      return;
    }
    rows.push({ address: line, isCatchAll: line.charAt(0) === CATCH_ALL_PREFIX });
  });

  var ownParsed = _parse(own);
  var store = {
    aliases: {
      list: function (query) {
        holds("permittedAuthors asks for the aliases of the account's canonical address",
          ownParsed.ok && query && query.destination === ownParsed.address, query);
        return rows;
      },
    },
    accounts: {
      get: function (canonicalAddress) {
        return { address: canonicalAddress, isAdmin: operators.indexOf(canonicalAddress) !== -1 };
      },
    },
  };
  return {
    lines:             lines,
    own:               own,
    ownParsed:         ownParsed,
    rows:              rows,
    operators:         operators,
    refusedLocalParts: refusedLocalParts,
    store:             store,
  };
}

function _taggedForm(parsed) {
  if (parsed.localPart.indexOf(address.TAG_SEPARATOR) !== -1) return null;
  var tagged = _parse(parsed.localPart + address.TAG_SEPARATOR + TAG_PROBE + "@" + parsed.domain);
  return tagged.ok ? tagged.written : null;
}

function _accountAuthors(fx) {
  var actor = { id: "fuzz-account", address: fx.own };
  var authors = neverThrows("blamepost.mail.listeners.permittedAuthors", function () {
    return listeners.permittedAuthors(fx.store, actor);
  });
  holds("permittedAuthors returns an array", Array.isArray(authors), authors);

  var granted = fx.ownParsed.ok ? [fx.ownParsed.address] : [];
  fx.rows.forEach(function (row) {
    if (row.isCatchAll) return;
    var parsed = _parse(row.address);
    if (parsed.ok) granted.push(parsed.address);
  });

  authors.forEach(function (author, i) {
    var parsed = _parse(author);
    holds("permittedAuthors: every address is canonical",
      parsed.ok && parsed.address === author, { author: author, parsed: parsed });
    holds("permittedAuthors: no address appears twice", authors.indexOf(author) === i, authors);
    holds("permittedAuthors: every address is the account's own or a non-catch-all alias",
      granted.indexOf(author) !== -1, { author: author, granted: granted });
  });
  if (fx.ownParsed.ok) {
    holds("permittedAuthors: the account's own address comes first",
      authors[0] === fx.ownParsed.address, authors);
  } else {
    holds("permittedAuthors: an account address that does not parse permits nothing",
      authors.length === 0, authors);
  }

  fx.lines.forEach(function (line) {
    var decision = neverThrows("blamepost.mail.listeners.permittedAuthor", function () {
      return listeners.permittedAuthor(fx.store, actor, line);
    });
    var parsed = _parse(line);
    holds("permittedAuthor agrees with permittedAuthors for an account",
      decision === (parsed.ok && authors.indexOf(parsed.address) !== -1),
      { candidate: line, decision: decision, authors: authors });
    if (!parsed.ok) return;
    var tagged = _taggedForm(parsed);
    if (tagged === null) return;
    holds("permittedAuthor: a plus tag does not change an account's answer",
      listeners.permittedAuthor(fx.store, actor, tagged) === decision,
      { candidate: line, tagged: tagged, decision: decision });
  });
}

function _credentialScope(fx) {
  var scopeDomain = fx.ownParsed.ok ? fx.ownParsed.domain : "example.com";
  var actor = {
    id:      "fuzz-credential",
    address: null,
    sendingCredential: {
      id:                "fuzz-credential",
      domain:            scopeDomain,
      refusedLocalParts: fx.refusedLocalParts,
    },
  };
  fx.lines.forEach(function (line) {
    var decision = neverThrows("blamepost.mail.listeners.permittedAuthor", function () {
      return listeners.permittedAuthor(fx.store, actor, line);
    });
    holds("permittedAuthor returns a boolean", decision === true || decision === false, decision);
    var parsed = _parse(line);
    var inside = parsed.ok && parsed.domain === scopeDomain &&
      fx.refusedLocalParts.indexOf(parsed.localPart) === -1 &&
      fx.operators.indexOf(parsed.address) === -1;
    holds("permittedAuthor: a sending credential writes exactly the addresses inside its scope",
      decision === inside,
      { candidate: line, parsed: parsed, scope: actor.sendingCredential, operators: fx.operators });
    if (!parsed.ok) return;
    var tagged = _taggedForm(parsed);
    if (tagged === null) return;
    holds("permittedAuthor: a plus tag does not move an address across a credential's scope",
      listeners.permittedAuthor(fx.store, actor, tagged) === decision,
      { candidate: line, tagged: tagged, decision: decision });
  });
}

module.exports.fuzz = function (data) {
  var text = data.toString("utf8");

  _foldIsIdempotent(text);
  _addressReadsBackAsItself(text);
  _domainReadsBackAsItself(text);

  var entries = _entries(text);
  entries.forEach(function (entry) {
    var cut = _addressOfEntry(entry);
    _addressReadsBackAsItself(cut);
  });

  _everyDisplayedAuthorIsMeasured(data, text);

  var fx = _identityFixture(text);
  _accountAuthors(fx);
  _credentialScope(fx);
};

// The readers above, named for `fuzz/reach.js`, which counts the seeds
// that arrive at each one.
module.exports.targets = function () {
  return [
    { name: "blamepost.store.address.parse", of: address, call: "parse" },
    { name: "blamepost.store.address.parseDomain", of: address, call: "parseDomain" },
    { name: "blamepost.store.address.canonical", of: address, call: "canonical" },
    { name: "blamepost.store.address.canonicalDomain", of: address, call: "canonicalDomain" },
    { name: "blamepost.store.address.fold", of: address, call: "fold" },
    { name: "blamepost.mail.compose.splitAddressHeader", of: compose, call: "splitAddressHeader" },
    { name: "blamepost.mail.compose.angleAddressCount", of: compose, call: "angleAddressCount" },
    { name: "blamepost.mail.compose.normalizeAddress", of: compose, call: "normalizeAddress" },
    { name: "blamepost.mail.listeners.permittedAuthors", of: listeners, call: "permittedAuthors" },
    { name: "blamepost.mail.listeners.permittedAuthor", of: listeners, call: "permittedAuthor" },
    { name: "b.safeMime.parse", of: b.safeMime, call: "parse" },
  ];
};
