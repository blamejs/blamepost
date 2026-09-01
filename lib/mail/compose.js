// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.mail.compose
 * @title  Message composition
 *
 * @intro
 *   Build an RFC 5322 message, sign it, send it through the one
 *   outbound path, and file the copy the sender keeps. This is the gap
 *   the framework leaves: `b.mailStore` stores messages, `b.mail.send.
 *   deliver` moves them, and `b.mail.agent` dispatches reads, but
 *   nothing upstream turns a subject, a body and a list of recipients
 *   into wire bytes a receiver will accept. That belongs to the
 *   application, and it lives here.
 *
 *   ## What conformance costs
 *
 *   The header set is the easy half. Five things get skipped and then
 *   bite.
 *
 *   **A real Date.** RFC 5322 §3.3 wants a numeric zone offset. A
 *   `Date` rendered the HTTP way ends in `GMT`, which is the obsolete
 *   zone form; receivers accept it and spam filters notice.
 *
 *   **Encoded words.** RFC 2047 is what carries an accented name or a
 *   subject outside ASCII. An unencoded high byte in a header is a
 *   message some receivers reject outright.
 *
 *   **Transfer encoding chosen from the content.** Pure ASCII inside
 *   the line limit goes out as is; anything else is quoted-printable so
 *   no line exceeds the RFC 5322 §2.1.1 limit of 998 octets.
 *
 *   **Bcc that stays blind.** The addresses belong in the envelope and
 *   must not be in the emitted header block. They do belong in the copy
 *   the sender files, which is the one place they are supposed to be
 *   visible.
 *
 *   **Threading that survives a reply.** RFC 5322 §3.6.4 plus the RFC
 *   5256 walk: `In-Reply-To` names the parent, `References` carries the
 *   parent's chain with the parent appended. Get this wrong and every
 *   reply starts a new conversation in the recipient's client, which is
 *   the single most visible way a mail server looks broken.
 *
 *   ## Reading the message being answered
 *
 *   A reply and a forward start from bytes that arrived from anywhere,
 *   so they are parsed through `b.safeMime`, which is bounded on depth,
 *   part count and size and refuses the malformed shapes rather than
 *   walking them.
 *
 *   What survives that is still not straightforward. The parser hands
 *   back header values with RFC 2047 encoded words already decoded, and
 *   the decoder does not restore the quoting the encoding replaced, so
 *   a display name that decoded to `Doe, John` is indistinguishable
 *   from two addresses. A comma alone therefore cannot end an address
 *   here, and the angle brackets RFC 5322 §3.4 puts around the
 *   addr-spec are what the reader anchors on instead. Getting that
 *   wrong costs the reply in one direction and gains a recipient
 *   nobody chose in the other.
 *
 *   ## Structure
 *
 *   The MIME tree is chosen from the content rather than fixed:
 *   one body part when there is only text, `multipart/alternative`
 *   when text and HTML are both present, `multipart/related` around
 *   that when an inline part is referenced by content id, and
 *   `multipart/mixed` on the outside when there are attachments.
 *   A message with none of those is a single part with no boundary,
 *   which is what a plain note should look like on the wire.
 *
 *   ## Order of operations on send
 *
 *   Build, sign, send, file. Signing happens after the full header set
 *   exists, because a signature over a header that later changes is a
 *   signature that fails. Sending happens before filing so a message
 *   the outbound path refuses outright is never shown to the sender as
 *   sent. The `Bcc` header is added to the filed copy after signing,
 *   which leaves the signature intact because `Bcc` is not in the
 *   signed header set.
 */

var b = require("../vendor/blamejs");

// Two spellings of one mailbox are one mailbox, and `lib/store/address`
// is the single place that decides so: it folds the case of both halves
// and strips the RFC 5233 plus tag down to the mailbox that owns it.
// Every comparison of one address against another goes through it, or
// it disagrees with the routing layer about who a recipient is.
var storeAddress = require("../store/address");

// The rule names out of a guard verdict, read from the module that
// already words them for the identity layer's own refusals. One phrasing
// for why an address was refused, whether an operator meets it at the
// command line or an account holder meets it on a compose form.
var storeErrors = require("../store/errors");

// The one forward scan that answers where a message's header block
// ends. Composed rather than repeated, so this module and the surfaces
// that read a stored message cannot disagree about the same octets.
var headerBreak = require("./mailbox").headerBreak;

// The signing refusal code this module branches on when it records a
// message it had to send unsigned. Read from the module that throws it,
// so the two cannot drift apart. The handle in `opts.dkim` carries the
// behavior; the contract lives here. The submission listener reads the
// same constant for the same decision, which is what keeps one query
// able to answer for both surfaces that compose their own outbound mail.
var DKIM_CODES = require("./dkim").CODES;

// Read once, at load, so a missing export is a boot failure rather than
// a throw from inside the catch that records an unsigned send. That
// catch runs per message and must not raise: a throw there would kill
// the send whose signing refusal it was only trying to record, which
// turns a message that would have gone out unsigned into one that does
// not go out at all.
if (!DKIM_CODES || typeof DKIM_CODES.noActiveSelector !== "string") {
  throw new TypeError("blamepost.mail.compose: the dkim module must export CODES with " +
    "noActiveSelector, which is the code this module files an unsigned send under when the " +
    "domain has no key");
}

var BYTES = b.constants.BYTES;

// RFC 5322 §2.1.1: 998 octets is the hard line limit, 78 the one every
// composer targets so a reader with a narrow window sees whole lines.
var LINE_SOFT_LIMIT = 78;
var LINE_HARD_LIMIT = 998;

// How much of an RFC 2231 §3 continued parameter goes on one segment.
// Well under the fold width, so the folder has somewhere to break
// between the segments rather than inside one.
var EXTENDED_PARAM_SEGMENT = 60;

// RFC 2045 §6.7: a quoted-printable line carries at most 76 characters
// including the trailing soft break.
var QP_LINE_LIMIT = 76;

// RFC 2047 §2: an encoded word is at most 75 characters including the
// charset, the encoding marker and the delimiters.
var ENCODED_WORD_LIMIT = 75;

// The fixed cost of one base64 encoded word: charset, encoding marker
// and both delimiters.
var ENCODED_WORD_OVERHEAD = "=?UTF-8?B??=".length;

// Raw bytes that fit inside one encoded word, rounded down so the
// base64 output lands on a whole group of four characters.
var ENCODED_WORD_RAW_BYTES = Math.floor((ENCODED_WORD_LIMIT - ENCODED_WORD_OVERHEAD) / 4) * 3;

// RFC 5322 §3.6.4 puts no cap on References, but a chain that grows
// without bound eventually trips a receiver's header size limit. The
// usual answer, and the one clients implement, keeps the root of the
// conversation plus the most recent ancestors.
var MAX_REFERENCES = 20;

// Attachment ceiling for one message, counted across every part rather
// than one at a time: a per-part check passes for each of a hundred
// large files and the message they build is still unsendable. The
// listeners cap a whole message at 50 MiB on the wire, and base64
// expands by a third, so a body above this could not be sent even if it
// were built.
var MAX_ATTACHMENT_BYTES = BYTES.mib(35);


var RE_LEADING_REPLY = /^\s*(?:re|aw|sv|antw|vs|res|odp)\s*(?:\[\d+\])?\s*:\s*/i;
var RE_LEADING_FORWARD = /^\s*(?:fwd?|tr|wg|vs|doorst)\s*:\s*/i;
var RE_SPECIALS = /[()<>@,;:\\".[\]]/;

// RFC 5322 §3.6.8 field-name: printable US-ASCII with the colon
// excluded, which also excludes whitespace.
var RE_FIELD_NAME = /^[\x21-\x39\x3b-\x7e]+$/;

// RFC 2231 §7 attribute-char: the RFC 2045 token characters minus the
// three the extended-parameter grammar reserves for itself.
var RE_ATTRIBUTE_CHAR = /[A-Za-z0-9!#$&+^_`{}|~.-]/;

// RFC 5322 §3.4 group label: the display name and the colon that opens
// a group. It crosses neither a quote nor an at sign, so a quoted local
// part carrying a colon is not mistaken for one.
var RE_GROUP_LABEL = /^[^"<>@:]*:[ \t]*/;

// Headers written from the message description, plus the ones that
// describe the MIME tree this module built. A caller supplying one of
// these does not replace the composer's copy, it adds a second, and a
// second `Bcc` is the blind copy arriving on the wire.
var COMPOSED_HEADERS = Object.freeze({
  "from":                      true,
  "to":                        true,
  "cc":                        true,
  "bcc":                       true,
  "reply-to":                  true,
  "subject":                   true,
  "date":                      true,
  "message-id":                true,
  "in-reply-to":               true,
  "references":                true,
  "mime-version":              true,
  "content-type":              true,
  "content-transfer-encoding": true,
  "content-disposition":       true,
  "content-id":                true,
});

var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function _pad2(n) { return n < 10 ? "0" + n : String(n); }

// RFC 5322 §3.3 date-time in UTC. The numeric zone is the point: the
// obsolete alphabetic form is accepted by receivers and penalised by
// some of them.
function _rfc5322Date(value) {
  var d = value instanceof Date ? value : new Date(value === undefined ? Date.now() : value);
  if (isNaN(d.getTime())) {
    throw new TypeError("compose: date must be a Date or a millisecond timestamp");
  }
  return DAYS[d.getUTCDay()] + ", " + d.getUTCDate() + " " + MONTHS[d.getUTCMonth()] + " " +
    d.getUTCFullYear() + " " + _pad2(d.getUTCHours()) + ":" + _pad2(d.getUTCMinutes()) +
    ":" + _pad2(d.getUTCSeconds()) + " +0000";
}

// Printable US-ASCII, plus the three whitespace characters a message
// legitimately contains. CR and LF count as ASCII here because a body
// arrives already normalized to CRLF; a header value that reached this
// point has been through the injection check, where CR and LF are
// refused outright.
function _isAscii(text) {
  for (var i = 0; i < text.length; i += 1) {
    var c = text.charCodeAt(i);
    if (c >= 32 && c <= 126) continue;
    if (c === 9 || c === 10 || c === 13) continue;
    return false;
  }
  return true;
}

// Split a string into chunks of at most `maxBytes` UTF-8 bytes without
// cutting a codepoint in half. A word that splits mid character decodes
// to a replacement character at the receiver.
function _chunkByBytes(text, maxBytes) {
  var out = [];
  var current = "";
  var currentBytes = 0;
  for (var i = 0; i < text.length; i += 1) {
    var ch = text[i];
    // Surrogate pairs travel together.
    var code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      ch += text[i + 1];
      i += 1;
    }
    var size = Buffer.byteLength(ch, "utf8");
    if (currentBytes + size > maxBytes && current.length > 0) {
      out.push(current);
      current = "";
      currentBytes = 0;
    }
    current += ch;
    currentBytes += size;
  }
  if (current.length > 0) out.push(current);
  return out;
}

// RFC 2047 §4.2 encoded words, base64 flavour. Base64 rather than the
// quoted form because it has one length rule instead of a per character
// one, and a receiver that implements either implements both.
function _encodeWord(text) {
  return _chunkByBytes(text, ENCODED_WORD_RAW_BYTES).map(function (chunk) {
    return "=?UTF-8?B?" + Buffer.from(chunk, "utf8").toString("base64") + "?=";
  }).join("\r\n ");
}

// The longest run of characters with no folding whitespace in it,
// which is the width the folder cannot get below.
function _longestUnfoldableRun(text) {
  var longest = 0;
  var current = 0;
  for (var i = 0; i < text.length; i += 1) {
    var ch = text.charAt(i);
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") { current = 0; continue; }
    current += 1;
    if (current > longest) longest = current;
  }
  return longest;
}

// A header value goes out as written when it is ASCII and has a fold
// point wherever one is needed, and as RFC 2047 encoded words when it
// does not. Encoding is the answer to both reasons a value cannot go
// out raw: bytes outside ASCII, and a run of characters longer than a
// line with no whitespace to fold at. The encoded form is never wider
// than one encoded word, so folding it later cannot split it.
function _headerText(text) {
  var value = String(text);
  if (!_isAscii(value)) return _encodeWord(value);
  if (_longestUnfoldableRun(value) > LINE_SOFT_LIMIT) return _encodeWord(value);
  return value;
}

// Refuse a header value carrying CR, LF or NUL. This is the
// header-injection class (CWE-93): a newline inside a subject or a
// display name smuggles a second header, and `Bcc:` is the one an
// attacker reaches for. It throws rather than repairing the value,
// because there is no shape of message in which one belongs here.
function _assertHeaderSafe(value, label) {
  return b.safeBuffer.assertHeaderSafe(String(value), label, TypeError, "compose/bad-header");
}

// The backstop under the folder. A fold point is folding whitespace,
// so a run of characters longer than a line with none in it cannot be
// represented at all: wrapping inside it would change the value and
// truncating would ship a different one. Every unstructured value is
// encoded before it gets here for exactly that reason, which leaves
// this to catch what a future caller writes past the folder.
function _assertLineLimit(name, lines) {
  for (var i = 0; i < lines.length; i += 1) {
    var octets = Buffer.byteLength(lines[i], "utf8");
    if (octets > LINE_HARD_LIMIT) {
      throw new TypeError("compose: the " + name + " header carries a run of " + octets +
        " octets with no folding whitespace in it, and RFC 5322 §2.1.1 stops a line at " +
        LINE_HARD_LIMIT);
    }
  }
}

// Fold a header onto continuation lines at whitespace, targeting the
// RFC 5322 §2.2.3 preferred width. Folding never happens inside an
// encoded word because those are built below the limit already.
function _foldHeader(name, value) {
  var line = name + ": " + value;
  if (line.length <= LINE_SOFT_LIMIT && line.indexOf("\r\n") === -1) return line;
  var pieces = line.split(/\r\n\s*/);
  var out = [];
  for (var p = 0; p < pieces.length; p += 1) {
    var words = pieces[p].split(" ");
    var current = "";
    for (var i = 0; i < words.length; i += 1) {
      if (current.length === 0) {
        current = words[i];
        continue;
      }
      if (current.length + 1 + words[i].length > LINE_SOFT_LIMIT) {
        out.push(current);
        current = words[i];
        continue;
      }
      current += " " + words[i];
    }
    if (current.length > 0) out.push(current);
  }
  _assertLineLimit(name, out);
  return out.join("\r\n ");
}

/**
 * @primitive blamepost.mail.compose.normalizeAddress
 * @signature blamepost.mail.compose.normalizeAddress(input, label)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5322 §3.4 (name-addr and addr-spec)
 * @related   blamepost.mail.compose.splitAddressHeader
 *
 * One entry from an address header split into `{ name, address }`. The
 * addr-spec is what RFC 5322 §3.4 puts inside the angle brackets, so an
 * entry that uses them is cut there and everything before them is the
 * display name; an entry with none is an addr-spec on its own.
 *
 * Composed by the submission listener as well as by the composer,
 * because both have to answer the same question about the same entry:
 * which part of `"Alice Smith" <alice@example.com>` is the address. Two
 * answers to that would be a display name one of them reads as an
 * address.
 *
 * A string never throws here. Anything that is neither a string nor an
 * object carrying an `address` string is a caller mistake and throws,
 * which is why `label` names the field being read.
 */
function _normalizeAddress(input, label) {
  if (typeof input === "string") {
    var trimmed = input.trim();
    var lt = trimmed.lastIndexOf("<");
    var gt = trimmed.lastIndexOf(">");
    if (lt !== -1 && gt > lt) {
      return {
        name:    trimmed.slice(0, lt).trim().replace(/^"|"$/g, ""),
        address: trimmed.slice(lt + 1, gt).trim(),
      };
    }
    return { name: "", address: trimmed };
  }
  if (input && typeof input === "object" && typeof input.address === "string") {
    return { name: typeof input.name === "string" ? input.name : "", address: input.address.trim() };
  }
  throw new TypeError(label + ": expected an address string or { name, address } object");
}

// Why an address was refused, said in the vocabulary the identity layer
// refuses in. The reason names the stage and the kinds name the rule, so
// a person reading this on a compose form is told what is wrong with the
// address rather than which function said so.
function _refusalDetail(verdict) {
  var kinds = storeErrors.issueKinds(verdict.detail);
  return kinds === "" ? String(verdict.reason) : verdict.reason + ": " + kinds;
}

// One address out of a message description, screened and then DERIVED.
//
// The derivation is the point. A guard answers whether a string is a
// usable addr-spec and it answers about the SPELLING it was handed: the
// absolute form of RFC 1035 section 2.3.1 is refused, because RFC 5321
// section 4.1.2 writes a domain with no empty label at the end of one.
// Nothing at the wire reads a HEADER against that grammar, so a message
// carrying `From: <bob@EXAMPLE.NET.>` is delivered and filed like any
// other, and the reply to it is composed from the address it names.
// Measuring the bytes here refuses the account holder's own reply for a
// spelling somebody else chose, and says `address syntax` while doing
// it, which points them at their draft rather than at the header they
// are answering.
//
// So the value is folded through the one derivation this server decides
// mailbox identity with. It composes the same guard under the same
// profile, so nothing that was refused for what it IS becomes
// acceptable: a homograph label, an IP literal, a second at sign and a
// domain that is not one are all still refused. What it hands back is a
// name rather than a verdict about a spelling.
//
// The direction matters as much as the fold. What this returns is what
// goes into the header and into the envelope, so it has to be a form the
// NEXT server along accepts under the grammar this one refuses the other
// for: the root dot removed, the domain folded as RFC 4343 says it may
// be. The RFC 5233 tag stays attached, because it belongs to the mailbox
// the sender chose and not to this server, and a reply that dropped it
// would land outside the filter the recipient wrote for it.
function _assertAddress(addr, label) {
  // Screened before the verdict, so a refusal message quoting the input
  // cannot carry a line break into whatever reads the error.
  _assertHeaderSafe(addr.address, label);
  var derived = storeAddress.parse(addr.address);
  if (!derived.ok) {
    throw new TypeError(label + ": '" + addr.address + "' is not an address this server can " +
      "send to (" + _refusalDetail(derived) + ")");
  }
  if (addr.name) _assertHeaderSafe(addr.name, label + " display name");
  return { name: addr.name, address: derived.written };
}

// Whether two addresses name the same mailbox. The canonical form is
// the answer whenever both sides parse: `Alice@Example.com` and
// `alice+list@example.com` are the same mailbox as `alice@example.com`,
// and the routing layer already delivers all three to one account.
//
// An address this server cannot parse names no mailbox here, so there
// is no canonical form to compare and the raw folded strings are all
// there is. Falling back to them keeps a header nobody can read from
// matching everything rather than nothing.
function _sameMailbox(left, right) {
  var a = storeAddress.parse(left);
  var bb = storeAddress.parse(right);
  if (a.ok && bb.ok) return a.address === bb.address;
  return storeAddress.fold(left) === storeAddress.fold(right);
}

// The return path becomes `MAIL FROM` on the wire, so it is the one
// address a receiver acts on before it has read a header, and the one
// place where a spelling that is not a forward path is refused by
// whoever this server hands the envelope to. RFC 5321 §4.5.5 keeps the
// empty path for reports; everything else goes through the same
// derivation every header address goes through, because the outbound
// composer asks only that it be a non-empty string and a caller holding
// a bounce address read out of a stored message holds whatever spelling
// that message carried.
function _assertReturnPath(value) {
  var text = String(value);
  if (text.length === 0) return text;
  _assertHeaderSafe(text, "compose.build: envelopeFrom");
  var derived = storeAddress.parse(text);
  if (!derived.ok) {
    throw new TypeError("compose.build: envelopeFrom '" + text + "' is not an address a " +
      "receiver can return mail to (" + _refusalDetail(derived) + ")");
  }
  return derived.written;
}

// A caller-supplied header name. Bad input throws here rather than
// producing a header line a receiver cannot parse or a second copy of
// one the composer already wrote.
function _assertHeaderName(name) {
  _assertHeaderSafe(name, "compose.build: header name");
  if (!RE_FIELD_NAME.test(name)) {
    throw new TypeError("compose.build: header name '" + String(name).slice(0, 40) +
      "' is not an RFC 5322 field name (printable US-ASCII, no colon, no whitespace)");
  }
  if (COMPOSED_HEADERS[name.toLowerCase()] === true) {
    throw new TypeError("compose.build: '" + name + "' is written from the message " +
      "description, so supplying it here emits a second copy of it. Set the matching field " +
      "on the message instead.");
  }
  return name;
}

function _formatAddress(addr) {
  if (!addr.name) return addr.address;
  var name = addr.name;
  if (!_isAscii(name)) return _encodeWord(name) + " <" + addr.address + ">";
  // RFC 5322 §3.2.4: a display name carrying a special goes inside a
  // quoted string, and the quote and the backslash inside it are
  // escaped, or the name ends the string early and everything after it
  // reads as address syntax.
  if (RE_SPECIALS.test(name)) {
    return b.safeBuffer.quoteString(name) + " <" + addr.address + ">";
  }
  return name + " <" + addr.address + ">";
}

function _normalizeList(value, label) {
  if (value === undefined || value === null) return [];
  var raw = Array.isArray(value) ? value : [value];
  var out = [];
  for (var i = 0; i < raw.length; i += 1) {
    if (raw[i] === undefined || raw[i] === null || raw[i] === "") continue;
    out.push(_assertAddress(_normalizeAddress(raw[i], label + "[" + i + "]"), label + "[" + i + "]"));
  }
  return out;
}

function _formatAddressList(list) {
  return list.map(_formatAddress).join(", ");
}

function _normalizeBody(text) {
  return String(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
}

function _needsQuotedPrintable(text) {
  if (!_isAscii(text)) return true;
  var lines = text.split("\r\n");
  for (var i = 0; i < lines.length; i += 1) {
    if (lines[i].length > LINE_SOFT_LIMIT) return true;
    // A line that begins with "From " is rewritten by mbox style stores
    // on the way in, and one that begins with a period is what SMTP
    // dot-stuffing works around. Encoding the first character leaves
    // neither anything to rewrite.
    if (lines[i].indexOf("From ") === 0) return true;
    if (lines[i].charAt(0) === ".") return true;
    // Whitespace at the end of a line is invisible and does not
    // survive: transports trim it, and RFC 6376 §3.4.2 relaxed body
    // canonicalization trims it before a DKIM signature is computed, so
    // a body signed one way and read another fails verification for a
    // difference nobody can see. Encoding makes it a byte again.
    if (/[ \t]$/.test(lines[i])) return true;
  }
  return false;
}

var QP_SAFE = (function () {
  var table = [];
  for (var i = 0; i < 256; i += 1) {
    table[i] = (i >= 33 && i <= 126 && i !== 61);
  }
  return table;
}());

// Rewrite a space or tab sitting at the end of an encoded line as its
// escape. RFC 2045 §6.7 rule 3 forbids it there, and every reason is
// practical: a transport that trims trailing whitespace deletes it, and
// the reader gets two words run together with no sign anything happened.
function _escapeTrailingHspace(encoded, trailing) {
  if (!trailing || encoded.length === 0) return encoded;
  return encoded.slice(0, -1) + "=" + _pad2Hex(encoded.charCodeAt(encoded.length - 1));
}

// RFC 2045 §6.7 quoted-printable. Three rules decide the output. A hard
// line break in the source stays a hard break and everything else wraps
// with a soft break, so no output line exceeds 76 characters. A space
// or tab travels literally only while another character follows it on
// the same encoded line. And the first character of a line reading
// `From ` or beginning with a period is encoded, because an mbox store
// rewrites the first and a transport dot-stuffs the second, and an
// encoded first character leaves neither anything to rewrite.
function _quotedPrintable(text) {
  var lines = text.split("\r\n");
  var out = [];
  for (var i = 0; i < lines.length; i += 1) {
    var bytes = Buffer.from(lines[i], "utf8");
    var protectFirst = lines[i].indexOf("From ") === 0 || lines[i].charAt(0) === ".";
    var encoded = "";
    var trailingHspace = false;
    for (var j = 0; j < bytes.length; j += 1) {
      var byte = bytes[j];
      var hspace = (byte === 32 || byte === 9);
      var literal = (hspace || QP_SAFE[byte]) && !(j === 0 && protectFirst);
      var piece = literal ? String.fromCharCode(byte) : "=" + _pad2Hex(byte);
      // A literal space or tab is budgeted at the width of its escape,
      // so the two characters it would grow by on becoming the last of
      // a line are already reserved when the wrap point is chosen.
      var cost = (literal && hspace) ? 3 : piece.length;
      if (encoded.length + cost > QP_LINE_LIMIT - 1) {
        out.push(_escapeTrailingHspace(encoded, trailingHspace) + "=");
        encoded = "";
      }
      encoded += piece;
      // Reassigned on every byte, so the line the wrap above just
      // closed carries the flag it was closed with and the new line
      // starts from this byte.
      trailingHspace = literal && hspace;
    }
    out.push(_escapeTrailingHspace(encoded, trailingHspace));
  }
  return out.join("\r\n");
}

// RFC 2231 §4 carries a parameter value outside ASCII as
// `name*=charset'language'percent-encoded`; emitting the raw bytes
// instead is what a receiver rejects. §3 splits one too long for a line
// into `name*0*`, `name*1*` and so on, with the charset prefix on the
// first segment only. A percent escape is three characters standing for
// one byte, so a segment boundary is chosen between escapes and never
// inside one. Returns the parameters as a list, because a continued one
// is several and each needs its own fold point.
function _extendedParam(name, value) {
  var bytes = Buffer.from(value, "utf8");
  var segments = [];
  var current = "";
  for (var i = 0; i < bytes.length; i += 1) {
    var ch = String.fromCharCode(bytes[i]);
    var piece = RE_ATTRIBUTE_CHAR.test(ch) ? ch : "%" + _pad2Hex(bytes[i]);
    if (current.length + piece.length > EXTENDED_PARAM_SEGMENT && current.length > 0) {
      segments.push(current);
      current = "";
    }
    current += piece;
  }
  segments.push(current);
  if (segments.length === 1) return [name + "*=UTF-8''" + segments[0]];
  return segments.map(function (segment, index) {
    return name + "*" + index + "*=" + (index === 0 ? "UTF-8''" : "") + segment;
  });
}

// What a receiver implementing neither RFC 2231 nor anything else still
// has to show for a name outside ASCII.
function _asciiFallbackName(filename) {
  var reduced = String(filename).replace(/[^\x20-\x7e]/g, "_").trim();
  return reduced.length > 0 ? reduced : "attachment";
}

function _pad2Hex(byte) {
  var hex = byte.toString(16).toUpperCase();
  return hex.length === 1 ? "0" + hex : hex;
}

function _base64Wrap(buf) {
  var text = buf.toString("base64");
  var lines = [];
  for (var i = 0; i < text.length; i += QP_LINE_LIMIT) lines.push(text.slice(i, i + QP_LINE_LIMIT));
  return lines.join("\r\n");
}

function _boundary(label) {
  return "=_blamepost_" + label + "_" + b.crypto.generateToken(12);
}

// Which domain an address belongs to, read through the one derivation
// that decides it. Two things downstream are keyed on the answer: the
// signer this hands the name to, and the Message-ID built around it,
// which is published with the message and is the identifier a reply and
// a thread are matched on for as long as the message exists. Splitting
// the address by hand here would answer with the spelling the address
// carried, so an absolute form would put an empty label inside a
// Message-ID nothing can take back.
//
// An empty string for a name that cannot be one, which is what the two
// callers already treat as "there is no domain to act on".
function _domainOf(value) {
  var parsed = storeAddress.parse(value);
  return parsed.ok ? parsed.domain : "";
}

function _stripPrefix(subject, pattern) {
  var value = String(subject || "");
  var previous;
  do {
    previous = value;
    value = value.replace(pattern, "");
  } while (value !== previous);
  return value.trim();
}

// Trim a chain to the cap. The root stays so the conversation is still
// anchored, and the most recent ancestors stay so the immediate
// position is still resolvable. Applied where the header is written,
// not where a chain is derived, so every caller inherits the bound.
function _boundReferences(chain) {
  if (chain.length <= MAX_REFERENCES) return chain;
  return [chain[0]].concat(chain.slice(chain.length - (MAX_REFERENCES - 1)));
}

// RFC 5322 §3.6.4 plus the RFC 5256 threading walk: the reply carries
// the parent's References with the parent's Message-Id appended. When
// the parent had none, the parent alone is the chain.
function _buildReferences(parentReferences, parentMessageId) {
  var chain = [];
  (parentReferences || []).forEach(function (id) {
    if (typeof id === "string" && id.length > 0 && chain.indexOf(id) === -1) chain.push(id);
  });
  if (parentMessageId && chain.indexOf(parentMessageId) === -1) chain.push(parentMessageId);
  return _boundReferences(chain);
}

// RFC 5322 §3.4 group syntax, taken off one piece of an address header.
//
// The comma split below has already separated a group's members, so
// what is left on a piece is the group's own label at the front and its
// terminating semicolon at the end. An empty group names nobody, which
// is the whole reason bulk mail writes `undisclosed-recipients:;` into
// `To`, so it contributes no address rather than one nothing can
// deliver to.
function _stripGroupSyntax(piece) {
  var text = piece.trim().replace(/;\s*$/, "");
  // The label is stripped only where an angle address cannot be holding
  // the colon, and the pattern crosses neither a quote nor an at sign,
  // so a quoted local part carrying a colon is left alone.
  if (text.indexOf("<") === -1) text = text.replace(RE_GROUP_LABEL, "");
  return text.trim();
}

/**
 * @primitive blamepost.mail.compose.splitAddressHeader
 * @signature blamepost.mail.compose.splitAddressHeader(raw)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5322 §3.4 (address), RFC 5322 §3.2.1 (quoted-pair), RFC 6854 (group syntax in From)
 * @related   blamepost.mail.compose.reply, blamepost.mail.listeners.create
 *
 * One address header value read into the addresses it names. Returns an
 * array of strings, each still carrying whatever display name was
 * written beside it, and an empty array for a header that names nobody.
 *
 * A display name may hold the separator, so a list is not a list of
 * whatever a comma separates: `"Doe, John" <john@example.net>` is one
 * address and splitting on the comma turns it into two, the first of
 * which is a fragment of somebody's name being carried as an address.
 * Quoting makes that case readable, and the MIME parser takes the
 * quoting away: it hands back header values with RFC 2047 encoded words
 * already decoded, and the decoder does not restore what the encoding
 * replaced. `=?UTF-8?B?RG9lLCBKb2hu?=` arrives as `Doe, John` with
 * nothing left to say it is one token.
 *
 * So a comma alone cannot end an address here. RFC 5322 §3.4 puts the
 * addr-spec inside the angle brackets, which is the part the decoder
 * cannot have invented: in a header that uses them, a piece carrying
 * none is decoded display text and is joined back onto the piece it was
 * cut from. That keeps a reply to `Doe, John` going to John, it keeps
 * an address planted in a display name out of the recipient list of a
 * reply that quotes the conversation back, and it keeps the same
 * address out of the set the submission listener measures an author
 * against.
 *
 * A header with no angle brackets anywhere is a plain list of
 * addresses, where the comma is the only separator there is.
 *
 * One reader for both jobs on purpose. The composer uses it to decide
 * who a reply goes to and the submission listener uses it to decide
 * whose name is on a message it is about to sign, and two readers would
 * be two answers to the question of how many addresses a header names,
 * which is the question an address hidden in a display name is asked to
 * produce different answers to.
 *
 * @example
 *   blamepost.mail.compose.splitAddressHeader("\"Doe, John\" <j@example.net>, a@example.com");
 *   // ["\"Doe, John\" <j@example.net>", "a@example.com"]
 */
function splitAddressHeader(raw) {
  if (typeof raw !== "string" || raw.trim().length === 0) return [];
  var pieces = [];
  var current = "";
  var inQuotes = false;
  var inAngle = false;
  var escaped = false;
  for (var i = 0; i < raw.length; i += 1) {
    var ch = raw[i];
    if (escaped) { escaped = false; current += ch; continue; }
    // RFC 5322 §3.2.1 quoted-pair. A backslash escapes the next
    // character inside a quoted string and nowhere else, so a name
    // ending in a literal backslash still ends where its closing quote
    // says it does. Reading that quote as escaped leaves the rest of
    // the header inside a string that never closes, and every address
    // after it disappears.
    if (inQuotes && ch === "\\") { escaped = true; current += ch; continue; }
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (!inQuotes && ch === "<") {
      inAngle = true;
    } else if (!inQuotes && ch === ">") {
      inAngle = false;
    } else if (ch === "," && !inQuotes && !inAngle) {
      pieces.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  pieces.push(current);

  var out = [];
  if (raw.indexOf("<") === -1) {
    pieces.forEach(function (piece) {
      var text = _stripGroupSyntax(piece);
      if (text.length > 0) out.push(text);
    });
    return out;
  }

  var pending = null;
  for (var p = 0; p < pieces.length; p += 1) {
    var piece = pending === null ? pieces[p] : pending + "," + pieces[p];
    if (piece.indexOf("<") === -1) { pending = piece; continue; }
    out.push(_stripGroupSyntax(piece));
    pending = null;
  }
  // Whatever trails the last angle address is a plain address in its
  // own right, and it is kept: the guard on the way into the message is
  // what decides whether it is one.
  if (pending !== null) {
    var trailing = _stripGroupSyntax(pending);
    if (trailing.length > 0) out.push(trailing);
  }
  return out.filter(function (piece) { return piece.length > 0; });
}

function _parseReferenceList(raw) {
  if (typeof raw !== "string" || raw.length === 0) return [];
  var out = [];
  var re = /<[^<>\s]+>/g;
  var match = re.exec(raw);
  while (match !== null) {
    out.push(match[0]);
    match = re.exec(raw);
  }
  return out;
}

/**
 * @primitive blamepost.mail.compose.create
 * @signature blamepost.mail.compose.create(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5322, RFC 2045, RFC 2046, RFC 2047, RFC 5256 (threading)
 *
 * Build the composition handle. Returns `{ build, send, reply,
 * forward }`.
 *
 * `build` produces wire bytes and does nothing else, so a caller can
 * inspect or test a message without sending it. `send` builds, signs,
 * hands the envelope to the outbound path and files the sender's copy.
 * `reply` and `forward` derive a new message from the raw bytes of an
 * existing one, carrying the threading headers and the quoted body,
 * then send it the same way.
 *
 * The delivery handle is required because there is exactly one
 * outbound path and this module is not an exception to it. A running
 * server passes `blamepost.mail.listeners.relay`, which is that handle
 * with the recipients this server hosts routed to mailboxes here, so a
 * message between two accounts on one server does not leave the
 * building. A handle with no identity store behind it treats every
 * recipient as remote, which is the right answer when there is nothing
 * to ask.
 *
 * @opts
 *   delivery:  object,   // required; blamepost.mail.listeners.relay, or the raw delivery handle
 *   hostname:  string,   // required; the right-hand side of generated Message-Ids
 *   dkim:      object,   // optional; the blamepost.mail.dkim handle
 *   mailStore: object,   // optional; where the sender's copy is filed
 *   sentFolder: string,  // folder for the filed copy; default "Sent"
 *
 * @example
 *   var compose = blamepost.mail.compose.create({
 *     delivery: delivery,
 *     hostname: "mx.example.com",
 *     dkim:     dkim,
 *   });
 *   var built = compose.build({
 *     from:    "alice@example.com",
 *     to:      ["bob@example.net"],
 *     subject: "Lunch",
 *     text:    "One o'clock?",
 *   });
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.mail.compose.create: opts object is required");
  }
  if (!opts.delivery || typeof opts.delivery.send !== "function") {
    throw new TypeError("blamepost.mail.compose.create: opts.delivery is required and must " +
      "expose send(envelope). Every outbound path in this server goes through the one " +
      "delivery handle so the MTA-STS, DANE and REQUIRETLS policy runs once. A running " +
      "server passes blamepost.mail.listeners.relay, which is that handle with the " +
      "recipients this server hosts routed to mailboxes here.");
  }
  if (typeof opts.hostname !== "string" || opts.hostname.length === 0) {
    throw new TypeError("blamepost.mail.compose.create: opts.hostname is required " +
      "(it is the right-hand side of a generated Message-Id)");
  }
  if (opts.dkim !== undefined && opts.dkim !== null && typeof opts.dkim.sign !== "function") {
    throw new TypeError("blamepost.mail.compose.create: opts.dkim must expose sign(domain, bytes)");
  }
  if (opts.mailStore !== undefined && opts.mailStore !== null &&
      typeof opts.mailStore.appendMessage !== "function") {
    throw new TypeError("blamepost.mail.compose.create: opts.mailStore must expose appendMessage");
  }

  var delivery = opts.delivery;
  var hostname = opts.hostname;
  var dkim = opts.dkim || null;
  var mailStore = opts.mailStore || null;
  var sentFolder = opts.sentFolder || "Sent";

  // A message that left without a signature is a delivery decision an
  // operator has to be able to see as it happens, beside the audit row
  // that keeps it. The row is what a trail is queried for later; the
  // line is what is already on the screen when somebody is watching.
  var log = b.log.boot("mail.compose");

  function _newMessageId(fromAddress) {
    var domain = _domainOf(fromAddress) || hostname;
    var id = "<" + b.crypto.generateToken(16) + "@" + domain + ">";
    return b.guardMessageId.validate(id);
  }

  function _validateAttachment(att, index) {
    if (!att || typeof att !== "object") {
      throw new TypeError("compose: attachments[" + index + "] must be an object");
    }
    if (typeof att.filename !== "string" || att.filename.length === 0) {
      throw new TypeError("compose: attachments[" + index + "].filename is required");
    }
    // The name enters a MIME parameter, never a path this server opens,
    // so the screening that earns its place is what stops a header from
    // being forged and what stops a receiver's reader from being
    // misled: no CR, LF or NUL, no path, no reserved device name, no
    // direction override, no null-byte truncation. The strict profile
    // adds the rules that belong to writing a file rather than naming
    // one, and refusing `backup.tar.gz`, `firmware.bin` or a name with
    // an accent in it is the server losing an account holder's
    // attachment for a threat that is not on this path.
    _assertHeaderSafe(att.filename, "compose: attachments[" + index + "].filename");
    var verdict = b.guardFilename.validate(att.filename, { profile: "balanced" });
    if (!verdict.ok) {
      throw new TypeError("compose: attachments[" + index + "].filename refused by " +
        "b.guardFilename (" + (verdict.issues && verdict.issues[0] && verdict.issues[0].kind) + ")");
    }
    if (att.content === undefined || att.content === null) {
      throw new TypeError("compose: attachments[" + index + "].content is required");
    }
    if (att.contentType !== undefined) _assertHeaderSafe(att.contentType, "attachment content type");
    if (att.cid !== undefined) {
      if (typeof att.cid !== "string" || /[<>\s]/.test(att.cid)) {
        throw new TypeError("compose: attachments[" + index + "].cid must be a token with no " +
          "angle brackets or whitespace; the brackets are added when the header is written");
      }
    }
    var content = Buffer.isBuffer(att.content) ? att.content : Buffer.from(String(att.content), "utf8");
    if (content.length > MAX_ATTACHMENT_BYTES) {
      throw new TypeError("compose: attachments[" + index + "] is " + content.length +
        " bytes, above the " + MAX_ATTACHMENT_BYTES + " byte ceiling one message can carry " +
        "once base64 expansion is counted");
    }
    return {
      filename:    att.filename,
      content:     content,
      contentType: att.contentType || "application/octet-stream",
      disposition: att.contentDisposition || (att.cid ? "inline" : "attachment"),
      cid:         att.cid || null,
    };
  }

  function _textPart(contentType, body) {
    var normalized = _normalizeBody(body);
    var qp = _needsQuotedPrintable(normalized);
    return {
      mediaType: contentType,
      headers: [
        _foldHeader("Content-Type", contentType + "; charset=utf-8"),
        _foldHeader("Content-Transfer-Encoding", qp ? "quoted-printable" : "7bit"),
      ],
      body: qp ? _quotedPrintable(normalized) : normalized,
    };
  }

  function _attachmentPart(att) {
    var ascii = _isAscii(att.filename);
    var shown = b.safeBuffer.quoteString(ascii ? att.filename : _asciiFallbackName(att.filename));
    var dispParams = ["filename=" + shown];
    if (!ascii) dispParams = dispParams.concat(_extendedParam("filename", att.filename));
    var headers = [
      _foldHeader("Content-Type", att.contentType + "; name=" + shown),
      _foldHeader("Content-Transfer-Encoding", "base64"),
      _foldHeader("Content-Disposition", att.disposition + "; " + dispParams.join("; ")),
    ];
    if (att.cid) headers.push(_foldHeader("Content-ID", "<" + att.cid + ">"));
    return { mediaType: att.contentType, headers: headers, body: _base64Wrap(att.content) };
  }

  function _multipart(subtype, parts, extraParams) {
    var boundary = _boundary(subtype);
    var lines = [];
    for (var i = 0; i < parts.length; i += 1) {
      lines.push("--" + boundary);
      lines.push(parts[i].headers.join("\r\n"));
      lines.push("");
      lines.push(parts[i].body);
    }
    lines.push("--" + boundary + "--");
    return {
      mediaType: "multipart/" + subtype,
      headers: [
        _foldHeader("Content-Type", "multipart/" + subtype + "; boundary=" +
          b.safeBuffer.quoteString(boundary) + (extraParams ? "; " + extraParams : "")),
      ],
      body: lines.join("\r\n"),
    };
  }

  // Choose the MIME tree from what the message actually carries. Every
  // extra level of nesting is a level a receiver's renderer can get
  // wrong, so none is added without content that needs it.
  function _buildTree(message, attachments) {
    var bodyParts = [];
    if (typeof message.text === "string" && message.text.length > 0) {
      bodyParts.push(_textPart("text/plain", message.text));
    }
    if (typeof message.html === "string" && message.html.length > 0) {
      bodyParts.push(_textPart("text/html", message.html));
    }
    if (bodyParts.length === 0) {
      throw new TypeError("compose: message needs a text or an html body");
    }
    var root = bodyParts.length === 1 ? bodyParts[0] : _multipart("alternative", bodyParts);

    var inline = attachments.filter(function (a) { return a.cid !== null; });
    var files = attachments.filter(function (a) { return a.cid === null; });

    if (inline.length > 0) {
      // RFC 2387: the alternative body and the parts its HTML
      // references by content id travel together as one related unit,
      // and §3.1's `type` parameter names the media type of the root
      // part so a reader knows which one to render first. It is read
      // off the root rather than assumed, because a message with an
      // html body and no plain one has a root that is not text/plain.
      root = _multipart("related", [root].concat(inline.map(_attachmentPart)),
        "type=" + b.safeBuffer.quoteString(root.mediaType));
    }
    if (files.length > 0) {
      root = _multipart("mixed", [root].concat(files.map(_attachmentPart)));
    }
    return root;
  }

  /**
   * @primitive blamepost.mail.compose.build
   * @signature compose.build(message)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 5322 §3, RFC 2045, RFC 2046, RFC 2047
   * @related   blamepost.mail.compose.create, blamepost.mail.compose.send
   *
   * Turn a message description into wire bytes. Returns
   * `{ rfc822, filed, messageId, envelopeFrom, recipients, headers }`.
   * `rfc822` is what goes on the wire and carries no `Bcc` header;
   * `filed` is the same message with the `Bcc` header restored, which
   * is the copy the sender keeps. `recipients` is the envelope list
   * including the blind copies.
   *
   * Every address is derived through the identity layer, the envelope
   * sender included, because that one becomes `MAIL FROM` on the wire.
   * What the header and the envelope carry is what the derivation
   * returns. So a message that arrived spelled with the absolute form
   * of a domain, or with a domain in another case, still answers, and
   * what leaves names the same mailbox in a form a receiver reads under
   * RFC 5321 §4.1.2. An address the derivation cannot read throws.
   * Every header value is refused if it carries CR,
   * LF or NUL, and every attachment filename goes through
   * `b.guardFilename` and then into a quoted MIME parameter. Bad input
   * throws here rather than producing a message a receiver will reject.
   *
   * `headers` adds headers the composer does not write itself. A name
   * it does write is refused rather than accepted, because supplying
   * one adds a second copy instead of replacing the first, and a second
   * `Bcc` is the blind copy arriving on the wire.
   *
   * @opts
   *   from:         string | object,     // required
   *   to:           array,               // required unless cc or bcc is present
   *   cc, bcc:      array,
   *   replyTo:      string | object,
   *   subject:      string,
   *   text, html:   string,              // at least one
   *   attachments:  array,               // { filename, content, contentType, cid }
   *   headers:      object,              // extra headers; names the composer writes are refused
   *   inReplyTo:    string,              // parent Message-Id, angle brackets included
   *   references:   array,               // the parent's chain, trimmed to the most recent 20
   *   date:         Date | number,
   *   messageId:    string,              // generated when omitted
   *   envelopeFrom: string,              // return path; defaults to From, empty for a report
   *
   * @example
   *   var built = compose.build({
   *     from: "alice@example.com", to: ["bob@example.net"],
   *     subject: "Lunch", text: "One o'clock?",
   *   });
   *   built.recipients;   // ["bob@example.net"]
   */
  function build(message) {
    if (!message || typeof message !== "object") {
      throw new TypeError("compose.build: message object is required");
    }
    var from = _assertAddress(_normalizeAddress(message.from, "compose.build: from"), "compose.build: from");
    var to = _normalizeList(message.to, "compose.build: to");
    var cc = _normalizeList(message.cc, "compose.build: cc");
    var bcc = _normalizeList(message.bcc, "compose.build: bcc");
    if (to.length === 0 && cc.length === 0 && bcc.length === 0) {
      throw new TypeError("compose.build: a message needs at least one recipient across " +
        "to, cc and bcc");
    }
    var replyTo = message.replyTo
      ? _assertAddress(_normalizeAddress(message.replyTo, "compose.build: replyTo"), "compose.build: replyTo")
      : null;

    var attachments = [];
    if (message.attachments !== undefined) {
      if (!Array.isArray(message.attachments)) {
        throw new TypeError("compose.build: message.attachments must be an array");
      }
      attachments = message.attachments.map(_validateAttachment);
      var carried = attachments.reduce(function (sum, att) { return sum + att.content.length; }, 0);
      if (carried > MAX_ATTACHMENT_BYTES) {
        throw new TypeError("compose.build: the attachments total " + carried + " bytes, above " +
          "the " + MAX_ATTACHMENT_BYTES + " byte ceiling one message can carry once base64 " +
          "expansion is counted");
      }
    }

    var messageId = message.messageId
      ? b.guardMessageId.validate(String(message.messageId))
      : _newMessageId(from.address);

    var inReplyTo = message.inReplyTo
      ? b.guardMessageId.validate(String(message.inReplyTo))
      : null;
    var references = [];
    if (message.references !== undefined) {
      if (!Array.isArray(message.references)) {
        throw new TypeError("compose.build: message.references must be an array of Message-Ids");
      }
      references = _boundReferences(message.references.map(function (id) {
        return b.guardMessageId.validate(String(id));
      }));
    }

    var tree = _buildTree(message, attachments);

    var headers = [];
    headers.push(_foldHeader("From", _formatAddress(from)));
    if (to.length > 0) headers.push(_foldHeader("To", _formatAddressList(to)));
    if (cc.length > 0) headers.push(_foldHeader("Cc", _formatAddressList(cc)));
    if (replyTo) headers.push(_foldHeader("Reply-To", _formatAddress(replyTo)));
    if (message.subject !== undefined && message.subject !== null && message.subject !== "") {
      _assertHeaderSafe(message.subject, "compose.build: subject");
      headers.push(_foldHeader("Subject", _headerText(message.subject)));
    }
    headers.push(_foldHeader("Date", _rfc5322Date(message.date)));
    headers.push(_foldHeader("Message-ID", messageId));
    if (inReplyTo) headers.push(_foldHeader("In-Reply-To", inReplyTo));
    if (references.length > 0) headers.push(_foldHeader("References", references.join(" ")));
    headers.push("MIME-Version: 1.0");
    if (message.headers && typeof message.headers === "object") {
      Object.keys(message.headers).forEach(function (name) {
        _assertHeaderName(name);
        _assertHeaderSafe(message.headers[name], "compose.build: header " + name);
        headers.push(_foldHeader(name, _headerText(message.headers[name])));
      });
    }
    tree.headers.forEach(function (line) { headers.push(line); });

    var headerBlock = headers.join("\r\n");
    var wire = headerBlock + "\r\n\r\n" + tree.body + "\r\n";

    var filed = wire;
    if (bcc.length > 0) {
      filed = headerBlock + "\r\n" + _foldHeader("Bcc", _formatAddressList(bcc)) +
        "\r\n\r\n" + tree.body + "\r\n";
    }

    var recipients = to.concat(cc).concat(bcc).map(function (a) { return a.address; });
    var envelopeFrom = message.envelopeFrom === undefined
      ? from.address
      : _assertReturnPath(message.envelopeFrom);

    return {
      rfc822:       Buffer.from(wire, "utf8"),
      filed:        Buffer.from(filed, "utf8"),
      messageId:    messageId,
      envelopeFrom: envelopeFrom,
      recipients:   recipients,
      headers:      headerBlock,
      from:         from,
      to:           to,
      cc:           cc,
      bcc:          bcc,
    };
  }

  // Insert a header immediately after the last header line of an
  // already built message. Used for the Bcc on the filed copy, which is
  // added after signing because Bcc is outside the signed header set.
  // The message stays in a buffer across the insertion. Routing it
  // through a string would rewrite every octet the decoder does not
  // recognize, and the filed copy is the account holder's own record of
  // what was sent: a body in a legacy charset would be readable in the
  // recipient's mailbox and damaged in the sender's.
  //
  // Where the header block ends is `headerBreak`'s answer. A message
  // this module built is CRLF throughout, so today the first empty line
  // is a CRLF one either way; the scan is composed anyway because the
  // insertion point has to stay correct for whatever a signer hands
  // back, and because one answer to this question in one place is the
  // whole reason there is a primitive for it.
  function _withHeader(rawBytes, headerLine) {
    var brk = headerBreak(rawBytes);
    if (brk === null) return rawBytes;
    return Buffer.concat([
      rawBytes.subarray(0, brk.at),
      Buffer.from("\r\n" + headerLine, "utf8"),
      rawBytes.subarray(brk.at),
    ]);
  }

  /**
   * @primitive blamepost.mail.compose.send
   * @signature compose.send(message, opts?)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 5322, RFC 6376 (signing), RFC 5321 (envelope)
   * @related   blamepost.mail.compose.build, blamepost.mail.delivery.send
   *
   * Build, sign, send and file. Signing runs when a DKIM handle is
   * wired and the From domain has an active selector; a signer that
   * refuses does not stop the message, because refusing to send an
   * account's own mail over a key problem is a worse outage than
   * sending it unsigned. The result's `signed` flag reports which of
   * the two happened.
   *
   * A message that goes out unsigned leaves an audit row, filed as a
   * failure and carrying the signer's refusal code, because the message
   * is now unattributable to its domain and that row is the only place
   * an operator finds out. The two causes are filed under two action
   * names, `blamepost.mail.compose.unsigned_no_key` for a domain still
   * waiting for its first pair and `blamepost.mail.compose.unsigned`
   * for everything else, because one is repaired by minting a pair and
   * the other by restoring one. The submission listener files the same
   * two causes the same way, so one query answers for both surfaces.
   *
   * The sender's copy is filed only after the outbound path accepts
   * the envelope, so a message that could not be handed over is never
   * shown as sent. A copy that cannot be written comes back as
   * `filed: null` rather than as a throw: by then the message has left,
   * and reporting it as a failure is how a caller ends up sending it
   * twice.
   *
   * @opts
   *   actor:  object,   // passed to the store when the copy is filed
   *   file:   boolean,  // set false to skip filing; default true
   *
   * @example
   *   var result = await compose.send({
   *     from: "alice@example.com", to: ["bob@example.net"],
   *     subject: "Lunch", text: "One o'clock?",
   *   }, { actor: session.actor });
   */
  async function send(message, sendOpts) {
    sendOpts = sendOpts || {};
    var built = build(message);
    var wire = built.rfc822;
    var signedDomain = _domainOf(built.from.address);
    var signed = false;
    if (dkim && signedDomain) {
      try {
        wire = await dkim.sign(signedDomain, wire);
        signed = true;
      } catch (err) {
        // The message still goes, because refusing to send an account's
        // own mail over a key problem is a worse outage than sending it
        // unsigned. But it leaves as mail receivers cannot attribute to
        // this domain, and the row that says so is the only place an
        // operator can find that out, so the row records a failure.
        // Filed as a success it would be invisible to
        // `b.audit.query` on outcome, which is the one question an
        // operator asks of an audit trail, and it would answer that
        // question with the opposite of the truth at the moment the
        // domain's DMARC policy starts sending failure reports.
        //
        // The cause goes in the action rather than the metadata.
        // `b.audit.query` filters on action, outcome and actor and takes
        // no metadata criteria, so a cause recorded in the metadata blob
        // is one an operator cannot filter on, and the two causes want
        // different answers. A domain with no selector is a setup state
        // that ends when setup ends, and the fix is one command.
        // Anything else keeps the original name: a key that will not
        // unseal is not that, and filing it as one would send an
        // operator to fix the wrong thing.
        //
        // This is the shape the submission listener files the same two
        // causes under, differing only in the module that wrote the row,
        // so one query answers for the browser and the wire together.
        var cause = err && err.code;
        b.audit.safeEmit({
          action: cause === DKIM_CODES.noActiveSelector
            ? "blamepost.mail.compose.unsigned_no_key"
            : "blamepost.mail.compose.unsigned",
          outcome:  "failure",
          metadata: {
            domain: signedDomain,
            cause:  cause || null,
            reason: (err && err.message) || String(err),
          },
        });
        log.error("mail from " + signedDomain + " is being sent without a DKIM " +
          "signature, so receivers cannot attribute it to that domain: " +
          ((err && err.message) || String(err)));
      }
    }

    var outcome = await delivery.send({
      from:       built.envelopeFrom,
      to:         built.recipients,
      rfc822:     wire,
      requireTls: message.requireTls,
    });

    var stored = null;
    if (mailStore && sendOpts.file !== false) {
      var copy = wire;
      if (built.bcc.length > 0) {
        copy = _withHeader(copy, _foldHeader("Bcc", _formatAddressList(built.bcc)));
      }
      try {
        stored = mailStore.appendMessage(sentFolder, copy, {
          actor: sendOpts.actor,
          flags: ["\\Seen"],
        });
      } catch (err) {
        // The message has left. Throwing here would report a send that
        // happened as a send that failed, and the caller's answer to
        // that is to try again, which sends it twice. The outcome is
        // returned with `filed` null instead, and the copy that could
        // not be written is recorded so it is a thing an operator can
        // find rather than a Sent folder quietly missing an entry.
        b.audit.safeEmit({
          action:   "blamepost.mail.compose.unfiled",
          outcome:  "failure",
          metadata: {
            folder:    sentFolder,
            messageId: built.messageId,
            reason:    (err && err.message) || String(err),
          },
        });
      }
    }

    return {
      messageId: built.messageId,
      signed:    signed,
      delivery:  outcome,
      filed:     stored,
    };
  }

  // Pull the parts of an existing message a reply or a forward needs.
  // The bytes come from the store and may have arrived from anywhere,
  // so parsing goes through b.safeMime, which is bounded on depth, part
  // count and size and refuses the malformed shapes rather than walking
  // into them.
  function _readOriginal(original, label) {
    var bytes = Buffer.isBuffer(original) ? original : Buffer.from(String(original || ""), "utf8");
    if (bytes.length === 0) {
      throw new TypeError(label + ": the original message bytes are required");
    }
    var tree = b.safeMime.parse(bytes);
    var text = b.safeMime.extractText(tree, { prefer: "plain" });
    var html = b.safeMime.extractText(tree, { prefer: "html" });
    return {
      bytes:      bytes,
      tree:       tree,
      messageId:  tree.headers.get("message-id") || null,
      references: _parseReferenceList(tree.headers.get("references")),
      subject:    tree.headers.get("subject") || "",
      from:       tree.headers.get("from") || "",
      to:         tree.headers.getAll ? (tree.headers.getAll("to") || []) : [],
      cc:         tree.headers.getAll ? (tree.headers.getAll("cc") || []) : [],
      replyTo:    tree.headers.get("reply-to") || "",
      date:       tree.headers.get("date") || "",
      // Both extractions fall back to whatever body the message has
      // when the one asked for is absent, so an html-only message
      // answers the plain request with its markup. Taken at face value
      // that markup ends up quoted inside the reply's own text/plain
      // part, which is a part whose whole contract is that it carries
      // no markup. Each is kept only when it is the type it claims.
      text:       text && text.contentType === "text/plain" ? text.body : "",
      html:       html && html.contentType === "text/html" ? html.body : "",
    };
  }

  // What a message with no text/plain part of its own contributes to a
  // plain-text quote. The markup comes off through the same sanitizer
  // the html quote runs, configured to keep no tags at all, and the
  // character references it leaves behind are resolved so the reader of
  // the reply sees an ampersand rather than the five characters that
  // spell one.
  function _plainRendering(html) {
    if (!html) return "";
    var stripped = b.guardHtml.sanitize(html, { profile: "strict", allowedTags: [] });
    return b.codepointClass.decodeMarkupEntities(stripped);
  }

  function _quoteText(original) {
    var who = original.from || "the sender";
    var when = original.date ? original.date : "an earlier message";
    var attribution = "On " + when + ", " + who + " wrote:";
    var source = original.text || _plainRendering(original.html);
    var quoted = _normalizeBody(source).split("\r\n").map(function (line) {
      return line.length === 0 ? ">" : "> " + line;
    }).join("\r\n");
    return attribution + "\r\n" + quoted;
  }

  // The quoted original is somebody else's markup about to travel
  // onward under this account's name and to be filed in this account's
  // mailbox. It is screened on the way into the reply rather than
  // trusted for having arrived, because the reply is the point at which
  // this server becomes the sender of it.
  function _quoteHtml(original) {
    if (!original.html) return "";
    return "<blockquote type=\"cite\">" +
      b.guardHtml.sanitize(original.html, { profile: "balanced" }) +
      "</blockquote>";
  }

  /**
   * @primitive blamepost.mail.compose.reply
   * @signature compose.reply(opts)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 5322 §3.6.4, RFC 5256 §5 (threading)
   * @related   blamepost.mail.compose.send, blamepost.mail.compose.forward
   *
   * Derive a reply from the raw bytes of the message being answered
   * and send it. The recipient is the original `Reply-To` when it is
   * present and the original `From` otherwise, which is the whole
   * point of that header. With `replyAll`, the original `To` and `Cc`
   * join the copy list minus the replying identity, so a reply to a
   * conversation does not silently drop half of it.
   *
   * Threading is the part that has to be right: `In-Reply-To` names
   * the parent and `References` carries the parent's chain with the
   * parent appended, so the receiver's client keeps the conversation
   * together rather than opening a new one.
   *
   * @opts
   *   original:  Buffer | string,   // required; the raw message being answered
   *   from:      string | object,   // required; the replying identity
   *   text, html: string,           // the new body
   *   replyAll:  boolean,           // copy the original recipients too
   *   quote:     boolean,           // include the quoted original; default true
   *   to, cc, bcc, attachments, headers, subject   // overrides
   *   actor:     object,            // passed through when the copy is filed
   *
   * @example
   *   await compose.reply({
   *     original: rawBytes,
   *     from:     "alice@example.com",
   *     text:     "One o'clock works.",
   *     replyAll: true,
   *   });
   */
  async function reply(replyOpts) {
    if (!replyOpts || typeof replyOpts !== "object") {
      throw new TypeError("compose.reply: opts object is required");
    }
    var original = _readOriginal(replyOpts.original, "compose.reply");
    var from = _assertAddress(_normalizeAddress(replyOpts.from, "compose.reply: from"), "compose.reply: from");
    var selfAddress = from.address;

    var to = replyOpts.to !== undefined
      ? replyOpts.to
      : splitAddressHeader(original.replyTo || original.from);
    var cc = replyOpts.cc;
    if (cc === undefined && replyOpts.replyAll === true) {
      cc = original.to.concat(original.cc)
        .reduce(function (acc, header) { return acc.concat(splitAddressHeader(header)); }, [])
        .filter(function (entry) {
          var addr = _normalizeAddress(entry, "compose.reply: cc").address;
          return !_sameMailbox(addr, selfAddress);
        });
    }

    var subject = replyOpts.subject !== undefined
      ? replyOpts.subject
      : "Re: " + _stripPrefix(original.subject, RE_LEADING_REPLY);

    var text = replyOpts.text || "";
    var html = replyOpts.html || "";
    if (replyOpts.quote !== false) {
      if (text || !html) text = (text ? text + "\r\n\r\n" : "") + _quoteText(original);
      if (html) html = html + _quoteHtml(original);
    }

    return await send({
      from:        from,
      to:          to,
      cc:          cc,
      bcc:         replyOpts.bcc,
      subject:     subject,
      text:        text,
      html:        html || undefined,
      attachments: replyOpts.attachments,
      headers:     replyOpts.headers,
      inReplyTo:   original.messageId,
      references:  _buildReferences(original.references, original.messageId),
      requireTls:  replyOpts.requireTls,
    }, { actor: replyOpts.actor, file: replyOpts.file });
  }

  /**
   * @primitive blamepost.mail.compose.forward
   * @signature compose.forward(opts)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 5322 §3.6.4, RFC 2046 §5.2.1 (message/rfc822)
   * @related   blamepost.mail.compose.reply
   *
   * Forward an existing message. The original travels as a
   * `message/rfc822` part rather than as quoted text, so the receiver
   * gets the real headers, the real attachments and a message their
   * client can open in place. The `References` chain is carried so the
   * forward stays attached to the conversation it came from, while
   * `In-Reply-To` is left off, because a forward answers nobody.
   *
   * @opts
   *   original:  Buffer | string,   // required; the raw message being forwarded
   *   from:      string | object,   // required
   *   to:        array,             // required
   *   text, html: string,           // an optional note above the forward
   *   cc, bcc, attachments, headers, subject   // overrides
   *   actor:     object,            // passed through when the copy is filed
   *
   * @example
   *   await compose.forward({
   *     original: rawBytes,
   *     from:     "alice@example.com",
   *     to:       ["carol@example.org"],
   *     text:     "Thought you should see this.",
   *   });
   */
  async function forward(forwardOpts) {
    if (!forwardOpts || typeof forwardOpts !== "object") {
      throw new TypeError("compose.forward: opts object is required");
    }
    var original = _readOriginal(forwardOpts.original, "compose.forward");
    var subject = forwardOpts.subject !== undefined
      ? forwardOpts.subject
      : "Fwd: " + _stripPrefix(original.subject, RE_LEADING_FORWARD);

    var note = forwardOpts.text || "";
    var intro = "Forwarded message\r\nFrom: " + (original.from || "") +
      "\r\nDate: " + (original.date || "") +
      "\r\nSubject: " + (original.subject || "");
    var text = note ? note + "\r\n\r\n" + intro : intro;

    var attachments = (forwardOpts.attachments || []).slice();
    attachments.push({
      filename:    _forwardFilename(original.subject),
      content:     original.bytes,
      contentType: "message/rfc822",
      contentDisposition: "attachment",
    });

    return await send({
      from:        forwardOpts.from,
      to:          forwardOpts.to,
      cc:          forwardOpts.cc,
      bcc:         forwardOpts.bcc,
      subject:     subject,
      text:        text,
      html:        forwardOpts.html,
      attachments: attachments,
      headers:     forwardOpts.headers,
      references:  _buildReferences(original.references, original.messageId),
      requireTls:  forwardOpts.requireTls,
    }, { actor: forwardOpts.actor, file: forwardOpts.file });
  }

  // A filename the receiver's client will show for the attached
  // original. Derived from the subject so it reads as something, and
  // reduced to characters that survive every filesystem the message
  // might be saved onto.
  function _forwardFilename(subject) {
    var base = String(subject || "message").replace(/[^A-Za-z0-9 ._]/g, "").trim();
    if (base.length === 0) base = "message";
    if (base.length > 60) base = base.slice(0, 60).trim();
    return base + ".eml";
  }

  return {
    build:   build,
    send:    send,
    reply:   reply,
    forward: forward,
  };
}

module.exports = {
  create: create,
  // One reader for an RFC 5322 address header and one for the entries
  // it yields, composed by the submission listener as well as by the
  // composer. A second pair would be a second answer to how many
  // addresses a header names and which part of one is the address,
  // which are the two questions a name with an address inside it is
  // written to produce different answers to.
  splitAddressHeader: splitAddressHeader,
  normalizeAddress:   _normalizeAddress,
};
