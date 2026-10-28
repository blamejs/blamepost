// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.mail.reports
 * @nav    DNS and domain authentication
 * @title  DMARC report ingest
 * @order  40
 *
 * @intro
 *   A DMARC report reaches this server as ordinary mail. Something has
 *   to decide that a message is a report, open whatever the reporter
 *   wrapped it in, say whether the report is evidence or a document a
 *   stranger composed, and hand the bytes to
 *   `blamepost.store.reports`, which owns every row. This module is
 *   that step and holds no rows of its own.
 *
 *   ## Recognition is by media type and structure, never by the name
 *
 *   RFC 7489 section 7.2.1.1 gives aggregate reports a filename
 *   convention: the receiver, the policy domain and the two ends of the
 *   window, joined by exclamation marks, with an extension naming the
 *   container. Reporters follow it loosely. Some send
 *   `application/octet-stream` for a gzip, some send a ZIP under a name
 *   ending `.gz`, and some send a name that follows no convention at
 *   all. So the name decides nothing here.
 *
 *   The media type selects which parts are worth looking at, and
 *   `b.fileType.detect` reads the leading bytes to decide what the part
 *   actually is. A part whose bytes are a gzip is opened as a gzip
 *   whatever it is called, and a name ending `.xml.gz` over bytes that
 *   are neither a container nor XML is passed over rather than believed.
 *   Reading the name instead would let whoever sent the message choose
 *   which decompressor runs, which is the first move in every archive
 *   parser incident there has been. The name is read once, screened, and
 *   put in the verdict so an operator can see which attachment a refusal
 *   was about.
 *
 *   A per-message failure report is recognized by structure: RFC 6591
 *   section 3.1 puts the report in a `message/feedback-report` part, and
 *   the presence of that part is what makes a message a forensic report.
 *
 *   ## Two things this module does that calling the parser would not
 *
 *   The framework's aggregate parser caps the bytes a gzip may expand
 *   to and does not cap the ratio it expands by, while the TLS-RPT
 *   parser beside it caps the compressed bytes, the decompressed bytes
 *   and the ratio. A report arrives from anyone who chooses to send one,
 *   so the missing bound is the one that matters: an eight-hundred-fold
 *   expansion that lands under the byte ceiling is accepted there and
 *   refused here. `b.safeDecompress` is composed with all three bounds
 *   and the parser is handed bytes that are already expanded, so the
 *   ratio holds whatever the layer below defaults to.
 *
 *   The same parser's comment says the framework ships no ZIP
 *   primitive. `b.archive.read.zip` does exist, and several large
 *   reporters send ZIP. Without it their reports arrive and produce
 *   nothing, and an absence in aggregate reporting reads exactly like a
 *   domain nobody is spoofing. Archives are opened in memory through
 *   `extractEntries`, under an entry cap, a per-entry byte cap and the
 *   same expansion cap the gzip path uses.
 *
 *   The bound on what a container may carry before any of it is expanded
 *   is spent where the two container paths are still one, so it does not
 *   depend on which container the sender chose. It was applied on the
 *   gzip path alone, which left the number an operator reads in
 *   `describe()` true of one container and not of the other.
 *
 *   ## A report is evidence only when the carrier was authenticated
 *
 *   A report is a document somebody composed and addressed here. Anyone
 *   who can send mail to the address in a `rua=` record can write a well
 *   formed one saying whatever they like, and a policy moved on that is
 *   a policy moved by the attacker it was meant to stop. So a report
 *   counts as evidence only when the message that carried it passed
 *   DMARC for the reporting organization's own domain, read from the
 *   `Authentication-Results` header this server's own inbound path
 *   wrote.
 *
 *   Three things make that reading narrow. Only a header whose
 *   authserv-id is this server's own is read, because every other one in
 *   the block was written by somebody else. Only the topmost such header
 *   is read, because this server prepends its own and anything below it
 *   arrived with the message. And the authenticated domain is compared
 *   against the organization named inside the report, so a party that
 *   passes DMARC for itself has still not authenticated a report about
 *   somebody else.
 *
 *   The comparison decides whether a report is evidence. It does not
 *   decide which organization the report counts as. The authenticated
 *   domain goes to the store with the verdict, and the store counts
 *   organizations by its registered domain, so one domain sending reports
 *   under the names Alpha, Beta and Gamma is one organization.
 *
 *   A report that fails any of that is stored and marked rather than
 *   discarded: an operator needs to see what arrived, and a later reader
 *   needs to be able to leave it out. The mark reaches three places. It
 *   is the verdict this module returns, it is the audit row this module
 *   writes, and it is handed to the store's ingest verb, which writes it
 *   on the report row and on every record row the report produced. The
 *   third is the one a later reading acts on: `blamepost.store.reports`
 *   rolls up over the record rows, so a verdict that lived only in the
 *   trail could be read by an operator and not by the reading a policy
 *   rests on.
 *
 *   ## What the filing seam can and cannot say
 *
 *   `blamepost.mail.mailbox.onFiled` is the one place a message reaching
 *   a mailbox can be observed, and it cannot say where the message came
 *   from: `appendMessage` is the same call for a peer's delivery and for
 *   an IMAP APPEND by the account holder, and nothing in the event
 *   separates them. An account holder who can APPEND into the reporting
 *   mailbox can therefore write an `Authentication-Results` header
 *   naming this server and have it read as this server's own verdict.
 *
 *   No reading of the message closes that, because the message is all
 *   there is. What closes it is the mailbox: the address a `rua=` or
 *   `ruf=` record points at belongs to the operator and to nobody else,
 *   and no account credential reaches it. That is a deployment rule
 *   rather than a check this module can make, and it is written here
 *   because it is the assumption everything above rests on.
 *
 *   ## Refusals
 *
 *   Untrusted internet input, read the way a wire reader reads: refused
 *   at the point of parse with a named code, counted, and never
 *   tolerated because it is nearly right. `receive` answers with a
 *   verdict and never throws, because the caller is holding a message a
 *   peer is waiting on. One unusable entry does not cost the archive
 *   that carries it, and one unusable message does not stop the mailbox.
 *   The construction path throws instead: an operator finds a bound they
 *   cannot have at boot.
 */

var b          = require("../vendor/blamejs");
var address    = require("../store/address");
var auditActor = require("../store/actor");
var mailbox    = require("./mailbox");
// The control-character table every stored field is refused against. A
// report is a peer's bytes and the fields taken out of it are printed
// beside a refusal an operator reads.
var displayText = require("../text");

var TIME  = b.constants.TIME;
var BYTES = b.constants.BYTES;

// Every reason this module answers with. Published so a caller deciding
// what to do about a refusal, and an operator surface deciding whether a
// sentence was written for a reader, both read one list rather than a
// prefix. A refusal the store raised is passed through in the store's
// own words instead of being renamed here, so a reader chasing a
// `domain-not-hosted` finds one vocabulary and not two.
var NOT_A_REPORTING_ADDRESS   = "not-a-reporting-address";
var NOT_A_REPORT              = "not-a-report";
var MESSAGE_TOO_LARGE         = "message-too-large";
var MESSAGE_UNREADABLE        = "message-unreadable";
var CONTAINER_UNREADABLE      = "container-unreadable";
var CONTAINER_RATIO_REFUSED   = "container-ratio-refused";
var CONTAINER_TOO_LARGE       = "container-too-large";
var CONTAINER_EMPTY           = "container-empty";
var CONTAINER_TOO_MANY        = "container-too-many-entries";
var CONTAINER_UNSUPPORTED     = "container-unsupported";
var CONTAINER_NESTED          = "container-nested";
var CONTAINER_ENTRY_TOO_LARGE = "container-entry-too-large";
var REPORT_UNREADABLE         = "report-unreadable";
var REPORT_TOO_LARGE          = "report-too-large";
var REPORT_WINDOW_IMPLAUSIBLE = "report-window-implausible";
var STORE_UNAVAILABLE         = "store-unavailable";

var CODES = Object.freeze({
  notAReportingAddress:   NOT_A_REPORTING_ADDRESS,
  notAReport:             NOT_A_REPORT,
  messageTooLarge:        MESSAGE_TOO_LARGE,
  messageUnreadable:      MESSAGE_UNREADABLE,
  containerUnreadable:    CONTAINER_UNREADABLE,
  containerRatioRefused:  CONTAINER_RATIO_REFUSED,
  containerTooLarge:      CONTAINER_TOO_LARGE,
  containerEmpty:         CONTAINER_EMPTY,
  containerTooManyEntries: CONTAINER_TOO_MANY,
  containerUnsupported:   CONTAINER_UNSUPPORTED,
  containerNested:        CONTAINER_NESTED,
  containerEntryTooLarge: CONTAINER_ENTRY_TOO_LARGE,
  reportUnreadable:       REPORT_UNREADABLE,
  reportTooLarge:         REPORT_TOO_LARGE,
  reportWindowImplausible: REPORT_WINDOW_IMPLAUSIBLE,
  storeUnavailable:       STORE_UNAVAILABLE,
});

// What this module concluded about the message that carried a report.
// Every value except the first says the report was kept and does not
// count as evidence, and each one says which of the four ways it failed,
// because they need different responses: a missing header is a receiving
// path that is not writing one, a failing verdict is a reporter with a
// broken posture, and a mismatch is somebody sending reports about a
// domain they have no part in.
var VERIFIED               = "verified";
var NOT_AUTHENTICATED_HERE = "carrier-not-authenticated-here";
var DMARC_NOT_PASS         = "carrier-dmarc-not-pass";
var CARRIER_UNREADABLE     = "carrier-domain-unreadable";
var REPORTER_MISMATCH      = "carrier-domain-is-not-the-reporter";
var REPORTER_UNNAMED       = "reporter-not-named-in-report";
var FORENSIC_NO_IDENTITY   = "carrier-verified-no-reporter-identity";

var AUTHENTICITY = Object.freeze({
  verified:             VERIFIED,
  notAuthenticatedHere: NOT_AUTHENTICATED_HERE,
  dmarcNotPass:         DMARC_NOT_PASS,
  carrierUnreadable:    CARRIER_UNREADABLE,
  reporterMismatch:     REPORTER_MISMATCH,
  reporterUnnamed:      REPORTER_UNNAMED,
  forensicNoIdentity:   FORENSIC_NO_IDENTITY,
});

// The two shapes of report this module routes, named once so the verdict
// and the audit row cannot disagree about what was read.
var KIND_AGGREGATE = "aggregate";
var KIND_FORENSIC  = "forensic";

// The containers a report is sent in, as they are reported back. The
// framework's signature registry names the gzip one `gz`; the wire and
// the operator both call it gzip, so it is translated once here.
var CONTAINER_XML  = "xml";
var CONTAINER_GZIP = "gzip";
var CONTAINER_ZIP  = "zip";

// How a candidate whose bytes are an archive this reader does not open
// is carried between the sniff and the refusal. It is not one of the
// three above and it is deliberately not the refusal code either: a
// `container` field holding a reason reads as a container named after a
// failure, which is a sentence an operator has to decode.
var CONTAINER_OTHER = "other-archive";

var SNIFF_GZIP = "gz";
var SNIFF_ZIP  = "zip";

// The RFC 6591 section 3.1 part that makes a message a forensic report.
var FEEDBACK_REPORT_TYPE = "message/feedback-report";

// The media types worth looking inside for an aggregate report. RFC 7489
// section 7.2.1.1 names the compressed and uncompressed forms; the
// octet-stream entry is there because a large share of real reporters
// declare that and nothing else. Membership makes a part a candidate and
// decides nothing else: the bytes still have to look like a container or
// like XML before anything is opened.
var AGGREGATE_MEDIA_TYPES = Object.freeze({
  "application/gzip":            1,
  "application/x-gzip":          1,
  "application/gzip-compressed": 1,
  "application/zip":             1,
  "application/x-zip":           1,
  "application/x-zip-compressed": 1,
  "application/xml":             1,
  "text/xml":                    1,
  "application/octet-stream":    1,
});

// The refusals the archive reader raises, mapped onto this module's own
// vocabulary. Read as an exact-code table rather than by looking for
// words inside a message, because the codes are the reader's published
// contract and the sentences beside them are not.
var ARCHIVE_REFUSALS = Object.freeze({
  "archive-read/too-many-entries": CONTAINER_TOO_MANY,
  "archive-read/entry-too-large":  CONTAINER_ENTRY_TOO_LARGE,
  "archive-read/total-too-large":  CONTAINER_ENTRY_TOO_LARGE,
  "archive-read/expansion-ratio":  CONTAINER_RATIO_REFUSED,
});

// The refusal `b.safeDecompress` raises when a payload expanded past the
// ratio it was given, which is the bound this module exists to add.
var RATIO_REFUSED_CODE = "safe-decompress/ratio-exceeded";

// How reporter-chosen text is screened before it reaches a verdict an
// operator reads. `b.guardText` owns the codepoint threat catalogue:
// bidi overrides, zero-width and invisible formatting characters, the
// Unicode Tags block and null bytes. An attachment name is printed
// beside a refusal, and a name that renders as one thing and sorts as
// another is a refusal read about the wrong file. Confusables are
// audited rather than refused, which is the guard's own default.
var REPORT_TEXT_GUARD = { profile: "strict", confusablePolicy: "audit" };

// The guard above allows tab, carriage return and line feed, which are
// ordinary in free text, and it reports the C1 range as clean. None of
// them is ordinary in a value printed into a console line, so
// `blamepost.text.hasControlChar` refuses all of them beside it.

// Bounds on the reporter-chosen text this module carries. An attachment
// name and a refusal code are both values somebody else wrote, so an
// unbounded one is a peer deciding how large this server's answers are.
var MAX_NAME_CHARS   = 200;
var MAX_DETAIL_CHARS = 200;

// The byte-order marks a generator may write ahead of an XML
// declaration, and the bytes that may follow one before the document
// opens. Written as octets because the payload is read as octets: a
// report is somebody else's bytes, and decoding them to look at them
// would substitute a replacement character for every sequence the
// decoder does not know, which is three octets where there was one.
var UTF8_BOM     = [0xEF, 0xBB, 0xBF];
var UTF16_LE_BOM = [0xFF, 0xFE];
var UTF16_BE_BOM = [0xFE, 0xFF];
var LEFT_ANGLE   = 0x3C;
var ASCII_SPACE  = Object.freeze({ 0x09: 1, 0x0A: 1, 0x0D: 1, 0x20: 1 });

// How many leading bytes are read to decide whether a payload is XML.
// Enough for a byte-order mark and the leading whitespace a
// pretty-printer adds, and short enough that the test costs nothing on a
// payload that is not one.
var XML_SNIFF_BYTES = 64;

// The carrier message, and how much of it this module will read. A
// report is an attachment on a small message; a ceiling above this is a
// peer deciding how much memory one delivery costs.
var DEFAULT_MAX_MESSAGE_BYTES = BYTES.mib(16);
var MIN_MAX_MESSAGE_BYTES     = BYTES.kib(16);
var MAX_MAX_MESSAGE_BYTES     = BYTES.mib(32);

// Parts in the carrier message. A report message has a note, an
// attachment and sometimes a signature; a hundred parts is a message
// built to make a walk expensive.
var DEFAULT_MAX_MESSAGE_PARTS = 32;
var MIN_MAX_MESSAGE_PARTS     = 2;
var MAX_MAX_MESSAGE_PARTS     = 128;

// The compressed bytes a container may hold before anything is expanded,
// which is the bound that stops work rather than allocation.
var DEFAULT_MAX_COMPRESSED_BYTES = BYTES.mib(4);
var MIN_MAX_COMPRESSED_BYTES     = BYTES.kib(1);
var MAX_MAX_COMPRESSED_BYTES     = BYTES.mib(8);

// The floor on the expanded report itself. Its ceiling is not a constant
// here: it is whatever the store handle says it will take, read off the
// handle at construction so the two bounds cannot drift apart.
var MIN_MAX_REPORT_BYTES = BYTES.kib(1);

// How far a payload may expand. The framework's own default for the
// primitive is fifty, which is comfortable for XML and refuses the
// classic bomb shapes; the ceiling is set where an operator with a
// reporter that genuinely compresses better can raise it and still not
// be accepting a thousandfold.
var DEFAULT_MAX_EXPANSION_RATIO = 50;
var MIN_MAX_EXPANSION_RATIO     = 2;
var MAX_MAX_EXPANSION_RATIO     = 1000;

// Reports in one archive. Reporters that batch send a handful; an
// archive with hundreds is a peer deciding how many store transactions
// one message costs.
var DEFAULT_MAX_ARCHIVE_ENTRIES = 16;
var MIN_MAX_ARCHIVE_ENTRIES     = 1;
var MAX_MAX_ARCHIVE_ENTRIES     = 64;

// What a report may claim to cover. An aggregate report covers a
// reporting interval, which RFC 7489 section 6.3 makes a day by default
// and lets a domain shorten. A report claiming years is a reporter with
// a broken clock or a document written to sit at the top of every
// reading, and either way there is nothing in it worth keeping.
var DEFAULT_MAX_REPORT_WINDOW_MS = TIME.days(32);
var MIN_MAX_REPORT_WINDOW_MS     = TIME.hours(1);
var MAX_MAX_REPORT_WINDOW_MS     = TIME.days(400);

// How far past now a report's window may end. Clocks disagree and
// reports are generated at the close of an interval, so a little slack
// is ordinary; a window ending next month has not happened.
var DEFAULT_MAX_WINDOW_SKEW_MS = TIME.days(2);
var MIN_MAX_WINDOW_SKEW_MS     = TIME.minutes(1);
var MAX_MAX_WINDOW_SKEW_MS     = TIME.days(30);

// How many verdicts are kept for an operator to read back. They are held
// in memory and lost on a restart, which is what they are for: the audit
// trail is the durable record and this is the console's recent view.
var DEFAULT_RECENT_LIMIT = 50;
var MIN_RECENT_LIMIT     = 1;
var MAX_RECENT_LIMIT     = 500;

// ---------------------------------------------------------------------------
// Reading a setting
// ---------------------------------------------------------------------------

function _whole(value, label, floor, ceiling, fallback) {
  var given = value;
  if (given === undefined || given === null) given = fallback;
  if (typeof given !== "number" || !Number.isInteger(given)) {
    throw new TypeError("blamepost.mail.reports.create: opts." + label +
      " must be a whole number between " + floor + " and " + ceiling + ".");
  }
  if (given < floor || given > ceiling) {
    throw new TypeError("blamepost.mail.reports.create: opts." + label + " is " + given +
      ", and it has to be between " + floor + " and " + ceiling + ".");
  }
  return given;
}

// ---------------------------------------------------------------------------
// Reading a value somebody else wrote
// ---------------------------------------------------------------------------
//
// Every reader below answers with a value or with null and never throws.
// A report is a peer's bytes: what a caller needs is which part could
// not be taken and why, so a refusal is a return value.

// One screened, bounded field of somebody else's text, or null when the
// value is absent or will not render. Absence and refusal are the same
// answer because every caller treats them the same way: the field is
// optional and a name that will not render is not better than no name.
function _screened(value, limit) {
  if (typeof value !== "string") return null;
  var trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > limit) return null;
  if (displayText.hasControlChar(trimmed)) return null;
  return b.guardText.validate(trimmed, REPORT_TEXT_GUARD).ok ? trimmed : null;
}

// The name a part was attached under, read out of the RFC 2183
// disposition and falling back to the RFC 2045 content-type parameter,
// which is where older reporters put it. Composed from the framework's
// quote-aware splitter rather than a hand-rolled one: the value is
// somebody else's and may carry a quoted separator. It is used for the
// answer an operator reads and never to decide what a part is.
function _attachmentName(headers) {
  var sources = [headers.get("content-disposition"), headers.get("content-type")];
  for (var s = 0; s < sources.length; s += 1) {
    if (typeof sources[s] !== "string") continue;
    var unfolded = b.structuredFields.unfoldHeaderContinuations(sources[s]);
    var pieces = b.structuredFields.splitUnquoted(unfolded, ";");
    for (var p = 1; p < pieces.length; p += 1) {
      var pair = b.structuredFields.parseKeyValuePiece(pieces[p].trim());
      if (pair.value === null) continue;
      if (pair.key !== "filename" && pair.key !== "name") continue;
      var raw = b.structuredFields.stripDoubleQuotes(pair.value.trim());
      var screened = _screened(raw, MAX_NAME_CHARS);
      if (screened !== null) return screened;
    }
  }
  return null;
}

// The media type of a part, folded for comparison against the table
// above. RFC 2045 section 5.1 makes media types case-insensitive.
function _mediaType(part) {
  if (!part || !part.leaf || typeof part.leaf.contentType !== "string") return "";
  return part.leaf.contentType.trim().toLowerCase();
}

// Does a payload begin the way an XML document does? A candidacy test
// and not a validation: it decides whether a part is worth handing to a
// parser, and the parser is what says whether the bytes are a report. A
// byte-order mark and leading whitespace are both ordinary in a report a
// generator pretty-printed.
function _startsWith(bytes, prefix) {
  if (bytes.length < prefix.length) return false;
  for (var i = 0; i < prefix.length; i += 1) {
    if (bytes[i] !== prefix[i]) return false;
  }
  return true;
}

function _looksXml(bytes) {
  // A document in a wide encoding answers yes here even though the shape
  // below cannot match it. The parser then refuses it in the operator's
  // hearing, which is what a report this server cannot read should cost,
  // rather than this test passing it over without a word.
  if (_startsWith(bytes, UTF16_LE_BOM) || _startsWith(bytes, UTF16_BE_BOM)) return true;
  var at = _startsWith(bytes, UTF8_BOM) ? UTF8_BOM.length : 0;
  var limit = Math.min(bytes.length, at + XML_SNIFF_BYTES);
  while (at < limit && ASCII_SPACE[bytes[at]] === 1) at += 1;
  return at < limit && bytes[at] === LEFT_ANGLE;
}

// A moment, from the seconds a report's date range carries.
function _momentFromSeconds(value) {
  if (typeof value !== "number" || !isFinite(value)) return null;
  return Math.round(value) * 1000;
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

/**
 * @primitive blamepost.mail.reports.create
 * @signature blamepost.mail.reports.create(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 7489 section 7.2.1.1, RFC 6591 section 3.1, RFC 8601
 * @related   blamepost.mail.reports.receive, blamepost.store.reports.create
 *
 * Build the reader that turns a message filed for a reporting address
 * into rows in the store. Returns
 * `{ receive, observe, describe, recent }`.
 *
 * `observe` is the form `blamepost.mail.mailbox.onFiled` takes: it reads
 * the address and the octets off the filed message event, calls `receive`
 * with them, and settles the promise that call returns. Registering it is
 * the whole of the wiring, and it is what `blamepost.create` does.
 *
 * Everything it needs is handed in. It holds no configuration of its
 * own, opens no volume and knows nothing about which domains this server
 * hosts: the store handle owns that question and answers it on every
 * report. Bad bounds are refused here rather than at the first report,
 * so an operator finds a ceiling they cannot have at boot.
 *
 * `authservId` is the name this server writes into the
 * `Authentication-Results` headers its own inbound path produces, and it
 * is required because without it there is no way to tell this server's
 * verdict from one a stranger wrote into the message.
 *
 * `reportingAddresses` is the set of addresses the `rua=` and `ruf=`
 * records point at. A message filed for anything else is passed over
 * untouched. An empty list is refused rather than read as every address.
 *
 * `maxReportBytes` cannot exceed what the store handle will take, which
 * is read from the handle rather than copied, so the two bounds cannot
 * drift apart.
 *
 * @opts
 *   store:              object,     // required, a blamepost.store.reports handle
 *   authservId:         string,     // required, this server's own RFC 8601 identity
 *   reportingAddresses: string[],   // required, non-empty
 *   maxMessageBytes:    number,     // 16 KiB to 32 MiB, default 16 MiB
 *   maxMessageParts:    number,     // 2 to 128, default 32
 *   maxReportBytes:     number,     // 1 KiB to the store's own ceiling, default that
 *   maxCompressedBytes: number,     // 1 KiB to 8 MiB, default 4 MiB
 *   maxExpansionRatio:  number,     // 2 to 1000, default 50
 *   maxArchiveEntries:  number,     // 1 to 64, default 16
 *   maxReportWindowMs:  number,     // 1 hour to 400 days, default 32 days
 *   maxWindowSkewMs:    number,     // 1 minute to 30 days, default 2 days
 *   recentLimit:        number,     // 1 to 500, default 50
 *
 * @example
 *   var reports = require("./lib/mail/reports");
 *   var reader = reports.create({
 *     store:              storeReports,
 *     authservId:         "mx.example.com",
 *     reportingAddresses: ["dmarc-reports@example.com"],
 *   });
 *   reader.describe().maxExpansionRatio;
 */
function create(opts) {
  opts = opts || {};

  var store = opts.store;
  if (!store || typeof store.ingestAggregate !== "function" ||
      typeof store.ingestForensic !== "function" ||
      typeof store.describe !== "function") {
    throw new TypeError("blamepost.mail.reports.create: opts.store must be a " +
      "blamepost.store.reports handle. This module reads reports and files them; " +
      "it holds no rows of its own and has nowhere to put one without it.");
  }

  var authservId = opts.authservId;
  if (typeof authservId !== "string" || authservId.trim().length === 0) {
    throw new TypeError("blamepost.mail.reports.create: opts.authservId must be the name " +
      "this server writes into its own Authentication-Results headers. Without it a " +
      "header a stranger wrote reads as this server's verdict.");
  }
  authservId = authservId.trim();

  if (!Array.isArray(opts.reportingAddresses) || opts.reportingAddresses.length === 0) {
    throw new TypeError("blamepost.mail.reports.create: opts.reportingAddresses must be a " +
      "non-empty list of the addresses the rua and ruf records point at. An empty list " +
      "would read as every address, which is the opposite of what it says.");
  }
  var reportingAddresses = [];
  for (var a = 0; a < opts.reportingAddresses.length; a += 1) {
    var parsed = address.parse(opts.reportingAddresses[a]);
    if (!parsed.ok) {
      throw new TypeError("blamepost.mail.reports.create: opts.reportingAddresses[" + a +
        "] is not an address (" + parsed.reason + ").");
    }
    if (reportingAddresses.indexOf(parsed.address) === -1) {
      reportingAddresses.push(parsed.address);
    }
  }

  var storeCeiling = store.describe().maxReportBytes;
  var maxMessageBytes = _whole(opts.maxMessageBytes, "maxMessageBytes",
    MIN_MAX_MESSAGE_BYTES, MAX_MAX_MESSAGE_BYTES, DEFAULT_MAX_MESSAGE_BYTES);
  var maxMessageParts = _whole(opts.maxMessageParts, "maxMessageParts",
    MIN_MAX_MESSAGE_PARTS, MAX_MAX_MESSAGE_PARTS, DEFAULT_MAX_MESSAGE_PARTS);
  var maxReportBytes = _whole(opts.maxReportBytes, "maxReportBytes",
    MIN_MAX_REPORT_BYTES, storeCeiling, storeCeiling);
  var maxCompressedBytes = _whole(opts.maxCompressedBytes, "maxCompressedBytes",
    MIN_MAX_COMPRESSED_BYTES, MAX_MAX_COMPRESSED_BYTES, DEFAULT_MAX_COMPRESSED_BYTES);
  var maxExpansionRatio = _whole(opts.maxExpansionRatio, "maxExpansionRatio",
    MIN_MAX_EXPANSION_RATIO, MAX_MAX_EXPANSION_RATIO, DEFAULT_MAX_EXPANSION_RATIO);
  var maxArchiveEntries = _whole(opts.maxArchiveEntries, "maxArchiveEntries",
    MIN_MAX_ARCHIVE_ENTRIES, MAX_MAX_ARCHIVE_ENTRIES, DEFAULT_MAX_ARCHIVE_ENTRIES);
  var maxReportWindowMs = _whole(opts.maxReportWindowMs, "maxReportWindowMs",
    MIN_MAX_REPORT_WINDOW_MS, MAX_MAX_REPORT_WINDOW_MS, DEFAULT_MAX_REPORT_WINDOW_MS);
  var maxWindowSkewMs = _whole(opts.maxWindowSkewMs, "maxWindowSkewMs",
    MIN_MAX_WINDOW_SKEW_MS, MAX_MAX_WINDOW_SKEW_MS, DEFAULT_MAX_WINDOW_SKEW_MS);
  var recentLimit = _whole(opts.recentLimit, "recentLimit",
    MIN_RECENT_LIMIT, MAX_RECENT_LIMIT, DEFAULT_RECENT_LIMIT);

  var counts = {
    received:       0,
    passedOver:     0,
    aggregate:      0,
    forensic:       0,
    refused:        0,
    unauthenticated: 0,
    recordsStored:  0,
    recordsRefused: 0,
    duplicates:     0,
  };
  var recent = [];

  // What the MIME parser is allowed to build out of a carrier message.
  // The message ceiling is applied on both the whole and the decoded
  // part, because an attachment is where the bytes actually are and a
  // budget that only bounds the envelope bounds nothing.
  //
  // Built from MESSAGE_PARSE_CAPS rather than written out here, so a
  // dimension the shared caps bound cannot go missing from this one.
  // Written out, this object carried no nesting depth at all, which left
  // the one parse reading messages strangers send to a published
  // reporting address as the only unbounded one in the application. The
  // two values below are narrower than the shared caps rather than wider,
  // and a report carrier is one message holding one attachment, so
  // nothing legitimate reaches them.
  var mimeBounds = Object.assign({}, mailbox.MESSAGE_PARSE_CAPS, {
    maxMessageBytes: maxMessageBytes,
    maxBodyBytes:    maxMessageBytes,
    maxParts:        maxMessageParts,
  });

  // ---- verdict shapes -----------------------------------------------------

  function _blank() {
    return {
      handled:         false,
      ok:              true,
      kind:            null,
      reason:          null,
      detail:          null,
      container:       null,
      attachment:      null,
      authenticated:   false,
      authenticity:    null,
      authenticatedAs: null,
      stored:          0,
      refused:         0,
      duplicates:      0,
      entries:         [],
    };
  }

  function _passOver(reason) {
    var verdict = _blank();
    verdict.reason = reason;
    counts.passedOver += 1;
    return verdict;
  }

  function _refuse(reason, detail, attachment) {
    var verdict = _blank();
    verdict.handled = true;
    verdict.ok      = false;
    verdict.reason  = reason;
    verdict.detail  = _screened(detail, MAX_DETAIL_CHARS);
    verdict.attachment = attachment || null;
    return verdict;
  }

  // ---- what this server itself said about the carrier ---------------------

  // The one `Authentication-Results` header this server wrote, read from
  // the top of the block down. RFC 8601 section 5 has a receiver prepend
  // its own, so the topmost header carrying this server's authserv-id is
  // this server's most recent verdict and anything below it either
  // arrived with the message or is older. Reading further down would let
  // whoever sent the message choose which verdict is read.
  function _carrierVerdict(tree) {
    var written = tree.headers.getAll("authentication-results");
    for (var i = 0; i < written.length; i += 1) {
      var unfolded = b.structuredFields.unfoldHeaderContinuations(written[i]);
      var pieces = b.structuredFields.splitUnquoted(unfolded, ";");
      if (pieces.length === 0) continue;
      // RFC 8601 section 2.2: the authserv-id, optionally followed by a
      // version token. Compared exactly rather than folded, because this
      // is the value this server writes verbatim and an exact test is
      // the narrower of the two.
      var head = pieces[0].trim();
      var space = head.search(/[ \t]/);
      var identity = space === -1 ? head : head.slice(0, space);
      if (identity !== authservId) continue;
      return _dmarcClause(pieces);
    }
    return { present: false, result: null, from: null };
  }

  // The `dmarc` method clause of one header, and the RFC 8601 section
  // 2.3 `header.from` property beside it, which is the identity DMARC
  // aligned against.
  function _dmarcClause(pieces) {
    for (var p = 1; p < pieces.length; p += 1) {
      var clause = pieces[p].trim();
      if (clause.length === 0) continue;
      var tokens = clause.split(/[ \t]+/);
      var method = b.structuredFields.parseKeyValuePiece(tokens[0]);
      if (method.key !== "dmarc" || method.value === null) continue;
      var verdict = method.value.trim().toLowerCase();
      var from = null;
      for (var t = 1; t < tokens.length; t += 1) {
        var property = b.structuredFields.parseKeyValuePiece(tokens[t]);
        if (property.key !== "header.from" || property.value === null) continue;
        from = b.structuredFields.stripDoubleQuotes(property.value.trim());
      }
      return { present: true, result: verdict, from: from };
    }
    return { present: true, result: null, from: null };
  }

  // The author domain out of the `header.from` property of a verdict this
  // server wrote, whichever of its two spellings the value carries.
  //
  // The RFC 8601 registry entry for the `dmarc` method defines the
  // property as the domain of the author address, which is what
  // `b.mail.inbound.verify` writes. Earlier framework releases wrote the
  // whole address there, and messages already filed carry that form, so
  // the reading takes either: a value with one `@` is an address and the
  // domain is what follows it, and a value with none is already the domain.
  //
  // A value with more than one `@` is neither. RFC 5322 section 3.4.1
  // gives an addr-spec exactly one, so `a@b@c` is a shape no reading of
  // this property has a right answer for, and guessing at one would pick
  // the party a report is attributed to out of a string that does not
  // name one. It is refused, and the caller reports the carrier as
  // unreadable.
  //
  // The domain is then derived by the identity layer like any other,
  // because this is the value the report's organization is compared
  // against and a second derivation would be a second answer to which
  // party sent a report.
  function _carrierDomain(value) {
    if (typeof value !== "string" || value.length === 0) return { ok: false };
    var at = value.indexOf("@");
    if (at !== -1 && at !== value.lastIndexOf("@")) return { ok: false };
    return address.parseDomain(at === -1 ? value : value.slice(at + 1));
  }

  // Do two names belong to the same registered party? Exact first, then
  // the organizational form RFC 7489 section 3.2 relaxed alignment uses,
  // so a reporter contacting from one host and signing as another is
  // still the same organization. A name the public-suffix reader will
  // not take falls back to the exact test, which is the narrower answer.
  function _sameParty(one, other) {
    if (one === other) return true;
    var left;
    var right;
    try {
      left  = b.publicSuffix.organizationalDomain(one);
      right = b.publicSuffix.organizationalDomain(other);
    } catch (_e) {
      return false;
    }
    return left !== null && right !== null && left === right;
  }

  // The whole authenticity rule, in one place. `reporter` is the
  // organization the report names as its author, or null when the report
  // carries none and when the shape of report has none to carry.
  function _authenticity(carrier, reporter) {
    if (!carrier.present || carrier.result === null) {
      return { authenticated: false, authenticity: NOT_AUTHENTICATED_HERE, as: null };
    }
    if (carrier.result !== "pass") {
      var failedFor = _carrierDomain(carrier.from);
      return { authenticated: false, authenticity: DMARC_NOT_PASS,
        as: failedFor.ok ? failedFor.domain : null };
    }
    var derived = _carrierDomain(carrier.from);
    if (!derived.ok) {
      return { authenticated: false, authenticity: CARRIER_UNREADABLE, as: null };
    }
    if (reporter === null) {
      return { authenticated: false, authenticity: REPORTER_UNNAMED, as: derived.domain };
    }
    if (!_sameParty(derived.domain, reporter)) {
      return { authenticated: false, authenticity: REPORTER_MISMATCH, as: derived.domain };
    }
    return { authenticated: true, authenticity: VERIFIED, as: derived.domain };
  }

  // ---- opening whatever the reporter wrapped the report in ----------------

  // Which parts of a carrier message are worth opening, and what each
  // one turns out to be. Membership of the media-type table makes a part
  // worth looking at; `b.fileType.detect` reads the leading bytes and
  // decides what it is. A part the sniff cannot place and that does not
  // begin like a document is not a report and is not reported as a
  // failure, because ordinary mail reaches this address too.
  function _candidates(tree) {
    var found = [];
    b.safeMime.walk(tree, function (part) {
      if (!part.leaf) return;
      if (AGGREGATE_MEDIA_TYPES[_mediaType(part)] !== 1) return;
      var body = part.leaf.body;
      if (!Buffer.isBuffer(body) || body.length === 0) return;
      var sniffed = b.fileType.detect(body);
      var container = null;
      if (sniffed === null) container = _looksXml(body) ? CONTAINER_XML : null;
      else if (sniffed.name === SNIFF_GZIP) container = CONTAINER_GZIP;
      else if (sniffed.name === SNIFF_ZIP) container = CONTAINER_ZIP;
      else if (sniffed.category === "archive") container = CONTAINER_OTHER;
      if (container === null) return;
      found.push({ container: container, bytes: body,
        attachment: _attachmentName(part.headers), sniffed: sniffed });
    });
    return found;
  }

  // One gzip, expanded under all three bounds. The framework primitive
  // caps the compressed bytes, the expanded bytes and the ratio between
  // them; the aggregate parser underneath caps only the second, which is
  // why the expansion happens here and the parser is handed bytes that
  // are already open.
  //
  // `maxCompressedBytes` is handed down as well as spent in `_open`. The
  // same number reaches the layer that does the work, so a caller that
  // ever reaches this verb by another route arrives under the bound
  // rather than outside it.
  function _expandGzip(bytes) {
    try {
      return { ok: true, bytes: b.safeDecompress(bytes, {
        algorithm:          "gzip",
        maxOutputBytes:     maxReportBytes,
        maxCompressedBytes: maxCompressedBytes,
        maxRatio:           maxExpansionRatio,
        ctx:                "blamepost.mail.reports",
      }) };
    } catch (e) {
      var code = (e && e.code) || null;
      return { ok: false,
        reason: code === RATIO_REFUSED_CODE ? CONTAINER_RATIO_REFUSED : CONTAINER_UNREADABLE,
        detail: code };
    }
  }

  // Every file in one archive, read into memory. `extractEntries` never
  // writes to disk, which is what a report being opened inside a mail
  // path needs: there is nowhere for an entry to land and nothing to
  // clean up when one is refused. The entry count is read from the
  // central directory before anything is expanded, so an archive holding
  // more than this reader takes costs one directory walk.
  async function _openArchive(bytes) {
    var opened = [];
    try {
      // Built inside the guard along with everything it is used for. The
      // reader refuses an adapter it cannot use by throwing, and a throw
      // from this verb would unwind into the seam that is holding a
      // peer's delivery.
      var reader = b.archive.read.zip(b.archive.adapters.buffer(bytes), {
        bombPolicy: {
          maxEntries:                maxArchiveEntries,
          maxEntryDecompressedBytes: maxReportBytes,
          maxTotalDecompressedBytes: maxReportBytes * maxArchiveEntries,
          maxExpansionRatio:         maxExpansionRatio,
        },
      });
      var listed = await reader.inspect();
      if (listed.length === 0) {
        return { ok: false, reason: CONTAINER_EMPTY, detail: null };
      }
      for await (var entry of reader.extractEntries()) {
        opened.push({ name: _screened(entry.name, MAX_NAME_CHARS), bytes: entry.bytes });
      }
    } catch (e) {
      var code = (e && e.code) || null;
      return { ok: false,
        reason: (code !== null && ARCHIVE_REFUSALS[code]) || CONTAINER_UNREADABLE,
        detail: code };
    }
    if (opened.length === 0) return { ok: false, reason: CONTAINER_EMPTY, detail: null };
    return { ok: true, entries: opened };
  }

  // ---- one aggregate report ----------------------------------------------

  function _entryRefusal(name, container, reason, detail) {
    return { name: name, container: container, ok: false, reason: reason,
      detail: _screened(detail, MAX_DETAIL_CHARS), stored: 0, refused: 0,
      duplicate: false, authenticated: false, authenticity: null, authenticatedAs: null };
  }

  // A refusal reached after the carrier was judged. It carries the verdict,
  // whether the verdict counts as evidence, and the domain it was reached
  // for, all three from the one judgment, so the answer and the trail row
  // never pair `verified` with `authenticated: false`.
  function _judgedRefusal(name, container, reason, detail, judged) {
    var refusal = _entryRefusal(name, container, reason, detail);
    refusal.authenticated   = judged.authenticated;
    refusal.authenticity    = judged.authenticity;
    refusal.authenticatedAs = judged.as;
    return refusal;
  }

  // Is the range a report claims to cover one a report could cover? The
  // store bounds the two moments so a reporter cannot write a window that
  // sorts before every real one, and this is the other half: a window
  // longer than a reporting interval has any business being, or one that
  // ends after the report could have been written.
  function _windowIsPlausible(metadata, now) {
    var range = metadata.dateRange || {};
    var begin = _momentFromSeconds(range.begin);
    var end   = _momentFromSeconds(range.end);
    if (begin === null || end === null) return false;
    if (end < begin) return false;
    if (end - begin > maxReportWindowMs) return false;
    if (end > now + maxWindowSkewMs) return false;
    return true;
  }

  // The organization a report names as its author. RFC 7489 Appendix C
  // has the contact mailbox and the organization name beside each other,
  // and reporters fill them in differently: the mailbox is the reliable
  // one and the name is a domain often enough to be worth the second
  // look. Either yields a name or the report names nobody, which is a
  // report nothing can be bound to rather than an error.
  function _reporterNamedBy(metadata) {
    var contact = address.parse(metadata.email);
    if (contact.ok) return contact.domain;
    var named = address.parseDomain(metadata.orgName);
    return named.ok ? named.domain : null;
  }

  // One report, from open bytes to rows. The bytes go to the store
  // rather than the shaped object this reads, because `raw` is what the
  // store publishes as its input and handing it a shape would make this
  // module the definition of the store's contract. The parse happens
  // twice for that: once here to decide whether the report is evidence
  // and whether its window is real, and once inside the store to write
  // the rows. Reports arrive a few times a day per reporter.
  function _fileAggregate(name, container, bytes, carrier, now) {
    if (bytes.length > maxReportBytes) {
      return _entryRefusal(name, container, REPORT_TOO_LARGE, String(bytes.length));
    }
    var shaped;
    try {
      shaped = b.mail.dmarc.parseAggregateReport(bytes);
    } catch (e) {
      return _entryRefusal(name, container, REPORT_UNREADABLE, (e && e.code) || null);
    }

    var metadata = shaped.reportMetadata || {};
    if (!_windowIsPlausible(metadata, now)) {
      return _entryRefusal(name, container, REPORT_WINDOW_IMPLAUSIBLE, null);
    }

    // Judged before the rows are written, because the store writes the
    // verdict onto every row the report produces and there is no second
    // write to correct it with afterwards. The organization the report
    // names comes out of the parse above, so nothing here waits on the
    // store to answer it.
    var judged = _authenticity(carrier, _reporterNamedBy(metadata));

    // The store answers a refusal as a verdict and reserves a throw for
    // a volume it cannot write, which is the one thing that must not
    // reach the caller: this verb is called from a seam holding a
    // message a peer is waiting on, and an exception there costs the
    // delivery and loses the reason with it. The fault becomes a named
    // refusal, counted and recorded like any other.
    // `authenticatedAs` is the domain this server's own header says the
    // carrier passed DMARC for. The store records its registered domain on
    // a verified report and counts organizations by it, so a party passing
    // DMARC for one domain is one organization whatever `<org_name>` its
    // reports carry.
    var verdict;
    try {
      verdict = store.ingestAggregate(bytes, {
        now:             now,
        evidence:        judged.authenticity,
        authenticatedAs: judged.authenticated ? judged.as : null,
      });
    } catch (e) {
      return _judgedRefusal(name, container, STORE_UNAVAILABLE, (e && e.code) || null, judged);
    }
    if (!verdict.ok) {
      return _judgedRefusal(name, container, verdict.reason, verdict.detail, judged);
    }
    return {
      name:            name,
      container:       container,
      ok:              true,
      reason:          null,
      detail:          null,
      stored:          verdict.stored,
      refused:         Array.isArray(verdict.refused) ? verdict.refused.length : 0,
      duplicate:       verdict.duplicate === true,
      authenticated:   judged.authenticated,
      authenticity:    judged.authenticity,
      authenticatedAs: judged.as,
    };
  }

  // ---- what the reader answers with --------------------------------------

  // The message-level verdict, assembled from the entries a message
  // produced. `stored` and `refused` are sums because an operator asking
  // what a message did wants one number, and the per-entry list is
  // beside them for the one that failed. A message whose every entry
  // failed is a refusal, and its reason is the first one, because that
  // is the one that says what went wrong first.
  function _fromEntries(entries, container, attachment, carrier) {
    // `carrier` is the message-level verdict, used only when no entry
    // produced a report of its own to judge against.
    var verdict = _blank();
    verdict.handled    = true;
    verdict.kind       = KIND_AGGREGATE;
    verdict.container  = container;
    verdict.attachment = attachment;
    verdict.entries    = entries;

    var succeeded = 0;
    var firstFailure = null;
    for (var i = 0; i < entries.length; i += 1) {
      verdict.stored  += entries[i].stored;
      verdict.refused += entries[i].refused;
      if (entries[i].duplicate) verdict.duplicates += 1;
      if (entries[i].ok) succeeded += 1;
      else if (firstFailure === null) firstFailure = entries[i];
    }

    var judgedBy = null;
    for (var j = 0; j < entries.length; j += 1) {
      if (entries[j].authenticity !== null) { judgedBy = entries[j]; break; }
    }
    if (judgedBy === null) {
      var carrierOnly = _authenticity(carrier, null);
      verdict.authenticated   = false;
      verdict.authenticity    = carrierOnly.authenticity;
      verdict.authenticatedAs = carrierOnly.as;
    } else {
      verdict.authenticated   = judgedBy.authenticated;
      verdict.authenticity    = judgedBy.authenticity;
      verdict.authenticatedAs = judgedBy.authenticatedAs;
    }

    if (succeeded === 0) {
      verdict.ok     = false;
      verdict.reason = firstFailure === null ? NOT_A_REPORT : firstFailure.reason;
      verdict.detail = firstFailure === null ? null : firstFailure.detail;
    }
    return verdict;
  }

  // Recorded once per message this reader took responsibility for. The
  // row says whether the carrier was authenticated for the reporting
  // organization and which domain it was authenticated as, which is what
  // an operator asked why a report was left out reads, and it is the one
  // place a message this reader REFUSED is recorded at all, because a
  // refusal wrote no row for a column to sit on. What a later reading
  // acts on is the column beside the rows, written by the store from the
  // same verdict. Emitted rather than awaited, because the caller is a
  // filing seam holding a message a peer is waiting on and the rows the
  // report produced are already committed.
  //
  // The three fields carrying the verdict are named differently here
  // than they are on the verdict object, and the difference is
  // load-bearing rather than untidy. `b.redact` scrubs any metadata key
  // whose name CONTAINS `auth`, case-insensitively and as a substring,
  // so a row written under the verdict's own field names arrives at a
  // later reader as three redaction markers: the mark is written where
  // it is declared and gone where it is read. The test over this row
  // reads the values back, so renaming these keys to match the verdict
  // fails there rather than silently emptying the trail.
  function _record(verdict) {
    b.audit.safeEmit({
      action: verdict.ok === false
        ? "blamepost.mail.reports.refused"
        : (verdict.kind === KIND_FORENSIC
            ? "blamepost.mail.reports.forensic_ingested"
            : "blamepost.mail.reports.aggregate_ingested"),
      // The outcome vocabulary is the framework's three values and the
      // emitter rewrites anything else into one of them, so a fourth
      // value written here would be recorded as a success without
      // anything saying it had been changed. A report that was stored
      // and does not count as evidence IS a successful ingest, and the
      // distinction an operator filters on is the `evidence` field
      // below rather than this column.
      outcome:  verdict.ok === false ? "denied" : "success",
      actor:    auditActor.current(),
      metadata: {
        kind:            verdict.kind,
        container:       verdict.container,
        attachment:      verdict.attachment,
        reason:          verdict.reason,
        detail:          verdict.detail,
        evidence:        verdict.authenticated,
        evidenceVerdict: verdict.authenticity,
        evidenceFor:     verdict.authenticatedAs,
        stored:          verdict.stored,
        refused:         verdict.refused,
        duplicates:      verdict.duplicates,
      },
    });
  }

  function _remember(verdict, at) {
    recent.push({
      at:              at,
      handled:         verdict.handled,
      ok:              verdict.ok,
      kind:            verdict.kind,
      reason:          verdict.reason,
      detail:          verdict.detail,
      container:       verdict.container,
      attachment:      verdict.attachment,
      authenticated:   verdict.authenticated,
      authenticity:    verdict.authenticity,
      authenticatedAs: verdict.authenticatedAs,
      stored:          verdict.stored,
      refused:         verdict.refused,
      duplicates:      verdict.duplicates,
    });
    while (recent.length > recentLimit) recent.shift();
  }

  function _tally(verdict) {
    if (!verdict.handled) return;
    counts.recordsStored  += verdict.stored;
    counts.recordsRefused += verdict.refused;
    counts.duplicates     += verdict.duplicates;
    if (!verdict.ok) { counts.refused += 1; return; }
    if (verdict.kind === KIND_FORENSIC) counts.forensic += 1;
    else counts.aggregate += 1;
    if (!verdict.authenticated) counts.unauthenticated += 1;
  }

  function _isReportingAddress(candidate) {
    if (typeof candidate !== "string") return false;
    var parsed = address.parse(candidate);
    return parsed.ok && reportingAddresses.indexOf(parsed.address) !== -1;
  }

  // The address a filed message is read as having arrived for. A
  // reporting address that is an alias files its mail under the
  // destination account, so the envelope recipient is checked first and
  // the account only when the recipient is not a reporting address.
  function _arrivedFor(event) {
    return _isReportingAddress(event.recipient) ? event.recipient : event.address;
  }

  /**
   * @primitive blamepost.mail.reports.receive
   * @signature reader.receive(raw, opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 7489 section 7.2, RFC 6591, RFC 8601
   * @related   blamepost.mail.reports.describe, blamepost.store.reports.ingestAggregate
   *
   * Read one message that was filed for a reporting address and file
   * whatever report it carries. `raw` is the message octets as they were
   * stored, which is the shape `blamepost.mail.mailbox.onFiled` hands an
   * observer.
   *
   * Answers `{ handled, ok, kind, reason, detail, container, attachment,
   * authenticated, authenticity, authenticatedAs, stored, refused,
   * duplicates, entries }` and never throws. `handled` says whether this
   * reader took responsibility for the message: a message for another
   * address, and one carrying nothing that looks like a report, are
   * passed over rather than refused, because ordinary mail reaches a
   * reporting address too. `ok` says whether what it took responsibility
   * for worked.
   *
   * `entries` holds one verdict per report the message carried, which is
   * more than one when a reporter batches several into an archive. One
   * entry that cannot be read never costs the others, and one report
   * whose records are partly unusable is stored with the unusable ones
   * counted.
   *
   * `authenticated` is false on anything this server did not itself
   * authenticate for the reporting organization, and `authenticity`
   * names which of the ways it failed. The report is stored anyway, with
   * `authenticity` written onto every row it produced, so what arrived
   * is visible and `blamepost.store.reports.rollup` leaves it out of the
   * counting a policy rests on.
   *
   * @opts
   *   arrivedFor: string,   // required, the address the message was filed for
   *   now:        number,   // the moment to read the report against, default the clock
   *
   * @example
   *   var verdict = await reader.receive(event.raw, { arrivedFor: event.address });
   *   verdict.stored;
   */
  async function receive(raw, receiveOpts) {
    var options = receiveOpts || {};
    var now = typeof options.now === "number" && isFinite(options.now)
      ? options.now : Date.now();
    var bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw || ""), "utf8");

    counts.received += 1;
    var verdict = await _read(bytes, options, now);
    _tally(verdict);
    _remember(verdict, now);
    if (verdict.handled) _record(verdict);
    return verdict;
  }

  // A fault in this reader itself, which is not one of the verdicts above.
  // `receive` answers with a verdict on every path it has, so nothing here
  // reaches this in the ordinary course; it exists so that if one ever
  // does, the failure is a row an operator can find rather than a process
  // that ended.
  function _recordReaderFault(fault) {
    try {
      b.audit.safeEmit({
        action:   "blamepost.mail.reports.reader_failed",
        outcome:  "failure",
        actor:    auditActor.current(),
        metadata: {
          // Repaired rather than refused. `_screened` answers null for a
          // value it will not take, which is the right answer for an
          // attachment name and the wrong one here: this row exists to
          // say what went wrong, and a row reading `error: null` is the
          // fault reported without the words it was reported for. The
          // bound is applied after the screen, so it cuts text that no
          // longer holds anything a reader acts on.
          error: displayText.forDisplay((fault && fault.message) || String(fault))
            .slice(0, MAX_DETAIL_CHARS),
        },
      });
    } catch (_e) {
      // allow:swallow-unverified the audit sink is the reporting path
      // itself and already swallows inside safeEmit, so reaching this
      // needs the sink replaced rather than a fault driven through it.
      // This runs inside the rejection handler of a promise nothing
      // awaits, where a throw becomes an unhandled rejection and ends the
      // process.
    }
  }

  // The shape `blamepost.mail.mailbox.onFiled` calls with. It takes the
  // filed message event, hands `receive` the two fields this reader needs,
  // and lets the rest go.
  //
  // It exists so the wiring reads as one line where the server is
  // assembled, and so the promise `receive` returns is settled somewhere.
  // The mailbox layer calls an observer synchronously and discards what it
  // returns, so a rejection left unattached here would be an unhandled
  // rejection, which ends the process over a message a stranger sent. It
  // must not throw either: that layer catches whatever comes out of an
  // observer precisely because filing is the operation a peer is waiting
  // on, and leaning on that catch would turn a fault in this reader into
  // an audit row about the mailbox.
  function observe(event) {
    if (!event || typeof event !== "object") return;
    var settled;
    try {
      settled = receive(event.raw, { arrivedFor: _arrivedFor(event) });
    } catch (thrown) {
      _recordReaderFault(thrown);
      return;
    }
    if (settled && typeof settled.catch === "function") settled.catch(_recordReaderFault);
  }

  async function _read(bytes, options, now) {
    if (!_isReportingAddress(options.arrivedFor)) {
      return _passOver(NOT_A_REPORTING_ADDRESS);
    }
    if (bytes.length > maxMessageBytes) {
      return _refuse(MESSAGE_TOO_LARGE, String(bytes.length), null);
    }

    var tree;
    try {
      tree = b.safeMime.parse(bytes, mimeBounds);
    } catch (e) {
      return _refuse(MESSAGE_UNREADABLE, (e && e.code) || null, null);
    }

    var carrier = _carrierVerdict(tree);

    var feedback = b.safeMime.findFirst(tree, function (part) {
      return _mediaType(part) === FEEDBACK_REPORT_TYPE;
    });
    if (feedback !== null) return _fileForensic(bytes, carrier, now);

    var candidates = _candidates(tree);
    if (candidates.length === 0) return _passOver(NOT_A_REPORT);

    // The message-level container and attachment describe the first
    // candidate part. RFC 7489 section 7.2.1.1 asks for one report per
    // message and reporters send one, so this is the whole answer in
    // practice; `entries` carries the per-report truth for a message
    // that carried several.
    var entries = [];
    var container = candidates[0].container === CONTAINER_OTHER
      ? null : candidates[0].container;
    var attachment = candidates[0].attachment;
    for (var c = 0; c < candidates.length; c += 1) {
      var opened = await _open(candidates[c], carrier, now);
      for (var o = 0; o < opened.length; o += 1) {
        entries.push(opened[o]);
      }
    }
    return _fromEntries(entries, container, attachment, carrier);
  }

  // One candidate part, opened into the entry verdicts it produced. A
  // container this reader does not open, and a container inside a
  // container, are both refusals rather than silences: the reporter sent
  // something archive-shaped to a reporting address, and an operator
  // whose reporter uses a format nothing here reads needs to be told
  // rather than to find an empty rollup.
  async function _open(found, carrier, now) {
    if (found.container === CONTAINER_OTHER) {
      return [_entryRefusal(found.attachment, null, CONTAINER_UNSUPPORTED,
        found.sniffed === null ? null : found.sniffed.mime)];
    }
    if (found.container === CONTAINER_XML) {
      return [_fileAggregate(found.attachment, CONTAINER_XML, found.bytes, carrier, now)];
    }
    // Both remaining containers are compressed, and this is the bound on
    // what one may carry before a decompressor is handed any of it. It is
    // spent here, where the two paths are still one, rather than inside
    // each reader: whoever sends a report chooses the container, so a
    // bound applied on one side of this branch is a bound the sender
    // decides whether to be held to. The archive path had none, and an
    // operator who lowered the number read a figure the gzip path obeyed
    // and the archive path did not.
    if (found.bytes.length > maxCompressedBytes) {
      return [_entryRefusal(found.attachment, found.container, CONTAINER_TOO_LARGE,
        String(found.bytes.length))];
    }
    if (found.container === CONTAINER_GZIP) {
      var expanded = _expandGzip(found.bytes);
      if (!expanded.ok) {
        return [_entryRefusal(found.attachment, CONTAINER_GZIP,
          expanded.reason, expanded.detail)];
      }
      return [_fileAggregate(found.attachment, CONTAINER_GZIP, expanded.bytes, carrier, now)];
    }
    var archive = await _openArchive(found.bytes);
    if (!archive.ok) {
      return [_entryRefusal(found.attachment, CONTAINER_ZIP, archive.reason, archive.detail)];
    }
    var out = [];
    for (var i = 0; i < archive.entries.length; i += 1) {
      var entry = archive.entries[i];
      var inner = b.fileType.detect(entry.bytes);
      if (inner !== null && inner.category === "archive") {
        out.push(_entryRefusal(entry.name, CONTAINER_ZIP, CONTAINER_NESTED, inner.mime));
        continue;
      }
      if (!_looksXml(entry.bytes)) {
        out.push(_entryRefusal(entry.name, CONTAINER_ZIP, REPORT_UNREADABLE, null));
        continue;
      }
      out.push(_fileAggregate(entry.name, CONTAINER_ZIP, entry.bytes, carrier, now));
    }
    return out;
  }

  // ---- one forensic report ------------------------------------------------

  // A per-message failure report carries no name for the organization
  // that generated it. RFC 6591 section 3.1 lists the failing message's
  // own identifiers and nothing about the reporter, so there is nothing
  // inside the report to bind the carrier's authenticated domain to. The
  // binding therefore stops at the carrier: the domain this server
  // authenticated is recorded, and an operator reads it and decides.
  function _fileForensic(bytes, carrier, now) {
    var verdict = _blank();
    verdict.handled = true;
    verdict.kind    = KIND_FORENSIC;

    var carrierOnly = _authenticity(carrier, null);
    if (carrierOnly.authenticity === REPORTER_UNNAMED) {
      verdict.authenticated   = true;
      verdict.authenticity    = FORENSIC_NO_IDENTITY;
      verdict.authenticatedAs = carrierOnly.as;
    } else {
      verdict.authenticated   = false;
      verdict.authenticity    = carrierOnly.authenticity;
      verdict.authenticatedAs = carrierOnly.as;
    }

    // Wrapped for the reason the aggregate path is: a volume fault must
    // not unwind through the seam that is holding a peer's delivery. The
    // verdict reached above goes in with the bytes, so every row the
    // report produces carries it and a later reading can leave out what
    // this server did not authenticate.
    var filed;
    try {
      filed = store.ingestForensic(bytes, { now: now, evidence: verdict.authenticity });
    } catch (e) {
      verdict.ok     = false;
      verdict.reason = STORE_UNAVAILABLE;
      verdict.detail = _screened((e && e.code) || null, MAX_DETAIL_CHARS);
      return verdict;
    }
    if (!filed.ok) {
      verdict.ok     = false;
      verdict.reason = filed.reason;
      verdict.detail = _screened(filed.detail, MAX_DETAIL_CHARS);
      return verdict;
    }
    verdict.stored     = filed.stored;
    verdict.refused    = Array.isArray(filed.refused) ? filed.refused.length : 0;
    verdict.duplicates = filed.duplicates;
    verdict.entries    = [{
      name:            null,
      container:       null,
      ok:              true,
      reason:          null,
      detail:          null,
      stored:          verdict.stored,
      refused:         verdict.refused,
      duplicate:       verdict.duplicates > 0,
      authenticated:   verdict.authenticated,
      authenticity:    verdict.authenticity,
      authenticatedAs: verdict.authenticatedAs,
    }];
    return verdict;
  }

  /**
   * @primitive blamepost.mail.reports.describe
   * @signature reader.describe()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the bounds in force, published rather than recomputed)
   * @related   blamepost.mail.reports.create, blamepost.mail.reports.recent
   *
   * The bounds this reader is running under and what it has done with
   * what it was handed. It is what the admin surface and `blamepost
   * doctor` report, so an operator reading how much a peer may send
   * reads the numbers actually in force rather than the ones a document
   * says.
   *
   * The counters separate the four outcomes a message can have, because
   * they need different responses. A rising `passedOver` is a mailbox
   * collecting mail that is not reports. A rising `refused` is a
   * reporter this server cannot read. A rising `unauthenticated` is
   * reports arriving that no policy decision should rest on.
   *
   * @example
   *   reader.describe().counts.unauthenticated;
   */
  function describe() {
    return {
      authservId:         authservId,
      reportingAddresses: reportingAddresses.slice(),
      maxMessageBytes:    maxMessageBytes,
      maxMessageParts:    maxMessageParts,
      maxReportBytes:     maxReportBytes,
      maxCompressedBytes: maxCompressedBytes,
      maxExpansionRatio:  maxExpansionRatio,
      maxArchiveEntries:  maxArchiveEntries,
      maxReportWindowMs:  maxReportWindowMs,
      maxWindowSkewMs:    maxWindowSkewMs,
      recentLimit:        recentLimit,
      counts:             Object.assign({}, counts),
    };
  }

  /**
   * @primitive blamepost.mail.reports.recent
   * @signature reader.recent()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the last verdicts, screened for printing)
   * @related   blamepost.mail.reports.describe, blamepost.mail.reports.receive
   *
   * The last verdicts this reader reached, newest last, bounded by the
   * limit it was built with. It answers the question the counters raise:
   * a count of refusals says something is wrong and these say which
   * attachment and which reason.
   *
   * Every value in one was written by whoever sent the message, so every
   * one has been through the same screening a peer's refusal goes
   * through before it reaches a console. They are held in memory and go
   * on a restart; the audit trail is the durable record.
   *
   * @example
   *   reader.recent()[0].reason;
   */
  function recentVerdicts() {
    return recent.slice();
  }

  return {
    receive:  receive,
    observe:  observe,
    describe: describe,
    recent:   recentVerdicts,
  };
}

module.exports = {
  create:       create,
  CODES:        CODES,
  AUTHENTICITY: AUTHENTICITY,
  DEFAULT_MAX_MESSAGE_BYTES:    DEFAULT_MAX_MESSAGE_BYTES,
  DEFAULT_MAX_COMPRESSED_BYTES: DEFAULT_MAX_COMPRESSED_BYTES,
  DEFAULT_MAX_EXPANSION_RATIO:  DEFAULT_MAX_EXPANSION_RATIO,
  DEFAULT_MAX_ARCHIVE_ENTRIES:  DEFAULT_MAX_ARCHIVE_ENTRIES,
  DEFAULT_MAX_REPORT_WINDOW_MS: DEFAULT_MAX_REPORT_WINDOW_MS,
  DEFAULT_MAX_WINDOW_SKEW_MS:   DEFAULT_MAX_WINDOW_SKEW_MS,
  DEFAULT_RECENT_LIMIT:         DEFAULT_RECENT_LIMIT,
};
