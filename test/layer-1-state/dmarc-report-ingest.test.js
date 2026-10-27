// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What happens between a report arriving as ordinary mail and the rows
 * the store writes.
 *
 * A DMARC report is a file somebody attached to a message. Before the
 * store can hold any of it, something has to decide that the message is
 * a report at all, open whatever the reporter wrapped it in, and say
 * whether the report is evidence or a document a stranger composed. That
 * decision is what this file drives.
 *
 * The questions, written as the failures they stop:
 *
 *   - a reporter that sends gzip and a reporter that sends ZIP are both
 *     read, because a container this server cannot open is a reporter
 *     whose findings never arrive, and an absence in reporting looks
 *     exactly like a domain nobody is spoofing;
 *   - the container is decided by the bytes rather than by the name on
 *     the attachment, so a name that disagrees with the content routes
 *     on the content;
 *   - a gzip that expands eight hundred times is refused here even
 *     though the parser underneath takes it, which is measured against
 *     that parser in the same run rather than asserted;
 *   - a report whose carrier did not pass DMARC for the reporting
 *     organization is stored and marked, so an operator sees what
 *     arrived and a later reader can leave it out;
 *   - the mark reaches the rows rather than only the trail, so the
 *     reading a policy is moved on counts the authenticated report and
 *     leaves the others out while still naming what it left;
 *   - the topmost header this server wrote is the one read, so a
 *     forgery further down the block cannot promote itself;
 *   - one unusable entry in an archive does not cost the archive, and
 *     one unusable message does not throw at the seam that is holding a
 *     peer's delivery;
 *   - and a message filed for the reporting address by IMAP APPEND is
 *     indistinguishable from one a peer delivered, which is asserted
 *     rather than hoped, because it is the reason the reporting mailbox
 *     must be one only the operator holds.
 *
 * Real database, real sealed columns, real vault, temporary data
 * directory. No sockets: the reader is handed the message octets, which
 * is the shape the filing seam hands it.
 *
 * Run standalone: node test/layer-1-state/dmarc-report-ingest.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeZlib = require("node:zlib");

var helpers      = require("../helpers");
var b            = require("../../lib/vendor/blamejs");
var config       = require("../../lib/config");
var store        = require("../../lib/store");
var storeReports = require("../../lib/store/reports");
var tables       = require("../../lib/store/tables");
var ingest       = require("../../lib/mail/reports");

var count = helpers.count;

var HOSTNAME         = "mx.example.com";
var AUTHSERV_ID      = "mx.example.com";
var DOMAIN           = "example.com";
var OTHER_DOMAIN     = "example.net";
var UNHOSTED_DOMAIN  = "somebody-else.example";
var REPORTER         = "reporter.example";
var OTHER_REPORTER   = "second-reporter.example";
var RUA_ADDRESS      = "dmarc-reports@example.com";
var RUF_ADDRESS      = "dmarc-failures@example.com";
var ACCOUNT_ADDRESS  = "someone@example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var DAY_MS  = 86400000;
var HOUR_MS = 3600000;

// The window every fixture report covers, and the moment the reader is
// told it is, so every plausibility answer below is arithmetic over
// fixed numbers rather than over whatever the clock said.
var WINDOW_BEGIN_SEC = 1750000000;
var WINDOW_END_SEC   = WINDOW_BEGIN_SEC + 86400;
var NOW_MS           = (WINDOW_END_SEC + 3600) * 1000;

// The expansion the bomb fixture is built to reach. Far above the cap
// the handle is built with, and the padded report stays well under the
// byte ceiling, so the ratio is the only bound that can refuse it.
var BOMB_PAD_CHARS = 1500000;

// Every control character a value printed into a console line is refused
// for: the C0 range, the delete codepoint and the C1 range at U+0080 to
// U+009F. Written as escapes so this file holds no control byte of its
// own for a source scan to trip over. A scanner that reads a fixture as
// binary stops reading the file, which is the quietest way a gate can
// stop gating.
//
// The C1 half is the same alphabet `blamepost.text.hasControlChar`
// refuses and the same one the store's own case names at U+009B, and it
// is here because a range this file stopped at U+007F asserts a narrower
// alphabet than the reader screens. U+009B is the single-byte control
// sequence introducer: one code point that opens an escape sequence, so
// a verdict carrying it repaints the console row it is printed on.
var CONTROL_RANGE = new RegExp("[\\u0000-\\u001F\\u007F\\u0080-\\u009F]");

// The right-to-left override, which renders a filename as its own
// reverse. It is built from its codepoint rather than typed, so this
// file is plain ASCII and the character exists only at run time.
var BIDI_OVERRIDE = String.fromCharCode(0x202E);

// The single-byte control sequence introducer, built the same way and
// for the same reason. A C1 octet does not survive being typed into a
// source file.
var C1_CSI = String.fromCharCode(0x009B);

// ---- fixtures --------------------------------------------------------------

function xmlRecord(sourceIp, messages, dkim, spf, disposition) {
  return "  <record>\n" +
    "    <row><source_ip>" + sourceIp + "</source_ip><count>" + messages + "</count>\n" +
    "      <policy_evaluated><disposition>" + disposition + "</disposition>" +
    "<dkim>" + dkim + "</dkim><spf>" + spf + "</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>" + DOMAIN + "</header_from></identifiers>\n" +
    "    <auth_results><spf><domain>" + DOMAIN + "</domain>" +
    "<result>" + spf + "</result></spf></auth_results>\n" +
    "  </record>\n";
}

// The alphabet the filler below draws from, and the recurrence it draws
// with. `padChars` repeats one character, which is what a fixture for the
// expansion ratio needs; a fixture for the bound on the COMPRESSED bytes
// needs the opposite, because a container filled with one character stays
// small however much of it goes in. The sequence is generated rather than
// typed so the fixture is a few lines instead of a few kilobytes, and it
// is a fixed recurrence rather than a random one so a failure here is the
// same failure on the next run.
var NOISE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

function noise(chars) {
  var out = [];
  var seed = 7;
  for (var i = 0; i < chars; i += 1) {
    seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
    out.push(NOISE_ALPHABET[seed % NOISE_ALPHABET.length]);
  }
  return out.join("");
}

function aggregateXml(opts) {
  opts = opts || {};
  var org      = opts.org || REPORTER;
  var reportId = opts.reportId || "0001";
  var policyOn = opts.domain || DOMAIN;
  var begin    = opts.begin === undefined ? WINDOW_BEGIN_SEC : opts.begin;
  var end      = opts.end === undefined ? WINDOW_END_SEC : opts.end;
  var pad      = opts.padChars || 0;
  var noisy    = opts.noiseChars || 0;
  var records  = opts.records || [
    xmlRecord("203.0.113.10", 7, "pass", "pass", "none"),
    xmlRecord("198.51.100.4", 3, "fail", "fail", "reject"),
  ];
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    (pad > 0 ? "  <!-- " + "A".repeat(pad) + " -->\n" : "") +
    (noisy > 0 ? "  <!-- " + noise(noisy) + " -->\n" : "") +
    "  <report_metadata>\n" +
    "    <org_name>" + org + "</org_name>\n" +
    "    <email>dmarc-noreply@" + org + "</email>\n" +
    "    <report_id>" + reportId + "</report_id>\n" +
    "    <date_range><begin>" + begin + "</begin><end>" + end + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + policyOn + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>reject</p><sp>reject</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    records.join("") +
    "</feedback>\n";
}

// An RFC 7489 section 7.2.1.1 attachment name. The fixtures below hand
// the reader names that agree with their bytes and names that do not, so
// the routing can be shown to read one and not the other.
function reportFilename(extension) {
  return REPORTER + "!" + DOMAIN + "!" + WINDOW_BEGIN_SEC + "!" + WINDOW_END_SEC +
    "." + extension;
}

// The header this server's own inbound path writes.
//
// `header.from` carries what `b.mail.inbound.verify` puts there, which is
// the whole author address rather than its domain. The RFC 8601 registry
// entry for the `dmarc` method defines that property as the domain, so
// the two spellings both reach a receiver's own header and the reader
// below is measured against both. `theShippedVerdictWritesTheAddressForm`
// pins which of them this server writes today, so a test written around
// a shape nothing produces cannot pass quietly again.
function authenticationResults(opts) {
  opts = opts || {};
  var id     = opts.authservId || AUTHSERV_ID;
  var result = opts.dmarc || "pass";
  var from   = opts.from || REPORTER;
  var author = opts.headerFrom === undefined ? "dmarc-noreply@" + from : opts.headerFrom;
  return "Authentication-Results: " + id +
    "; spf=" + (opts.spf || result) + " smtp.mailfrom=dmarc-noreply@" + from +
    "; dkim=" + (opts.dkim || result) + " header.d=" + from +
    "; dmarc=" + result + " header.from=" + author + "\r\n";
}

// A carrier message with one attachment. `headers` is whatever
// authentication the case under test wants in front of it, already
// terminated; an empty string is a message this server recorded nothing
// about.
function carrier(opts) {
  var contentType = opts.contentType;
  var filename    = opts.filename;
  var payload     = Buffer.isBuffer(opts.payload)
    ? opts.payload
    : Buffer.from(String(opts.payload), "utf8");
  var extra = opts.headers === undefined ? authenticationResults({}) : opts.headers;
  return Buffer.from(
    extra +
    "From: dmarc-noreply@" + (opts.from || REPORTER) + "\r\n" +
    "To: " + (opts.to || RUA_ADDRESS) + "\r\n" +
    "Subject: Report Domain: " + DOMAIN + "\r\n" +
    "Content-Type: multipart/mixed; boundary=\"bnd-report\"\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "This is an aggregate report from " + REPORTER + ".\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: " + contentType + "\r\n" +
    "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" +
    payload.toString("base64") + "\r\n" +
    "--bnd-report--\r\n",
    "utf8");
}

function zipOf(files) {
  var built = b.archive.zip();
  for (var i = 0; i < files.length; i += 1) {
    var content = files[i].content;
    built.addFile(files[i].name,
      Buffer.isBuffer(content) ? content : Buffer.from(String(content), "utf8"));
  }
  return built.toBuffer();
}

// The RFC 6591 shape, whole, which is what the store's forensic verb
// reads. The reported message rides inside it because a real one does.
function forensicMessage(opts) {
  opts = opts || {};
  var reported = opts.reportedDomain || DOMAIN;
  var extra    = opts.headers === undefined ? authenticationResults({}) : opts.headers;
  return Buffer.from(
    extra +
    "From: dmarc-noreply@" + REPORTER + "\r\n" +
    "To: " + RUF_ADDRESS + "\r\n" +
    "Content-Type: multipart/report; report-type=feedback-report; " +
    "boundary=\"bnd-forensic\"\r\n" +
    "\r\n" +
    "--bnd-forensic\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "An authentication failure report.\r\n" +
    "\r\n" +
    "--bnd-forensic\r\n" +
    "Content-Type: message/feedback-report\r\n" +
    "\r\n" +
    "Feedback-Type: auth-failure\r\n" +
    "User-Agent: Reporter/1.0\r\n" +
    "Version: 1\r\n" +
    "Auth-Failure: dmarc\r\n" +
    "Original-Mail-From: " + (opts.mailFrom || "stranger@third-party.example") + "\r\n" +
    "Original-Rcpt-To: " + (opts.rcptTo || "victim@example.com") + "\r\n" +
    "Arrival-Date: Mon, 15 Jun 2025 09:00:00 +0000\r\n" +
    "Reported-Domain: " + reported + "\r\n" +
    "Source-IP: 203.0.113.99\r\n" +
    "Delivery-Result: reject\r\n" +
    "Identity-Alignment: none\r\n" +
    "\r\n" +
    "--bnd-forensic\r\n" +
    "Content-Type: message/rfc822\r\n" +
    "\r\n" +
    "From: \"Someone Real\" <stranger@third-party.example>\r\n" +
    "To: victim@example.com\r\n" +
    "Subject: a stranger's subject\r\n" +
    "\r\n" +
    "a stranger's body\r\n" +
    "\r\n" +
    "--bnd-forensic--\r\n",
    "utf8");
}

// ---- handles ---------------------------------------------------------------

function storeBounds(overrides) {
  return Object.assign({
    aggregateRetentionMs: 7 * DAY_MS,
    forensicRetentionMs:  HOUR_MS,
    sweepIntervalMs:      HOUR_MS,
    forensicEnabled:      true,
    hostedDomain:         function (name) {
      return name === DOMAIN || name === OTHER_DOMAIN;
    },
  }, overrides || {});
}

function readerBounds(storeHandle, overrides) {
  return Object.assign({
    store:              storeHandle,
    authservId:         AUTHSERV_ID,
    reportingAddresses: [RUA_ADDRESS, RUF_ADDRESS],
    maxExpansionRatio:  50,
    maxArchiveEntries:  4,
  }, overrides || {});
}

function refusesWith(label, message, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  count(label,
    thrown !== null && String(thrown.message).indexOf(message) !== -1,
    thrown === null ? "accepted" : String(thrown.message));
}

// ---- the factory refuses what it cannot act on -----------------------------

function theFactoryRefusesWhatItCannotActOn(storeHandle) {
  refusesWith("a reader with no store to file into is refused",
    "opts.store", function () {
      ingest.create(readerBounds(storeHandle, { store: null }));
    });
  refusesWith("a reader with no name of its own is refused",
    "opts.authservId", function () {
      ingest.create(readerBounds(storeHandle, { authservId: "" }));
    });
  refusesWith("a reader with an empty list of reporting addresses is refused",
    "opts.reportingAddresses", function () {
      ingest.create(readerBounds(storeHandle, { reportingAddresses: [] }));
    });
  refusesWith("a reporting address that is not an address is refused",
    "opts.reportingAddresses", function () {
      ingest.create(readerBounds(storeHandle, { reportingAddresses: ["not an address"] }));
    });
  refusesWith("an expansion cap below the floor is refused",
    "opts.maxExpansionRatio", function () {
      ingest.create(readerBounds(storeHandle, { maxExpansionRatio: 1 }));
    });
  refusesWith("a report ceiling above what the store will take is refused",
    "opts.maxReportBytes", function () {
      ingest.create(readerBounds(storeHandle, {
        maxReportBytes: storeHandle.describe().maxReportBytes + 1,
      }));
    });

  var reader = ingest.create(readerBounds(storeHandle));
  var described = reader.describe();
  count("the reader publishes the bounds it is running under",
    described.maxExpansionRatio === 50 && described.maxArchiveEntries === 4 &&
    described.authservId === AUTHSERV_ID,
    JSON.stringify(described));
  count("and it has counted nothing before it has been handed anything",
    described.counts.received === 0 && described.counts.aggregate === 0,
    JSON.stringify(described.counts));
}

// ---- a message that is not this reader's business --------------------------

async function mailForSomebodyElseIsPassedOver(reader) {
  var forAnAccount = await reader.receive(
    carrier({ contentType: "application/gzip", filename: reportFilename("xml.gz"),
      payload: nodeZlib.gzipSync(Buffer.from(aggregateXml({ reportId: "pass-1" }), "utf8")) }),
    { arrivedFor: ACCOUNT_ADDRESS, now: NOW_MS });
  count("a report filed for an account is not this reader's to open",
    forAnAccount.handled === false &&
    forAnAccount.reason === ingest.CODES.notAReportingAddress,
    JSON.stringify(forAnAccount));

  var ordinary = await reader.receive(
    Buffer.from(
      "From: someone@third-party.example\r\n" +
      "To: " + RUA_ADDRESS + "\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      "\r\n" +
      "Please stop sending me these.\r\n", "utf8"),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("ordinary mail at the reporting address is passed over rather than refused",
    ordinary.handled === false && ordinary.ok === true &&
    ordinary.reason === ingest.CODES.notAReport,
    JSON.stringify(ordinary));

  var counts = reader.describe().counts;
  count("both are counted as passed over, so a mailbox filling up is visible",
    counts.passedOver === 2, JSON.stringify(counts));
}

// ---- the three containers a reporter sends ---------------------------------

async function everyContainerAReporterSendsIsOpened(reader) {
  var plain = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "plain-1" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("an uncompressed report is read",
    plain.handled === true && plain.ok === true && plain.kind === "aggregate" &&
    plain.container === "xml" && plain.stored === 2,
    JSON.stringify(plain));

  var gzipped = await reader.receive(
    carrier({ contentType: "application/gzip", filename: reportFilename("xml.gz"),
      payload: nodeZlib.gzipSync(Buffer.from(aggregateXml({ reportId: "gzip-1" }), "utf8")) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a gzipped report is read",
    gzipped.handled === true && gzipped.ok === true &&
    gzipped.container === "gzip" && gzipped.stored === 2,
    JSON.stringify(gzipped));

  var zipBytes = zipOf([{ name: "report.xml", content: aggregateXml({ reportId: "zip-1" }) }]);

  // Measured against the parser underneath in the same run, for the
  // reason the ratio bound below is measured: a route this reader adds
  // is only worth having if the layer below has none, and reading that
  // off a comment is how the assertion outlives the fact.
  var underneathReadIt;
  try {
    var shaped = b.mail.dmarc.parseAggregateReport(zipBytes);
    underneathReadIt = Array.isArray(shaped.records);
  } catch (_e) {
    underneathReadIt = false;
  }
  count("the parser underneath cannot open an archive, which is why this route exists",
    underneathReadIt === false, String(underneathReadIt));

  var zipped = await reader.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipBytes }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a zipped report is read",
    zipped.handled === true && zipped.ok === true &&
    zipped.container === "zip" && zipped.stored === 2,
    JSON.stringify(zipped));

  var forensic = await reader.receive(forensicMessage({}),
    { arrivedFor: RUF_ADDRESS, now: NOW_MS });
  count("a per-message failure report is recognized by its own part rather than a name",
    forensic.handled === true && forensic.ok === true &&
    forensic.kind === "forensic" && forensic.stored === 1,
    JSON.stringify(forensic));
}

// ---- the bytes decide the container, not the name --------------------------

async function theBytesDecideTheContainer(reader) {
  var zipUnderAGzipName = await reader.receive(
    carrier({ contentType: "application/gzip", filename: reportFilename("xml.gz"),
      payload: zipOf([{ name: "report.xml",
        content: aggregateXml({ reportId: "mislabeled-1" }) }]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("an archive named as a gzip is opened as the archive it is",
    zipUnderAGzipName.ok === true && zipUnderAGzipName.container === "zip" &&
    zipUnderAGzipName.stored === 2,
    JSON.stringify(zipUnderAGzipName));

  var gzipUnderNoName = await reader.receive(
    carrier({ contentType: "application/octet-stream", filename: "attachment.dat",
      payload: nodeZlib.gzipSync(
        Buffer.from(aggregateXml({ reportId: "unnamed-1" }), "utf8")) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report whose name follows no convention at all is still read",
    gzipUnderNoName.ok === true && gzipUnderNoName.container === "gzip" &&
    gzipUnderNoName.stored === 2,
    JSON.stringify(gzipUnderNoName));

  var nameOnly = await reader.receive(
    carrier({ contentType: "application/gzip", filename: reportFilename("xml.gz"),
      payload: Buffer.from("this attachment is not a report at all\r\n", "utf8") }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report name over bytes that are not one is passed over rather than believed",
    nameOnly.handled === false && nameOnly.reason === ingest.CODES.notAReport,
    JSON.stringify(nameOnly));
}

// ---- the expansion bound this reader adds ----------------------------------

async function theExpansionBoundIsThisReadersOwn(reader) {
  var padded = Buffer.from(
    aggregateXml({ reportId: "bomb-1", padChars: BOMB_PAD_CHARS }), "utf8");
  var bomb   = nodeZlib.gzipSync(padded);
  var ratio  = Math.ceil(padded.length / bomb.length);

  count("the fixture expands far past the cap the reader is running under",
    ratio > reader.describe().maxExpansionRatio * 4,
    ratio + ":1 over a cap of " + reader.describe().maxExpansionRatio);
  count("and it stays well under the byte ceiling, so only the ratio can refuse it",
    padded.length < reader.describe().maxReportBytes,
    padded.length + " of " + reader.describe().maxReportBytes);

  // Measured against the parser underneath in the same run. A cap this
  // reader adds is only worth having if the layer below does not have
  // one, and asserting that from a document rather than from the code is
  // how the assertion outlives the fact.
  var underneathTookIt;
  try {
    var shaped = b.mail.dmarc.parseAggregateReport(bomb);
    underneathTookIt = Array.isArray(shaped.records) && shaped.records.length > 0;
  } catch (_e) {
    underneathTookIt = false;
  }
  count("the parser underneath accepts the same bytes, which is what this bound is for",
    underneathTookIt === true, String(underneathTookIt));

  var refused = await reader.receive(
    carrier({ contentType: "application/gzip", filename: reportFilename("xml.gz"),
      payload: bomb }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("and the reader refuses it on the ratio",
    refused.handled === true && refused.ok === false &&
    refused.reason === ingest.CODES.containerRatioRefused,
    JSON.stringify(refused));
  count("nothing from a refused container reaches the store",
    refused.stored === 0, JSON.stringify(refused));
}

// ---- the bound on the container holds on every container --------------------

// `maxCompressedBytes` bounds what a container may carry before anything
// inside it is expanded. It is spent ahead of the decompressor rather
// than against what comes out, which is what separates it from the
// ceiling on the report and from the ratio: those two are answers about
// a payload that has already been opened.
//
// Whoever sends a report chooses the container it arrives in. So a bound
// that holds on one of the two this reader opens is a bound the sender
// decides whether to be held to, and an operator who lowered it reads a
// number in `describe()` that the gzip path obeys and the archive path
// does not.
//
// One report, sent twice, in the two containers. Every other bound in
// force is measured against the fixture first, so the refusal below can
// only be this one; then the same two containers go to a reader whose
// bound is above them, which is what says the fixture is otherwise good.
async function theContainerBoundHoldsOnEveryContainer(storeHandle) {
  // Filler that does not compress, so the container is large in the
  // dimension this bound measures while its expansion stays ordinary.
  var xml   = aggregateXml({ reportId: "container-1", noiseChars: 6000 });
  var plain = Buffer.from(xml, "utf8");
  var gzip  = nodeZlib.gzipSync(plain);
  var zip   = zipOf([{ name: "report.xml", content: xml }]);

  var tight = ingest.create(readerBounds(storeHandle, { maxCompressedBytes: 1024 }));
  var bound = tight.describe().maxCompressedBytes;

  count("the reader is running under the container bound this case is about",
    bound === 1024, String(bound));
  count("and both containers carry more than it before anything is expanded",
    gzip.length > bound && zip.length > bound,
    "gzip " + gzip.length + ", zip " + zip.length + ", bound " + bound);

  // Three measurements that leave this bound as the only one a refusal
  // could come from. Without them a reader that refused for its own
  // reasons would read here as a reader honoring a bound.
  count("the report inside is well under the ceiling on a report, so that is not what refuses",
    plain.length < tight.describe().maxReportBytes,
    plain.length + " of " + tight.describe().maxReportBytes);
  count("neither container expands anywhere near the ratio cap, so that is not it either",
    (plain.length / gzip.length) < tight.describe().maxExpansionRatio &&
    (plain.length / zip.length) < tight.describe().maxExpansionRatio,
    (plain.length / gzip.length).toFixed(2) + ":1 and " +
    (plain.length / zip.length).toFixed(2) + ":1 against " +
    tight.describe().maxExpansionRatio);
  count("and the archive holds one entry, so the entry count is not it",
    tight.describe().maxArchiveEntries > 1, String(tight.describe().maxArchiveEntries));

  var overGzip = await tight.receive(
    carrier({ contentType: "application/gzip", filename: reportFilename("xml.gz"),
      payload: gzip }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a gzip over the bound is refused as the container it is",
    overGzip.handled === true && overGzip.ok === false &&
    overGzip.reason === ingest.CODES.containerTooLarge && overGzip.stored === 0,
    JSON.stringify(overGzip));

  var overZip = await tight.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zip }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("and an archive over the same bound is refused the same way, not opened",
    overZip.handled === true && overZip.ok === false &&
    overZip.reason === ingest.CODES.containerTooLarge && overZip.stored === 0,
    JSON.stringify(overZip));

  // The other direction. A fixture that is refused whatever the bound
  // says would pass both assertions above while proving nothing, so the
  // same two containers go to a reader that takes them.
  var roomy = ingest.create(readerBounds(storeHandle));
  var readGzip = await roomy.receive(
    carrier({ contentType: "application/gzip", filename: reportFilename("xml.gz"),
      payload: nodeZlib.gzipSync(
        Buffer.from(aggregateXml({ reportId: "container-2", noiseChars: 6000 }), "utf8")) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  var readZip = await roomy.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipOf([{ name: "report.xml",
        content: aggregateXml({ reportId: "container-3", noiseChars: 6000 }) }]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("the same report in the same two containers is read under a bound above it",
    readGzip.ok === true && readGzip.stored === 2 &&
    readZip.ok === true && readZip.stored === 2,
    JSON.stringify([readGzip.reason, readZip.reason]));
}

// ---- what an archive can carry ---------------------------------------------

async function everyArchiveShapeEndsSomewhereDefinite(reader) {
  var several = await reader.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipOf([
        { name: "first.xml",  content: aggregateXml({ reportId: "multi-1" }) },
        { name: "second.xml", content: aggregateXml({ reportId: "multi-2" }) },
      ]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("an archive carrying two reports files both",
    several.ok === true && several.entries.length === 2 && several.stored === 4,
    JSON.stringify(several));

  var mixed = await reader.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipOf([
        { name: "good.xml",  content: aggregateXml({ reportId: "mixed-1" }) },
        { name: "notes.txt", content: "a file the reporter should not have put here" },
      ]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("one unusable entry does not cost the archive the usable one",
    mixed.stored === 2 && mixed.entries.length === 2 &&
    mixed.entries.filter(function (e) { return e.ok === false; }).length === 1,
    JSON.stringify(mixed));
  count("and the entry that could not be read is named with a reason",
    mixed.entries.some(function (e) {
      return e.ok === false && typeof e.reason === "string" && e.reason.length > 0;
    }), JSON.stringify(mixed.entries));

  var empty = await reader.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipOf([]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("an archive with nothing in it is a refusal rather than a quiet success",
    empty.handled === true && empty.ok === false &&
    empty.reason === ingest.CODES.containerEmpty,
    JSON.stringify(empty));

  var crowded = [];
  for (var i = 0; i < reader.describe().maxArchiveEntries + 1; i += 1) {
    crowded.push({ name: "r" + i + ".xml",
      content: aggregateXml({ reportId: "crowded-" + i }) });
  }
  var tooMany = await reader.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipOf(crowded) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("an archive holding more reports than the reader takes is refused whole",
    tooMany.handled === true && tooMany.ok === false &&
    tooMany.reason === ingest.CODES.containerTooManyEntries,
    JSON.stringify(tooMany));

  var nested = await reader.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipOf([{ name: "inner.gz",
        content: nodeZlib.gzipSync(
          Buffer.from(aggregateXml({ reportId: "nested-1" }), "utf8")) }]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a container inside a container is refused rather than unwrapped again",
    nested.entries.length === 1 && nested.entries[0].ok === false &&
    nested.entries[0].reason === ingest.CODES.containerNested,
    JSON.stringify(nested));

  var broken = await reader.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: Buffer.concat([Buffer.from([0x50, 0x4B, 0x03, 0x04]),
        Buffer.from("not really an archive", "utf8")]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("bytes claiming to be an archive and failing to open are refused with a reason",
    broken.handled === true && broken.ok === false &&
    broken.reason === ingest.CODES.containerUnreadable &&
    typeof broken.detail === "string",
    JSON.stringify(broken));
}

// ---- the authenticity rule -------------------------------------------------

// Which spelling of `header.from` this server's own inbound path writes,
// measured rather than assumed.
//
// Every case below builds the header by hand, and the whole file is about
// a reader that only sees headers this server wrote. So a hand-built
// header in a shape the inbound path does not produce would test a
// reading of a value that never arrives, and would go on passing while
// every real report was refused. That is what happened: the property was
// written here as a bare domain, the inbound path writes the whole author
// address, and no report a peer delivered could be counted as evidence.
//
// The verdict is taken from `b.mail.inbound.verify` with a resolver of
// this file's own, so the claim follows the framework instead of being a
// second copy of it.
async function theShippedVerdictWritesTheAddressForm() {
  var zone = {
    "reporter.example|TXT":        [["v=spf1 ip4:192.0.2.9 -all"]],
    "_dmarc.reporter.example|TXT": [["v=DMARC1; p=none"]],
  };
  var verdict = await b.mail.inbound.verify({
    ip:       "192.0.2.9",
    helo:     "mta.reporter.example",
    mailFrom: "dmarc-noreply@" + REPORTER,
    message:  "From: dmarc-noreply@" + REPORTER + "\r\nTo: " + RUA_ADDRESS +
      "\r\nSubject: Report Domain: " + DOMAIN + "\r\n\r\nbody\r\n",
    authservId: AUTHSERV_ID,
    dnsLookup: async function (qname, type) {
      var key = String(qname).toLowerCase() + "|" + String(type).toUpperCase();
      if (!Object.prototype.hasOwnProperty.call(zone, key)) {
        var absent = new Error("no " + type + " records for " + qname);
        absent.code = "ENODATA";
        throw absent;
      }
      return zone[key];
    },
  });
  var written = String(verdict.authResults || "").replace(/\r\n[ \t]+/g, " ");
  count("the shipped inbound path writes header.from as the whole author address",
    written.indexOf("header.from=dmarc-noreply@" + REPORTER) !== -1, written);
  count("and the cases below are written in that shape",
    authenticationResults({ dmarc: "pass", from: REPORTER })
      .indexOf("header.from=dmarc-noreply@" + REPORTER) !== -1,
    authenticationResults({ dmarc: "pass", from: REPORTER }));
}

async function evidenceIsSeparatedFromWhatAnybodyCouldHaveSent(reader) {
  var carried = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "auth-1" }),
      headers: authenticationResults({ dmarc: "pass", from: REPORTER }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report whose carrier passed for the reporting organization counts as evidence",
    carried.authenticated === true && carried.authenticity === "verified" &&
    carried.authenticatedAs === REPORTER,
    JSON.stringify(carried));

  // The other spelling of the same property. The RFC 8601 registry entry
  // for the `dmarc` method defines `header.from` as the author's domain,
  // so a header written to the registry rather than to what this server
  // writes today carries the bare name. Both reach this reader, from an
  // older release of this server and from any receiver that follows the
  // registry, and both name the same party.
  var domainForm = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "auth-1b" }),
      headers: authenticationResults({ dmarc: "pass", from: REPORTER,
        headerFrom: REPORTER }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a verdict naming the author's domain rather than the whole address counts too",
    domainForm.authenticated === true && domainForm.authenticity === "verified" &&
    domainForm.authenticatedAs === REPORTER,
    JSON.stringify(domainForm));

  // A value that is neither. RFC 5322 section 3.4.1 gives an addr-spec
  // exactly one `@`, so nothing here names a party and the reader refuses
  // rather than picking one of the two names in it.
  var twoAts = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "auth-1c" }),
      headers: authenticationResults({ dmarc: "pass", from: REPORTER,
        headerFrom: "noreply@" + REPORTER + "@attacker.example" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a header.from carrying two at signs names no party and is not evidence",
    twoAts.authenticated === false &&
    twoAts.authenticity === "carrier-domain-unreadable" &&
    twoAts.authenticatedAs === null,
    JSON.stringify(twoAts));

  var unsigned = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "auth-2" }), headers: "" }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report this server recorded nothing about is stored anyway",
    unsigned.ok === true && unsigned.stored === 2, JSON.stringify(unsigned));
  count("and it is marked so a later reader can leave it out",
    unsigned.authenticated === false &&
    unsigned.authenticity === "carrier-not-authenticated-here",
    JSON.stringify(unsigned));

  var strangersHeader = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "auth-3" }),
      headers: authenticationResults({ authservId: "mx.somebody-else.example" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a header some other server wrote is not this server's verdict",
    strangersHeader.authenticated === false &&
    strangersHeader.authenticity === "carrier-not-authenticated-here",
    JSON.stringify(strangersHeader));

  var failed = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "auth-4" }),
      headers: authenticationResults({ dmarc: "fail", from: REPORTER }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a carrier that failed DMARC is stored and marked, not counted as evidence",
    failed.ok === true && failed.stored === 2 && failed.authenticated === false &&
    failed.authenticity === "carrier-dmarc-not-pass",
    JSON.stringify(failed));

  var wrongParty = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ org: REPORTER, reportId: "auth-5" }),
      headers: authenticationResults({ dmarc: "pass", from: OTHER_REPORTER }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a carrier that passed for somebody other than the reporter is not evidence",
    wrongParty.authenticated === false &&
    wrongParty.authenticity === "carrier-domain-is-not-the-reporter" &&
    wrongParty.authenticatedAs === OTHER_REPORTER,
    JSON.stringify(wrongParty));

  // The forgery vector for a message a peer really delivered: the peer
  // writes a header naming this server's own identity, and this server
  // then prepends its own. Reading anything but the topmost one hands
  // the decision to whoever sent the message.
  var forgedBelow = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "auth-6" }),
      headers: authenticationResults({ dmarc: "fail", from: "attacker.example" }) +
        authenticationResults({ dmarc: "pass", from: REPORTER }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("the topmost header this server wrote is the one read",
    forgedBelow.authenticated === false &&
    forgedBelow.authenticatedAs === "attacker.example",
    JSON.stringify(forgedBelow));

  var counts = reader.describe().counts;
  count("every report that did not count as evidence is counted",
    counts.unauthenticated >= 5, JSON.stringify(counts));
}

// ---- the filing seam cannot say where a message came from ------------------

async function theSeamCannotTellAPeerFromAnAccountHolder(reader) {
  // The mailbox layer calls its observers from the one path an inbound
  // delivery and an IMAP APPEND both take, and hands them nothing that
  // separates the two. So a message an account holder uploaded, carrying
  // a header naming this server, is read exactly as a peer's delivery
  // would be. That is not a gap this reader can close, and asserting it
  // is what keeps the reason the reporting mailbox belongs to the
  // operator alone from being forgotten.
  var appended = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "append-1" }),
      headers: authenticationResults({ dmarc: "pass", from: REPORTER }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a message uploaded into the reporting mailbox reads as evidence, " +
    "which is why that mailbox belongs to the operator alone",
    appended.authenticated === true, JSON.stringify(appended));
}

// ---- what the store refuses, and what a bad report costs -------------------

async function aRefusalNeverEscapesTheSeam(reader) {
  var elsewhere = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ domain: UNHOSTED_DOMAIN, reportId: "unhosted-1" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report about a domain hosted somewhere else is refused in the store's own words",
    elsewhere.handled === true && elsewhere.ok === false &&
    elsewhere.reason === "domain-not-hosted",
    JSON.stringify(elsewhere));

  var damaged = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: "<?xml version=\"1.0\"?><feedback><report_metadata>" }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report that will not parse refuses rather than throwing at the seam",
    damaged.handled === true && damaged.ok === false &&
    damaged.reason === ingest.CODES.reportUnreadable,
    JSON.stringify(damaged));

  var oneBadRecord = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "partial-1", records: [
        xmlRecord("203.0.113.10", 7, "pass", "pass", "none"),
        xmlRecord("not-an-address", 3, "fail", "fail", "reject"),
        xmlRecord("198.51.100.9", 5, "fail", "fail", "reject"),
      ] }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("one unusable record does not discard the report that carries it",
    oneBadRecord.ok === true && oneBadRecord.stored === 2 && oneBadRecord.refused === 1,
    JSON.stringify(oneBadRecord));

  var again = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "partial-1", records: [
        xmlRecord("203.0.113.10", 7, "pass", "pass", "none"),
      ] }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("the same report sent twice is reported as the resend it is",
    again.ok === true && again.duplicates === 1 && again.stored === 0,
    JSON.stringify(again));

  var absurd = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "window-1",
        begin: WINDOW_BEGIN_SEC, end: WINDOW_BEGIN_SEC + (900 * 86400) }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report claiming to cover years is refused before it reaches the store",
    absurd.handled === true && absurd.ok === false &&
    absurd.reason === ingest.CODES.reportWindowImplausible,
    JSON.stringify(absurd));

  var ahead = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "window-2",
        begin: WINDOW_BEGIN_SEC + (60 * 86400), end: WINDOW_END_SEC + (60 * 86400) }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("and so is one whose window has not happened yet",
    ahead.handled === true && ahead.ok === false &&
    ahead.reason === ingest.CODES.reportWindowImplausible,
    JSON.stringify(ahead));

  // The third branch of the same reading, and the one neither case above
  // reaches: both of those are ranges that run forwards. A window that
  // ends before it begins covers no time at all, and every arithmetic
  // the reading does over it answers a number rather than refusing, so
  // the range has to be refused on its shape before its length is
  // measured.
  var backwards = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "window-3",
        begin: WINDOW_END_SEC, end: WINDOW_BEGIN_SEC }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("and so is one whose window ends before it begins",
    backwards.handled === true && backwards.ok === false &&
    backwards.reason === ingest.CODES.reportWindowImplausible,
    JSON.stringify(backwards));
}

// ---- the carrier is parsed under bounds, and they are this reader's --------

// The message a report arrives on is the one parse in this server that
// reads bytes a stranger posted to a published address. `maxMessageParts`
// is the bound on how much structure that parse will build, and it was a
// published refusal nothing drove: the code was declared, the cap was
// handed to the parser, and no vector said either still worked.
//
// The refusal is asserted on its reason AND on the detail beside it. A
// carrier can fail to parse for several reasons at once, and a case that
// read only the reason would pass on a malformed header while the bound
// it names had stopped being applied.
async function theCarrierPartCountIsBounded(storeHandle) {
  var tight = ingest.create(readerBounds(storeHandle, { maxMessageParts: 2 }));
  var cap = tight.describe().maxMessageParts;
  count("the reader publishes the part count it is running under", cap === 2, String(cap));

  var parts = [];
  for (var i = 0; i <= cap; i += 1) {
    parts.push("--bnd-many\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
      "a note the reporter attached\r\n");
  }
  var crowded = await tight.receive(
    Buffer.from(
      authenticationResults({}) +
      "From: dmarc-noreply@" + REPORTER + "\r\n" +
      "To: " + RUA_ADDRESS + "\r\n" +
      "Content-Type: multipart/mixed; boundary=\"bnd-many\"\r\n" +
      "\r\n" + parts.join("") + "--bnd-many--\r\n", "utf8"),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a carrier built of more parts than it takes is refused rather than walked",
    crowded.handled === true && crowded.ok === false &&
    crowded.reason === ingest.CODES.messageUnreadable,
    JSON.stringify(crowded));
  count("and the refusal names the part count, so it is that bound and not another",
    String(crowded.detail || "").indexOf("part-count") !== -1,
    String(crowded.detail));

  // The other direction, so the assertion above is about the bound and
  // not about the fixture. The same shape under the shipped cap is read.
  var roomy = ingest.create(readerBounds(storeHandle));
  var ordinary = await roomy.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "parts-1" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("and a carrier inside the shipped cap is read as the report it carries",
    ordinary.ok === true && ordinary.stored === 2, JSON.stringify(ordinary));
}

// ---- what is kept for reading back has a bottom ----------------------------

// `recent()` is the console's view and it is held in memory, so the
// number of verdicts kept is a bound on what one process holds for a
// mailbox anybody can write to. The trim was covered by an assertion
// that the answer is no longer than the limit, which is true of a reader
// that has never reached the limit: the shared reader in this file sees
// about thirty messages against a limit of fifty, so the line that drops
// the oldest verdict never ran.
async function whatIsKeptForReadingBackIsTrimmed(storeHandle) {
  var keeping = 3;
  var reader = ingest.create(readerBounds(storeHandle, { recentLimit: keeping }));
  var sent = keeping * 3;
  for (var i = 0; i < sent; i += 1) {
    await reader.receive(
      carrier({ contentType: "text/xml", filename: "kept-" + i + ".xml",
        payload: aggregateXml({ reportId: "kept-" + i }) }),
      { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  }

  var recent = reader.recent();
  count("the reader was handed more messages than it keeps verdicts for",
    sent > keeping && reader.describe().counts.received === sent,
    sent + " handed, " + keeping + " kept");
  count("and it kept exactly the limit rather than everything it was handed",
    recent.length === keeping, recent.length + " of " + keeping);
  // Newest last, which is what the primitive says it answers. The oldest
  // verdicts are the ones that went, so the attachment names left are the
  // last three sent.
  count("keeping the newest, so the console shows what just happened rather than a prefix",
    recent[recent.length - 1].attachment === "kept-" + (sent - 1) + ".xml" &&
    recent[0].attachment === "kept-" + (sent - keeping) + ".xml",
    JSON.stringify(recent.map(function (e) { return e.attachment; })));
  count("and the counters still answer for every message, not only the kept ones",
    reader.describe().counts.aggregate === sent, JSON.stringify(reader.describe().counts));
}

// ---- a message too large to read, and one that will not parse --------------

async function aMessageThisReaderWillNotOpenIsRefusedLoud(storeHandle) {
  var small = ingest.create(readerBounds(storeHandle, {
    maxMessageBytes: 65536,
  }));
  var oversize = await small.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "oversize-1", padChars: 200000 }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a message past the ceiling is refused before anything parses it",
    oversize.handled === true && oversize.ok === false &&
    oversize.reason === ingest.CODES.messageTooLarge,
    JSON.stringify(oversize));

  var notAMessage = await small.receive(
    Buffer.from("this has no header block at all", "utf8"),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("bytes that are not a message end in a verdict rather than an exception",
    notAMessage.handled === false || notAMessage.ok === false,
    JSON.stringify(notAMessage));

  var counts = small.describe().counts;
  count("the reader counts what it refused", counts.refused >= 1, JSON.stringify(counts));
}

// ---- what an operator reads back -------------------------------------------

function whatWentPastIsReadableWithoutTrustingIt(reader) {
  var recent = reader.recent();
  count("the reader keeps the verdicts an operator asks about",
    Array.isArray(recent) && recent.length > 0, String(recent.length));
  count("and it keeps no more of them than it says it does",
    recent.length <= reader.describe().recentLimit,
    recent.length + " of " + reader.describe().recentLimit);

  var everyValue = JSON.stringify(recent);
  count("nothing a reporter chose reaches a console with control characters in it",
    CONTROL_RANGE.test(everyValue) === false, everyValue.slice(0, 120));

  var withNames = recent.filter(function (entry) { return entry.attachment !== null; });
  count("a verdict names the attachment it was about",
    withNames.length > 0, JSON.stringify(recent.slice(0, 2)));

  var counts = reader.describe().counts;
  count("the counters add up to the messages the reader was handed",
    counts.received === counts.passedOver + counts.aggregate + counts.forensic +
      counts.refused,
    JSON.stringify(counts));
}

// ---- the refusals a smaller reader reaches ---------------------------------

async function everyPublishedRefusalIsReachable(storeHandle) {
  // A reader whose report ceiling is a kilobyte, so the two size
  // refusals fire on fixtures small enough to read in a failure line.
  var tight = ingest.create(readerBounds(storeHandle, { maxReportBytes: 1024 }));

  var wideReport = await tight.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "wide-1", padChars: 4000 }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report larger than the reader takes is refused before anything parses it",
    wideReport.handled === true && wideReport.ok === false &&
    wideReport.reason === ingest.CODES.reportTooLarge,
    JSON.stringify(wideReport));

  var wideEntry = await tight.receive(
    carrier({ contentType: "application/zip", filename: reportFilename("zip"),
      payload: zipOf([{ name: "wide.xml",
        content: aggregateXml({ reportId: "wide-2", padChars: 4000 }) }]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("an archive entry larger than the reader takes is refused on the entry",
    wideEntry.handled === true && wideEntry.ok === false &&
    wideEntry.reason === ingest.CODES.containerEntryTooLarge,
    JSON.stringify(wideEntry));

  var reader = ingest.create(readerBounds(storeHandle));

  // A container this server does not open, recognized by its own magic.
  // The reporter sent something archive-shaped to a reporting address,
  // so an operator is told rather than left with an empty rollup.
  var otherArchive = await reader.receive(
    carrier({ contentType: "application/octet-stream", filename: reportFilename("bz2"),
      payload: Buffer.concat([Buffer.from("BZh", "ascii"),
        Buffer.from("9 not really compressed at all", "utf8")]) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a container format this server does not open is refused rather than passed over",
    otherArchive.handled === true && otherArchive.ok === false &&
    otherArchive.reason === ingest.CODES.containerUnsupported,
    JSON.stringify(otherArchive));

  var noIdentity = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "no-from-1" }),
      headers: "Authentication-Results: " + AUTHSERV_ID + "; dmarc=pass\r\n" }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a passing verdict that names no identity authenticates nothing",
    noIdentity.ok === true && noIdentity.authenticated === false &&
    noIdentity.authenticity === ingest.AUTHENTICITY.carrierUnreadable,
    JSON.stringify(noIdentity));

  var anonymous = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ org: "A Reporting Organization", reportId: "anon-1" })
        .replace(/<email>[^<]*<\/email>/, "") }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a report naming nobody it could have come from is not evidence for anybody",
    anonymous.authenticated === false &&
    anonymous.authenticity === ingest.AUTHENTICITY.reporterUnnamed,
    JSON.stringify(anonymous));

  var forensic = await reader.receive(forensicMessage({ rcptTo: "second@example.com" }),
    { arrivedFor: RUF_ADDRESS, now: NOW_MS });
  count("a failure report binds to the carrier and says so, having no reporter of its own",
    forensic.ok === true && forensic.authenticated === true &&
    forensic.authenticity === ingest.AUTHENTICITY.forensicNoIdentity &&
    forensic.authenticatedAs === REPORTER,
    JSON.stringify(forensic));

  var unsignedForensic = await reader.receive(
    forensicMessage({ rcptTo: "third@example.com", headers: "" }),
    { arrivedFor: RUF_ADDRESS, now: NOW_MS });
  count("and one this server recorded nothing about is kept and marked like any other",
    unsignedForensic.ok === true && unsignedForensic.authenticated === false &&
    unsignedForensic.authenticity === ingest.AUTHENTICITY.notAuthenticatedHere,
    JSON.stringify(unsignedForensic));
}

// A store that cannot write is the one failure the seam must survive.
// The verb is called from the path an inbound delivery is waiting on, so
// a volume fault has to arrive as a refusal naming itself rather than as
// an exception that costs the message its delivery and loses the reason.
async function aVolumeThatWillNotWriteDoesNotCostTheDelivery(storeHandle) {
  var faulting = Object.assign({}, storeHandle, {
    ingestAggregate: function () {
      var fault = new Error("the volume is not writable");
      fault.code = "db/read-only";
      throw fault;
    },
    ingestForensic: function () {
      var fault = new Error("the volume is not writable");
      fault.code = "db/read-only";
      throw fault;
    },
  });
  var reader = ingest.create(readerBounds(faulting));

  var aggregate = await reader.receive(
    carrier({ contentType: "text/xml", filename: reportFilename("xml"),
      payload: aggregateXml({ reportId: "fault-1" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  count("a store that throws on an aggregate report answers as a refusal, not an exception",
    aggregate.handled === true && aggregate.ok === false &&
    aggregate.reason === ingest.CODES.storeUnavailable &&
    aggregate.detail === "db/read-only",
    JSON.stringify(aggregate));
  // The carrier was judged before the store was asked, and the store
  // failing does not change what the carrier said. Answering with the
  // carrier alone instead reports `reporter-not-named-in-report` for a
  // report that named its reporter and matched it.
  count("and it keeps the judgment reached before the store was asked, verdict, flag and " +
    "domain together",
  aggregate.authenticity === ingest.AUTHENTICITY.verified &&
    aggregate.authenticated === true && aggregate.authenticatedAs === REPORTER &&
    aggregate.entries.length === 1 && aggregate.entries[0].authenticated === true &&
    aggregate.entries[0].authenticity === ingest.AUTHENTICITY.verified,
  JSON.stringify(aggregate));

  var forensic = await reader.receive(forensicMessage({ rcptTo: "fourth@example.com" }),
    { arrivedFor: RUF_ADDRESS, now: NOW_MS });
  count("and so does one that throws on a failure report",
    forensic.handled === true && forensic.ok === false &&
    forensic.reason === ingest.CODES.storeUnavailable,
    JSON.stringify(forensic));

  count("both are counted as refusals rather than passing quietly",
    reader.describe().counts.refused === 2,
    JSON.stringify(reader.describe().counts));
}

// Every value the reader can answer with is in the published set, and
// every published value is one a reader could meet. A vocabulary with a
// member nothing raises is a branch nobody tested.
function thePublishedVocabularyIsTheOneInUse(reader) {
  var published = Object.keys(ingest.CODES).map(function (key) {
    return ingest.CODES[key];
  });
  var seen = reader.recent().map(function (entry) { return entry.reason; })
    .filter(function (reason) { return reason !== null; });
  var unpublished = seen.filter(function (reason) {
    return published.indexOf(reason) === -1;
  });
  // The set has to be non-empty for either half of this to mean
  // anything. An `every` over nothing is true, and a run that reached no
  // refusal at all would report the same verdict as one whose refusals
  // are all published.
  count("this reader reached refusals from both vocabularies, so the test below has a set",
    seen.length > 0 && unpublished.length > 0, JSON.stringify(seen));
  count("and the only ones not published here are the store's own",
    unpublished.every(function (reason) { return reason === "domain-not-hosted"; }),
    JSON.stringify(unpublished));

  var verdicts = Object.keys(ingest.AUTHENTICITY).map(function (key) {
    return ingest.AUTHENTICITY[key];
  });
  var reached = reader.recent().map(function (entry) { return entry.authenticity; })
    .filter(function (value) { return value !== null; });
  count("every authenticity verdict it reached is one the module publishes",
    reached.length > 0 &&
    reached.every(function (value) { return verdicts.indexOf(value) !== -1; }),
    JSON.stringify(reached));
}

// ---- the mark reaches the reading, not only the trail -----------------------

// From a message on the wire to the number a policy is moved on. The
// verdict this reader reaches has to arrive on the rows the store
// writes, because the reading is SQL over those rows: a verdict that
// lived only in the audit trail would be visible to an operator reading
// the trail and invisible to the reading a policy rests on.
//
// Filed against the second hosted domain, so the arithmetic is over what
// this function put on the volume. Each message carries the same report
// body under a different identifier, which the store's uniqueness rule
// needs and the reading never reads, so the Authentication-Results
// header is the only thing the numbers can be tracking. It is changed in
// both directions for that reason.
async function theVerdictReachesTheReadingAPolicyRestsOn(storeHandle) {
  var reader  = ingest.create(readerBounds(storeHandle));
  var records = [
    xmlRecord("203.0.113.10", 7, "pass", "pass", "none"),
    xmlRecord("198.51.100.4", 3, "fail", "fail", "reject"),
  ];
  var CARRIED = 10;
  var ALIGNED = 7;

  function filedUnder(reportId, headers) {
    return reader.receive(
      carrier({ contentType: "text/xml", filename: reportFilename("xml"),
        payload: aggregateXml({ domain: OTHER_DOMAIN, reportId: reportId,
          records: records }),
        headers: headers }),
      { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  }
  function reading(opts) {
    return storeHandle.rollup(Object.assign({ domain: OTHER_DOMAIN }, opts || {}))[0];
  }

  count("nothing has been reported about this domain before any of these arrive",
    storeHandle.rollup({ domain: OTHER_DOMAIN }).length === 0,
    JSON.stringify(storeHandle.rollup({ domain: OTHER_DOMAIN })));

  var open = await filedUnder("wire-open", "");
  count("a report this server recorded nothing about is stored and marked",
    open.ok === true && open.stored === 2 && open.authenticated === false &&
    open.authenticity === ingest.AUTHENTICITY.notAuthenticatedHere,
    JSON.stringify(open));
  var afterOpen = storeHandle.rollup({ domain: OTHER_DOMAIN });
  count("the reading answers about its window rather than losing it",
    afterOpen.length === 1 && afterOpen[0].counted === 0,
    JSON.stringify(afterOpen));
  count("and names the volume it left out",
    afterOpen[0].unauthenticated === CARRIED, JSON.stringify(afterOpen[0]));

  var sealed = await filedUnder("wire-sealed",
    authenticationResults({ dmarc: "pass", from: REPORTER }));
  count("the same report under a carrier that passed counts as evidence",
    sealed.ok === true && sealed.authenticated === true &&
    sealed.authenticity === ingest.AUTHENTICITY.verified,
    JSON.stringify(sealed));
  var afterSealed = reading();
  count("and it is the one the counting moves for",
    afterSealed.counted === CARRIED && afterSealed.aligned === ALIGNED &&
    afterSealed.failingSources === 1, JSON.stringify(afterSealed));
  count("with the volume left out unchanged by it",
    afterSealed.unauthenticated === CARRIED, JSON.stringify(afterSealed));

  var failed = await filedUnder("wire-failed",
    authenticationResults({ dmarc: "fail", from: REPORTER }));
  count("a carrier that failed DMARC is stored under the reason it failed for",
    failed.ok === true && failed.stored === 2 &&
    failed.authenticity === ingest.AUTHENTICITY.dmarcNotPass,
    JSON.stringify(failed));
  var afterFailed = reading();
  count("changing the header back leaves the counting where the passing one put it",
    afterFailed.counted === CARRIED && afterFailed.aligned === ALIGNED &&
    afterFailed.failingSources === 1, JSON.stringify(afterFailed));
  count("and grows what was left out by exactly what that report carried",
    afterFailed.unauthenticated === 2 * CARRIED, JSON.stringify(afterFailed));

  // Read off the rows rather than through the reading, because the
  // reading would answer the same way if the store were writing one
  // verdict for every report and the numbers happened to line up.
  var row = b.db.from(tables.DMARC_REPORTS).where({ reportId: "wire-failed" }).first();
  count("the report row carries the reader's own verdict rather than a flag",
    row !== null && row !== undefined && row.evidence === ingest.AUTHENTICITY.dmarcNotPass,
    JSON.stringify(row && row.evidence));
  var itsRecords = b.db.from(tables.DMARC_RECORDS).where({ reportRowId: row._id }).all();
  count("and every record row copied out of it carries that same value",
    itsRecords.length === 2 && itsRecords.every(function (record) {
      return record.evidence === row.evidence;
    }), JSON.stringify(itsRecords.map(function (record) { return record.evidence; })));
  var passing = b.db.from(tables.DMARC_REPORTS).where({ reportId: "wire-sealed" }).first();
  count("the report that did count carries a different value, so the two are told apart " +
    "on the volume and not only in the answer",
    passing.evidence === tables.REPORT_EVIDENCE_VERIFIED &&
    passing.evidence !== row.evidence,
    passing.evidence + " against " + row.evidence);

  var everything = reading({ includeUnauthenticated: true });
  count("asked to include them the reading covers every report that arrived",
    everything.counted === 3 * CARRIED && everything.aligned === 3 * ALIGNED,
    JSON.stringify(everything));
  count("and still says how much of it nobody authenticated",
    everything.unauthenticated === 2 * CARRIED, JSON.stringify(everything));

  // The failure-report path writes its own rows and reaches its own
  // verdict, so it carries the same mark rather than being the one path
  // where a later reading has nothing to go on.
  var forensic = await reader.receive(forensicMessage({ rcptTo: "rollup@example.com" }),
    { arrivedFor: RUF_ADDRESS, now: NOW_MS });
  var forensicRow = b.db.from(tables.DMARC_FORENSIC)
    .where({ originalRcptTo: "rollup@example.com" }).first();
  count("a failure report's rows carry the verdict its carrier reached",
    forensic.ok === true && forensicRow !== null && forensicRow !== undefined &&
    forensicRow.evidence === ingest.AUTHENTICITY.forensicNoIdentity,
    JSON.stringify(forensic.authenticity) + " on the answer, " +
      JSON.stringify(forensicRow && forensicRow.evidence) + " on the row");
}

// The reader's vocabulary and the column's are two lists of the same
// values, and a value in one and not the other is stored as no verdict
// at all. That failure is silent in both directions: the reader goes on
// answering with it and the reading goes on leaving it out.
function everyVerdictTheReaderProducesIsOneTheColumnAdmits() {
  var produced = Object.keys(ingest.AUTHENTICITY).map(function (key) {
    return ingest.AUTHENTICITY[key];
  });
  var admitted = tables.REPORT_EVIDENCE;
  var strangers = produced.filter(function (value) {
    return admitted.indexOf(value) === -1;
  });
  count("the reader publishes verdicts, so there is a set to hold against the column",
    produced.length > 0 && admitted.length > 0,
    produced.length + " against " + admitted.length);
  count("and the column admits every one of them",
    strangers.length === 0, JSON.stringify(strangers));
  count("the column also admits the value it holds when no verdict reached the write, " +
    "which is one the reader never answers with",
    admitted.indexOf(tables.REPORT_EVIDENCE_NOT_RECORDED) !== -1 &&
    produced.indexOf(tables.REPORT_EVIDENCE_NOT_RECORDED) === -1,
    tables.REPORT_EVIDENCE_NOT_RECORDED);
  count("and the one value the reading counts is one the reader can reach",
    produced.indexOf(tables.REPORT_EVIDENCE_VERIFIED) !== -1,
    tables.REPORT_EVIDENCE_VERIFIED);
}

// ---- the durable half of the mark ------------------------------------------

async function theVerdictIsWrittenWhereALaterReadingCanFindIt(storeHandle) {
  // The backlog every case above left behind, taken before the capture
  // is installed rather than inside it. An emit is fire-and-forget, so
  // the rows those cases wrote drain on the next flush whoever calls it,
  // and a capture installed in front of that drain fills with them. The
  // wait below is then spent reading somebody else's rows, which made
  // this case's budget a function of how much every earlier case emitted:
  // it passed until a case above it sent a few more messages, and the
  // failure named a timeout rather than the coupling.
  await b.audit.flush();
  var capture = helpers.auditCapture();

  // A row is selected by the attachment name the case under test used
  // rather than by position. The emit is fire-and-forget, so a row from
  // an earlier case can still be in flight when this capture is
  // installed, and a wait phrased as a count is satisfied by that one.
  async function rowFor(action, attachment) {
    await helpers.waitUntil(function () {
      return capture.forAction(action).some(function (row) {
        return helpers.metadataOf(row).attachment === attachment;
      });
    }, { timeoutMs: 5000,
      label: "dmarc-report-ingest: the trail row for " + attachment });
    var found = capture.forAction(action).filter(function (row) {
      return helpers.metadataOf(row).attachment === attachment;
    });
    return found[found.length - 1];
  }

  try {
    var reader = ingest.create(readerBounds(storeHandle));

    await reader.receive(
      carrier({ contentType: "text/xml", filename: "trail-verified.xml",
        payload: aggregateXml({ reportId: "trail-1" }),
        headers: authenticationResults({ dmarc: "pass", from: REPORTER }) }),
      { arrivedFor: RUA_ADDRESS, now: NOW_MS });
    var keptRow = await rowFor("blamepost.mail.reports.aggregate_ingested",
      "trail-verified.xml");
    var kept = helpers.metadataOf(keptRow);
    count("a report that counted as evidence leaves a row saying so",
      kept.evidence === true && kept.evidenceVerdict === "verified" &&
      kept.evidenceFor === REPORTER && kept.stored === 2,
      JSON.stringify(kept));

    await reader.receive(
      carrier({ contentType: "text/xml", filename: "trail-unauthenticated.xml",
        payload: aggregateXml({ reportId: "trail-2" }), headers: "" }),
      { arrivedFor: RUA_ADDRESS, now: NOW_MS });
    var openRow = await rowFor("blamepost.mail.reports.aggregate_ingested",
      "trail-unauthenticated.xml");
    var open = helpers.metadataOf(openRow);
    count("and one that did not is stored with a row a later reading can exclude it by",
      open.evidence === false &&
      open.evidenceVerdict === "carrier-not-authenticated-here" && open.stored === 2,
      JSON.stringify(open));
    // The outcome column cannot carry this distinction. The emitter
    // rewrites any value outside its three into one of them, so a row
    // written with a fourth is recorded as a success and nothing says it
    // was changed. Both rows are successful ingests and the field above
    // is what tells them apart, which is asserted here so an author
    // reaching for a fourth outcome finds out from this file.
    count("both stored reports are recorded under the outcome vocabulary that exists",
      keptRow.outcome === "success" && openRow.outcome === "success",
      keptRow.outcome + " then " + openRow.outcome);
    count("and the field that separates them is one the redactor leaves alone",
      kept.evidence === true && open.evidence === false,
      JSON.stringify([kept.evidence, open.evidence]));

    await reader.receive(
      carrier({ contentType: "application/zip", filename: "trail-empty.zip",
        payload: zipOf([]) }),
      { arrivedFor: RUA_ADDRESS, now: NOW_MS });
    var refusal = helpers.metadataOf(
      await rowFor("blamepost.mail.reports.refused", "trail-empty.zip"));
    count("a refusal leaves a row naming the reason rather than going quiet",
      refusal.reason === ingest.CODES.containerEmpty, JSON.stringify(refusal));

    // The store refuses this report after the reader has judged its
    // carrier. The row carries the verdict and the flag that says whether
    // the verdict counts as evidence, and the two have to agree: a row
    // reading `evidence: false` beside `evidenceVerdict: "verified"` tells
    // an operator two opposite things about one message.
    var judged = await reader.receive(
      carrier({ contentType: "text/xml", filename: "trail-judged-unhosted.xml",
        payload: aggregateXml({ domain: UNHOSTED_DOMAIN, reportId: "trail-judged-1" }),
        headers: authenticationResults({ dmarc: "pass", from: REPORTER }) }),
      { arrivedFor: RUA_ADDRESS, now: NOW_MS });
    count("a report from a verified carrier that the store refuses is answered as that refusal",
      judged.handled === true && judged.ok === false && judged.reason === "domain-not-hosted",
      JSON.stringify(judged));
    count("and the answer says the carrier was verified and counts as evidence, together",
      judged.authenticity === ingest.AUTHENTICITY.verified && judged.authenticated === true &&
      judged.authenticatedAs === REPORTER && judged.entries.length === 1 &&
      judged.entries[0].authenticated === true &&
      judged.entries[0].authenticity === ingest.AUTHENTICITY.verified,
      JSON.stringify(judged));
    var judgedRow = helpers.metadataOf(
      await rowFor("blamepost.mail.reports.refused", "trail-judged-unhosted.xml"));
    count("and the refusal row's evidence flag agrees with the verdict written beside it",
      judgedRow.evidence === true && judgedRow.evidenceVerdict === "verified" &&
      judgedRow.evidenceFor === REPORTER && judgedRow.reason === "domain-not-hosted",
      JSON.stringify(judgedRow));
  } finally {
    capture.release();
  }
}

async function aHostileAttachmentNameIsNotPrintedAsItArrived(storeHandle) {
  var reader = ingest.create(readerBounds(storeHandle));
  await reader.receive(
    carrier({ contentType: "text/xml", filename: "report" + BIDI_OVERRIDE + "fdp.xml",
      payload: aggregateXml({ reportId: "hostile-name-1" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  var printed = JSON.stringify(reader.recent());
  count("an attachment name carrying a bidi override does not reach the reader's own answer",
    printed.indexOf(BIDI_OVERRIDE) === -1, printed.slice(0, 160));

  // The same claim for the C1 range, which the reader refuses through
  // the same screen and which the range above stopped short of. A
  // reporter chooses the attachment name, so a name carrying U+009B is a
  // reporter deciding what the console does when an operator reads the
  // verdict back.
  await reader.receive(
    carrier({ contentType: "text/xml",
      filename: "report" + C1_CSI + "31m.xml",
      payload: aggregateXml({ reportId: "hostile-name-2" }) }),
    { arrivedFor: RUA_ADDRESS, now: NOW_MS });
  var withC1 = JSON.stringify(reader.recent());
  count("and neither does one carrying the single-byte control sequence introducer",
    withC1.indexOf(C1_CSI) === -1, withC1.slice(0, 200));

  // Over the whole alphabet rather than over the two characters this
  // case happened to send, and over the verdicts of the reader that
  // actually received them. The same assertion runs on the main reader,
  // whose messages carry no hostile name at all, so a range widened
  // there alone would be a check over an alphabet nothing in the run
  // produces.
  count("so nothing a reporter chose reaches a console with a control character in it, " +
    "across the C0 range, the delete code point and the C1 range together",
  CONTROL_RANGE.test(withC1) === false, withC1.slice(0, 200));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dmarc-ingest");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    // The store refuses to open without this: it decrypts a working copy
    // of the database and will not put one somewhere it was not told to.
    process.env.BLAMEJS_TMPDIR = workDir;

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    await store.open(cfg);

    var storeHandle = storeReports.create(storeBounds());

    theFactoryRefusesWhatItCannotActOn(storeHandle);

    var reader = ingest.create(readerBounds(storeHandle));

    await mailForSomebodyElseIsPassedOver(reader);
    await everyContainerAReporterSendsIsOpened(reader);
    await theBytesDecideTheContainer(reader);
    await theExpansionBoundIsThisReadersOwn(reader);
    await theContainerBoundHoldsOnEveryContainer(storeHandle);
    await everyArchiveShapeEndsSomewhereDefinite(reader);
    await theShippedVerdictWritesTheAddressForm();
    await evidenceIsSeparatedFromWhatAnybodyCouldHaveSent(reader);
    await theSeamCannotTellAPeerFromAnAccountHolder(reader);
    await aRefusalNeverEscapesTheSeam(reader);
    await theCarrierPartCountIsBounded(storeHandle);
    await whatIsKeptForReadingBackIsTrimmed(storeHandle);
    await aMessageThisReaderWillNotOpenIsRefusedLoud(storeHandle);
    await everyPublishedRefusalIsReachable(storeHandle);
    await aVolumeThatWillNotWriteDoesNotCostTheDelivery(storeHandle);
    await theVerdictReachesTheReadingAPolicyRestsOn(storeHandle);
    everyVerdictTheReaderProducesIsOneTheColumnAdmits();
    whatWentPastIsReadableWithoutTrustingIt(reader);
    thePublishedVocabularyIsTheOneInUse(reader);
    await theVerdictIsWrittenWhereALaterReadingCanFindIt(storeHandle);
    await aHostileAttachmentNameIsNotPrintedAsItArrived(storeHandle);

    return helpers.getChecks();
  } finally {
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "dmarc-report-ingest",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
