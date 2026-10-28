// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What this server keeps when a peer sends it a DMARC report, and what
 * it refuses to keep at all.
 *
 * An aggregate report is a peer's account of mail that claimed one of
 * this server's domains. A forensic report is the same claim about a
 * single message, and it arrives carrying that message: a real subject
 * line, a real From header and often the body, belonging to somebody
 * who has no account here and was never told this server would hold
 * their mail. The rules below are written as the failures they stop.
 *
 *   - a reporter that sends the same report twice leaves one row, and
 *     two reporters that both number a report `0001` leave two;
 *   - the volume and alignment an operator reads back are computed from
 *     the stored rows and agree with the reporter's own totals;
 *   - a report whose carrier this server did not authenticate is stored
 *     and left out of that reading, with the volume it carried named
 *     beside the counting rather than quietly missing from it;
 *   - a row carrying no verdict at all, which is what a row written
 *     before the column existed carries, is left out on the same terms;
 *   - a report holding one unusable record stores the rest and counts
 *     the one it refused, because five hundred records must not be lost
 *     to one;
 *   - rows are destroyed once their window passes and not one sweep
 *     before it, with the forensic window the shorter of the two;
 *   - an erasure request from somebody with no account here reaches
 *     their rows and leaves a trail saying so;
 *   - and the reported message never reaches the volume at all, on any
 *     setting, which is asserted against the bytes rather than against
 *     the intention.
 *
 * Real database, real sealed columns, real vault, temporary data
 * directory. No sockets: the reader is handed the report bytes, which
 * is the shape the mailbox filing seam hands it.
 *
 * Run standalone: node test/layer-1-state/dmarc-report-store.test.js
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var b          = require("../../lib/vendor/blamejs");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var auditActor = require("../../lib/store/actor");
var reports    = require("../../lib/store/reports");
var tables     = require("../../lib/store/tables");

// The shared assertion, so a failure line reads the same as every other
// file's and the runner's total covers every check made here.
var count = helpers.count;

var HOSTNAME         = "mx.example.com";
var DOMAIN           = "example.com";
var OTHER_DOMAIN     = "example.net";
// A third hosted domain, so the two listing verbs are measured over rows
// their own functions filed. The counting tests above share a volume, and
// an ordering assertion read across everything on it would be an
// assertion about what ran first.
var LISTED_DOMAIN    = "example.org";
// A name no report on this volume mentions. Both listings narrow to a
// domain, and a request for one nothing was reported about has to answer
// with nothing rather than with everything, which is the failure a
// filter that was accepted and never applied produces.
var UNREPORTED_DOMAIN = "quiet.example";
// A fourth hosted domain, where one sender is named by an authenticated
// report in one window and by an unauthenticated one in another. Every
// figure the counted reading carries about that sender has to come from
// the first window alone, and a figure that quietly took both is a number
// a stranger moved.
var MIXED_DOMAIN     = "mixed.example";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var DAY_MS  = 86400000;
var HOUR_MS = 3600000;

// The window the fixture reports cover, fixed so the arithmetic below is
// written against numbers rather than against whatever the clock said.
var WINDOW_BEGIN_SEC = 1750000000;
var WINDOW_END_SEC   = WINDOW_BEGIN_SEC + 86400;

// A string that appears only inside the reported message of the forensic
// fixture. Every table is searched for it afterwards, in the sealed form
// the rows are actually stored in, so the assertion is about bytes on
// the volume rather than about which field name was chosen.
var BODY_MARKER = "reported-body-marker-4f7a2c19";

// The subject of the stranger's message, which the parser hands back
// under reportedHeaders. It is searched for on the same terms.
var HEADER_MARKER = "stranger-subject-marker-8b31de5c";

// What the stored cells are joined with when they are searched as one
// string. A newline cannot appear inside either marker and keeps the
// joined text readable when a failure prints it.
var CELL_SEPARATOR = "\n";

// What a caller hands the ingest verbs about the message that carried a
// report. Every ingest below says which one it is rather than leaving it
// out, because leaving it out is itself a third answer and one of the
// cases under test.
var AUTHENTICATED   = { evidence: tables.REPORT_EVIDENCE_VERIFIED };
var UNAUTHENTICATED = { evidence: "carrier-dmarc-not-pass" };

// A verdict the column does not admit, which is what a caller reaches
// with a value from somewhere other than the declared set.
var UNDECLARED = { evidence: "carrier-was-fine-honestly" };

// The report the exclusion is measured on: ten messages, seven of them
// aligned, one sending address failing on both identifiers. Filed
// several times over with nothing changed but the carrier verdict and
// the identifier the store's uniqueness rule needs.
var MEASURED_MESSAGES = 10;
var MEASURED_ALIGNED  = 7;

// The senders the two listing verbs are measured on, and the volume each
// one failed on. The numbers are chosen so that no order the volume was
// filed in produces the order the answer has to come back in: the three
// go onto the volume as 40, 90, 65 and have to read back as 90, 65, 40,
// which is neither the order they arrived in nor its reverse. A listing
// that forgot to sort, or sorted on the row identifier, cannot pass by
// luck.
var QUIET_SOURCE    = "198.51.100.20";
var LOUD_SOURCE     = "198.51.100.21";
var MIDDLE_SOURCE   = "198.51.100.22";
var QUIET_FAILED    = 40;
var LOUD_FAILED     = 90;
var MIDDLE_FAILED   = 65;

// A sender whose mail aligned. It is in the same reports as the three
// above and must never appear in a list of what is failing.
var ALIGNED_SOURCE   = "203.0.113.30";
var ALIGNED_MESSAGES = 5;

// A sender that appears only in a report this server did not
// authenticate, and the largest volume in the fixture. Anybody who can
// send mail to a published reporting address can name an address and a
// number, so this is the row that decides whether the listing is
// evidence or a repetition of what a stranger wrote.
var FORGED_SOURCE   = "198.51.100.99";
var FORGED_MESSAGES = 500;

// The moment the reports named below are stored at, taken once so the
// reading of when a reporter was last heard from is an assertion about
// numbers rather than about the clock. It has to be a moment inside the
// retention window rather than the window the reports cover: what these
// rows are stored at is what decides when the sweep destroys them, and
// the sweep runs later in this same file.
var LISTED_AT = Date.now();

// The bounds a composed handle is built with here. They are the shape
// this module expects to be handed rather than anything it reads for
// itself, and they are short so a sweep can be driven across a window
// inside one run.
function boundsFor(overrides) {
  return Object.assign({
    aggregateRetentionMs: 7 * DAY_MS,
    forensicRetentionMs:  HOUR_MS,
    sweepIntervalMs:      HOUR_MS,
    forensicEnabled:      true,
    hostedDomain:         function (name) {
      return name === DOMAIN || name === OTHER_DOMAIN ||
        name === LISTED_DOMAIN || name === MIXED_DOMAIN;
    },
  }, overrides || {});
}

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

function aggregateXml(opts) {
  var org      = opts.org || "reporter.example";
  var reportId = opts.reportId || "0001";
  var domain   = opts.domain || DOMAIN;
  var begin    = opts.begin || WINDOW_BEGIN_SEC;
  var end      = opts.end || WINDOW_END_SEC;
  var records  = opts.records || [
    xmlRecord("203.0.113.10", 7, "pass", "pass", "none"),
    xmlRecord("198.51.100.4", 3, "fail", "fail", "reject"),
    xmlRecord("198.51.100.9", 5, "fail", "fail", "reject"),
    xmlRecord("203.0.113.77", 2, "fail", "pass", "none"),
  ];
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>" + org + "</org_name>\n" +
    "    <email>dmarc-noreply@" + org + "</email>\n" +
    "    <report_id>" + reportId + "</report_id>\n" +
    "    <date_range><begin>" + begin + "</begin><end>" + end + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + domain + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>reject</p><sp>reject</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    records.join("") +
    "</feedback>\n";
}

function forensicMessage(opts) {
  opts = opts || {};
  var mailFrom  = opts.mailFrom || "stranger@third-party.example";
  var rcptToAll = opts.rcptTo || ["victim@reporter.example"];
  var reported  = opts.reportedDomain || DOMAIN;
  var arrival   = opts.arrival || "Mon, 01 Sep 2025 09:00:00 +0000";
  var rcptLines = rcptToAll.map(function (one) {
    return "Original-Rcpt-To: " + one + "\r\n";
  }).join("");
  return "From: dmarc-noreply@reporter.example\r\n" +
    "To: ruf@" + reported + "\r\n" +
    "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd42\"\r\n" +
    "\r\n" +
    "--bnd42\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "An authentication failure report.\r\n" +
    "\r\n" +
    "--bnd42\r\n" +
    "Content-Type: message/feedback-report\r\n" +
    "\r\n" +
    "Feedback-Type: auth-failure\r\n" +
    "User-Agent: Reporter/1.0\r\n" +
    "Version: 1\r\n" +
    "Auth-Failure: dmarc\r\n" +
    "Original-Mail-From: " + mailFrom + "\r\n" +
    rcptLines +
    "Arrival-Date: " + arrival + "\r\n" +
    "Reported-Domain: " + reported + "\r\n" +
    "Source-IP: 203.0.113.99\r\n" +
    "Delivery-Result: reject\r\n" +
    "Identity-Alignment: none\r\n" +
    "DKIM-Domain: " + reported + "\r\n" +
    "DKIM-Selector: s1\r\n" +
    "SPF-DNS: v=spf1 -all\r\n" +
    "Authentication-Results: mx.reporter.example; dmarc=fail header.from=" + reported + "\r\n" +
    "Reported-URI: https://phish.example/" + BODY_MARKER + "\r\n" +
    "\r\n" +
    "--bnd42\r\n" +
    "Content-Type: message/rfc822\r\n" +
    "\r\n" +
    "From: \"Someone Real\" <" + mailFrom + ">\r\n" +
    "To: " + rcptToAll[0] + "\r\n" +
    "Subject: " + HEADER_MARKER + "\r\n" +
    "\r\n" +
    BODY_MARKER + "\r\n" +
    "\r\n" +
    "--bnd42--\r\n";
}

// ---- helpers over the volume -----------------------------------------------

// Every stored cell of the three tables, as SQLite holds it. Read through
// the raw statement rather than the chainable query on purpose: the
// chainable one unseals, and what has to be searched for the marker is
// the ciphertext and the cleartext alike.
function everyStoredCell() {
  var names = [
    tables.DMARC_REPORTS,
    tables.DMARC_RECORDS,
    tables.DMARC_FORENSIC,
  ];
  var text = [];
  for (var t = 0; t < names.length; t += 1) {
    var rows = b.db.prepare("SELECT * FROM " + names[t]).all();
    for (var r = 0; r < rows.length; r += 1) {
      var row = rows[r];
      var keys = Object.keys(row);
      for (var k = 0; k < keys.length; k += 1) {
        var value = row[keys[k]];
        if (value === null || value === undefined) continue;
        text.push(String(value));
      }
    }
  }
  return text.join(CELL_SEPARATOR);
}

function declaredColumnsOf(table) {
  return b.db.getDeclaredColumns(table) || [];
}

function refusesWith(label, code, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "accepted" : String(thrown.code) + " " + String(thrown.message));
  return thrown;
}

// The same assertion for a verb that settles a promise. An async
// function reports a refusal as a rejection rather than as a throw, so
// the synchronous form above would record every one of them as accepted.
async function refusesAsyncWith(label, code, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null && thrown.code === code,
    thrown === null ? "accepted" : String(thrown.code) + " " + String(thrown.message));
  return thrown;
}

// ---- the factory refuses bounds it cannot act on ---------------------------

function theFactoryRefusesBoundsItCannotActOn() {
  refusesWith("a handle built with no aggregate window is refused",
    "store/bad-reports-opts", function () {
      reports.create(boundsFor({ aggregateRetentionMs: undefined }));
    });
  refusesWith("a forensic window longer than the aggregate one is refused",
    "store/bad-reports-opts", function () {
      reports.create(boundsFor({ forensicRetentionMs: 30 * DAY_MS,
        aggregateRetentionMs: 7 * DAY_MS }));
    });
  refusesWith("a sweep interval of zero is refused",
    "store/bad-reports-opts", function () {
      reports.create(boundsFor({ sweepIntervalMs: 0 }));
    });
  refusesWith("a handle with no way to ask whether a domain is hosted is refused",
    "store/bad-reports-opts", function () {
      reports.create(boundsFor({ hostedDomain: null }));
    });

  var handle = reports.create(boundsFor());
  var shape = handle.describe();
  count("the handle publishes the windows it was handed",
    shape.aggregateRetentionMs === 7 * DAY_MS && shape.forensicRetentionMs === HOUR_MS,
    JSON.stringify(shape));
  count("and says whether it will keep forensic rows at all",
    shape.forensicEnabled === true, JSON.stringify(shape));
}

// ---- one report stored once ------------------------------------------------

function aResentReportLeavesOneRow(handle) {
  var first = handle.ingestAggregate(aggregateXml({}), AUTHENTICATED);
  count("a report this server has not seen is stored",
    first.ok === true && first.duplicate === false && first.stored === 4,
    JSON.stringify(first));

  var again = handle.ingestAggregate(aggregateXml({}), AUTHENTICATED);
  count("the same reporting organization resending the same report id stores nothing more",
    again.ok === true && again.duplicate === true && again.stored === 0,
    JSON.stringify(again));
  count("and it names the row already holding that report",
    again.reportRowId === first.reportRowId,
    String(again.reportRowId) + " vs " + String(first.reportRowId));

  count("so one report row is on the volume",
    b.db.from(tables.DMARC_REPORTS).count() === 1,
    String(b.db.from(tables.DMARC_REPORTS).count()));
  count("and its records were not stored twice",
    b.db.from(tables.DMARC_RECORDS).count() === 4,
    String(b.db.from(tables.DMARC_RECORDS).count()));

  // The half a report id alone cannot answer. Two reporters number their
  // reports independently, so a key that is only the id would silently
  // discard the second organization's whole report.
  var other = handle.ingestAggregate(
    aggregateXml({ org: "second.example", reportId: "0001" }), AUTHENTICATED);
  count("a different reporting organization using the same report id is not a duplicate",
    other.ok === true && other.duplicate === false && other.stored === 4,
    JSON.stringify(other));
  count("and both reports are held",
    b.db.from(tables.DMARC_REPORTS).count() === 2,
    String(b.db.from(tables.DMARC_REPORTS).count()));
}

// ---- one bad record does not cost the report -------------------------------

function oneUnusableRecordDoesNotDiscardTheRest(handle) {
  var mixed = handle.ingestAggregate(aggregateXml({
    org:      "third.example",
    reportId: "0002",
    records:  [
      xmlRecord("203.0.113.10", 4, "pass", "pass", "none"),
      xmlRecord("not an address at all", 5, "fail", "fail", "none"),
      xmlRecord("198.51.100.4", 6, "fail", "fail", "reject"),
      xmlRecord("203.0.113.20", -1, "pass", "pass", "none"),
    ],
  }), AUTHENTICATED);
  count("a report carrying two unusable records stores the other two",
    mixed.ok === true && mixed.stored === 2, JSON.stringify(mixed));
  count("and the refusals are counted rather than thrown",
    mixed.refused.length === 2, JSON.stringify(mixed.refused));
  count("each naming the record it refused and why",
    mixed.refused[0].index === 1 && mixed.refused[0].reason === "source-ip-refused" &&
      mixed.refused[1].index === 3 && mixed.refused[1].reason === "message-count-refused",
    JSON.stringify(mixed.refused));
  count("the report row records how many it could not take",
    b.db.from(tables.DMARC_REPORTS).where({ reportId: "0002" }).first().refusedCount === 2,
    JSON.stringify(b.db.from(tables.DMARC_REPORTS).where({ reportId: "0002" }).first()));

  // A report about a domain nobody here answers for is not evidence
  // about anything this server sends, and taking it would let any peer
  // choose how much of this volume a report occupies.
  var foreign = handle.ingestAggregate(aggregateXml({
    org: "fourth.example", reportId: "0003", domain: "not-hosted.example",
  }));
  count("a report about a domain this server does not host is refused whole",
    foreign.ok === false && foreign.reason === "domain-not-hosted",
    JSON.stringify(foreign));

  var garbage = handle.ingestAggregate("<feedback><nothing/></feedback>");
  count("a report that is not a report is refused with a reason rather than a throw",
    garbage.ok === false && typeof garbage.reason === "string",
    JSON.stringify(garbage));
}

// The two fields a reporter names itself with are printed straight into a
// console table beside a count, and a report is a stranger's bytes. The
// screen in front of them refuses the C0 range and the delete code point,
// and U+009B sits above both: it is the single-byte form of CSI, so a
// terminal printing it acts on the rest of the line rather than showing
// it. A row holding one is a row every later reader has to remember to
// screen, so it is refused on the way in.
//
// Written from its code point, because a C1 octet does not survive being
// typed into a source file.
var C1_CSI = String.fromCharCode(0x9b);

function aReporterNamingItselfWithAControlCharacterIsRefused(handle) {
  var named = handle.ingestAggregate(aggregateXml({
    org: "reporter.example" + C1_CSI + "31m", reportId: "0011",
  }));
  count("a report whose organization name carries a C1 control is refused whole",
    named.ok === false && named.reason === "reporting-organization-refused",
    JSON.stringify(named));

  var numbered = handle.ingestAggregate(aggregateXml({
    org: "eleventh.example", reportId: "0012" + C1_CSI + "2K",
  }));
  count("and so is one whose report identifier carries it",
    numbered.ok === false && numbered.reason === "report-identifier-refused",
    JSON.stringify(numbered));

  var stored = b.db.from(tables.DMARC_REPORTS).all().filter(function (row) {
    return String(row.orgName || "").indexOf(C1_CSI) !== -1 ||
      String(row.reportId || "").indexOf(C1_CSI) !== -1;
  });
  count("and no row on the volume holds one",
    stored.length === 0, JSON.stringify(stored).slice(0, 300));

  // Neither refusal stored anything, which is what keeps this case out of
  // the counting the rest of this file measures. A reporter naming itself
  // in an ordinary way is taken, and the cases either side of this one
  // are where that is measured.
  count("a refused report leaves no record rows behind either",
    b.db.from(tables.DMARC_RECORDS).all().filter(function (row) {
      return String(row.reportRowId || "").indexOf("0011") !== -1;
    }).length === 0, "record rows were written for a report that was refused whole");
}

// ---- the reading an operator acts on ---------------------------------------

function theRollupCountsWhatWasStored(handle) {
  var rows = handle.rollup({ domain: DOMAIN });
  var window = rows.filter(function (row) {
    return row.windowBegin === WINDOW_BEGIN_SEC * 1000;
  });
  count("the rollup answers one row per domain and window",
    window.length === 1, JSON.stringify(rows));

  var only = window[0];
  // Three reports were taken for this window. Two hold the four-record
  // fixture (7 + 3 + 5 + 2 = 17 each) and the third holds the two records
  // it could take (4 + 6 = 10).
  count("counted volume is the sum of the records stored",
    only.counted === 17 + 17 + 10, JSON.stringify(only));
  // Aligned is a message that passed on either identifier, which is the
  // rule RFC 7489 section 4.2 states and the reporter already applied.
  count("aligned volume counts a message passing on either identifier",
    only.aligned === (7 + 2) + (7 + 2) + 4, JSON.stringify(only));
  count("and unaligned is the remainder rather than a second count",
    only.unaligned === only.counted - only.aligned, JSON.stringify(only));
  // 198.51.100.4 and 198.51.100.9 fail both, and 198.51.100.4 appears in
  // three of the reports. What an operator needs is how many senders are
  // failing, not how many report rows mention one.
  count("distinct sources failing both alignments counts senders rather than rows",
    only.failingSources === 2, JSON.stringify(only));
  count("and every one of the three was authenticated, so the reading left nothing out",
    only.unauthenticated === 0, JSON.stringify(only));

  var narrowed = handle.rollup({ domain: OTHER_DOMAIN });
  count("a domain with no reports rolls up to nothing rather than to everything",
    narrowed.length === 0, JSON.stringify(narrowed));

  // The unfiltered reading is a different statement, and a domain
  // filter that was quietly ignored would make the two identical while
  // both looked right.
  var everywhere = handle.rollup({});
  count("asked about no domain in particular it answers about every one reported on",
    everywhere.length === rows.length, JSON.stringify(everywhere));

  var outside = handle.rollup({ domain: DOMAIN, since: WINDOW_END_SEC * 1000 + 1 });
  count("a window that ends before the reading begins is not in it",
    outside.length === 0, JSON.stringify(outside));

  refusesWith("a rollup asked for a name that is not a domain refuses",
    "store/bad-domain", function () { handle.rollup({ domain: "not a domain" }); });
  refusesWith("a rollup asked for a moment that is not one refuses",
    "store/bad-reports-opts", function () { handle.rollup({ since: "yesterday" }); });
}

// ---- what the reading leaves out -------------------------------------------

// The counting a policy is moved on covers the reports this server
// authenticated and nothing else. Everything here is filed against a
// second hosted domain, so the arithmetic is over rows this function put
// on the volume rather than over what ran before it.
//
// Each report carries the same two records under a different identifier,
// which the store's uniqueness rule needs and the reading never looks
// at. So the carrier verdict is the only thing about them that changes,
// and it changes in both directions: a reading that tracked the order
// they arrived in, or the fixture, would move where this says it does
// not.
function theRollupLeavesOutWhatNobodyAuthenticated(handle) {
  var records = [
    xmlRecord("203.0.113.10", 7, "pass", "pass", "none"),
    xmlRecord("198.51.100.4", 3, "fail", "fail", "reject"),
  ];
  function reportNumbered(reportId) {
    return aggregateXml({ org: "seventh.example", reportId: reportId,
      domain: OTHER_DOMAIN, records: records });
  }
  function reading(opts) {
    return handle.rollup(Object.assign({ domain: OTHER_DOMAIN }, opts || {}))[0];
  }

  count("nothing has been reported about this domain before any of these are filed",
    handle.rollup({ domain: OTHER_DOMAIN }).length === 0,
    JSON.stringify(handle.rollup({ domain: OTHER_DOMAIN })));

  var open = handle.ingestAggregate(reportNumbered("0100"), UNAUTHENTICATED);
  count("a report nobody authenticated is stored like any other",
    open.ok === true && open.stored === 2, JSON.stringify(open));

  var afterOpen = handle.rollup({ domain: OTHER_DOMAIN });
  count("the window answers in a row of its own rather than dropping out of the reading",
    afterOpen.length === 1, JSON.stringify(afterOpen));
  count("and none of what it carried is counted",
    afterOpen[0].counted === 0 && afterOpen[0].aligned === 0 &&
    afterOpen[0].unaligned === 0 && afterOpen[0].failingSources === 0,
    JSON.stringify(afterOpen[0]));
  count("while the volume the reading left out is named beside the counting",
    afterOpen[0].unauthenticated === MEASURED_MESSAGES, JSON.stringify(afterOpen[0]));

  handle.ingestAggregate(reportNumbered("0101"), AUTHENTICATED);
  var sealed = reading();
  count("the authenticated report is the one the counting moves for",
    sealed.counted === MEASURED_MESSAGES && sealed.aligned === MEASURED_ALIGNED &&
    sealed.unaligned === MEASURED_MESSAGES - MEASURED_ALIGNED,
    JSON.stringify(sealed));
  count("distinct failing senders are counted over the authenticated report alone",
    sealed.failingSources === 1, JSON.stringify(sealed));
  count("and the volume left out does not move for it",
    sealed.unauthenticated === MEASURED_MESSAGES, JSON.stringify(sealed));

  handle.ingestAggregate(reportNumbered("0102"), UNAUTHENTICATED);
  var third = reading();
  count("changing the verdict back leaves the counting where the authenticated one put it",
    third.counted === MEASURED_MESSAGES && third.aligned === MEASURED_ALIGNED &&
    third.failingSources === 1, JSON.stringify(third));
  count("and grows what was left out by exactly what that report carried",
    third.unauthenticated === 2 * MEASURED_MESSAGES, JSON.stringify(third));

  var silent = handle.ingestAggregate(reportNumbered("0103"));
  count("a report filed with no verdict at all is stored",
    silent.ok === true && silent.stored === 2, JSON.stringify(silent));
  count("and it is left out, because saying nothing about a carrier is not evidence",
    reading().counted === MEASURED_MESSAGES &&
    reading().unauthenticated === 3 * MEASURED_MESSAGES,
    JSON.stringify(reading()));

  handle.ingestAggregate(reportNumbered("0104"), UNDECLARED);
  count("and so is one filed under a verdict the column does not admit",
    reading().counted === MEASURED_MESSAGES &&
    reading().unauthenticated === 4 * MEASURED_MESSAGES,
    JSON.stringify(reading()));

  var undeclared = b.db.from(tables.DMARC_REPORTS).where({ reportId: "0104" }).first();
  count("the row holds the value the column admits rather than the one it was handed",
    undeclared.evidence === tables.REPORT_EVIDENCE_NOT_RECORDED,
    JSON.stringify(undeclared.evidence) + " from " + JSON.stringify(UNDECLARED.evidence));

  // The copy on the record rows is what the reading groups over, so a
  // report row holding one verdict and its records holding another is
  // the failure the whole denormalization can produce.
  var authenticatedRow = b.db.from(tables.DMARC_REPORTS).where({ reportId: "0101" }).first();
  count("the report row carries the verdict it was filed under",
    authenticatedRow.evidence === tables.REPORT_EVIDENCE_VERIFIED,
    JSON.stringify(authenticatedRow.evidence));
  var itsRecords = b.db.from(tables.DMARC_RECORDS)
    .where({ reportRowId: authenticatedRow._id }).all();
  count("and every record row copied out of it carries that same value",
    itsRecords.length === 2 && itsRecords.every(function (row) {
      return row.evidence === authenticatedRow.evidence;
    }), JSON.stringify(itsRecords.map(function (row) { return row.evidence; })));

  var everything = reading({ includeUnauthenticated: true });
  count("asked to include them the counting covers every report that arrived",
    everything.counted === 5 * MEASURED_MESSAGES &&
    everything.aligned === 5 * MEASURED_ALIGNED, JSON.stringify(everything));
  count("and it still says how much of that nobody authenticated",
    everything.unauthenticated === 4 * MEASURED_MESSAGES, JSON.stringify(everything));
  count("anything short of an explicit true leaves them out",
    reading({ includeUnauthenticated: "yes" }).counted === MEASURED_MESSAGES,
    JSON.stringify(reading({ includeUnauthenticated: "yes" })));
}

// A record row with no evidence field on it at all, which is the shape a
// row already on the volume had when this column was added to the table.
// The dangerous answer is the one where that row reads as authenticated,
// so it is driven rather than reasoned about.
function aRowFromBeforeTheColumnIsNotReadAsEvidence(handle) {
  var before = handle.rollup({ domain: OTHER_DOMAIN })[0];
  var written = tables.insertRow(tables.DMARC_RECORDS, {
    reportRowId:  "a-report-row-written-before-the-column",
    policyDomain: OTHER_DOMAIN,
    windowBegin:  WINDOW_BEGIN_SEC * 1000,
    windowEnd:    WINDOW_END_SEC * 1000,
    sourceIp:     "203.0.113.200",
    messageCount: 11,
    disposition:  "none",
    alignedDkim:  "pass",
    alignedSpf:   "pass",
    receivedAt:   Date.now(),
  });
  var held = b.db.prepare("SELECT evidence FROM " + tables.DMARC_RECORDS +
    " WHERE _id = ?").all(written._id);
  count("a row written with no verdict on it takes the declared default",
    held.length === 1 && held[0].evidence === tables.REPORT_EVIDENCE_NOT_RECORDED,
    JSON.stringify(held));
  count("and that default is not the value the reading counts",
    tables.REPORT_EVIDENCE_NOT_RECORDED !== tables.REPORT_EVIDENCE_VERIFIED,
    tables.REPORT_EVIDENCE_NOT_RECORDED + " against " + tables.REPORT_EVIDENCE_VERIFIED);

  var after = handle.rollup({ domain: OTHER_DOMAIN })[0];
  count("so the counting does not move for it",
    after.counted === before.counted && after.aligned === before.aligned,
    JSON.stringify(after));
  count("and its volume joins what the reading says it left out",
    after.unauthenticated === before.unauthenticated + 11, JSON.stringify(after));
}

// ---- the ceilings are ceilings ---------------------------------------------

// ---- the senders a reading names, and the ones it must not -----------------

// A count of failing senders tells an operator that something is wrong.
// The list is what they act on, and what goes into it is the whole
// question. Anybody who can send mail to a published reporting address
// can compose a report naming an address and a number, so a list
// assembled from reports nobody authenticated is a list of machines a
// stranger chose, handed to an operator who is about to change a policy
// over it.
//
// So the discriminating case is two senders failing on both identifiers,
// one of them in a report this server authenticated and the other only in
// a report it did not, and the answer has to name the first and not the
// second.
async function theFailingSourceListNamesOnlyAuthenticatedSenders(handle) {
  var capture = helpers.auditCapture();
  try {
    // Filed in an order the answer must not preserve, and with one sender
    // that aligned sitting among them.
    var counted = handle.ingestAggregate(aggregateXml({
      org:      "alpha.example",
      reportId: "0200",
      domain:   LISTED_DOMAIN,
      records:  [
        xmlRecord(QUIET_SOURCE,   QUIET_FAILED,     "fail", "fail", "reject"),
        xmlRecord(LOUD_SOURCE,    LOUD_FAILED,      "fail", "fail", "reject"),
        xmlRecord(MIDDLE_SOURCE,  MIDDLE_FAILED,    "fail", "fail", "reject"),
        xmlRecord(ALIGNED_SOURCE, ALIGNED_MESSAGES, "pass", "pass", "none"),
      ],
    }), { evidence: tables.REPORT_EVIDENCE_VERIFIED, authenticatedAs: "alpha.example",
      now: LISTED_AT });
    count("the report the listing is measured on was stored whole",
      counted.ok === true && counted.stored === 4, JSON.stringify(counted));

    var forged = handle.ingestAggregate(aggregateXml({
      org:      "beta.example",
      reportId: "0201",
      domain:   LISTED_DOMAIN,
      records:  [xmlRecord(FORGED_SOURCE, FORGED_MESSAGES, "fail", "fail", "reject")],
    }), { evidence: "carrier-dmarc-not-pass", now: LISTED_AT + 1000 });
    count("and the report nobody authenticated was stored like any other",
      forged.ok === true && forged.stored === 1, JSON.stringify(forged));

    // Driven inside a scope that establishes who is acting, which is what
    // the console and the command line both do. A row saying an address
    // was disclosed and naming nobody answers nothing later.
    var listed = await auditActor.runAs(auditActor.forCommandLine(), function () {
      return handle.failingSources({ domain: LISTED_DOMAIN });
    });
    var named = listed.sources.map(function (one) { return one.sourceIp; });

    count("the failing senders are named rather than counted",
      named.length === 3, JSON.stringify(named));
    count("a sender that failed in a report this server authenticated is named",
      named.indexOf(LOUD_SOURCE) !== -1 && named.indexOf(MIDDLE_SOURCE) !== -1 &&
      named.indexOf(QUIET_SOURCE) !== -1, JSON.stringify(named));
    count("a sender that failed only in a report nobody authenticated is not named",
      named.indexOf(FORGED_SOURCE) === -1, JSON.stringify(named));
    count("and a sender whose mail aligned is not a failing sender at all",
      named.indexOf(ALIGNED_SOURCE) === -1, JSON.stringify(named));

    count("the list is ordered by the volume each sender failed on",
      named[0] === LOUD_SOURCE && named[1] === MIDDLE_SOURCE &&
      named[2] === QUIET_SOURCE, JSON.stringify(named));
    count("with the volume beside each sender rather than a share of a total",
      listed.sources[0].messages === LOUD_FAILED &&
      listed.sources[1].messages === MIDDLE_FAILED &&
      listed.sources[2].messages === QUIET_FAILED, JSON.stringify(listed.sources));
    count("the volume the list left out is published beside it",
      listed.unauthenticated === FORGED_MESSAGES, JSON.stringify(listed));
    count("a complete answer says how many it listed and how many there are",
      listed.truncated === false && listed.listed === 3 && listed.total === 3,
      JSON.stringify(listed));

    // The address is sealed on the volume, so a listing that skipped the
    // unsealing would hand back the deployment-keyed hash and look like a
    // list of senders. It has to be the address a receiver saw.
    count("what comes back is the sending address and not the hash beside it",
      listed.sources.every(function (one) {
        return nodeNet.isIP(one.sourceIp) !== 0;
      }), JSON.stringify(named));

    // A bound that is honored and never says so is this repository's most
    // found defect: an operator reads three of nine as all there is.
    var capped = await handle.failingSources({ domain: LISTED_DOMAIN, limit: 2 });
    count("a bound is honored rather than declared",
      capped.sources.length === 2, JSON.stringify(capped.sources));
    count("and the answer that was cut short says it was cut short",
      capped.truncated === true && capped.listed === 2 && capped.total === 3,
      JSON.stringify(capped));
    count("a cut list keeps the loudest senders rather than whichever came first",
      capped.sources[0].sourceIp === LOUD_SOURCE &&
      capped.sources[1].sourceIp === MIDDLE_SOURCE, JSON.stringify(capped.sources));
    count("and the volume left out does not shrink with the list",
      capped.unauthenticated === FORGED_MESSAGES, JSON.stringify(capped));

    // The operator investigating why the numbers look low asks for the
    // excluded rows as well, and then the forged sender is named, at the
    // top, because it is the largest thing in the fixture.
    var everything = await handle.failingSources({
      domain: LISTED_DOMAIN, includeUnauthenticated: true,
    });
    var everyName = everything.sources.map(function (one) { return one.sourceIp; });
    count("asked for the excluded rows too the reading names the unauthenticated sender",
      everyName.indexOf(FORGED_SOURCE) === 0 && everyName.length === 4,
      JSON.stringify(everyName));
    count("and still says how much of what it counted nobody authenticated",
      everything.unauthenticated === FORGED_MESSAGES, JSON.stringify(everything));

    // A sender whose own mail partly aligned is a relay of the operator's
    // that is misconfigured; one whose mail never aligned is somebody
    // else's machine. They need opposite responses, so the reading keeps
    // them apart.
    count("what a sender did get through is carried beside what it failed on",
      listed.sources.every(function (one) { return one.aligned === 0; }),
      JSON.stringify(listed.sources));
    count("and how many reporting windows saw it, so one blip reads as one",
      listed.sources.every(function (one) { return one.windows === 1; }),
      JSON.stringify(listed.sources));

    var quiet = await handle.failingSources({ domain: UNREPORTED_DOMAIN });
    count("a domain nothing is failing for lists nothing rather than everything",
      quiet.sources.length === 0 && quiet.total === 0 && quiet.truncated === false &&
      quiet.unauthenticated === 0, JSON.stringify(quiet));

    var outside = await handle.failingSources({
      domain: LISTED_DOMAIN, since: WINDOW_END_SEC * 1000 + 1,
    });
    count("a window that ends before the reading begins names no senders",
      outside.sources.length === 0, JSON.stringify(outside));

    // A read that discloses an address records that somebody looked. The
    // row names the domain and the size of the answer; it does not carry
    // the addresses, because a second copy of them in the trail is a copy
    // no erasure request can reach.
    var trail = capture.forAction("blamepost.store.reports.sources_read");
    count("reading the senders records that somebody read them",
      trail.length >= 1, String(trail.length));
    count("and the row names the operator who looked rather than nobody",
      trail.length >= 1 && typeof trail[0].actorUserId === "string" &&
        trail[0].actorUserId.indexOf(auditActor.COMMAND_LINE_MARK) === 0,
      JSON.stringify(trail[0] && trail[0].actorUserId));
    count("with the domain and the size of what was disclosed",
      trail.length >= 1 && helpers.metadataOf(trail[0]).domain === LISTED_DOMAIN &&
        helpers.metadataOf(trail[0]).listed === 3,
      trail.length >= 1 ? JSON.stringify(helpers.metadataOf(trail[0])) : "no row");
    count("and none of the addresses it disclosed written into the row",
      trail.every(function (row) {
        return JSON.stringify(row).indexOf(LOUD_SOURCE) === -1;
      }), JSON.stringify(trail.length));

    await refusesAsyncWith("a listing asked about no domain in particular is refused",
      "store/bad-reports-opts", function () { return handle.failingSources({}); });
    await refusesAsyncWith("a listing asked for a name that is not a domain is refused",
      "store/bad-domain", function () {
        return handle.failingSources({ domain: "not a domain" });
      });
    await refusesAsyncWith("a listing asked for a bound it cannot honor is refused",
      "store/bad-reports-opts", function () {
        return handle.failingSources({ domain: LISTED_DOMAIN, limit: 0 });
      });
    await refusesAsyncWith("a listing asked for a moment that is not one is refused",
      "store/bad-reports-opts", function () {
        return handle.failingSources({ domain: LISTED_DOMAIN, since: "yesterday" });
      });
  } finally {
    capture.release();
  }
}

// ---- an unauthenticated window moves nothing in the counted reading --------

// The exclusion is easy to apply to the volume and easy to forget on
// everything beside it. A sender listed with the volume it failed on in
// authenticated reports, and beside it a window count and a last-seen
// date that quietly took the unauthenticated report in as well, is a row
// where three of the four figures are evidence and one is whatever a
// stranger wrote. It is the harder failure to notice, because the number
// that is wrong is small and plausible.
//
// So one sender is named twice: once by an authenticated report covering
// one window, and once by an unauthenticated report covering a later one.
// Every figure the counted reading carries has to come from the first.
async function anUnauthenticatedWindowMovesNothingInTheCountedReading(handle) {
  var laterBegin = WINDOW_BEGIN_SEC + (2 * 86400);
  var laterEnd   = WINDOW_END_SEC + (2 * 86400);

  handle.ingestAggregate(aggregateXml({
    org: "delta.example", reportId: "0300", domain: MIXED_DOMAIN,
    begin: WINDOW_BEGIN_SEC, end: WINDOW_END_SEC,
    records: [xmlRecord(QUIET_SOURCE, QUIET_FAILED, "fail", "fail", "reject")],
  }), { evidence: tables.REPORT_EVIDENCE_VERIFIED, authenticatedAs: "delta.example",
    now: LISTED_AT });

  handle.ingestAggregate(aggregateXml({
    org: "delta.example", reportId: "0301", domain: MIXED_DOMAIN,
    begin: laterBegin, end: laterEnd,
    records: [xmlRecord(QUIET_SOURCE, FORGED_MESSAGES, "fail", "fail", "reject")],
  }), { evidence: "carrier-dmarc-not-pass", now: LISTED_AT + 1000 });

  var counted = await handle.failingSources({ domain: MIXED_DOMAIN });
  count("the sender is listed once however many reports name it",
    counted.sources.length === 1 && counted.sources[0].sourceIp === QUIET_SOURCE,
    JSON.stringify(counted.sources));
  count("the volume it is listed against is the authenticated one alone",
    counted.sources[0].messages === QUIET_FAILED, JSON.stringify(counted.sources[0]));
  count("the windows it is counted in do not include the one nobody authenticated",
    counted.sources[0].windows === 1, JSON.stringify(counted.sources[0]));
  count("and neither does when it was last seen failing",
    counted.sources[0].lastSeen === WINDOW_END_SEC * 1000,
    JSON.stringify(counted.sources[0]));

  var everything = await handle.failingSources({
    domain: MIXED_DOMAIN, includeUnauthenticated: true,
  });
  count("asked for the excluded rows too the same sender carries both windows",
    everything.sources.length === 1 && everything.sources[0].windows === 2 &&
    everything.sources[0].messages === QUIET_FAILED + FORGED_MESSAGES,
    JSON.stringify(everything.sources[0]));
  count("and the later window is then the one it was last seen failing in",
    everything.sources[0].lastSeen === laterEnd * 1000,
    JSON.stringify(everything.sources[0]));

  // The same trap on the other listing, and the worse half of it. When a
  // reporter was last heard from is the whole answer to whether it has
  // gone quiet, so a moment moved by a report nobody authenticated lets
  // whoever wrote that report make a domain read as freshly reported on
  // while every real receiver has stopped.
  var heard = handle.reporters({ domain: MIXED_DOMAIN });
  count("the reporter is named once and counted on its authenticated report alone",
    heard.reporters.length === 1 && heard.reporters[0].reports === 1,
    JSON.stringify(heard.reporters));
  count("when it was last heard from is not moved by the report nobody authenticated",
    heard.reporters[0].newestAt === LISTED_AT, JSON.stringify(heard.reporters[0]));
  count("and the records it is credited with come from that report alone",
    heard.reporters[0].records === 1, JSON.stringify(heard.reporters[0]));

  // The wider reading lists the later arrival too. It is the same name,
  // and it is not the same organization: nothing authenticated the second
  // report, so it is listed by the name it gave, with no organization,
  // and the authenticated organization's own entry is not moved by it.
  var heardAll = handle.reporters({
    domain: MIXED_DOMAIN, includeUnauthenticated: true,
  });
  var byOrganization = heardAll.reporters.filter(function (one) {
    return one.organization === "delta.example";
  });
  var byNameOnly = heardAll.reporters.filter(function (one) {
    return one.organization === null && one.orgName === "delta.example";
  });
  count("the reading that takes the excluded reports in carries the later arrival",
    byNameOnly.length === 1 && byNameOnly[0].newestAt === LISTED_AT + 1000 &&
    byNameOnly[0].reports === 1, JSON.stringify(heardAll.reporters));
  count("as its own entry, apart from the organization whose name it borrowed",
    heardAll.reporters.length === 2 && heardAll.total === 2 && byOrganization.length === 1 &&
    byOrganization[0].newestAt === LISTED_AT && byOrganization[0].reports === 1,
    JSON.stringify(heardAll));
}

// ---- who has been heard from, and when -------------------------------------

// A domain nobody is reporting on and a domain whose mail all aligns
// produce the same empty reading, and the second is fine while the first
// means the evidence stopped arriving. Telling them apart needs the
// reporters named and the moment each was last heard from, which is a
// question about the reports table rather than about the records inside
// them.
//
// The same authenticity rule applies. A reporter that is only ever heard
// from in reports this server did not authenticate has not been heard
// from, and listing it would answer the absence question with the thing
// that caused it.
function theReportersHeardFromAreNamed(handle) {
  // A second report from the reporter already filed above, and one from a
  // third. The reporter whose only report went unauthenticated is
  // already on the volume from the function before this one.
  handle.ingestAggregate(aggregateXml({
    org: "alpha.example", reportId: "0202", domain: LISTED_DOMAIN,
    records: [xmlRecord(QUIET_SOURCE, QUIET_FAILED, "fail", "fail", "reject")],
  }), { evidence: tables.REPORT_EVIDENCE_VERIFIED, authenticatedAs: "alpha.example",
    now: LISTED_AT + 2000 });
  handle.ingestAggregate(aggregateXml({
    org: "gamma.example", reportId: "0203", domain: LISTED_DOMAIN,
    records: [xmlRecord(QUIET_SOURCE, QUIET_FAILED, "fail", "fail", "reject")],
  }), { evidence: tables.REPORT_EVIDENCE_VERIFIED, authenticatedAs: "gamma.example",
    now: LISTED_AT + 3000 });

  var heard = handle.reporters({ domain: LISTED_DOMAIN });
  var names = heard.reporters.map(function (one) { return one.orgName; });

  count("the reporting organizations are named rather than left to a date",
    names.length === 2, JSON.stringify(names));
  count("a reporter heard from in an authenticated report is named",
    names.indexOf("alpha.example") !== -1 && names.indexOf("gamma.example") !== -1,
    JSON.stringify(names));
  count("a reporter heard from only in a report nobody authenticated is not",
    names.indexOf("beta.example") === -1, JSON.stringify(names));
  count("the list is ordered by how much each reporter has been heard from",
    names[0] === "alpha.example" && names[1] === "gamma.example",
    JSON.stringify(names));
  count("with how many reports each one sent",
    heard.reporters[0].reports === 2 && heard.reporters[1].reports === 1,
    JSON.stringify(heard.reporters));
  count("and when the most recent one arrived rather than the window it covered",
    heard.reporters[0].newestAt === LISTED_AT + 2000 &&
    heard.reporters[1].newestAt === LISTED_AT + 3000,
    JSON.stringify(heard.reporters));
  count("the reports the reading left out are counted beside it",
    heard.unauthenticatedReports === 1, JSON.stringify(heard));
  count("a complete answer says how many it listed and how many there are",
    heard.truncated === false && heard.listed === 2 && heard.total === 2,
    JSON.stringify(heard));

  var capped = handle.reporters({ domain: LISTED_DOMAIN, limit: 1 });
  count("a bound is honored rather than declared",
    capped.reporters.length === 1 && capped.reporters[0].orgName === "alpha.example",
    JSON.stringify(capped.reporters));
  count("and the answer that was cut short says it was cut short",
    capped.truncated === true && capped.listed === 1 && capped.total === 2,
    JSON.stringify(capped));

  var everything = handle.reporters({
    domain: LISTED_DOMAIN, includeUnauthenticated: true,
  });
  var everyName = everything.reporters.map(function (one) { return one.orgName; });
  count("asked for the excluded reports too the unauthenticated reporter is named",
    everyName.indexOf("beta.example") !== -1 && everyName.length === 3,
    JSON.stringify(everyName));
  count("and a tie on report count breaks on the most recent arrival",
    everyName[0] === "alpha.example" && everyName[1] === "gamma.example" &&
    everyName[2] === "beta.example", JSON.stringify(everyName));

  var quiet = handle.reporters({ domain: UNREPORTED_DOMAIN });
  count("a domain no reporter was heard from about lists nobody",
    quiet.reporters.length === 0 && quiet.total === 0 &&
    quiet.unauthenticatedReports === 0, JSON.stringify(quiet));

  refusesWith("a reporter listing asked about no domain in particular is refused",
    "store/bad-reports-opts", function () { handle.reporters({}); });
  refusesWith("a reporter listing asked for a name that is not a domain is refused",
    "store/bad-domain", function () { handle.reporters({ domain: "not a domain" }); });
  refusesWith("a reporter listing asked for a bound it cannot honor is refused",
    "store/bad-reports-opts", function () {
      handle.reporters({ domain: LISTED_DOMAIN, limit: 0 });
    });
  refusesWith("a reporter listing asked for a moment that is not one is refused",
    "store/bad-reports-opts", function () {
      handle.reporters({ domain: LISTED_DOMAIN, until: null, since: {} });
    });
}

function theCeilingsAreEnforcedRatherThanDeclared() {
  var small = reports.create(boundsFor({ maxReportBytes: 2048, maxRecordsPerReport: 2 }));
  count("the handle publishes the ceilings it was handed",
    small.describe().maxReportBytes === 2048 &&
      small.describe().maxRecordsPerReport === 2,
    JSON.stringify(small.describe()));

  var many = [];
  for (var i = 0; i < 4; i += 1) {
    many.push(xmlRecord("203.0.113." + (100 + i), 1, "pass", "pass", "none"));
  }
  var overRecords = small.ingestAggregate(aggregateXml({
    org: "fifth.example", reportId: "0004", records: many,
  }));
  count("a report carrying more records than the handle takes is refused whole",
    overRecords.ok === false && overRecords.reason === "too-many-records",
    JSON.stringify(overRecords));

  var padding = [];
  for (var p = 0; p < 200; p += 1) {
    padding.push(xmlRecord("203.0.113.1", 1, "pass", "pass", "none"));
  }
  var overBytes = small.ingestAggregate(aggregateXml({
    org: "sixth.example", reportId: "0005", records: padding,
  }));
  count("a report larger than the handle reads is refused before it is parsed",
    overBytes.ok === false && overBytes.reason === "report-too-large",
    JSON.stringify(overBytes));

  var overBytesForensic = small.ingestForensic(forensicMessage({
    mailFrom: "oversize@third-party.example",
  }) + new Array(3000).join("x"));
  count("and so is a forensic report larger than it reads",
    overBytesForensic.ok === false && overBytesForensic.reason === "report-too-large",
    JSON.stringify(overBytesForensic));

  count("none of the three refusals left a row behind",
    b.db.from(tables.DMARC_REPORTS).where({ orgKey: "fifth.example" }).count() === 0 &&
      b.db.from(tables.DMARC_REPORTS).where({ orgKey: "sixth.example" }).count() === 0,
    String(b.db.from(tables.DMARC_REPORTS).count()));
}

// ---- the reported message never lands --------------------------------------

function theReportedMessageNeverReachesTheVolume(handle) {
  // The parser hands the reported message back. That is the point of
  // asserting it here: what follows measures this server's decision, not
  // the parser's silence.
  var parsed = b.mail.dmarc.parseForensicReport(forensicMessage({}));
  count("the parser does return the reported message and its headers",
    parsed.ok === true &&
      parsed.report.reportedMessage.indexOf(BODY_MARKER) !== -1 &&
      JSON.stringify(parsed.report.reportedHeaders).indexOf(HEADER_MARKER) !== -1,
    parsed.ok ? String(parsed.report.reportedHeaders.length) : JSON.stringify(parsed.error));

  var taken = handle.ingestForensic(forensicMessage({
    rcptTo: ["victim@reporter.example", "second@reporter.example"],
  }));
  count("a forensic report naming two recipients is stored as one row each",
    taken.ok === true && taken.stored === 2, JSON.stringify(taken));

  var stored = everyStoredCell();
  // What the search covered, before what it did not find. A reading that
  // never reached a row reports the same absence as one that read every
  // row, and only this tells the two apart.
  count("the search covered rows that are actually there",
    stored.length > 0 && stored.indexOf(DOMAIN) !== -1,
    String(stored.length) + " characters of stored cells");

  count("the reported message body is nowhere on the volume",
    stored.indexOf(BODY_MARKER) === -1, "marker found in a stored cell");
  count("and neither is the stranger's subject line",
    stored.indexOf(HEADER_MARKER) === -1, "header marker found in a stored cell");
  // The envelope IS kept, and is kept sealed. A row holding the address
  // in the clear would satisfy every assertion above and still hand a
  // stolen file the list of people this server has reports about.
  count("the stranger's address is held as ciphertext rather than as itself",
    stored.indexOf("stranger@third-party.example") === -1,
    "a sealed address is readable in a stored cell");
  count("and it is still findable through the derived hash",
    b.db.from(tables.DMARC_FORENSIC)
      .where({ originalMailFrom: "stranger@third-party.example" }).count() === 2,
    String(b.db.from(tables.DMARC_FORENSIC).count()));

  // The other half of by construction: there is no column any later
  // change could route the message into without declaring one first. The
  // names checked for are the parser's own, so this reads against the
  // contract the reader composes rather than against a guess at what a
  // column might be called.
  var CARRIES_THE_MESSAGE = ["reportedMessage", "reportedHeaders", "reportedHeaderMap",
    "reportedHeadersTruncated", "reportedUri", "authenticationResults", "extraFields"];
  var everyColumn = declaredColumnsOf(tables.DMARC_REPORTS)
    .concat(declaredColumnsOf(tables.DMARC_RECORDS))
    .concat(declaredColumnsOf(tables.DMARC_FORENSIC));
  var carried = CARRIES_THE_MESSAGE.filter(function (field) {
    return everyColumn.indexOf(field) !== -1;
  });
  count("no column in any of the three tables is declared to hold the reported message",
    carried.length === 0, carried.join(", ") + " in " + everyColumn.join(", "));

  var resent = handle.ingestForensic(forensicMessage({
    rcptTo: ["victim@reporter.example", "second@reporter.example"],
  }));
  count("a forensic report sent twice stores nothing more",
    resent.ok === true && resent.stored === 0 && resent.duplicates === 2,
    JSON.stringify(resent));

  var malformed = handle.ingestForensic("this is not a report");
  count("a forensic message that will not parse is refused with a reason",
    malformed.ok === false && typeof malformed.reason === "string",
    JSON.stringify(malformed));

  var foreign = handle.ingestForensic(forensicMessage({ reportedDomain: "not-hosted.example" }));
  count("a forensic report about a domain this server does not host is refused",
    foreign.ok === false && foreign.reason === "domain-not-hosted",
    JSON.stringify(foreign));
}

function forensicRowsAreNotKeptWhenTheyAreTurnedOff() {
  var quiet = reports.create(boundsFor({ forensicEnabled: false }));
  var before = b.db.from(tables.DMARC_FORENSIC).count();
  var verdict = quiet.ingestForensic(forensicMessage({ mailFrom: "nobody@third-party.example" }));
  count("a handle told not to keep forensic rows refuses the report rather than storing it",
    verdict.ok === false && verdict.reason === "forensic-not-kept", JSON.stringify(verdict));
  count("and the table did not grow",
    b.db.from(tables.DMARC_FORENSIC).count() === before,
    String(b.db.from(tables.DMARC_FORENSIC).count()));
}

// ---- somebody with no account here asks to be forgotten --------------------

async function anErasureRequestFromAStrangerIsActedOn(handle) {
  var capture = helpers.auditCapture();
  try {
    var before = b.db.from(tables.DMARC_FORENSIC)
      .where({ originalMailFrom: "stranger@third-party.example" }).count();
    count("the stranger's rows are there to be erased", before === 2, String(before));

    // Run it the way the command line does, inside the scope that
    // establishes who is acting. An erasure carried out on somebody
    // else's behalf is exactly the row an auditor asks the operator
    // about, so the row has to name one.
    var verdict = await auditActor.runAs(auditActor.forCommandLine(), function () {
      return handle.forgetAddress("Stranger@Third-Party.Example",
        "erasure request received by post");
    });
    count("the request destroys every row naming that address",
      verdict.destroyed === 2, JSON.stringify(verdict));
    count("and reports nothing preserved and nothing failed",
      verdict.preserved.length === 0 && verdict.failed.length === 0, JSON.stringify(verdict));
    count("the address it acted on is the folded one",
      verdict.address === "stranger@third-party.example", String(verdict.address));

    count("the rows are gone",
      b.db.from(tables.DMARC_FORENSIC)
        .where({ originalMailFrom: "stranger@third-party.example" }).count() === 0,
      String(b.db.from(tables.DMARC_FORENSIC).count()));

    var trail = capture.forAction("blamepost.store.reports.address_forgotten");
    count("a row records that the erasure was asked for and carried out",
      trail.length === 1, String(trail.length));
    count("and it names the operator who carried it out rather than nobody",
      trail.length === 1 && typeof trail[0].actorUserId === "string" &&
        trail[0].actorUserId.indexOf(auditActor.COMMAND_LINE_MARK) === 0,
      JSON.stringify(trail[0] && trail[0].actorUserId));
    count("with the reason the operator recorded",
      trail.length === 1 &&
        helpers.metadataOf(trail[0]).reason === "erasure request received by post",
      trail.length === 1 ? JSON.stringify(helpers.metadataOf(trail[0])) : "no row");

    var quiet = await handle.forgetAddress("stranger@third-party.example", "asked twice");
    count("asking again destroys nothing and is not an error",
      quiet.destroyed === 0 && quiet.failed.length === 0, JSON.stringify(quiet));

    await refusesAsyncWith("an erasure with no recorded reason is refused",
      "store/bad-reports-opts", function () {
        return handle.forgetAddress("someone@third-party.example", "  ");
      });
    await refusesAsyncWith("an erasure naming something that is not an address is refused",
      "store/bad-address", function () {
        return handle.forgetAddress("not an address", "a reason");
      });
  } finally {
    capture.release();
  }
}

// An aggregate report names a contact address, and an erasure request
// for that address takes the address out of the report. The report and
// its records stay, so a resend of the same report is still read as one
// and its records are not counted twice.
async function aForgottenContactStillDeduplicatesItsReport(handle) {
  var xml = aggregateXml({ org: "contact.example", reportId: "erase-0001" });
  var contact = "dmarc-noreply@contact.example";
  var first = handle.ingestAggregate(xml, AUTHENTICATED);
  count("the report naming the contact is stored", first.ok === true && first.duplicate === false,
    JSON.stringify(first));
  var before = JSON.stringify(handle.rollup({ domain: DOMAIN }));

  var verdict = await handle.forgetAddress(contact, "erasure request for a report contact");
  count("the erasure acts on the report row naming the contact",
    verdict.destroyed >= 1 && verdict.failed.length === 0, JSON.stringify(verdict));
  count("and no report row names the contact afterwards",
    b.db.from(tables.DMARC_REPORTS).where({ reportEmail: contact }).count() === 0,
    String(b.db.from(tables.DMARC_REPORTS).where({ reportEmail: contact }).count()));

  var again = handle.ingestAggregate(xml, AUTHENTICATED);
  count("a resend of the same report is still read as a resend",
    again.ok === true && again.duplicate === true, JSON.stringify(again));
  count("so the counts the policy step reads are what they were before the erasure",
    JSON.stringify(handle.rollup({ domain: DOMAIN })) === before,
    JSON.stringify(handle.rollup({ domain: DOMAIN })) + " against " + before);
  count("and the resend does not store the contact address again",
    b.db.from(tables.DMARC_REPORTS).where({ reportEmail: contact }).count() === 0,
    String(b.db.from(tables.DMARC_REPORTS).where({ reportEmail: contact }).count()));

  // The state a process leaves when it stops between erasing the report
  // row and settling its copy: the copy under its pending key, the old
  // row gone, the records still pointing at it. The next report read
  // settles the copy first, so a resend is still a resend.
  var crashXml = aggregateXml({ org: "stopped.example", reportId: "erase-0002" });
  handle.ingestAggregate(crashXml, AUTHENTICATED);
  var crashBefore = JSON.stringify(handle.rollup({ domain: DOMAIN }));
  var original = b.db.from(tables.DMARC_REPORTS).where({ reportId: "erase-0002" }).first();
  var copy = {};
  ["orgName", "reportId", "policyDomain", "windowBegin", "windowEnd", "storedCount",
    "refusedCount", "evidence", "verifiedOrgDomain", "receivedAt"].forEach(function (name) {
    if (original[name] !== undefined) copy[name] = original[name];
  });
  copy.orgKey = original.orgKey + "\u001fpending\u001f" + original._id;
  copy.storedCount = -(original.storedCount + 1);
  tables.insertRow(tables.DMARC_REPORTS, copy);
  b.db.eraseHard(tables.DMARC_REPORTS, original._id, { reason: "a stopped erasure" });

  var afterCrash = handle.ingestAggregate(crashXml, AUTHENTICATED);
  count("a resend after an erasure that stopped partway is still read as a resend",
    afterCrash.ok === true && afterCrash.duplicate === true, JSON.stringify(afterCrash));
  count("and the counts are what they were before the erasure began",
    JSON.stringify(handle.rollup({ domain: DOMAIN })) === crashBefore,
    JSON.stringify(handle.rollup({ domain: DOMAIN })) + " against " + crashBefore);
  var settled = b.db.from(tables.DMARC_REPORTS).where({ reportId: "erase-0002" }).all();
  count("and the copy is settled under the report's own key with its count restored",
    settled.length === 1 && settled[0].orgKey === original.orgKey &&
      settled[0].storedCount === original.storedCount,
    JSON.stringify(settled.map(function (r) { return [r.orgKey, r.storedCount]; })));
}

// ---- the window is a window ------------------------------------------------

async function rowsGoWhenTheirWindowPassesAndNotBefore(handle) {
  // The erasure request above destroyed the forensic rows this file
  // stored earlier, so there has to be evidence here for the sweep to
  // act on rather than an empty table it would pass over.
  var seeded = handle.ingestForensic(forensicMessage({
    mailFrom: "later@third-party.example",
    rcptTo:   ["victim@reporter.example"],
  }));
  count("a forensic row is on the volume for the sweep to reach",
    seeded.ok === true && seeded.stored === 1, JSON.stringify(seeded));

  var forensicBefore  = b.db.from(tables.DMARC_FORENSIC).count();
  var aggregateBefore = b.db.from(tables.DMARC_RECORDS).count();
  count("there is forensic evidence to age out", forensicBefore > 0, String(forensicBefore));
  count("and aggregate evidence beside it", aggregateBefore > 0, String(aggregateBefore));

  var early = await handle.sweep();
  count("a sweep run inside both windows destroys nothing",
    early.destroyed === 0, JSON.stringify(early.summaries));
  count("and every row is still there",
    b.db.from(tables.DMARC_FORENSIC).count() === forensicBefore &&
      b.db.from(tables.DMARC_RECORDS).count() === aggregateBefore,
    String(b.db.from(tables.DMARC_FORENSIC).count()) + " / " +
      String(b.db.from(tables.DMARC_RECORDS).count()));

  // Age every row past the forensic window and not past the aggregate
  // one. The two windows are separate settings and the shorter has to
  // act on its own, or a server keeping aggregate history for a year
  // would keep a stranger's headers for a year with it.
  var pastForensic = Date.now() - (HOUR_MS + 60000);
  b.db.prepare("UPDATE " + tables.DMARC_FORENSIC + " SET receivedAt = ?").run(pastForensic);
  b.db.prepare("UPDATE " + tables.DMARC_RECORDS + " SET receivedAt = ?").run(pastForensic);
  b.db.prepare("UPDATE " + tables.DMARC_REPORTS + " SET receivedAt = ?").run(pastForensic);

  // A preview before anything is destroyed. An operator asked to widen
  // a window wants the count first, and a preview that destroyed while
  // reporting what it would destroy is the one mistake it cannot make.
  var previewed = await handle.sweep({ dryRun: true });
  count("a preview counts the rows that would go",
    previewed.dryRun === true && previewed.destroyed === forensicBefore,
    JSON.stringify(previewed.summaries));
  count("and destroys none of them",
    b.db.from(tables.DMARC_FORENSIC).count() === forensicBefore,
    String(b.db.from(tables.DMARC_FORENSIC).count()));

  // A preservation order over the domain suspends destruction of its
  // evidence. It is the reason these rules name a subject at all, and a
  // rule that named a sealed column instead would consult the registry
  // with ciphertext and quietly honor nothing.
  var holds = b.legalHold.create({ db: b.db, audit: b.audit });
  holds.place(DOMAIN, {
    reason:   "a preservation order covers this domain's reports",
    citation: "FRCP-26",
  });
  var underHold = await handle.sweep();
  count("a preservation order over the domain stops the rows going",
    b.db.from(tables.DMARC_FORENSIC).count() === forensicBefore,
    String(b.db.from(tables.DMARC_FORENSIC).count()));
  count("and the pass says the hold is why rather than reporting a clean sweep",
    underHold.destroyed === 0 && underHold.summaries.some(function (summary) {
      return (summary.legalHoldsHonored || 0) > 0;
    }), JSON.stringify(underHold.summaries));
  holds.release(DOMAIN, {
    reason:   "the order was lifted",
    approver: "records@example.com",
  });

  var middle = await handle.sweep();
  count("the shorter window destroys the forensic rows",
    b.db.from(tables.DMARC_FORENSIC).count() === 0, JSON.stringify(middle.summaries));
  count("and leaves the aggregate rows alone",
    b.db.from(tables.DMARC_RECORDS).count() === aggregateBefore,
    String(b.db.from(tables.DMARC_RECORDS).count()));
  count("the sweep says how many it destroyed",
    middle.destroyed === forensicBefore, JSON.stringify(middle.summaries));

  var pastAggregate = Date.now() - (7 * DAY_MS + 60000);
  b.db.prepare("UPDATE " + tables.DMARC_RECORDS + " SET receivedAt = ?").run(pastAggregate);
  b.db.prepare("UPDATE " + tables.DMARC_REPORTS + " SET receivedAt = ?").run(pastAggregate);

  var late = await handle.sweep();
  count("past the longer window the aggregate records go too",
    b.db.from(tables.DMARC_RECORDS).count() === 0, JSON.stringify(late.summaries));
  count("and the report rows they belonged to go with them",
    b.db.from(tables.DMARC_REPORTS).count() === 0,
    String(b.db.from(tables.DMARC_REPORTS).count()));
  count("the rollup then answers about nothing rather than about stale rows",
    handle.rollup({ domain: DOMAIN }).length === 0,
    JSON.stringify(handle.rollup({ domain: DOMAIN })));
}

function theSweepTimerCanBeDisarmed(handle) {
  count("a handle that has not been started is not sweeping",
    handle.describe().sweeping === false, JSON.stringify(handle.describe()));
  handle.start();
  count("starting arms the sweep", handle.describe().sweeping === true,
    JSON.stringify(handle.describe()));
  handle.start();
  count("starting twice keeps the first timer rather than arming a second",
    handle.describe().sweeping === true, JSON.stringify(handle.describe()));
  handle.stop();
  count("stopping disarms it", handle.describe().sweeping === false,
    JSON.stringify(handle.describe()));
  handle.stop();
  count("and stopping an already stopped handle is not an error",
    handle.describe().sweeping === false, JSON.stringify(handle.describe()));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dmarc-report-store");
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

    theFactoryRefusesBoundsItCannotActOn();

    var handle = reports.create(boundsFor());

    aResentReportLeavesOneRow(handle);
    oneUnusableRecordDoesNotDiscardTheRest(handle);
    aReporterNamingItselfWithAControlCharacterIsRefused(handle);
    theRollupCountsWhatWasStored(handle);
    theRollupLeavesOutWhatNobodyAuthenticated(handle);
    aRowFromBeforeTheColumnIsNotReadAsEvidence(handle);
    await theFailingSourceListNamesOnlyAuthenticatedSenders(handle);
    await anUnauthenticatedWindowMovesNothingInTheCountedReading(handle);
    theReportersHeardFromAreNamed(handle);
    theCeilingsAreEnforcedRatherThanDeclared();
    theReportedMessageNeverReachesTheVolume(handle);
    forensicRowsAreNotKeptWhenTheyAreTurnedOff();
    await anErasureRequestFromAStrangerIsActedOn(handle);
    await aForgottenContactStillDeduplicatesItsReport(handle);
    await rowsGoWhenTheirWindowPassesAndNotBefore(handle);
    theSweepTimerCanBeDisarmed(handle);

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
  name:      "dmarc-report-store",
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
