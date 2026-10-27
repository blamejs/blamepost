// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The DMARC reading in the administration console, driven the way an
 * operator drives it: a real listener, a real session, and the version a
 * browser negotiates against the TLS port.
 *
 * A domain publishes a DMARC record and receivers send back a day of
 * counting each. The number an operator moves a policy on is what share
 * of the mail claiming that domain aligned, and the reason they cannot
 * read it off the store directly is that the store answers per reporting
 * window and the question is per domain. So the console groups, and
 * every claim below is about whether the grouped answer is the one the
 * reports actually said.
 *
 * ## What is measured
 *
 *   - The counted and aligned volumes and the alignment rate a signed-in
 *     operator reads are the sums of the reports that were filed, taken
 *     from the fixture rather than from a second run of the console's own
 *     query. A page asserted against the query it renders agrees with
 *     itself whatever either of them does.
 *   - A hosted domain that no receiver has reported on is SHOWN, saying
 *     it has no counted evidence. A domain missing from a listing reads
 *     as a domain with nothing wrong, and those are the two states an
 *     operator most needs told apart.
 *   - The window the page read is the window it says it read, including
 *     when the request asked for more days than the server keeps rows
 *     for.
 *   - A domain named in the query string is resolved against the hosted
 *     domains before anything is read, so a name this server does not
 *     host reaches neither the store nor the page.
 *   - An account holding no operator role is refused, and the refusal
 *     names the role rather than the page.
 *   - This run holds no credential for any zone, so nothing on the page
 *     posts back to it and the route that would publish a record refuses
 *     by name. Publishing from a server that does hold one is measured
 *     in web-zone-publish.
 *
 * ## Why HTTP/2
 *
 * The framework binds the TLS listener with ALPN offering h2, so a
 * browser sends `:authority` and no `Host` header. Those are different
 * requests to anything in the lifecycle that reads this server's own
 * origin, and a reader speaking HTTP/1.1 cannot see the difference. The
 * operator here speaks h2 for that reason.
 *
 * Real database, real vault, real TLS listener on a reserved loopback
 * port.
 *
 * Run standalone: node test/layer-2-integration/web-dmarc-console.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var tables    = require("../../lib/store/tables");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;

var HOSTNAME       = "mx.example.com";
// Three hosted domains, one per state the page has to tell apart: one
// reported on and counted, one nobody has reported on, and one that
// reports arrived for where not a single report counted. The third is
// the state an operator reads as a broken server unless the page says
// otherwise, and it is the one a fixture with two domains cannot reach.
var REPORTED       = "example.com";
var QUIET          = "example.net";
var UNCOUNTED      = "example.org";

var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var OPERATOR_ADDRESS  = "operator@" + REPORTED;
var OPERATOR_PASSWORD = "quiet lantern bicycle 4291";
var READER_ADDRESS    = "quillfeather@" + REPORTED;
var READER_PASSWORD   = "amber kettle rowboat 7715";

// How long this run keeps aggregate rows, in the unit an operator writes
// it in. It is named here because the console bounds the window a
// request may ask about by it: rows older than this are gone, so a page
// offering to read further back would be offering an emptier answer than
// the shorter one.
var AGGREGATE_DAYS = 60;

// The mail each window counted, and how it broke down. These are the
// authority for every number asserted against the page: the console's
// own query is not consulted, because a page checked against the query
// it renders agrees with itself whichever of the two is wrong.
//
// Alignment is the rule RFC 7489 section 4.2 states: a message aligned
// when it passed on EITHER identifier. The second window carries the
// case that separates that rule from a stricter one, mail that passed
// DKIM and failed SPF, and it is counted as aligned.
var WINDOW_ONE_ALIGNED     = 100;
var WINDOW_ONE_FAIL_HEAVY  = 25;
var WINDOW_ONE_FAIL_LIGHT  = 5;
var WINDOW_TWO_ALIGNED     = 60;
var WINDOW_TWO_FAILING     = 40;

var TOTAL_COUNTED   = WINDOW_ONE_ALIGNED + WINDOW_ONE_FAIL_HEAVY + WINDOW_ONE_FAIL_LIGHT +
                      WINDOW_TWO_ALIGNED + WINDOW_TWO_FAILING;
var TOTAL_ALIGNED   = WINDOW_ONE_ALIGNED + WINDOW_TWO_ALIGNED;
var TOTAL_UNALIGNED = TOTAL_COUNTED - TOTAL_ALIGNED;
var TOTAL_RATE      = Math.round((TOTAL_ALIGNED / TOTAL_COUNTED) * 100);

// Distinct sending addresses that failed on both identifiers, per
// window. One relay sending forty messages is one source, which is the
// whole reason this is counted separately from the volume.
var WINDOW_ONE_SOURCES = 2;
var WINDOW_TWO_SOURCES = 1;

// The four sending addresses the reports name. Two failed on both
// identifiers inside reports this server authenticated, one aligned, and
// the fourth is named only inside the report nobody authenticated.
// Whether that fourth address reaches the page is the difference between
// a list an operator can act on and a list of machines a stranger chose.
var HEAVY_SOURCE    = "203.0.113.10";
var LIGHT_SOURCE    = "198.51.100.7";
var ALIGNED_SOURCE  = "203.0.113.5";
var EXCLUDED_SOURCE = "192.0.2.44";

// What the heavier of the two senders failed on across both windows,
// which is the figure the page lists it against. It is larger than the
// lighter one, and the lighter one is filed first, so a list that came
// back in the order the rows were written reads in the wrong order here.
var HEAVY_FAILED = WINDOW_ONE_FAIL_HEAVY + WINDOW_TWO_FAILING;
var LIGHT_FAILED = WINDOW_ONE_FAIL_LIGHT;

// The organization every report in this run names as its author, and how
// many of its reports about the reported domain this server
// authenticated. The third report carries no verdict, so it is not among
// them and is counted apart.
var REPORTING_ORG      = "reporter.example";
var COUNTED_REPORTS    = 2;
var EXCLUDED_REPORTS   = 1;

// The name every report gives itself in `<org_name>`. It differs from the
// domain the reports are authenticated for, so the page can be read for
// which of the two it shows as the organization.
var REPORTER_NAME      = "Reporter Example";

// A third window, filed with no verdict about the message that carried
// the report. The store leaves that volume out of the counting, and this
// run is the one that says whether an operator can find it: a number
// missing from a total with nowhere on the page to read it is a number
// an operator concludes is a fault in the server.
//
// It is large, and larger than everything counted, so a page that folded
// it into the totals could not pass the counted claims by accident.
var EXCLUDED_MESSAGES = 500;

// The whole of what arrived for the third domain, none of it counted.
var UNCOUNTED_MESSAGES = 77;

// How long the server is given to come down. Nothing is connected to the
// listeners, so this is a ceiling rather than a wait.
var STOP_MS = 8000;

// A name no server hosts, shaped to break out of an attribute if it ever
// reached one. What is asserted is stronger than escaping: the console
// resolves a requested domain against the hosted rows first, so this
// reaches neither the store nor the rendered page in any form.
var HOSTILE_DOMAIN = "\"><script>alert(1)</script>";

// ---------------------------------------------------------------------------
// The reports
// ---------------------------------------------------------------------------

function recordXml(domain, sourceIp, messages, dkim, spf) {
  return "  <record>\n" +
    "    <row><source_ip>" + sourceIp + "</source_ip><count>" + messages + "</count>\n" +
    "      <policy_evaluated><disposition>none</disposition>" +
    "<dkim>" + dkim + "</dkim><spf>" + spf + "</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>" + domain + "</header_from></identifiers>\n" +
    "    <auth_results><spf><domain>" + domain + "</domain>" +
    "<result>" + spf + "</result></spf></auth_results>\n" +
    "  </record>\n";
}

function aggregateXml(domain, reportId, beginSeconds, endSeconds, records) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>" + REPORTER_NAME + "</org_name>\n" +
    "    <email>dmarc-noreply@" + REPORTING_ORG + "</email>\n" +
    "    <report_id>" + reportId + "</report_id>\n" +
    "    <date_range><begin>" + beginSeconds + "</begin>" +
    "<end>" + endSeconds + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + domain + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>quarantine</p><sp>quarantine</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    records.join("") +
    "</feedback>\n";
}

// Three reports. Two carry the verdict this server reaches when it
// authenticated the message that delivered them, which is what puts
// their counting into the reading a policy rests on. The third carries
// no verdict, which is what any stranger writing to a published
// reporting address produces, and the store leaves its volume out.
//
// The third sits in a window of its own so the two counted windows can
// be asserted whole: a page that folded the excluded volume into the
// counting would move numbers that are pinned exactly.
function fileTheReports(reports, now) {
  var day    = 86400;
  var nowSec = Math.floor(now / 1000);
  // The domain the carrier passed DMARC for travels with the verdict, as
  // it does from the reader on the filing seam. The store counts the
  // organization by it.
  var verified = { evidence: tables.REPORT_EVIDENCE_VERIFIED, authenticatedAs: REPORTING_ORG };

  var first = reports.ingestAggregate(aggregateXml(REPORTED, "console-0001",
    nowSec - (2 * day), nowSec - day, [
      recordXml(REPORTED, ALIGNED_SOURCE, WINDOW_ONE_ALIGNED,    "pass", "pass"),
      recordXml(REPORTED, LIGHT_SOURCE,   WINDOW_ONE_FAIL_LIGHT, "fail", "fail"),
      recordXml(REPORTED, HEAVY_SOURCE,   WINDOW_ONE_FAIL_HEAVY, "fail", "fail"),
    ]), verified);
  count("the first day of counting is taken by the store, so the page below has evidence " +
    "to read", first.ok === true && first.stored === 3,
    JSON.stringify({ ok: first.ok, reason: first.reason, stored: first.stored,
      refused: first.refused }));

  var second = reports.ingestAggregate(aggregateXml(REPORTED, "console-0002",
    nowSec - day, nowSec, [
      recordXml(REPORTED, ALIGNED_SOURCE, WINDOW_TWO_ALIGNED, "pass", "fail"),
      recordXml(REPORTED, HEAVY_SOURCE,   WINDOW_TWO_FAILING, "fail", "fail"),
    ]), verified);
  count("and so is the second, which carries the mail that passed one identifier and " +
    "failed the other", second.ok === true && second.stored === 2,
    JSON.stringify({ ok: second.ok, reason: second.reason, stored: second.stored,
      refused: second.refused }));

  var unsigned = reports.ingestAggregate(aggregateXml(REPORTED, "console-0003",
    nowSec - (4 * day), nowSec - (3 * day), [
      recordXml(REPORTED, EXCLUDED_SOURCE, EXCLUDED_MESSAGES, "fail", "fail"),
    ]));
  count("a report this server never authenticated is stored rather than discarded, so the " +
    "volume it claims can be read back",
    unsigned.ok === true && unsigned.stored === 1,
    JSON.stringify({ ok: unsigned.ok, reason: unsigned.reason, stored: unsigned.stored,
      refused: unsigned.refused }));

  // The third domain's only report, and it is one nobody authenticated.
  // Its whole volume is left out, so the domain has reports arriving and
  // a counting of zero, which is the state that reads as a broken server.
  var orphan = reports.ingestAggregate(aggregateXml(UNCOUNTED, "console-0004",
    nowSec - (2 * day), nowSec - day, [
      recordXml(UNCOUNTED, "192.0.2.90", UNCOUNTED_MESSAGES, "fail", "fail"),
    ]));
  count("and the domain whose only report is one nobody authenticated has that report " +
    "stored too", orphan.ok === true && orphan.stored === 1,
    JSON.stringify({ ok: orphan.ok, reason: orphan.reason, stored: orphan.stored,
      refused: orphan.refused }));
}

// ---------------------------------------------------------------------------
// Reading the page
// ---------------------------------------------------------------------------

// The block of the page that belongs to one domain. The console renders
// a card per domain, so a number asserted against the whole page would
// pass on a number that belongs to the other one.
function cardFor(body, domain) {
  var chunks = String(body).split("class=\"keycard\"");
  var mark = "<code>" + domain + "</code>";
  for (var i = 1; i < chunks.length; i += 1) {
    if (chunks[i].indexOf(mark) !== -1) return chunks[i];
  }
  return "";
}

// Whether a figure appears under its own label inside one card. The
// console writes each figure beside the label that names it, so a page
// that moved a number under the wrong heading fails here rather than
// passing on a coincidence.
function figure(card, label, value) {
  return new RegExp(">" + value + "</span>\\s*<span[^>]*>" + label + "<").test(card);
}

// One reporting window's row, asserted whole. Every figure in it is tied
// to the others by position, so a page that rendered the right numbers
// against the wrong window, or in the wrong columns, is a failure rather
// than five separate searches that each find their number somewhere.
function windowRow(card, counted, aligned, unaligned, rate, sources) {
  return new RegExp(
    "<td>" + counted   + "</td>\\s*" +
    "<td>" + aligned   + "</td>\\s*" +
    "<td>" + unaligned + "</td>\\s*" +
    "<td>" + rate      + "%</td>\\s*" +
    "<td>" + sources   + "</td>").test(card);
}

// The rendered page with its layout whitespace collapsed, for reading a
// sentence that the template wraps across lines.
function flat(body) {
  return String(body).replace(/\s+/g, " ");
}

// One of the two listing blocks the narrowed page carries, taken from its
// heading to the end of the block it opens. Asserting against the whole
// page would let an address found in the counting above stand in for one
// the listing was supposed to name.
function sectionFrom(body, heading) {
  var text = String(body);
  var at = text.indexOf(">" + heading + "<");
  if (at === -1) return "";
  var end = text.indexOf("class=\"keycard\"", at);
  return end === -1 ? text.slice(at) : text.slice(at, end);
}

// One listed sender's row, from the cell naming it to the end of the row.
// A figure asserted against the whole listing would pass on the same
// number appearing in a different sender's row.
function rowNaming(listing, value) {
  var at = listing.indexOf("<code>" + value + "</code>");
  if (at === -1) return "";
  var end = listing.indexOf("</tr>", at);
  return end === -1 ? listing.slice(at) : listing.slice(at, end);
}

async function testTheOperatorReadsTheCountingTheReportsSent(operator) {
  var page = await operator.get("/admin/dmarc");
  count("the console answers the DMARC page to a signed-in operator over the version a " +
    "browser negotiates", page.status === 200, String(page.status));
  if (page.status !== 200) return;

  count("and it is the DMARC page rather than another one that happens to answer",
    page.body.indexOf("DMARC") !== -1, page.body.replace(/\s+/g, " ").slice(0, 200));

  var card = cardFor(page.body, REPORTED);
  count("the reported domain has a block of its own on the page",
    card.length > 0, page.body.replace(/\s+/g, " ").slice(0, 400));

  count("the counted volume is the sum of what the reports counted, " + TOTAL_COUNTED,
    figure(card, "Counted", TOTAL_COUNTED), card.replace(/\s+/g, " ").slice(0, 400));
  count("the aligned volume is the mail that passed on either identifier, " + TOTAL_ALIGNED,
    figure(card, "Aligned", TOTAL_ALIGNED), card.replace(/\s+/g, " ").slice(0, 400));
  count("the unaligned volume is the rest of it, " + TOTAL_UNALIGNED,
    figure(card, "Unaligned", TOTAL_UNALIGNED), card.replace(/\s+/g, " ").slice(0, 400));
  count("and the alignment rate is those two as a percentage, " + TOTAL_RATE,
    card.indexOf(TOTAL_RATE + "%") !== -1, card.replace(/\s+/g, " ").slice(0, 400));

  // Per window, because the totals above are one number over a range and
  // an operator deciding whether a policy can move reads whether the
  // failures are one bad day or every day. Each row carries its own
  // failing-source count: one relay sending forty messages is one
  // source, so that number is counted rather than derived from volume.
  count("the first window is listed with its own counting, its own alignment rate and its " +
    "own two failing sources",
    windowRow(card,
      WINDOW_ONE_ALIGNED + WINDOW_ONE_FAIL_HEAVY + WINDOW_ONE_FAIL_LIGHT,
      WINDOW_ONE_ALIGNED,
      WINDOW_ONE_FAIL_HEAVY + WINDOW_ONE_FAIL_LIGHT,
      Math.round((WINDOW_ONE_ALIGNED /
        (WINDOW_ONE_ALIGNED + WINDOW_ONE_FAIL_HEAVY + WINDOW_ONE_FAIL_LIGHT)) * 100),
      WINDOW_ONE_SOURCES),
    card.replace(/\s+/g, " ").slice(0, 900));

  count("and so is the second, whose aligned half passed one identifier and failed the " +
    "other, and which saw one failing source rather than two",
    windowRow(card,
      WINDOW_TWO_ALIGNED + WINDOW_TWO_FAILING,
      WINDOW_TWO_ALIGNED,
      WINDOW_TWO_FAILING,
      Math.round((WINDOW_TWO_ALIGNED / (WINDOW_TWO_ALIGNED + WINDOW_TWO_FAILING)) * 100),
      WINDOW_TWO_SOURCES),
    card.replace(/\s+/g, " ").slice(0, 900));

  // This server holds no credential for any zone, and on that
  // configuration the page reads and does not write. Publishing is
  // offered only where there is something to publish through, so a
  // deployment whose operator holds their own DNS gets a page with
  // nothing on it that posts back.
  count("nothing on the page posts back to it, so no reading here can change a policy",
    /<form[^>]*method="post"[^>]*action="\/admin\/dmarc"/i.test(page.body) === false &&
    /action="\/admin\/dmarc"[^>]*method="post"/i.test(page.body) === false,
    flat(page.body).slice(0, 300));
  count("and the page says where a record is published instead, rather than leaving the " +
    "reader to look for a button that is not there",
    flat(page.body).indexOf("Nothing on this page changes a DMARC record") !== -1,
    flat(page.body).slice(-600));

  return page;
}

// The other half of the same claim. A form that is not rendered is not a
// route that refuses, and the difference is the whole question: a post
// composed by hand, or replayed from a page served by a server that did
// hold a credential, arrives at the route either way.
async function testTheZoneVerbsRefuseWhenThisServerEditsNoZone(operator) {
  var attempt = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: REPORTED,
    level:  "none",
    reason: "publish a record on a server that holds no credential",
  });
  count("a post asking this server to publish a record is refused when it edits no zone",
    attempt.status === 503, String(attempt.status));
  count("and the refusal is a problem document under its own type rather than a page",
    String(attempt.headers["content-type"] || "").indexOf("application/problem+json") !== -1,
    String(attempt.headers["content-type"]) + " " + flat(attempt.body).slice(0, 200));

  var parsed;
  try { parsed = JSON.parse(attempt.body); } catch (_e) { parsed = null; }
  count("the type names what is missing rather than what was asked for",
    parsed !== null && parsed.type === "urn:blamepost:problem:zone-writer-not-configured",
    flat(attempt.body).slice(0, 300));
  count("and the detail names the setting an operator would change",
    parsed !== null && typeof parsed.detail === "string" &&
    parsed.detail.indexOf("BLAMEPOST_ZONE_PROVIDER") !== -1,
    parsed === null ? flat(attempt.body).slice(0, 300) : String(parsed.detail).slice(0, 300));
}

async function testADomainNobodyHasReportedOnIsShownRatherThanOmitted(operator) {
  var page = await operator.get("/admin/dmarc");
  if (page.status !== 200) return;

  var card = cardFor(page.body, QUIET);
  count("a hosted domain no receiver has reported on still has a block on the page, " +
    "because a domain left out of a listing reads as a domain with nothing wrong",
    card.length > 0, page.body.replace(/\s+/g, " ").slice(0, 600));
  count("and it says it has no counted evidence rather than showing a zero, which is a " +
    "different claim",
    card.indexOf("No reports counted") !== -1, card.replace(/\s+/g, " ").slice(0, 400));

  // Where it sits on the page. The domain with nothing counted is the
  // one an operator cannot see any other way, so it is placed above the
  // domains whose numbers are already on the screen.
  count("and it is placed above the domains that do have counting, because that is the " +
    "state the page exists to make visible",
    page.body.indexOf("<code>" + QUIET + "</code>") <
      page.body.indexOf("<code>" + REPORTED + "</code>"),
    page.body.indexOf("<code>" + QUIET + "</code>") + " before " +
      page.body.indexOf("<code>" + REPORTED + "</code>"));
}

// Reports arriving and none of them counting is not the same reading as
// no reports arriving, and it is the louder one: it says either that this
// server is not authenticating what reaches its reporting address, or
// that somebody else is writing to it. An operator handed a zero with no
// way to tell the two apart reads a working server as a broken one.
async function testADomainWhoseReportsAllWentUncountedSaysSo(operator) {
  var page = await operator.get("/admin/dmarc");
  if (page.status !== 200) return;

  var card = cardFor(page.body, UNCOUNTED);
  count("a domain whose every report was left out has a block of its own",
    card.length > 0, flat(page.body).slice(0, 700));
  count("and it says nothing counted rather than reporting no reports, which is the other " +
    "domain's state and not this one",
    card.indexOf("Nothing counted.") !== -1 &&
    card.indexOf("No reports counted.") === -1,
    flat(card).slice(0, 600));
  count("and the volume that was left out is readable on it",
    card.indexOf("Left out: " + UNCOUNTED_MESSAGES + " messages") !== -1,
    flat(card).slice(0, 700));

  count("the page leads with it, above the domain nobody has reported on and above the " +
    "domains that do have counting",
    page.body.indexOf("<code>" + UNCOUNTED + "</code>") <
      page.body.indexOf("<code>" + QUIET + "</code>"),
    page.body.indexOf("<code>" + UNCOUNTED + "</code>") + " before " +
      page.body.indexOf("<code>" + QUIET + "</code>"));

  count("and it is called out at the top of the page rather than only in its own block, " +
    "because it is a reading that is wrong rather than one that is bad",
    flat(page.body).indexOf("and none of them counted") !== -1,
    flat(page.body).slice(0, 900));
}

// A report anybody could have written is not evidence, and the store
// leaves its volume out of the counting. That leaves an operator with a
// total lower than the one their receivers' own dashboards show, and no
// way to tell a quiet domain from a domain whose reports were all
// discarded. So what was left out has to be readable, and it has to be
// somewhere the counted figures are not.
async function testWhatWasLeftOutIsShownApartFromWhatWasCounted(operator) {
  var page = await operator.get("/admin/dmarc");
  if (page.status !== 200) return;
  var card = cardFor(page.body, REPORTED);

  count("the volume left out of the counting is named on the page rather than being " +
    "missing from a total with nowhere to read it",
    card.indexOf("Left out: " + EXCLUDED_MESSAGES + " messages") !== -1,
    flat(card).slice(0, 700));

  count("and the counted volume is still the counted volume, " + TOTAL_COUNTED +
    ", rather than that number folded into it",
    figure(card, "Counted", TOTAL_COUNTED) &&
    figure(card, "Counted", TOTAL_COUNTED + EXCLUDED_MESSAGES) === false,
    flat(card).slice(0, 700));

  // Separate rather than a column, because the two answer different
  // questions and a reader scanning the counting must not pick one of
  // these figures out of it by accident.
  var apart = card.indexOf("Left out:");
  var counted = apart === -1 ? card : card.slice(0, apart);
  count("nothing that was left out appears among the counted reporting windows",
    counted.indexOf(">" + EXCLUDED_MESSAGES + "<") === -1,
    flat(counted).slice(0, 700));

  count("and the window that carried it is listed under what was left out, so the volume " +
    "can be placed in time rather than being one number",
    apart !== -1 && card.slice(apart).indexOf(">" + EXCLUDED_MESSAGES + "<") !== -1,
    flat(card.slice(apart === -1 ? 0 : apart)).slice(0, 500));
}

// The question this console exists to answer and a count cannot: which
// machines are sending mail that claims the domain and fails alignment.
// An operator cannot fix an SPF record, or block a relay, from a number.
//
// The addresses are sealed on the volume, so the page unseals them, and
// that is exactly why what goes into the list is the whole question.
// Anybody who can send mail to a published reporting address can compose
// a report naming any address and any volume, so a page drawing on one
// would be handing an operator a machine somebody else chose. The
// discriminating row is the fourth address: it fails on both identifiers
// and it appears only inside the report this server did not
// authenticate.
async function testTheFailingSendersAreNamedFromAuthenticatedReportsOnly(operator) {
  var page = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(REPORTED));
  count("the page narrowed to one domain answers", page.status === 200, String(page.status));
  if (page.status !== 200) return;

  var listing = sectionFrom(page.body, "Failing senders");
  count("the page narrowed to a domain lists the senders rather than only counting them",
    listing.length > 0, flat(page.body).slice(0, 600));

  count("the sender that failed on the most mail is named, as an address rather than a hash",
    listing.indexOf("<code>" + HEAVY_SOURCE + "</code>") !== -1, flat(listing).slice(0, 900));
  count("and so is the one that failed on the least, so the list is not only the loudest",
    listing.indexOf("<code>" + LIGHT_SOURCE + "</code>") !== -1, flat(listing).slice(0, 900));
  count("a sender named only by a report this server did not authenticate is not listed",
    listing.indexOf(EXCLUDED_SOURCE) === -1, flat(listing).slice(0, 900));
  count("and neither is a sender whose mail aligned, which is not a failing sender at all",
    listing.indexOf("<code>" + ALIGNED_SOURCE + "</code>") === -1,
    flat(listing).slice(0, 900));

  // The lighter sender is filed first, so a listing handed back in the
  // order the rows were written reads in the opposite order here.
  count("the list is ordered by the volume each sender failed on rather than by arrival",
    listing.indexOf("<code>" + HEAVY_SOURCE + "</code>") <
      listing.indexOf("<code>" + LIGHT_SOURCE + "</code>"),
    flat(listing).slice(0, 900));

  var heavyRow = rowNaming(listing, HEAVY_SOURCE);
  count("the volume a sender failed on is in that sender's own row, summed over its windows",
    heavyRow.indexOf("<td>" + HEAVY_FAILED + "</td>") !== -1, flat(heavyRow));
  count("and so is how many reporting windows saw it, so one relay reads as one",
    heavyRow.indexOf("<td>2</td>") !== -1, flat(heavyRow));
  count("the lighter sender carries its own volume rather than the other one's",
    rowNaming(listing, LIGHT_SOURCE).indexOf("<td>" + LIGHT_FAILED + "</td>") !== -1,
    flat(rowNaming(listing, LIGHT_SOURCE)));

  // The excluded volume is kept out of the list and shown apart from it,
  // the way the counting above already separates the two readings.
  var apart = listing.indexOf("Left out:");
  count("the failing volume nobody authenticated is named apart from the list",
    apart !== -1 && listing.slice(apart).indexOf(String(EXCLUDED_MESSAGES)) !== -1,
    flat(listing.slice(apart === -1 ? 0 : apart)).slice(0, 600));
  count("and none of it appears among the senders that were listed",
    listing.slice(0, apart === -1 ? listing.length : apart)
      .indexOf(">" + EXCLUDED_MESSAGES + "<") === -1,
    flat(listing).slice(0, 900));

  // The overview is not where this list belongs. It renders a card per
  // hosted domain, and a page that read the senders for every one of them
  // would be reading a list nobody can act on until they have picked a
  // domain.
  var overview = await operator.get("/admin/dmarc");
  count("the overview over every domain does not list any sending address",
    overview.status === 200 && overview.body.indexOf("<code>" + HEAVY_SOURCE + "</code>") === -1,
    String(overview.status));
}

// A receiver that stopped reporting and a domain whose mail all aligns
// read the same on the counting: both are quiet. They need opposite
// responses, and the only thing that separates them is who was last heard
// from and when. The console had a date derived from the window a
// reporter declared, which is a range the reporter chose and says nothing
// about whether it is still sending.
async function testWhoHasBeenHeardFromIsNamedAndDated(operator) {
  var page = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(REPORTED));
  if (page.status !== 200) return;

  var listing = sectionFrom(page.body, "Reporting organizations");
  count("the organizations that reported are named on the page",
    listing.indexOf("<code>" + REPORTING_ORG + "</code>") !== -1,
    flat(listing).slice(0, 900));

  var row = rowNaming(listing, REPORTING_ORG);
  count("with how many of its reports this server authenticated",
    row.indexOf("<td>" + COUNTED_REPORTS + "</td>") !== -1, flat(row));
  count("and when the most recent one arrived, so silence is visible rather than inferred",
    flat(listing).indexOf("Last heard") !== -1, flat(listing).slice(0, 900));
  count("the organization is the domain its reports were authenticated for, in the row's " +
    "own heading cell",
    listing.indexOf("<th scope=\"row\"><code>" + REPORTING_ORG + "</code></th>") !== -1,
    flat(listing).slice(0, 900));
  count("and the name the reports gave is shown apart and labeled as the reporter's own " +
    "description rather than a verified identity",
    row.indexOf("<td><code>" + REPORTER_NAME + "</code>") !== -1 &&
    listing.indexOf("<th scope=\"row\"><code>" + REPORTER_NAME + "</code></th>") === -1 &&
    flat(listing).indexOf("Name in its reports") !== -1 &&
    flat(listing).indexOf("the reporter's own description of itself") !== -1 &&
    flat(listing).indexOf("this server has not verified it") !== -1,
    flat(listing).slice(0, 900));

  var apart = listing.indexOf("Left out:");
  count("the reports this server did not authenticate are counted apart from the list",
    apart !== -1 && listing.slice(apart).indexOf(String(EXCLUDED_REPORTS)) !== -1,
    flat(listing.slice(apart === -1 ? 0 : apart)).slice(0, 600));
  count("and the count of them agrees with the noun beside it rather than reading 1 reports",
    flat(listing).indexOf(EXCLUDED_REPORTS + " report that this server") !== -1,
    flat(listing.slice(apart === -1 ? 0 : apart)).slice(0, 400));

  // A domain nobody reported on has to say so here as well. It is the
  // reading that sends an operator to check the record rather than
  // concluding their mail is fine.
  var quiet = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(QUIET));
  count("a domain no reporter was heard from about says nobody has been heard from",
    quiet.status === 200 &&
    flat(sectionFrom(quiet.body, "Reporting organizations"))
      .indexOf("Nobody has been heard from") !== -1,
    flat(sectionFrom(quiet.body, "Reporting organizations")).slice(0, 600));
}

async function testTheWindowThePageReadIsTheWindowItSaysItRead(operator) {
  var asked = await operator.get("/admin/dmarc?days=7");
  count("a window named in the request is the one the page says it read",
    asked.status === 200 && flat(asked.body).indexOf("over the last 7 days") !== -1,
    asked.status + " " + flat(asked.body).slice(0, 400));

  // Rows older than the retention window are gone, so a page offering to
  // read further back would offer an emptier answer than the shorter one.
  var tooFar = await operator.get("/admin/dmarc?days=99999");
  count("a window longer than this server keeps rows for is read back as the window it " +
    "actually kept, " + AGGREGATE_DAYS + " days",
    tooFar.status === 200 &&
    flat(tooFar.body).indexOf("over the last " + AGGREGATE_DAYS + " days") !== -1,
    tooFar.status + " " + flat(tooFar.body).slice(0, 400));

  var nonsense = await operator.get("/admin/dmarc?days=notanumber");
  count("and a window that is not a number at all renders the page over the default rather " +
    "than refusing the request",
    nonsense.status === 200, String(nonsense.status));
}

// Every entry in the console navigation answers. A page reachable and
// unlinked is invisible and a link to a page that is not there is
// navigation that answers 404, and neither state is one that a test of
// any single page can see, because each of those drives one page.
async function testEveryConsoleNavigationEntryAnswers(operator) {
  var page = await operator.get("/admin");
  count("the console overview answers, so there is a navigation to read",
    page.status === 200, String(page.status));
  if (page.status !== 200) return;

  var targets = [];
  var re = /class="adminnav-link[^"]*"\s+href="([^"]+)"/g;
  var found;
  while ((found = re.exec(page.body)) !== null) targets.push(found[1]);
  count("the navigation was read rather than missed, so this claim answers for something",
    targets.length > 0, targets.join(", "));
  count("and the DMARC page is linked from it rather than being reachable and unlisted",
    targets.indexOf("/admin/dmarc") !== -1, targets.join(", "));

  for (var i = 0; i < targets.length; i += 1) {
    var reached = await operator.get(targets[i]);
    count("the console navigation entry " + targets[i] + " answers to an operator",
      reached.status === 200, targets[i] + " -> " + reached.status);
  }
}

async function testARequestedDomainIsResolvedBeforeAnythingReadsIt(operator) {
  var hosted = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(QUIET));
  count("naming one hosted domain narrows the page to it",
    hosted.status === 200 && cardFor(hosted.body, QUIET).length > 0 &&
    cardFor(hosted.body, REPORTED).length === 0,
    hosted.status + " " + hosted.body.replace(/\s+/g, " ").slice(0, 400));

  var stranger = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(HOSTILE_DOMAIN));
  count("a domain this server does not host is resolved away before anything reads it, so " +
    "the page answers rather than refusing", stranger.status === 200, String(stranger.status));
  count("and no part of what was asked for reaches the rendered page, in any form",
    stranger.body.indexOf("alert(1)") === -1 &&
    stranger.body.indexOf("<script>alert") === -1,
    stranger.body.replace(/\s+/g, " ").slice(0, 400));
}

async function testAnAccountWithoutTheRoleCannotReachIt(reader) {
  var page = await reader.get("/admin/dmarc");
  count("an account that does not administer this server is refused the DMARC page",
    page.status === 403, String(page.status));
  count("and the refusal names the role rather than the page, so the reader knows what to " +
    "ask for", page.body.indexOf("does not administer this server") !== -1,
    page.body.replace(/\s+/g, " ").slice(0, 300));
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("web-dmarc-console");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var server  = null;
  var running = false;

  try {
    process.env.BLAMEJS_TMPDIR = workDir;

    var material = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:                       HOSTNAME,
        BLAMEPOST_DATA_DIR:                       dataDir,
        BLAMEPOST_VAULT_PASSPHRASE:               VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED:               "1",
        BLAMEPOST_TLS_CERT:                       material.certFile,
        BLAMEPOST_TLS_KEY:                        material.keyFile,
        BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS: String(AGGREGATE_DAYS),
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: REPORTED });
    await identity.domains.add({ domain: QUIET });
    await identity.domains.add({ domain: UNCOUNTED });
    await identity.accounts.create({
      address: OPERATOR_ADDRESS, password: OPERATOR_PASSWORD, isAdmin: true });
    await identity.accounts.create({
      address: READER_ADDRESS, password: READER_PASSWORD });

    fileTheReports(identity.reports, Date.now());

    // Every mail listener off. This file is about the browser surface,
    // and a port taken is a port another file in the same run cannot
    // have.
    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = {
        enabled: false,
        port:    await wire.reservePort(),
        address: LOOPBACK,
      };
    }

    server = blamepost.create({
      config:       Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;

    var operator = browser.browserAt(origin, { ca: material.caPem, http2: true });
    var signedIn = await operator.signIn(OPERATOR_ADDRESS, OPERATOR_PASSWORD);
    count("the operator signs in to the console over HTTP/2",
      signedIn.status === 302 || signedIn.status === 303,
      signedIn.status + " " + String(signedIn.body).replace(/\s+/g, " ").slice(0, 200));

    await testTheOperatorReadsTheCountingTheReportsSent(operator);
    await testADomainNobodyHasReportedOnIsShownRatherThanOmitted(operator);
    await testWhatWasLeftOutIsShownApartFromWhatWasCounted(operator);
    await testADomainWhoseReportsAllWentUncountedSaysSo(operator);
    await testTheFailingSendersAreNamedFromAuthenticatedReportsOnly(operator);
    await testWhoHasBeenHeardFromIsNamedAndDated(operator);
    await testTheWindowThePageReadIsTheWindowItSaysItRead(operator);
    await testARequestedDomainIsResolvedBeforeAnythingReadsIt(operator);
    await testTheZoneVerbsRefuseWhenThisServerEditsNoZone(operator);
    await testEveryConsoleNavigationEntryAnswers(operator);

    var reader = browser.browserAt(origin, { ca: material.caPem, http2: true });
    var readerIn = await reader.signIn(READER_ADDRESS, READER_PASSWORD);
    count("the account holding no operator role signs in to its own mailbox",
      readerIn.status === 302 || readerIn.status === 303,
      readerIn.status + " " + String(readerIn.body).replace(/\s+/g, " ").slice(0, 200));
    await testAnAccountWithoutTheRoleCannotReachIt(reader);

    await server.stop({ timeoutMs: STOP_MS });
    running = false;

    return helpers.getChecks();
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: STOP_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
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
  name:      "web-dmarc-console",
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
