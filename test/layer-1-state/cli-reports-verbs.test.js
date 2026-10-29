// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The `reports` verbs, driven through the shipped binary.
 *
 * What a peer reports about a hosted domain is the only reading an
 * operator has of mail sent in that domain's name from somewhere else,
 * and four things about reading it back can be wrong in ways that look
 * exactly like the right answer.
 *
 * A total can be short. Reports whose carrier this server could not
 * authenticate are left out of the counting, which is correct and is
 * also a number an operator would act on without knowing it had been
 * removed, so both numbers are read back here and the wide reading is
 * checked against the narrow one.
 *
 * An absence can read as a clean bill. A domain nobody reports on prints
 * the same totals as a domain nobody spoofs, so the verb has to say which
 * of the two it is looking at, and a hosted domain with no reports is in
 * this fixture for that reason alone.
 *
 * A reading can be refused at the moment it is wanted. `list` and `show`
 * are reached while a domain looks like it is being spoofed, which is
 * while the server is running and holding the data volume, so both are
 * driven here against a volume this process is holding open.
 *
 * And an erasure can report success over rows it left behind. The person
 * whose message headers reached a forensic report has no account here and
 * no verb of their own, so `forget` is run and then the rows are read back
 * through a fresh open rather than the verb's own output being believed.
 *
 * Everything spawns the real binary. The status comes from the spawn and
 * never from a pipeline, because a pipeline reports the last command's
 * status and would make a correct refusal look like success.
 *
 * Run standalone: node test/layer-1-state/cli-reports-verbs.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var tables    = require("../../lib/store/tables");

var count = cliHelper.count;

var HOSTNAME     = "mx.example.com";
var DOMAIN       = "example.com";
var QUIET_DOMAIN = "example.net";

// A domain whose one report is evidence and carries no recorded
// organization, which is what every verified report stored before the
// organization was recorded looks like.
var UNATTRIBUTED_DOMAIN   = "example.org";
var UNATTRIBUTED_REPORTER = "earlier-reporter.example";
var UNATTRIBUTED_MESSAGES = 6;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The two reporting organizations, kept apart by what this server
// concluded about the message each one's report arrived in. Only the
// first counts toward a reading a policy is moved on.
var VERIFIED_REPORTER   = "verified-reporter.example";
var UNVERIFIED_REPORTER = "unverified-reporter.example";

// The stranger whose envelope a forensic report carries. They have no
// account on this server, which is the whole reason `forget` exists, and
// their address is what the read-back after the erasure looks for.
var STRANGER  = "stranger@third-party.example";
var RECIPIENT = "victim@" + VERIFIED_REPORTER;

// The reporting period the fixture reports cover. It sits inside the
// thirty days the verbs read by default, so a run measures the default
// range rather than one the test had to widen.
var DAY_MS       = 86400000;
var WINDOW_END   = Math.floor((Date.now() - DAY_MS) / 1000);
var WINDOW_BEGIN = WINDOW_END - 86400;

// The arithmetic the fixture is built to produce, written here so a
// failure prints the number that moved rather than a recomputation of
// whatever the code did.
//
// The authenticated report counts 7 aligned on both identifiers, 2
// aligned on one, and 3 plus 5 aligned on neither. The report nobody
// authenticated counts 100, all of it failing both.
var COUNTED_VERIFIED   = 17;
var ALIGNED_VERIFIED   = 9;
var UNALIGNED_VERIFIED = COUNTED_VERIFIED - ALIGNED_VERIFIED;
var UNAUTHENTICATED    = 100;
var COUNTED_WIDE       = COUNTED_VERIFIED + UNAUTHENTICATED;
var FAILING_SOURCES_VERIFIED = 2;
var FAILING_SOURCES_WIDE     = 3;

// The sending address the authenticated report counts most mail from,
// and the one only the unauthenticated report names.
var BIGGEST_FAILING_SOURCE  = "198.51.100.9";
var UNAUTHENTICATED_SOURCE  = "192.0.2.55";

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
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>" + opts.org + "</org_name>\n" +
    "    <email>dmarc-noreply@" + opts.org + "</email>\n" +
    "    <report_id>" + opts.reportId + "</report_id>\n" +
    "    <date_range><begin>" + WINDOW_BEGIN + "</begin><end>" + WINDOW_END +
    "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + (opts.domain || DOMAIN) + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>reject</p><sp>reject</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    opts.records.join("") +
    "</feedback>\n";
}

// One per-message failure report, carrying a stranger's envelope. The
// message it is about is deliberately in it, because the store's promise
// is that no column can hold one.
function forensicMessage(rcptTo) {
  return "From: dmarc-noreply@" + VERIFIED_REPORTER + "\r\n" +
    "To: ruf@" + DOMAIN + "\r\n" +
    "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd7\"\r\n" +
    "\r\n" +
    "--bnd7\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "An authentication failure report.\r\n" +
    "\r\n" +
    "--bnd7\r\n" +
    "Content-Type: message/feedback-report\r\n" +
    "\r\n" +
    "Feedback-Type: auth-failure\r\n" +
    "User-Agent: Reporter/1.0\r\n" +
    "Version: 1\r\n" +
    "Auth-Failure: dmarc\r\n" +
    "Original-Mail-From: " + STRANGER + "\r\n" +
    "Original-Rcpt-To: " + rcptTo + "\r\n" +
    "Arrival-Date: Mon, 01 Sep 2025 09:00:00 +0000\r\n" +
    "Reported-Domain: " + DOMAIN + "\r\n" +
    "Source-IP: 203.0.113.99\r\n" +
    "Delivery-Result: reject\r\n" +
    "Identity-Alignment: none\r\n" +
    "DKIM-Domain: " + DOMAIN + "\r\n" +
    "DKIM-Selector: s1\r\n" +
    "\r\n" +
    "--bnd7\r\n" +
    "Content-Type: message/rfc822\r\n" +
    "\r\n" +
    "From: \"Someone Real\" <" + STRANGER + ">\r\n" +
    "To: " + rcptTo + "\r\n" +
    "Subject: a stranger's subject line\r\n" +
    "\r\n" +
    "the body of somebody else's message\r\n" +
    "\r\n" +
    "--bnd7--\r\n";
}

function parseJson(text) {
  try { return JSON.parse(text); }
  catch (_e) { return null; }
}

// The reading for one domain out of `reports list --json`, which is an
// array with one entry per domain.
function readingFor(parsed, domain) {
  if (!Array.isArray(parsed)) return null;
  for (var i = 0; i < parsed.length; i += 1) {
    if (parsed[i] && parsed[i].domain === domain) return parsed[i];
  }
  return null;
}

// ---- what a listing says ---------------------------------------------------

// The counting, and the volume it leaves out. Both numbers are read back
// because a total that is short and says nothing is the reading an
// operator moves a policy on.
function theListingPublishesBothNumbers(cli) {
  var listed = cli(["reports", "list", "--json"]);
  count("`reports list` answers", listed.status === 0,
    "exit " + listed.status + " " + listed.both.slice(0, 300));

  var reading = readingFor(parseJson(listed.stdout), DOMAIN);
  count("and it carries a reading for the domain that was reported on",
    reading !== null, listed.stdout.slice(0, 400));
  if (reading === null) return;

  count("the counting is over the reports this server authenticated and nothing else",
    reading.counted === COUNTED_VERIFIED,
    "counted " + reading.counted + ", expected " + COUNTED_VERIFIED);
  count("the aligned volume is the part that passed on either identifier",
    reading.aligned === ALIGNED_VERIFIED,
    "aligned " + reading.aligned + ", expected " + ALIGNED_VERIFIED);
  count("and the unaligned volume is the rest of it",
    reading.unaligned === UNALIGNED_VERIFIED,
    "unaligned " + reading.unaligned + ", expected " + UNALIGNED_VERIFIED);
  count("the volume left out of that counting is published beside it rather than dropped",
    reading.unauthenticated === UNAUTHENTICATED,
    "unauthenticated " + reading.unauthenticated + ", expected " + UNAUTHENTICATED);
  count("the sources failing both alignments are counted over the same set as the totals",
    reading.failingSourceCount === FAILING_SOURCES_VERIFIED,
    "failingSourceCount " + reading.failingSourceCount + ", expected " +
    FAILING_SOURCES_VERIFIED);
  count("an organization is published as the domain its report was authenticated for",
    reading.organizationCount === 1 && Array.isArray(reading.organizations) &&
    reading.organizations.length === 1 &&
    reading.organizations[0].organization === VERIFIED_REPORTER,
    JSON.stringify(reading.organizations));
  count("and each report row keeps that domain apart from the name the report gave itself",
    Array.isArray(reading.reportsShown) && reading.reportsShown.some(function (row) {
      return row.organization === VERIFIED_REPORTER && row.orgName === VERIFIED_REPORTER;
    }) && reading.reportsShown.some(function (row) {
      return row.organization === null && row.orgName === UNVERIFIED_REPORTER;
    }), JSON.stringify(reading.reportsShown).slice(0, 400));

  var text = cli(["reports", "list"]);
  count("the text an operator reads names the volume that was left out",
    text.stdout.indexOf(String(UNAUTHENTICATED)) !== -1, text.stdout.slice(0, 900));
  count("and names the command that folds it back in",
    text.stdout.indexOf("--include-unauthenticated") !== -1, text.stdout.slice(0, 900));
  count("and names the largest failing sending address, which is the one being acted on",
    text.stdout.indexOf(BIGGEST_FAILING_SOURCE) !== -1, text.stdout.slice(0, 900));
  count("and names the organization that reported",
    text.stdout.indexOf(VERIFIED_REPORTER) !== -1, text.stdout.slice(0, 900));
  count("and labels the name a report gives itself as the report's own words",
    text.stdout.indexOf("the name its reports give: " + VERIFIED_REPORTER) !== -1,
    text.stdout.slice(0, 1400), { limit: 1400 });

  // The sending addresses are sealed on the volume, so listing them
  // unseals them, and the store records that somebody did. A listing
  // that grouped the rows itself rather than composing the store's own
  // reading would print the same addresses and leave no row at all,
  // which is what this reads back.
  var trail = cli(["audit", "read", "--action", "blamepost.store.reports.sources_read",
    "--limit", "5", "--json"]);
  count("reading the failing senders leaves a row saying somebody unsealed them",
    trail.status === 0 && trail.stdout.indexOf("sources_read") !== -1,
    "exit " + trail.status + " " + trail.stdout.slice(0, 300));
  count("and the row names the domain the addresses were read for",
    trail.stdout.indexOf(DOMAIN) !== -1, trail.stdout.slice(0, 400));
}

// The wide reading. It is the one an operator takes when a number looks
// wrong, so it has to move every total rather than only the one that was
// short.
function theExcludedReportsAreReachable(cli) {
  var wide = cli(["reports", "list", "--include-unauthenticated", "--json"]);
  count("`reports list --include-unauthenticated` answers", wide.status === 0,
    "exit " + wide.status + " " + wide.both.slice(0, 300));

  var reading = readingFor(parseJson(wide.stdout), DOMAIN);
  count("and it carries a reading for the domain", reading !== null,
    wide.stdout.slice(0, 400));
  if (reading === null) return;

  count("the wide counting folds the unauthenticated volume in",
    reading.counted === COUNTED_WIDE,
    "counted " + reading.counted + ", expected " + COUNTED_WIDE);
  count("and it still says how much of that nobody authenticated, so the two readings " +
    "cannot be confused for one another",
    reading.unauthenticated === UNAUTHENTICATED,
    "unauthenticated " + reading.unauthenticated);
  count("the failing sources move with it, so the list and the totals agree",
    reading.failingSourceCount === FAILING_SOURCES_WIDE,
    "failingSourceCount " + reading.failingSourceCount + ", expected " +
    FAILING_SOURCES_WIDE);

  var wideText = cli(["reports", "list", "--include-unauthenticated"]);
  count("and the sending address only the unauthenticated report named is now listed",
    wideText.stdout.indexOf(UNAUTHENTICATED_SOURCE) !== -1, wideText.stdout.slice(0, 900));

  var narrowText = cli(["reports", "list"]);
  count("while the narrow reading leaves that address out, because the report naming it " +
    "is not evidence",
    narrowText.stdout.indexOf(UNAUTHENTICATED_SOURCE) === -1, narrowText.stdout.slice(0, 900));
}

// A domain nobody has reported on. Its totals are the totals of a domain
// nobody is spoofing, so the absence has to be said in words.
function aDomainNobodyReportsOnSaysSo(cli) {
  var listed = cli(["reports", "list", "--domain", QUIET_DOMAIN]);
  count("`reports list --domain` answers for a hosted domain with no reports",
    listed.status === 0, "exit " + listed.status + " " + listed.both.slice(0, 300));
  count("and it says no report has arrived rather than printing zeroes",
    /No aggregate report/.test(listed.stdout), listed.stdout.slice(0, 600));
  count("and it points at the record that decides where reports are sent",
    listed.stdout.indexOf("rua=") !== -1, listed.stdout.slice(0, 600));

  var quiet = readingFor(parseJson(cli(["reports", "list", "--json"]).stdout), QUIET_DOMAIN);
  count("the structured answer carries the quiet domain too, so a script sees the gap",
    quiet !== null && quiet.reports === 0,
    quiet === null ? "absent" : JSON.stringify(quiet.reports));
}

// A verified report with no recorded organization. Its messages are in the
// totals, it names no organization, and the listing says how many such
// reports there are.
function aReportWithNoRecordedOrganizationCountsTowardNone(cli) {
  var reading = readingFor(parseJson(cli(["reports", "list", "--json"]).stdout),
    UNATTRIBUTED_DOMAIN);
  count("a verified report with no recorded organization keeps its messages in the totals",
    reading !== null && reading.counted === UNATTRIBUTED_MESSAGES,
    reading === null ? "absent" : JSON.stringify(reading).slice(0, 400));
  if (reading === null) return;
  count("and counts toward no organization",
    reading.organizationCount === 0 && reading.organizations.length === 0,
    JSON.stringify(reading.organizations));
  count("and the structured answer says how many reports that is",
    reading.unattributedReports === 1, String(reading.unattributedReports));

  var text = cli(["reports", "list", "--domain", UNATTRIBUTED_DOMAIN]);
  count("the text says those reports count toward no organization",
    text.status === 0 && flatText(text.stdout).indexOf("1 report in the totals arrived before " +
      "this server recorded the domain a report passed DMARC for. A report like that counts " +
      "toward no organization.") !== -1,
    text.stdout.slice(0, 900));
}

function flatText(value) {
  return String(value).replace(/\s+/g, " ");
}

// ---- what one report says --------------------------------------------------

function oneReportReadsBackWithWhatItCarried(cli) {
  var reading = readingFor(parseJson(cli(["reports", "list", "--json"]).stdout), DOMAIN);
  count("the listing hands back report ids to look one up with",
    reading !== null && Array.isArray(reading.reportsShown) && reading.reportsShown.length === 2,
    reading === null ? "no reading" : JSON.stringify(reading.reportsShown).slice(0, 300));
  if (reading === null || !Array.isArray(reading.reportsShown)) return;

  var verified = reading.reportsShown.filter(function (row) { return row.counted; })[0];
  var excluded = reading.reportsShown.filter(function (row) { return !row.counted; })[0];
  count("one of them counts and one of them does not, which is what the listing said",
    verified !== undefined && excluded !== undefined,
    JSON.stringify(reading.reportsShown).slice(0, 400));
  if (verified === undefined || excluded === undefined) return;

  var shown = cli(["reports", "show", verified.id, "--json"]);
  count("`reports show` answers for an id the listing printed", shown.status === 0,
    "exit " + shown.status + " " + shown.both.slice(0, 300));
  var report = parseJson(shown.stdout);
  count("and it carries every record the report stored",
    report !== null && report.recordsHeld === 4,
    report === null ? shown.stdout.slice(0, 300) : String(report.recordsHeld));
  count("and the records name the sending addresses the reporter counted",
    report !== null && Array.isArray(report.records) &&
      report.records.some(function (row) { return row.sourceIp === BIGGEST_FAILING_SOURCE; }),
    report === null ? "" : JSON.stringify(report.records).slice(0, 400));

  var shownText = cli(["reports", "show", verified.id]);
  count("the text names the policy the reporter judged the mail against",
    /p=reject/.test(shownText.stdout), shownText.stdout.slice(0, 600));
  count("and says this server authenticated the message that carried it",
    /authenticated the message/.test(shownText.stdout), shownText.stdout.slice(0, 600));
  count("and names the organization it counts as apart from the name it gave itself",
    shownText.stdout.indexOf("counted as the organization " + VERIFIED_REPORTER) !== -1 &&
      shownText.stdout.indexOf("the name the report gives itself: " + VERIFIED_REPORTER) !== -1,
    shownText.stdout.slice(0, 600));

  var excludedText = cli(["reports", "show", excluded.id]);
  count("a report this server did not authenticate says so, and names the verdict",
    /did not authenticate/.test(excludedText.stdout) &&
      excludedText.stdout.indexOf("carrier-dmarc-not-pass") !== -1,
    excludedText.stdout.slice(0, 600));
  count("and it counts as no organization, whatever name it gave",
    excludedText.stdout.indexOf("counted as the organization (none") !== -1,
    excludedText.stdout.slice(0, 600));

  var absent = cli(["reports", "show", "no-such-report-id"]);
  count("an id no row holds is refused rather than answered with an empty report",
    absent.status === 2, "exit " + absent.status + " " + absent.both.slice(0, 300));

  var empty = cli(["reports", "show"]);
  count("and `reports show` with no id prints the usage rather than reading everything",
    empty.status === 2 && /Usage: blamepost reports/.test(empty.both),
    "exit " + empty.status + " " + empty.both.slice(0, 200));
}

// ---- the erasure verb ------------------------------------------------------

// Both flags, each refused on its own. A destroying verb that took an
// absent reason would write a row that answers nothing later, and one
// that destroyed without a confirmation would take a reporting
// organization's whole counting with a mistyped address.
function theErasureVerbRefusesWithoutAReasonAndAConfirmation(cli) {
  var noReason = cli(["reports", "forget", STRANGER, "--confirm"]);
  count("`reports forget` refuses without --reason", noReason.status === 2,
    "exit " + noReason.status + " " + noReason.both.slice(0, 300));
  count("and the refusal names the flag it wants", /give --reason/.test(noReason.both),
    noReason.both.slice(0, 300));

  var noConfirm = cli(["reports", "forget", STRANGER, "--reason", "erasure request by post"]);
  count("`reports forget` refuses without --confirm", noConfirm.status === 2,
    "exit " + noConfirm.status + " " + noConfirm.both.slice(0, 300));
  count("and the refusal says a reporter's contact mailbox is matched as well, which is " +
    "the blast radius the argument does not show",
    /contact mailbox/.test(noConfirm.both), noConfirm.both.slice(0, 500));

  var notAnAddress = cli(["reports", "forget", "not an address",
    "--reason", "erasure request by post", "--confirm"]);
  count("and a value that is not an address is refused as an argument problem",
    notAnAddress.status === 2, "exit " + notAnAddress.status + " " +
    notAnAddress.both.slice(0, 300));
}

// The discriminating vector. The verb's own output is not the evidence:
// the rows are read back through a fresh open afterwards, because a
// destroying verb that reports success over rows it left behind is the
// one answer nobody can correct later.
async function theErasureDestroysTheRowsItReports(cli, cfg) {
  var before = await forensicRowsNaming(cfg, STRANGER);
  count("the fixture has a stranger's rows to erase", before.matched === 2,
    "found " + before.matched + " row(s) naming " + STRANGER);

  var erased = cli(["reports", "forget", STRANGER,
    "--reason", "erasure request received by post", "--confirm", "--json"]);
  count("`reports forget` runs against a free volume", erased.status === 0,
    "exit " + erased.status + " " + erased.both.slice(0, 400));

  var answer = parseJson(erased.stdout);
  count("and it says how many rows named the address", answer !== null && answer.matched === 2,
    erased.stdout.slice(0, 400));
  count("and how many it destroyed, so a row that stayed cannot read as one that went",
    answer !== null && answer.destroyed === answer.matched,
    answer === null ? "" : answer.destroyed + " of " + answer.matched);

  var after = await forensicRowsNaming(cfg, STRANGER);
  count("read back through a fresh open, no forensic row names that address any more",
    after.matched === 0, "found " + after.matched + " row(s) still naming " + STRANGER);
  count("and no stored row holds the address in any column at all, which is the check " +
    "the verb's own count cannot make",
    after.anywhere === 0, "found " + after.anywhere + " row(s) holding " + STRANGER);
  count("the rows belonging to other people are still there, so the erasure was bounded " +
    "by the address it was given",
    after.total === before.total - before.matched,
    "held " + after.total + " forensic row(s), was " + before.total);

  var again = cli(["reports", "forget", STRANGER,
    "--reason", "confirming it is gone", "--confirm"]);
  count("running it again over an address no row names says so rather than reporting a " +
    "second erasure",
    again.status === 0 && /No report row/.test(again.stdout),
    "exit " + again.status + " " + again.stdout.slice(0, 300));
}

// Every forensic row naming one address, read through an opener that
// sees the volume itself. Two readings rather than one: the indexed
// lookup the erasure uses, and a walk of every row comparing the
// unsealed columns, which is the one that answers even if the lookup
// stopped matching.
async function forensicRowsNaming(cfg, wanted) {
  var handle = await store.open(cfg);
  try {
    var matched = b.db.from(tables.DMARC_FORENSIC)
      .where({ originalMailFrom: wanted }).count() +
      b.db.from(tables.DMARC_FORENSIC).where({ originalRcptTo: wanted }).count();
    var all = b.db.from(tables.DMARC_FORENSIC).all();
    var anywhere = all.filter(function (row) {
      return row.originalMailFrom === wanted || row.originalRcptTo === wanted;
    }).length;
    return { matched: matched, anywhere: anywhere, total: all.length };
  } finally {
    handle.close();
  }
}

// ---- while the server holds the volume -------------------------------------

// The two readings answer, and the destroying verb does not. An operator
// reaches for `reports list` exactly when a domain looks like it is being
// spoofed, which is while the server is up.
function theReadingsAnswerFromACopyAndTheErasureRefuses(cli, reportId) {
  var listed = cli(["reports", "list"]);
  count("`reports list` answers while the server holds the volume", listed.status === 0,
    "exit " + listed.status + " " + listed.both.slice(0, 400));
  count("and it is not refused as a second opener",
    !/already open|store\/volume-in-use/i.test(listed.both), listed.both.slice(0, 400));
  count("and the answer says it came off a copy, before the answer rather than under it",
    /Snapshot of/.test(listed.stdout), listed.stdout.slice(0, 300));

  var asJson = cli(["reports", "list", "--json"]);
  var parsed = parseJson(asJson.stdout);
  count("`--json` carries the snapshot marker as well, so a script reads it too",
    parsed !== null && typeof parsed.snapshot === "object" && parsed.snapshot !== null,
    asJson.stdout.slice(0, 300));
  count("and the reading itself is still there beside it",
    parsed !== null && Array.isArray(parsed.result) &&
      parsed.result.some(function (row) { return row && row.domain === DOMAIN; }),
    JSON.stringify(parsed && parsed.result).slice(0, 300));

  var shown = cli(["reports", "show", reportId]);
  count("`reports show` answers from the copy as well", shown.status === 0,
    "exit " + shown.status + " " + shown.both.slice(0, 400));
  count("and labels its answer the same way", /Snapshot of/.test(shown.stdout),
    shown.stdout.slice(0, 300));

  var forgotten = cli(["reports", "forget", STRANGER,
    "--reason", "erasure request received by post", "--confirm"]);
  count("`reports forget` is refused while the server holds the volume, rather than " +
    "erasing rows on a copy nothing keeps",
    forgotten.status !== 0, "exit " + forgotten.status + " " +
    forgotten.both.slice(0, 400));
  count("and the refusal is the one about a second writer",
    /already open|store\/volume-in-use|different process namespace/i.test(forgotten.both),
    forgotten.both.slice(0, 400));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-reports-verbs");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var holding = null;
  try {
    process.env.BLAMEJS_TMPDIR = workDir;

    var env = {
      BLAMEPOST_HOSTNAME:               HOSTNAME,
      BLAMEPOST_DATA_DIR:               dataDir,
      BLAMEPOST_VAULT_PASSPHRASE:       VAULT_PASSPHRASE,
      // Forensic rows are what an erasure request is about, and they are
      // off unless an operator turns them on, so the fixture turns them
      // on rather than testing the erasure against an empty table.
      BLAMEPOST_DMARC_FORENSIC_ENABLED: "1",
    };
    var cfg = config.load({ env: env, cwd: root });

    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      env:             { BLAMEPOST_DMARC_FORENSIC_ENABLED: "1" },
    });

    var seeded = await store.open(cfg);
    await seeded.domains.add({ domain: DOMAIN });
    await seeded.domains.add({ domain: QUIET_DOMAIN });

    var verified = seeded.reports.ingestAggregate(aggregateXml({
      org:      VERIFIED_REPORTER,
      reportId: "0001",
      records:  [
        xmlRecord("203.0.113.10", 7, "pass", "pass", "none"),
        xmlRecord("198.51.100.4", 3, "fail", "fail", "reject"),
        xmlRecord(BIGGEST_FAILING_SOURCE, 5, "fail", "fail", "reject"),
        xmlRecord("203.0.113.77", 2, "fail", "pass", "none"),
      ],
    }), { evidence: tables.REPORT_EVIDENCE_VERIFIED, authenticatedAs: VERIFIED_REPORTER });
    count("the fixture stored the report this server authenticated",
      verified.ok === true && verified.stored === 4,
      JSON.stringify(verified).slice(0, 300));

    var unverified = seeded.reports.ingestAggregate(aggregateXml({
      org:      UNVERIFIED_REPORTER,
      reportId: "0002",
      records:  [xmlRecord(UNAUTHENTICATED_SOURCE, UNAUTHENTICATED, "fail", "fail", "none")],
    }), { evidence: "carrier-dmarc-not-pass" });
    count("and the report it could not authenticate, which is stored and not counted",
      unverified.ok === true && unverified.stored === 1,
      JSON.stringify(unverified).slice(0, 300));

    await seeded.domains.add({ domain: UNATTRIBUTED_DOMAIN });
    var unattributed = seeded.reports.ingestAggregate(aggregateXml({
      org:      UNATTRIBUTED_REPORTER,
      reportId: "0003",
      domain:   UNATTRIBUTED_DOMAIN,
      records:  [xmlRecord("203.0.113.11", UNATTRIBUTED_MESSAGES, "pass", "pass", "none")],
    }), { evidence: tables.REPORT_EVIDENCE_VERIFIED });
    count("and a verified report with no recorded organization",
      unattributed.ok === true && unattributed.stored === 1,
      JSON.stringify(unattributed).slice(0, 300));

    var filed = seeded.reports.ingestForensic(forensicMessage(RECIPIENT),
      { evidence: tables.REPORT_EVIDENCE_VERIFIED });
    var second = seeded.reports.ingestForensic(forensicMessage("other@" + VERIFIED_REPORTER),
      { evidence: tables.REPORT_EVIDENCE_VERIFIED });
    count("and two forensic rows carrying a stranger's envelope",
      filed.ok === true && filed.stored === 1 && second.ok === true && second.stored === 1,
      JSON.stringify([filed, second]).slice(0, 300));
    seeded.close();

    theListingPublishesBothNumbers(cli);
    aReportWithNoRecordedOrganizationCountsTowardNone(cli);
    theExcludedReportsAreReachable(cli);
    aDomainNobodyReportsOnSaysSo(cli);
    oneReportReadsBackWithWhatItCarried(cli);
    theErasureVerbRefusesWithoutAReasonAndAConfirmation(cli);

    // The server: one process, holding the volume for as long as it
    // serves. The flush lands the seeded rows in the encrypted file, so
    // what the copy reads is the fixture rather than an empty database.
    var reading = readingFor(parseJson(cli(["reports", "list", "--json"]).stdout), DOMAIN);
    var anId = reading && reading.reportsShown.length > 0 ? reading.reportsShown[0].id : "none";
    holding = await store.open(cfg);
    b.db.flushToDisk();
    theReadingsAnswerFromACopyAndTheErasureRefuses(cli, anId);
    holding.close();
    holding = null;

    await theErasureDestroysTheRowsItReports(cli, cfg);

    return helpers.getChecks();
  } finally {
    if (holding) {
      try { holding.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "cli-reports-verbs", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
