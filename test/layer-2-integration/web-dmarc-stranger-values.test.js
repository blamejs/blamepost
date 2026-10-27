// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a stranger writes into an aggregate report, and what the operator
 * console does with it.
 *
 * A DMARC aggregate report is mail. Anybody who can reach the published
 * reporting address sends one, and three of the values it carries are
 * free text the sender chose: the reporting organization's name, the
 * report identifier, and the sending address each record names. All
 * three are shown on the console page an operator reads during an
 * incident, the organization's name under a heading that says it is the
 * reporter's own description of itself.
 *
 * Two separate defenses answer for those values and they answer for
 * different things, which is why both are measured here rather than one
 * standing in for the other.
 *
 * The store screens each field as the report is filed. What that screen
 * refuses is a name that cannot be printed safely beside a count: a
 * control character, a name longer than the column, a bidi override
 * (CVE-2021-42574), and an invisible formatting character. A record
 * naming a sending address that is not an address is refused on its own
 * while the rest of the report is taken, because one unusable record is
 * not a reason to discard a reporter's whole window.
 *
 * The screen does NOT refuse markup, and a report is entitled to carry
 * an angle bracket: a reporter that writes `&lt;` into its own name is
 * sending well formed XML, and what arrives at the store is an ordinary
 * string with a bracket in it. That value is stored, and the page is
 * what has to render it as text. A run that only asked whether markup
 * was refused would therefore report a defense this server does not
 * have, and would be silent on the one it does.
 *
 * So both are asked: the shapes the screen turns away never reach the
 * page, and the shapes it takes reach it as text. The control matters as
 * much as either, because a screen that refused everything would satisfy
 * every refusal below while making the page useless.
 *
 * Run standalone: node test/layer-2-integration/web-dmarc-stranger-values.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var tables    = require("../../lib/store/tables");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 6620";
var OPERATOR         = "adam@" + DOMAIN;

// The names a reporter can write. Each carrier below is a separate
// reporting organization, so an accepted name gets a row of its own on
// the page rather than being folded in beside another organization's.
var PLAIN_ORG  = "Ordinary Reporter";
// Accepted by the screen and hostile to a template: no angle bracket and
// no ampersand, so the XML parses and the text guard takes it, and a
// quotation mark that would close an attribute if one were ever written
// around this value.
var ATTR_ORG   = "Reporter\" onmouseover=alert(207) x=\"";
var ATTR_RAW   = "\" onmouseover=alert(207)";
var ATTR_SHOWN = "Reporter&quot; onmouseover=alert(207) x=&quot;";

// Markup, written the way a reporter sending well formed XML writes it.
// The parser decodes the entities, so what reaches the store is a plain
// string carrying angle brackets, and the store takes it. The page is
// what has to render it as text, and that is what is asked below.
//
// The last two spell the same bytes and are kept apart because they are
// different facts: one is what the reporter puts on the wire and the
// other is what the console has to put in the document. They coincide
// because XML and HTML escape a bracket the same way, and a change to
// either end should have to move its own constant.
var MARKUP_ORG       = "<script>alert(208)</script>";
var MARKUP_ORG_XML   = "&lt;script&gt;alert(208)&lt;/script&gt;";
var MARKUP_ORG_SHOWN = "&lt;script&gt;alert(208)&lt;/script&gt;";

// The two the screen exists for. A bidi override reorders what an
// operator reads without changing the bytes, and an invisible formatting
// character hides inside a name that looks like another one.
var BIDI_ORG      = "Reporter‮txeN";
var ZERO_WIDTH_ORG = "Repor​ter Example";

var TAB_ORG    = "Reporter\tExample";
var LONG_ORG   = new Array(260).join("x");
var BAD_SOURCE = "not-an-address";

// The reasons the store publishes for each refusal. Read back by name,
// because a test asserting only that something was refused passes when
// the report was refused for an unrelated reason and stops measuring the
// screen it was written for.
var ORG_REFUSED    = "reporting-organization-refused";
var REPORT_REFUSED = "report-identifier-refused";
var SOURCE_REFUSED = "source-ip-refused";

// Every reporter-written field this file screens, which is the unit the
// run publishes. A field added to the report reader without a case here
// leaves this number where it was.
var FIELDS_SCREENED = 3;

var SHUTDOWN_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// The reports
// ---------------------------------------------------------------------------

function recordXml(domain, sourceIp, messages) {
  return "  <record>\n" +
    "    <row><source_ip>" + sourceIp + "</source_ip><count>" + messages + "</count>\n" +
    "      <policy_evaluated><disposition>none</disposition>" +
    "<dkim>fail</dkim><spf>fail</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>" + domain + "</header_from></identifiers>\n" +
    "    <auth_results><spf><domain>" + domain + "</domain>" +
    "<result>fail</result></spf></auth_results>\n" +
    "  </record>\n";
}

function aggregateXml(org, reportId, beginSeconds, endSeconds, records) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>" + org + "</org_name>\n" +
    "    <email>dmarc-noreply@reporter.example</email>\n" +
    "    <report_id>" + reportId + "</report_id>\n" +
    "    <date_range><begin>" + beginSeconds + "</begin>" +
    "<end>" + endSeconds + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + DOMAIN + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>quarantine</p><sp>quarantine</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    records.join("") +
    "</feedback>\n";
}

// One report, filed the way the reading seam files one: with the domain
// this server authenticated the carrying message for, which is what the
// store counts an organization by.
function file(reports, opts) {
  var day    = 86400;
  var nowSec = Math.floor(Date.now() / 1000);
  return reports.ingestAggregate(
    aggregateXml(opts.org, opts.reportId,
      nowSec - ((opts.daysAgo + 1) * day), nowSec - (opts.daysAgo * day),
      [recordXml(DOMAIN, opts.source, 9)]),
    { evidence: tables.REPORT_EVIDENCE_VERIFIED, authenticatedAs: opts.carrier });
}

function verdictOf(answer) {
  return JSON.stringify({
    ok: answer.ok, reason: answer.reason, stored: answer.stored, refused: answer.refused });
}

// ---------------------------------------------------------------------------
// Screened at the filing seam
// ---------------------------------------------------------------------------

// The two the screen is written for. Both are legal XML, both are short,
// and neither carries a control character, so the only thing that can
// turn either away is the text guard.
function testABidiOverrideAndAnInvisibleCharacterAreRefused(reports) {
  var bidi = file(reports, {
    org: BIDI_ORG, carrier: "bidi.example", reportId: "b-1", daysAgo: 6,
    source: "198.51.100.12",
  });
  count("a reporting organization whose name carries a bidi override is refused, and the " +
    "report it arrived in is not stored in part",
    bidi.ok === false && bidi.reason === ORG_REFUSED && bidi.stored === 0,
    verdictOf(bidi));

  var invisible = file(reports, {
    org: ZERO_WIDTH_ORG, carrier: "zw.example", reportId: "z-1", daysAgo: 16,
    source: "198.51.100.16",
  });
  count("and so is one carrying an invisible formatting character, which is how a name " +
    "reads as another name",
    invisible.ok === false && invisible.reason === ORG_REFUSED && invisible.stored === 0,
    verdictOf(invisible));
}

// The identifier is screened the same way and answers under a reason of
// its own, so a refusal names the field an operator would have to ask
// the reporter about.
function testTheReportIdentifierIsScreenedUnderItsOwnReason(reports) {
  var answer = file(reports, {
    org: PLAIN_ORG, carrier: "rid.example", reportId: BIDI_ORG, daysAgo: 12,
    source: "198.51.100.15",
  });
  count("a report identifier carrying a bidi override is refused under its own reason " +
    "rather than the organization's",
    answer.ok === false && answer.reason === REPORT_REFUSED && answer.stored === 0,
    verdictOf(answer));
}

// The two shapes that are not markup and are still wrong in a value
// printed into a table beside a count.
function testAWhitespaceControlAndAnOverlongNameAreRefused(reports) {
  var tabbed = file(reports, {
    org: TAB_ORG, carrier: "tab.example", reportId: "t-1", daysAgo: 8,
    source: "198.51.100.13",
  });
  count("a name carrying a tab is refused, because a console prints it beside a count",
    tabbed.ok === false && tabbed.reason === ORG_REFUSED, verdictOf(tabbed));

  var overlong = file(reports, {
    org: LONG_ORG, carrier: "long.example", reportId: "l-1", daysAgo: 10,
    source: "198.51.100.14",
  });
  count("and a name longer than the column takes is refused rather than cut down to fit",
    overlong.ok === false && overlong.reason === ORG_REFUSED, verdictOf(overlong));
}

// A record is refused on its own. The reporter's window is otherwise
// usable and discarding it would lose counting over one unreadable row.
function testASendingAddressThatIsNotOneCostsItsRecordAndNotTheReport(reports) {
  var answer = file(reports, {
    org: PLAIN_ORG, carrier: "ip.example", reportId: "i-1", daysAgo: 14,
    source: BAD_SOURCE,
  });
  count("a record naming a sending address that is not an address is refused on its own, " +
    "and the report that carried it is taken rather than discarded",
    answer.ok === true && answer.stored === 0 &&
    Array.isArray(answer.refused) && answer.refused.length === 1 &&
    answer.refused[0].reason === SOURCE_REFUSED,
    verdictOf(answer));
}

// The control. A screen that refused everything would satisfy every case
// above and leave the page with nothing on it.
function testAnOrdinaryReportIsTaken(reports) {
  var plain = file(reports, {
    org: PLAIN_ORG, carrier: "plain.example", reportId: "p-1", daysAgo: 2,
    source: "198.51.100.10",
  });
  count("an ordinary reporting organization is taken, so the refusals above are about the " +
    "shape of a value rather than about the screen refusing everything",
    plain.ok === true && plain.stored === 1, verdictOf(plain));

  var attr = file(reports, {
    org: ATTR_ORG, carrier: "attr.example", reportId: "a-1", daysAgo: 4,
    source: "198.51.100.11",
  });
  count("and so is a name carrying a quotation mark, which the screen has no reason to " +
    "refuse and the page still has to render",
    attr.ok === true && attr.stored === 1, verdictOf(attr));

  // Stated as a fact about this server rather than as a hope. The
  // reporter sent well formed XML and the entities decode to brackets,
  // so the value is ordinary text and the store keeps it. Everything
  // that stops it being markup happens when the page is written.
  var markup = file(reports, {
    org: MARKUP_ORG_XML, carrier: "markup.example", reportId: "m-1", daysAgo: 18,
    source: "198.51.100.18",
  });
  count("a name whose entities decode to a script element is stored, because a bracket in " +
    "a reporter's name is not by itself a refusal",
    markup.ok === true && markup.stored === 1, verdictOf(markup));
}

// ---------------------------------------------------------------------------
// What reaches the page
// ---------------------------------------------------------------------------

async function testTheConsoleShowsWhatWasTakenAndNoneOfWhatWasNot(operator) {
  var page = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(DOMAIN));
  var body = String(page.body || "");
  count("the console answers the page narrowed to the reported domain",
    page.status === 200, String(page.status));

  count("the organization whose report was taken is named on it",
    body.indexOf(PLAIN_ORG) !== -1, body.replace(/\s+/g, " ").slice(0, 200));

  count("the name carrying a bidi override reaches the page in no form, so nothing an " +
    "operator reads has been reordered under them",
    body.indexOf("‮") === -1 && body.indexOf("txeN") === -1,
    body.replace(/\s+/g, " ").slice(0, 200));
  count("nor does the one carrying an invisible formatting character",
    body.indexOf("​") === -1, "no zero-width character on the page");
  count("nor the name carrying a tab", body.indexOf(TAB_ORG) === -1, "not shown");
  count("nor the name longer than the column takes", body.indexOf(LONG_ORG) === -1,
    "not shown");
  count("nor the sending address that is not an address",
    body.indexOf(BAD_SOURCE) === -1, "not shown");

  // The stored value that has to survive rendering. It is shown, and the
  // quotation mark it carries is written as an entity, so a template
  // that later wrapped this value in an attribute would not be closing
  // it here.
  count("the name carrying a quotation mark is shown rather than dropped",
    body.indexOf("onmouseover") !== -1, "the reporter's name is on the page");
  count("and the quotation mark reaches the page as an entity rather than as itself",
    body.indexOf(ATTR_SHOWN) !== -1, body.replace(/\s+/g, " ").slice(0, 200));
  count("so the sequence that would close an attribute is nowhere in the rendered page",
    body.indexOf(ATTR_RAW) === -1, "no raw attribute break");

  // The value the store had no reason to refuse. It is on the page, and
  // it is on it as text: the brackets the reporter wrote are entities in
  // the rendered document, so a browser draws a name and runs nothing.
  count("the stored name that decodes to a script element is shown rather than dropped",
    body.indexOf(MARKUP_ORG_SHOWN) !== -1, body.replace(/\s+/g, " ").slice(0, 200));
  count("and it reaches the page as text, so no part of it is an element a browser runs",
    body.indexOf(MARKUP_ORG) === -1 && body.indexOf("<script>alert") === -1,
    "no live element from a reporter's name");
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

function baseEnv(dataDir, material) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    BLAMEPOST_TLS_CERT:         material.certFile,
    BLAMEPOST_TLS_KEY:          material.keyFile,
  };
}

async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
  }
  return sections;
}

async function run() {
  var root    = helpers.tempDir("web-dmarc-stranger-values");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "stranger values run" });
    await identity.accounts.create({
      address: OPERATOR, password: ADMIN_PASSWORD, isAdmin: true });

    testAnOrdinaryReportIsTaken(identity.reports);
    testABidiOverrideAndAnInvisibleCharacterAreRefused(identity.reports);
    testTheReportIdentifierIsScreenedUnderItsOwnReason(identity.reports);
    testAWhitespaceControlAndAnOverlongNameAreRefused(identity.reports);
    testASendingAddressThatIsNotOneCostsItsRecordAndNotTheReport(identity.reports);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var operator = browser.browserAt(origin, { ca: material.caPem });
    count("the operator signs in",
      (await operator.signIn(OPERATOR, ADMIN_PASSWORD)).status === 302);

    await testTheConsoleShowsWhatWasTakenAndNoneOfWhatWasNot(operator);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;

    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
    console.log("EXAMINED " + FIELDS_SCREENED + " reporter-fields");
  }
}

module.exports = {
  name: "web-dmarc-stranger-values", run: run, getChecks: helpers.getChecks,
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
