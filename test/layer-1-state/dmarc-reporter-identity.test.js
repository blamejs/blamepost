// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Who a DMARC aggregate report counts as, when the policy stepper asks how
 * many independent organizations back a step.
 *
 * Tokens exercised here:
 *
 *   blamepost.mail.reports.observe
 *   blamepost.store.reports.reporters
 *   blamepost.store.reports.ingestAggregate
 *   blamepost.mail.dmarcPolicy.evaluate
 *
 * A report names its author twice, in `<org_name>` and in the contact
 * mailbox, and whoever sends the report writes both. What this server
 * establishes for itself is the domain the carrier message passed DMARC
 * for. The rules below are written as the failures they stop:
 *
 *   - one party with one DMARC-passing domain, sending reports under the
 *     names Alpha, Beta and Gamma, is one organization in the listing and
 *     in the stepper's count, and the step it asked for is refused;
 *   - several subdomains of one registered domain are one organization;
 *   - three organizations that each authenticated as their own registered
 *     domain are three, and the step they back is offered;
 *   - a report nobody authenticated, filed first under a real reporter's
 *     name and report identifier, does not stop that reporter's own report
 *     from being stored and counted, and neither does an authenticated
 *     report from another domain that borrows the name;
 *   - a genuine resend from the same organization is still one report;
 *   - and on a volume written before the organization was recorded, the
 *     upgrade drops the old uniqueness rule, and a row carrying no recorded
 *     organization counts toward no organization.
 *
 * Every carrier goes through `observe`, which is the function the server
 * registers on the mailbox filing seam, so the path under test is the one
 * a peer's delivery takes.
 *
 * Real database, real sealed columns, real vault, real audit chain,
 * temporary data directories. The zone is a table and the DKIM selector
 * inventory is a stand-in, because what is under test is the counting.
 *
 * Run standalone: node test/layer-1-state/dmarc-reporter-identity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers      = require("../helpers");
var dnsZone      = require("../helpers/dns-zone");
var b            = require("../../lib/vendor/blamejs");
var config       = require("../../lib/config");
var store        = require("../../lib/store");
var storeReports = require("../../lib/store/reports");
var tables       = require("../../lib/store/tables");
var ingest       = require("../../lib/mail/reports");
var postureMod   = require("../../lib/mail/posture");
var policyMod    = require("../../lib/mail/dmarc-policy");

var count = helpers.count;

var HOSTNAME         = "mx.example.com";
var AUTHSERV_ID      = "mx.example.com";
var RUA              = "dmarc-reports@example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var DAY_MS = 86400000;

// The moment every seeded window is measured back from, taken once so the
// arithmetic is about offsets rather than about the clock between carriers.
var NOW = Date.now();

// The selector record the stand-in inventory publishes and the zone
// carries, so the posture reading finds a key this server would sign with.
var DKIM_TXT = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

var ALIGNED_SOURCE = "203.0.113.10";
var FAILING_SOURCE = "198.51.100.7";

// The domain that holds the three names, and the names themselves.
var ONE_PARTY  = "attacker.example";
var THREE_NAMES = ["Alpha", "Beta", "Gamma"];

// The one uniqueness rule the upgrade removes and the one it leaves.
var OLD_UNIQUE_INDEX = "idx_blamepost_dmarc_reports_id";

// Every domain this run reports on, filled as fixtures build so the store
// handle answers the hosted question for each of them.
var hosted = {};

// The zone every posture reading is taken over.
var zone = {};

// ---- fixtures --------------------------------------------------------------

function dayStart(offset) {
  return (Math.floor(NOW / DAY_MS) + offset) * DAY_MS;
}

// Thirteen reported days inside the quarantine window and one well outside
// it, which is the shape the stepper's own test uses to clear every
// evidence rule without a report on the boundary day.
function fullFortnight() {
  var days = [-20];
  for (var i = 13; i >= 1; i -= 1) days.push(-i);
  return days;
}

function xmlRecord(sourceIp, messages, aligned) {
  var verdict = aligned ? "pass" : "fail";
  return "  <record>\n" +
    "    <row><source_ip>" + sourceIp + "</source_ip><count>" + messages + "</count>\n" +
    "      <policy_evaluated><disposition>none</disposition>" +
    "<dkim>" + verdict + "</dkim><spf>" + verdict + "</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>example.com</header_from></identifiers>\n" +
    "  </record>\n";
}

function aggregateXml(opts) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>" + opts.name + "</org_name>\n" +
    "    <email>dmarc-noreply@" + opts.contact + "</email>\n" +
    "    <report_id>" + opts.reportId + "</report_id>\n" +
    "    <date_range><begin>" + Math.floor(opts.begin / 1000) + "</begin>" +
    "<end>" + Math.floor(opts.end / 1000) + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + opts.domain + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>none</p><pct>100</pct>\n" +
    "  </policy_published>\n" +
    opts.records.join("") +
    "</feedback>\n";
}

// The header this server's own inbound path writes. A null `from` writes
// no header, which is a carrier this server recorded nothing about.
//
// `header.from` carries the whole author address, which is what
// `b.mail.inbound.verify` puts there. The registry entry for the `dmarc`
// method defines the property as the domain and the reader takes either,
// but a file built around the spelling the server does not produce is a
// file that keeps passing while every real report is refused.
// `test/layer-1-state/dmarc-report-ingest.test.js` measures which
// spelling the shipped path writes and drives both.
function authenticationResults(from) {
  if (from === null) return "";
  return "Authentication-Results: " + AUTHSERV_ID +
    "; spf=pass smtp.mailfrom=dmarc-noreply@" + from +
    "; dkim=pass header.d=" + from +
    "; dmarc=pass header.from=dmarc-noreply@" + from + "\r\n";
}

function carrier(opts) {
  var payload = Buffer.from(aggregateXml(opts), "utf8");
  return Buffer.from(
    authenticationResults(opts.carrierFrom) +
    "From: dmarc-noreply@" + (opts.carrierFrom || opts.contact) + "\r\n" +
    "To: " + RUA + "\r\n" +
    "Subject: Report Domain: " + opts.domain + "\r\n" +
    "Content-Type: multipart/mixed; boundary=\"bnd-report\"\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "An aggregate report.\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: text/xml\r\n" +
    "Content-Disposition: attachment; filename=\"" + opts.reportId + ".xml\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" +
    payload.toString("base64") + "\r\n" +
    "--bnd-report--\r\n",
    "utf8");
}

// How many messages the reader has finished with, whatever it concluded.
// `observe` answers before the report is filed, so a test waits on this
// rather than on a fixed delay.
function settled(reader) {
  var c = reader.describe().counts;
  return c.passedOver + c.aggregate + c.forensic + c.refused;
}

// Hand one carrier to the filing seam and wait until the reader has filed
// it. Answers the reader's verdict about that message.
async function fileThroughTheSeam(reader, raw) {
  var before = settled(reader);
  reader.observe({ raw: raw, address: RUA });
  await helpers.waitUntil(function () { return settled(reader) > before; }, {
    timeoutMs: 10000,
    label:     "dmarc-reporter-identity: the reader filing one carrier",
  });
  var recent = reader.recent();
  return recent[recent.length - 1];
}

// One hosted domain, with the zone entries a posture reading of it needs.
function hostDomain(domain) {
  hosted[domain] = true;
  zone[domain] = { txt: ["v=spf1 -all"], mx: [HOSTNAME] };
  zone["_dmarc." + domain] = { txt: ["v=DMARC1; p=none; rua=mailto:" + RUA] };
  zone["sel1._domainkey." + domain] = { txt: [DKIM_TXT] };
}

// Reports about `domain` for every day in `dayOffsets`, one per entry of
// `parties`. A party is the domain the carrier passed DMARC for, the
// contact mailbox domain the report names, and the `<org_name>` it writes.
async function seedThroughTheSeam(reader, opts) {
  hostDomain(opts.domain);
  var verdicts = [];
  for (var d = 0; d < opts.dayOffsets.length; d += 1) {
    var offset = opts.dayOffsets[d];
    var begin  = dayStart(offset);
    for (var p = 0; p < opts.parties.length; p += 1) {
      var party = opts.parties[p];
      verdicts.push(await fileThroughTheSeam(reader, carrier({
        carrierFrom: party.from,
        contact:     party.contact,
        name:        party.name,
        reportId:    opts.domain + "-" + offset + "-" + p,
        domain:      opts.domain,
        begin:       begin,
        end:         begin + DAY_MS - 1000,
        records:     [xmlRecord(ALIGNED_SOURCE, 40, true)],
      })));
    }
  }
  return verdicts;
}

function everyOneCounted(verdicts) {
  return verdicts.length > 0 && verdicts.every(function (one) {
    return one.ok === true && one.authenticated === true && one.stored === 1 &&
      one.duplicates === 0;
  });
}

// ---- the handles -----------------------------------------------------------

function dkimStandIn() {
  return {
    dnsRecords: async function (domain) {
      return [{ dnsName: "sel1._domainkey." + domain, dnsTxtValue: DKIM_TXT,
        state: "active" }];
    },
  };
}

function storeHandle() {
  return storeReports.create({
    aggregateRetentionMs: 400 * DAY_MS,
    forensicRetentionMs:  DAY_MS,
    hostedDomain: function (name) { return hosted[name] === true; },
  });
}

function readerOver(reportsHandle) {
  return ingest.create({
    store:              reportsHandle,
    authservId:         AUTHSERV_ID,
    reportingAddresses: [RUA],
  });
}

function policyOver(reportsHandle) {
  var resolver = dnsZone.resolverOver(zone);
  return policyMod.create({
    store:   reportsHandle,
    posture: postureMod.create({
      hostname: HOSTNAME, resolver: resolver, dkim: dkimStandIn(),
    }),
    dnsLookup:        postureMod.txtLookup(resolver),
    reportingAddress: RUA,
  });
}

// ---- one party, three names ------------------------------------------------

async function oneAuthenticatedPartyUnderThreeNamesIsOneOrganization(ctx) {
  var domain = "three-names.example";
  var parties = THREE_NAMES.map(function (name) {
    return { from: ONE_PARTY, contact: ONE_PARTY, name: name };
  });
  var verdicts = await seedThroughTheSeam(ctx.reader, {
    domain: domain, dayOffsets: fullFortnight(), parties: parties,
  });
  count("every report the one party sent passed the carrier rule and was stored as evidence",
    everyOneCounted(verdicts), JSON.stringify(verdicts.slice(0, 3)));

  var heard = ctx.reports.reporters({ domain: domain });
  count("the reporter listing counts one organization for one authenticated domain",
    heard.total === 1 && heard.listed === 1, JSON.stringify(heard));
  count("and names it by the domain that authenticated its reports",
    heard.reporters.length === 1 && heard.reporters[0].organization === ONE_PARTY,
    JSON.stringify(heard.reporters));
  count("with the three names it wrote into its reports counted beside it",
    heard.reporters.length === 1 && heard.reporters[0].names === THREE_NAMES.length,
    JSON.stringify(heard.reporters));

  var verdict = await policyOver(ctx.reports).evaluate({ domain: domain, now: NOW });
  count("the stepper counts one reporting organization",
    verdict.evidence !== null && verdict.evidence.organizations === 1,
    JSON.stringify(verdict.evidence));
  count("and refuses the step the three names would otherwise have cleared",
    verdict.ok === false && verdict.reason === policyMod.CODES.reportersThin,
    verdict.reason + " " + verdict.detail);
}

async function subdomainsOfOneRegisteredDomainAreOneOrganization(ctx) {
  var domain = "subdomains.example";
  var parties = ["a", "b", "c"].map(function (label) {
    var sub = label + "." + ONE_PARTY;
    return { from: sub, contact: sub, name: sub };
  });
  var verdicts = await seedThroughTheSeam(ctx.reader, {
    domain: domain, dayOffsets: [-1], parties: parties,
  });
  count("reports from three subdomains that each passed DMARC are stored as evidence",
    everyOneCounted(verdicts), JSON.stringify(verdicts));

  var heard = ctx.reports.reporters({ domain: domain });
  count("three subdomains of one registered domain are one organization",
    heard.total === 1 && heard.reporters.length === 1 &&
    heard.reporters[0].organization === ONE_PARTY,
    JSON.stringify(heard));
}

async function threeAuthenticatedOrganizationsAreThree(ctx) {
  var domain = "three-organizations.example";
  var orgs = ["alpha.example", "beta.example", "gamma.example"];
  var parties = orgs.map(function (org) {
    return { from: org, contact: org, name: org };
  });
  var verdicts = await seedThroughTheSeam(ctx.reader, {
    domain: domain, dayOffsets: fullFortnight(), parties: parties,
  });
  count("reports from three organizations are stored as evidence",
    everyOneCounted(verdicts), JSON.stringify(verdicts.slice(0, 3)));

  var heard = ctx.reports.reporters({ domain: domain });
  count("three organizations that each authenticated as their own domain are three",
    heard.total === 3 && heard.listed === 3, JSON.stringify(heard));
  var named = heard.reporters.map(function (one) { return one.organization; }).sort();
  count("and each is named by the domain it authenticated as",
    JSON.stringify(named) === JSON.stringify(orgs), JSON.stringify(named));

  var verdict = await policyOver(ctx.reports).evaluate({ domain: domain, now: NOW });
  count("the stepper counts three organizations",
    verdict.evidence !== null && verdict.evidence.organizations === 3,
    JSON.stringify(verdict.evidence));
  count("and offers the step they back",
    verdict.ok === true && verdict.next === "quarantine",
    verdict.reason + " " + verdict.detail);
}

// ---- a report filed first under somebody else's name -----------------------

async function aForgedReportCannotShadowTheReporterItNames(ctx) {
  var domain = "shadowed.example";
  var reporter = "reporter.example";
  hostDomain(domain);
  var begin = dayStart(-2);
  var end   = begin + DAY_MS - 1000;

  // A report nobody authenticated, naming the real reporter and a report
  // identifier the real reporter is about to use. It claims a large clean
  // volume and no failing sender.
  var forged = await fileThroughTheSeam(ctx.reader, carrier({
    carrierFrom: null, contact: reporter, name: reporter, reportId: "shadow-1",
    domain: domain, begin: begin, end: end,
    records: [xmlRecord(ALIGNED_SOURCE, 900, true)],
  }));
  count("a report nobody authenticated is stored and not counted",
    forged.ok === true && forged.stored === 1 && forged.authenticated === false,
    JSON.stringify(forged));

  var real = await fileThroughTheSeam(ctx.reader, carrier({
    carrierFrom: reporter, contact: reporter, name: reporter, reportId: "shadow-1",
    domain: domain, begin: begin, end: end,
    records: [xmlRecord(ALIGNED_SOURCE, 60, true), xmlRecord(FAILING_SOURCE, 30, false)],
  }));
  count("the real reporter's report under the same name and identifier is stored",
    real.ok === true && real.authenticated === true && real.stored === 2 &&
    real.duplicates === 0, JSON.stringify(real));

  var reading = ctx.reports.rollup({ domain: domain });
  count("and the counting is over the real report rather than the one filed ahead of it",
    reading.length === 1 && reading[0].counted === 90 && reading[0].aligned === 60 &&
    reading[0].failingSources === 1, JSON.stringify(reading));
  var failing = await ctx.reports.failingSources({ domain: domain });
  count("so the sender the real report names as failing is listed",
    failing.sources.length === 1 && failing.sources[0].sourceIp === FAILING_SOURCE,
    JSON.stringify(failing.sources));

  // The same move from a party that does pass DMARC, for its own domain,
  // and writes the real reporter's name into `<org_name>`.
  var borrowed = await fileThroughTheSeam(ctx.reader, carrier({
    carrierFrom: ONE_PARTY, contact: ONE_PARTY, name: reporter, reportId: "shadow-2",
    domain: domain, begin: begin, end: end,
    records: [xmlRecord(ALIGNED_SOURCE, 900, true)],
  }));
  count("an authenticated report borrowing the real reporter's name is stored",
    borrowed.ok === true && borrowed.authenticated === true && borrowed.stored === 1,
    JSON.stringify(borrowed));

  var second = await fileThroughTheSeam(ctx.reader, carrier({
    carrierFrom: reporter, contact: reporter, name: reporter, reportId: "shadow-2",
    domain: domain, begin: begin, end: end,
    records: [xmlRecord(ALIGNED_SOURCE, 10, true)],
  }));
  count("and does not stop the real reporter's report with the same identifier",
    second.ok === true && second.authenticated === true && second.stored === 1 &&
    second.duplicates === 0, JSON.stringify(second));

  var heard = ctx.reports.reporters({ domain: domain });
  var named = heard.reporters.map(function (one) { return one.organization; }).sort();
  count("the listing names the two domains that authenticated, not the one borrowed name",
    heard.total === 2 && JSON.stringify(named) === JSON.stringify([ONE_PARTY, reporter]),
    JSON.stringify(heard.reporters));

  var resent = await fileThroughTheSeam(ctx.reader, carrier({
    carrierFrom: reporter, contact: reporter, name: reporter, reportId: "shadow-2",
    domain: domain, begin: begin, end: end,
    records: [xmlRecord(ALIGNED_SOURCE, 10, true)],
  }));
  count("a genuine resend from the same organization is still one report",
    resent.ok === true && resent.stored === 0 && resent.duplicates === 1,
    JSON.stringify(resent));
}

// ---- a volume written before the organization was recorded -----------------

function indexesOf(table) {
  return b.db.prepare("PRAGMA index_list(" + table + ")").all();
}

function columnsOf(table) {
  return b.db.prepare("PRAGMA table_info(" + table + ")").all()
    .map(function (row) { return row.name; });
}

function indexColumns(name) {
  return b.db.prepare("PRAGMA index_info(" + name + ")").all()
    .map(function (row) { return row.name; });
}

// Put the reports table back into the shape an earlier build left it in:
// the uniqueness rule on the organization's own name and the report
// identifier, no column for the domain that authenticated the report, and
// no record that the upgrade ran. Everything this build added is taken
// out, and what an earlier build had is put back.
function rewindToTheEarlierShape() {
  var table = tables.DMARC_REPORTS;
  indexesOf(table).forEach(function (index) {
    if (index.origin !== "c") return;
    var cols = indexColumns(index.name);
    if (cols.indexOf("verifiedOrgDomain") !== -1) {
      b.db.prepare("DROP INDEX " + index.name).run();
    }
  });
  if (columnsOf(table).indexOf("verifiedOrgDomain") !== -1) {
    b.db.prepare("ALTER TABLE " + table + " DROP COLUMN verifiedOrgDomain").run();
  }
  b.db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS " + OLD_UNIQUE_INDEX + " ON " + table +
    " (orgKey, reportId)").run();
  var recorded = b.db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '_blamejs_migrations'").all();
  if (recorded.length > 0) b.db.prepare("DELETE FROM _blamejs_migrations").run();
}

async function theUpgradeDropsTheOldRuleAndInventsNoOrganization(root) {
  var dataDir = nodePath.join(root, "upgraded");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  var cfg = config.load({
    env: {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    },
    cwd: root,
  });

  var domain = "upgraded.example";
  hostDomain(domain);
  var begin = dayStart(-1);

  var first = await store.open(cfg);
  try {
    var earlier = storeHandle();
    THREE_NAMES.forEach(function (name, i) {
      earlier.ingestAggregate(aggregateXml({
        name: name, contact: ONE_PARTY, reportId: "legacy-" + i, domain: domain,
        begin: begin, end: begin + DAY_MS - 1000,
        records: [xmlRecord(ALIGNED_SOURCE, 40, true)],
      }), { evidence: tables.REPORT_EVIDENCE_VERIFIED, now: NOW });
    });
    rewindToTheEarlierShape();
    count("the volume holds the earlier build's uniqueness rule before the upgrade",
      indexesOf(tables.DMARC_REPORTS).some(function (index) {
        return index.name === OLD_UNIQUE_INDEX;
      }) && columnsOf(tables.DMARC_REPORTS).indexOf("verifiedOrgDomain") === -1,
      JSON.stringify(indexesOf(tables.DMARC_REPORTS)));
  } finally {
    first.close();
  }

  var upgraded = await store.open(cfg);
  try {
    var indexes = indexesOf(tables.DMARC_REPORTS);
    count("the upgrade removes the uniqueness rule keyed on the name a report gives itself",
      !indexes.some(function (index) { return index.name === OLD_UNIQUE_INDEX; }),
      JSON.stringify(indexes));
    var scoped = indexes.filter(function (index) {
      return index.unique === 1 &&
        JSON.stringify(indexColumns(index.name)) ===
          JSON.stringify(["verifiedOrgDomain", "orgKey", "reportId"]);
    });
    count("and leaves one keyed on the authenticated organization as well",
      scoped.length === 1, JSON.stringify(indexes));

    var rows = b.db.from(tables.DMARC_REPORTS).where({ policyDomain: domain }).all();
    count("the upgrade adds the column the authenticated organization is recorded in",
      columnsOf(tables.DMARC_REPORTS).indexOf("verifiedOrgDomain") !== -1,
      JSON.stringify(columnsOf(tables.DMARC_REPORTS)));
    count("rows written before the upgrade carry no recorded organization",
      typeof tables.REPORT_ORGANIZATION_NONE === "string" &&
      rows.length === 3 && rows.every(function (row) {
        return row.verifiedOrgDomain === tables.REPORT_ORGANIZATION_NONE &&
          row.evidence === tables.REPORT_EVIDENCE_VERIFIED;
      }), JSON.stringify(rows.map(function (row) {
        return [row.orgName, row.evidence, row.verifiedOrgDomain];
      })));

    var reportsHandle = storeHandle();
    var heard = reportsHandle.reporters({ domain: domain });
    count("so they count toward no organization, whatever names they carry",
      heard.total === 0 && heard.reporters.length === 0, JSON.stringify(heard));
    count("and the listing says how many evidence reports it could not attribute",
      heard.unattributedReports === 3, JSON.stringify(heard));

    var verdict = await policyOver(reportsHandle).evaluate({ domain: domain, now: NOW });
    count("the stepper reads the same zero",
      verdict.evidence !== null && verdict.evidence.organizations === 0,
      JSON.stringify(verdict.evidence));

    var reader = readerOver(reportsHandle);
    var fresh = await fileThroughTheSeam(reader, carrier({
      carrierFrom: "alpha.example", contact: "alpha.example", name: "alpha.example",
      reportId: "after-upgrade-1", domain: domain,
      begin: begin, end: begin + DAY_MS - 1000,
      records: [xmlRecord(ALIGNED_SOURCE, 40, true)],
    }));
    var after = reportsHandle.reporters({ domain: domain });
    count("a report authenticated after the upgrade counts as its organization",
      fresh.ok === true && fresh.authenticated === true && after.total === 1 &&
      after.reporters[0].organization === "alpha.example",
      JSON.stringify(after));
  } finally {
    upgraded.close();
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dmarc-reporter-identity");
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

    var identity = await store.open(cfg);
    try {
      // The stepper is built at each evaluation rather than here, because
      // the zone it resolves against is read when the resolver is built
      // and every case adds its own domain to it.
      var reportsHandle = storeHandle();
      var ctx = {
        reports: reportsHandle,
        reader:  readerOver(reportsHandle),
      };

      await oneAuthenticatedPartyUnderThreeNamesIsOneOrganization(ctx);
      await subdomainsOfOneRegisteredDomainAreOneOrganization(ctx);
      await threeAuthenticatedOrganizationsAreThree(ctx);
      await aForgedReportCannotShadowTheReporterItNames(ctx);
    } finally {
      identity.close();
    }

    await theUpgradeDropsTheOldRuleAndInventsNoOrganization(root);

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
  name:      "dmarc-reporter-identity",
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
