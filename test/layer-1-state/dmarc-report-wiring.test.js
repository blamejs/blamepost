// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The settings that decide how long DMARC report rows are kept, followed
 * from the environment an operator writes them in to the handle that
 * acts on them.
 *
 * `dmarc-report-store.test.js` drives the store handle with bounds
 * handed straight to it, which answers what the module does with a
 * number and says nothing about where the number comes from. This file
 * answers the other half, and it is the half this project gets wrong
 * most often: a value accepted where it is written and never read where
 * it acts.
 *
 *   - opening the volume builds the handle, and the milliseconds it
 *     reports are the days the operator wrote, converted once;
 *   - the question the handle asks about a domain is answered by the
 *     hosted-domain rows rather than by a list captured at boot, so a
 *     domain added after the handle exists is one it accepts reports
 *     for;
 *   - starting the server arms the sweep and stopping it disarms it,
 *     because a sweep that outlives the server reads a volume that has
 *     already closed;
 *   - and a server assembled over a store with no report handle is
 *     refused rather than started with nothing sweeping.
 *
 * Real database, real vault, real listeners on reserved loopback ports.
 *
 * Run standalone: node test/layer-1-state/dmarc-report-wiring.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var HOSTNAME     = "mx.example.com";
var DOMAIN       = "example.com";
var LATER_DOMAIN = "example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The two windows this run configures, in the unit an operator writes
// them in. Neither is the shipped default, so a handle reporting the
// right milliseconds is reporting what was configured rather than what
// the module falls back to.
var AGGREGATE_DAYS = 21;
var FORENSIC_DAYS  = 3;

// The listeners the assembled server binds. POP3 is left off because it
// is off by default and this file is not about the listener set.
var LISTENER_NAMES = ["mx", "submission", "submissions", "imap", "managesieve"];

// How long the server is given to come down. The listeners are on
// loopback with nothing connected, so this is a ceiling rather than a
// wait.
var STOP_MS = 8000;

// One aggregate report, small enough to read and complete enough to
// parse. It carries a single record because what is being measured here
// is which domain the report is accepted for, not what is stored out of
// it.
function aggregateXml(domain, reportId) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>reporter.example</org_name>\n" +
    "    <email>dmarc-noreply@reporter.example</email>\n" +
    "    <report_id>" + reportId + "</report_id>\n" +
    "    <date_range><begin>1750000000</begin><end>1750086400</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + domain + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>reject</p><sp>reject</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    "  <record>\n" +
    "    <row><source_ip>203.0.113.10</source_ip><count>4</count>\n" +
    "      <policy_evaluated><disposition>none</disposition>" +
    "<dkim>pass</dkim><spf>pass</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>" + domain + "</header_from></identifiers>\n" +
    "    <auth_results><spf><domain>" + domain + "</domain>" +
    "<result>pass</result></spf></auth_results>\n" +
    "  </record>\n" +
    "</feedback>\n";
}

// ---- what opening the volume built -----------------------------------------

function theHandleIsBuiltFromTheSettings(identity) {
  count("opening the volume hands back a report handle rather than leaving the caller to " +
    "build one",
    identity.reports !== undefined && identity.reports !== null &&
    typeof identity.reports.ingestAggregate === "function",
    typeof identity.reports);
  if (!identity.reports) return;

  var shape = identity.reports.describe();
  count("the aggregate window it is running is the number of days the operator wrote, " +
    "converted at the wiring rather than in the module",
    shape.aggregateRetentionMs === b.constants.TIME.days(AGGREGATE_DAYS),
    AGGREGATE_DAYS + " day(s) reached the handle as " + shape.aggregateRetentionMs + "ms");
  count("and so is the forensic one",
    shape.forensicRetentionMs === b.constants.TIME.days(FORENSIC_DAYS),
    FORENSIC_DAYS + " day(s) reached the handle as " + shape.forensicRetentionMs + "ms");
  count("the switch an operator set reaches it too",
    shape.forensicEnabled === true, String(shape.forensicEnabled));
  count("and nothing is sweeping before anything has started, so a command that opens the " +
    "volume and exits does not hold the event loop open",
    shape.sweeping === false, JSON.stringify(shape.sweeping));

  count("the windows it declared to the retention controller are the two it reports",
    shape.rules.length === 3, JSON.stringify(shape.rules.map(function (r) { return r.name; })));
}

// ---- where the hosted-domain answer comes from ------------------------------

// The handle refuses a report about a domain hosted somewhere else, which
// is what stops any peer deciding how much of this volume reports
// occupy. What that refusal is worth depends entirely on where the answer
// comes from: a list read once at boot would go on refusing a domain the
// operator added ten minutes later, and there is nothing in the refusal
// to tell them why.
async function theHostedQuestionIsAnsweredByTheDomainRows(identity) {
  await identity.domains.add({ domain: DOMAIN });

  var hosted = identity.reports.ingestAggregate(aggregateXml(DOMAIN, "wiring-0001"));
  count("a report about a domain this server hosts is taken",
    hosted.ok === true && hosted.stored === 1,
    JSON.stringify({ ok: hosted.ok, reason: hosted.reason, stored: hosted.stored }));

  var elsewhere = identity.reports.ingestAggregate(aggregateXml(LATER_DOMAIN, "wiring-0002"));
  count("a report about a domain it does not host is refused, naming that as the reason",
    elsewhere.ok === false && elsewhere.reason === "domain-not-hosted",
    JSON.stringify({ ok: elsewhere.ok, reason: elsewhere.reason }));

  // The same report again, with the domain now hosted and the handle
  // untouched. A handle built over a captured list answers this the same
  // way it answered a moment ago, which is the failure this drives.
  await identity.domains.add({ domain: LATER_DOMAIN });
  var later = identity.reports.ingestAggregate(aggregateXml(LATER_DOMAIN, "wiring-0002"));
  count("and a domain added after the handle was built is one it accepts reports for, so " +
    "the answer is read from the rows rather than from a list captured at boot",
    later.ok === true && later.stored === 1,
    JSON.stringify({ ok: later.ok, reason: later.reason, stored: later.stored }));
}

// ---- the sweep and the server's lifecycle -----------------------------------

async function theSweepIsArmedAndDisarmedWithTheServer(identity, cfg) {
  // Both domains, because the MX listener will not bind while any hosted
  // domain has an unacknowledged DNS posture, and the checks above added
  // the second one.
  var hosted = [DOMAIN, LATER_DOMAIN];
  for (var d = 0; d < hosted.length; d += 1) {
    await identity.domains.acknowledgeDns({
      domain: hosted[d], acknowledgedBy: "operator@" + hosted[d],
    });
  }

  var sections = {};
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    sections[LISTENER_NAMES[i]] = {
      enabled: true,
      port:    await wire.reservePort(),
      address: "127.0.0.1",
    };
  }
  var runtimeConfig = Object.assign({}, cfg, {
    httpPort:  0,
    httpsPort: 0,
    listeners: sections,
  });

  // A store with everything the assembly reads except the report handle.
  // Wired defensively, that store starts a server whose report rows are
  // never swept and says nothing; the refusal is what makes the wiring a
  // requirement rather than a convention.
  var withoutReports = Object.assign({}, identity, { reports: undefined });
  var refused = null;
  try {
    blamepost.create({
      config:       runtimeConfig,
      store:        withoutReports,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
    });
  } catch (e) { refused = e; }
  count("a server assembled over a store carrying no report handle is refused rather than " +
    "started with nothing sweeping",
    refused !== null && /reports/.test(String(refused.message)),
    refused === null ? "assembled" : String(refused.message).slice(0, 200));

  // A handle that sweeps and counts and cannot take a report. It is the
  // shape a defensive wiring produces, and every surface reads clean on
  // it: the sweep runs, the console draws its page, and the reports peers
  // send arrive at the mailbox and are read by nothing. The refusal is
  // asserted here rather than left to the reader's own construction,
  // because a guarantee enforced inside whichever module happens to call
  // the verb is a guarantee that moves when that module does.
  var cannotIngest = Object.assign({}, identity, {
    reports: Object.assign({}, identity.reports, {
      ingestAggregate: undefined, ingestForensic: undefined,
    }),
  });
  var refusedIngest = null;
  try {
    blamepost.create({
      config:       runtimeConfig,
      store:        cannotIngest,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
    });
  } catch (e) { refusedIngest = e; }
  count("and one carrying a report handle that sweeps and counts but cannot take a report " +
    "is refused at the assembly rather than accepted and read by nothing",
    refusedIngest !== null && /ingestAggregate/.test(String(refusedIngest.message)),
    refusedIngest === null ? "assembled" : String(refusedIngest.message).slice(0, 200));

  var server = blamepost.create({
    config:       runtimeConfig,
    store:        identity,
    mailStore:    identity.mailbox,
    messageStore: identity.messageStore,
  });
  count("assembling a server does not arm the sweep on its own, because nothing has bound " +
    "and nothing is running",
    identity.reports.describe().sweeping === false,
    JSON.stringify(identity.reports.describe().sweeping));

  var running = false;
  try {
    await server.start();
    running = true;
    count("starting the server arms the sweep, so rows past their window are destroyed " +
      "while it runs rather than at the next boot",
      identity.reports.describe().sweeping === true,
      JSON.stringify(identity.reports.describe().sweeping));

    await server.stop({ timeoutMs: STOP_MS });
    running = false;
    count("and stopping it disarms the sweep, so no pass reads the volume while the store " +
      "is being closed",
      identity.reports.describe().sweeping === false,
      JSON.stringify(identity.reports.describe().sweeping));
  } finally {
    if (running) {
      try { await server.stop({ timeoutMs: STOP_MS }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
  }
}

// ---- the run ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dmarc-report-wiring");
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

    var certificate = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:                       HOSTNAME,
        BLAMEPOST_DATA_DIR:                       dataDir,
        BLAMEPOST_VAULT_PASSPHRASE:               VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED:               "1",
        BLAMEPOST_TLS_CERT:                       certificate.certFile,
        BLAMEPOST_TLS_KEY:                        certificate.keyFile,
        BLAMEPOST_DMARC_FORENSIC_ENABLED:         "true",
        BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS: String(AGGREGATE_DAYS),
        BLAMEPOST_DMARC_FORENSIC_RETENTION_DAYS:  String(FORENSIC_DAYS),
      },
      cwd: root,
    });

    var identity = await store.open(cfg);

    theHandleIsBuiltFromTheSettings(identity);
    await theHostedQuestionIsAnsweredByTheDomainRows(identity);
    await theSweepIsArmedAndDisarmedWithTheServer(identity, cfg);

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
  name:      "dmarc-report-wiring",
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
