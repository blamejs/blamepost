// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Reports addressed to a reporting address that is an alias.
 *
 * `BLAMEPOST_POSTMASTER` names the address the rua record points at and
 * the reverse path this server's own mail carries. Nothing requires it to
 * be an account: an operator commonly points `postmaster@` at the mailbox
 * they actually read. Local delivery files such a message under the
 * destination account, so a reader that compared the account a message
 * was filed for against the reporting address matched nothing, and every
 * report landed in the mailbox without a row being written.
 *
 * Both readers on the filing seam are driven here from port 25: the DMARC
 * reader (`blamepost.mail.reports`) and the delivery report reader
 * (`blamepost.mail.delivery.reports`). Each has to read a report sent to
 * the alias, and each has to pass over a report sent straight to the
 * destination account, which is not a reporting address.
 *
 * Run standalone: node test/layer-2-integration/inbound-report-alias.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");
var nodeZlib = require("node:zlib");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var dsn       = require("../helpers/dsn");
var dnsZone   = require("../helpers/dns-zone");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME   = "mx.example.com";
var DOMAIN     = "example.com";
var POSTMASTER = "postmaster@" + DOMAIN;
var OPERATOR   = "operator@" + DOMAIN;

var REPORTER     = "reporter.example";
var REPORTER_MTA = "mta." + REPORTER;
var PEER_REVERSE = "1.0.0.127.in-addr.arpa";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;
var SETTLE_TIMEOUT_MS   = 8000;

var count = helpers.count;

var NOW_SEC          = Math.floor(Date.now() / 1000);
var WINDOW_END_SEC   = NOW_SEC - 3600;
var WINDOW_BEGIN_SEC = WINDOW_END_SEC - 86400;

// ---- fixtures ---------------------------------------------------------------

function aggregateXml(reportId) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>" + REPORTER + "</org_name>\n" +
    "    <email>dmarc-noreply@" + REPORTER + "</email>\n" +
    "    <report_id>" + reportId + "</report_id>\n" +
    "    <date_range><begin>" + WINDOW_BEGIN_SEC + "</begin>" +
    "<end>" + WINDOW_END_SEC + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + DOMAIN + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>reject</p><sp>reject</sp><pct>100</pct>\n" +
    "  </policy_published>\n" +
    "  <record>\n" +
    "    <row><source_ip>203.0.113.10</source_ip><count>4</count>\n" +
    "      <policy_evaluated><disposition>none</disposition>" +
    "<dkim>pass</dkim><spf>pass</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>" + DOMAIN + "</header_from></identifiers>\n" +
    "    <auth_results><spf><domain>" + DOMAIN + "</domain>" +
    "<result>pass</result></spf></auth_results>\n" +
    "  </record>\n" +
    "</feedback>\n";
}

function carrier(to, reportId) {
  var payload = nodeZlib.gzipSync(Buffer.from(aggregateXml(reportId), "utf8"));
  return "From: dmarc-noreply@" + REPORTER + "\r\n" +
    "To: " + to + "\r\n" +
    "Subject: Report Domain: " + DOMAIN + "\r\n" +
    "Message-ID: <" + reportId + "@" + REPORTER + ">\r\n" +
    "Content-Type: multipart/mixed; boundary=\"bnd-report\"\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "This is an aggregate report from " + REPORTER + ".\r\n" +
    "\r\n" +
    "--bnd-report\r\n" +
    "Content-Type: application/gzip\r\n" +
    "Content-Disposition: attachment; filename=\"" + REPORTER + "!" + DOMAIN + "!" +
    WINDOW_BEGIN_SEC + "!" + WINDOW_END_SEC + ".xml.gz\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n" +
    "\r\n" +
    payload.toString("base64") + "\r\n" +
    "--bnd-report--\r\n";
}

function deliveryReport(to, messageId) {
  return dsn.report({
    to:         to,
    messageId:  messageId,
    recipients: [{
      address:    "tls-reports@receiver.example.org",
      action:     "failed",
      status:     "5.1.1",
      diagnostic: "550 5.1.1 no such user here",
    }],
  });
}

// ---- the wire ---------------------------------------------------------------

async function deliver(ctx, to, message, label) {
  var peer = await Wire.mx(ctx.ports.mx, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label, helo: REPORTER_MTA,
  });
  peer.send("MAIL FROM:<>");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + to + ">");
  var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  if (!/^250 /m.test(rcptReply)) {
    peer.send("QUIT");
    peer.close();
    return { rcptReply: rcptReply, accepted: null };
  }
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(message + ".\r\n", "<the message and its terminating dot>");
  var accepted = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return { rcptReply: rcptReply, accepted: accepted };
}

function dmarcOf(server) { return server.mail.reports.describe(); }
function deliveryReportsOf(server) { return server.mail.delivery.describe().reports; }

function rowsFor(identity) {
  return identity.reports.rollup({ domain: DOMAIN, includeUnauthenticated: true });
}

// ---- cases ------------------------------------------------------------------

async function aDmarcReportToTheAliasReachesTheRows(ctx) {
  var before = dmarcOf(ctx.server);
  var sent = await deliver(ctx, POSTMASTER, carrier(POSTMASTER, "alias-0001"),
    "dmarc-to-alias");
  count("a DMARC report addressed to the postmaster alias is accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await helpers.waitUntil(function () {
    var shape = dmarcOf(ctx.server);
    return shape.counts.received >= before.counts.received + 1 ? shape : false;
  }, { timeoutMs: SETTLE_TIMEOUT_MS,
    label: "inbound-report-alias: the DMARC report reaches the reader" });
  count("the reader takes it as a report rather than passing it over",
    after.counts.passedOver === before.counts.passedOver &&
    after.counts.aggregate === before.counts.aggregate + 1, JSON.stringify(after.counts));

  var rows = rowsFor(ctx.identity);
  count("and its records reach the rows the console reads",
    rows.length === 1 && rows[0].counted === 4, JSON.stringify(rows));
}

async function aDmarcReportToTheDestinationAccountIsPassedOver(ctx) {
  var before = dmarcOf(ctx.server);
  var sent = await deliver(ctx, OPERATOR, carrier(OPERATOR, "alias-0002"),
    "dmarc-to-account");
  count("a DMARC report addressed to the destination account is accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await helpers.waitUntil(function () {
    var shape = dmarcOf(ctx.server);
    return shape.counts.received >= before.counts.received + 1 ? shape : false;
  }, { timeoutMs: SETTLE_TIMEOUT_MS,
    label: "inbound-report-alias: the account's report reaches the reader" });
  count("the account is not a reporting address, so the reader passes the report over",
    after.counts.passedOver === before.counts.passedOver + 1 &&
    after.counts.aggregate === before.counts.aggregate, JSON.stringify(after.counts));
  var rows = rowsFor(ctx.identity);
  count("and no row is added for it",
    rows.length === 1 && rows[0].counted === 4, JSON.stringify(rows));
}

async function aDeliveryReportToTheAliasIsRead(ctx) {
  var before = deliveryReportsOf(ctx.server);
  var sent = await deliver(ctx, POSTMASTER, deliveryReport(POSTMASTER, "dsn-alias"),
    "dsn-to-alias");
  count("a delivery report addressed to the postmaster alias is accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await helpers.waitUntil(function () {
    var r = deliveryReportsOf(ctx.server);
    return r.examined >= before.examined + 1 ? r : false;
  }, { timeoutMs: SETTLE_TIMEOUT_MS,
    label: "inbound-report-alias: the delivery report reaches the reader" });
  count("the delivery report reader reads it",
    after.read === before.read + 1 && after.byAction.failed === before.byAction.failed + 1,
    JSON.stringify(after));
}

async function aDeliveryReportToTheDestinationAccountIsLeftAlone(ctx) {
  var before = deliveryReportsOf(ctx.server);
  var sent = await deliver(ctx, OPERATOR, deliveryReport(OPERATOR, "dsn-account"),
    "dsn-to-account");
  count("a delivery report addressed to the destination account is accepted at the wire",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));
  await helpers.passiveObserve(300, "no delivery report read for the account");
  var after = deliveryReportsOf(ctx.server);
  count("the delivery report reader does not examine a report sent to the account",
    after.examined === before.examined && after.read === before.read,
    JSON.stringify({ before: before.examined, after: after.examined }));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-report-alias");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_POSTMASTER:       POSTMASTER,
      },
      cwd: root,
    });

    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });
    await identity.accounts.create({ address: OPERATOR, password: ACCOUNT_PASSWORD });
    await identity.aliases.add({ address: POSTMASTER, destination: OPERATOR });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    var zone = {};
    zone[PEER_REVERSE + "|PTR"] = [{ type: 12, decoded: REPORTER_MTA, ttl: 60 }];
    zone[REPORTER_MTA + "|A"]   = [{ type: 1,  decoded: LOOPBACK,     ttl: 60 }];
    zone[REPORTER_MTA + "|TXT"] = [{ type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"],
                                     ttl: 60 }];
    zone[REPORTER + "|TXT"]     = [{ type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"],
                                     ttl: 60 }];
    zone["_dmarc." + REPORTER + "|TXT"] = [{ type: 16, decoded: ["v=DMARC1; p=none"], ttl: 60 }];

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        inbound:   { mode: "enforce", onTemperror: "defer" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
      resolver:     dnsZone.pinnedResolverOver(zone),
    });
    await server.start();
    running = true;

    var ctx = {
      server:   server,
      identity: identity,
      caPem:    leaf.ca,
      ports:    { mx: sections.mx.port },
    };

    await aDmarcReportToTheAliasReachesTheRows(ctx);
    await aDmarcReportToTheDestinationAccountIsPassedOver(ctx);
    await aDeliveryReportToTheAliasIsRead(ctx);
    await aDeliveryReportToTheDestinationAccountIsLeftAlone(ctx);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "inbound-report-alias", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
