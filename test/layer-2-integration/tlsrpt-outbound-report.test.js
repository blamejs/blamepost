// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An account sends mail to a domain that asked to be told how it went,
 * driven through a real submission listener with a real mail client on
 * a real socket.
 *
 * RFC 8460 makes a sender that reads `_smtp._tls.<domain>` owe that
 * receiver an account of its transport security. This server asks its
 * own operators to publish that record, so the claim under test is that
 * it honors other people's: a message submitted by an account, over
 * SASL and TLS, against a receiver whose MTA-STS record cannot be
 * resolved, has to end in a report addressed to where that receiver
 * asked for it and carrying the policy failure that actually happened.
 *
 * The path matters more than the assertion. Everything here starts at
 * the wire an operator's client speaks: the account authenticates, the
 * envelope is accepted for relay, the delivery handoff runs inside the
 * listener's own answer, and only then is the report composed. A run
 * that called the reporter directly would prove the reporter works and
 * say nothing about whether a submitted message ever reaches it.
 *
 * The resolver is the server's own pinned one, answering from a table,
 * because the record that decides where this server's failure reports
 * go is exactly the record a forged answer would redirect. One name in
 * that table cannot be looked up at all, which is what produces a
 * genuine RFC 8460 policy failure in a build whose transport cannot
 * open a socket: the MTA-STS question is settled before any transport
 * is constructed.
 *
 * Nothing leaves the machine. The HTTPS submission goes to a recording
 * client, in the shape the framework's own submission takes.
 *
 * Run standalone: node test/layer-2-integration/tlsrpt-outbound-report.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");
var zlib     = require("node:zlib");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var zone      = require("../helpers/dns-zone");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME  = "mx.example.com";
var DOMAIN    = "example.com";
var ELSEWHERE = "example.net";
var ENDPOINT  = "https://reports.example.net/tlsrpt";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var BODY = "Confirming the order. Marker 4c81ba30.";

var count = helpers.count;

// The zone this run answers from. Three entries carry the case:
//
//   - the receiver publishes a mail exchanger, so the composer gets
//     past MX lookup rather than stopping short of the policy;
//   - its MTA-STS record cannot be looked up, which under an enforcing
//     posture is a refusal to deliver and an RFC 8460 §4.3 policy
//     failure at the same time;
//   - and it publishes a TLS-RPT endpoint, so it is owed the report.
//
// The server's own domain publishes a TLS-RPT record too, which is what
// the operator guide asks an operator to publish and what the posture
// check has to read the way a sender would.
var ZONE = {
  "example.net|MX":             [{ exchange: "mx.example.net", priority: 10 }],
  "_mta-sts.example.net|TXT":   zone.FAILING,
  "_smtp._tls.example.net|TXT": [{ type: 16, decoded: ["v=TLSRPTv1; rua=" + ENDPOINT] }],

  "example.com|MX":             [{ exchange: HOSTNAME, priority: 10 }],
  "_smtp._tls.example.com|TXT": [{ type: 16, decoded: ["v=TLSRPTv1; rua=mailto:tls@example.com"] }],
};

// The client the framework's TLS-RPT submission posts through, in the
// shape it expects back.
function recordingClient() {
  var posts = [];
  return {
    posts: posts,
    request: async function (opts) {
      posts.push(opts);
      return { statusCode: 202, headers: {}, body: "" };
    },
  };
}

var plainResponse = wire.saslPlain;

async function submissionSession(port, caPem, address, password, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^220 /m, "banner");
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted over TLS");
  session.send("AUTH PLAIN " + plainResponse(address, password));
  await session.read(/^235 /m, "authenticated");
  return session;
}

function spoolFiles(dataDir) {
  var dir = nodePath.join(dataDir, "queue");
  if (!nodeFs.existsSync(dir)) return [];
  return nodeFs.readdirSync(dir).sort();
}

// ---- the case --------------------------------------------------------------

async function aSubmittedMessageEndsInAReportToTheReceiver(ports, caPem, alice, server, dataDir, resolver) {
  var recipient = "bob@" + ELSEWHERE;
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-tlsrpt");

  sender.send("MAIL FROM:<" + alice + ">");
  count("the sender is accepted",
    /^250 /m.test(await sender.read(/^\d{3} /m, "MAIL FROM answered")), "");

  sender.send("RCPT TO:<" + recipient + ">");
  var rcptReply = await sender.read(/^\d{3} /m, "RCPT TO answered");
  count("a recipient somewhere else is accepted for relay",
    /^250 /m.test(rcptReply), visible(rcptReply));

  sender.send("DATA");
  await sender.read(/^354 /m, "DATA answered");
  sender.sendRaw([
    "From: " + alice,
    "To: " + recipient,
    "Subject: The order",
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <tlsrpt-4c81ba30@example.com>",
    "",
    BODY,
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");

  var accepted = await sender.read(/^\d{3} /m, "message answered");
  count("the message is accepted for delivery", /^250 /m.test(accepted), visible(accepted));
  sender.send("QUIT");
  sender.close();

  // The handoff runs inside the listener's own answer, so the spool and
  // the observation are both written by the time the client sees its
  // 250. Polled rather than slept on, because that is a claim about a
  // loaded runner as much as about this one.
  var observed = await helpers.waitUntil(async function () {
    var rows = await server.mail.delivery.tlsRpt.observed();
    var row = rows.filter(function (r) { return r.domain === ELSEWHERE; })[0];
    return row || false;
  }, {
    timeoutMs: 5000,
    label:     "tls-rpt: the submitted message leaves an observation against the receiver",
  });

  count("the attempt is recorded against the receiver, not against the account",
    observed.domain === ELSEWHERE && observed.failed === 1, JSON.stringify(observed).slice(0, 200));
  count("and it is recorded as the MTA-STS failure it was",
    observed.failures.length === 1 &&
    observed.failures[0].resultType === "sts-policy-fetch-error",
    JSON.stringify(observed.failures).slice(0, 200));
  count("the message itself is waiting rather than lost",
    spoolFiles(dataDir).length === 2, spoolFiles(dataDir).join(" "));

  // The endpoint question is asked at the moment of the run rather than
  // read from anything cached when the message was sent, and it is
  // asked of the resolver the operator pinned.
  var client = recordingClient();
  var run = await server.mail.delivery.tlsRpt.run({ httpClient: client });

  count("the run reports on the receiver that asked to be told",
    run.ran === 1 && run.results[0].domain === ELSEWHERE &&
    run.results[0].outcome === "submitted", JSON.stringify(run.results).slice(0, 200));
  count("the endpoint lookup went to the pinned resolver",
    resolver.wasAsked("_smtp._tls." + ELSEWHERE, "TXT"), resolver.asked().join(" "));
  count("one report went to the endpoint the receiver published",
    client.posts.length === 1 && client.posts[0].url === ENDPOINT,
    client.posts.map(function (p) { return p.url; }).join(" "));

  var report = JSON.parse(zlib.gunzipSync(client.posts[0].body).toString("utf8"));
  count("it is signed with this server's name, so the receiver knows who is telling them",
    report["organization-name"] === HOSTNAME, String(report["organization-name"]));
  count("it is about the receiver's own domain",
    report.policies[0].policy["policy-domain"] === ELSEWHERE,
    String(report.policies[0].policy["policy-domain"]));
  count("and it carries the one failed session rather than a count of waiting messages",
    report.policies[0].summary["total-failure-session-count"] === 1 &&
    report.policies[0].summary["total-successful-session-count"] === 0,
    JSON.stringify(report.policies[0].summary));
  count("naming the policy failure RFC 8460 §4.3 has for it",
    report.policies[0]["failure-details"][0]["result-type"] === "sts-policy-fetch-error",
    JSON.stringify(report.policies[0]["failure-details"]));

  count("no account address appears anywhere in the report",
    JSON.stringify(report).indexOf(alice) === -1 &&
    JSON.stringify(report).indexOf(recipient) === -1, "");

  var after = (await server.mail.delivery.tlsRpt.observed())
    .filter(function (r) { return r.domain === ELSEWHERE; });
  count("the period closes once the receiver has the report", after.length === 0,
    JSON.stringify(after).slice(0, 120));

  var outbound = server.describe().outbound;
  count("the handle counts the report it sent", outbound.tlsRpt.reportsSubmitted === 1 &&
    outbound.tlsRpt.reportsUnsent === 0, JSON.stringify(outbound.tlsRpt));
  count("and says it is reporting on a period rather than on nothing",
    outbound.tlsRpt.reporting === true && outbound.tlsRpt.reportingIntervalMs > 0,
    JSON.stringify(outbound.tlsRpt));

  // The audit trail is where an operator reads this back, so a row
  // written under an unregistered namespace would be discarded without
  // a word and the whole record would be a claim nobody could check.
  await b.audit.flush();
  var rows = await b.audit.query({ action: "blamepost.mail.delivery.tls_rpt_sent", limit: 20 });
  count("the report this server sent is on the audit trail",
    rows.length === 1, String(rows.length));
  count("naming the receiver it went to and what it carried",
    rows.length === 1 && JSON.parse(rows[0].metadata).domain === ELSEWHERE &&
    JSON.parse(rows[0].metadata).failed === 1,
    rows.length === 1 ? String(rows[0].metadata) : "");
}

// The other half of the same record. An operator publishes `_smtp._tls`
// for their own domain because this server's documentation asks them
// to, so the check that tells them whether they got it right has to
// read it the way the senders they are asking will read it.
async function theServersOwnRecordIsCheckedTheWayASenderReadsIt(server) {
  var report = await server.mail.posture.check({ domains: [DOMAIN] });
  var finding = report.domains[0].findings.filter(function (f) {
    return f.record === "TLS-RPT";
  })[0];
  count("the posture check has a verdict on the record the operator published",
    finding !== undefined, JSON.stringify(report.domains[0].findings.map(function (f) {
      return f.record;
    })));
  count("and a record a sender would act on passes",
    finding !== undefined && finding.ok === true, JSON.stringify(finding).slice(0, 200));
  count("without failing the run, because reporting is a posture rather than a requirement",
    finding !== undefined && finding.severity === "advised", String(finding.severity));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("tlsrpt-outbound");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server   = null;
  var running  = false;
  var identity = null;

  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "tls report test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    var resolver = zone.pinnedResolverOver(ZONE);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:       0,
        listeners:      sections,
        inbound:        { mode: "monitor" },
        // Enforcing, because that is the posture under which an
        // unreadable MTA-STS record is a refusal and a reportable
        // policy failure rather than a shrug.
        outboundPolicy: { mtaSts: "enforce", dane: "off" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      resolver:     resolver,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    await aSubmittedMessageEndsInAReportToTheReceiver(
      { submission: sections.submission.port }, leaf.ca, alice.address, server, dataDir, resolver);
    await theServersOwnRecordIsCheckedTheWayASenderReadsIt(server);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // `server.stop` does not close the store, because the caller owns
    // what it passed in, and the database handle behind it is one per
    // process.
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "tlsrpt-outbound-report", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
