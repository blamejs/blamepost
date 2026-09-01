// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * This server composes delivery status notifications and sends them. It
 * also receives them, and until now nothing read one.
 *
 * For an account's own mail that is the right answer: a report about a
 * message alice sent is addressed to alice, lands in alice's mailbox,
 * and a person reads it. The mail this server sends on its own behalf
 * has nobody like that behind it. Its reverse path is the reporting
 * identity the operator configured, the reports about it land in a
 * mailbox nobody opens, and a report saying a receiver's TLS report
 * endpoint has stopped accepting mail is the only notice anybody gets
 * that this server has quietly stopped honoring something it publishes.
 *
 * So the cases below drive real messages at the MX port and assert on
 * what the operator can see afterwards. What they must NOT observe is
 * any change to what this server is going to send next. A report is a
 * document a stranger composed and addressed here, nothing in it is
 * bound to a message this server actually sent, and a queue that can be
 * emptied by posting a well formed report at port 25 is worse than a
 * queue nobody reports on.
 *
 * The malformed cases are the point rather than the trimming. A report
 * arrives inside a message that was accepted, filed and is now somebody
 * else's property, so there is no protocol code left to refuse it with
 * and no version of refusing it that does not amount to deleting mail.
 * Every one of them therefore ends as a recorded verdict: the report is
 * never believed, and the operator can tell the difference between a
 * report that said nothing arrived and no report at all.
 *
 * The path under test runs from the MX port through the filing seam
 * `blamepost.mail.mailbox.onFiled` into `blamepost.mail.delivery.reports`,
 * driven as a peer drives it rather than by calling either of them.
 *
 * Run standalone: node test/layer-2-integration/inbound-delivery-report.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var dsn       = require("../helpers/dsn");
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
var ALICE      = "alice@" + DOMAIN;

var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD  = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;
var COUNTER_TIMEOUT_MS  = 5000;

var count = helpers.count;

// The bytes a peer's mail server sends are the shared fixture, so the
// case driving the MX port and the case driving the reader directly
// cannot disagree about what a report looks like.
var report       = dsn.report;
var plainMessage = dsn.plainMessage;

// ---- the wire --------------------------------------------------------------

// One inbound message, from the envelope through the terminating dot,
// over the MX ladder every peer climbs. The reverse path is empty
// because that is what RFC 5321 section 6.1 puts on a report, and a
// case that sent one from a real address would be testing a shape no
// report has.
async function deliver(port, caPem, to, message, label) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, label: label, helo: "relay.example.net",
  });
  peer.send("MAIL FROM:<>");
  var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + to + ">");
  var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  if (!/^250 /m.test(rcptReply)) {
    peer.send("QUIT");
    peer.close();
    return { mailReply: mailReply, rcptReply: rcptReply, accepted: null };
  }
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw(message + ".\r\n", "<the message and its terminating dot>");
  var accepted = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return { mailReply: mailReply, rcptReply: rcptReply, accepted: accepted };
}

// What the delivery handle says about the reports it has read. Read
// through `describe`, which is the same answer the admin surface renders
// and the same one an operator reads, rather than through a private
// counter no shipped surface exposes.
function reportsOf(server) {
  var shape = server.mail.delivery.describe();
  return shape.reports || null;
}

async function untilExamined(server, wanted, label) {
  return await helpers.waitUntil(function () {
    var r = reportsOf(server);
    return r !== null && r.examined >= wanted ? r : false;
  }, { timeoutMs: COUNTER_TIMEOUT_MS, label: label });
}

// ---- cases -----------------------------------------------------------------

// The case the whole thing exists for. A receiver refused a report this
// server owed it, the peer sent back the RFC 3464 account of that
// refusal, and the operator can now see that it happened.
async function aReportAboutThisServersOwnMailIsRead(ctx) {
  var before = reportsOf(ctx.server);
  count("the delivery handle reports on the reports it receives", before !== null,
    JSON.stringify(Object.keys(ctx.server.mail.delivery.describe())));
  if (before === null) return;

  var sent = await deliver(ctx.ports.mx, ctx.caPem, POSTMASTER, report({
    to: POSTMASTER,
    messageId: "dsn-single",
    recipients: [{
      address:    "tls-reports@receiver.example.org",
      action:     "failed",
      status:     "5.1.1",
      diagnostic: "550 5.1.1 no such user here",
    }],
  }), "report-single");
  count("a report addressed to the reporting identity is accepted",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await untilExamined(ctx.server, before.examined + 1,
    "the report reaches the reader");
  count("the report was read", after.read === before.read + 1,
    JSON.stringify(after));
  count("and the recipient it names is counted as a permanent failure",
    after.byAction.failed === before.byAction.failed + 1, JSON.stringify(after));
  count("nothing about it was unreadable", after.unreadable === before.unreadable,
    JSON.stringify(after));

  var recent = after.recent || [];
  var last = recent.length > 0 ? recent[recent.length - 1] : null;
  count("the operator can see which address the report was about",
    last !== null && JSON.stringify(last).indexOf("tls-reports@receiver.example.org") !== -1,
    JSON.stringify(last));
}

// Reading a report must not move anything. Anybody can compose one and
// address it here, so a report that could drain the outbound queue is a
// queue anybody can drain.
async function readingAReportChangesNothingThisServerWillSend(ctx) {
  var beforeShape = ctx.server.mail.delivery.describe();
  var before = reportsOf(ctx.server);

  await deliver(ctx.ports.mx, ctx.caPem, POSTMASTER, report({
    to: POSTMASTER,
    messageId: "dsn-no-mutation",
    originalEnvelopeId: "forged-envelope-id-0001",
    recipients: [{
      address: "someone@receiver.example.org", action: "failed", status: "5.7.1",
      diagnostic: "550 5.7.1 policy",
    }],
  }), "report-no-mutation");
  await untilExamined(ctx.server, before.examined + 1, "the second report is read");

  var afterShape = ctx.server.mail.delivery.describe();
  count("the outbound queue depth is untouched by a report",
    afterShape.waiting === beforeShape.waiting,
    beforeShape.waiting + " then " + afterShape.waiting);
  count("the spool holds exactly what it held",
    afterShape.spool.messages === beforeShape.spool.messages &&
    afterShape.spool.bytes === beforeShape.spool.bytes,
    JSON.stringify(beforeShape.spool) + " then " + JSON.stringify(afterShape.spool));

  // The envelope id is a string whoever composed the report chose, and
  // this server issues none of its own. It is kept as what the report
  // said, and it is the only thing in a report that could ever look like
  // the name of a message this server sent.
  var recent = afterShape.reports.recent || [];
  var last = recent.length > 0 ? recent[recent.length - 1] : null;
  count("an envelope id nobody here issued is kept as what the report said",
    last !== null && last.originalEnvelopeId === "forged-envelope-id-0001",
    JSON.stringify(last));
}

// One report, two recipients, two different outcomes. The framework
// parser derives its whole verdict from the first group, so a reader
// that took that answer would report a delayed recipient as though it
// had never been mentioned.
async function everyRecipientInAReportIsRead(ctx) {
  var before = reportsOf(ctx.server);
  await deliver(ctx.ports.mx, ctx.caPem, POSTMASTER, report({
    to: POSTMASTER,
    messageId: "dsn-multi",
    recipients: [
      { address: "first@receiver.example.org",  action: "failed",  status: "5.1.1" },
      { address: "second@receiver.example.org", action: "delayed", status: "4.4.1" },
    ],
  }), "report-multi");
  var after = await untilExamined(ctx.server, before.examined + 1,
    "the multi recipient report is read");

  count("both recipients are counted", after.recipients === before.recipients + 2,
    JSON.stringify(after));
  count("the permanent failure is counted under the token the report used",
    after.byAction.failed === before.byAction.failed + 1, JSON.stringify(after));
  count("and the delayed recipient is counted under its own rather than dropped",
    after.byAction.delayed === before.byAction.delayed + 1, JSON.stringify(after));
}

// An Action token RFC 3464 section 2.3.3 does not define. The first
// group is where the framework parser checks it, so this one proves the
// reader survives the parser's own refusal.
async function anUnknownActionOnTheFirstRecipientIsRefused(ctx) {
  var before = reportsOf(ctx.server);
  var sent = await deliver(ctx.ports.mx, ctx.caPem, POSTMASTER, report({
    to: POSTMASTER,
    messageId: "dsn-bad-action-first",
    recipients: [{ address: "first@receiver.example.org", action: "quarantined", status: "5.1.1" }],
  }), "report-bad-action-first");
  count("the message still arrives, because it is a valid message",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  var after = await untilExamined(ctx.server, before.examined + 1,
    "the unreadable report is examined");
  count("an undefined Action leaves the report unread", after.read === before.read,
    JSON.stringify(after));
  count("and it is recorded as unreadable rather than passed over",
    after.unreadable === before.unreadable + 1, JSON.stringify(after));
}

// The same token on a LATER group. The framework parser validates the
// first recipient only, so this one is the reader's own check.
async function anUnknownActionOnALaterRecipientIsRefused(ctx) {
  var before = reportsOf(ctx.server);
  await deliver(ctx.ports.mx, ctx.caPem, POSTMASTER, report({
    to: POSTMASTER,
    messageId: "dsn-bad-action-later",
    recipients: [
      { address: "first@receiver.example.org",  action: "failed",      status: "5.1.1" },
      { address: "second@receiver.example.org", action: "quarantined", status: "5.1.1" },
    ],
  }), "report-bad-action-later");
  var after = await untilExamined(ctx.server, before.examined + 1,
    "the later bad action is examined");

  count("an undefined Action anywhere in the report leaves it unread",
    after.read === before.read, JSON.stringify(after));
  count("the whole report is refused rather than the readable half kept",
    after.byAction.failed === before.byAction.failed &&
    after.unreadable === before.unreadable + 1,
    JSON.stringify(after));
}

// RFC 3464 section 2.3.3 makes Action mandatory in every per recipient
// group. The framework parser reads its absence as an empty string and
// carries on, which produces a report saying a recipient failed when
// the report never said so.
async function aRecipientGroupWithNoActionIsRefused(ctx) {
  var before = reportsOf(ctx.server);
  await deliver(ctx.ports.mx, ctx.caPem, POSTMASTER, report({
    to: POSTMASTER,
    messageId: "dsn-no-action",
    recipients: [{ address: "first@receiver.example.org", action: null, status: "5.1.1" }],
  }), "report-no-action");
  var after = await untilExamined(ctx.server, before.examined + 1,
    "the report with no action is examined");

  count("a group carrying no Action leaves the report unread",
    after.read === before.read, JSON.stringify(after));
  count("and nothing is counted as failed on a report that never said so",
    after.byAction.failed === before.byAction.failed &&
    after.unreadable === before.unreadable + 1,
    JSON.stringify(after));
}

// Ordinary mail to the operator. Most of what arrives at this address is
// this, and a reader that recorded every one of them would bury the
// reports it exists to surface.
async function ordinaryMailToTheReportingIdentityIsNotAReport(ctx) {
  var before = reportsOf(ctx.server);
  await deliver(ctx.ports.mx, ctx.caPem, POSTMASTER,
    plainMessage(POSTMASTER, "a question about the server"), "plain-to-postmaster");
  var after = await untilExamined(ctx.server, before.examined + 1,
    "the ordinary message is examined");

  count("an ordinary message is not read as a report", after.read === before.read,
    JSON.stringify(after));
  count("and it is not recorded as an unreadable one either",
    after.unreadable === before.unreadable, JSON.stringify(after));
}

// A report addressed to an account is that account's mail. It belongs in
// their mailbox and it is theirs to read, and a server that also filed a
// row about it would be reading the account's mail on the operator's
// behalf.
async function aReportForAnAccountIsLeftAlone(ctx) {
  var before = reportsOf(ctx.server);
  var sent = await deliver(ctx.ports.mx, ctx.caPem, ALICE, report({
    to: ALICE,
    messageId: "dsn-for-alice",
    recipients: [{ address: "friend@receiver.example.org", action: "failed", status: "5.1.1" }],
  }), "report-for-alice");
  count("a report addressed to an account is accepted",
    /^250 /m.test(String(sent.accepted)), visible(String(sent.accepted)));

  // An address this server never sends from produces no reader activity
  // at all, so there is no counter to wait on. The window is the price
  // of asserting that nothing happened.
  await helpers.passiveObserve(250, "no report reader activity for an account's mail");
  var after = reportsOf(ctx.server);
  count("an account's own report is not examined by the operator's reader",
    after.examined === before.examined, JSON.stringify(before) + " then " + JSON.stringify(after));
}

// The report is evidence and it stays where it landed. A reader that
// consumed what it read would take the one copy the operator can look at
// when the counters say something they do not understand.
async function theReportIsStillInTheMailbox(ctx) {
  var client = await Wire.imap(ctx.ports.imap, {
    caPem:    ctx.caPem,
    servername: HOSTNAME,
    label:    "imap-postmaster",
    address:  POSTMASTER,
    password: ACCOUNT_PASSWORD,
  });
  var tag = client.tag();
  client.send(tag + " SELECT INBOX");
  var selected = await client.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"), "SELECT answered");
  count("the reporting identity can open its own mailbox",
    new RegExp("^" + tag + " OK", "m").test(selected), visible(selected));
  count("and every message that arrived for it is still there",
    /^\* [1-9][0-9]* EXISTS/m.test(selected), visible(selected));

  var fetchTag = client.tag();
  client.send(fetchTag + " FETCH 1 BODY[]");
  var fetched = await client.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
    "FETCH answered");
  count("the report body is readable exactly as it arrived",
    fetched.indexOf("message/delivery-status") !== -1, visible(fetched).slice(0, 400));

  var logout = client.tag();
  client.send(logout + " LOGOUT");
  client.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-report");
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
        // The address this server puts on the mail it sends about
        // itself, which is therefore the address reports about that mail
        // come back to.
        BLAMEPOST_POSTMASTER:       POSTMASTER,
      },
      cwd: root,
    });

    // Given back before the directory under it goes, whichever way this
    // run ends. A database handle still open while its files are removed
    // is a locked file on Windows and a teardown rejection on Linux, and
    // either one lands on top of the verdict this run had already
    // reached.
    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "inbound report test" });
    await identity.accounts.create({ address: POSTMASTER, password: ACCOUNT_PASSWORD });
    await identity.accounts.create({ address: ALICE,      password: ACCOUNT_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        // The authentication gate resolves SPF and DMARC against live
        // DNS at the end of DATA and this process has no resolver, so
        // enforce mode would defer every message and the run would be
        // measuring the absence of DNS.
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var ctx = {
      server: server,
      caPem:  leaf.ca,
      ports:  { mx: sections.mx.port, imap: sections.imap.port },
    };

    await aReportAboutThisServersOwnMailIsRead(ctx);
    await readingAReportChangesNothingThisServerWillSend(ctx);
    await everyRecipientInAReportIsRead(ctx);
    await anUnknownActionOnTheFirstRecipientIsRefused(ctx);
    await anUnknownActionOnALaterRecipientIsRefused(ctx);
    await aRecipientGroupWithNoActionIsRefused(ctx);
    await ordinaryMailToTheReportingIdentityIsNotAReport(ctx);
    await aReportForAnAccountIsLeftAlone(ctx);
    await theReportIsStillInTheMailbox(ctx);

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

module.exports = { name: "inbound-delivery-report", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
