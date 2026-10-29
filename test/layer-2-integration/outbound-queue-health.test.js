// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the health probes say about the outbound queue, over the endpoint
 * a load balancer and a container runtime actually poll.
 *
 * This is the outage a mail server can have while every other reading is
 * perfect. The listeners are bound, the store is open, the certificate is
 * fresh, and mail is not moving: a peer is refusing everything, a
 * resolver has stopped answering, or nothing is draining the spool at
 * all. From outside, that server is indistinguishable from a healthy one,
 * and the operator finds out when somebody asks why their message never
 * arrived.
 *
 * The hard part is what counts as a fault, because "the queue is not
 * empty" is not one. A queue with messages in it is a working mail
 * server: a peer down for an hour is ordinary, and RFC 5321 §4.5.4.1 has
 * a sender retrying for days before giving up. A probe that reported
 * every non-empty queue would be a probe operators learn to ignore,
 * which is worse than no probe.
 *
 * So three conditions are read, and each one is a way for mail to stop
 * rather than a way for it to be slow:
 *
 *   - The spool has filled past the depth at which it stops accepting
 *     mail for forwarding. That is not a threshold invented here: it is
 *     the ceiling the spool already applies to a message arriving for an
 *     alias, so crossing it means this server has ALREADY begun refusing
 *     mail it would otherwise have taken, and the operator's own account
 *     holders are next.
 *   - Mail is waiting and nothing is draining it. The sweep is armed
 *     before the browser surface binds and disarmed after it stops, so a
 *     disarmed sweep on a server that is answering probes has no benign
 *     reading.
 *   - This build cannot put a message on the wire at all, in which case
 *     every message that reaches the spool stays there by construction.
 *
 * Both verdicts are REDUCED rather than refused, and that is the property
 * this file pins hardest, because it is the one that would be tempting to
 * get wrong. A failing liveness check asks a runtime to restart the
 * process, and a restart does not drain a queue: the spool is files on
 * the volume, every stuck entry is read back on the next boot exactly as
 * it was, and the attempts that were in flight are lost and repeated. A
 * failing readiness check withdraws the browser surface, which is the
 * administration console an operator would open to read the queue and
 * cancel what is never going to leave. Neither lever touches the
 * subsystem that is stuck, and the readiness lever does not even move the
 * traffic that fills it: the spool is fed by the MX and submission
 * listeners, which are on their own ports and keep taking mail whatever a
 * proxy decides about the HTTP one.
 *
 * The spool is filled through real submission sessions on a real
 * socket rather than by writing files, because the depth the probe reads
 * has to be the depth mail actually produces. Nothing leaves the
 * machine: the resolver answers for one domain and there is no peer
 * behind the name, so every recipient defers and stays on the spool.
 *
 * The third condition is reported and not driven. Whether a message can
 * reach a peer at all is decided by the vendored framework's transport
 * surface, which is read-only, so there is no configuration this file
 * could set to remove it. `wireDeliveryStatus` is held to its own
 * verdicts in test/layer-1-state/mail-delivery.test.js; what is pinned
 * here is that the probe carries the answer rather than leaving it in a
 * boot line nobody is watching.
 *
 * Run standalone: node test/layer-2-integration/outbound-queue-health.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME  = "mx.example.com";
var DOMAIN    = "example.com";
var ELSEWHERE = "example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The ceiling this run holds the spool to, and the depth at which mail
// arriving for forwarding stops being taken. The second number is read
// off the running server rather than computed here: it is the spool's
// own reservation, and a second arithmetic for it in this file could
// disagree with the one the spool acts on and still pass.
var MAX_SPOOL_MESSAGES = 10;

var BODY = "Ordering two more of the blue ones. Marker 5c31ab90.";

// The fault names the queue check reports, which is the contract an
// operator's monitoring rule matches on.
var FAULT_DEPTH = "queue depth";
var FAULT_DRAIN = "queue drain";

var ANSWERING_RESOLVER = {
  queryMx: function (name) {
    if (String(name).toLowerCase() === ELSEWHERE) {
      return Promise.resolve([{ priority: 10, exchange: "mx." + ELSEWHERE }]);
    }
    return Promise.reject(new Error("no mail exchanger for " + name));
  },
  queryTxt: function () { return Promise.resolve([]); },
  // The posture checker asks every hosted domain for a TLSA record and
  // refuses a handle that cannot answer, so a fixture standing in for a
  // resolver carries this reader whether or not its own subject is DANE.
  queryTlsa: function () { return Promise.resolve({ rrs: [] }); },
  queryPtr: function () { return Promise.resolve([]); },
  query:    function () { return Promise.resolve([]); },
};

// ---- reading the probes -----------------------------------------------------

// Both endpoints answer the full per-check breakdown to a loopback peer,
// which is what this file is, so the queue answer is readable rather
// than only the verdict word.
async function probe(port, path) {
  var res  = await fetch("http://" + LOOPBACK + ":" + port + path);
  var body = await res.json();
  return {
    status: res.status,
    body:   body,
    queue:  body && body.checks ? body.checks.queue : undefined,
    said:   res.status + " " + JSON.stringify(body),
  };
}

function readiness(port) { return probe(port, "/readyz"); }
function liveness(port)  { return probe(port, "/healthz"); }

function faultsOf(reading) {
  return (reading.queue && Array.isArray(reading.queue.faults))
    ? reading.queue.faults : [];
}

// ---- the spool --------------------------------------------------------------

function spoolIds(dataDir) {
  var dir = nodePath.join(dataDir, "queue");
  if (!nodeFs.existsSync(dir)) return [];
  return nodeFs.readdirSync(dir)
    .filter(function (n) { return n.slice(-5) === ".json"; })
    .map(function (n) { return n.slice(0, -5); })
    .sort();
}

async function submitOneTo(ctx, recipient, marker) {
  var session = await Wire.connect(ctx.ports.submission, "submission-" + marker);
  await session.read(/^220 /m, "banner");
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(ctx.caPem, HOSTNAME);
  session.send("EHLO client.example.net");
  await session.read(/^250 /m, "EHLO accepted over TLS");
  session.send("AUTH PLAIN " + wire.saslPlain(ctx.alice, ALICE_PASSWORD));
  await session.read(/^235 /m, "authenticated");
  session.send("MAIL FROM:<" + ctx.alice + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  session.send("RCPT TO:<" + recipient + ">");
  await session.read(/^\d{3} /m, "RCPT TO answered");
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  session.sendRaw([
    "From: " + ctx.alice,
    "To: " + recipient,
    "Subject: " + marker,
    "Date: Sun, 23 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker + "@example.com>",
    "",
    BODY,
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");
  var answer = await session.read(/^\d{3} /m, "message answered");
  session.send("QUIT");
  session.close();
  return answer;
}

// ---- an empty queue is answered for, rather than passed over ----------------

async function anEmptyQueueIsAnAnswerRatherThanAnAbsentOne(ctx) {
  var fit = await readiness(ctx.httpPort);

  count("the readiness probe reports the outbound queue, rather than answering only " +
    "about ports, the store and the certificate",
    fit.queue !== undefined, fit.said);
  count("a server with nothing waiting leaves the verdict clean",
    fit.status === 200 && fit.body.status === "ok", fit.said);

  // No mail waiting and no queue are different facts. An answer this
  // reader could not take has to say so rather than reading as an empty
  // spool, or a delivery handle that stopped answering would report a
  // mail server with nothing wrong.
  count("and the probe says it READ the queue, so an empty spool is not the same " +
    "answer as a queue nobody could ask",
    fit.queue.read === true && fit.queue.ok === true && faultsOf(fit).length === 0,
    JSON.stringify(fit.queue));
  count("an empty spool is reported as empty",
    fit.queue.waiting === 0, JSON.stringify(fit.queue));
  count("the sweep that drains the spool is armed and the probe says so",
    fit.queue.draining === true, JSON.stringify(fit.queue));
  count("this build can put a message on the wire and the probe carries that too, " +
    "so a build that cannot is not left in a boot line nobody is watching",
    fit.queue.transport === true, JSON.stringify(fit.queue));
  count("and the probe names the depth at which this spool stops taking mail for " +
    "forwarding, so the number it reports as waiting can be read against something",
    typeof fit.queue.forwardingStopsAt === "number" &&
    fit.queue.forwardingStopsAt > 0 &&
    fit.queue.forwardingStopsAt < MAX_SPOOL_MESSAGES,
    JSON.stringify(fit.queue));

  return fit.queue.forwardingStopsAt;
}

// ---- mail retrying normally is not a fault ---------------------------------

async function aQueueThatIsRetryingNormallyIsNotAFault(ctx, stopsAt) {
  // One message short of the reservation. Every one of these is a real
  // recipient this server is still retrying, which is a mail server
  // working rather than a mail server stuck.
  for (var i = 0; i < stopsAt - 1; i += 1) {
    await submitOneTo(ctx, "bob" + i + "@" + ELSEWHERE, "retrying-" + i);
  }
  var depth = spoolIds(ctx.dataDir).length;
  count("the submissions reached the spool, so the depth being read is one mail " +
    "actually produced",
    depth === stopsAt - 1, String(depth));

  var fit = await readiness(ctx.httpPort);
  count("a queue holding mail that is retrying normally leaves the verdict clean, " +
    "because a peer that is down for an hour is ordinary and a probe that reported " +
    "every non-empty queue is one an operator learns to ignore",
    fit.status === 200 && fit.body.status === "ok", fit.said);
  count("and the check reports the depth without calling it a fault",
    fit.queue.ok === true && fit.queue.waiting === depth && faultsOf(fit).length === 0,
    JSON.stringify(fit.queue));
}

// ---- a queue past the point where it refuses mail --------------------------

async function aQueuePastItsReservationReducesTheVerdict(ctx, stopsAt) {
  await submitOneTo(ctx, "crossing@" + ELSEWHERE, "crossing");
  var depth = spoolIds(ctx.dataDir).length;
  count("the spool has reached the depth at which it stops taking mail for forwarding",
    depth === stopsAt, String(depth) + " of " + String(stopsAt));

  var over = await readiness(ctx.httpPort);
  count("a spool that has filled past the depth where it stops accepting mail for " +
    "forwarding reduces the verdict, because this server has already begun refusing " +
    "mail it would otherwise have taken",
    over.status === 200 && over.body.status === "degraded", over.said);
  count("and the reduced verdict names the queue depth rather than leaving an " +
    "operator a failing streak with nothing to act on",
    over.queue.ok === false && faultsOf(over).indexOf(FAULT_DEPTH) !== -1,
    JSON.stringify(over.queue));
  count("and it reports how much is waiting against the depth that stops it",
    over.queue.waiting === depth && over.queue.forwardingStopsAt === stopsAt,
    JSON.stringify(over.queue));

  // The lever question, and the reason this is degraded rather than a
  // refusal. Readiness withdraws the administration console an operator
  // reads the queue from, and it moves no traffic that fills the spool:
  // the MX and submission listeners are on their own ports and keep
  // taking mail whatever a proxy decides about this one.
  count("readiness is REDUCED and not refused, so a proxy keeps the browser surface " +
    "the operator would open to read and cancel what is waiting",
    over.status === 200 && over.status !== 503, over.said);

  // The same reading on the liveness probe. A restart re-reads the same spool
  // off the same volume, so every stuck entry is still stuck and the
  // attempts in flight are lost and repeated.
  var live = await liveness(ctx.httpPort);
  count("liveness is REDUCED and not failed, because a restart does not drain a " +
    "queue: the spool is files on the volume and every entry is read back exactly " +
    "as it was",
    live.status === 200 && live.body.status === "degraded", live.said);
  count("and the liveness answer names the same fault, so one alert rule reads both",
    live.queue.ok === false && faultsOf(live).indexOf(FAULT_DEPTH) !== -1,
    JSON.stringify(live.queue));
}

// ---- and it clears -----------------------------------------------------------

async function drainingBackUnderTheReservationClearsIt(ctx, stopsAt) {
  var ids = spoolIds(ctx.dataDir);
  await ctx.server.mail.delivery.queue.remove(ids[0], {
    reason: "draining one entry back under the reservation",
    notice: { withheld: "fixture-removal" },
  });
  var depth = spoolIds(ctx.dataDir).length;
  count("one entry left the spool, putting it back under the reservation",
    depth === stopsAt - 1, String(depth));

  var back = await readiness(ctx.httpPort);
  count("the verdict clears once the spool is back under the depth that refuses, so " +
    "the signal recovers rather than latching until a restart",
    back.status === 200 && back.body.status === "ok", back.said);
  count("and the check reports no fault against the queue",
    back.queue.ok === true && faultsOf(back).length === 0, JSON.stringify(back.queue));
}

// ---- mail waiting with nothing draining it ----------------------------------

async function mailWaitingWithNothingDrainingItReducesTheVerdict(ctx) {
  var waiting = spoolIds(ctx.dataDir).length;
  count("there is mail on the spool for the drain reading to be about",
    waiting > 0, String(waiting));

  ctx.server.mail.delivery.stop();

  var stalled = await readiness(ctx.httpPort);
  count("mail waiting with nothing draining it reduces the verdict, which is the " +
    "difference between a queue that is retrying and a queue that is not moving",
    stalled.status === 200 && stalled.body.status === "degraded", stalled.said);
  count("and the check says the sweep is not running and names it as the fault",
    stalled.queue.ok === false && stalled.queue.draining === false &&
    faultsOf(stalled).indexOf(FAULT_DRAIN) !== -1,
    JSON.stringify(stalled.queue));
  count("the depth is not what reported it: the spool is under the reservation",
    faultsOf(stalled).indexOf(FAULT_DEPTH) === -1 &&
    stalled.queue.waiting < stalled.queue.forwardingStopsAt,
    JSON.stringify(stalled.queue));
  count("a stalled drain does not refuse traffic either, for the same reason a full " +
    "spool does not: neither lever reaches the subsystem that stopped",
    stalled.status === 200, stalled.said);

  ctx.server.mail.delivery.start();

  var moving = await readiness(ctx.httpPort);
  count("arming the sweep again clears the verdict",
    moving.status === 200 && moving.body.status === "ok", moving.said);
  count("and the check reports the drain running with the same mail still waiting, " +
    "so what cleared it was the drain rather than the queue emptying",
    moving.queue.draining === true && moving.queue.ok === true &&
    moving.queue.waiting === waiting,
    JSON.stringify(moving.queue));
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("outbound-queue-health");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "queue health test" });
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

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:       0,
        listeners:      sections,
        inbound:        { mode: "monitor" },
        outboundPolicy: { mtaSts: "off", dane: "off" },
        // A retry budget with room left in it, and a first wait long
        // enough that no sweep can drain the spool underneath a reading.
        // On a budget of one the first attempt is also the last, so the
        // recipient ends permanently refused with a report to its sender
        // and nothing stays on the spool to read a depth from.
        outboundRetry:  {
          maxAttempts: 5,
          backoffMs:   [b.constants.TIME.minutes(30), b.constants.TIME.hours(1),
                        b.constants.TIME.hours(2), b.constants.TIME.hours(4),
                        b.constants.TIME.hours(8)],
        },
        outboundSpool:  { maxMessages: MAX_SPOOL_MESSAGES },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      resolver:     ANSWERING_RESOLVER,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.describe().web.bound;
    count("the browser surface took a cleartext port, which is where the probes answer",
      typeof bound.http === "number" && bound.http > 0, JSON.stringify(bound));

    var ctx = {
      ports:    { submission: sections.submission.port },
      caPem:    leaf.ca,
      alice:    alice.address,
      server:   server,
      dataDir:  dataDir,
      httpPort: bound.http,
    };

    var stopsAt = await helpers.withTestTimeout(
      "queue health: an empty queue is answered for",
      function () { return anEmptyQueueIsAnAnswerRatherThanAnAbsentOne(ctx); },
      { timeoutMs: 60000 });
    await helpers.withTestTimeout("queue health: mail retrying normally is not a fault",
      function () { return aQueueThatIsRetryingNormallyIsNotAFault(ctx, stopsAt); },
      { timeoutMs: 120000 });
    await helpers.withTestTimeout("queue health: a queue past its reservation reduces",
      function () { return aQueuePastItsReservationReducesTheVerdict(ctx, stopsAt); },
      { timeoutMs: 60000 });
    await helpers.withTestTimeout("queue health: draining back under it clears",
      function () { return drainingBackUnderTheReservationClearsIt(ctx, stopsAt); },
      { timeoutMs: 60000 });
    await helpers.withTestTimeout("queue health: mail waiting with nothing draining it",
      function () { return mailWaitingWithNothingDrainingItReducesTheVerdict(ctx); },
      { timeoutMs: 60000 });

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
  }
}

module.exports = { name: "outbound-queue-health", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
