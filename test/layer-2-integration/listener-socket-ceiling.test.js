// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * listener-socket-ceiling: how many sockets one listener accepts at
 * once, whoever they belong to, measured at the number SECURITY.md
 * publishes.
 *
 * The per-address ceiling bounds ONE peer. It says nothing about how
 * many peers there are, so the process-wide total is that ceiling
 * multiplied by however many source addresses a sender can speak from,
 * and a botnet, a NAT pool or a single v6 /64 makes that number large.
 * The listener ceiling is the bound that does not multiply: each
 * listener accepts at most 1024 sockets at once and closes the rest
 * before its own state machine ever sees them.
 *
 * Nothing measured it. `maxConnections` appears in this repository only
 * inside a comment saying the value belongs to the framework and that
 * the parity gate over the rate limiter's table cannot see it, because
 * it is not in that table. So the one number an operator is told about
 * the process-wide total was a number nothing here held and nothing here
 * checked, and a refresh that moved it would move what this server
 * accepts while the shipped document went on promising 1024.
 *
 * What is asserted, on a real listener with real sockets:
 *
 *   - Every socket up to the published ceiling is admitted and greeted.
 *   - The one past it is closed having been told nothing at all. That
 *     silence is the discriminator: the per-address ceiling and the
 *     per-minute rate both refuse in words a client can read, and this
 *     one happens before the protocol exists, so a refusal line here
 *     would mean some other bound answered.
 *   - The listener says so in its own audit trail, naming the ceiling it
 *     applied, because a listener sitting at capacity and turning real
 *     senders away otherwise looks exactly like an idle one.
 *   - Closing a socket gives the slot back, so this is a ceiling on
 *     concurrency rather than a budget the listener spends once.
 *
 * The per-address ceiling and the per-minute connection rate are raised
 * to their own maxima for this run, so the only bound left to answer is
 * the listener's. Left at their defaults a run like this would be
 * refused in words at the tenth socket and would never reach the ceiling
 * it is about.
 *
 * This file opens more than a thousand sockets, so it costs a few
 * seconds where most files in this layer cost under one. That is the
 * price of measuring a bound whose whole point is that it is only
 * reachable in bulk.
 *
 * Run standalone: node test/layer-2-integration/listener-socket-ceiling.test.js
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
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count        = helpers.count;
var auditCapture = helpers.auditCapture;
var metadataOf   = helpers.metadataOf;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The number SECURITY.md publishes. Written here as the document writes
// it rather than read off the framework, which would assert that the
// framework agrees with itself and stay true across the refresh this
// file exists to catch.
var DOCUMENTED_SOCKET_CEILING = 1024;

// The two per-address bounds, raised to the maxima the configuration
// schema allows so that neither of them is what answers below.
var PER_ADDRESS_CONCURRENT = 1024;
var PER_ADDRESS_PER_MINUTE = 10000;

// How long a socket is given to be greeted or closed. Opening a thousand
// of them is bulk work on the runner as well as on the listener, so the
// budget is generous; nothing waits it out unless something is wrong.
var SETTLE_CEILING_MS = 60000;

// The IMAP greeting, which is what an admitted socket receives and a
// refused one does not.
var GREETING = /^\* OK \[CAPABILITY/;

// ---- sockets ---------------------------------------------------------------

// One connection, watched for the two things that can happen to it: the
// listener greets it, or the listener closes it.
async function openWatched(port, label) {
  var session = await Wire.connect(port, label);
  session.closed = false;
  session.socket.once("close", function () { session.closed = true; });
  return session;
}

function greeted(session) { return GREETING.test(session.buf); }

// ---- cases -----------------------------------------------------------------

// Fill the listener to the published ceiling, then ask for one more.
async function theListenerAcceptsExactlyTheCeilingAndClosesTheNext(port, audit) {
  var admitted = [];
  for (var i = 0; i < DOCUMENTED_SOCKET_CEILING; i += 1) {
    admitted.push(await openWatched(port, "ceiling-" + i));
  }

  // Waited on "answered", not on "greeted". A listener whose ceiling had
  // moved below the published one greets some of these and closes the
  // rest, and waiting for the greeting that is never coming would report
  // that as a timeout with no number in it. Waiting for every socket to
  // have been answered EITHER way puts the count in the assertion below,
  // where a reader can see which ceiling was in force.
  await helpers.waitUntil(function () {
    return admitted.every(function (s) { return greeted(s) || s.closed; });
  }, {
    timeoutMs: SETTLE_CEILING_MS,
    label:     "socket ceiling: every socket up to the published ceiling is answered",
  });

  count("a listener greets every socket up to the ceiling the document publishes, " +
    DOCUMENTED_SOCKET_CEILING + " of them at once",
    admitted.filter(greeted).length === DOCUMENTED_SOCKET_CEILING,
    admitted.filter(greeted).length + " greeted of " + DOCUMENTED_SOCKET_CEILING);

  count("and none of them was refused in words, so neither per-address bound is what is " +
    "being measured here",
    admitted.every(function (s) { return !/BAD|BYE|Too many/.test(s.buf); }),
    visible(admitted.map(function (s) { return s.buf; })
      .filter(function (t) { return !GREETING.test(t); }).join(" | ").slice(0, 200)));

  var past = await openWatched(port, "ceiling-past");
  await helpers.waitUntil(function () { return past.closed; }, {
    timeoutMs: SETTLE_CEILING_MS,
    label:     "socket ceiling: the socket past the ceiling is closed",
  });

  count("the socket past the ceiling is closed rather than accepted and starved",
    past.closed === true, String(past.closed));
  // Silence is the discriminator. Both per-address bounds refuse in
  // words a client can read, and both run inside the connection handler;
  // this ceiling is enforced before the handler exists, so a refusal
  // line here would mean some other bound answered and the ceiling was
  // never reached.
  count("having been told nothing at all, because the ceiling is applied before the " +
    "protocol is, which is what separates it from the per-address bounds",
    past.buf.length === 0, visible(past.buf));

  await helpers.waitUntil(function () {
    return audit.forAction("mail.server.imap.max_connections_refused").length >= 1;
  }, {
    timeoutMs: SETTLE_CEILING_MS,
    label:     "socket ceiling: the refusal reaches the audit trail",
  });

  var rows = audit.forAction("mail.server.imap.max_connections_refused");
  var ceilings = rows.map(function (row) { return metadataOf(row).maxConnections; });
  count("the listener records the refusal against the ceiling SECURITY.md publishes, " +
    DOCUMENTED_SOCKET_CEILING + " sockets, so a listener at capacity does not look like " +
    "an idle one",
    ceilings.length > 0 &&
      ceilings.every(function (n) { return n === DOCUMENTED_SOCKET_CEILING; }),
    rows.length + " row(s), ceilings " + JSON.stringify(ceilings));

  // A concurrency ceiling, not a lifetime budget. One socket goes back
  // and the next one in is greeted; a listener that had spent something
  // permanent would refuse it as well.
  //
  // The attempt is retried rather than made once. The runtime releases
  // the slot when it sees the socket close, which is after this side
  // stops using it, so a single attempt would be racing that release
  // instead of measuring what it wanted to.
  admitted[0].close();
  var replacement = await helpers.waitUntil(async function () {
    var attempt = await openWatched(port, "ceiling-replacement");
    if (greeted(attempt)) return attempt;
    await helpers.waitUntil(function () {
      return greeted(attempt) || attempt.closed;
    }, { timeoutMs: 2000, label: "socket ceiling: this attempt is answered" });
    if (greeted(attempt)) return attempt;
    attempt.close();
    return false;
  }, {
    timeoutMs: SETTLE_CEILING_MS,
    label:     "socket ceiling: a released slot is reusable",
  });

  count("closing one socket gives its slot back, so the ceiling bounds what is open at " +
    "once rather than what has ever been opened",
    greeted(replacement), visible(replacement.buf));

  admitted.forEach(function (session) { session.close(); });
  past.close();
  replacement.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("socketceiling");
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
  var audit    = null;

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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "socket ceiling test" });
    await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
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
        inbound:   { mode: "monitor" },
        limits:    {
          maxConcurrentConnectionsPerIp: PER_ADDRESS_CONCURRENT,
          connectionsPerIpPerMinute:     PER_ADDRESS_PER_MINUTE,
        },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    audit = auditCapture();

    await theListenerAcceptsExactlyTheCeilingAndClosesTheNext(sections.imap.port, audit);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // The audit store is process-wide, so it is handed back whatever
    // the verdict was.
    if (audit) {
      try { audit.release(); }
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

module.exports = { name: "listener-socket-ceiling", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
