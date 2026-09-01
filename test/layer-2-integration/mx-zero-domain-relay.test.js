// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A server that hosts no domain does not bind port 25.
 *
 * The framework's MX listener refuses a recipient outside the hosted
 * set at RCPT with `550 5.7.1 Relaying denied`, and it applies that
 * check whatever the set holds. An empty one is expressible, and a
 * listener built over it refuses every recipient rather than accepting
 * them, so there is no arrangement here where a relay probe is answered
 * `250`.
 *
 * What this file pins is the choice made on top of that, and the choice
 * turns on what a sender does next. A permanent refusal at RCPT tells a
 * peer the address does not exist here, which it reports back to its own
 * sender instead of retrying. During the window between an MX record
 * going live and the first domain being added, an operator's arriving
 * mail would be bounced rather than held. A port that is not listening
 * is a connection refused, which senders treat as temporary and retry
 * against, so the same mail arrives once the domain exists. Nothing is
 * lost by staying shut, since with no hosted domain there is no mailbox
 * for any address either way.
 *
 * So the moment to refuse is the bind, alongside the DNS posture gate
 * that already keeps port 25 shut until the records are live.
 *
 * The three cases below pin the whole shape: the refusal to bind, the
 * listeners that must still come up without a domain so a first boot is
 * possible, and the relay refusal itself once a domain exists, which is
 * the behavior the bind gate stands in front of.
 *
 * Run standalone: node test/layer-2-integration/mx-zero-domain-relay.test.js
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

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Neither of these is hosted here in any case below. A relay probe uses
// a sender and a recipient the server has no relationship with, which is
// what makes the answer to it the open-relay signature.
var STRANGER_SENDER    = "attacker@evil.example.net";
var STRANGER_RECIPIENT = "victim@unrelated.example.org";

var count = helpers.count;

// ---- the fixture -----------------------------------------------------------

// One server, built over its own data directory and certificate. The
// caller decides whether a domain is hosted and which listeners are
// asked for, because those two are the whole variable across the cases.
async function withServer(label, opts, body) {
  var root    = helpers.tempDir("zero-domain-" + label);
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // directory it reads from this variable. Pointing it inside the test's
  // own tree keeps the encrypted at rest path exactly as it ships.
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
      // The classical bridge rather than the CA default: this
      // certificate exists so a node:tls handshake happens on loopback,
      // and node verifies this algorithm on every runtime the suite runs.
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
        // The server wide half of the DNS posture gate. Set in every
        // case so the gate under test is the domain one rather than
        // this one, which has its own coverage elsewhere.
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    // Given back before the directory under it goes, whichever way this
    // run ends. A database handle still open while its files are removed
    // is a locked file on Windows and a teardown rejection on Linux, and
    // either one lands on top of the verdict this run had already
    // reached. This file opens one per case, so the registration is per
    // directory too.
    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    var address = null;
    if (opts.hostDomain === true) {
      await identity.domains.add({ domain: DOMAIN });
      await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "zero domain test" });
      var alice = await identity.accounts.create({
        address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
      address = alice.address;
    }

    var sections = {
      mx:          { enabled: opts.mx !== false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false,             port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false,             port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: opts.imap === true, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false,             port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false,             port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        // The message authentication gate resolves SPF and DMARC against
        // live DNS at the end of DATA and this process has no resolver,
        // so enforce mode would defer on a lookup error and the case
        // would be measuring the absence of DNS. What that gate does
        // with a real answer belongs to a case that can give it one.
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });

    var startError = null;
    try {
      await server.start();
      running = true;
    } catch (err) {
      startError = err;
    }

    await body({
      server:     server,
      startError: startError,
      started:    running,
      caPem:      leaf.ca,
      ports:      { mx: sections.mx.port, imap: sections.imap.port },
      address:    address,
    });

    if (running) {
      await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
      running = false;
    }
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

// ---- cases -----------------------------------------------------------------

// With nothing hosted, the MX listener has no recipient it could ever
// accept, and the relay check the framework would apply is unreachable
// because there is no hosted set to compare against. Binding anyway
// puts a listener on port 25 whose only possible answers are a `250` to
// a stranger's recipient and a `451` afterwards.
async function anMxListenerWithNoHostedDomainRefusesToBind() {
  await withServer("no-domain", { hostDomain: false, mx: true }, async function (ctx) {
    // The rest of the server has to come up. An operator reaches the
    // first domain through `blamepost init`, which opens the data
    // directory directly, and taking the browser surface down for the
    // duration would make the first boot look like a broken one.
    count("a server hosting no domain still starts", ctx.startError === null,
      ctx.startError === null ? "started" : visible(ctx.startError.message));
    if (ctx.startError !== null) return;

    // The listener that cannot do its job is absent rather than bound.
    // This is the whole of the finding: an MX listener with nothing
    // hosted answers `250` to a stranger's sender and a stranger's
    // recipient, which is the open-relay signature a scanner records,
    // and only refuses once the peer has sent the entire message.
    var bound = ctx.server.mail.listeners.bound();
    count("the MX listener is not among the bound listeners",
      bound.mx === undefined, JSON.stringify(bound));

    // Asked of the socket rather than of the inventory, because a
    // listener left bound while the inventory forgot it is the same
    // exposure with a tidier report.
    var reached = true;
    var session = null;
    try {
      session = await Wire.connect(ctx.ports.mx, "mx-after-refusal");
    } catch (_e) {
      reached = false;
    }
    if (session) session.close();
    count("nothing accepts a connection on the MX port", reached === false,
      reached ? "the port answered a TCP connection on " + ctx.ports.mx : "connection refused");
  });
}

// The first boot has no domain in it: an operator runs `blamepost init`
// against the data directory to create the first one, and `init` opens
// the store directly rather than talking to a running server. A gate
// that refused the whole boot would still leave that path open, but it
// would take the mailbox listeners down with it for no reason, so the
// refusal is scoped to the listener that cannot work.
async function theOtherListenersStillComeUpWithNoHostedDomain() {
  await withServer("no-domain-mx-off", { hostDomain: false, mx: false, imap: true },
    async function (ctx) {
      count("a server hosting no domain still starts when the MX listener is off",
        ctx.startError === null,
        ctx.startError === null ? "started" : visible(ctx.startError.message));

      if (ctx.startError !== null) return;
      var session = await Wire.connect(ctx.ports.imap, "imap-no-domain");
      var greeting = await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
      count("the IMAP listener answers on a server with no hosted domain",
        /^\* OK \[CAPABILITY/.test(greeting), visible(greeting));
      session.close();
    });
}

// The behavior the bind gate exists to protect. Once a domain is
// hosted the framework's relay check is reachable, and a recipient
// outside the hosted set is refused at RCPT with a permanent code,
// before the peer is ever invited to send the message.
async function aRelayProbeIsRefusedAtRcptOnceADomainIsHosted() {
  await withServer("hosted", { hostDomain: true, mx: true }, async function (ctx) {
    count("a server with a hosted domain starts", ctx.startError === null,
      ctx.startError === null ? "started" : visible(ctx.startError.message));
    if (ctx.startError !== null) return;

    var peer = await Wire.mx(ctx.ports.mx, {
      caPem: ctx.caPem, servername: HOSTNAME, label: "relay-probe",
      helo: "scanner.example.net",
    });

    peer.send("MAIL FROM:<" + STRANGER_SENDER + ">");
    var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");

    peer.send("RCPT TO:<" + STRANGER_RECIPIENT + ">");
    var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
    count("a recipient outside the hosted set is refused at RCPT",
      /^550 /m.test(rcptReply), visible(rcptReply));
    count("the relay refusal carries the RFC 3463 code for it",
      /5\.7\.1/.test(rcptReply), visible(rcptReply));

    // A refused recipient leaves the transaction with none, so DATA has
    // nothing to carry and the peer is never invited to send. The
    // sender line is quoted alongside because a `250` there and a `550`
    // here is the pair that says the refusal landed on the recipient
    // rather than on the connection.
    peer.send("DATA");
    var dataReply = await peer.read(/^\d{3} /m, "DATA answered");
    count("the peer is never invited to send a message it has no recipient for",
      !/^354 /m.test(dataReply), visible(mailReply) + " then " + visible(dataReply));

    peer.send("QUIT");
    peer.close();
  });
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await anMxListenerWithNoHostedDomainRefusesToBind();
  await theOtherListenersStillComeUpWithNoHostedDomain();
  await aRelayProbeIsRefusedAtRcptOnceADomainIsHosted();
  return helpers.getChecks();
}

module.exports = { name: "mx-zero-domain-relay", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
