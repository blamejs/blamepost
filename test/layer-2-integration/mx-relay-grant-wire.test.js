// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The relay allowlist, measured on the wire rather than in the
 * configuration.
 *
 * `relayAllowedFor` names source ranges the MX listener accepts a
 * recipient outside the hosted domains for. The framework's listener
 * honors it: a peer inside one of the ranges gets past the check that
 * answers everyone else `550 5.7.1 Relaying denied`, and its `RCPT TO`
 * for a stranger's domain is accepted with `250`. Nothing after that
 * can deliver the message. The delivery handoff resolves every
 * recipient against the hosted domains, an address elsewhere resolves to
 * nothing, and a message whose only recipient is that address is
 * answered `451` once the peer has sent all of it.
 *
 * `250` to a stranger's sender and `250` to a stranger's recipient is
 * the answer an open relay gives and the answer a scanner records. The
 * refusal that follows is a temporary code for a permanent condition, so
 * a well-behaved peer retries the same message forever and the operator
 * who configured the range believes the branch-office printer can send.
 *
 * This server refuses the setting at boot instead. The two cases below
 * are the wire consequence of that decision:
 *
 *   - A server configured to relay for the connecting peer's own network
 *     never gets an MX listener at all. The composition refuses, so
 *     there is no port answering and no `250` to record. The range is
 *     measured from the address that would have matched it, because a
 *     grant tested from outside its own range proves only that the range
 *     arithmetic works.
 *   - The listener that a server without the setting DOES bind refuses a
 *     recipient outside the hosted domains at RCPT, permanently, and
 *     never invites the peer to send. That is the guarantee the grant
 *     would have widened, and it is asserted here so that removing the
 *     grant cannot quietly remove the refusal with it.
 *
 * Both peers connect from loopback, which is the address the allowlisted
 * range names in the first case and names nowhere in the second. The
 * difference under test is the configuration, not the network position,
 * because after the refusal there is no configuration that gives any
 * network position a relay grant.
 *
 * Run standalone: node test/layer-2-integration/mx-relay-grant-wire.test.js
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

// The range that names the peer this test connects from. A relay grant
// measured from an address outside its own range proves nothing about
// the grant: every peer is refused there anyway.
var LOOPBACK_RANGE = [{ cidr: "127.0.0.0/8", scope: "the machine running this test" }];

// Neither is hosted here. A relay probe uses a sender and a recipient
// the server has no relationship with, which is what makes the answer to
// it the open-relay signature.
var STRANGER_SENDER    = "printer@branch.example.net";
var STRANGER_RECIPIENT = "someone@unrelated.example.org";

var count = helpers.count;

// ---- the fixture -----------------------------------------------------------

// One server over its own data directory and certificate. The caller
// decides whether a relay range is configured, because that is the whole
// variable across the two cases, and the fixture catches at BOTH
// construction and start: the relay refusal fires while the listeners
// are composed, which is inside `blamepost.create` and before anything
// binds.
async function withServer(label, relayAllowedFor, body) {
  var root    = helpers.tempDir("relay-wire-" + label);
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

    // The loader is deliberately not asked for the relay range. It
    // refuses one of its own accord, and this case is about the door
    // BESIDE the loader: a configuration object handed straight to the
    // composition, which is what every fixture here builds.
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "relay wire test" });
    await identity.accounts.create({ address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    var overrides = {
      httpPort:  0,
      listeners: sections,
      // The message authentication gate resolves SPF and DMARC against
      // live DNS at the end of DATA and this process has no resolver, so
      // enforce mode would defer on a lookup error and the case would be
      // measuring the absence of DNS rather than the relay decision.
      inbound:   { mode: "monitor" },
    };
    if (relayAllowedFor !== null) overrides.relayAllowedFor = relayAllowedFor;

    var buildError = null;
    var startError = null;
    try {
      server = blamepost.create({
        config:       Object.assign({}, cfg, overrides),
        store:        identity,
        mailStore:    identity.mailbox,
        messageStore: identity.messageStore,
        tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
        httpAddress:  LOOPBACK,
      });
    } catch (err) {
      buildError = err;
    }

    if (buildError === null) {
      try {
        await server.start();
        running = true;
      } catch (err) {
        startError = err;
      }
    }

    await body({
      server:     server,
      buildError: buildError,
      startError: startError,
      started:    running,
      caPem:      leaf.ca,
      mxPort:     sections.mx.port,
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
    // The store is a singleton, because the framework's database is. A
    // case that left it open would hand the next case the PREVIOUS
    // case's data directory, and the first thing that case does is add
    // the domain the last one already added. Closing here is what makes
    // the two cases independent rather than sequential.
    try { store.close(); }
    catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

// Whether anything is answering on the MX port, asked of the socket
// rather than of the server's own inventory. A listener left bound while
// the inventory forgot it is the same exposure with a tidier report.
async function somethingAnswersOn(port) {
  var session;
  try {
    session = await Wire.connect(port, "relay-port-probe");
  } catch (_e) {
    return false;
  }
  session.close();
  return true;
}

// ---- cases -----------------------------------------------------------------

// A server told to relay for the network the peer is on. The range names
// loopback, and loopback is where the session below would come from, so
// this is the configuration in which a relay grant is at its most live.
//
// The whole assertion is that it never becomes a listener. A grant that
// reaches the framework's listener is a `250` to a stranger's recipient,
// and no answer given after that can take it back.
async function aServerConfiguredToRelayNeverBindsTheListener() {
  await withServer("granted", LOOPBACK_RANGE, async function (ctx) {
    count("a configuration carrying a relay range is refused rather than composed",
      ctx.buildError !== null,
      ctx.buildError === null ? "the server was built" : visible(ctx.buildError.message));

    count("and the refusal names the setting the operator has to remove",
      ctx.buildError !== null &&
      String(ctx.buildError.message).indexOf("relayAllowedFor") !== -1,
      ctx.buildError === null ? "nothing was thrown" : visible(ctx.buildError.message));

    count("and points at authenticated submission for the device that needed it",
      ctx.buildError !== null && /submission/i.test(String(ctx.buildError.message)),
      ctx.buildError === null ? "nothing was thrown" : visible(ctx.buildError.message));

    // The refusal is only worth anything if nothing bound on the way to
    // it. A composition that threw after the MX listener was already
    // accepting connections is the exposure with an error message on top.
    var answering = await somethingAnswersOn(ctx.mxPort);
    count("nothing is accepting connections on the MX port",
      answering === false,
      answering ? "the port answered a TCP connection on " + ctx.mxPort : "connection refused");
  });
}

// The same server without the setting, which is the only shape it can
// now take. The listener binds, and the recipient the grant would have
// admitted is refused at RCPT with a permanent code, before the peer is
// invited to send anything.
//
// This is the guarantee the grant widened, so it is pinned here: a later
// change that removed the relay refusal by removing the hosted-domain
// check instead would pass every case above and fail this one.
async function theBoundListenerRefusesAStrangersRecipientAtRcpt() {
  await withServer("ungranted", null, async function (ctx) {
    count("a server with no relay range composes",
      ctx.buildError === null,
      ctx.buildError === null ? "built" : visible(ctx.buildError.message));
    count("and starts",
      ctx.startError === null,
      ctx.startError === null ? "started" : visible(ctx.startError.message));
    if (ctx.buildError !== null || ctx.startError !== null) return;

    var peer = await Wire.mx(ctx.mxPort, {
      caPem: ctx.caPem, servername: HOSTNAME, label: "relay-probe",
      helo: "branch.example.net",
    });

    peer.send("MAIL FROM:<" + STRANGER_SENDER + ">");
    var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");

    peer.send("RCPT TO:<" + STRANGER_RECIPIENT + ">");
    var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
    count("a recipient outside the hosted domains is refused at RCPT",
      /^550 /m.test(rcptReply), visible(rcptReply));
    count("the refusal is the relay one rather than a missing mailbox",
      /5\.7\.1/.test(rcptReply), visible(rcptReply));

    // A refused recipient leaves the transaction with none, so the peer
    // is never invited to send. The sender line is quoted alongside
    // because a `250` there and a `550` here is the pair that says the
    // refusal landed on the recipient rather than on the connection.
    peer.send("DATA");
    var dataReply = await peer.read(/^\d{3} /m, "DATA answered");
    count("the peer is never invited to send a message it has no recipient for",
      !/^354 /m.test(dataReply), visible(mailReply) + " then " + visible(dataReply));

    // And the hosted half still works, so the case above is a relay
    // refusal rather than a listener refusing everything.
    peer.send("RCPT TO:<alice@" + DOMAIN + ">");
    var localReply = await peer.read(/^\d{3} /m, "hosted RCPT answered");
    count("a recipient at a hosted domain is still accepted",
      /^250 /m.test(localReply), visible(localReply));

    peer.send("QUIT");
    peer.close();
  });
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await aServerConfiguredToRelayNeverBindsTheListener();
  await theBoundListenerRefusesAStrangersRecipientAtRcpt();
  return helpers.getChecks();
}

module.exports = { name: "mx-relay-grant-wire", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
