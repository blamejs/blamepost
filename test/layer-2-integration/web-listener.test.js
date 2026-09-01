// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The HTTP listener on a real port, driven with a real client.
 *
 * The container's own health check is an HTTP request to `/healthz` on
 * the cleartext port, and the compose file polls the same URL, so the
 * thing under test is the wire: a socket that accepts, a probe whose
 * verdict tracks the listeners and the store, a JMAP mount that answers
 * inside this application rather than on a port of its own, and a sign
 * in page that renders. A process that boots and never binds this port
 * is reported unhealthy thirty seconds later with no other symptom, so
 * the endpoint has to be exercised end to end rather than through the
 * probe controller alone.
 *
 * It needs no external service. The port is ephemeral on the loopback
 * interface and the data directory is temporary, so this file runs
 * wherever the integration layer runs.
 *
 * Run standalone: node test/layer-2-integration/web-listener.test.js
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var LOOPBACK = "127.0.0.1";

function baseEnv(dataDir) {
  return {
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
}

// The listener table the probe reads, held in a variable the test can
// change, so each state can prove what the verdict does with it.
//
// The reason there are three states rather than two is the whole of what
// this file checks about the probe. A listener that was supposed to bind
// and did not is a failure; a listener this server deliberately holds
// shut is not, and the two arrive at the same place, no port taken, by
// completely different routes. A table that carried one boolean would
// report a first boot with no domain hosted as a server that failed to
// come up.
var WITHHELD_REASON = "this server hosts no domain, so there is nothing to receive for";

var listenerTable = [
  { name: "mx", state: "unbound", reason: "the listener took no port" },
  { name: "imap", state: "bound", reason: null },
];

function setListenerState(name, state, reason) {
  listenerTable.forEach(function (row) {
    if (row.name !== name) return;
    row.state  = state;
    row.reason = reason === undefined ? null : reason;
  });
}

function wiringFor(cfg, identity, mailStore) {
  var deliveryHandle = blamepost.mail.delivery.create({
    hostname: cfg.hostname,
    dataDir:  cfg.dataDir,
  });
  var dkimHandle = blamepost.mail.dkim.create({
    dataDir: cfg.dataDir,
    store:   identity,
  });
  return {
    agent: b.mail.agent.create({ store: mailStore, dispatch: { mode: "local" } }),
    store:     identity,
    mailbox:   identity.mailbox,
    mailStore: mailStore,
    compose:   blamepost.mail.compose.create({
      delivery:  deliveryHandle,
      hostname:  cfg.hostname,
      dkim:      dkimHandle,
      mailStore: mailStore,
    }),
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    cfg,
    listeners: function () { return listenerTable; },
    address:   LOOPBACK,
    httpPort:  0,
  };
}

function urlFor(port, path) {
  return "http://" + LOOPBACK + ":" + port + path;
}

// Whether anything is still accepting on the port. Used after the drain,
// where the assertion is that the socket is gone rather than that some
// request failed for a reason of its own.
function accepts(port) {
  return new Promise(function (resolve) {
    var socket = nodeNet.connect({ host: LOOPBACK, port: port });
    socket.once("connect", function () { socket.destroy(); resolve(true); });
    socket.once("error", function () { resolve(false); });
  });
}

async function probe(port, path) {
  var res  = await fetch(urlFor(port, path));
  var body = await res.json();
  return { status: res.status, body: body, said: res.status + " " + JSON.stringify(body) };
}

// A listener that was supposed to bind and did not.
//
// Readiness refuses, because a load balancer sending mail traffic at a
// port nothing holds is the failure this probe exists to prevent.
// Liveness does not, and that is deliberate: a liveness probe failing
// tells an orchestrator to KILL the process, and no restart frees a port
// another process is holding. It restarts into the same failure with the
// reason gone from the logs, and the operator loses the running server
// they would otherwise have read it from.
async function testAListenerThatFailedToBind(port) {
  var live = await probe(port, "/healthz");
  count("a listener that did not bind leaves the process answering its liveness probe, " +
    "because killing it would not free the port and would take the surface that " +
    "explains the failure down with it",
    live.status === 200, live.said);
  count("and liveness says the server is not fully fit rather than saying it is fine",
    live.body.status === "degraded", live.said);

  var ready = await probe(port, "/readyz");
  count("readiness refuses while a listener that was supposed to bind has not, so " +
    "nothing routes traffic at a port that is not being held",
    ready.status === 503, ready.said);
  count("and the refusal says the process cannot serve",
    ready.body.status === "fail", ready.said);
  count("the listener that did not bind is named in the refusal",
    (ready.body.checks.listeners.unbound || []).indexOf("mx") !== -1,
    JSON.stringify(ready.body.checks.listeners));
}

// The same absent port, arrived at deliberately.
//
// Nothing about this is a failure, so nothing here refuses. It is still
// a reason mail is not arriving, so nothing here reports the server
// simply fit either: the answer is the reduced one, on both probes, with
// the reason attached.
async function testAListenerHeldShutOnPurpose(port) {
  setListenerState("mx", "withheld", WITHHELD_REASON);

  var live = await probe(port, "/healthz");
  count("a listener held shut on purpose does not fail liveness",
    live.status === 200, live.said);
  count("and liveness reports the server serving with something held back, so a monitor " +
    "is not told everything is fine while the port is shut",
    live.body.status === "degraded", live.said);

  var ready = await probe(port, "/readyz");
  count("readiness keeps routing traffic here, because every listener that was supposed " +
    "to bind did and the browser surface is the one an operator needs next",
    ready.status === 200, ready.said);
  count("and readiness gives the same reduced verdict rather than a clean one",
    ready.body.status === "degraded", ready.said);
  count("the critical listener verdict stays clean, so the refusing state is still " +
    "available to mean a listener that failed",
    ready.body.checks.listeners.ok === true,
    JSON.stringify(ready.body.checks.listeners));

  var held = ready.body.checks["listeners-withheld"].withheld || [];
  count("the listener being held is named with the reason it is being held, so the " +
    "answer is something an operator can act on",
    held.length === 1 && held[0].name === "mx" && held[0].reason === WITHHELD_REASON,
    JSON.stringify(held));
}

// A listener the configuration does not enable is neither of the above.
// It appears in the inventory so that reading the probe answers the
// question rather than leaving the reader to notice an absence, and it
// counts against nothing, because a listener nobody asked for cannot
// fail to arrive.
async function testAListenerTheConfigurationDoesNotEnable(port) {
  setListenerState("mx", "bound", null);
  listenerTable.push({ name: "pop3", state: "disabled", reason: "not enabled here" });

  var live = await probe(port, "/healthz");
  count("a listener the configuration does not enable leaves the verdict clean",
    live.status === 200 && live.body.status === "ok", live.said);
  count("and it is still reported, so the probe answers what happened to it rather than " +
    "leaving it out of the inventory altogether",
    (live.body.checks.listeners.disabled || []).indexOf("pop3") !== -1,
    JSON.stringify(live.body.checks.listeners));

  var ready = await probe(port, "/readyz");
  count("readiness reports the process fit to serve", ready.body.status === "ok", ready.said);
  count("every listener that was supposed to bind is counted as bound",
    ready.body.checks.listeners.bound === 2, JSON.stringify(ready.body.checks.listeners));

  // This listener was given no certificate, which is the shape behind a
  // proxy that terminates TLS and holds the only copy of the key. The
  // certificate check still answers, and it answers that there was
  // nothing on disk to read rather than being absent: an absent check is
  // also what a certificate check that failed to register looks like, and
  // the two would be indistinguishable from here.
  count("a server that terminates no TLS of its own still answers the certificate check, " +
    "and says it read nothing rather than leaving the reader to notice an absence",
    ready.body.checks.certificate !== undefined &&
    ready.body.checks.certificate.ok === true &&
    ready.body.checks.certificate.read === false,
    JSON.stringify(ready.body.checks.certificate));
}

// The detail above is answered to this client because it arrives over
// the loopback interface, which is where the container's own health
// check runs. A table this application cannot classify is a different
// matter: it refuses rather than reading an unrecognized row as one more
// listener that is fine.
async function testAnUnreadableTableRefuses(port) {
  var held = listenerTable.slice();
  listenerTable.push({ name: "invented", state: "probably-fine", reason: null });
  try {
    var ready = await probe(port, "/readyz");
    count("a listener state this application does not recognize refuses rather than " +
      "passing, because a row nobody can classify is not a row that is known to be up",
      ready.status === 503 && ready.body.status === "fail", ready.said);
  } finally {
    listenerTable.length = 0;
    held.forEach(function (row) { listenerTable.push(row); });
  }
}

async function testProbeTracksTheListeners(port) {
  await testAListenerThatFailedToBind(port);
  await testAListenerHeldShutOnPurpose(port);
  await testAListenerTheConfigurationDoesNotEnable(port);
  await testAnUnreadableTableRefuses(port);
}

async function testTheBrowserSurfaceIsMounted(port) {
  var signIn = await fetch(urlFor(port, "/sign-in"));
  count("the sign in page renders over the wire", signIn.status === 200, signIn.status);
  var signInBody = await signIn.text();
  check("the rendered page is a complete document produced on the server",
    signInBody.indexOf("<form") !== -1 && signInBody.indexOf("</html>") !== -1);

  var missing = await fetch(urlFor(port, "/there-is-no-such-page"));
  count("an unknown path gets this application's own refusal",
    missing.status === 404, missing.status);
}

async function testJmapIsMountedInsideTheApplication(port) {
  var discovery = await fetch(urlFor(port, "/.well-known/jmap"), { redirect: "manual" });
  count("JMAP autodiscovery answers on the same port as webmail",
    discovery.status !== 404, discovery.status);

  var session = await fetch(urlFor(port, "/jmap/session"), { redirect: "manual" });
  count("the JMAP session endpoint is mounted and refuses an unauthenticated caller",
    session.status !== 404 && session.status !== 200, session.status);
}

async function testWellKnownDocuments(port) {
  var policy = await fetch(urlFor(port, "/.well-known/mta-sts.txt"));
  count("the MTA-STS policy is served from this application",
    policy.status === 200, policy.status);
  var policyBody = await policy.text();
  count("the policy carries the enforcing mode and this server's name",
    policyBody.indexOf("version: STSv1") === 0 &&
    policyBody.indexOf("mode: enforce") !== -1 &&
    policyBody.indexOf("mx: mx.example.com") !== -1,
    JSON.stringify(policyBody));

  var securityTxt = await fetch(urlFor(port, "/.well-known/security.txt"));
  count("the disclosure contact is published", securityTxt.status === 200, securityTxt.status);
}

async function testDrain(listener, port) {
  var closed = await listener.stop({ timeoutMs: 2000 });
  count("the drain reports the cleartext listener closed",
    closed.closed.indexOf("http") !== -1, JSON.stringify(closed));
  check("the port stops accepting once the drain finishes",
    (await accepts(port)) === false);
  check("the listener holds no port after the drain",
    Object.keys(listener.bound()).length === 0);

  // Readiness is refused from the moment a drain begins and there is no
  // way back, so taking the port again would serve traffic behind a
  // probe that goes on saying the process cannot.
  var restarted = null;
  try { await listener.start(); } catch (e) { restarted = e; }
  count("a drained listener refuses to take its port back",
    restarted !== null && /already been drained/.test(String(restarted.message)),
    restarted === null ? "start resolved" : restarted.message);
  check("the refusal leaves the port closed",
    (await accepts(port)) === false);
}

async function run() {
  var root = helpers.tempDir("weblistener");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var listener = null;
  try {
    var cfg = config.load({ env: baseEnv(dataDir), cwd: root });
    var identity = await store.open(cfg);
    // On the framework database itself, the way the facade builds it.
    var mailStore = b.mailStore.create({ backend: b.db });

    listener = blamepost.web.serve(wiringFor(cfg, identity, mailStore));
    var ports = await listener.start();
    count("blamepost.web.serve.start reports the port it actually took",
      typeof ports.http === "number" && ports.http > 0, JSON.stringify(ports));
    check("the port is accepting connections", (await accepts(ports.http)) === true);

    await testProbeTracksTheListeners(ports.http);
    await testTheBrowserSurfaceIsMounted(ports.http);
    await testJmapIsMountedInsideTheApplication(ports.http);
    await testWellKnownDocuments(ports.http);
    await testDrain(listener, ports.http);
    listener = null;
  } finally {
    if (listener !== null) {
      try { await listener.stop({ timeoutMs: 2000 }); }
      catch (_e) { /* the assertion that failed is the result, not this */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "web-listener", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
