// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What happens to a running server when its certificate is renewed.
 *
 * This is the one certificate event every deployment has. blamepost
 * issues nothing: `tlsCert` and `tlsKey` name files an operator's
 * certificate client writes, and every sixty to ninety days that client
 * rewrites both of them underneath a process that is already serving.
 * Nothing about that moment is exceptional, and everything about it is
 * invisible: the renewal succeeds, the files on disk are correct, and
 * whether the listeners present the new chain or go on presenting the
 * old one cannot be read from anything the operator can see. A server
 * still holding the expired chain answers its own health probe, reports
 * every listener bound, and fails every handshake a sending MTA offers,
 * which is a total inbound outage that starts on a schedule and
 * announces itself only as other people's bounces.
 *
 * So the case is the renewal itself, on real ports, driven by real
 * protocol clients:
 *
 *   - Every listener is opened before the rotation and verified against
 *     the authority that issued the material on disk. Verification
 *     stays on throughout. A client that skipped it would pass against
 *     a listener presenting anything at all, which is the whole
 *     question here.
 *   - The pair is then rewritten at the same two paths under a
 *     DIFFERENT private authority, which is what makes the reading
 *     unambiguous: the new chain does not verify against the old
 *     authority and the old chain does not verify against the new one,
 *     so "which certificate is this listener presenting" is answered by
 *     whether the handshake completes rather than by an assertion about
 *     an object this test reached into.
 *   - Every listener is opened again and has to present the renewed
 *     chain, and has to stop presenting the one it booted with. The
 *     serial numbers are read alongside, so a failure says which
 *     certificate was actually served rather than only that a handshake
 *     did not complete.
 *
 * Every port is held to that, with no exception. ManageSieve on 4190 was
 * one for a while: the framework's listener read its certificate option
 * once at construction, so a renewal reached the other ports and not it,
 * and the server named the port on every reload. It reads the option per
 * connection now, so the exception is gone and the check that carried it
 * is the ordinary one.
 *
 * Every wire protocol is driven rather than one, and the browser surface
 * is driven with them. The listeners take their certificate through a
 * shared composition, so a rotation that reaches one and misses another
 * is a divergence no single-protocol case can see, and a partially
 * rotated server is the worst of the available states: the operator's
 * own client confirms the new certificate on the port they checked while
 * a different port is still failing. The TLS port of the browser surface
 * is the one an operator is most likely to check by hand, which is
 * exactly why it is driven here rather than assumed.
 *
 * A rotation must also not quietly change anything about the connection
 * other than the certificate. A replacement context is built from
 * whatever options it is handed, so a rotation that names the material
 * and nothing else can reset the transport floor underneath a listener
 * that was refusing everything below TLS 1.3 a moment earlier. That is
 * invisible from the certificate, so it is measured with a client that
 * will not speak above TLS 1.2 and has to be refused.
 *
 * The last part of the file is what the readiness probe says about the
 * certificate, over the endpoint a load balancer actually polls. A
 * renewal that stopped running is the slowest outage this server has:
 * nothing changes for weeks, and then every peer stops talking to it at
 * once. A probe that answers only about ports and the store reports
 * perfect health for the whole of that. So the probe reads the pair on
 * disk and reduces its verdict while there is still time to act, and it
 * does NOT refuse: a certificate with days left is a server carrying
 * mail for every peer today, and a probe that took it out of rotation
 * early would cause the outage it was watching for.
 *
 * The configuration names FILES. Passing a pre-built context is the
 * other supported shape and it is the one that cannot rotate at all,
 * because nothing behind it is watching a path, so a case written that
 * way would be measuring the configuration in which this cannot fail.
 *
 * Run standalone: node test/layer-2-integration/tls-certificate-renewal.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var certs     = require("../helpers/certs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var LOOPBACK    = wire.LOOPBACK;

var check = helpers.check;
var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The floor the framework accepts, which is also the fastest this case
// can ask for. The interval an operator runs is the framework's default
// and is not what this case is about: what it is about is that the
// rotation arrives at the listeners at all.
var POLL_MS = 1000;

// The budget the rotation gets to reach every listener. Generously
// above the poll interval, because the reading that matters is whether
// the new chain EVER arrives, not how quickly.
var ROTATION_BUDGET_MS = 15000;

// ---- reading what a listener is actually presenting -------------------------

// A verifying session on each listener, in the shape a real client of
// that protocol opens. Returns the session so the caller can close it;
// throws when the chain does not verify against the authority given,
// which is the assertion.
var LADDERS = {
  mx: function (port, caPem) {
    return Wire.mx(port, { caPem: caPem, servername: HOSTNAME, label: "mx" });
  },
  submission: function (port, caPem) {
    return Wire.submission(port, { caPem: caPem, servername: HOSTNAME, label: "submission" });
  },
  imap: function (port, caPem) {
    return Wire.imap(port, { caPem: caPem, servername: HOSTNAME, label: "imap" });
  },
  pop3: function (port, caPem) {
    return Wire.pop3(port, { caPem: caPem, servername: HOSTNAME, label: "pop3" });
  },
  managesieve: function (port, caPem) {
    return Wire.managesieve(port, { caPem: caPem, servername: HOSTNAME, label: "managesieve" });
  },
};

// The two implicit-TLS ports have no ladder, because there is no
// plaintext phase to ladder through: the handshake IS the connection.
// Submission on 465 and the browser surface's TLS port are the same
// shape of client, so they are the same function: two spellings of one
// verifying handshake would eventually disagree about what verifying
// means, and the disagreement would look like a certificate fault.
//
// `pinVersion` caps the client at one protocol version, which is how the
// transport floor is read. A server holding the floor answers a client
// that will not come above TLS 1.2 with a protocol-version alert, and
// that alert can only come from the server, so it separates a listener
// that refused from a client that never offered.
function directTlsSession(port, caPem, pinVersion) {
  return new Promise(function (resolve, reject) {
    var connectOpts = {
      host: LOOPBACK, port: port, servername: HOSTNAME, ca: caPem,
    };
    if (pinVersion !== undefined) {
      connectOpts.minVersion = pinVersion;
      connectOpts.maxVersion = pinVersion;
    }
    var socket = nodeTls.connect(connectOpts, function () {
      resolve({ socket: socket, close: function () { socket.destroy(); } });
    });
    socket.once("error", reject);
    socket.setTimeout(wire.WIRE_TIMEOUT_MS, function () {
      socket.destroy();
      reject(new Error("implicit-TLS handshake timed out"));
    });
  });
}

function sessionOn(name, port, caPem) {
  return (name === "submissions" || name === "https")
    ? directTlsSession(port, caPem)
    : LADDERS[name](port, caPem);
}

// What a listener answers a client pinned below the transport floor.
// Returns the refusal, or null when the handshake completed, which is
// the failure this reads for.
async function refusalBelowTheFloor(port, caPem) {
  var session = null;
  try {
    session = await directTlsSession(port, caPem, "TLSv1.2");
    return null;
  } catch (err) {
    return (err && (err.code || err.message)) || String(err);
  } finally {
    if (session && typeof session.close === "function") {
      try { session.close(); } catch (_e) { /* the reading is already taken */ }
    }
  }
}

// Whether a verifying session against `caPem` completes on this port.
// Used both as an assertion and as a waitUntil predicate, so it answers
// with a boolean rather than throwing.
async function verifiesAgainst(name, port, caPem) {
  var session = null;
  try {
    session = await sessionOn(name, port, caPem);
    return true;
  } catch (_e) {
    return false;
  } finally {
    if (session && typeof session.close === "function") {
      try { session.close(); } catch (_e2) { /* the verdict is already decided */ }
    }
  }
}

// The serial of the certificate a listener actually presented, taken off
// a session that completed. Every one of these ports except the implicit
// TLS one reaches its handshake through a protocol negotiation, so this
// goes through the same ladder rather than opening a bare TLS socket:
// a direct connect to a listener expecting a greeting first reports an
// OpenSSL record error, which says nothing at all about the certificate.
//
// Read for the failure message rather than for a verdict. Naming the
// serial that was served turns "the handshake did not verify" into "this
// listener is still presenting the certificate from before the renewal".
async function servedSerial(name, port, caPem) {
  var session = null;
  try {
    session = await sessionOn(name, port, caPem);
    var socket = session.socket || session.tlsSocket;
    if (!socket || typeof socket.getPeerCertificate !== "function") return "(not readable)";
    var peer = socket.getPeerCertificate(false);
    return peer && peer.serialNumber ? peer.serialNumber : "(none)";
  } catch (err) {
    return "(no verifying session: " + ((err && err.message) || String(err)).slice(0, 80) + ")";
  } finally {
    if (session && typeof session.close === "function") {
      try { session.close(); } catch (_e) { /* the reading is already taken */ }
    }
  }
}

// ---- the case ---------------------------------------------------------------

async function everyListenerPresentsTheRenewedCertificate(server, ports, boot, renewed) {
  var i;
  var name;

  // Which ports this server SAYS a renewal will not reach. Read from the
  // server rather than restated here, because the whole value of the
  // statement is that it matches what the ports actually do, and a
  // second copy of the list in this file could agree with neither.
  var stale = server.describe().certificate.staleAfterRotation;
  var rotates = ["mx", "submission", "submissions", "imap", "pop3", "managesieve", "https"];
  var all = rotates.slice();

  count("the server names no port a renewal fails to reach, because every one of them " +
    "takes the new certificate while this process runs",
    stale.length === 0, JSON.stringify(stale));
  count("the browser surface is not among them: it holds the same certificate handle the " +
    "mail listeners do and installs the renewed pair on the running server",
    stale.indexOf("https") === -1, JSON.stringify(stale));
  rotates.forEach(function (n) {
    check(n + " is not named as stale, because a renewal reaches it while this process runs",
      stale.indexOf(n) === -1);
  });

  // Before the rotation: the material on disk is what is being served,
  // and it verifies.
  var bootSerials = {};
  for (i = 0; i < all.length; i += 1) {
    name = all[i];
    check(name + " presents the certificate that was on disk at boot",
      (await verifiesAgainst(name, ports[name], boot.caPem)) === true);
    bootSerials[name] = await servedSerial(name, ports[name], boot.caPem);
  }

  // The renewal. A certificate client rewrites both paths in place;
  // nothing signals the process.
  nodeFs.writeFileSync(boot.certFile, renewed.chain, "utf8");
  nodeFs.writeFileSync(boot.keyFile, renewed.key, "utf8");

  // One listener is polled to the budget, because the rotation reaches
  // every listener that takes one through the same load. The rest are
  // then read immediately: a rotation that arrived at one and not
  // another is the divergence worth naming, and waiting separately on
  // each would hide it behind five budgets.
  await helpers.waitUntil(function () {
    return verifiesAgainst("submission", ports.submission, renewed.caPem);
  }, {
    timeoutMs: ROTATION_BUDGET_MS,
    label:     "certificate renewal: the submission listener presents the renewed chain",
  });

  for (i = 0; i < rotates.length; i += 1) {
    name = rotates[i];
    var nowServing = await servedSerial(name, ports[name], renewed.caPem);
    check(name + " presents the RENEWED certificate after the files were rewritten " +
      "(was serial " + bootSerials[name] + ", now serving " + nowServing + ")",
      (await verifiesAgainst(name, ports[name], renewed.caPem)) === true);
    check(name + " no longer presents the certificate it booted with",
      (await verifiesAgainst(name, ports[name], boot.caPem)) === false);
  }

  // ManageSieve is in the loop above rather than held apart below it,
  // and that is the whole of what changed here.
  //
  // The framework's ManageSieve listener used to copy its certificate
  // option into a local when it was constructed and read the copy at
  // every STARTTLS afterwards, so no rotation could reach it while the
  // process ran. This file carried a pair of checks asserting exactly
  // that, in both directions, so the day the listener started reading its
  // option per connection the assertion would fail and say so. It does
  // now, so the port takes the ordinary treatment: it has to present the
  // renewed chain and has to stop presenting the one it booted with, on
  // the same terms as its four siblings. There is no separate case left
  // to write, because there is no longer anything separate about it.

  // What the rotation must NOT have changed.
  //
  // Installing a certificate on a running TLS server means building a
  // replacement context, and a context is built from the options it is
  // handed rather than from the ones the listener bound with. A rotation
  // that names the material alone can therefore hand back a listener that
  // is presenting the right certificate and accepting a protocol version
  // it refused an hour earlier, which no certificate check can see. The
  // reading is a client that will not come above TLS 1.2: it has to be
  // refused, and refused by the SERVER, which is what a protocol-version
  // alert says and a client-side refusal does not.
  var floor = await refusalBelowTheFloor(ports.https, renewed.caPem);
  check("the rotated browser port still refuses a client pinned below the transport floor, " +
    "so the renewal replaced the certificate and left the floor where it was " +
    "(answered " + floor + ")",
    floor !== null && /PROTOCOL_VERSION|protocol version|wrong version|unsupported protocol/i
      .test(String(floor)));

  await whatHoldsTheFloorAfterARotation(ports.https, renewed.caPem);
}

// What the rotation cleared, what it did not, and which of the two the
// floor above is actually standing on.
//
// Installing a certificate on a running node:tls server means building a
// replacement context out of the options object handed to
// `setSecureContext`, and this server hands it the material alone. Node
// reads a fixed list of context settings off that object and writes
// `undefined` for each one it does not find there, so a rotation named
// `{cert, key}` silently clears the protocol floor, the cipher list, the
// curve preference and the certificate-compression list that the bind was
// given. The check above says the floor is still there; it cannot say why.
//
// It is there because the framework moves the process-wide default to
// TLS 1.3 before anything binds, so the setting the rotation cleared falls
// back to a value that already is the posture. Node's own default is
// TLS 1.2, and on that default this port would answer a rotated
// certificate over a protocol version it refused an hour earlier, with
// every certificate check still passing.
//
// So the floor rests on one mechanism, in a file this repository does not
// own, and nothing at the call site names it. That is pinned here rather
// than left implicit: the day the default moves, this says so, instead of
// the port quietly dropping a version and no certificate check noticing.
//
// The rest are the attacks that did not land, kept because an attack
// nobody wrote down is one nobody re-runs.
async function whatHoldsTheFloorAfterARotation(httpsPort, caPem) {
  count("the process-wide default protocol floor is TLS 1.3, which is what the rotated " +
    "port falls back to once the rotation has cleared the floor it bound with " +
    "(reads " + nodeTls.DEFAULT_MIN_VERSION + ")",
    nodeTls.DEFAULT_MIN_VERSION === "TLSv1.3", String(nodeTls.DEFAULT_MIN_VERSION));

  // A client that will not come above TLS 1.1, which is further below the
  // floor than the check above reaches. A rotation that reverted the
  // floor to a runtime default rather than clearing it outright would
  // still refuse 1.2 on some runtimes and admit this.
  var older = await refusalBelowTheFloor11(httpsPort, caPem);
  check("and a client pinned below that again is refused as well, so the floor is a floor " +
    "rather than one version being singled out (answered " + older + ")",
    older !== null);

  // Protocol negotiation has to survive the rotation too. The bind hands
  // the listener an ALPN list, and a context rebuilt from material alone
  // is a place that list could have been dropped: a browser would fall
  // back to HTTP/1.1 and nothing would report it.
  var negotiated = await alpnAfterRotation(httpsPort, caPem);
  count("the rotated port still negotiates HTTP/2 over ALPN, so the rotation replaced the " +
    "certificate without costing the protocol the bind advertised " +
    "(negotiated " + negotiated + ")",
    negotiated === "h2", String(negotiated));
}

// The same reading as refusalBelowTheFloor, one version lower.
async function refusalBelowTheFloor11(port, caPem) {
  var session = null;
  try {
    session = await directTlsSession(port, caPem, "TLSv1.1");
    return null;
  } catch (err) {
    return (err && (err.code || err.message)) || String(err);
  } finally {
    if (session && typeof session.close === "function") {
      try { session.close(); } catch (_e) { /* the reading is already taken */ }
    }
  }
}

// Which application protocol the rotated port agrees to speak.
function alpnAfterRotation(port, caPem) {
  return new Promise(function (resolve) {
    var socket = nodeTls.connect({
      host: LOOPBACK, port: port, servername: HOSTNAME, ca: caPem,
      ALPNProtocols: ["h2", "http/1.1"],
    }, function () {
      var chosen = socket.alpnProtocol;
      socket.destroy();
      resolve(chosen);
    });
    socket.once("error", function (e) {
      socket.destroy();
      resolve("(no session: " + ((e && e.code) || e) + ")");
    });
    socket.setTimeout(wire.WIRE_TIMEOUT_MS, function () {
      socket.destroy();
      resolve("(timed out)");
    });
  });
}

// ---- what the readiness probe says about the certificate --------------------

async function readiness(port) {
  var res  = await fetch("http://" + LOOPBACK + ":" + port + "/readyz");
  var body = await res.json();
  return { status: res.status, body: body, said: res.status + " " + JSON.stringify(body) };
}

// A certificate with most of its life left. The probe has to answer
// about it at all, because a probe that reports only ports and the store
// calls a server whose renewal died three weeks ago perfectly healthy.
// The answer also has to be clean here, or the reduced verdict means
// nothing when it arrives.
async function theProbeReadsAHealthyCertificate(httpPort) {
  var fit = await readiness(httpPort);
  count("the readiness probe reports the certificate this server would present, rather " +
    "than answering only about ports and the store",
    fit.body.checks !== undefined && fit.body.checks.certificate !== undefined, fit.said);
  count("a certificate with most of its life left leaves the verdict clean",
    fit.status === 200 && fit.body.status === "ok", fit.said);
  count("and the probe says it read the pair and found one this server can present",
    fit.body.checks.certificate.read === true &&
    fit.body.checks.certificate.ok === true &&
    fit.body.checks.certificate.usable === true &&
    fit.body.checks.certificate.faults.length === 0,
    JSON.stringify(fit.body.checks.certificate));
}

// The same probe against a certificate a renewal client should already
// have replaced. Reduced, not refused: this server is carrying mail for
// every peer today, and a readiness probe that refused would take it out
// of rotation days before anything was actually wrong.
async function theProbeReducesInsideTheRenewalWindow(httpPort) {
  var near = await readiness(httpPort);
  count("a certificate inside the renewal window reduces the verdict rather than refusing " +
    "traffic, because every peer is being served today and taking the server out of " +
    "rotation now would cause the outage the probe is watching for",
    near.status === 200 && near.body.status === "degraded", near.said);
  count("and the reduced verdict names the certificate and how many days are left on it",
    near.body.checks.certificate.ok === false &&
    near.body.checks.certificate.usable === true &&
    near.body.checks.certificate.expiresInDays === 0 &&
    near.body.checks.certificate.faults.indexOf("certificate validity") !== -1,
    JSON.stringify(near.body.checks.certificate));
}

// A pair on disk this server could not present at all.
//
// A renewal that wrote one half of the pair produces exactly this, and
// so does a certificate that has run out: both are readable files that
// no listener could build a context from. The verdict is the same one,
// and deliberately so. A process already running has the working
// certificate it started with in memory and is still serving every peer
// with it, `blamepost.create` refuses to boot on a pair like this, so a
// restart answers the fault by ending the server, and the browser
// surface is where an operator reads which of the two files went wrong.
// Refusing readiness here would withdraw all three.
async function theProbeReportsAPairItCouldNotPresent(httpPort, keyFile, foreign) {
  nodeFs.writeFileSync(keyFile, foreign.key, "utf8");
  var unusable = await readiness(httpPort);
  count("a pair on disk this server could not present reduces the verdict rather than " +
    "refusing traffic, because the listeners are still serving the certificate they hold " +
    "and a restart would answer the fault by ending the server",
    unusable.status === 200 && unusable.body.status === "degraded", unusable.said);
  count("and the probe says plainly that the pair on disk is not one this server could " +
    "present, which is the same answer a certificate that has run out produces",
    unusable.body.checks.certificate.read === true &&
    unusable.body.checks.certificate.ok === false &&
    unusable.body.checks.certificate.usable === false &&
    unusable.body.checks.certificate.faults.indexOf("private key") !== -1,
    JSON.stringify(unusable.body.checks.certificate));
}

async function run() {
  var root = helpers.tempDir("tlsrenewal");
  var dataDir = nodePath.join(root, "data");
  var tlsDir  = nodePath.join(root, "tls");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server = null;
  var running = false;
  try {
    // What the operator has on disk at boot, and what their certificate
    // client writes over it later. Two authorities rather than two
    // leaves under one: it is the authority that makes each handshake
    // answer unambiguously which of the two is being presented.
    var boot = await certs.writePair(tlsDir, { hostname: HOSTNAME });
    // The renewal, minted with a single day of life. Two things are being
    // read off one rotation: which ports present it, which the authority
    // answers, and what the readiness probe says about a certificate a
    // renewal client should already have replaced, which the remaining
    // life answers. A leaf with a day left is inside the window this
    // server warns about and is still perfectly serviceable, which is the
    // state the probe has to describe without refusing.
    var renewed = await certs.pair({
      hostname:      HOSTNAME,
      authorityName: "blamepost renewed authority",
      validityDays:  1,
    });
    // A third pair, never written whole. Its key alone goes onto disk at
    // the end, which is what a renewal that wrote one file and not the
    // other leaves behind.
    var foreign = await certs.pair({
      hostname:      HOSTNAME,
      authorityName: "blamepost unrelated authority",
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         boot.certFile,
        BLAMEPOST_TLS_KEY:          boot.keyFile,
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "certificate renewal test" });
    await identity.accounts.create({ address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: true, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        // Ephemeral rather than the shipped 8443. Naming the two files
        // is what brings the TLS port up at all, so this is the first
        // configuration in the suite where the browser surface takes a
        // second port, and a fixed one would collide with whatever else
        // the host is running.
        httpsPort: 0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      // No tlsContext: the configuration names the two files, which is
      // the path an operator drives and the only one a renewal reaches.
      tlsPollMs:    POLL_MS,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var names = Object.keys(sections);
    var ports = {};
    names.forEach(function (n) { ports[n] = sections[n].port; });
    // The browser surface asked the operating system for both of its
    // ports, so the numbers come off the running server rather than out
    // of the configuration that asked for zero.
    var webPorts = server.describe().web.bound;
    ports.https = webPorts.https;
    count("the browser surface took a TLS port, which is what makes it a listener a " +
      "renewal has to reach",
      typeof ports.https === "number" && ports.https > 0, JSON.stringify(webPorts));

    await theProbeReadsAHealthyCertificate(webPorts.http);
    await everyListenerPresentsTheRenewedCertificate(server, ports, boot, renewed);
    await theProbeReducesInsideTheRenewalWindow(webPorts.http);
    await theProbeReportsAPairItCouldNotPresent(webPorts.http, boot.keyFile, foreign);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "tls-certificate-renewal", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
