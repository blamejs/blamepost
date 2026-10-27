// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * body-rate-floor-smtp: the slowest a peer may send a message body
 * before both SMTP listeners cut it, measured on the wire at the number
 * SECURITY.md publishes.
 *
 * An idle timer cannot reach this peer. It sends one octet, waits, sends
 * another, and every arriving octet pushes the deadline out again, so
 * the connection is never idle and is never doing anything either. It
 * holds a socket, a slot in the per-address ceiling and an assembled
 * body for as long as it likes. The floor is the bound that answers it:
 * a body arriving below a hundred bytes a second is answered `421 4.7.0`
 * and cut.
 *
 * Nothing measured it here. The only byte-rate vector in this suite runs
 * over an IMAP literal, and the document's promise is about a message
 * body over the two SMTP listeners, in both framings. The number belongs
 * to the vendored limiter and no call site in this repository passes
 * one, so a refresh that moved it would change what this server tolerates
 * while the shipped document went on promising a hundred.
 *
 * Three vectors, which is every framing the document names:
 *
 *   - `DATA` on the MX listener, which is the one a stranger reaches
 *     without signing in.
 *   - `DATA` on the submission listener.
 *   - `BDAT` on the submission listener, which is the framing the
 *     document calls chunked transfer and the only listener that
 *     advertises `CHUNKING`. It is named separately because it was the
 *     first way this floor was bypassed: enforced on the DATA path
 *     alone, a peer simply used the other verb.
 *
 * Each is asserted twice. The reply code is pinned exactly, because a
 * peer decides whether to retry on the code and an operator filters a
 * log on it. The number is read off the refusal's own audit row, where
 * the limiter records the floor it applied, so a refresh that moves the
 * floor fails this file rather than moving what the document means.
 *
 * The three run together. Each has to trickle for longer than the
 * limiter's judging window before a verdict exists, so running them one
 * after another would cost three windows to measure one number.
 *
 * Run standalone: node test/layer-2-integration/body-rate-floor-smtp.test.js
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
var PEER     = "sender@example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The number SECURITY.md publishes, written here as the document writes
// it. Read off the limiter instead it would assert that the limiter
// agrees with itself, which stays true across the refresh this file
// exists to catch.
var DOCUMENTED_FLOOR_BYTES_PER_SECOND = 100;

// What a peer sending below it is told. RFC 5321 section 4.2.1 puts 421
// at "service not available, closing transmission channel", which is the
// verdict here: the connection goes, the message does not become a
// permanent failure, and a sender on a genuinely bad link returns later.
var FLOOR_REFUSAL_CODE = "421 4.7.0";

// The trickle. One octet every four hundred milliseconds is two and a
// half bytes a second against a floor of a hundred, so no run of this
// is a judgement call about timing. The announced body is large enough
// that arriving in full would take a quarter of an hour at that rate,
// which is what makes its size irrelevant to the verdict.
var TRICKLE_OCTETS      = 4000;
var TRICKLE_INTERVAL_MS = 400;

// This case's own ceiling, separate from the limiter's judging window.
// It exists so a listener that holds the connection fails here rather
// than inheriting the hang this file was written to catch.
var TRICKLE_CEILING_MS = 45000;

// ---- the trickle -----------------------------------------------------------

// Push one octet at a time until the listener answers or the socket
// dies, then stop. Nothing waits a fixed budget: the interval only
// produces the traffic, and the verdict is whatever the listener said.
function startTrickle(session) {
  var state = { stopped: false, sent: 0 };
  state.ticker = setInterval(function () {
    if (state.stopped || state.sent >= TRICKLE_OCTETS) return;
    try { session.sendRaw("x", "<one octet>"); state.sent += 1; }
    catch (_e) { state.stopped = true; }
  }, TRICKLE_INTERVAL_MS);
  state.stop = function () {
    state.stopped = true;
    clearInterval(state.ticker);
  };
  return state;
}

// Trickle a body into a session already in its body phase, and hand back
// what the listener said and how far the payload got.
async function trickleUntilAnswered(session, label) {
  var trickle = startTrickle(session);
  try {
    await helpers.waitUntil(function () {
      return /^421 /m.test(session.buf) || session.socket.destroyed;
    }, {
      timeoutMs: TRICKLE_CEILING_MS,
      label:     "body-rate floor: " + label + " is answered below the floor",
    });
  } finally {
    trickle.stop();
  }
  return { said: session.buf, sent: trickle.sent };
}

// ---- the three body phases -------------------------------------------------

// An inbound peer, taken as far as the DATA continuation and no further.
async function mxDataBody(port, caPem, to) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, label: "mx-trickle" });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + to + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  return peer;
}

// An authenticated client, taken to the same place on the submission
// listener.
async function submissionDataBody(port, caPem, address) {
  var session = await Wire.submission(port, {
    caPem: caPem, servername: HOSTNAME,
    address: address, password: ALICE_PASSWORD, label: "submission-trickle" });
  session.send("MAIL FROM:<" + address + ">");
  await session.read(/^250 /m, "MAIL FROM accepted");
  session.send("RCPT TO:<" + address + ">");
  await session.read(/^250 /m, "RCPT TO accepted");
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  return session;
}

// The same client, using the chunked framing RFC 3030 defines. BDAT
// takes its payload straight after the command line with no
// continuation, so the body phase opens on the command itself.
async function submissionBdatBody(port, caPem, address) {
  var session = await Wire.submission(port, {
    caPem: caPem, servername: HOSTNAME,
    address: address, password: ALICE_PASSWORD, label: "submission-bdat-trickle" });
  session.send("MAIL FROM:<" + address + ">");
  await session.read(/^250 /m, "MAIL FROM accepted");
  session.send("RCPT TO:<" + address + ">");
  await session.read(/^250 /m, "RCPT TO accepted");
  session.send("BDAT " + TRICKLE_OCTETS);
  return session;
}

// ---- cases -----------------------------------------------------------------

// One framing, one listener, one verdict.
function theFloorAnsweredThisPeer(vector, outcome, rows) {
  count(vector.label + " below the floor is answered rather than held open, which is the " +
    "bound an idle timer cannot give because every arriving octet resets it",
    /^421 /m.test(outcome.said), visible(outcome.said.slice(-200)));

  // Pinned exactly. A conforming sender decides whether to retry on the
  // code, and an operator watching for a slow-transfer attack filters on
  // it.
  count("and the code is " + FLOOR_REFUSAL_CODE + ", so a sender on a genuinely bad link " +
    "returns later rather than treating the message as refused",
    outcome.said.indexOf(FLOOR_REFUSAL_CODE) !== -1, visible(outcome.said.slice(-200)));

  count("well before the announced body could have arrived, so what was measured is the " +
    "rate rather than the size", outcome.sent < TRICKLE_OCTETS,
    outcome.sent + " of " + TRICKLE_OCTETS + " octets sent");

  var floors = rows.map(function (row) { return metadataOf(row).minBytesPerSecond; });
  count(vector.label + " is refused against the floor SECURITY.md publishes, " +
    DOCUMENTED_FLOOR_BYTES_PER_SECOND + " bytes a second, rather than against whatever " +
    "number the limiter happens to default to",
    rows.length > 0 &&
      floors.every(function (n) { return n === DOCUMENTED_FLOOR_BYTES_PER_SECOND; }),
    rows.length + " refusal row(s), floors " + JSON.stringify(floors));

  count("and the row says the rate was why, so an operator reading the audit trail can " +
    "tell a slow sender from a refused one",
    rows.length > 0 && rows.every(function (row) {
      return metadataOf(row).reason === "body-rate-below-floor";
    }),
    JSON.stringify(rows.map(function (row) { return metadataOf(row).reason; })));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("bodyrate");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "body rate floor test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
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

    audit = auditCapture();

    // Every session reaches its body phase before any of them starts
    // trickling, so the three judging windows overlap rather than run
    // one after another.
    var bodies = await Promise.all([
      mxDataBody(sections.mx.port, leaf.ca, alice.address),
      submissionDataBody(sections.submission.port, leaf.ca, alice.address),
      submissionBdatBody(sections.submission.port, leaf.ca, alice.address),
    ]);

    var outcomes = await Promise.all([
      trickleUntilAnswered(bodies[0], "a DATA body on the MX listener"),
      trickleUntilAnswered(bodies[1], "a DATA body on the submission listener"),
      trickleUntilAnswered(bodies[2], "a BDAT chunk on the submission listener"),
    ]);
    bodies.forEach(function (session) { session.close(); });

    // The reply reaches the peer before the row reaches the audit store,
    // so the rows are waited for rather than read at whatever moment the
    // last socket happened to close.
    await helpers.waitUntil(function () {
      return audit.forAction("mail.server.mx.data_refused").length >= 1 &&
        audit.forAction("mail.server.submission.data_refused").length >= 2;
    }, {
      timeoutMs: 5000,
      label:     "body-rate floor: every refusal writes its audit row",
    });

    var mxRows         = audit.forAction("mail.server.mx.data_refused");
    var submissionRows = audit.forAction("mail.server.submission.data_refused");

    theFloorAnsweredThisPeer({ label: "a DATA body arriving on the MX listener" },
      outcomes[0], mxRows);
    theFloorAnsweredThisPeer({ label: "a DATA body arriving on the submission listener" },
      outcomes[1], submissionRows);
    theFloorAnsweredThisPeer({ label: "a BDAT chunk arriving on the submission listener" },
      outcomes[2], submissionRows);

    count("the chunked framing is refused by the same floor as the line-by-line one, so a " +
      "peer cannot pick a verb to get past it", submissionRows.length === 2,
      submissionRows.length + " submission refusal row(s)");

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

module.exports = { name: "body-rate-floor-smtp", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
