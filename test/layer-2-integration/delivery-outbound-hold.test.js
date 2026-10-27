// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * An account sending to somebody who is not on this server, driven
 * through a real submission listener with a real mail client on a real
 * socket.
 *
 * The claim is about what happens to that message when the peer cannot
 * be reached. It has to be kept, whole and retriable, for as long as the
 * operator's retry budget says, and then it has to end with a report to
 * the account that sent it. Both halves matter: a message retried
 * forever is one nobody is ever told about, and a message dropped
 * silently is worse.
 *
 * The message on disk has to be the message the client submitted, byte
 * for byte. A transport that rebuilds the body from structured fields
 * would spool and send something the sender never wrote, and a peer
 * would accept it, so this is the layer where that guarantee is
 * checkable at all.
 *
 * The resolver is supplied to the server, so the recipient domain
 * answers with a mail exchanger and the composer gets past MX lookup and
 * policy to a transport. The host it names does not resolve, so the
 * attempt ends at the connect and nothing leaves the machine.
 *
 * Run standalone: node test/layer-2-integration/delivery-outbound-hold.test.js
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
var ELSEWHERE = "example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

var BODY = "Ordering two more of the blue ones. Marker 9f2b41c7.";

// A resolver that answers, which is the only way to reach the part of
// the outbound path this file is about. Everything else fails at MX
// lookup, and a failure there never constructs a transport.
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

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
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

function spoolFiles(dataDir, ext) {
  var dir = nodePath.join(dataDir, "queue");
  if (!nodeFs.existsSync(dir)) return [];
  return nodeFs.readdirSync(dir).filter(function (n) {
    return ext === undefined || n.slice(-ext.length) === ext;
  }).sort();
}

// ---- the case --------------------------------------------------------------

async function aMessageToSomebodyElsewhereIsKeptRatherThanLost(ports, caPem, alice, server, dataDir) {
  var recipient = "bob@" + ELSEWHERE;
  var sender = await submissionSession(ports.submission, caPem,
    alice, ALICE_PASSWORD, "submission-outbound");

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
    "Subject: The blue ones",
    "Date: Sun, 23 Aug 2026 09:00:00 +0000",
    "Message-ID: <outbound-9f2b41c7@example.com>",
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

  // The handoff runs inside the listener's own answer, so the spool is
  // written by the time the client sees its 250. Polled rather than
  // slept on, because "by the time" is a claim about a loaded runner as
  // much as about this one.
  var files = await helpers.waitUntil(function () {
    var f = spoolFiles(dataDir);
    return f.length >= 2 ? f : false;
  }, {
    timeoutMs: 5000,
    label:     "outbound hold: the relayed message reaches the spool",
  });

  count("the message this server could not send is on disk, descriptor and body both",
    files.length === 2, files.join(" "));

  var id = files[0].replace(/\.(json|eml)$/, "");
  var entry = await server.mail.delivery.queue.show(id);
  count("the queue can say what happened to it", entry !== null, id);
  count("it is addressed to the recipient the client gave",
    entry.recipient === recipient, entry.recipient);
  count("it is from the account that authenticated", entry.from === alice, entry.from);
  count("the attempt spent its place in the budget", entry.attempt === 1,
    String(entry.attempt));
  count("nothing is holding it outside that budget",
    entry.projection.held === false, JSON.stringify(entry.projection).slice(0, 200));
  count("and the projection an operator reads says how it ends and who hears",
    /more attempt/.test(String(entry.projection.ifItNeverSucceeds)) &&
    /report is sent to/.test(String(entry.projection.ifItNeverSucceeds)),
    String(entry.projection.ifItNeverSucceeds).slice(0, 200));
  count("while what the attempt actually met is on the entry",
    String(entry.reason).length > 0, entry.reason);

  var outbound = server.describe().outbound;
  count("the build reports that it can reach a peer",
    outbound.wireDelivery.available === true, JSON.stringify(outbound.wireDelivery));
  count("nobody is recorded as a sender who could not be told",
    outbound.reportsUnsent === 0, String(outbound.reportsUnsent));

  // The body on disk is the message the client wrote, so a later attempt
  // sends what was submitted rather than a rebuild of it. This is the
  // guarantee no check of the framework surface can make: a transport
  // that rebuilds the body is callable and destroys the message.
  var body = nodeFs.readFileSync(nodePath.join(dataDir, "queue", id + ".eml"), "utf8");
  count("the spooled body is the message the client sent",
    body.indexOf(BODY) !== -1, String(body.length) + " bytes");
  count("and it was not rebuilt into something the sender never wrote",
    body.indexOf("multipart/alternative") === -1, String(body.length) + " bytes");

  // Sweeping to the end of the budget ends the message and tells the
  // account that sent it, which is the trade the budget exists to make.
  await server.mail.delivery.queue.runDue({ force: true });
  await server.mail.delivery.queue.runDue({ force: true });

  count("the message that ran out of attempts is off disk",
    !nodeFs.existsSync(nodePath.join(dataDir, "queue", id + ".json")),
    spoolFiles(dataDir).join(" "));
  count("and the account that sent it was told rather than left assuming it arrived",
    server.describe().outbound.reportsUnsent === 0);

  // What is left is the report itself, addressed back to the account
  // with the reverse path RFC 5321 §6.1 requires.
  var left = spoolFiles(dataDir, ".json");
  count("a report to the sender took the message's place", left.length === 1,
    spoolFiles(dataDir).join(" "));
  var report = await server.mail.delivery.queue.show(left[0].slice(0, -5));
  count("addressed to the account that sent the message",
    report !== null && report.recipient === alice, report && report.recipient);
  count("and traveling with the empty reverse path",
    report !== null && report.from === "", report && JSON.stringify(report.from));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("outbound-hold");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "outbound hold test" });
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
        // Three attempts: enough that the first send leaves the message
        // in the spool where this case can read it, and few enough that
        // the end of the budget is reachable in a test rather than in
        // five hours.
        outboundRetry:  {
          maxAttempts: 3,
          backoffMs:   [b.constants.TIME.minutes(1), b.constants.TIME.minutes(5),
                        b.constants.TIME.minutes(15)],
        },
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

    await aMessageToSomebodyElsewhereIsKeptRatherThanLost(
      { submission: sections.submission.port }, leaf.ca, alice.address, server, dataDir);

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

module.exports = { name: "delivery-outbound-hold", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
