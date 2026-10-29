// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The send ceiling a domain-scoped credential carries, measured against
 * requests that arrive at the same instant rather than one after another.
 *
 * A credential speaks for every address at a hosted domain, so the two
 * ceilings on it are what bounds the damage a leaked one does. The
 * existing coverage spends those ceilings one message at a time and
 * reads them back, which is the shape an application produces and not
 * the shape an attacker produces. An attacker holding a leaked
 * credential opens as many connections as the listener accepts and sends
 * on all of them together.
 *
 * `test/layer-2-integration/api-send-credential-parity.test.js` already
 * drives two simultaneous requests, but both carry ONE `Idempotency-Key`,
 * so the replay record serializes them and neither reaches the counter
 * beside the other. The requests here carry DISTINCT keys and distinct
 * bodies, which is what puts two counter updates in flight together.
 *
 * The claims:
 *
 *   - A credential set to three messages sends two and is refused on the
 *     third when the messages are sent one at a time. This is the
 *     control, and it is what says the ceiling is wired at all.
 *   - The same credential, sent through concurrently, is refused on the
 *     same message. What may not happen is that the burst is accepted
 *     whole.
 *   - What the window reads afterwards matches what the route accepted.
 *     A window that reads less than the route sent is a ceiling that
 *     spends less than it relays, and the difference is mail that left
 *     under no ceiling at all.
 *
 * The counter underneath reads its window and writes it back across two
 * awaits, so two calls that reach it inside one microtask drain both read
 * the same total and the second write replaces the first. Driven directly
 * as a batch of promises, twenty counts collapse to one. It does not
 * reproduce through either transport: a request carries a TLS record, an
 * HTTP parse, a credential verify, a message build and a header parse
 * ahead of the counter, and that work separates two requests by more than
 * the read-and-write window is wide. This file is what says so on the
 * shipped path, and what would fail if that separation ever stopped
 * holding.
 *
 * Run standalone:
 *   node test/layer-2-integration/sending-credential-ceiling-concurrency.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var reservePort = wire.reservePort;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";

var BOUNCE_MAILBOX = "postbox@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// The ceiling every case below is measured against. The registry counts
// the message in front of it and refuses it when the count goes past the
// ceiling, so a credential set to three accepts three messages and
// refuses the fourth.
var CEILING_MESSAGES = 3;
var ROOM_BELOW_CEILING = CEILING_MESSAGES;

// How many requests the burst carries. Well above the ceiling, so a
// ceiling that holds refuses most of them and a ceiling that does not
// accepts the lot.
var BURST_SIZE = 8;

// One message over the sending route, under a key and a body of its own
// so the replay record never collapses two of them into one.
function sendOnce(reader, token, marker, to) {
  var body = JSON.stringify({
    from:    "shop@" + DOMAIN,
    to:      [to],
    subject: marker,
    text:    "A message written by an application rather than by a person.",
  });
  return reader.post("/api/send", "application/json", body, {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": marker,
    "Accept":          "application/json",
  });
}

function acceptedCount(answers) {
  return answers.filter(function (a) { return a.status === 202; }).length;
}

function statusList(answers) {
  return answers.map(function (a) { return a.status; }).join(", ");
}

// The control. One message at a time against a credential with room for
// three, so the run says plainly whether the ceiling is wired before it
// asks whether concurrency walks past it.
async function theCeilingHoldsOneMessageAtATime(reader, identity, to) {
  var made = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential with room for three messages, sent one at a time",
    maxMessages:   CEILING_MESSAGES,
    maxRecipients: 1000,
  });

  var answers = [];
  for (var i = 0; i < BURST_SIZE; i += 1) {
    answers.push(await sendOnce(reader, made.token,
      "ceiling-sequential-" + i + "-" + Date.now(), to));
  }

  count("a credential set to " + CEILING_MESSAGES + " messages accepts " +
    ROOM_BELOW_CEILING + " when they are sent one at a time",
    acceptedCount(answers) === ROOM_BELOW_CEILING,
    acceptedCount(answers) + " of " + BURST_SIZE + " accepted: " + statusList(answers));

  count("and every message past the ceiling is refused with 429, which is the answer " +
    "that carries the wait",
    answers.slice(ROOM_BELOW_CEILING).every(function (a) { return a.status === 429; }),
    statusList(answers.slice(ROOM_BELOW_CEILING)));

  var reading = await identity.credentials.counters.read(made.id);
  count("and the window afterwards reads the messages the route actually accepted",
    reading.messages >= acceptedCount(answers),
    "window=" + reading.messages + ", accepted=" + acceptedCount(answers));
}

// The same credential and the same ceiling, with the requests in flight
// together. A ceiling that is read and written across an await is one
// that every request in a burst reads before any of them has written.
async function theCeilingHoldsWhenRequestsArriveTogether(reader, identity, to) {
  var made = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential with room for three messages, sent all at once",
    maxMessages:   CEILING_MESSAGES,
    maxRecipients: 1000,
  });

  var stamp = Date.now();
  var jobs = [];
  for (var i = 0; i < BURST_SIZE; i += 1) {
    jobs.push(sendOnce(reader, made.token, "ceiling-concurrent-" + i + "-" + stamp, to));
  }
  var answers = await Promise.all(jobs);
  var accepted = acceptedCount(answers);

  count("a credential set to " + CEILING_MESSAGES + " messages accepts no more than " +
    ROOM_BELOW_CEILING + " when " + BURST_SIZE + " requests arrive at once, because a " +
    "ceiling an attacker walks past by opening more connections is not a ceiling",
    accepted <= ROOM_BELOW_CEILING,
    accepted + " of " + BURST_SIZE + " accepted: " + statusList(answers));

  // The window against the route's own answer. These two are the same
  // number when every accepted message spent a slot, and they come apart
  // when several messages shared one.
  var reading = await identity.credentials.counters.read(made.id);
  count("and the window reads at least as many messages as the route accepted, so no " +
    "message left under a slot another message had already spent",
    reading.messages >= accepted,
    "window=" + reading.messages + ", accepted=" + accepted);
}

// The recipient ceiling, asked the same way. It is the half a message
// counter cannot see: one message carrying a hundred thousand addresses
// is the event a leaked credential produces.
async function theRecipientCeilingHoldsWhenRequestsArriveTogether(reader, identity, to) {
  var made = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential whose recipient ceiling is spent all at once",
    maxMessages:   1000,
    maxRecipients: CEILING_MESSAGES,
  });

  var stamp = Date.now();
  var jobs = [];
  for (var i = 0; i < BURST_SIZE; i += 1) {
    jobs.push(sendOnce(reader, made.token, "recipient-concurrent-" + i + "-" + stamp, to));
  }
  var answers = await Promise.all(jobs);
  var accepted = acceptedCount(answers);

  count("a credential set to " + CEILING_MESSAGES + " recipients accepts no more than " +
    ROOM_BELOW_CEILING + " single-recipient messages when they arrive at once",
    accepted <= ROOM_BELOW_CEILING,
    accepted + " of " + BURST_SIZE + " accepted: " + statusList(answers));

  var reading = await identity.credentials.counters.read(made.id);
  count("and the window reads at least as many recipients as the route accepted messages for",
    reading.recipients >= accepted,
    "window=" + reading.recipients + ", accepted=" + accepted);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sending-credential-ceiling-concurrency");
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
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, by: "sending credential ceiling concurrency test" });

    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

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
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    var tlsOrigin = "https://" + LOOPBACK + ":" + bound.https;
    var reader = browser.browserAt(tlsOrigin, {
      ca: material.caPem, servername: HOSTNAME });

    await theCeilingHoldsOneMessageAtATime(reader, identity, bob.address);
    await theCeilingHoldsWhenRequestsArriveTogether(reader, identity, bob.address);
    await theRecipientCeilingHoldsWhenRequestsArriveTogether(reader, identity, bob.address);

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

module.exports = {
  name:      "sending-credential-ceiling-concurrency",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
