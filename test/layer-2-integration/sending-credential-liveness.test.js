// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What reaches a submission session that is already open under a sending
 * credential, and what does not.
 *
 * A credential's scope is settled when the client authenticates. The
 * question this file answers is what happens to a session that is still
 * open when the thing it was verified against stops being true. Two
 * changes can happen while the server runs, and both are measured here
 * against the same still-open connection:
 *
 *   - The credential's expiry passes. Nothing writes the volume for this
 *     to happen: the moment was recorded when the credential was issued
 *     and the clock reaches it on its own.
 *   - The hosted domain the credential speaks for is disabled. The admin
 *     console writes that through the running server's own store handle,
 *     so it lands without the server being stopped.
 *
 * The five verbs that change a credential are NOT among them. `revoke`,
 * `remove`, `rotate` and `refusals` open the data volume for writing, and
 * the running server holds it, so each is refused until the server is
 * stopped. That refusal is driven here through the shipped binary while
 * the server is up, because it is the half of the containment story an
 * operator acts on: stopping the server is what ends every session, and a
 * revoke that could not run until then cannot leave one behind.
 *
 * Every case is driven over BOTH transports in the same run.
 * `POST /api/send` verifies the credential on each request, so it answers
 * the moment either change lands. The submission listener settles the
 * scope at AUTH. Measuring the two separately is what lets them drift,
 * and the first configuration where they disagree is the one where a
 * credential an operator has stopped is still sending.
 *
 * Two hosted domains, so the domain that gets disabled is not the domain
 * the recipient reads their mail at.
 *
 * Run standalone: node test/layer-2-integration/sending-credential-liveness.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var cliHelper = require("../helpers/cli");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME      = "mx.example.com";
var DOMAIN        = "example.com";
var SECOND_DOMAIN = "example.org";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";

var BOUNCE_MAILBOX        = "postbox@" + DOMAIN;
var SECOND_BOUNCE_MAILBOX = "postbox@" + SECOND_DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// How long the expiring credential lives. It has to outlast one
// authenticated session plus one accepted message on a loaded runner, and
// every second past that is a second this file spends waiting.
var LIFETIME_MS = 8000;

// The ceiling on the wait for that moment to arrive. It is a wall clock
// deadline rather than an event, so the poll is what turns it into one.
var EXPIRY_WAIT_MS = 30000;

// The ceiling on one spawned command. A verb refused at the volume lock
// answers immediately; anything approaching this is a run that hung.
var CLI_CEILING_MS = 60000;

var SMTP_ACCEPTED = /^250 /m;

// Every message carries a marker, so a wire code is settled against the
// recipient's mailbox rather than believed.
var BEFORE_EXPIRY_MARKER  = "liveness-before-expiry-5c81a03f";
var AFTER_EXPIRY_MARKER   = "liveness-after-expiry-9d47b2e6";
var BEFORE_DISABLE_MARKER = "liveness-before-disable-1af06d75";
var AFTER_DISABLE_MARKER  = "liveness-after-disable-70e3c914";

// ---- one message on a session that is already open -------------------------

// The session is passed in rather than opened here, which is the whole
// point: the scope under test is the one settled at that session's AUTH,
// and a second connection would be re-verified and prove nothing.
async function sendOn(session, opts) {
  session.send("MAIL FROM:<" + opts.from + ">");
  var envelope = await session.read(/^\d{3} /m, "MAIL FROM answered");
  if (!SMTP_ACCEPTED.test(envelope)) {
    return { accepted: false, at: "envelope", reply: visible(envelope) };
  }

  session.send("RCPT TO:<" + opts.to + ">");
  var rcpt = await session.read(/^\d{3} /m, "RCPT TO answered");
  if (!SMTP_ACCEPTED.test(rcpt)) {
    return { accepted: false, at: "recipient", reply: visible(rcpt) };
  }

  session.send("DATA");
  var opened = await session.read(/^\d{3} /m, "DATA answered");
  if (!/^354 /m.test(opened)) {
    return { accepted: false, at: "data", reply: visible(opened) };
  }

  session.sendRaw([
    "From: " + opts.from,
    "To: " + opts.to,
    "Subject: " + opts.marker,
    "Date: Mon, 31 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + opts.marker + "@" + opts.domain + ">",
    "",
    "A message written by an application rather than by a person.",
    "",
    ".",
    "",
  ].join("\r\n"), "<" + opts.marker + ">");
  var answered = await session.read(/^\d{3} /m, "message answered");
  return SMTP_ACCEPTED.test(answered)
    ? { accepted: true, at: "accepted", reply: visible(answered) }
    : { accepted: false, at: "message", reply: visible(answered) };
}

// The same message over the sending route, reported in the same shape.
async function sendOverRoute(reader, token, opts) {
  var answer = await reader.post("/api/send", "application/json", JSON.stringify({
    from:         opts.from,
    to:           [opts.to],
    subject:      opts.marker,
    text:         "A message written by an application rather than by a person.",
    envelopeFrom: opts.from,
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": opts.marker,
    "Accept":          "application/json",
  });
  return {
    accepted: answer.status === 202,
    status:   answer.status,
    reply:    String(answer.body).slice(0, 300),
  };
}

// ---- the expiry passes under an open session -------------------------------

async function anExpiryPassesUnderAnOpenSession(ports, caPem, reader, made, bob) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "liveness-expiry",
    address: DOMAIN, password: made.token,
  });
  try {
    var before = await sendOn(session, {
      from: "receipts@" + DOMAIN, to: bob, domain: DOMAIN, marker: BEFORE_EXPIRY_MARKER });
    count("a credential inside its lifetime sends on the session it authenticated",
      before.accepted === true, before.at + " " + before.reply);
    count("and it did so before the expiry, so what follows measures the expiry rather " +
      "than a session that was already past it",
      Date.now() < made.expiresAt,
      (made.expiresAt - Date.now()) + "ms of lifetime left");

    await helpers.waitUntil(function () { return Date.now() > made.expiresAt; }, {
      timeoutMs: EXPIRY_WAIT_MS,
      label:     "sending-credential-liveness: the credential's expiry to pass",
    });

    var route = await sendOverRoute(reader, made.token, {
      from: "receipts@" + DOMAIN, to: bob, marker: AFTER_EXPIRY_MARKER + "-http" });
    count("the sending route refuses the expired credential, because it verifies the " +
      "credential presented on every request",
      route.accepted === false && route.status === 401, route.status + " " + route.reply);

    var after = await sendOn(session, {
      from: "receipts@" + DOMAIN, to: bob, domain: DOMAIN, marker: AFTER_EXPIRY_MARKER });
    count("and the still-open submission session refuses it too, so an expiry an operator " +
      "set is an expiry on both transports rather than one a connection outlives",
      after.accepted === false, after.at + " " + after.reply);
    count("the refusal is permanent rather than a temporary one a sender retries until " +
      "its queue lifetime runs out",
      after.accepted === false && /^550 5\.7\.1 /m.test(after.reply), after.reply);
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// ---- the domain is disabled under an open session --------------------------

// The console's own call, made against the same store handle the console
// holds. `lib/web/index.js` reaches `store.domains.setStatus` from the
// admin surface, so this lands exactly where a disable an operator pressed
// lands, without a browser session standing between the write and the
// question being asked.
async function aDomainIsDisabledUnderAnOpenSession(ports, caPem, reader, identity, made, bob) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "liveness-disable",
    address: SECOND_DOMAIN, password: made.token,
  });
  try {
    var before = await sendOn(session, {
      from: "receipts@" + SECOND_DOMAIN, to: bob, domain: SECOND_DOMAIN,
      marker: BEFORE_DISABLE_MARKER });
    count("a credential for a domain in service sends on the session it authenticated",
      before.accepted === true, before.at + " " + before.reply);

    await identity.domains.setStatus({
      domain: SECOND_DOMAIN,
      status: "disabled",
      reason: "the liveness test withdraws the domain while a session is open",
    });
    var row = identity.domains.get(SECOND_DOMAIN);
    count("the domain is disabled on the volume the running server reads, which is the " +
      "write the admin console makes and the command line cannot",
      row !== null && row !== undefined && row.status === "disabled",
      JSON.stringify(row && row.status));

    var route = await sendOverRoute(reader, made.token, {
      from: "receipts@" + SECOND_DOMAIN, to: bob, marker: AFTER_DISABLE_MARKER + "-http" });
    count("the sending route refuses a credential whose domain has been withdrawn",
      route.accepted === false && route.status === 401, route.status + " " + route.reply);

    var after = await sendOn(session, {
      from: "receipts@" + SECOND_DOMAIN, to: bob, domain: SECOND_DOMAIN,
      marker: AFTER_DISABLE_MARKER });
    count("and the still-open submission session refuses it too, so withdrawing a domain " +
      "stops the mail leaving under its name rather than stopping the next sign-in",
      after.accepted === false, after.at + " " + after.reply);
    count("that refusal is permanent as well, and carries the same code and enhanced " +
      "status as the one an expiry draws, because they are one refusal",
      after.accepted === false && /^550 5\.7\.1 /m.test(after.reply), after.reply);
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// ---- revoking is what the operator cannot do without stopping --------------

// The other half of the containment story, driven through the shipped
// binary rather than reasoned about. `credential revoke` opens the data
// volume for writing and the running server holds it, so the verb is
// refused while any session could still be open. Stopping the server is
// what makes it run, and stopping the server closes every session, so
// there is no window in which a revoked credential is still sending.
async function revokingRefusesWhileTheServerHoldsTheVolume(cliAsync, id) {
  var refused = await cliAsync(["credential", "revoke", id,
    "--reason", "the liveness test asks for a revoke while the server is up"]);
  count("`credential revoke` is refused while the server holds the data volume",
    refused.status !== 0 && refused.ceilingHit !== true,
    "exit " + refused.status + " " + refused.both.slice(0, 300));
  count("and the refusal says the volume is already open for writing, which is the " +
    "instruction to stop the server",
    /already open|open for writing|store\/volume-in-use/i.test(refused.both),
    refused.both.slice(0, 400));
}

// ---- where the wire codes are settled --------------------------------------

async function onlyTheMessagesSentWhileLiveReachedTheMailbox(ports, caPem, bob) {
  var reader = await Wire.imap(ports.imap, {
    caPem: caPem, servername: HOSTNAME, label: "liveness-settle",
    address: bob, password: BOB_PASSWORD,
  });
  var selectTag = reader.tag();
  reader.send(selectTag + " SELECT INBOX");
  var selected = await reader.read(new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"),
    "SELECT answered");
  var existing = /^\* (\d+) EXISTS/m.exec(selected);
  count("the recipient's mailbox can be read", existing !== null, visible(selected));

  var held = existing === null ? 0 : parseInt(existing[1], 10);
  var seen = "";
  for (var seq = 1; seq <= held; seq += 1) {
    var fetchTag = reader.tag();
    reader.send(fetchTag + " FETCH " + seq + " BODY.PEEK[]");
    seen += await reader.read(new RegExp("^" + fetchTag + " (OK|NO|BAD)", "m"),
      "message " + seq + " fetched");
  }
  reader.send(reader.tag() + " LOGOUT");
  reader.close();

  count("the message sent inside the credential's lifetime is in the mailbox",
    seen.indexOf(BEFORE_EXPIRY_MARKER) !== -1, BEFORE_EXPIRY_MARKER);
  count("the message sent while the domain was in service is in the mailbox",
    seen.indexOf(BEFORE_DISABLE_MARKER) !== -1, BEFORE_DISABLE_MARKER);
  count("nothing reached it from the session that went on after the expiry, so the wire " +
    "code is settled against the mailbox rather than believed",
    seen.indexOf(AFTER_EXPIRY_MARKER) === -1, AFTER_EXPIRY_MARKER);
  count("and nothing from the session that went on after the domain was withdrawn",
    seen.indexOf(AFTER_DISABLE_MARKER) === -1, AFTER_DISABLE_MARKER);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sending-credential-liveness");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "credential liveness test" });
    await identity.domains.add({ domain: SECOND_DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: SECOND_DOMAIN, by: "credential liveness test" });

    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });
    await identity.accounts.create({
      address: SECOND_BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    var withdrawn = await identity.credentials.create({
      domain:        SECOND_DOMAIN,
      bounceMailbox: SECOND_BOUNCE_MAILBOX,
      reason:        "the second domain's receipts application",
      maxMessages:   50,
      maxRecipients: 100,
    });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
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

    var ports = { submission: sections.submission.port, imap: sections.imap.port };
    var bound = server.web.bound();
    count("the browser surface took a TLS port, which is the only one a credential may " +
      "be presented on",
      typeof bound.https === "number" && bound.https > 0, JSON.stringify(bound));

    var reader = browser.browserAt("https://" + LOOPBACK + ":" + bound.https,
      { ca: material.caPem, servername: HOSTNAME });

    var cliAsync = cliHelper.createAsync({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      ceilingMs:       CLI_CEILING_MS,
    });

    await revokingRefusesWhileTheServerHoldsTheVolume(cliAsync, withdrawn.id);
    await aDomainIsDisabledUnderAnOpenSession(
      ports, material.caPem, reader, identity, withdrawn, bob.address);

    // Issued here rather than beside the other one, so its lifetime starts
    // running when the case that measures it starts. A credential minted
    // at boot spends that lifetime on whatever runs before it, and the
    // case would then be measuring a session that was already past the
    // expiry when it authenticated.
    var expiring = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the receipts application is tested for one short window",
      expiresAt:     Date.now() + LIFETIME_MS,
      maxMessages:   50,
      maxRecipients: 100,
    });
    await anExpiryPassesUnderAnOpenSession(
      ports, material.caPem, reader, expiring, bob.address);
    await onlyTheMessagesSentWhileLiveReachedTheMailbox(ports, material.caPem, bob.address);

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
  name:      "sending-credential-liveness",
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
