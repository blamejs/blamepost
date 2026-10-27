// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A sending credential is refused every mailbox in its domain that carries
 * the operator role, and the role is read from the account table when the
 * message is checked rather than from the credential.
 *
 * `sending-credential-operator-refusal-currency.test.js` measures an
 * operator mailbox CREATED after the credential was issued. This file
 * measures the other ways the account table moves under a credential that
 * is already sending:
 *
 *   - An existing account is GRANTED the role after issuance. The
 *     credential's stored refusal list does not name it, which is asserted
 *     first, so a refusal can only come from the live read. Both transports
 *     are driven, the SMTP arm on the envelope sender and on the From
 *     header, and a subaddressed spelling is asked over the route.
 *
 *   - The role is granted and then taken back while ONE SMTP session stays
 *     open. The session authenticated before either change, so an answer
 *     that moves with the role is an answer read per message.
 *
 *   - A credential whose refusal list the operator has EMPTIED is still
 *     refused an operator mailbox. `postmaster` is asked of the same
 *     credential as the control: it is permitted, which shows the emptied
 *     list is the one being read.
 *
 * Run standalone:
 *   node test/layer-2-integration/sending-credential-operator-role-floor.test.js
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

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";
var ADMIN_PASSWORD   = "granite meadow lantern 5518";
var CAROL_PASSWORD   = "copper lagoon whistle 4471";
var FRANK_PASSWORD   = "velvet quarry beacon 3902";

var BOUNCE_MAILBOX = "postbox@" + DOMAIN;
var EARLY_OPERATOR = "earlyadmin";

// Carol is an ordinary mailbox when the credential is issued and is
// granted the role once the server is running. Frank is granted it and
// has it taken back while one SMTP session stays open.
var CAROL = "carol";
var FRANK = "frank";

// An address at the domain that belongs to nobody. The SMTP header arm
// writes it as the envelope sender so the refusal it measures can only
// come from the From header.
var APPLICATION = "shop";

var SHUTDOWN_TIMEOUT_MS = 5000;

var SMTP_ACCEPTED = /^250 /m;

var markerSequence = 0;
function marker(label) {
  markerSequence += 1;
  return "operator-role-floor-" + label + "-" + Date.now() + "-" + markerSequence;
}

function at(localPart) {
  return localPart + "@" + DOMAIN;
}

// One message over the sending route, written as the given author.
async function authorOverSendRoute(reader, token, from, to) {
  var key = marker("route");
  var body = JSON.stringify({
    from:    from,
    to:      [to],
    subject: key,
    text:    "A message written by an application rather than by a person.",
  });
  var answer = await reader.post("/api/send", "application/json", body, {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": key,
    "Accept":          "application/json",
  });
  return { status: answer.status, body: String(answer.body).slice(0, 300) };
}

// One whole message over SMTP submission. The verdict names whether the
// envelope or the header refused it.
async function messageOverSubmission(ports, caPem, token, opts) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "operator-role-floor-" + opts.label,
    address: DOMAIN, password: token,
  });
  var id = marker(opts.label);
  try {
    session.send("MAIL FROM:<" + opts.envelopeFrom + ">");
    var envelope = await session.read(/^\d{3} /m, "MAIL FROM answered");
    if (!SMTP_ACCEPTED.test(envelope)) {
      return { accepted: false, at: "envelope", reply: visible(envelope) };
    }
    session.send("RCPT TO:<" + opts.to + ">");
    await session.read(/^\d{3} /m, "RCPT TO answered");
    session.send("DATA");
    await session.read(/^354 /m, "DATA answered");
    session.sendRaw([
      "From: " + opts.from,
      "To: " + opts.to,
      "Subject: " + id,
      "Date: Mon, 31 Aug 2026 12:00:00 +0000",
      "Message-ID: <" + id + "@" + DOMAIN + ">",
      "",
      "A message written by an application rather than by a person.",
      "",
      ".",
      "",
    ].join("\r\n"), "<" + id + ">");
    var answered = await session.read(/^\d{3} /m, "message answered");
    return SMTP_ACCEPTED.test(answered)
      ? { accepted: true, at: "accepted", reply: visible(answered) }
      : { accepted: false, at: "header", reply: visible(answered) };
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// One envelope sender asked on a session that is already open.
async function envelopeOnSession(session, mailFrom, label) {
  session.send("RSET");
  await session.read(/^\d{3} /m, label + ": RSET answered");
  session.send("MAIL FROM:<" + mailFrom + ">");
  var reply = await session.read(/^\d{3} /m, label + ": MAIL FROM answered");
  return { accepted: SMTP_ACCEPTED.test(reply), reply: visible(reply) };
}

// ---- a role granted to an existing account after issuance ---------------

async function aRoleGrantedAfterIssuance(ports, caPem, reader, identity, made, carol, to) {
  var shown = await identity.credentials.show(made.id);
  count("the credential's stored refusal list does not name the account that is about to " +
    "be granted the role, so a refusal below can only come from reading the account table",
    Array.isArray(shown.refusedLocalParts) && shown.refusedLocalParts.indexOf(CAROL) === -1,
    JSON.stringify(shown.refusedLocalParts));

  var before = await authorOverSendRoute(reader, made.token, at(CAROL), to);
  count("before the grant, the credential may write as that ordinary mailbox",
    before.status === 202, "status " + before.status + ": " + before.body);

  await identity.accounts.setAdmin({
    id: carol.id, isAdmin: true, reason: "carol covers the operator rota" });

  var route    = await authorOverSendRoute(reader, made.token, at(CAROL), to);
  var tagged   = await authorOverSendRoute(reader, made.token, CAROL + "+receipts@" + DOMAIN, to);
  var envelope = await messageOverSubmission(ports, caPem, made.token, {
    label: "granted-envelope", envelopeFrom: at(CAROL), from: at(CAROL), to: to });
  var header   = await messageOverSubmission(ports, caPem, made.token, {
    label: "granted-header", envelopeFrom: at(APPLICATION), from: at(CAROL), to: to });

  console.log("  measured: route=" + route.status + " route/tagged=" + tagged.status +
    " submission/envelope=" + envelope.at + " submission/header=" + header.at);

  count("after the grant, the sending route refuses that mailbox as the author",
    route.status === 403, "status " + route.status + ": " + route.body);
  count("and refuses it under a subaddress, which delivers to the same mailbox",
    tagged.status === 403, "status " + tagged.status + ": " + tagged.body);
  count("and the submission listener refuses it as the envelope sender",
    envelope.accepted === false && envelope.at === "envelope", JSON.stringify(envelope));
  count("and refuses it as the From header behind a permitted envelope sender",
    header.accepted === false && header.at === "header", JSON.stringify(header));
}

// ---- one open session across a grant and a revocation --------------------

async function oneSessionAcrossTheRoleChanging(ports, caPem, identity, made, frank) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "operator-role-floor-open-session",
    address: DOMAIN, password: made.token,
  });
  var first, granted, revoked;
  try {
    first = await envelopeOnSession(session, at(FRANK), "before the grant");

    await identity.accounts.setAdmin({
      id: frank.id, isAdmin: true, reason: "frank takes the operator pager" });
    granted = await envelopeOnSession(session, at(FRANK), "after the grant");

    await identity.accounts.setAdmin({
      id: frank.id, isAdmin: false, reason: "frank hands the operator pager back" });
    revoked = await envelopeOnSession(session, at(FRANK), "after the revocation");
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }

  console.log("  measured: open-session before=" + first.accepted +
    " granted=" + granted.accepted + " revoked=" + revoked.accepted);

  count("on a session that authenticated before any change, an ordinary mailbox is an " +
    "envelope sender the credential may write", first.accepted === true, first.reply);
  count("and the same session is refused it once the account is granted the role, with " +
    "no new sign-in", granted.accepted === false, granted.reply);
  count("and permitted it again once the role is taken back, because the role is read on " +
    "each message in both directions", revoked.accepted === true, revoked.reply);
}

// ---- an emptied refusal list ---------------------------------------------

async function anEmptiedListKeepsTheFloor(ports, caPem, reader, identity, cleared, to) {
  var shown = await identity.credentials.show(cleared.id);
  count("the emptied credential's stored refusal list holds nothing",
    Array.isArray(shown.refusedLocalParts) && shown.refusedLocalParts.length === 0,
    JSON.stringify(shown.refusedLocalParts));

  var postmaster = await authorOverSendRoute(reader, cleared.token, at("postmaster"), to);
  var route      = await authorOverSendRoute(reader, cleared.token, at(EARLY_OPERATOR), to);
  var envelope   = await messageOverSubmission(ports, caPem, cleared.token, {
    label: "cleared-envelope", envelopeFrom: at(EARLY_OPERATOR), from: at(EARLY_OPERATOR),
    to: to });

  console.log("  measured: cleared route/postmaster=" + postmaster.status +
    " route/operator=" + route.status + " submission/operator=" + envelope.at);

  count("an emptied list permits postmaster, so the list being read is the emptied one",
    postmaster.status === 202, "status " + postmaster.status + ": " + postmaster.body);
  count("and the sending route still refuses an operator mailbox, because emptying the " +
    "list does not lift the operator-role refusal",
    route.status === 403, "status " + route.status + ": " + route.body);
  count("and the submission listener refuses the same operator mailbox as the envelope sender",
    envelope.accepted === false && envelope.at === "envelope", JSON.stringify(envelope));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sendcred-operator-floor");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "operator role floor test" });

    var bob = await identity.accounts.create({ address: at("bob"), password: BOB_PASSWORD });
    await identity.accounts.create({ address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });
    await identity.accounts.create({
      address: at(EARLY_OPERATOR), password: ADMIN_PASSWORD, isAdmin: true });
    var carol = await identity.accounts.create({ address: at(CAROL), password: CAROL_PASSWORD });
    var frank = await identity.accounts.create({ address: at(FRANK), password: FRANK_PASSWORD });

    var made = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the shop front sends receipts",
      maxMessages:   100,
      maxRecipients: 200,
    });
    var cleared = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the helpdesk answers as postmaster and abuse",
      maxMessages:   100,
      maxRecipients: 200,
    });
    await identity.credentials.setRefusedLocalParts({
      id: cleared.id, localParts: [], reason: "the helpdesk answers as postmaster and abuse" });

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

    var ports = { submission: sections.submission.port };
    var bound = server.web.bound();
    var reader = browser.browserAt("https://" + LOOPBACK + ":" + bound.https, {
      ca: material.caPem, servername: HOSTNAME });

    await aRoleGrantedAfterIssuance(ports, material.caPem, reader, identity, made, carol,
      bob.address);
    await oneSessionAcrossTheRoleChanging(ports, material.caPem, identity, made, frank);
    await anEmptiedListKeepsTheFloor(ports, material.caPem, reader, identity, cleared,
      bob.address);

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
  name:      "sending-credential-operator-role-floor",
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
