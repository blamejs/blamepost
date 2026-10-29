// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The local parts a sending credential is held back from, measured after
 * the operator adds a mailbox rather than before.
 *
 * A credential speaks for every address at a hosted domain except the
 * ones its refusal list names, and that list starts as `postmaster`,
 * `abuse` and every mailbox in the domain carrying the operator role.
 * The operator-role half is derived from the accounts that exist when
 * the credential is issued.
 *
 * An operator adds mailboxes for as long as the domain is in service,
 * and a credential issued for an application in January is still sending
 * when an operator mailbox is added in June. This file asks whether the
 * credential is held back from that mailbox.
 *
 * Both transports are driven, because a credential reaches this server
 * two ways and one answer would say nothing about the other:
 *
 *   - `POST /api/send` writing the later operator mailbox as the author.
 *   - SMTP submission writing it as the envelope sender.
 *
 * The control beside them is a credential issued AFTER that mailbox
 * exists. It is refused, which is what says the refusal list works at all
 * and localizes the difference to WHEN the list was derived rather than
 * to whether it is consulted.
 *
 * `postmaster` and `abuse` are asked of both credentials as a second
 * control. They are constants rather than derived entries, so they are
 * refused whenever the credential was issued, and a run where either arm
 * also fails is a run where the refusal list is not being read at all.
 *
 * Both are asked, and on both transports. They are the two local parts
 * the shipped description of a sending credential names by hand, and a
 * pair held back by one line of the same list is a pair that can come
 * apart one entry at a time.
 *
 * Run standalone:
 *   node test/layer-2-integration/sending-credential-operator-refusal-currency.test.js
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

var BOUNCE_MAILBOX = "postbox@" + DOMAIN;

// The operator mailbox that exists before any credential is issued, and
// the one added afterwards. Both carry the operator role, and the only
// difference between them is the moment they were created.
var EARLY_OPERATOR = "earlyadmin";
var LATER_OPERATOR = "lateradmin";

var SHUTDOWN_TIMEOUT_MS = 5000;

var SMTP_ACCEPTED = /^250 /m;

// One message over the sending route, written as the given author.
async function authorOverSendRoute(reader, token, from, marker, to) {
  var body = JSON.stringify({
    from:    from,
    to:      [to],
    subject: marker,
    text:    "A message written by an application rather than by a person.",
  });
  var answer = await reader.post("/api/send", "application/json", body, {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": marker,
    "Accept":          "application/json",
  });
  return { status: answer.status, body: String(answer.body).slice(0, 300) };
}

// One envelope sender over SMTP submission. The reply to `MAIL FROM` is
// the whole answer, so the session stops there.
async function envelopeOverSubmission(ports, caPem, token, mailFrom, label) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "refusal-currency-" + label,
    address: DOMAIN, password: token,
  });
  try {
    session.send("MAIL FROM:<" + mailFrom + ">");
    var reply = await session.read(/^\d{3} /m, "MAIL FROM answered");
    return { accepted: SMTP_ACCEPTED.test(reply), reply: visible(reply) };
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// The credential issued before the later operator mailbox existed.
async function acredentialIssuedBeforeTheMailbox(ports, caPem, reader, token, to) {
  var early = EARLY_OPERATOR + "@" + DOMAIN;
  var later = LATER_OPERATOR + "@" + DOMAIN;
  var post  = "postmaster@" + DOMAIN;
  var abuse = "abuse@" + DOMAIN;

  // Every verdict is taken before any of them is asserted, so the log
  // carries both transports even though the first refused assertion ends
  // the run. A file that asserted as it went would report the route and
  // say nothing about the wire.
  var earlyAnswer = await authorOverSendRoute(
    reader, token, early, "refusal-currency-early-" + Date.now(), to);
  var postAnswer = await authorOverSendRoute(
    reader, token, post, "refusal-currency-postmaster-" + Date.now(), to);
  var abuseAnswer = await authorOverSendRoute(
    reader, token, abuse, "refusal-currency-abuse-" + Date.now(), to);
  var laterAnswer = await authorOverSendRoute(
    reader, token, later, "refusal-currency-later-" + Date.now(), to);
  var postEnvelope = await envelopeOverSubmission(
    ports, caPem, token, post, "postmaster-envelope");
  var abuseEnvelope = await envelopeOverSubmission(
    ports, caPem, token, abuse, "abuse-envelope");
  var laterEnvelope = await envelopeOverSubmission(
    ports, caPem, token, later, "later-envelope");

  console.log("  measured: route/early=" + earlyAnswer.status +
    " route/postmaster=" + postAnswer.status +
    " route/abuse=" + abuseAnswer.status +
    " route/later=" + laterAnswer.status +
    " submission/postmaster=" + (postEnvelope.accepted ? "accepted" : "refused") +
    " submission/abuse=" + (abuseEnvelope.accepted ? "accepted" : "refused") +
    " submission/later=" + (laterEnvelope.accepted ? "accepted" : "refused"));

  // The two controls first. A run where either of these fails is a run
  // where the refusal list is not being consulted, and the arms below
  // would be measuring nothing.
  count("a credential is refused the operator mailbox that existed when it was issued",
    earlyAnswer.status === 403,
    "status " + earlyAnswer.status + ": " + earlyAnswer.body);

  count("and it is refused postmaster, which is held back whenever the credential was issued",
    postAnswer.status === 403,
    "status " + postAnswer.status + ": " + postAnswer.body);

  count("and it is refused abuse, the other local part a credential is held back from " +
    "without an operator naming it",
    abuseAnswer.status === 403,
    "status " + abuseAnswer.status + ": " + abuseAnswer.body);

  count("and the submission listener refuses postmaster as an envelope sender, so the pair " +
    "is held back on the port an application presents a credential to as well as on the route",
    postEnvelope.accepted === false, postEnvelope.reply);

  count("and it refuses abuse there too, so neither half of the pair is held back on one " +
    "transport alone",
    abuseEnvelope.accepted === false, abuseEnvelope.reply);

  // The claim, on both transports. A fix that reaches one and not the
  // other is visible here rather than at the first message.
  count("and it is refused the operator mailbox added after it was issued, because a " +
    "mailbox that carries the operator role is one no credential may write as, whenever " +
    "the operator created it",
    laterAnswer.status === 403,
    "status " + laterAnswer.status + ": " + laterAnswer.body);

  count("and the submission listener refuses it as an envelope sender too, because both " +
    "transports read one refusal list",
    laterEnvelope.accepted === false, laterEnvelope.reply);
}

// The control credential, issued once the later operator mailbox exists.
// It is refused, which is what says the difference is the moment the list
// was derived rather than whether it is read.
async function acredentialIssuedAfterTheMailbox(reader, identity, to) {
  var made = await identity.credentials.create({
    domain:        DOMAIN,
    bounceMailbox: BOUNCE_MAILBOX,
    reason:        "a credential issued after the second operator mailbox exists",
    maxMessages:   100,
    maxRecipients: 200,
  });

  count("a credential issued after the mailbox exists starts with it on its refusal list",
    made.refusedLocalParts.indexOf(LATER_OPERATOR) !== -1,
    JSON.stringify(made.refusedLocalParts));

  var answer = await authorOverSendRoute(reader, made.token,
    LATER_OPERATOR + "@" + DOMAIN, "refusal-currency-control-" + Date.now(), to);
  count("and it is refused that author, so the refusal list is read on this transport",
    answer.status === 403,
    "status " + answer.status + ": " + answer.body);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sendcred-refusal-currency");
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
      domain: DOMAIN, by: "operator refusal currency test" });

    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    // The operator mailbox that exists first.
    await identity.accounts.create({
      address: EARLY_OPERATOR + "@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });

    var made = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the shop front sends receipts",
      maxMessages:   100,
      maxRecipients: 200,
    });

    count("the credential starts with the operator mailbox that already existed held back",
      made.refusedLocalParts.indexOf(EARLY_OPERATOR) !== -1,
      JSON.stringify(made.refusedLocalParts));

    // The operator adds a second operator mailbox, which is the ordinary
    // day-2 action this file is about.
    await identity.accounts.create({
      address: LATER_OPERATOR + "@" + DOMAIN, password: ADMIN_PASSWORD, isAdmin: true });

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

    await acredentialIssuedBeforeTheMailbox(
      ports, material.caPem, reader, made.token, bob.address);
    await acredentialIssuedAfterTheMailbox(reader, identity, bob.address);

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
  name:      "sending-credential-operator-refusal-currency",
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
