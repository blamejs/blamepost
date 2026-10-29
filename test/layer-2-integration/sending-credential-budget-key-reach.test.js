// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Who can reach a sending credential's failure budget, and what they
 * have to hold to reach it.
 *
 * The budget is keyed on the identifier inside a presented token paired
 * with the peer that presented it.
 * `blamepost.mail.listeners.verifySendingCredential` reads that
 * identifier out of the token BEFORE the secret is checked, which is
 * what lets a wrong secret be charged to the credential it was offered
 * for. The identifier names a row and is not a secret, and the module
 * that issues it says so.
 *
 * Two separate things therefore have to hold, and this file drives both
 * against a running server.
 *
 * The first is that the identifier is not published. A credential's
 * bounces come back to a return path this server mints for it, and
 * `POST /api/send` puts that address in the envelope sender of every
 * message the credential sends that does not name one of its own, so the
 * RFC 5233 tag on it reaches every recipient the application writes to.
 * `blamepost.store.credentials` derives that tag from the identifier
 * under the deployment's vault-sealed key rather than writing the
 * identifier into it, so what the recipients hold is a tag that names no
 * credential the budget is keyed on.
 *
 * The second is that even the identifier itself is not a lever. It
 * reaches an operator through the audit trail, through the command line
 * and through a credential listing, so a value that has been written
 * down is a value that can get out. Pairing the budget key with the peer
 * means a run of guesses locks the address that made them and no other
 * address, so the application goes on sending from its own.
 *
 * `test/layer-2-integration/api-send-credential-parity.test.js` already
 * spends this budget, but it builds its guesses out of the REAL token,
 * which is the shape of an attacker who already has the secret. Nothing
 * else in the tree asks what a party holding only a published value can
 * do.
 *
 * ## What this file drives
 *
 * Two credentials in one hosted domain, so a refusal can be told apart
 * from a server that has stopped answering.
 *
 *   - The tag on the published return path is NOT the identifier the
 *     budget is keyed on, and the identifier appears nowhere in the
 *     address. This is the setup fact, and it is asserted rather than
 *     assumed because the first half of the file rests on it.
 *   - Both credentials send before anything is spent.
 *   - A peer presents five tokens carrying the published tag and a
 *     secret it invented. Each is refused, which is correct.
 *   - The real credential is then asked to send on both transports. A
 *     party who has only ever received the application's mail must not
 *     be able to stop it sending.
 *   - The second credential in the same domain is asked the same
 *     question, so a refusal above is a targeted one rather than a
 *     server-wide outage.
 *   - Then a SECOND source address presents five tokens carrying the
 *     real identifier and invented secrets, and the application, dialing
 *     from its own address, still sends. A host that cannot hand this
 *     run a second source address names that and counts it as a skip.
 *
 * Every token used to attack is built from a published value or from the
 * identifier alone: the real secret is never read, never copied and
 * never derived from.
 *
 * Run standalone:
 *   node test/layer-2-integration/sending-credential-budget-key-reach.test.js
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
var saslPlain   = wire.saslPlain;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var BOB_PASSWORD     = "amber cascade thimble 7734";
var BOUNCE_PASSWORD  = "harbor kettle sundial 6620";

var BOUNCE_MAILBOX = "postbox@" + DOMAIN;

var SHUTDOWN_TIMEOUT_MS = 5000;

// A second address on this host's loopback interface, dialed out from so
// the listener reads a peer it can tell apart from the one the
// application uses. Linux and Windows carry the whole of 127.0.0.0/8 on
// loopback and a socket may bind any of it; a host that does not is
// named and counted as a skip rather than folded into the pass count.
var SECOND_SOURCE = "127.0.0.2";

// How many wrong secrets a credential absorbs on one peer before the
// failure budget locks that peer. It is `b.auth.lockout`'s own default,
// which the listener composes without naming a number of its own.
// Written here rather than read from the server, so a budget that
// stopped counting is a failure rather than an agreement.
var CREDENTIAL_BUDGET_ATTEMPTS = 5;

// A token built from nothing but a value the holder already has.
//
// The secret half is sixty four hexadecimal characters this file chose,
// which is the shape `blamepost.store.credentials` issues and therefore
// the shape `b.apiKey.parseFormat` reads. Nothing about it comes from
// the credential: the point of the file is what a party who has never
// seen the secret can do with the rest of the token.
function tokenAround(identifier, nonce) {
  var secret = "";
  var alphabet = "0123456789abcdef";
  for (var i = 0; i < 64; i += 1) {
    secret += alphabet[(i * 7 + nonce * 13) % alphabet.length];
  }
  return "bpk_send_" + identifier + "_" + secret;
}

// The tag on a return path, which is what this server publishes. Read
// out of the address rather than off the credential, so what the file
// attacks with is what an application's correspondent actually holds.
function tagFromReturnPath(returnPath) {
  var match = /^bounces\+([0-9a-f]+)@/.exec(String(returnPath));
  return match === null ? null : match[1];
}

// One message over the sending route, reported as accepted or not.
async function overSendRoute(reader, token, marker, bob) {
  var answer = await reader.post("/api/send", "application/json", JSON.stringify({
    from:    "shop@" + DOMAIN,
    to:      [bob],
    subject: marker,
    text:    "A message written by an application rather than by a person.",
  }), {
    "Authorization":   "Bearer " + token,
    "Idempotency-Key": marker,
    "Accept":          "application/json",
  });
  return { accepted: answer.status === 202, status: answer.status,
    reply: String(answer.body).slice(0, 200) };
}

// One AUTH exchange on the submission listener and nothing else.
async function authenticateOverSubmission(ports, caPem, secret, label) {
  var session = await Wire.submission(ports.submission, {
    caPem: caPem, servername: HOSTNAME, label: "budget-key-" + label,
  });
  try {
    session.send("AUTH PLAIN " + saslPlain(DOMAIN, secret));
    return await session.read(/^\d{3} /m, "AUTH answered");
  } finally {
    try { session.send("QUIT"); } catch (_e) { /* the socket is already gone */ }
    session.close();
  }
}

// The setup fact the first half of the file rests on: the value this
// server publishes is not the value the failure budget is keyed on.
function theTagIsNotTheIdentifier(target) {
  var published = tagFromReturnPath(target.returnPath);
  count("the credential's return path carries an RFC 5233 tag, which is what this server " +
    "writes into the envelope sender of the application's mail",
    published !== null, JSON.stringify(target.returnPath));

  count("and the tag is NOT the identifier the failure budget is keyed on, so a recipient " +
    "of the application's mail holds no key into that budget",
    published !== target.id, JSON.stringify(published) + " vs id " + JSON.stringify(target.id));

  count("and the identifier appears nowhere in the published address, so it cannot be read " +
    "back out of one a correspondent is holding",
    String(target.returnPath).indexOf(target.id) === -1, String(target.returnPath));

  count("and the registry hands the tag back beside the address, so an operator reading a " +
    "bounce can still say which credential produced it",
    target.returnPathTag === published, String(target.returnPathTag));

  return published;
}

// Both credentials work before anything is spent, so every refusal below
// is about what the spray did rather than about a credential that never
// sent.
async function bothCredentialsSendFirst(ports, caPem, reader, target, bystander, bob) {
  var targetFirst = await overSendRoute(reader, target.token, "budget-key-target-before", bob);
  count("the credential under attack sends before anything is spent",
    targetFirst.accepted, targetFirst.status + ": " + targetFirst.reply);

  var bystanderFirst = await overSendRoute(reader, bystander.token,
    "budget-key-bystander-before", bob);
  count("and so does the second credential in the same domain, which is the control",
    bystanderFirst.accepted, bystanderFirst.status + ": " + bystanderFirst.reply);

  var wire235 = await authenticateOverSubmission(ports, caPem, target.token, "target-before");
  count("the credential under attack also authenticates on the submission listener, so " +
    "both transports are live before the spray",
    /^235 /m.test(wire235), visible(wire235));
}

// The spray. Every token is built from the published tag and a secret
// this file invented.
async function aStrangerSpendsTheBudget(reader, published, bob) {
  for (var i = 0; i < CREDENTIAL_BUDGET_ATTEMPTS; i += 1) {
    var guess = await overSendRoute(reader, tokenAround(published, i + 1),
      "budget-key-spray-" + i, bob);
    count("a token carrying the published tag and an invented secret is refused " +
      "(attempt " + (i + 1) + " of " + CREDENTIAL_BUDGET_ATTEMPTS + "), which is correct " +
      "and is the whole of what the peer is entitled to learn",
      guess.status === 401, guess.status + ": " + guess.reply);
  }
}

// The claim. A party holding only the value this server published must
// not be able to stop the application sending.
//
// All three readings are TAKEN before any of them is asserted, for the
// reason `helpers.check` ends a run at the first failure: a file that
// asserted as it went would report one transport and leave the other and
// the control unmeasured, and the control is what says a refusal is
// targeted rather than a server that stopped answering.
async function theApplicationStillSends(ports, caPem, reader, target, bystander, bob) {
  var bystanderAfter = await overSendRoute(reader, bystander.token,
    "budget-key-bystander-after", bob);
  var routeAfter = await overSendRoute(reader, target.token, "budget-key-target-after", bob);
  var wireAfter = await authenticateOverSubmission(ports, caPem, target.token, "target-after");

  count("the second credential in the same domain still sends after the spray, so the " +
    "refusals below are targeted rather than a server that stopped answering",
    bystanderAfter.accepted, bystanderAfter.status + ": " + bystanderAfter.reply);

  count("the credential still authenticates on the submission listener while presenting " +
    "its CORRECT secret, which is the transport a sending application is most likely to " +
    "be configured for",
    /^235 /m.test(wireAfter), visible(wireAfter));

  count("and it still sends over the sending route, because a party who has only received " +
    "the application's mail holds a tag, and a tag names no credential the budget is " +
    "keyed on",
    routeAfter.accepted, routeAfter.status + ": " + routeAfter.reply);
}

// Whether this host will let the run dial out from a second address. The
// probe carries no credential at all, so it reaches the route's own
// refusal without touching any budget.
async function aSecondSourceIsAvailable(origin, caPem) {
  var reader = browser.browserAt(origin,
    { ca: caPem, servername: HOSTNAME, localAddress: SECOND_SOURCE });
  try {
    await reader.post("/api/send", "application/json", "{}", { "Accept": "application/json" });
    return reader;
  } catch (_bindError) {
    return null;
  }
}

// The second half. The identifier reaches operators through the audit
// trail, the command line and a credential listing, so a party who has
// one has it whether or not this server publishes it. Guessing with it
// has to cost that party their own address and nothing else.
async function aSecondPeerCannotStopTheApplication(ports, caPem, origin, reader, target, bob) {
  var stranger = await aSecondSourceIsAvailable(origin, caPem);
  if (stranger === null) {
    helpers.skip("this host would not let a socket dial out from " + SECOND_SOURCE + ", so " +
      "the run could not present a second source address and the claim that one peer's " +
      "lockout is not every peer's lockout could not be driven on the wire");
    return;
  }

  for (var i = 0; i < CREDENTIAL_BUDGET_ATTEMPTS; i += 1) {
    var guess = await overSendRoute(stranger, tokenAround(target.id, i + 21),
      "budget-key-second-peer-" + i, bob);
    count("a token carrying the credential's real IDENTIFIER and an invented secret is " +
      "refused when it comes from a second source address (attempt " + (i + 1) + " of " +
      CREDENTIAL_BUDGET_ATTEMPTS + ")",
      guess.status === 401, guess.status + ": " + guess.reply);
  }

  var strangerLocked = await overSendRoute(stranger, target.token,
    "budget-key-second-peer-settled", bob);
  count("and that source is then refused even holding the CORRECT secret, so the guessing " +
    "it did was counted rather than waved through",
    strangerLocked.status === 401, strangerLocked.status + ": " + strangerLocked.reply);

  var routeAfter = await overSendRoute(reader, target.token, "budget-key-own-source-after", bob);
  var wireAfter = await authenticateOverSubmission(ports, caPem, target.token, "own-source");

  count("the application, dialing from its own address, still sends over the sending route, " +
    "because the budget is keyed on the credential AND the peer and a lockout one address " +
    "earned is not a lockout for every address",
    routeAfter.accepted, routeAfter.status + ": " + routeAfter.reply);

  count("and it still authenticates on the submission listener from that address, so the " +
    "pairing holds on the transport the guessing was not done over",
    /^235 /m.test(wireAfter), visible(wireAfter));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("budget-key-reach");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "budget key reach test" });

    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD });
    await identity.accounts.create({
      address: BOUNCE_MAILBOX, password: BOUNCE_PASSWORD });

    var target = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "the shop front sends receipts",
      maxMessages:   50,
      maxRecipients: 100,
    });
    var bystander = await identity.credentials.create({
      domain:        DOMAIN,
      bounceMailbox: BOUNCE_MAILBOX,
      reason:        "a second application in the same domain",
      maxMessages:   50,
      maxRecipients: 100,
    });

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
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var ports = { submission: sections.submission.port };
    var bound = server.web.bound();
    count("the browser surface took a TLS port, which is the only one a credential may " +
      "be presented on",
      typeof bound.https === "number" && bound.https > 0, JSON.stringify(bound));

    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var reader = browser.browserAt(origin, { ca: material.caPem, servername: HOSTNAME });

    var published = theTagIsNotTheIdentifier(target);
    await bothCredentialsSendFirst(ports, material.caPem, reader, target, bystander,
      bob.address);
    await aStrangerSpendsTheBudget(reader, published, bob.address);
    await theApplicationStillSends(ports, material.caPem, reader, target, bystander,
      bob.address);
    await aSecondPeerCannotStopTheApplication(ports, material.caPem, origin, reader, target,
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
  name:      "sending-credential-budget-key-reach",
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
