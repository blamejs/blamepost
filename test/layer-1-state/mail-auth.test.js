// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Signing in, over the wire, the way a mail client signs in.
 *
 * A mail client reaches this server through one door: SASL PLAIN over
 * TLS. Everything else in the suite drives the store or the listener
 * table directly, which is a view no client has. This file opens a
 * socket, negotiates TLS with a certificate minted for the run, and
 * spells out the AUTHENTICATE exchange byte for byte.
 *
 * What it pins:
 *
 *   - A client that carries its credentials on the AUTHENTICATE line
 *     is authenticated. RFC 9051 section 6.2.2 makes that argument
 *     optional rather than an extension, so an IMAP4rev2 listener
 *     answers it without any capability beside it.
 *   - A client that leaves the credentials off is asked for them and
 *     authenticated when it answers. This is the form a client picks
 *     when it will not use an argument it has not seen advertised,
 *     and before this exchange existed it was the form that could
 *     never reach a mailbox.
 *   - Being asked changes no verdict. A wrong password, a withdrawn
 *     exchange, an empty answer and an authorization identity that is
 *     not the authentication identity are all refused on the second
 *     line exactly as they are on the first.
 *   - One challenge per exchange. A client that answers with nothing
 *     is refused rather than asked again, so an idle socket cannot
 *     trade empty lines with the server forever.
 *   - Submission answers the same two shapes on its own reply codes,
 *     `334` and `235`, per RFC 4954 section 4.
 *
 * ManageSieve is the exception, and the reason is in the vendored
 * tree rather than here. Its listener reads one verdict from the
 * verifier and has nowhere to put a challenge
 * (`mail-server-managesieve.js`, `_completeAuthenticate`), and its
 * command validator returns the mechanism without the quoted initial
 * response beside it (`guard-managesieve-command.js`,
 * `_validateAuthenticate`), so a client that quotes its credentials
 * arrives at the verifier with nothing to verify. The one spelling
 * that carries credentials all the way through is the literal, and
 * that is what this file drives.
 *
 * The verifier this repository hands that listener never asks for
 * credentials, because the ask would come back to the client as the
 * refusal that spends its attempt. That choice is not visible from
 * the wire: the listener answers `NO` either way. What the wire can
 * show, and what this file asserts, is that the exchange ends on one
 * reply and that the reply is a verdict.
 *
 * The certificate is issued for this run by the framework's own CA
 * and never leaves the temporary directory. The client verifies the
 * chain against it rather than skipping verification, so the
 * handshake under test is a real one.
 *
 * Run standalone: node test/layer-1-state/mail-auth.test.js
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

var count = helpers.count;

// The socket machinery is shared with the layer 2 round trip, so both
// files agree on what a greeting looks like and on how a read that
// never arrives reports itself.
var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var WRONG_PASSWORD   = "not the password alice set 8830";

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var LOOPBACK = "127.0.0.1";

// RFC 4616 separates the three SASL PLAIN fields with NUL. Written as
// its code point so this file carries no control byte of its own.
var NUL = String.fromCharCode(0);

// How long shutdown is given to drain the listeners before the run
// gives up on it. The budget a wire read gets is the shared helper's
// business, not this file's.
var SHUTDOWN_TIMEOUT_MS = 5000;

// The base64 SASL PLAIN response: empty authorization identity, the
// address, the password. RFC 4616 section 2, and the shared helper owns
// it because every authenticating wire file needs the same three bytes
// in the same order.
var plainResponse = wire.saslPlain;

// ---- sessions --------------------------------------------------------------

// Each session is raised to TLS and left at exactly the point where a
// client authenticates, because the authentication exchange is what
// this file is about and a ladder that signed in would have already
// spent it. The ladders themselves belong to the shared socket helper:
// every wire file climbs the same three, and a second copy is how two
// of them start disagreeing about what a greeting looks like.
function imapSession(port, caPem, label) {
  return Wire.imap(port, { caPem: caPem, servername: HOSTNAME, label: label });
}

function submissionSession(port, caPem, label) {
  return Wire.submission(port, { caPem: caPem, servername: HOSTNAME, label: label });
}

function sieveSession(port, caPem, label) {
  return Wire.managesieve(port, { caPem: caPem, servername: HOSTNAME, label: label });
}

// ---- the exchanges ---------------------------------------------------------

// The regression. A client that will not use an argument it has not
// seen advertised sends the mechanism alone and waits. Before the
// verifier could ask for credentials, this exchange ended in a
// refusal and the account had no way in at all.
async function testChallengedExchangeAuthenticates(port, caPem, address) {
  var wire = await imapSession(port, caPem, "imap-challenged");
  wire.send("x1 AUTHENTICATE PLAIN");
  var challenge = await wire.read(/^\+ ?\r\n|^x1 (NO|BAD)/m, "the challenge");
  count("AUTHENTICATE with no credentials on the line is answered with a challenge",
    /^\+ ?\r\n/.test(challenge), visible(challenge));

  wire.send(plainResponse(address, ALICE_PASSWORD));
  var verdict = await wire.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  count("the credentials sent in answer to the challenge authenticate the account",
    /^x1 OK/m.test(verdict), visible(verdict));
  count("the session is authenticated rather than merely not refused",
    verdict.indexOf("AUTHENTICATE completed") !== -1, visible(verdict));
  wire.close();
  return wire.transcript();
}

// The same exchange with the wrong password. Being asked for
// credentials must not soften what happens to bad ones.
async function testChallengedExchangeRefusesWrongPassword(port, caPem, address) {
  var wire = await imapSession(port, caPem, "imap-challenged-wrong");
  wire.send("x1 AUTHENTICATE PLAIN");
  await wire.read(/^\+ ?\r\n/, "the challenge");
  wire.send(plainResponse(address, WRONG_PASSWORD));
  var verdict = await wire.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  count("a wrong password answered into the challenge is refused",
    /^x1 NO/m.test(verdict), visible(verdict));
  wire.close();
}

// The inline form, which RFC 9051 section 6.2.2 carries as an optional
// argument of the base protocol rather than as an extension.
async function testInlineExchangeAuthenticates(port, caPem, address) {
  var wire = await imapSession(port, caPem, "imap-inline");
  wire.send("x1 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
  var verdict = await wire.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  count("credentials carried on the AUTHENTICATE line authenticate the account",
    /^x1 OK/m.test(verdict), visible(verdict));
  wire.close();
  return wire.transcript();
}

async function testInlineExchangeRefusesWrongPassword(port, caPem, address) {
  var wire = await imapSession(port, caPem, "imap-inline-wrong");
  wire.send("x1 AUTHENTICATE PLAIN " + plainResponse(address, WRONG_PASSWORD));
  var verdict = await wire.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  count("a wrong password carried on the line is refused",
    /^x1 NO/m.test(verdict), visible(verdict));
  wire.close();
}

// RFC 9051 section 6.2.2 lets a client withdraw an exchange it has
// started by sending a single asterisk. The exchange has to end, and
// the connection has to stay usable, or a client that changed its mind
// would have to reconnect to try again.
async function testCancelledExchangeEndsAndTheSessionSurvives(port, caPem, address) {
  var wire = await imapSession(port, caPem, "imap-cancelled");
  wire.send("x1 AUTHENTICATE PLAIN");
  await wire.read(/^\+ ?\r\n/, "the challenge");
  wire.send("*");
  var verdict = await wire.read(/^x1 (OK|NO|BAD)/m, "the verdict on the withdrawn exchange");
  count("an exchange the client withdraws ends without authenticating",
    /^x1 (NO|BAD)/m.test(verdict), visible(verdict));

  wire.send("x2 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
  var second = await wire.read(/^x2 (OK|NO|BAD)/m, "the verdict on the second attempt");
  count("the connection is still usable, so the client can start a new exchange",
    /^x2 OK/m.test(second), visible(second));
  wire.close();
}

// One challenge per exchange. A client that answers with nothing gets
// a verdict rather than another challenge: the alternative is a socket
// where the two sides trade empty lines until the idle timeout.
async function testEmptyAnswerIsRefusedRatherThanChallengedAgain(port, caPem) {
  var wire = await imapSession(port, caPem, "imap-empty-answer");
  wire.send("x1 AUTHENTICATE PLAIN");
  await wire.read(/^\+ ?\r\n/, "the challenge");
  wire.send("");
  // Read until the tagged answer rather than for a fixed window, so a
  // slow verdict is not read as no verdict. A second challenge in its
  // place never ends the read, and the read's own deadline fails it.
  var after = await wire.read(/^x1 [^\r\n]*\r\n/m, "the tagged answer to the empty response");
  count("an empty answer is refused", /^x1 (NO|BAD)/m.test(after), visible(after));
  count("and it draws no second challenge", after.indexOf("+ ") === -1, visible(after));
  wire.close();
}

// The authorization identity is the account a client asks to act as.
// This server grants nobody that, and being asked for the credentials
// rather than reading them off the line changes nothing about it.
async function testProxyAuthorizationIsRefusedInsideTheExchange(port, caPem, address) {
  var wire = await imapSession(port, caPem, "imap-proxy-auth");
  wire.send("x1 AUTHENTICATE PLAIN");
  await wire.read(/^\+ ?\r\n/, "the challenge");
  var response = Buffer.from(
    "postmaster@" + DOMAIN + NUL + address + NUL + ALICE_PASSWORD, "utf8").toString("base64");
  wire.sendRaw(response + "\r\n", "<response naming a second identity>");
  var verdict = await wire.read(/^x1 (OK|NO|BAD)/m, "the verdict");
  count("a response asking to act as another account is refused",
    /^x1 NO/m.test(verdict), visible(verdict));
  wire.close();
}

// Submission runs the same two shapes on RFC 4954's reply codes.
async function testSubmissionChallengedExchangeAuthenticates(port, caPem, address) {
  var wire = await submissionSession(port, caPem, "submission-challenged");
  wire.send("AUTH PLAIN");
  var challenge = await wire.read(/^(334|535|501|503)/m, "the challenge");
  count("AUTH with no credentials on the line is answered with 334",
    /^334/m.test(challenge), visible(challenge));

  wire.send(plainResponse(address, ALICE_PASSWORD));
  var verdict = await wire.read(/^(235|535)/m, "the verdict");
  count("the credentials sent in answer to 334 authenticate the account",
    /^235/m.test(verdict), visible(verdict));
  wire.close();
  return wire.transcript();
}

async function testSubmissionInlineExchangeAuthenticates(port, caPem, address) {
  var wire = await submissionSession(port, caPem, "submission-inline");
  wire.send("AUTH PLAIN " + plainResponse(address, ALICE_PASSWORD));
  var verdict = await wire.read(/^(235|535)/m, "the verdict");
  count("credentials carried on the AUTH line authenticate the account",
    /^235/m.test(verdict), visible(verdict));
  wire.close();
}

// ManageSieve carries its initial response as a literal: the octet
// count on the AUTHENTICATE line, the base64 on the line after it.
async function testSieveLiteralExchangeAuthenticates(port, caPem, address) {
  var wire = await sieveSession(port, caPem, "sieve-literal");
  var response = plainResponse(address, ALICE_PASSWORD);
  wire.send('AUTHENTICATE "PLAIN" {' + Buffer.byteLength(response, "utf8") + "+}");
  wire.sendRaw(response + "\r\n", "<base64 response>");
  // Read until the verdict arrives rather than for a fixed window: the
  // password check is an Argon2id derivation, and how long it takes
  // depends on the host.
  var said = await wire.read(/^(OK|NO|BYE)[^\r\n]*\r\n/m, "the verdict on the exchange");
  count("a ManageSieve client that sends its credentials as a literal is authenticated",
    said.indexOf('OK "Authenticated"') !== -1, visible(said));
  wire.close();
  return wire.transcript();
}

// A ManageSieve exchange that carries no credentials is asked for
// them. RFC 5804 section 2.1 writes the server's challenge as a
// literal, so the empty ask PLAIN needs reaches the client as a
// zero-length one, and the credential travels on the line after it.
//
// The alternative a listener can reach for is a refusal, and it is
// costly rather than merely unhelpful: RFC 2449 keeps a per-account
// failure budget behind this verb, so refusing a normal round trip
// spends the defense that budget exists to provide and lets a client
// following the specification lock out its own account holder.
async function testSieveNoInitialResponseIsChallenged(port, caPem, address) {
  var wire = await sieveSession(port, caPem, "sieve-no-initial-response");
  wire.send('AUTHENTICATE "PLAIN"');
  var invitation = await wire.read(/^(?:\{0\}|OK|NO|BYE)/m, "the answer to a bare AUTHENTICATE");
  count("AUTHENTICATE with no initial response is asked for one rather than refused",
    /^\{0\}\r\n\r\n/m.test(invitation), visible(invitation));

  wire.send('"' + plainResponse(address, ALICE_PASSWORD) + '"');
  var verdict = await wire.read(/^(OK|NO|BYE)/m, "the verdict");
  count("and the credential sent in answer to it authenticates the account",
    /^OK/.test(verdict), visible(verdict));
  wire.close();
}

// ---- a credential offered before TLS ---------------------------------------

// The property every session ladder in this suite rests on, and the one
// no ladder can show. `test/helpers/wire.js` states it outright: every
// listener here refuses a credential before TLS, which is exactly why
// each ladder upgrades before it authenticates. That arrangement means
// the absence of the property could never surface from a ladder, since
// no ladder ever offers a credential in the clear.
//
// It is also what stands behind the operator posture that a TCP
// terminator in front of one of these ports is not a route to it: the
// listener is handed a plaintext connection and refuses every
// credential. A listener that stopped doing so would put an address
// check between a password and the wire.
//
// The credential offered is alice's REAL one, so a listener that had
// stopped refusing would sign her in over the clear rather than fail
// for some unrelated reason. Each protocol is asked in its own
// spelling and each answer is pinned to that protocol's refusal rather
// than to "not success", so a listener that closed the socket, timed
// out, or answered a parse error fails here rather than passes.
var BEFORE_TLS_VECTORS = [
  {
    name:    "IMAP",
    // RFC 9051 section 6.2.2. A command the server will not run in this
    // state is a protocol error, which is BAD.
    offer:   function (session, address) {
      session.send("x1 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
      return session.read(/^x1 (OK|NO|BAD)/m, "the answer to a credential before TLS");
    },
    refused: /^x1 BAD/m,
    says:    "BAD",
    signedIn: /^x1 OK/m,
  },
  {
    name:    "submission",
    // RFC 3207 section 4: a server that requires STARTTLS answers 530
    // to anything else. RFC 4954 section 4 routes AUTH into the same
    // refusal.
    offer:   async function (session, address) {
      session.send("EHLO client.example.net");
      await session.read(/^250 /m, "EHLO accepted in the clear");
      session.send("AUTH PLAIN " + plainResponse(address, ALICE_PASSWORD));
      return session.read(/^\d{3}[ -]/m, "the answer to a credential before TLS");
    },
    // Pinned to the exact code rather than to any 5xx, because this is
    // the one THREAT-MODEL.md names for the case and the value of a
    // wire code is that somebody can filter on it.
    refused: /^538 5\.7\.11 /m,
    says:    "538 5.7.11, the code named for this refusal",
    signedIn: /^235 /m,
  },
  {
    name:    "POP3",
    // RFC 2595 section 4: the credential commands are unavailable until
    // STLS has run, and POP3 spells every refusal -ERR.
    offer:   async function (session, address) {
      session.send("USER " + address);
      await session.read(/^(\+OK|-ERR)/m, "USER answered in the clear");
      session.send("PASS " + ALICE_PASSWORD);
      return session.read(/^(\+OK|-ERR)/m, "the answer to a credential before TLS");
    },
    refused: /^-ERR/m,
    says:    "-ERR",
    signedIn: /^\+OK/m,
  },
  {
    name:    "ManageSieve",
    // RFC 5804 section 2.2. The literal is the one spelling that
    // carries credentials all the way through this listener, which is
    // why it is the one offered here.
    offer:   function (session, address) {
      var response = plainResponse(address, ALICE_PASSWORD);
      session.sendNonSyncLiteral('AUTHENTICATE "PLAIN"', response, "<the SASL response>");
      return session.read(/^(OK|NO|BYE)/m, "the answer to a credential before TLS");
    },
    refused: /^(NO|BYE)/m,
    says:    "NO or BYE",
    signedIn: /^OK/m,
  },
];

// The greeting each listener writes before anything is asked of it.
// Read and discarded, so the answer a vector asserts on is the answer
// to the credential rather than the banner still sitting in the buffer.
var BEFORE_TLS_GREETINGS = {
  IMAP:        /^\* OK \[CAPABILITY[^\r\n]*\r\n/,
  submission:  /^220 /m,
  POP3:        /^\+OK /m,
  ManageSieve: /^OK[^\r\n]*\r\n/m,
};

async function testACredentialOfferedBeforeTlsIsRefused(ports, address) {
  var transcripts = [];
  for (var i = 0; i < BEFORE_TLS_VECTORS.length; i += 1) {
    var vector  = BEFORE_TLS_VECTORS[i];
    var session = await Wire.connect(ports[vector.name], vector.name + "-before-tls");
    try {
      await session.read(BEFORE_TLS_GREETINGS[vector.name], "greeting in the clear");
      var reply = await vector.offer(session, address);
      count(vector.name + " refuses a credential on an unencrypted session, so a plaintext " +
        "connection reaching this port is not a route to an account",
        !vector.signedIn.test(reply), visible(reply));
      count("and " + vector.name + " says so with " + vector.says + ", its own refusal, " +
        "rather than by closing the socket or timing out",
        vector.refused.test(reply), visible(reply));
      count("and the refusal tells the client to negotiate TLS rather than leaving it to " +
        "guess why a correct password failed",
        /TLS|STARTTLS|STLS|encrypt/i.test(reply), visible(reply));
      transcripts.push(vector.name + ":\n" + session.transcript());
    } finally {
      session.close();
    }
  }
  return transcripts.join("\n\n");
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("auth");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory backed directory and reads this variable to find it. Pointing
  // it inside the test's own temporary tree keeps the encrypted at rest
  // path exactly as it ships rather than opting the test out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

  try {
    // A certificate for this run, issued by the framework's own CA into
    // the temporary tree. The listeners require TLS before they will
    // read credentials, which is the posture under test rather than
    // something to work around, so the run needs a real one.
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      // The classical bridge rather than the CA default. This
      // certificate exists to make a node:tls handshake happen on the
      // loopback interface, and node verifies this algorithm on every
      // runtime the suite runs on.
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
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    // The three listeners a client authenticates against. Inbound mail
    // takes no credentials and is left unbound, which also keeps the
    // DNS posture gate out of a run that is not about it.
    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      // Bound for the before-TLS case below. Its credential exchange is
      // two commands rather than one, and it is the second listener
      // this server offers to a client that can only reach it through
      // something terminating TLS in front of the port.
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config:       Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var imapPort  = sections.imap.port;
    var smtpPort  = sections.submission.port;
    var sievePort = sections.managesieve.port;

    var challenged = await testChallengedExchangeAuthenticates(imapPort, leaf.ca, alice.address);
    await testChallengedExchangeRefusesWrongPassword(imapPort, leaf.ca, alice.address);
    var inline = await testInlineExchangeAuthenticates(imapPort, leaf.ca, alice.address);
    await testInlineExchangeRefusesWrongPassword(imapPort, leaf.ca, alice.address);
    await testCancelledExchangeEndsAndTheSessionSurvives(imapPort, leaf.ca, alice.address);
    await testEmptyAnswerIsRefusedRatherThanChallengedAgain(imapPort, leaf.ca);
    await testProxyAuthorizationIsRefusedInsideTheExchange(imapPort, leaf.ca, alice.address);

    var smtpChallenged = await testSubmissionChallengedExchangeAuthenticates(
      smtpPort, leaf.ca, alice.address);
    await testSubmissionInlineExchangeAuthenticates(smtpPort, leaf.ca, alice.address);

    var sieveLiteral = await testSieveLiteralExchangeAuthenticates(
      sievePort, leaf.ca, alice.address);
    await testSieveNoInitialResponseIsChallenged(sievePort, leaf.ca, alice.address);

    var beforeTls = await testACredentialOfferedBeforeTlsIsRefused({
      IMAP:        imapPort,
      submission:  smtpPort,
      POP3:        sections.pop3.port,
      ManageSieve: sievePort,
    }, alice.address);

    // The transcripts of the exchanges that authenticate, so a run's
    // log shows the wire rather than only the verdict.
    console.log("\nIMAP, credentials asked for:\n" + challenged);
    console.log("\nIMAP, credentials on the line:\n" + inline);
    console.log("\nSubmission, credentials asked for:\n" + smtpChallenged);
    console.log("\nManageSieve, credentials as a literal:\n" + sieveLiteral);
    console.log("\nA credential offered before TLS, on every listener that takes one:\n" +
      beforeTls);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = { name: "mail-auth", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
