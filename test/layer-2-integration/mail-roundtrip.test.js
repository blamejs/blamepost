// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The thing a mail server is for: a message arrives from outside, and
 * the person it was addressed to reads it.
 *
 * Nothing else in the suite covers that end to end. Cases either drive
 * the store through a function call, or open a socket and stop at
 * authentication. Both halves have been green while the path between
 * them was broken, which is how five defects that lost mail reached a
 * 662 check run, and how the entire outbound path stayed broken under
 * 839. A test that never delivers a message cannot notice that
 * delivering a message does not work.
 *
 * So this one is a peer and then a client, on real sockets, and it
 * asserts on what each of them is told:
 *
 *   - A peer connects to the MX port, upgrades with STARTTLS, and is
 *     answered at every step of RFC 5321: 220 on the banner, 250 to
 *     EHLO, MAIL and RCPT, 354 to DATA, 250 after the terminating dot.
 *   - The recipient then signs in on the IMAP port as an ordinary
 *     client, selects INBOX, and finds that message with the body that
 *     was sent. The name is the interesting part: a client says INBOX,
 *     the store holds a physical folder whose name it never sees, and
 *     the translation between them is where isolation lives.
 *   - A peer offering an address this server does not host is never
 *     answered with a 250. Accepting mail and then discarding it is the
 *     failure the wire-protocol rule exists to prevent: a sender is
 *     told the message arrived and nobody ever sees it. The case says
 *     where the refusal lands today and why it is not the 550 the RFC
 *     would rather have.
 *
 * Message authentication is deliberately in monitor rather than enforce
 * for this run. The gate resolves SPF and DMARC against live DNS at the
 * end of DATA, and this process has no resolver, so enforce mode defers
 * on a temporary error and the run would be measuring the absence of
 * DNS rather than the delivery path. What that gate does with a real
 * answer belongs to a case that can give it one.
 *
 * Run standalone: node test/layer-2-integration/mail-roundtrip.test.js
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
var PEER     = "sender@example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Distinctive enough that finding it in a FETCH response means the
// bytes traveled rather than that something plausible was rebuilt.
var SUBJECT = "Roundtrip probe 8fa21c";
var BODY    = "The body that was sent, marker 4d91e07b.";

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// ---- the peer --------------------------------------------------------------

// An MX session raised to TLS and sitting where a peer announces its
// envelope. A real peer upgrades when the banner offers it, so this
// does too rather than taking a plaintext shortcut no MTA would.
async function mxSession(port, caPem, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^220 /m, "banner");
  session.send("EHLO peer.example.net");
  await session.read(/^250 /m, "EHLO accepted");
  session.send("STARTTLS");
  await session.read(/^220 /m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("EHLO peer.example.net");
  await session.read(/^250 /m, "EHLO accepted over TLS");
  return session;
}

// ---- the client ------------------------------------------------------------

// An IMAP session raised to TLS and authenticated as one account, which
// is where a mail client starts every time it checks for mail.
async function imapSession(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, ALICE_PASSWORD));
  await session.read(/^a1 OK/m, "authenticated");
  return session;
}

// ---- cases -----------------------------------------------------------------

async function aMessageArrivesAndIsRead(ports, caPem, address) {
  var peer = await mxSession(ports.mx, caPem, "mx-accept");

  peer.send("MAIL FROM:<" + PEER + ">");
  var mailReply = await peer.read(/^\d{3} /m, "MAIL FROM answered");
  count("the peer's envelope sender is accepted", /^250 /m.test(mailReply), visible(mailReply));

  peer.send("RCPT TO:<" + address + ">");
  var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  count("a recipient this server hosts is accepted", /^250 /m.test(rcptReply), visible(rcptReply));

  peer.send("DATA");
  var dataReply = await peer.read(/^\d{3} /m, "DATA answered");
  count("the peer is invited to send the message", /^354 /m.test(dataReply), visible(dataReply));

  // The message, then the RFC 5321 section 4.5.2 terminator. Written as
  // one payload with its own framing, because the dot is part of the
  // protocol rather than a line of the message.
  var message = [
    "From: " + PEER,
    "To: " + address,
    "Subject: " + SUBJECT,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <roundtrip-8fa21c@example.net>",
    "",
    BODY,
    "",
  ].join("\r\n");
  peer.sendRaw(message + ".\r\n", "<the message and its terminating dot>");

  var accepted = await peer.read(/^\d{3} /m, "message answered");
  count("the message is accepted once the dot arrives",
    /^250 /m.test(accepted), visible(accepted));
  peer.send("QUIT");
  peer.close();

  // Now the other half: the account this was addressed to opens its
  // mailbox the way any client would and looks for it.
  var client = await imapSession(ports.imap, caPem, address, "imap-read");

  client.send("a2 SELECT INBOX");
  var selected = await client.read(/^a2 (OK|NO|BAD)/m, "SELECT answered");
  count("the recipient can select INBOX by the name a client uses",
    /^a2 OK/m.test(selected), visible(selected));
  count("and the mailbox reports the message that just arrived",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  client.send("a3 FETCH 1 BODY[]");
  var fetched = await client.read(/^a3 (OK|NO|BAD)/m, "FETCH answered");
  count("the fetch succeeds", /^a3 OK/m.test(fetched), visible(fetched));
  count("the subject that was sent is the subject that is read",
    fetched.indexOf(SUBJECT) !== -1, visible(fetched));
  count("and the body survived the trip intact",
    fetched.indexOf(BODY) !== -1, visible(fetched));

  client.send("a4 LOGOUT");
  client.close();
}

// A message for a mailbox that does not exist here must not be answered
// with a 250. The peer would consider it delivered, and the report that
// should tell the sender cannot be sent, so the message would be gone
// with nobody informed.
//
// The refusal lands at the end of DATA rather than at RCPT, and it is
// transient rather than permanent, because that is the loudest answer
// this composition can reach. The framework's MX listener refuses
// another domain at RCPT from its `localDomains` list, but it has no
// hook for the per address question, and the only refusal its agent
// handoff can produce is `451 4.3.0`. A peer holding a 451 still has the
// message: it retries, gives up on its own schedule, and reports back to
// the sender.
//
// So this pins two things. The wrong answer, 250, is refused outright.
// The right answer, 550 at RCPT, needs a hook the MX listener does not
// have, which is filed as blamejs#630. When it lands this case tightens
// rather than changes: same claim, earlier and permanent, and the branch
// below already takes that answer if it starts arriving.
async function anUnknownRecipientIsNeverAccepted(ports, caPem) {
  var peer = await mxSession(ports.mx, caPem, "mx-refuse");

  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");

  peer.send("RCPT TO:<nobody@" + DOMAIN + ">");
  var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");

  // A permanent refusal here would be the better outcome, so accept it
  // if a framework release starts providing one, and go on to check the
  // rest only while it does not.
  if (/^550 /m.test(rcptReply)) {
    count("an address this server does not host is refused at RCPT", true, visible(rcptReply));
    peer.send("QUIT");
    peer.close();
    return;
  }

  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw([
    "From: " + PEER,
    "To: nobody@" + DOMAIN,
    "Subject: for a mailbox that is not here",
    "",
    "body",
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");

  var verdict = await peer.read(/^\d{3} /m, "message answered");
  count("a message for a mailbox that does not exist is never accepted",
    !/^250 /m.test(verdict), visible(verdict));
  count("the peer is told to keep the message and try again",
    /^4\d\d /m.test(verdict), visible(verdict));

  peer.send("QUIT");
  peer.close();
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("roundtrip");
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
        // The MX listener refuses to bind until an operator says the
        // zone is live. Both halves are required, the server wide
        // variable here and the per domain row below, so a domain added
        // after the acknowledgement cannot inherit it.
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    // Given back before the directory under it goes, whichever way this
    // run ends. A database handle still open while its files are removed
    // is a locked file on Windows and a teardown rejection on Linux, and
    // either one lands on top of the verdict this run had already
    // reached.
    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "roundtrip test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
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

    var ports = { mx: sections.mx.port, imap: sections.imap.port };

    await aMessageArrivesAndIsRead(ports, leaf.ca, alice.address);
    await anUnknownRecipientIsNeverAccepted(ports, leaf.ca);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "mail-roundtrip", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
