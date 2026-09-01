// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One message, two local recipients, and one of them cannot take it.
 *
 * SMTP gives a message one reply after DATA, not one per recipient, so
 * a server that has stored a message for some of the addresses on it
 * has already spent its only chance to say no. The comment above the
 * inbound handoff states the rule this creates and states it correctly:
 * only the case where NOTHING was stored may answer a temporary
 * failure, because a peer that retries re-sends the whole message and
 * every recipient who already has it gets another copy.
 *
 * The refusals the handoff collects itself follow that rule. A
 * recipient whose delivery THROWS does not: the exception leaves the
 * loop, leaves the handoff, and the listener answers `451 4.3.0` with
 * the earlier recipients' copies already on disk. A full mailbox is the
 * ordinary way to reach that, and a peer's retry schedule runs for
 * days.
 *
 * So this run addresses one message to two accounts on this server,
 * caps the second one so its append is refused, and sends the same
 * message twice, which is exactly what a peer does when it is told to
 * try again. What it asserts is the rule the comment already states:
 *
 *   - a recipient who could take the message has it once, and still has
 *     it once after the peer retried;
 *   - because a copy was stored, the peer is told the message was
 *     accepted, so there is no retry to duplicate anything;
 *   - the recipient who could not take it has nothing, which is the
 *     condition a report to the sender exists for.
 *
 * A full mailbox is the door that reaches the handoff, and it is the
 * only door left. An address with no mailbox behind it never gets that
 * far: the listener answers a name it does not hold with `550 5.1.1` at
 * RCPT, so the peer withdraws that recipient before it opens DATA and
 * there is nothing for the handoff to collect. That split is on purpose
 * and it runs on the status the condition carries. A mailbox that is
 * full or an account that is suspended is temporary, the owner can
 * clear it, and a permanent refusal on the wire would bounce their mail
 * for a condition that ends by itself, so those are still met at the
 * handoff exactly as before.
 *
 * Which leaves partial delivery with a second half to hold, and it is
 * the half a mailing list depends on. A refusal at RCPT is a verdict
 * about ONE recipient, not about the transaction: the message still
 * has to open DATA and reach everybody whose address is live. A
 * listener that dropped the whole envelope on the first closed address
 * would break every list that ever had a member leave.
 *
 * And the control, because a run that only proves the accepted case
 * would be satisfied by a server that accepts everything: when NO
 * recipient could be stored, the peer IS told to try again, and nothing
 * is on disk for the retry to duplicate.
 *
 * Run standalone: node test/layer-1-state/inbound-partial-delivery.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var dnsZone   = require("../helpers/dns-zone");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var Wire     = wire.Wire;
var LOOPBACK = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var TAKER_PASSWORD   = "quiet lantern bicycle 4291";
var FULL_PASSWORD    = "another quiet lantern 7715";

// The peer, and a sender its published policy authorizes from the
// connecting address. Message authentication runs in the shipped
// enforce mode, so the message has to earn its way past SPF and DMARC
// before it can reach the delivery this file is about.
var PEER_NAME = "peer.example.net";
var SENDER    = "sender@partner.example.net";

var ZONE = Object.freeze({
  "1.0.0.127.in-addr.arpa|PTR": [{ type: 12, decoded: PEER_NAME, ttl: 60 }],
  "peer.example.net|A":         [{ type: 1,  decoded: LOOPBACK,  ttl: 60 }],
  "partner.example.net|TXT": [
    { type: 16, decoded: ["v=spf1 ip4:" + LOOPBACK + " -all"], ttl: 60 },
  ],
  "_dmarc.partner.example.net|TXT": [
    { type: 16, decoded: ["v=DMARC1; p=reject; adkim=s; aspf=s"], ttl: 60 },
  ],
});

// A cap the message below crosses on its own, so the recipient that
// cannot take it is refused for a reason that does not depend on what
// else the run stored.
var CAP_BYTES = 4096;
var BODY_PAD  = 8192;

var SHUTDOWN_TIMEOUT_MS = 5000;

function peerMessage(recipient) {
  var body = new Array(BODY_PAD).join("x");
  return "Message-ID: <partial-delivery-1@partner.example.net>\r\n" +
    "From: Sender <" + SENDER + ">\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: One message for two mailboxes\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" + body + "\r\n";
}

function held(identity, account) {
  return identity.mailbox.selectFolder({ id: account.id }, "INBOX", {}).exists;
}

// One inbound message from a peer, over a real socket, to whatever
// recipients it is given. Returns what the peer was told at each step,
// which is the whole of what a real peer decides its next move from.
async function deliverFromAPeer(port, caPem, rcpts, label) {
  var peer = await Wire.mx(port, {
    caPem: caPem, servername: HOSTNAME, helo: PEER_NAME, label: label,
  });
  try {
    peer.send("MAIL FROM:<" + SENDER + ">");
    var mail = await peer.read(/^\d{3} /m, "MAIL FROM answered");
    var rcptReplies = [];
    for (var i = 0; i < rcpts.length; i += 1) {
      peer.send("RCPT TO:<" + rcpts[i] + ">");
      rcptReplies.push((await peer.read(/^\d{3} /m, "RCPT TO answered")).trim());
    }
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA accepted");
    // RFC 5321 section 4.5.2 dot stuffing. The body here carries no
    // leading dot, and doing it anyway keeps this reader honest about
    // what it is sending.
    var payload = peerMessage(rcpts[0]).replace(/\r\n\./g, "\r\n..");
    peer.sendRaw(payload + "\r\n.\r\n", "<the message>");
    var data = await peer.read(/^\d{3} /m, "DATA answered");
    return { mail: mail.trim(), rcpts: rcptReplies, data: data.trim() };
  } finally {
    peer.close();
  }
}

// ---- the case --------------------------------------------------------------

async function testOneFullMailboxDoesNotCostTheOtherRecipient(port, caPem, identity, taker, full) {
  var before = held(identity, taker);
  count("the recipient whose mailbox is capped starts with nothing in it",
    held(identity, full) === 0, String(held(identity, full)));

  var first = await deliverFromAPeer(port, caPem, [taker.address, full.address], "mx-first");
  count("the peer's envelope sender is accepted", /^250 /.test(first.mail), first.mail);
  count("both recipients are accepted at RCPT, because neither address is the problem",
    first.rcpts.every(function (line) { return /^250 /.test(line); }),
    JSON.stringify(first.rcpts));

  var takerHas = held(identity, taker);
  count("the recipient who could take it has the message",
    takerHas === before + 1, takerHas + " against " + before);
  count("the recipient whose mailbox is full has nothing", held(identity, full) === 0,
    String(held(identity, full)));

  // The rule the handoff's own comment states. A copy is on disk, so
  // the only answer that does not cost the first recipient a duplicate
  // is one that stops the peer retrying.
  count("because a copy was stored, the peer is told the message was accepted rather " +
    "than told to try again, which is the only answer that does not duplicate the " +
    "copy already on disk",
    /^2\d\d /.test(first.data), first.data);

  // Drive a second transaction anyway, because the interesting question
  // is what the full mailbox does on a redelivery rather than what the
  // taker does. A conforming peer answered 2xx above does not send this
  // one at all, which is the whole point of the answer.
  //
  // The taker's count is deliberately NOT asserted here. This server
  // carries no message-level duplicate suppression, so a peer that
  // resends after losing our reply does store a second copy, and that is
  // a gap in its own right rather than something this vector settles.
  // Asserting one copy here would demand a property nothing implements
  // and would pass only while nobody redelivers.
  var second = await deliverFromAPeer(port, caPem, [taker.address, full.address], "mx-retry");
  count("a redelivery is answered rather than dropped", /^\d{3} /.test(second.data), second.data);
  count("the full mailbox is still empty rather than partly filled by the redelivery",
    held(identity, full) === 0, String(held(identity, full)));
}

// One closed address on a message, and the rest of it still arriving.
//
// The refusal itself is settled elsewhere; what is asked here is its
// blast radius. A name this server does not hold is answered `550
// 5.1.1` at RCPT, and the only thing that must not follow is the peer
// losing the recipients that ARE live. So the transaction is driven to
// the end: DATA has to open, the message has to be accepted, and the
// live recipient has to hold exactly one more copy than before.
//
// Driven in both orders. With the live address first, a listener that
// abandoned the envelope on a refusal would still look correct, because
// there would be nothing left to refuse. With the closed address first,
// it could not.
async function testOneClosedAddressDoesNotCostTheRestOfTheMessage(port, caPem, identity, taker) {
  var before = held(identity, taker);
  var CLOSED = "nobody@" + DOMAIN;

  var outcome = await deliverFromAPeer(port, caPem,
    [taker.address, CLOSED], "mx-one-closed");
  count("a live mailbox is accepted at RCPT", /^250 /.test(outcome.rcpts[0]),
    JSON.stringify(outcome.rcpts));
  count("and an address with no mailbox behind it is refused there and then, with the " +
    "550 5.1.1 RFC 5321 section 3.3 defines, rather than accepted and met after DATA",
    /^550 5\.1\.1/.test(outcome.rcpts[1]), JSON.stringify(outcome.rcpts));
  count("a message that lost one recipient at RCPT is still accepted, because the " +
    "transaction still holds one", /^2\d\d /.test(outcome.data), outcome.data);
  count("and the recipient who could take it has exactly one more than before",
    held(identity, taker) === before + 1,
    held(identity, taker) + " against " + before);

  // The same message with the closed address named first. This is the
  // order that tells a per-recipient refusal from a per-transaction one,
  // and it is the ordinary order for a list: the members are in whatever
  // sequence the list holds them, not sorted by whether they still read
  // their mail.
  var reversed = await deliverFromAPeer(port, caPem,
    [CLOSED, taker.address], "mx-closed-first");
  count("the closed address is refused the same way when it is named first",
    /^550 5\.1\.1/.test(reversed.rcpts[0]), JSON.stringify(reversed.rcpts));
  count("and the live address named after it is still accepted, so the refusal is a " +
    "verdict about one recipient and not about the envelope",
    /^250 /.test(reversed.rcpts[1]), JSON.stringify(reversed.rcpts));
  count("so DATA still opened and the message was still accepted",
    /^2\d\d /.test(reversed.data), reversed.data);
  count("and the live recipient's count moved again, which is what says it was moving " +
    "for a reason rather than sitting still",
    held(identity, taker) === before + 2,
    held(identity, taker) + " against " + before);
}

// The control. When nothing could be stored, a temporary failure is
// correct: the peer keeps the message, retries on its own schedule, and
// there is no copy anywhere for that retry to duplicate.
async function testWhenNothingLandsThePeerIsToldToRetry(port, caPem, identity, full, alsoFull) {
  var before = held(identity, full) + held(identity, alsoFull);
  var outcome = await deliverFromAPeer(port, caPem,
    [full.address, alsoFull.address], "mx-all-refused");
  count("a message no recipient could take is answered with a temporary failure, so " +
    "the peer keeps it and retries", /^4\d\d /.test(outcome.data), outcome.data);
  count("and nothing was stored for that retry to duplicate",
    held(identity, full) + held(identity, alsoFull) === before,
    (held(identity, full) + held(identity, alsoFull)) + " against " + before);
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("partial");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_TLS_CERT:         material.certFile,
        BLAMEPOST_TLS_KEY:          material.keyFile,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "partial delivery run" });

    var taker = await identity.accounts.create({
      address: "taker@" + DOMAIN, password: TAKER_PASSWORD });
    var full = await identity.accounts.create({
      address: "brimming@" + DOMAIN, password: FULL_PASSWORD, quotaBytes: CAP_BYTES });
    var alsoFull = await identity.accounts.create({
      address: "loaded@" + DOMAIN, password: FULL_PASSWORD + " two", quotaBytes: CAP_BYTES });
    count("one recipient has room and two do not",
      taker.quotaBytes === 0 && full.quotaBytes === CAP_BYTES &&
      alsoFull.quotaBytes === CAP_BYTES,
      JSON.stringify([taker.quotaBytes, full.quotaBytes, alsoFull.quotaBytes]));

    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = {
        enabled: names[i] === "mx",
        port:    await wire.reservePort(),
        address: LOOPBACK,
      };
    }

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
        // The shipped posture, named here so the delivery below is the
        // one an operator runs rather than one this file relaxed to
        // make a point.
        inbound: { mode: "enforce", onTemperror: "defer" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
      resolver:     dnsZone.pinnedResolverOver(ZONE),
    });
    await server.start();
    running = true;

    var mxPort = server.mail.listeners.bound().mx;
    count("the MX listener took its port", typeof mxPort === "number" && mxPort > 0,
      String(mxPort));

    // The control runs first: it is the case that asserts nothing was
    // stored, and it can only say that while nothing has been. The two
    // that do store run after it, in the order that leaves the taker's
    // count arithmetic readable.
    await testWhenNothingLandsThePeerIsToldToRetry(mxPort, material.caPem,
      identity, full, alsoFull);
    await testOneClosedAddressDoesNotCostTheRestOfTheMessage(mxPort, material.caPem,
      identity, taker);
    await testOneFullMailboxDoesNotCostTheOtherRecipient(mxPort, material.caPem,
      identity, taker, full);

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

module.exports = { name: "inbound-partial-delivery", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
