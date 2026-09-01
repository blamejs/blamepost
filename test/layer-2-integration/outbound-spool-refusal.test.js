// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What an account holder sees when the spool has no room left, driven
 * through a real submission listener with a real mail client on a real
 * socket, and through a real MX listener with a real peer on another.
 *
 * The spool is what keeps a message this build cannot send. Because it
 * keeps everything, it fills, and what happens at the moment it is full
 * is the whole question. Two answers are wrong in the same way:
 * accepting the message and dropping it loses mail the sender was told
 * had been taken, and refusing without telling the client loses it just
 * as completely with better manners.
 *
 * The answer here is a temporary refusal on the wire. A 4xx leaves the
 * message in the client's outbox, where the person who wrote it can see
 * it is not gone and can send it again; and it leaves an inbound
 * message with the peer that still holds it, which retries on its own
 * schedule and generates a report from its side if it eventually gives
 * up. Both are the sender keeping their own mail.
 *
 * The other half is the moment of crossing. An envelope that fits some
 * of its recipients and not the rest must be refused whole, because a
 * client that retries a partly-spooled message delivers it twice to
 * everyone whose copy was already waiting. That extends to a mixed
 * envelope: nothing may reach a local mailbox either, for the same
 * reason.
 *
 * The resolver is supplied so a recipient elsewhere gets past MX
 * lookup. Nothing leaves the machine: there is no transport behind the
 * composer, so no outbound socket is opened.
 *
 * Run standalone: node test/layer-2-integration/outbound-spool-refusal.test.js
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

var HOSTNAME  = "mx.example.com";
var DOMAIN    = "example.com";
var ELSEWHERE = "example.net";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The ceiling this run holds the server to. Small enough to reach over
// a handful of wire sessions, large enough that the reserved share is
// more than one entry.
var MAX_SPOOL_MESSAGES = 10;

var BODY = "Ordering two more of the blue ones. Marker 5c31ab90.";

var ANSWERING_RESOLVER = {
  queryMx: function (name) {
    if (String(name).toLowerCase() === ELSEWHERE) {
      return Promise.resolve([{ priority: 10, exchange: "mx." + ELSEWHERE }]);
    }
    return Promise.reject(new Error("no mail exchanger for " + name));
  },
  queryTxt: function () { return Promise.resolve([]); },
  queryPtr: function () { return Promise.resolve([]); },
  query:    function () { return Promise.resolve([]); },
};

var count = helpers.count;
var plainResponse = wire.saslPlain;

function spoolIds(dataDir) {
  var dir = nodePath.join(dataDir, "queue");
  if (!nodeFs.existsSync(dir)) return [];
  return nodeFs.readdirSync(dir)
    .filter(function (n) { return n.slice(-5) === ".json"; })
    .map(function (n) { return n.slice(0, -5); })
    .sort();
}

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

// One submission of one message to one or more recipients. Returns the
// reply to the terminating dot, which is the line the client acts on.
async function submitTo(port, caPem, alice, recipients, marker, label) {
  var session = await submissionSession(port, caPem, alice, ALICE_PASSWORD, label);
  session.send("MAIL FROM:<" + alice + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  var accepted = [];
  for (var i = 0; i < recipients.length; i += 1) {
    session.send("RCPT TO:<" + recipients[i] + ">");
    var reply = await session.read(/^\d{3} /m, "RCPT TO answered");
    if (/^250 /m.test(reply)) accepted.push(recipients[i]);
  }
  session.send("DATA");
  await session.read(/^354 /m, "DATA answered");
  session.sendRaw([
    "From: " + alice,
    "To: " + recipients.join(", "),
    "Subject: " + marker,
    "Date: Sun, 23 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker + "@example.com>",
    "",
    BODY,
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");
  var answer = await session.read(/^\d{3} /m, "message answered");
  session.send("QUIT");
  session.close();
  return { answer: answer, rcptAccepted: accepted };
}

// ---- an account holder meets a full spool ----------------------------------

async function afullSpoolRefusesTemporarilyRatherThanSwallowing(ctx) {
  var alice = ctx.alice;
  var accepted = 0;
  var refusal = null;

  // Send until the server stops taking them. Each one is a whole
  // submission session, which is what a mail client does.
  for (var i = 0; i < MAX_SPOOL_MESSAGES + 4; i += 1) {
    var result = await submitTo(ctx.ports.submission, ctx.caPem, alice,
      ["bob" + i + "@" + ELSEWHERE], "fill-" + i, "submission-fill-" + i);
    if (/^250 /m.test(result.answer)) { accepted += 1; continue; }
    refusal = result.answer;
    break;
  }

  count("the server stops taking messages before the spool is unbounded",
    refusal !== null, "accepted " + accepted + " of " + (MAX_SPOOL_MESSAGES + 4));
  count("and it stopped at the ceiling rather than somewhere else",
    accepted === MAX_SPOOL_MESSAGES, String(accepted));

  // The code is the whole point. 4xx leaves the message in the outbox;
  // 5xx tells the client to give up and report it undeliverable, which
  // is the same message lost with a better error page.
  count("the refusal is temporary, so the client keeps the message",
    refusal !== null && /^4\d\d[ -]/m.test(refusal), visible(refusal));
  count("it is not a permanent refusal",
    refusal !== null && !/^5\d\d[ -]/m.test(refusal), visible(refusal));

  var depth = spoolIds(ctx.dataDir).length;
  count("nothing was written for the refused message",
    depth === MAX_SPOOL_MESSAGES, String(depth));

  // And the operator can find out why, which the wire code alone does
  // not say.
  var described = ctx.server.describe().outbound;
  count("the handle reports the ceiling it is holding",
    described.spool && described.spool.maxMessages === MAX_SPOOL_MESSAGES,
    JSON.stringify(described.spool));
  count("and reports how full it is",
    described.spool && described.spool.messages === MAX_SPOOL_MESSAGES,
    JSON.stringify(described.spool));
  count("and says the spool is what refused",
    described.spool && described.spool.refused >= 1,
    JSON.stringify(described.spool));
}

// ---- an envelope crossing the ceiling mid-transaction ----------------------

async function anEnvelopeThatCrossesTheCeilingDeliversNothing(ctx) {
  // Clear a little room: fewer slots than the envelope needs.
  var ids = spoolIds(ctx.dataDir);
  var freeing = { reason: "freeing a slot", notice: { withheld: "fixture-removal" } };
  await ctx.server.mail.delivery.queue.remove(ids[0], freeing);
  await ctx.server.mail.delivery.queue.remove(ids[1], freeing);
  var before = spoolIds(ctx.dataDir).length;
  count("two slots were freed for the crossing",
    before === MAX_SPOOL_MESSAGES - 2, String(before));

  var bob = "bob@" + DOMAIN;
  var folders = ctx.identity.mailbox.accountFolders({ id: ctx.bobId });
  var inbox = folders.filter(function (f) { return f.name === "INBOX"; })[0];
  function inboxCount() {
    return ctx.identity.messageStore
      .queryByModseq(inbox.storeName, { sinceModseq: 0 }).length;
  }
  var inboxBefore = inboxCount();

  // Four recipients elsewhere and one on this server, with two slots
  // left. The whole envelope has to be refused: a client that retries a
  // partly-spooled message sends it twice to everyone already waiting,
  // and to the local mailbox as well.
  var result = await submitTo(ctx.ports.submission, ctx.caPem, ctx.alice,
    ["one@" + ELSEWHERE, "two@" + ELSEWHERE, "three@" + ELSEWHERE,
      "four@" + ELSEWHERE, bob],
    "crossing-1", "submission-crossing");

  count("every recipient was accepted at RCPT, so the crossing is at the message",
    result.rcptAccepted.length === 5, result.rcptAccepted.join(" "));
  count("the message that cannot fit whole is refused temporarily",
    /^4\d\d[ -]/m.test(result.answer), visible(result.answer));
  count("not one of its recipients was spooled",
    spoolIds(ctx.dataDir).length === before, String(spoolIds(ctx.dataDir).length));
  count("and the local recipient did not receive a copy either",
    inboxCount() === inboxBefore,
    String(inboxBefore) + " -> " + String(inboxCount()));

  // An envelope that does fit is still taken, so the ceiling bounds
  // rather than latches.
  var fits = await submitTo(ctx.ports.submission, ctx.caPem, ctx.alice,
    ["five@" + ELSEWHERE, "six@" + ELSEWHERE], "crossing-2", "submission-fits");
  count("an envelope that fits is accepted", /^250 /m.test(fits.answer),
    visible(fits.answer));
  count("and both of its recipients were spooled",
    spoolIds(ctx.dataDir).length === before + 2,
    String(spoolIds(ctx.dataDir).length));
}

// ---- a stranger's mail stops short of the ceiling --------------------------

// An alias on a hosted domain that forwards elsewhere is how mail from
// a stranger reaches the outbound spool. Its volume is chosen by
// whoever sends to the alias, so it must not be able to spend the room
// the operator's own account holders need.
async function forwardingForStrangersStopsShortOfTheCeiling(ctx) {
  // Empty the spool so the reserved share is the thing being measured.
  var ids = spoolIds(ctx.dataDir);
  for (var i = 0; i < ids.length; i += 1) {
    await ctx.server.mail.delivery.queue.remove(ids[i], {
      reason: "emptying the spool for the reservation check",
      notice: { withheld: "fixture-removal" },
    });
  }
  count("the spool starts empty for the reservation check",
    spoolIds(ctx.dataDir).length === 0, String(spoolIds(ctx.dataDir).length));

  var forwarded = 0;
  var mxRefusal = null;
  for (var n = 0; n < MAX_SPOOL_MESSAGES + 2; n += 1) {
    var peer = await Wire.mx(ctx.ports.mx, {
      caPem: ctx.caPem, servername: HOSTNAME, label: "mx-forward-" + n,
      helo: "relay.example.org",
    });
    peer.send("MAIL FROM:<stranger" + n + "@example.org>");
    await peer.read(/^\d{3} /m, "MAIL FROM answered");
    peer.send("RCPT TO:<" + ctx.aliasAddress + ">");
    var rcptReply = await peer.read(/^\d{3} /m, "RCPT TO answered");
    count("the alias is accepted at RCPT so the crossing is at the message",
      /^250 /m.test(rcptReply), visible(rcptReply));
    peer.send("DATA");
    await peer.read(/^354 /m, "DATA answered");
    peer.sendRaw([
      "From: stranger" + n + "@example.org",
      "To: " + ctx.aliasAddress,
      "Subject: forward-" + n,
      "Date: Sun, 23 Aug 2026 09:00:00 +0000",
      "Message-ID: <forward-" + n + "@example.org>",
      "",
      BODY,
      "",
      ".",
      "",
    ].join("\r\n"), "<the message and its terminating dot>");
    var reply = await peer.read(/^\d{3} /m, "message answered");
    peer.send("QUIT");
    peer.close();
    if (/^250 /m.test(reply)) { forwarded += 1; continue; }
    mxRefusal = reply;
    break;
  }

  count("forwarding for strangers stops before the ceiling, not at it",
    mxRefusal !== null && forwarded > 0 && forwarded < MAX_SPOOL_MESSAGES,
    "forwarded " + forwarded + " of " + MAX_SPOOL_MESSAGES);
  count("and the peer is told to try again rather than to give up",
    mxRefusal !== null && /^4\d\d[ -]/m.test(mxRefusal), visible(mxRefusal));

  // The room the strangers could not take is the room an authenticated
  // account holder still has.
  var mine = await submitTo(ctx.ports.submission, ctx.caPem, ctx.alice,
    ["reserved@" + ELSEWHERE], "reserved-1", "submission-reserved");
  count("an account holder can still send after strangers were stopped",
    /^250 /m.test(mine.answer), visible(mine.answer));
  count("and their message reached the spool",
    spoolIds(ctx.dataDir).length === forwarded + 1,
    String(spoolIds(ctx.dataDir).length));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("outbound-spool-refusal");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "spool refusal test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: ALICE_PASSWORD });

    // The alias is the route a stranger's message takes off this server.
    var aliasAddress = "forwards@" + DOMAIN;
    await identity.aliases.add({
      address:     aliasAddress,
      destination: "onward@" + ELSEWHERE,
    });

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
        httpPort:       0,
        listeners:      sections,
        inbound:        { mode: "monitor" },
        outboundPolicy: { mtaSts: "off", dane: "off" },
        // A budget with room left in it, which is what puts a message in
        // the spool at all. On a budget of one the first attempt is also
        // the last, so the recipient ends permanently refused with a
        // report to its sender and nothing is written for this file to
        // fill the spool with.
        outboundRetry:  {
          maxAttempts: 5,
          backoffMs:   [b.constants.TIME.minutes(1), b.constants.TIME.minutes(5),
                        b.constants.TIME.minutes(15), b.constants.TIME.hours(1),
                        b.constants.TIME.hours(4)],
        },
        outboundSpool:  { maxMessages: MAX_SPOOL_MESSAGES },
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

    var ctx = {
      ports:        { submission: sections.submission.port, mx: sections.mx.port },
      caPem:        leaf.ca,
      alice:        alice.address,
      bobId:        bob.id,
      aliasAddress: aliasAddress,
      server:       server,
      identity:     identity,
      dataDir:      dataDir,
    };

    await helpers.withTestTimeout("spool refusal: a full spool refuses temporarily",
      function () { return afullSpoolRefusesTemporarilyRatherThanSwallowing(ctx); },
      { timeoutMs: 60000 });
    await helpers.withTestTimeout("spool refusal: an envelope crossing the ceiling delivers nothing",
      function () { return anEnvelopeThatCrossesTheCeilingDeliversNothing(ctx); },
      { timeoutMs: 60000 });
    await helpers.withTestTimeout("spool refusal: strangers stop short of the ceiling",
      function () { return forwardingForStrangersStopsShortOfTheCeiling(ctx); },
      { timeoutMs: 60000 });

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

module.exports = { name: "outbound-spool-refusal", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
