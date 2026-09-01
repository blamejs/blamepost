// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The one path in this server that destroys mail on purpose.
 *
 * Everything else here fails safe by doing nothing. EXPUNGE fails by
 * removing a message that should have stayed, or by keeping one an
 * operator was told had gone, and neither is recoverable from a log.
 * So it is driven the way a client drives it, on a socket, and both
 * answers are asserted: the message that may go, goes, and the message
 * that may not, stays and is still readable afterwards.
 *
 * A legal hold that fails open is the worse of the two. Nobody checks a
 * gate they have been told is holding, so a hold that quietly lets a
 * message through is discovered when somebody asks for the message,
 * which is the moment it needed to exist. That case is the reason this
 * file exists.
 *
 * The retention floor is the other gate `b.mail.agent.expunge` holds,
 * and it is asserted separately, on a second server. It is read from
 * the agent's compliance posture, which is off by default, so a case
 * about it has to stand up a server that has one. Writing this file is
 * what turned up that the posture had no way of being set at all:
 * `blamepost.mail.mailbox.create` took a `posture` option, nothing
 * passed one, and no configuration key supplied it, so the floor was
 * documented in three places and armed by nothing.
 *
 * Run standalone: node test/layer-2-integration/mail-expunge.test.js
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

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// ---- delivering something to destroy ---------------------------------------

// One message through the front door, so what EXPUNGE later removes got
// there the way real mail does rather than being written into the store
// by the test.
async function deliver(mxPort, caPem, to, marker) {
  var peer = await Wire.connect(mxPort, "mx-deliver");
  await peer.read(/^220 /m, "banner");
  peer.send("EHLO peer.example.net");
  await peer.read(/^250 /m, "EHLO accepted");
  peer.send("STARTTLS");
  await peer.read(/^220 /m, "STARTTLS accepted");
  await peer.upgrade(caPem, HOSTNAME);
  peer.send("EHLO peer.example.net");
  await peer.read(/^250 /m, "EHLO accepted over TLS");
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + to + ">");
  await peer.read(/^250 /m, "RCPT TO accepted");
  peer.send("DATA");
  await peer.read(/^354 /m, "DATA answered");
  peer.sendRaw([
    "From: " + PEER,
    "To: " + to,
    "Subject: " + marker,
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + marker + "@example.net>",
    "",
    "Body of " + marker + ".",
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");
  await peer.read(/^250 /m, "message accepted");
  peer.send("QUIT");
  peer.close();
}

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

async function aDeletedMessageIsActuallyRemoved(ports, caPem, address) {
  var client = await imapSession(ports.imap, caPem, address, "imap-expunge");

  client.send("b0 SELECT INBOX");
  var selected = await client.read(/^b0 (OK|NO|BAD)/m, "SELECT answered");
  count("the mailbox holds the delivered message", /^\* 1 EXISTS/m.test(selected), visible(selected));

  client.send("b1 STORE 1 +FLAGS (\\Deleted)");
  var stored = await client.read(/^b1 (OK|NO|BAD)/m, "STORE answered");
  count("the client can flag a message deleted", /^b1 OK/m.test(stored), visible(stored));

  client.send("b2 EXPUNGE");
  var expunged = await client.read(/^b2 (OK|NO|BAD)/m, "EXPUNGE answered");
  count("EXPUNGE succeeds", /^b2 OK/m.test(expunged), visible(expunged));
  count("and the client is told which message went",
    /^\* 1 EXPUNGE/m.test(expunged), visible(expunged));

  // A fresh SELECT rather than a re-read of the same session, because
  // the question is whether the message left the store rather than
  // whether one connection stopped mentioning it.
  client.send("b3 SELECT INBOX");
  var after = await client.read(/^b3 (OK|NO|BAD)/m, "SELECT answered");
  count("a new session finds the mailbox empty",
    /^\* 0 EXISTS/m.test(after), visible(after));

  client.send("b4 LOGOUT");
  client.close();
}

async function aHeldMessageSurvivesExpunge(ports, caPem, address, messageStore, folder) {
  var client = await imapSession(ports.imap, caPem, address, "imap-hold");

  client.send("c0 SELECT INBOX");
  var selected = await client.read(/^c0 (OK|NO|BAD)/m, "SELECT answered");
  count("the held message is in the mailbox to begin with",
    /^\* 1 EXISTS/m.test(selected), visible(selected));

  client.send("c1 STORE 1 +FLAGS (\\Deleted)");
  await client.read(/^c1 (OK|NO|BAD)/m, "STORE answered");

  client.send("c2 EXPUNGE");
  var expunged = await client.read(/^c2 (OK|NO|BAD)/m, "EXPUNGE answered");
  count("EXPUNGE completes rather than erroring",
    /^c2 OK/m.test(expunged), visible(expunged));
  // The refusal is silence about that message, per RFC 9051: a message
  // that was not removed draws no untagged EXPUNGE. Telling the client
  // it went and keeping it is the failure this asserts against.
  count("the client is NOT told the held message was removed",
    !/^\* \d+ EXPUNGE/m.test(expunged), visible(expunged));

  client.send("c3 SELECT INBOX");
  var after = await client.read(/^c3 (OK|NO|BAD)/m, "SELECT answered");
  count("the held message is still in the mailbox",
    /^\* 1 EXISTS/m.test(after), visible(after));

  client.send("c4 FETCH 1 BODY[]");
  var fetched = await client.read(/^c4 (OK|NO|BAD)/m, "FETCH answered");
  count("and it is still readable, body and all",
    /^c4 OK/m.test(fetched) && fetched.indexOf("held-message") !== -1, visible(fetched));

  client.send("c5 LOGOUT");
  client.close();

  // The store's own view, because the wire could agree with the store
  // about a message both of them have lost track of.
  var rows = messageStore.queryByModseq(folder, { sinceModseq: 0 });
  count("the store still holds exactly one message in that folder",
    Array.isArray(rows) && rows.length === 1,
    Array.isArray(rows) ? rows.length + " row(s)" : String(rows));
}

// A message younger than the floor cannot be hard deleted, and the
// account owner is refused as squarely as an administrator. That is the
// whole point of a regulatory floor and it is also the part an operator
// will be surprised by, so it is asserted rather than described.
//
// Anything delivered during a test run is seconds old, and the shortest
// floor on offer is a year, so a freshly delivered message is inside
// every floor there is. No clock has to be moved to reach this.
async function theRetentionFloorRefusesARecentDelete(ports, caPem, address, messageStore, folder) {
  var client = await imapSession(ports.imap, caPem, address, "imap-floor");

  client.send("d0 SELECT INBOX");
  await client.read(/^d0 (OK|NO|BAD)/m, "SELECT answered");
  client.send("d1 STORE 1 +FLAGS (\\Deleted)");
  await client.read(/^d1 (OK|NO|BAD)/m, "STORE answered");

  client.send("d2 EXPUNGE");
  var expunged = await client.read(/^d2 (OK|NO|BAD)/m, "EXPUNGE answered");
  count("EXPUNGE under a retention floor completes rather than erroring",
    /^d2 OK/m.test(expunged), visible(expunged));
  count("the owner is NOT told a message inside the floor was removed",
    !/^\* \d+ EXPUNGE/m.test(expunged), visible(expunged));

  client.send("d3 SELECT INBOX");
  var after = await client.read(/^d3 (OK|NO|BAD)/m, "SELECT answered");
  count("and the message is still there",
    /^\* 1 EXISTS/m.test(after), visible(after));

  client.send("d4 LOGOUT");
  client.close();

  var rows = messageStore.queryByModseq(folder, { sinceModseq: 0 });
  count("the store agrees the message survived the floor",
    Array.isArray(rows) && rows.length === 1,
    Array.isArray(rows) ? rows.length + " row(s)" : String(rows));
}

// ---- runner ----------------------------------------------------------------

// One server, with whatever posture the caller wants, torn down after.
// Two of these run: the ordinary server every operator gets, and one
// carrying a regulatory posture, because the floor cannot be reached
// without arming it and arming it changes what delete means for
// everybody on that server.
async function withServer(label, posture, fn) {
  var root    = helpers.tempDir("expunge-" + label);
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

    var env = {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    };
    if (posture) env.BLAMEPOST_COMPLIANCE_POSTURE = posture;
    var cfg = config.load({ env: env, cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "expunge test" });
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

    await fn({
      ports:    { mx: sections.mx.port, imap: sections.imap.port },
      caPem:    leaf.ca,
      identity: identity,
      alice:    alice,
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    // The store belongs to whoever opened it, and `server.stop` does not
    // touch it. The database handle behind it is one per process, so a
    // second server opened without this one closing first would find the
    // first server's data under its own temporary directory, which is
    // how the posture case first read as "example.com is already hosted
    // here" against an empty tree.
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

// The store names a folder one way and the wire names it another, so
// asking the store about "INBOX" asks it about a folder it has never
// heard of.
function inboxOf(identity, alice) {
  var folders = identity.mailbox.accountFolders({ id: alice.id });
  var inbox = folders.filter(function (f) { return f.name === "INBOX"; })[0];
  count("the account has an INBOX the store can name",
    !!inbox && typeof inbox.storeName === "string" && inbox.storeName.length > 0,
    folders.map(function (f) { return f.name + " => " + f.storeName; }).join(", "));
  return inbox.storeName;
}

async function run() {
  await withServer("default", null, async function (ctx) {
    count("a server with no posture set reports none",
      ctx.identity.mailbox.describe().posture === null,
      String(ctx.identity.mailbox.describe().posture));

    await deliver(ctx.ports.mx, ctx.caPem, ctx.alice.address, "ordinary-message");
    await aDeletedMessageIsActuallyRemoved(ctx.ports, ctx.caPem, ctx.alice.address);

    // The second message, put under hold through the store the way an
    // operator responding to a preservation order would, rather than
    // through a wire verb no protocol offers.
    await deliver(ctx.ports.mx, ctx.caPem, ctx.alice.address, "held-message");
    var folder = inboxOf(ctx.identity, ctx.alice);
    var rows = ctx.identity.messageStore.queryByModseq(folder, { sinceModseq: 0 });
    count("one message is waiting to be held", rows.length === 1, rows.length + " row(s)");
    ctx.identity.messageStore.setLegalHold([rows[0].objectid], { hold: true });

    await aHeldMessageSurvivesExpunge(ctx.ports, ctx.caPem, ctx.alice.address,
      ctx.identity.messageStore, folder);
  });

  await withServer("soc2", "soc2", async function (ctx) {
    count("a server given a posture reports it back",
      ctx.identity.mailbox.describe().posture === "soc2",
      String(ctx.identity.mailbox.describe().posture));

    await deliver(ctx.ports.mx, ctx.caPem, ctx.alice.address, "recent-message");
    var folder = inboxOf(ctx.identity, ctx.alice);
    await theRetentionFloorRefusesARecentDelete(ctx.ports, ctx.caPem, ctx.alice.address,
      ctx.identity.messageStore, folder);
  });

  // The postures this server does not offer, and the reason, checked
  // rather than described. Under any of the three the agent refuses
  // every operation whose actor lacks the field that posture names, and
  // no actor built here carries one. Configuration refuses them at boot
  // instead, which is the difference between a server that will not
  // start and a server that starts and answers NO to everything.
  ["hipaa", "pci-dss", "gdpr"].forEach(function (posture) {
    var threw = null;
    try {
      config.load({
        env: {
          BLAMEPOST_HOSTNAME:           HOSTNAME,
          BLAMEPOST_DATA_DIR:           helpers.path.join(helpers.os.tmpdir(), "unused"),
          BLAMEPOST_VAULT_PASSPHRASE:   VAULT_PASSPHRASE,
          BLAMEPOST_COMPLIANCE_POSTURE: posture,
        },
        cwd: helpers.REPO_ROOT,
      });
    } catch (e) { threw = e; }
    count(posture + " is refused at configuration time rather than at every mailbox call",
      threw !== null && /BLAMEPOST_COMPLIANCE_POSTURE/.test(threw.message),
      threw ? threw.message.slice(0, 120) : "accepted");
  });

  return helpers.getChecks();
}

module.exports = { name: "mail-expunge", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
