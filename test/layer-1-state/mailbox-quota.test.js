// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The storage cap an operator sets on an account, and what happens the
 * moment a message crosses it.
 *
 * The cap is a column on the accounts table, a schema key an operator
 * sets from the command line, and a number the administration pages
 * render. Nothing exercised it. That is the shape this project has been
 * caught by before: a capability present at every layer, described in
 * the operator guide, and never once driven, so the only way to find
 * out whether it holds is to run out of disk.
 *
 * The default cap is zero, which means no limit, and a suite that runs
 * only at the default is a suite in the one configuration where a
 * broken cap cannot show. So every account here carries a real cap and
 * the messages are sized against it.
 *
 * Two paths reach the check and they are not the same code:
 *
 *   - the adapter's own append, which is what inbound delivery and the
 *     composer's copy to Sent both call;
 *   - IMAP APPEND on a bound port, which is what a mail client sends to
 *     save a draft, to file a message from another server, and to
 *     migrate a mailbox.
 *
 * The second one is the one worth having. The framework's listener
 * makes a pre-check of its own against the adapter's `quota` reader,
 * which answers no cap because a wire folder name belongs to every
 * account that has one, and then relies on the append below it to
 * refuse. A run that only called the append would never learn whether
 * the refusal survives the trip out to the wire, or whether the client
 * is told the one thing it can act on: the `OVERQUOTA` response code
 * RFC 9208 section 5 defines.
 *
 * Driving APPEND at all turned up a wire defect in the vendored
 * listener, and this file pins it rather than working around it in
 * silence. The details are beside the case that meets it.
 *
 * Run standalone: node test/layer-1-state/mailbox-quota.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var Wire     = wire.Wire;
var visible  = wire.visible;
var LOOPBACK = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var BOB_PASSWORD     = "another quiet lantern 7715";
var CARLA_PASSWORD   = "a third quiet lantern 3308";

// Small enough that two messages cross it and one does not, so the
// refusal is about the cap rather than about anything else.
var CAP_BYTES = 8192;
var FILLER_PAD = 5000;

// A message that crosses the cap on its own, so the wire case does not
// depend on what the append cases before it happened to leave behind.
// A run whose refusal needs a primed mailbox is a run that stops
// refusing the day the priming changes.
var OVER_CAP_PAD = CAP_BYTES;

var SHUTDOWN_TIMEOUT_MS = 5000;

function messageOf(recipient, subject, padBytes) {
  var body = new Array(Math.max(1, padBytes)).join("x");
  return Buffer.from(
    "Message-ID: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" + body + "\r\n", "utf8");
}

function appendOrThrown(mailbox, accountId, folder, raw) {
  try { return { stored: mailbox.appendMessage(folder, raw, { actor: { id: accountId } }) }; }
  catch (e) { return { thrown: e }; }
}

// ---- the cap on the append path -------------------------------------------

function testAMessageUnderTheCapIsStored(mailbox, alice) {
  var outcome = appendOrThrown(mailbox, alice.id, "INBOX",
    messageOf(alice.address, "Under the cap", FILLER_PAD));
  count("a message that fits under the cap is stored",
    outcome.thrown === undefined && typeof outcome.stored.objectid === "string",
    outcome.thrown === undefined ? outcome.stored.objectid : outcome.thrown.message);
  return outcome.stored;
}

function testAMessageOverTheCapIsRefused(mailbox, alice) {
  var outcome = appendOrThrown(mailbox, alice.id, "INBOX",
    messageOf(alice.address, "Over the cap", FILLER_PAD));
  var refusal = outcome.thrown;
  count("the message that crosses the cap is refused rather than stored",
    refusal !== undefined, outcome.thrown === undefined ? outcome.stored.objectid : "");
  count("the refusal is the mailbox layer's own, named so a caller can branch on it",
    refusal.code === "mailbox/over-quota", refusal.code);
  count("it carries the marker the IMAP listener reads to choose a response code",
    refusal.overquota === true, String(refusal.overquota));
  count("it carries the limit that was crossed", refusal.limit === CAP_BYTES,
    String(refusal.limit));
  count("and the message an operator reads names what is held and what was needed",
    /holds \d+ bytes of its \d+ byte limit/.test(refusal.message) &&
    /needs \d+ more/.test(refusal.message), refusal.message);
  return refusal;
}

// The cap belongs to an account, not to the server. An implementation
// summing every folder on the volume would refuse the second account
// for the first account's mail, and would look identical from the
// inside of a single account run.
function testTheCapIsCountedPerAccount(mailbox, bob, carla) {
  var bobsOwn = appendOrThrown(mailbox, bob.id, "INBOX",
    messageOf(bob.address, "Bobs own", FILLER_PAD));
  count("a second capped account is unaffected by the first account's usage",
    bobsOwn.thrown === undefined, bobsOwn.thrown && bobsOwn.thrown.message);

  var bobsSecond = appendOrThrown(mailbox, bob.id, "INBOX",
    messageOf(bob.address, "Bobs second", FILLER_PAD));
  count("and it runs out on its own budget rather than on somebody else's",
    bobsSecond.thrown !== undefined && bobsSecond.thrown.code === "mailbox/over-quota",
    bobsSecond.thrown && bobsSecond.thrown.code);

  // The omission vector. Zero is the operator's way of saying no limit
  // and it is the shipped default, so a run that never sets a cap is
  // the run where a broken cap cannot show.
  var uncapped = appendOrThrown(mailbox, carla.id, "INBOX",
    messageOf(carla.address, "First uncapped", FILLER_PAD));
  var uncappedAgain = appendOrThrown(mailbox, carla.id, "INBOX",
    messageOf(carla.address, "Second uncapped", FILLER_PAD));
  var uncappedThird = appendOrThrown(mailbox, carla.id, "INBOX",
    messageOf(carla.address, "Third uncapped", FILLER_PAD));
  count("an account left at the default cap of zero takes more than any cap would allow",
    uncapped.thrown === undefined && uncappedAgain.thrown === undefined &&
    uncappedThird.thrown === undefined,
    JSON.stringify([uncapped.thrown && uncapped.thrown.code,
                    uncappedAgain.thrown && uncappedAgain.thrown.code,
                    uncappedThird.thrown && uncappedThird.thrown.code]));
}

// Zero already means no limit, so it cannot also stand for an account
// nobody holds: answering zero for one would hand an unlimited mailbox
// to an identity that does not exist.
function testAnAppendForNoLiveAccountIsRefused(mailbox, alice) {
  var outcome = appendOrThrown(mailbox, "acct_nobody_holds_this", "INBOX",
    messageOf(alice.address, "For nobody", 10));
  count("an append whose actor names no live account is refused",
    outcome.thrown !== undefined, outcome.thrown === undefined ? "it was stored" : "");
  count("and the refusal says the account is the problem rather than the quota",
    outcome.thrown.code === "store/no-such-account" ||
    outcome.thrown.code === "mailbox/no-such-account",
    outcome.thrown.code + ": " + outcome.thrown.message);
}

// Deleting mail has to give the budget back, or a capped account fills
// up once and stays full however much its owner clears out.
async function testExpungingReturnsTheBudget(mailbox, alice, filler) {
  var actor = { id: alice.id, address: alice.address, roles: ["account"] };
  var outcome = await mailbox.expungeObjects(actor, "INBOX", [filler.objectid]);
  count("the message under the cap can be destroyed",
    Array.isArray(outcome.deleted) && outcome.deleted.indexOf(filler.objectid) !== -1,
    JSON.stringify(outcome));

  var again = appendOrThrown(mailbox, alice.id, "INBOX",
    messageOf(alice.address, "After the clear out", FILLER_PAD));
  count("and the space it held is available to the next message",
    again.thrown === undefined && typeof again.stored.objectid === "string",
    again.thrown === undefined ? again.stored.objectid : again.thrown.message);
  return again.stored;
}

// ---- the cap on the wire ---------------------------------------------------

// APPEND carries its message as a literal, and RFC 9051 section 4.3
// has the client announce the octet count and wait for the server's
// continuation before sending it. Section 7.5 makes that continuation a
// line opening with `+`, and a conforming client waits for exactly that
// line and for nothing else.
//
// So the read below is anchored on the start of a line. Reading it any
// looser would accept an untagged response whose text merely happens to
// begin with a plus, which is a shape a conforming client waits through
// forever, and a session that tolerates it measures the rest of the
// path while APPEND is unusable in the field.
//
// The other route stays closed on purpose. LITERAL+ (RFC 7888) would
// let the client skip the continuation altogether, and the guard
// refuses it under the strict profile this server ships, which is also
// why CAPABILITY does not advertise it. The synchronising exchange is
// therefore the only way an APPEND completes here, which is what makes
// the shape of the continuation load-bearing rather than cosmetic.
var CONTINUATION = /^\+ Ready for literal data/m;

async function appendOverTheWire(session, payload, label) {
  var tag = session.tag();
  session.send(tag + " APPEND INBOX {" + Buffer.byteLength(payload, "utf8") + "}");
  var ready = await session.read(/^(?:(?:\* )?\+|\* BAD|\S+ (?:NO|BAD))/m,
    label + " continuation");
  session.sendRaw(payload + "\r\n", "<" + label + ">");
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    label + " answered");
  return { ready: ready, reply: reply };
}

async function testTheWireRefusalCarriesTheResponseCode(port, caPem, alice) {
  var session = await Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME, label: "imap-quota",
    address: alice.address, password: ALICE_PASSWORD,
  });
  try {
    var advertised = session.tag();
    session.send(advertised + " CAPABILITY");
    var caps = await session.read(new RegExp("^" + advertised + " OK", "m"), "capabilities");
    count("the listener does not advertise the extension that would let a client " +
      "skip the literal continuation", caps.indexOf("LITERAL+") === -1, visible(caps));

    var accepted = await appendOverTheWire(session,
      messageOf(alice.address, "Wire under the cap", 200).toString("utf8"), "under-cap");
    count("the literal is answered with the continuation request RFC 9051 section 7.5 " +
      "defines, which is the line a conforming client waits for",
      CONTINUATION.test(accepted.ready), visible(accepted.ready));
    count("and not as an untagged response whose text merely opens with a plus",
      !/^\* \+/m.test(accepted.ready), visible(accepted.ready));
    count("a message under the cap is accepted over the wire",
      /OK \[APPENDUID/.test(accepted.reply), visible(accepted.reply));
    // The second half of the same wire defect. RFC 9051 section 4.3 has
    // the CRLF after the literal terminate the command, and the
    // vendored listener completes the command as soon as the announced
    // octets arrive, so that CRLF is then read as a fresh line and
    // answered as an empty one. Every APPEND a conforming client sends
    // draws an untagged BAD it did nothing to earn. Pinned for the same
    // reason as the continuation above.
    count("the trailing CRLF of the literal is still answered as an empty command, " +
      "so an APPEND draws an untagged refusal beside its own reply. Tighten this " +
      "file when a refresh fixes it",
      /^\* BAD [^\r\n]*empty command line/m.test(accepted.reply), visible(accepted.reply));

    var refused = await appendOverTheWire(session,
      messageOf(alice.address, "Wire over the cap", OVER_CAP_PAD).toString("utf8"), "over-cap");
    count("the message that crosses the cap is refused over the wire",
      /^\S+ NO /m.test(refused.reply), visible(refused.reply));
    count("and the refusal carries the response code RFC 9208 section 5 defines, " +
      "which is the one thing a client can act on",
      refused.reply.indexOf("[OVERQUOTA]") !== -1, visible(refused.reply));
    return session.transcript();
  } finally {
    session.close();
  }
}

// A second account on the same listener, because a cap enforced on the
// connection rather than on the account would refuse this one too.
async function testAnotherAccountOnTheSameListenerIsUnaffected(port, caPem, carla) {
  var session = await Wire.imap(port, {
    caPem: caPem, servername: HOSTNAME, label: "imap-quota-uncapped",
    address: carla.address, password: CARLA_PASSWORD,
  });
  try {
    var outcome = await appendOverTheWire(session,
      messageOf(carla.address, "Uncapped over the wire", OVER_CAP_PAD).toString("utf8"),
      "uncapped");
    count("an account with no cap appends the same message the capped one could not",
      /OK \[APPENDUID/.test(outcome.reply), visible(outcome.reply));
  } finally {
    session.close();
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("quota");
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
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });

    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD, quotaBytes: CAP_BYTES });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: BOB_PASSWORD, quotaBytes: CAP_BYTES });
    var carla = await identity.accounts.create({
      address: "carla@" + DOMAIN, password: CARLA_PASSWORD });
    count("the two capped accounts carry the cap the operator set",
      alice.quotaBytes === CAP_BYTES && bob.quotaBytes === CAP_BYTES,
      JSON.stringify([alice.quotaBytes, bob.quotaBytes]));
    count("and the third is left at the default, which is no limit",
      carla.quotaBytes === 0, String(carla.quotaBytes));

    var mailbox = identity.mailbox;
    var filler = testAMessageUnderTheCapIsStored(mailbox, alice);
    testAMessageOverTheCapIsRefused(mailbox, alice);
    testTheCapIsCountedPerAccount(mailbox, bob, carla);
    testAnAppendForNoLiveAccountIsRefused(mailbox, alice);
    var replacement = await testExpungingReturnsTheBudget(mailbox, alice, filler);

    // Clear the space back out before the wire run, so the sizes the
    // session below sends are measured against a known budget rather
    // than against whatever the append cases happened to leave.
    await mailbox.expungeObjects(
      { id: alice.id, address: alice.address, roles: ["account"] },
      "INBOX", [replacement.objectid]);

    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = {
        enabled: names[i] === "imap",
        port:    await wire.reservePort(),
        address: LOOPBACK,
      };
    }

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var imapPort = server.mail.listeners.bound().imap;
    count("the IMAP listener took its port", typeof imapPort === "number" && imapPort > 0,
      String(imapPort));

    await testTheWireRefusalCarriesTheResponseCode(imapPort, material.caPem, alice);
    await testAnotherAccountOnTheSameListenerIsUnaffected(imapPort, material.caPem, carla);

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

module.exports = { name: "mailbox-quota", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
