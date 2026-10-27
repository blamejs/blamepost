// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What one IMAP session costs the server, measured against what it asked.
 *
 * Three bounds, each read on a real session against the listener.
 *
 * An APPEND is refused on its announcement when the literal is larger
 * than the operator's message ceiling. The message store refuses such a
 * message at the append in any case, and refusing it there means the
 * server has already buffered every octet of a message it was always
 * going to refuse.
 *
 * An IDLE that ends because the client went away leaves nothing
 * scheduled behind it. RFC 2177 has the server end an IDLE that runs
 * past about thirty minutes, and a timer for that ceiling that outlives
 * the session keeps the session's socket and state in memory for the
 * rest of the half hour.
 *
 * A command naming one message reads one message. The flags of a
 * message are kept beside its sealed fields, and the only read that
 * returns them opens all of them, so a FETCH or STORE that read the
 * whole folder to answer about one message cost a folder's worth of
 * unsealing, synchronously, on every command. Measured at a thousand
 * messages that was about five seconds per command, during which no
 * other connection on the server was served. The count of reads is what
 * is asserted here, because a count does not depend on the machine.
 *
 * Run standalone: node test/layer-2-integration/imap-session-resource-bounds.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var b = helpers.b;

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var ALICE_PASSWORD   = "a long enough account password for one test run";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The lowest message ceiling the configuration schema accepts, so the
// literal above it is small enough to send whole if it is invited.
var MESSAGE_CEILING = 64 * 1024;

// Enough messages that a read of the whole folder and a read of one
// message cannot be mistaken for each other.
var FOLDER_MESSAGES = 30;

// How long an IDLE may run before the server ends it. Timers shorter
// than this are the listener's ordinary bookkeeping and not the ceiling.
var IDLE_CEILING_FLOOR_MS = 20 * 60 * 1000;

async function ask(session, command, what) {
  var tag = session.tag();
  session.send(tag + " " + command);
  var text = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)[^\\r\\n]*\\r\\n", "m"),
    what || command);
  return { text: text, verdict: new RegExp("^" + tag + " (OK|NO|BAD)", "m").exec(text)[1] };
}

function messageOfSize(marker, size) {
  var head = "From: sender@example.net\r\nTo: alice@" + DOMAIN + "\r\nSubject: " + marker +
    "\r\n\r\n";
  var pad = size - Buffer.byteLength(head) - 2;
  return head + "x".repeat(pad) + "\r\n";
}

// ---- cases -----------------------------------------------------------------

async function anAppendOverTheCeilingIsRefusedOnItsAnnouncement(session) {
  var tag = session.tag();
  session.send(tag + " APPEND INBOX {" + (MESSAGE_CEILING + 1) + "}");
  var reply = await session.read(new RegExp("^(\\+|" + tag + " (OK|NO|BAD)|\\* BAD)", "m"),
    "announcement answered");
  count("a literal one octet over the operator's message ceiling is refused on the announcement",
    new RegExp("^" + tag + " NO", "m").test(reply), visible(reply));
  count("so the continuation that invites the octets is never sent",
    !/^\+/m.test(reply), visible(reply));
  count("and the refusal names the ceiling it was measured against",
    reply.indexOf(String(MESSAGE_CEILING)) !== -1, visible(reply));

  // The other side of the boundary, so the refusal is the ceiling and not
  // a literal limit set somewhere below it.
  var atCeiling = messageOfSize("at-the-ceiling", MESSAGE_CEILING);
  var fits = session.tag();
  await session.sendLiteral(fits + " APPEND INBOX", atCeiling, "<a message at the ceiling>");
  var accepted = await session.read(new RegExp("^" + fits + " (OK|NO|BAD)", "m"),
    "APPEND at the ceiling answered");
  count("a message exactly at the ceiling is invited and stored",
    new RegExp("^" + fits + " OK", "m").test(accepted), visible(accepted));
}

// The ceiling timer the listener schedules for an IDLE is caught as it
// is created, and the question is whether it is canceled once the
// client that issued the IDLE is gone. The listener schedules through
// the global timer functions, so wrapping them for the length of one
// command sees exactly what it schedules and cancels.
async function anIdleEndedByTheClientLeavesNothingScheduled(openSession) {
  var realSet   = global.setTimeout;
  var realClear = global.clearTimeout;
  var scheduled = [];
  var canceled  = new Set();
  global.setTimeout = function (fn, ms) {
    var timer = realSet.apply(this, arguments);
    if (typeof ms === "number" && ms >= IDLE_CEILING_FLOOR_MS) scheduled.push(timer);
    return timer;
  };
  global.clearTimeout = function (timer) {
    canceled.add(timer);
    return realClear.apply(this, arguments);
  };
  try {
    // Only what the IDLE command itself schedules is counted, so a long
    // timer the sign-in path happens to arm cannot stand in for it.
    var dropped = await openSession("idle dropped");
    var tag = dropped.tag();
    var before = scheduled.length;
    dropped.send(tag + " IDLE");
    var idling = await dropped.read(/^(\+|\S+ (NO|BAD))/m, "IDLE answered");
    count("IDLE is accepted with a continuation", /^\+/m.test(idling), visible(idling));
    count("and the listener schedules a ceiling for it",
      scheduled.length - before === 1, String(scheduled.length - before));

    var ceiling = scheduled[before];
    dropped.close();
    var released = true;
    try {
      await helpers.waitUntil(function () { return canceled.has(ceiling); }, {
        timeoutMs: 5000,
        label:     "imap resource bounds: the IDLE ceiling is canceled once the client is gone",
      });
    } catch (_e) { released = false; }
    count("the ceiling of an IDLE whose client disconnected is canceled",
      released, "canceled " + canceled.has(ceiling));

    // The ordinary end, for contrast: DONE completes the IDLE and cancels
    // the ceiling in the same step.
    var finished = await openSession("idle done");
    var doneTag = finished.tag();
    var beforeDone = scheduled.length;
    finished.send(doneTag + " IDLE");
    await finished.read(/^\+/m, "IDLE answered");
    count("the second IDLE schedules its own ceiling",
      scheduled.length - beforeDone === 1, String(scheduled.length - beforeDone));
    var second = scheduled[beforeDone];
    finished.send("DONE");
    var done = await finished.read(new RegExp("^" + doneTag + " (OK|NO|BAD)", "m"), "DONE answered");
    count("DONE completes the IDLE", new RegExp("^" + doneTag + " OK", "m").test(done),
      visible(done));
    count("and cancels its ceiling", canceled.has(second), String(canceled.has(second)));
    finished.close();
  } finally {
    global.setTimeout   = realSet;
    global.clearTimeout = realClear;
  }
}

async function aCommandNamingOneMessageReadsOneMessage(session, identity, alice) {
  for (var i = 0; i < FOLDER_MESSAGES; i += 1) {
    identity.mailbox.appendMessage("Archive",
      Buffer.from(messageOfSize("folder-" + (i + 1), 512)), { actor: { id: alice.id } });
  }
  await ask(session, "SELECT Archive");

  var messageStore = identity.messageStore;
  var realFetch = messageStore.fetchByObjectId;
  var reads = 0;
  messageStore.fetchByObjectId = function () {
    reads += 1;
    return realFetch.apply(this, arguments);
  };
  async function readsFor(command) {
    reads = 0;
    var answer = await ask(session, command);
    return { reads: reads, text: answer.text, verdict: answer.verdict };
  }
  try {
    var uidOnly = await readsFor("FETCH 1 (UID)");
    count("FETCH of one message's UID reads no stored message row",
      uidOnly.verdict === "OK" && uidOnly.reads === 0, uidOnly.reads + " " + visible(uidOnly.text));

    var stored = await readsFor("STORE 5 +FLAGS (\\Flagged)");
    count("STORE on one message reads that one message and no other",
      stored.verdict === "OK" && stored.reads === 1, stored.reads + " " + visible(stored.text));

    var flags = await readsFor("FETCH 5 (FLAGS)");
    count("FETCH of one message's flags reads that one message",
      flags.reads === 1, String(flags.reads));
    // Matched loosely, because the list also carries the mark recorded
    // when the message was filed saying whether it carries files. What
    // this reads is that the STORE above landed.
    count("and the flags are the ones just set",
      /^\* 5 FETCH \(FLAGS \([^)]*\\Flagged[^)]*\)\)/m.test(flags.text), visible(flags.text));

    var uids = await ask(session, "FETCH 7 (UID)");
    var uid7 = /UID (\d+)/.exec(uids.text)[1];
    var peek = await readsFor("UID FETCH " + uid7 + " (BODY.PEEK[HEADER.FIELDS (SUBJECT)])");
    count("a peeking read of one message's header reads no stored message row",
      peek.reads === 0, String(peek.reads));
    count("and returns that message's subject",
      /Subject: folder-7\b/.test(peek.text), visible(peek.text));

    var body = await readsFor("FETCH 9 BODY[]");
    count("a read that marks one message seen reads that one message",
      body.reads === 1, String(body.reads));
    var seen = await readsFor("FETCH 9 (FLAGS)");
    count("and the message is marked seen", /\\Seen/.test(seen.text), visible(seen.text));

    // The whole-folder question still reads the whole folder: this is the
    // ceiling, recorded so a change to it is seen.
    var all = await readsFor("FETCH 1:* (FLAGS)");
    count("FETCH of every message's flags reads every message once",
      all.reads === FOLDER_MESSAGES, String(all.reads));
  } finally {
    messageStore.fetchByObjectId = realFetch;
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("imap-session-resource-bounds");
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
  var sessions = [];
  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });

    // Through the environment rather than onto the loaded object, so the
    // store and the listeners read the same ceiling from the same place.
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_LIMITS:           JSON.stringify({ maxMessageBytes: MESSAGE_CEILING }),
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, listeners: sections, inbound: { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    async function openSession(label) {
      var opened = await Wire.imap(sections.imap.port, {
        caPem: leaf.ca, servername: HOSTNAME,
        address: alice.address, password: ALICE_PASSWORD,
        label: "imap-session-resource-bounds " + label,
      });
      sessions.push(opened);
      return opened;
    }

    var session = await openSession("main");
    await anAppendOverTheCeilingIsRefusedOnItsAnnouncement(session);
    await anIdleEndedByTheClientLeavesNothingScheduled(openSession);
    await aCommandNamingOneMessageReadsOneMessage(session, identity, alice);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    sessions.forEach(function (s) { s.close(); });
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
  name: "imap-session-resource-bounds", run: run, getChecks: helpers.getChecks,
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
