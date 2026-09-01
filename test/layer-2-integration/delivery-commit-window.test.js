// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a message leaves behind when the answer changes while it is being
 * delivered, driven through a real submission listener with a real mail
 * client on a real socket and through a real MX listener with a real
 * peer on another.
 *
 * Delivering one message is several writes: a copy into every mailbox on
 * this server that the envelope names, and an entry in the outbound
 * queue for every recipient that is somewhere else. SMTP gives all of
 * them one reply. So the moment a refusal is raised decides whether the
 * sender's retry is a delivery or a second copy: a message refused
 * before anything is written is one the sender still holds, and a
 * message refused after a mailbox already has it is one that arrives
 * twice.
 *
 * Two answers can change between the moment they are read and the moment
 * they are acted on, and both are read by every message:
 *
 *   - whether the outbound queue has room. It is one directory shared by
 *     every connection and by the retry sweep, so a reading of how full
 *     it is answers about the moment it was taken and about nothing
 *     later.
 *   - whether a recipient still has somewhere to land. An operator
 *     suspending a mailbox during an incident does it while mail is
 *     arriving, which is the whole point of doing it.
 *
 * The claims:
 *
 *   - A message the sender was told to try again leaves no copy behind.
 *     The mailbox holds exactly one copy after the refusal and the retry
 *     that follows it, on both listeners.
 *   - A mailbox suspended while the message is being transmitted does
 *     not receive it, on both listeners.
 *   - The outbound queue never holds more than the ceiling an operator
 *     configured, however many connections crossed it at once.
 *
 * The interleavings are arranged rather than raced. A test that waited
 * for two sessions to land in the right order would reproduce the
 * failure only sometimes, which is worse than no test at all. Each
 * vector wraps ONE primitive so that the single call carrying that
 * vector's marker parks until this file releases it; every other call
 * runs the real primitive untouched, and the wrapper is armed only for
 * the window between the recipient being accepted and the message being
 * transmitted. Nothing about the code path under test changes: the same
 * listeners, the same store, the same queue, in the same order. Only the
 * moment one call finishes is this file's to choose.
 *
 * The resolver answers so a recipient elsewhere gets past MX lookup.
 * Nothing leaves the machine: there is no transport behind the composer,
 * so no outbound socket is opened and every remote recipient defers into
 * the queue, which is what fills it.
 *
 * Run standalone: node test/layer-2-integration/delivery-commit-window.test.js
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
var VECTOR_TIMEOUT_MS   = 60000;

// How long a parked call may stay parked before this file gives up on
// the session that is supposed to reach it. Generous, because what it is
// waiting on is a whole wire session on a loaded runner.
var PARK_TIMEOUT_MS = 30000;

// The ceiling this run holds the server to, and the share of it a
// message arriving from a stranger may take. The share is read from the
// handle rather than restated, so a change to the reserved fraction
// moves this file with it instead of leaving it measuring the wrong
// number and still passing.
var MAX_SPOOL_MESSAGES = 10;

var BODY_PREFIX = "Ordering two more of the blue ones. Marker ";

// The vectors, named once. Each is a claim about what is on disk after
// the interleaving, printed at the end as the unit examined: a run that
// exercised one window and a run that exercised five otherwise report
// the same check total and neither says which happened.
var WINDOWS_EXAMINED = 5;

var ANSWERING_RESOLVER = {
  queryMx: function (name) {
    var domain = String(name).toLowerCase();
    if (domain === ELSEWHERE) {
      return Promise.resolve([{ priority: 10, exchange: "mx." + ELSEWHERE }]);
    }
    return Promise.reject(new Error("no mail exchanger for " + name));
  },
  queryTxt: function () { return Promise.resolve([]); },
  queryPtr: function () { return Promise.resolve([]); },
  query:    function () { return Promise.resolve([]); },
};

var count = helpers.count;

function spoolIds(dataDir) {
  var dir = nodePath.join(dataDir, "queue");
  if (!nodeFs.existsSync(dir)) return [];
  return nodeFs.readdirSync(dir)
    .filter(function (n) { return n.slice(-5) === ".json"; })
    .map(function (n) { return n.slice(0, -5); })
    .sort();
}

function spoolDepth(ctx) { return spoolIds(ctx.dataDir).length; }

// ---------------------------------------------------------------------------
// The seams
// ---------------------------------------------------------------------------

// A gate parks the ONE call this vector names and lets every other call
// through to the real primitive. `arm` opens the window, so a call the
// same session made earlier runs untouched: the routing question the MX
// listener answers at RCPT is one of those.
function _gate(label) {
  return {
    label:  label,
    armed:  false,
    parked: null,
    arm:    function () { this.armed = true; },
  };
}

// The mailbox write, wrapped so the call carrying this vector's marker
// parks AFTER the copy has landed. That is the state the claim is about:
// the mailbox already holds the message and the rest of the message has
// not been decided yet.
function installAppendGate(mailboxHandle, marker) {
  var gate = _gate("mailbox append");
  var real = mailboxHandle.appendMessage;
  mailboxHandle.appendMessage = function (name, rawBytes, appendOpts) {
    var stored = real.call(mailboxHandle, name, rawBytes, appendOpts);
    var text = Buffer.isBuffer(rawBytes) ? rawBytes.toString("utf8") : String(rawBytes || "");
    if (!gate.armed || gate.parked !== null || text.indexOf(marker) === -1) return stored;
    gate.armed = false;
    return new Promise(function (resolve) {
      gate.parked = { release: function () { resolve(stored); } };
    });
  };
  gate.remove = function () { mailboxHandle.appendMessage = real; };
  return gate;
}

// The routing question, wrapped so the call naming this vector's
// recipient parks after it has been answered. What comes back when the
// gate releases is the verdict as it stood BEFORE the window, which is
// exactly what a caller holding a reading across a suspension has.
function installResolveGate(storeHandle, recipient) {
  var gate = _gate("recipient routing");
  var real = storeHandle.resolve;
  var wanted = String(recipient).toLowerCase();
  storeHandle.resolve = function (address) {
    var verdict = real(address);
    if (!gate.armed || gate.parked !== null ||
        String(address).toLowerCase() !== wanted) {
      return verdict;
    }
    gate.armed = false;
    return new Promise(function (resolve) {
      gate.parked = { release: function () { resolve(verdict); } };
    });
  };
  gate.remove = function () { storeHandle.resolve = real; };
  return gate;
}

// The volume write, wrapped so the spool body carrying this vector's
// marker parks on its way to disk. The queue reading that authorized it
// was taken before the conversation that ended here, and this is the
// point at which a second connection can still take the room.
function installSpoolWriteGate(marker) {
  var gate = _gate("spool body write");
  var real = b.atomicFile.write;
  b.atomicFile.write = function (target, payload, writeOpts) {
    var text = Buffer.isBuffer(payload) ? payload.toString("utf8") : String(payload || "");
    if (!gate.armed || gate.parked !== null || text.indexOf(marker) === -1) {
      return real.call(b.atomicFile, target, payload, writeOpts);
    }
    gate.armed = false;
    return new Promise(function (resolve, reject) {
      gate.parked = {
        release: function () {
          return real.call(b.atomicFile, target, payload, writeOpts).then(resolve, reject);
        },
      };
    });
  };
  gate.remove = function () { b.atomicFile.write = real; };
  return gate;
}

async function reachThePark(gate) {
  await helpers.waitUntil(function () { return gate.parked !== null; }, {
    timeoutMs: PARK_TIMEOUT_MS,
    label:     "delivery-commit-window: the session reaching its " + gate.label,
  });
}

// ---------------------------------------------------------------------------
// The wire sessions
// ---------------------------------------------------------------------------

function messageBytes(from, recipients, marker) {
  return [
    "From: " + from,
    "To: " + recipients.join(", "),
    "Subject: " + marker,
    "Date: Sun, 23 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + marker + "@example.com>",
    "",
    BODY_PREFIX + marker,
    "",
    ".",
    "",
  ].join("\r\n");
}

// A submission session carried as far as the terminating dot, with the
// reply to it left unread. Splitting the session in two is what lets a
// second connection run while this one is parked inside the handoff.
async function beginSubmission(ctx, recipients, marker, label) {
  var session = await Wire.submission(ctx.ports.submission, {
    caPem:      ctx.caPem,
    servername: HOSTNAME,
    address:    ctx.alice,
    password:   ALICE_PASSWORD,
    label:      label,
  });
  session.send("MAIL FROM:<" + ctx.alice + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  var accepted = [];
  for (var i = 0; i < recipients.length; i += 1) {
    session.send("RCPT TO:<" + recipients[i] + ">");
    var reply = await session.read(/^\d{3} /m, "RCPT TO answered");
    if (/^250 /m.test(reply)) accepted.push(recipients[i]);
  }
  return { session: session, rcptAccepted: accepted, recipients: recipients, marker: marker };
}

function transmit(pending, from) {
  pending.session.send("DATA");
  return pending.session.read(/^354 /m, "DATA answered").then(function () {
    pending.session.sendRaw(messageBytes(from, pending.recipients, pending.marker),
      "<the message and its terminating dot>");
  });
}

async function finish(pending) {
  var answer = await pending.session.read(/^\d{3} /m, "message answered");
  pending.session.send("QUIT");
  pending.session.close();
  return answer;
}

// One whole submission, for the sessions that have no window to hold
// open. Returns the reply to the terminating dot, which is the line the
// client acts on.
async function submit(ctx, recipients, marker, label) {
  var pending = await beginSubmission(ctx, recipients, marker, label);
  await transmit(pending, ctx.alice);
  return await finish(pending);
}

async function beginPeer(ctx, from, recipients, marker, label) {
  var session = await Wire.mx(ctx.ports.mx, {
    caPem:      ctx.caPem,
    servername: HOSTNAME,
    label:      label,
    helo:       "relay.example.org",
  });
  session.send("MAIL FROM:<" + from + ">");
  await session.read(/^\d{3} /m, "MAIL FROM answered");
  var accepted = [];
  for (var i = 0; i < recipients.length; i += 1) {
    session.send("RCPT TO:<" + recipients[i] + ">");
    var reply = await session.read(/^\d{3} /m, "RCPT TO answered");
    if (/^250 /m.test(reply)) accepted.push(recipients[i]);
  }
  return { session: session, rcptAccepted: accepted, recipients: recipients, marker: marker };
}

// ---------------------------------------------------------------------------
// Reading what landed
// ---------------------------------------------------------------------------

function filedIn(ctx, storeName) {
  return ctx.identity.messageStore.queryByModseq(storeName, { sinceModseq: 0 }).length;
}

// Fill the queue to a named depth with messages nobody here is about, so
// each vector starts from the depth its claim is written against.
async function settleSpoolTo(ctx, depth, tag) {
  var ids = spoolIds(ctx.dataDir);
  for (var d = 0; ids.length - d > depth; d += 1) {
    await ctx.server.mail.delivery.queue.remove(ids[d], {
      reason: "settling the spool to the depth this vector is written against",
      notice: { withheld: "fixture-removal" },
    });
  }
  var guard = 0;
  while (spoolDepth(ctx) < depth) {
    guard += 1;
    if (guard > MAX_SPOOL_MESSAGES * 2) {
      throw new Error("delivery-commit-window: could not fill the queue to " + depth +
        " for " + tag + "; it is holding " + spoolDepth(ctx));
    }
    var answer = await submit(ctx, ["filler" + guard + "@" + ELSEWHERE],
      tag + "-fill-" + guard, tag + "-fill-" + guard);
    if (!/^250 /m.test(answer)) {
      throw new Error("delivery-commit-window: the server refused a filler for " + tag +
        " at depth " + spoolDepth(ctx) + ": " + visible(answer));
    }
  }
  return spoolDepth(ctx);
}

// ---------------------------------------------------------------------------
// A refusal raised after a mailbox already holds the message
// ---------------------------------------------------------------------------

// Submission. The envelope names one mailbox here and one recipient
// elsewhere. The local copy is filed, and only then is the queue asked
// about the recipient that has to leave. A client answered 4xx sends the
// whole message again.
async function aRefusedSubmissionLeavesNoCopyBehind(ctx) {
  var marker = "commit-window-submission";
  await settleSpoolTo(ctx, MAX_SPOOL_MESSAGES - 1, "submission-window");
  var before = filedIn(ctx, ctx.bob.storeName);
  count("the mailbox this message is addressed to starts empty", before === 0, String(before));

  var gate = installAppendGate(ctx.identity.mailbox, marker);
  var answer;
  try {
    var pending = await beginSubmission(ctx,
      [ctx.bob.address, "onward@" + ELSEWHERE], marker, "submission-window");
    count("both recipients were accepted at RCPT, so the crossing is at the message",
      pending.rcptAccepted.length === 2, pending.rcptAccepted.join(" "));

    gate.arm();
    await transmit(pending, ctx.alice);
    await reachThePark(gate);
    count("the message has reached a mailbox and has not yet reached the queue",
      filedIn(ctx, ctx.bob.storeName) === before + 1,
      String(filedIn(ctx, ctx.bob.storeName)));

    // A second connection takes the last slot while the first is holding
    // a copy it has already filed. This is the ordinary case: two people
    // sending at once on a server whose queue is nearly full.
    var rival = await submit(ctx, ["rival@" + ELSEWHERE], marker + "-rival", "submission-rival");
    count("a second session met the queue while the first was mid-message",
      /^\d{3} /m.test(rival), visible(rival));

    gate.parked.release();
    answer = await finish(pending);
  } finally {
    gate.remove();
  }

  var afterFirst = filedIn(ctx, ctx.bob.storeName);
  count("the first attempt filed one copy", afterFirst === before + 1, String(afterFirst));

  // What a mail client does with a 4xx: it keeps the message and sends
  // it again once there is room. Nothing is retried after a 250, so the
  // retry runs only when the server asked for one.
  var retried = null;
  if (/^4\d\d[ -]/m.test(answer)) {
    var ids = spoolIds(ctx.dataDir);
    if (ids.length > 0) {
      await ctx.server.mail.delivery.queue.remove(ids[0],
        { reason: "making room before the retry", notice: { withheld: "fixture-removal" } });
    }
    retried = await submit(ctx, [ctx.bob.address, "onward@" + ELSEWHERE], marker,
      "submission-window-retry");
  }

  var landed = filedIn(ctx, ctx.bob.storeName) - before;
  count("a message the sender was told to try again leaves exactly one copy in the mailbox",
    landed === 1,
    landed + " copy(ies) after first answer " + visible(answer) +
    (retried === null ? " with no retry" : " and retry " + visible(retried)));
}

// The MX listener, over an envelope that names one mailbox here and one
// alias forwarding off this server. Same shape, different listener, and
// the party that retries is a peer rather than a person.
async function aRefusedPeerMessageLeavesNoCopyBehind(ctx) {
  var marker = "commit-window-inbound";
  var strangerCeiling = ctx.server.describe().outbound.spool.forwarding.maxMessages;
  await settleSpoolTo(ctx, strangerCeiling - 1, "inbound-window");
  var before = filedIn(ctx, ctx.carol.storeName);
  count("the mailbox this message is addressed to starts empty", before === 0, String(before));

  var gate = installAppendGate(ctx.identity.mailbox, marker);
  var answer;
  try {
    var pending = await beginPeer(ctx, "stranger@example.org",
      [ctx.carol.address, ctx.aliasAddress], marker, "inbound-window");
    count("both recipients were accepted at RCPT, so the crossing is at the message",
      pending.rcptAccepted.length === 2, pending.rcptAccepted.join(" "));

    gate.arm();
    await transmit(pending, "stranger@example.org");
    await reachThePark(gate);
    count("the peer's message has reached a mailbox and has not yet reached the queue",
      filedIn(ctx, ctx.carol.storeName) === before + 1,
      String(filedIn(ctx, ctx.carol.storeName)));

    var rival = await submit(ctx, ["rival@" + ELSEWHERE], marker + "-rival", "inbound-rival");
    count("a second session met the queue while the peer was mid-message",
      /^\d{3} /m.test(rival), visible(rival));

    gate.parked.release();
    answer = await finish(pending);
  } finally {
    gate.remove();
  }

  var retried = null;
  if (/^4\d\d[ -]/m.test(answer)) {
    var ids = spoolIds(ctx.dataDir);
    if (ids.length > 0) {
      await ctx.server.mail.delivery.queue.remove(ids[0],
        { reason: "making room before the retry", notice: { withheld: "fixture-removal" } });
    }
    var again = await beginPeer(ctx, "stranger@example.org",
      [ctx.carol.address, ctx.aliasAddress], marker, "inbound-window-retry");
    await transmit(again, "stranger@example.org");
    retried = await finish(again);
  }

  var landed = filedIn(ctx, ctx.carol.storeName) - before;
  count("a peer told to try again leaves exactly one copy in the mailbox",
    landed === 1,
    landed + " copy(ies) after first answer " + visible(answer) +
    (retried === null ? " with no retry" : " and retry " + visible(retried)));
}

// ---------------------------------------------------------------------------
// A mailbox suspended while the message is being transmitted
// ---------------------------------------------------------------------------

async function aMailboxSuspendedDuringDataReceivesNothing(ctx, who, listener) {
  var marker = "commit-window-suspend-" + listener;
  var before = filedIn(ctx, who.storeName);
  count(listener + ": the mailbox starts empty before it is suspended",
    before === 0, String(before));

  var gate = installResolveGate(ctx.identity, who.address);
  var answer;
  try {
    var pending = listener === "submission"
      ? await beginSubmission(ctx, [who.address], marker, "suspend-" + listener)
      : await beginPeer(ctx, "stranger@example.org", [who.address], marker,
        "suspend-" + listener);
    count(listener + ": the mailbox was reachable when the recipient was accepted",
      pending.rcptAccepted.length === 1, pending.rcptAccepted.join(" "));

    gate.arm();
    await transmit(pending, listener === "submission" ? ctx.alice : "stranger@example.org");
    await reachThePark(gate);

    // The containment step, landing inside the window the message is
    // already open across. This is what an operator does when a mailbox
    // is being used to receive something they want stopped.
    await ctx.identity.accounts.suspend({
      id:     who.id,
      reason: "reported for receiving mail the operator wants stopped",
    });
    count(listener + ": the mailbox is suspended while the message is still on the wire",
      ctx.identity.accounts.get(who.id).status === "suspended",
      ctx.identity.accounts.get(who.id).status);

    gate.parked.release();
    answer = await finish(pending);
  } finally {
    gate.remove();
    await ctx.identity.accounts.reinstate({ id: who.id });
  }

  var landed = filedIn(ctx, who.storeName) - before;
  count(listener + ": a mailbox suspended during the message receives nothing",
    landed === 0, landed + " copy(ies), the sender was answered " + visible(answer));

  // What the sender is told differs by listener, and each is the answer
  // the message deserves. Nothing on the peer's message could be
  // delivered, so it is handed back and the peer retries on its own
  // schedule against a condition an operator can lift. The account
  // holder's message was handled, and the address that stopped accepting
  // mail comes back to them as a delivery report rather than as a
  // refusal of everything they sent, which is the same answer they get
  // for a mailbox that was already suspended when they sent.
  count(listener + ": the sender is answered the way this listener answers a recipient that " +
    "has stopped accepting mail",
    listener === "inbound" ? /^4\d\d[ -]/m.test(answer) : /^250 /m.test(answer),
    visible(answer));
}

// ---------------------------------------------------------------------------
// The ceiling, with two connections crossing it at once
// ---------------------------------------------------------------------------

async function theQueueNeverHoldsMoreThanItsCeiling(ctx) {
  var marker = "commit-window-ceiling";
  var start = await settleSpoolTo(ctx, MAX_SPOOL_MESSAGES - 1, "ceiling-window");
  count("the queue starts one slot below its ceiling",
    start === MAX_SPOOL_MESSAGES - 1, String(start));

  var gate = installSpoolWriteGate(marker);
  var first;
  var rival;
  try {
    var pending = await beginSubmission(ctx, ["held@" + ELSEWHERE], marker, "ceiling-first");
    gate.arm();
    await transmit(pending, ctx.alice);
    await reachThePark(gate);
    count("the first message has been admitted and is on its way to the queue",
      spoolDepth(ctx) === start, String(spoolDepth(ctx)));

    // The second connection asks the same question of the same queue and
    // is answered from a reading the first one has already spent.
    rival = await submit(ctx, ["rival@" + ELSEWHERE], marker + "-rival", "ceiling-rival");

    await gate.parked.release();
    first = await finish(pending);
  } finally {
    gate.remove();
  }

  var depth = spoolDepth(ctx);
  count("the queue never holds more than the ceiling the operator configured",
    depth <= MAX_SPOOL_MESSAGES,
    depth + " of " + MAX_SPOOL_MESSAGES + "; first answer " + visible(first) +
    ", second answer " + visible(rival));
  count("and one of the two was taken, so the ceiling bounds rather than latches",
    /^250 /m.test(first) || /^250 /m.test(rival),
    visible(first) + " / " + visible(rival));
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("delivery-commit-window");
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "delivery commit window test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });
    var bob = await identity.accounts.create({
      address: "bob@" + DOMAIN, password: ALICE_PASSWORD });
    var carol = await identity.accounts.create({
      address: "carol@" + DOMAIN, password: ALICE_PASSWORD });
    var dave = await identity.accounts.create({
      address: "dave@" + DOMAIN, password: ALICE_PASSWORD });
    var erin = await identity.accounts.create({
      address: "erin@" + DOMAIN, password: ALICE_PASSWORD });

    // The alias is the route a stranger's message takes off this server,
    // which is what puts an inbound message in the outbound queue.
    var aliasAddress = "forwards@" + DOMAIN;
    await identity.aliases.add({
      address:     aliasAddress,
      destination: "onward@" + ELSEWHERE,
    });

    // Resolved while every account is still active, because two of these
    // mailboxes are suspended mid-vector and a folder listing taken then
    // would be answering a different question.
    function inboxOf(account) {
      var folders = identity.mailbox.accountFolders({ id: account.id });
      var inbox = folders.filter(function (f) { return f.name === "INBOX"; })[0];
      if (!inbox) throw new Error("delivery-commit-window: " + account.address + " has no INBOX");
      return { id: account.id, address: account.address, storeName: inbox.storeName };
    }

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
        // the queue at all rather than ending it on its first attempt.
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
      bob:          inboxOf(bob),
      carol:        inboxOf(carol),
      dave:         inboxOf(dave),
      erin:         inboxOf(erin),
      aliasAddress: aliasAddress,
      server:       server,
      identity:     identity,
      dataDir:      dataDir,
    };

    await helpers.withTestTimeout("commit window: a refused submission leaves no copy behind",
      function () { return aRefusedSubmissionLeavesNoCopyBehind(ctx); },
      { timeoutMs: VECTOR_TIMEOUT_MS });
    await helpers.withTestTimeout("commit window: a refused peer message leaves no copy behind",
      function () { return aRefusedPeerMessageLeavesNoCopyBehind(ctx); },
      { timeoutMs: VECTOR_TIMEOUT_MS });
    await helpers.withTestTimeout("commit window: a mailbox suspended during submission",
      function () { return aMailboxSuspendedDuringDataReceivesNothing(ctx, ctx.dave, "submission"); },
      { timeoutMs: VECTOR_TIMEOUT_MS });
    await helpers.withTestTimeout("commit window: a mailbox suspended during inbound delivery",
      function () { return aMailboxSuspendedDuringDataReceivesNothing(ctx, ctx.erin, "inbound"); },
      { timeoutMs: VECTOR_TIMEOUT_MS });
    await helpers.withTestTimeout("commit window: the queue never passes its ceiling",
      function () { return theQueueNeverHoldsMoreThanItsCeiling(ctx); },
      { timeoutMs: VECTOR_TIMEOUT_MS });

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
  name:      "delivery-commit-window",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that exercised
// one window and a run that exercised five otherwise report the same
// total and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + WINDOWS_EXAMINED + " delivery-window");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
