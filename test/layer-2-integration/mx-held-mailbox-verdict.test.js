// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a sending server is told when the mailbox it is delivering to is
 * out of service, asked once per state a mailbox can be held in.
 *
 * `tables.ACCOUNT_STATUS` declares four states and three of them refuse
 * delivery. Two of those three lift: a suspension is applied to be
 * lifted, and an archived account is reinstatable on purpose. The answer
 * for both is temporary, so the peer keeps the message and retries, and
 * the mail lands when the operator puts the mailbox back.
 *
 * The third does not lift. An account part way through an erasure has
 * had its mail destroyed, `reinstate` refuses it in as many words, and
 * the only way out of the state is the row going, after which the
 * address resolves to no mailbox at all and is answered permanently.
 * There is no future in which a retry against it succeeds. Answering it
 * temporarily spends the sending server's entire retry window against an
 * address that can never accept the message and then bounces to the
 * person who sent it days late, with a report that says the condition
 * was transient.
 *
 * The refusal reaches the wire through one table lookup with one
 * fallback, and the fallback answers for the whole `account-` family. A
 * table entry is read first, so naming the terminal state in the table
 * changes that state and leaves the other two on the fallback. That
 * precedence is what these cases measure: the erasing mailbox has to
 * move and the other two have to stay exactly where they were, or the
 * entry is not an entry, it is a rewrite of the family.
 *
 * Everything asserted here is decided at RCPT, which is where RFC 5321
 * section 3.3 puts a verdict about a mailbox. That matters twice over: a
 * permanent answer at RCPT costs one command instead of a whole message
 * body, and it reaches the peer before it has transmitted anything, so
 * the sender is told about the address rather than about a message that
 * was accepted and then could not be filed.
 *
 * Four claims:
 *
 *   - A mailbox in service is accepted, so every refusal below is about
 *     the state rather than about a listener that stopped working.
 *   - A suspended mailbox is accepted at RCPT, because the condition
 *     lifts and the sender's own retry is the right place for the
 *     message to wait.
 *   - An archived mailbox is too, for the same reason: archiving is
 *     reversible, and a mailbox closed by mistake is a support call.
 *   - A mailbox part way through an erasure is refused permanently, with
 *     the code an operator filters for and a sentence that tells the
 *     sender's postmaster to stop trying.
 *
 * The erasing row is produced the way an erasure actually stops, with a
 * preservation order over a message the erasure was asked to destroy.
 * A status written onto a row by hand would prove that the listener
 * reads a column, not that it answers the state an operator can reach.
 *
 * Run standalone: node test/layer-2-integration/mx-held-mailbox-verdict.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var tables    = require("../../lib/store/tables");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var MAILBOX_PASSWORD = "quiet lantern bicycle 4291";

// One subject per state. A single subject moved between states would
// leave every case measuring a row an earlier case had already changed,
// and two of these states refuse the verb that would move them.
var ACTIVE    = "clara@" + DOMAIN;
var SUSPENDED = "holly@" + DOMAIN;
var ARCHIVED  = "ivy@" + DOMAIN;
var ERASING   = "jack@" + DOMAIN;

// The sender a peer writes. Nobody here owns it, which is what inbound
// mail from the internet looks like.
var PEER_SENDER = "postmaster@peer.example.net";

// What keeps the erasure from finishing, so the run holds a real
// `erasing` row. An order names a record and the rule keeping it, which
// is what an operator answering the erasure request has to quote.
var HOLD_REASON   = "preservation order 24-cv-01933";
var HOLD_CITATION = "FRCP-26";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The three states that refuse delivery, read from the frozen list
// rather than spelled out. A fifth status added to the store arrives
// here as a case with no subject rather than as a silent hole.
var OUT_OF_SERVICE = tables.ACCOUNT_STATUS.filter(function (name) {
  return name !== "active";
});

// Which subject stands in each state, so the loop below names its own
// coverage rather than trusting that four constants were all used.
var SUBJECT_IN = {
  suspended: SUSPENDED,
  archived:  ARCHIVED,
  erasing:   ERASING,
};

// The states whose condition lifts, and the one that does not. Both are
// declared, because an asymmetry nobody wrote down is one the next
// reader closes by accident.
var LIFTS      = ["suspended", "archived"];
var IRREVERSIBLE = ["erasing"];

var count = helpers.count;

// The message the order is placed over. The adapter keeps the bytes it
// was handed rather than a re-encoding, so anything built another way
// would not be a message this server could serve back.
function heldMail(to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: the record an order keeps\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <held." + to.replace(/[^a-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body.\r\n", "utf8");
}

function statusOf(identity, address) {
  var row = identity.accounts.get(address);
  return (row === null || row === undefined) ? null : row.status;
}

// The `erasing` row, produced the way an erasure actually stops. A
// preservation order over one message the erasure was asked to destroy
// keeps the mail, and the mail keeps the identity that owns it.
async function makeErasing(identity, address) {
  var doomed = await identity.accounts.create({
    address: address, password: MAILBOX_PASSWORD });
  var owner = {
    id: doomed.id, address: doomed.address, domain: doomed.domain,
    isAdmin: false, mailboxes: [doomed.address], roles: ["account"],
  };
  var kept = identity.mailbox.appendMessage("INBOX", heldMail(address), { actor: owner });
  await identity.mailbox.legalHold.place(owner, "INBOX", [kept.objectid], {
    reason: HOLD_REASON, citation: HOLD_CITATION });

  var partial = await identity.accounts["delete"]({
    id: doomed.id, destroy: true, reason: "erasure requested by the account holder" });
  count("the run has a mailbox part way through an erasure, left behind by an order rather " +
    "than by a status written onto a row",
    partial.outcome === "partially-erased" && statusOf(identity, address) === "erasing",
    JSON.stringify({ outcome: partial.outcome, status: statusOf(identity, address) }));
}

// ---- the fixture -----------------------------------------------------------

// One server, one hosted domain, four mailboxes, and no restart across
// the run. Each case takes a session of its own against the same bound
// listener, so what differs between them is the state of the recipient.
async function withServer(body) {
  var root    = helpers.tempDir("mx-held-mailbox-verdict");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // directory it reads from this variable. Pointing it inside the run's
  // own tree keeps the encrypted at rest path exactly as it ships.
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
      // The classical bridge rather than the CA default: this
      // certificate exists so a node:tls handshake happens on loopback,
      // and node verifies this algorithm on every runtime the suite runs.
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
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
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "held mailbox verdict test" });

    await identity.accounts.create({ address: ACTIVE, password: MAILBOX_PASSWORD });

    var held = await identity.accounts.create({
      address: SUSPENDED, password: MAILBOX_PASSWORD });
    await identity.accounts.suspend({ id: held.id, reason: "credential reuse reported" });

    var closed = await identity.accounts.create({
      address: ARCHIVED, password: MAILBOX_PASSWORD });
    await identity.accounts["delete"]({ id: closed.id, reason: "the owner has left" });

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        // The message authentication gate resolves SPF and DMARC against
        // live DNS at the end of DATA and this process has no resolver,
        // so enforce mode would defer on a lookup error and every case
        // would be measuring the absence of DNS. Everything asserted here
        // is decided at RCPT, before that gate runs at all.
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

    // After the server is up, because the erasure walks the mailbox
    // adapter and the composition is what wires the delete path's
    // retention floor and preservation gate to it.
    await makeErasing(identity, ERASING);

    await body({
      identity: identity,
      caPem:    leaf.ca,
      mxPort:   sections.mx.port,
    });

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
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

// One RCPT, over a session of its own, and the reply to it.
//
// A session each rather than one held open across the run, because the
// listener resolves the recipient per RCPT and a connection straddling
// two subjects would leave which one a reply is about to the socket.
async function rcptReply(ctx, label, recipient) {
  var peer = await Wire.mx(ctx.mxPort, {
    caPem: ctx.caPem, servername: HOSTNAME, label: label, helo: "peer.example.net",
  });
  peer.send("MAIL FROM:<" + PEER_SENDER + ">");
  await peer.read(/^\d{3} /m, "MAIL FROM answered");
  peer.send("RCPT TO:<" + recipient + ">");
  var reply = await peer.read(/^\d{3} /m, "RCPT TO answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

// ---- cases -----------------------------------------------------------------

// The control. A mailbox in service is accepted, so every refusal below
// is about the recipient's state rather than about a listener that
// stopped answering.
async function aMailboxInServiceIsAccepted(ctx) {
  var reply = await rcptReply(ctx, "active", ACTIVE);
  count("a mailbox in service is accepted at RCPT",
    /^250 /m.test(reply), visible(reply));
}

// The run has to be standing in every state before any of it means
// anything. A subject that quietly failed to reach its state would make
// its case pass against a mailbox that was simply active.
function everyStateHasASubjectStandingInIt(ctx) {
  count("the store declares four account states, three of which refuse delivery",
    tables.ACCOUNT_STATUS.length === 4 && OUT_OF_SERVICE.length === 3,
    tables.ACCOUNT_STATUS.join(", "));
  count("the run names a subject for every state that refuses delivery",
    OUT_OF_SERVICE.every(function (state) {
      return typeof SUBJECT_IN[state] === "string";
    }), OUT_OF_SERVICE.join(", "));
  OUT_OF_SERVICE.forEach(function (state) {
    var address = SUBJECT_IN[state];
    count("the run has a subject standing in " + state,
      typeof address === "string" && statusOf(ctx.identity, address) === state,
      String(address) + " is " + String(statusOf(ctx.identity, address)));
  });
}

// The two states that lift. Both are answered temporarily, and the
// answer at RCPT is acceptance: the message stays with the peer, whose
// own retry schedule is the right place for it to wait while an operator
// puts the mailbox back.
async function aMailboxWhoseConditionLiftsKeepsTheSendersRetry(ctx) {
  for (var i = 0; i < LIFTS.length; i += 1) {
    var state = LIFTS[i];
    var address = SUBJECT_IN[state];
    var reply = await rcptReply(ctx, "held-" + state, address);
    count("a " + state + " mailbox is accepted at RCPT, because the condition lifts and the " +
      "sender's own retry is where the message should wait",
      /^250 /m.test(reply), visible(reply));
    count("and it is not answered permanently, which would return the message to whoever " +
      "sent it over a hold an operator is going to lift",
      !/^5\d\d[ -]/m.test(reply), visible(reply));
  }
}

// The state that does not lift, and the finding. The mail is already
// destroyed, reinstatement is refused, and the only exit is the row
// going, after which the address is answered permanently anyway. A
// temporary answer here spends the whole of the sender's retry window
// against an address that can never take the message.
async function anErasureIsAnsweredPermanentlyAtRcpt(ctx) {
  for (var i = 0; i < IRREVERSIBLE.length; i += 1) {
    var state = IRREVERSIBLE[i];
    var address = SUBJECT_IN[state];
    var reply = await rcptReply(ctx, "held-" + state, address);

    count("a mailbox part way through an erasure is refused at RCPT rather than accepted, " +
      "because no retry against it can ever succeed",
      /^5\d\d[ -]/m.test(reply), visible(reply));
    count("and the refusal is 550 5.1.1, the code RFC 5321 section 3.3 gives a mailbox that " +
      "is not there and the code an operator filters their logs for",
      /^550 5\.1\.1 /m.test(reply), visible(reply));
    count("the sentence tells the sender's postmaster there is no mailbox rather than " +
      "asking them to try again",
      /no mailbox by that name/i.test(reply) && !/at the moment/i.test(reply),
      visible(reply));
  }
}

// The precedence the entry depends on, measured rather than assumed. The
// refusal reads a table first and falls back to the whole `account-`
// family, so naming one member in the table has to move that member and
// leave the others alone. Both halves are asserted together, because an
// entry that moved everything would satisfy either half on its own.
async function namingOneStateInTheTableLeavesTheOthersOnTheFallback(ctx) {
  var moved = [];
  var stayed = [];
  for (var i = 0; i < OUT_OF_SERVICE.length; i += 1) {
    var state = OUT_OF_SERVICE[i];
    var reply = await rcptReply(ctx, "precedence-" + state, SUBJECT_IN[state]);
    if (/^5\d\d[ -]/m.test(reply)) moved.push(state);
    else stayed.push(state);
  }
  count("exactly one state is answered permanently, so the table entry reaches its own " +
    "member and not the family",
    moved.length === 1 && moved[0] === IRREVERSIBLE[0], "permanent: " + moved.join(", "));
  count("and the states whose condition lifts are still answered by the family fallback",
    stayed.length === LIFTS.length &&
      LIFTS.every(function (state) { return stayed.indexOf(state) !== -1; }),
    "temporary: " + stayed.join(", "));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await withServer(async function (ctx) {
    everyStateHasASubjectStandingInIt(ctx);
    await aMailboxInServiceIsAccepted(ctx);
    await aMailboxWhoseConditionLiftsKeepsTheSendersRetry(ctx);
    await anErasureIsAnsweredPermanentlyAtRcpt(ctx);
    await namingOneStateInTheTableLeavesTheOthersOnTheFallback(ctx);
  });
  return helpers.getChecks();
}

module.exports = {
  name: "mx-held-mailbox-verdict", run: run, getChecks: helpers.getChecks,
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
