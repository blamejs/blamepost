// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A mailbox taken out of service under a session that is already open.
 *
 * `test/layer-2-integration/account-status-wire-signin.test.js` asks
 * what happens when a credential ARRIVES for a mailbox that is out of
 * service, on all five surfaces. This file asks the other half of the
 * same rule: the credential arrived while the mailbox was in service,
 * the session is open, and the operator takes the mailbox out of service
 * with the socket still connected.
 *
 * That is the state an operator is actually in during an incident. They
 * suspend a mailbox whose password they believe somebody else is
 * holding, and the holder is already signed in. An IMAP client keeps one
 * connection open for hours under IDLE, a submission session stays open
 * for as long as the client has mail to send, and a POP3 session holds
 * its maildrop for the length of its download. Nothing about suspending
 * the account closes any of them.
 *
 * What is driven, per state and on every surface a session can be open
 * on:
 *
 *   - The control, first. Each session serves its protocol's ordinary
 *     read while the mailbox is in service. Without it every refusal
 *     below is satisfied by a listener that stopped serving anything.
 *   - The state change, applied through the operator verb that reaches
 *     it rather than by writing a status onto a row, with the sessions
 *     still open.
 *   - The next operation on each of those same sessions, with no
 *     reconnection and no second credential. Every one of them has to be
 *     refused.
 *   - The audit row each wire refusal writes, read for the reason it
 *     names. A session that stopped serving because its mail had been
 *     erased and a session that stopped serving because the account is
 *     out of service look identical on the wire, and only the row tells
 *     the two apart.
 *   - The reinstatement. A suspended mailbox returned to service serves
 *     the SAME open sessions again, which is what separates a gate from
 *     a session that broke for good on the first refusal.
 *
 * Every status that is not active is read off the store's own frozen
 * list rather than spelled out, so a fifth status added to the store
 * arrives here as a failing vector rather than as a silent hole. The
 * withdrawn domain is the second gate and is driven beside them: an
 * implementation reading the account row alone passes every status above
 * and fails that one.
 *
 * Nothing external is needed. Every port is ephemeral on the loopback
 * interface and the volume is a temporary directory.
 *
 * Run standalone: node test/layer-2-integration/account-status-live-session.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var tables    = require("../../lib/store/tables");
var listeners = require("../../lib/mail/listeners");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var LOOPBACK    = wire.LOOPBACK;
var visible     = wire.visible;

var count = helpers.count;

var HOSTNAME         = "mx.example.com";
var DOMAIN           = "example.com";
var WITHDRAWN_DOMAIN = "example.org";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// One password for every subject here. Each session authenticates with
// the password its account was created with, so a refusal after the
// state change can only be the state.
var PASSWORD = "quiet lantern bicycle 4291";

// What keeps an erasure from finishing, so the run holds a real
// `erasing` row rather than a status written onto one by hand.
var HOLD_REASON   = "preservation order 24-cv-01933";
var HOLD_CITATION = "FRCP-26";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The row a wire listener writes when it refuses a command because the
// session's account is no longer one this server serves.
var STOPPED_ACTION = "blamepost.mail.listeners.session_account_stopped";

// One ManageSieve reply line, the shape every command here answers with.
var ONE_SIEVE_REPLY = /^(?:OK|NO|BYE)[^\r\n]*\r\n/m;

// Every status that is not active, read off the store's frozen list.
var OUT_OF_SERVICE = tables.ACCOUNT_STATUS.filter(function (name) {
  return name !== "active";
});

// The actor the message store wants for a seeded append.
function actorFor(row) {
  return {
    id:        row.id,
    username:  row.address,
    address:   row.address,
    domain:    row.domain,
    isAdmin:   false,
    mailboxes: [String(row.address).toLowerCase()],
    roles:     ["account"],
  };
}

// The message each account starts with, so a FETCH and a STAT have
// something to answer with before anything is taken out of service.
function seedMail(to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: the message a live session reads\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <seed." + to.replace(/[^a-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body.\r\n", "utf8");
}

// The message a submission session offers, whose author is the account
// that signed in, because the identity binding is strict.
function outboundMail(from) {
  return "From: <" + from + ">\r\n" +
    "To: <" + from + ">\r\n" +
    "Subject: the message a live session sends\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <sent." + from.replace(/[^a-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body.";
}

// ---- one operation per surface ---------------------------------------------
//
// Each answers a list of `{ verb, ok, text }`: what was asked, whether
// the surface served it, and what it said. The claim is read off the
// same list in both directions, so the control and the refusal cannot
// end up asking different questions.

async function imapOperations(session) {
  var fetched = await session.imapAsk("FETCH 1 (UID)", "FETCH answered");
  var listed  = await session.imapAsk('LIST "" "*"', "LIST answered");
  var stat    = await session.imapAsk('STATUS "INBOX" (MESSAGES)', "STATUS answered");
  return [
    { verb: "IMAP FETCH",  ok: fetched.verdict === "OK", text: visible(fetched.text) },
    { verb: "IMAP LIST",   ok: listed.verdict  === "OK", text: visible(listed.text) },
    { verb: "IMAP STATUS", ok: stat.verdict    === "OK", text: visible(stat.text) },
  ];
}

async function pop3Operations(session) {
  session.send("STAT");
  var stat = await session.read(/^(\+OK|-ERR)/m, "STAT answered");
  session.send("LIST");
  var listed = await session.read(/^(\+OK|-ERR)/m, "LIST answered");
  return [
    { verb: "POP3 STAT", ok: /^\+OK/m.test(stat),   text: visible(stat) },
    { verb: "POP3 LIST", ok: /^\+OK/m.test(listed), text: visible(listed) },
  ];
}

async function manageSieveOperations(session) {
  session.send("LISTSCRIPTS");
  var listed = await session.read(ONE_SIEVE_REPLY, "LISTSCRIPTS answered");
  return [{
    verb: "ManageSieve LISTSCRIPTS",
    ok:   /^OK/.test(wire.lastManageSieveReply(listed)),
    text: visible(listed),
  }];
}

// One whole message, envelope to final dot, because the message is what
// a submission session exists to move and a refusal anywhere along it is
// the session no longer sending.
async function submissionOperations(session, address) {
  session.send("MAIL FROM:<" + address + ">");
  var from = await session.read(/^\d{3} /m, "MAIL FROM answered");
  if (!/^250/m.test(from)) {
    return [{ verb: "submission MAIL FROM", ok: false, text: visible(from) }];
  }
  session.send("RCPT TO:<" + address + ">");
  var rcpt = await session.read(/^\d{3} /m, "RCPT TO answered");
  if (!/^25\d/m.test(rcpt)) {
    return [{ verb: "submission RCPT TO", ok: false, text: visible(rcpt) }];
  }
  session.send("DATA");
  var invited = await session.read(/^\d{3} /m, "DATA answered");
  if (!/^354/m.test(invited)) {
    return [{ verb: "submission DATA", ok: false, text: visible(invited) }];
  }
  session.sendRaw(outboundMail(address) + "\r\n.\r\n", "<the message>");
  var accepted = await session.read(/^\d{3} /m, "the message answered");
  return [{
    verb: "submission relay",
    ok:   /^250/m.test(accepted),
    text: visible(accepted),
  }];
}

async function browserOperations(reader) {
  var page = await reader.get("/mail?folder=INBOX");
  var jmap = await reader.get("/jmap/session", { Accept: "application/json" });
  return [
    {
      verb:     "the mailbox page",
      ok:       page.status === 200,
      text:     page.status + " " + String(page.location || ""),
      status:   page.status,
      location: String(page.location || ""),
    },
    { verb: "the JMAP session document", ok: jmap.status === 200, text: String(jmap.status) },
  ];
}

// ---- the sessions one subject holds ----------------------------------------

// Four wire sessions and one browser reader, all authenticated as one
// account, all raised while the account is in service. The IMAP session
// selects INBOX here rather than after the state change, so a refused
// FETCH later is the account rather than a session with no mailbox
// open.
async function openSessions(ports, caPem, origin, address) {
  var ladderOpts = {
    caPem:      caPem,
    servername: HOSTNAME,
    address:    address,
    password:   PASSWORD,
  };

  var imap = await Wire.imap(ports.imap,
    Object.assign({ label: "imap/" + address }, ladderOpts));
  var selected = await imap.imapAsk('SELECT "INBOX"', "SELECT INBOX");
  count("the IMAP session for " + address + " has INBOX open before anything changes",
    selected.verdict === "OK", visible(selected.text));

  var pop3 = await Wire.pop3(ports.pop3,
    Object.assign({ label: "pop3/" + address }, ladderOpts));
  var managesieve = await Wire.managesieve(ports.managesieve,
    Object.assign({ label: "managesieve/" + address }, ladderOpts));
  var submission = await Wire.submission(ports.submission,
    Object.assign({ label: "submission/" + address }, ladderOpts));

  var reader = browser.browserAt(origin, { ca: caPem });
  var landed = await reader.signIn(address, PASSWORD);
  count("the browser session for " + address + " is signed in before anything changes",
    landed.status === 302, landed.status + " " + String(landed.body).slice(0, 200));

  return {
    address:     address,
    imap:        imap,
    pop3:        pop3,
    managesieve: managesieve,
    submission:  submission,
    reader:      reader,
    close:       function () {
      imap.close();
      pop3.close();
      managesieve.close();
      submission.close();
    },
  };
}

// Everything the four wire sessions and the browser answer right now, as
// one list.
async function whatEverySurfaceAnswers(sessions) {
  var answers = [];
  answers = answers.concat(await imapOperations(sessions.imap));
  answers = answers.concat(await pop3Operations(sessions.pop3));
  answers = answers.concat(await manageSieveOperations(sessions.managesieve));
  answers = answers.concat(await submissionOperations(sessions.submission, sessions.address));
  answers = answers.concat(await browserOperations(sessions.reader));
  return answers;
}

// The wire half alone, for the reinstatement, where the browser reader
// has its own question.
async function whatTheWireSurfacesAnswer(sessions) {
  var answers = [];
  answers = answers.concat(await imapOperations(sessions.imap));
  answers = answers.concat(await pop3Operations(sessions.pop3));
  answers = answers.concat(await manageSieveOperations(sessions.managesieve));
  answers = answers.concat(await submissionOperations(sessions.submission, sessions.address));
  return answers;
}

// ---- standing the states up ------------------------------------------------

// One account per vector, each reaching its state the way an operator
// reaches it rather than by writing a status onto a row.
async function takeOutOfService(identity, status, stood) {
  if (status === "suspended") {
    await identity.accounts.suspend({
      id: stood.row.id, reason: "the credential was reported stolen" });
    return true;
  }
  if (status === "archived") {
    await identity.accounts["delete"]({ id: stood.row.id, reason: "the owner has left" });
    return true;
  }
  if (status === "erasing") {
    await identity.mailbox.legalHold.place(stood.actor, "INBOX", [stood.seeded.objectid], {
      reason: HOLD_REASON, citation: HOLD_CITATION });
    var partial = await identity.accounts["delete"]({
      id: stood.row.id, destroy: true,
      reason: "erasure requested by the account holder" });
    count("the run holds an account part way through an erasure, left behind by an order " +
      "rather than by a status written onto a row",
      partial.outcome === "partially-erased", JSON.stringify(partial.outcome));
    return true;
  }
  // A status the store has grown since this file was written. It is
  // reported rather than skipped: a state nobody stood up is a state
  // nobody measured.
  count("the run knows how to take a live session's account out of service into every " +
    "state the store declares, including " + status, false,
    "add the operator verb that reaches '" + status + "' beside the others");
  return false;
}

function vectorsToDrive() {
  var vectors = OUT_OF_SERVICE.map(function (status) {
    return {
      name:    "the account is " + status,
      reason:  "account-" + status,
      address: status + "@" + DOMAIN,
      domain:  DOMAIN,
      apply:   function (identity, stood) { return takeOutOfService(identity, status, stood); },
    };
  });
  vectors.push({
    name:    "the account's domain has been withdrawn",
    reason:  "domain-disabled",
    address: "ivy@" + WITHDRAWN_DOMAIN,
    domain:  WITHDRAWN_DOMAIN,
    apply:   async function (identity) {
      await identity.domains.setStatus({
        domain: WITHDRAWN_DOMAIN,
        status: "disabled",
        reason: "the domain is under investigation",
      });
      return true;
    },
  });
  return vectors;
}

// ---- the cases -------------------------------------------------------------

async function everySurfaceServesWhileTheMailboxIsInService(sessions, vector) {
  var answers = await whatEverySurfaceAnswers(sessions);
  for (var i = 0; i < answers.length; i += 1) {
    count(answers[i].verb + " serves the open session while the mailbox is in service (" +
      vector.name + ")", answers[i].ok === true, answers[i].text);
  }
}

async function noSurfaceServesTheOpenSessionAfterwards(sessions, vector) {
  var answers = await whatEverySurfaceAnswers(sessions);
  for (var i = 0; i < answers.length; i += 1) {
    count(answers[i].verb + " stops serving the session that was already open once " +
      vector.name, answers[i].ok === false, answers[i].text);
  }
  var page = answers.filter(function (answer) { return answer.verb === "the mailbox page"; })[0];
  count("the browser lands on the sign-in page rather than on a mailbox (" + vector.name + ")",
    page.status === 302 && page.location.indexOf("/sign-in") !== -1, page.text);
}

// The reason, read off the row rather than off the wire. IMAP answers a
// refused LIST with a sentence that carries no state, so the row is the
// only place the cause is legible, and a session that stopped serving
// for some other reason would satisfy every wire claim above.
async function theRefusalRowNamesTheReason(audit, stood, vector) {
  function rowsForThisAccount() {
    return audit.forAction(STOPPED_ACTION).filter(function (row) {
      return helpers.metadataOf(row).accountId === stood.row.id;
    });
  }
  // The trail is written through the buffering sink every other row on
  // this server goes through, so the row lands a moment after the reply
  // the client already read.
  var rows;
  try {
    rows = await helpers.waitUntil(function () {
      var found = rowsForThisAccount();
      return found.length > 0 ? found : false;
    }, {
      timeoutMs: 10000,
      label:     "account-status-live-session: the refusal rows for " + vector.address,
    });
  } catch (_timedOut) {
    rows = rowsForThisAccount();
  }
  count("the wire refusals for " + vector.address + " are written down, so an operator " +
    "reading the trail finds out why a client that was working stopped",
    rows.length > 0, "rows: " + rows.length);
  if (rows.length === 0) return;
  var reasons = rows.map(function (row) { return helpers.metadataOf(row).reason; });
  count("and each names " + vector.reason + " rather than some other fault the session " +
    "might have hit",
    reasons.every(function (reason) { return reason === vector.reason; }),
    reasons.join(", "));
}

// The cell that is deliberately open. A gate that never lets go is not a
// gate, and a session that broke for good on the first refusal passes
// every case above.
async function theSameSessionsServeAgainOnceTheMailboxIsBack(identity, sessions, stood) {
  await identity.accounts.reinstate({ id: stood.row.id });
  count("the suspended mailbox is back in service",
    identity.accounts.get(stood.row.address).status === "active",
    String(identity.accounts.get(stood.row.address).status));

  var answers = await whatTheWireSurfacesAnswer(sessions);
  for (var i = 0; i < answers.length; i += 1) {
    count(answers[i].verb + " serves the same open session again once the mailbox is back " +
      "in service", answers[i].ok === true, answers[i].text);
  }

  var reader = browser.browserAt(sessions.reader.origin, { ca: sessions.caPem });
  var landed = await reader.signIn(stood.row.address, PASSWORD);
  count("and the browser admits the same credential again",
    landed.status === 302, landed.status + " " + String(landed.body).slice(0, 200));
}

// ---- the store has to be able to answer, where the answer is needed -------
//
// The re-read is only as good as the store behind it, so a listener that
// performs it refuses to bind against a store that cannot. The refusal
// belongs to the LISTENER rather than to the composition: inbound mail
// carries no session and a held mailbox is answered at RCPT, so a server
// binding port 25 and nothing else never reaches the re-read, and asking
// that composition for readers it will never call would refuse a store
// that answers everything asked of it.
//
// Both halves are driven, because either one alone is satisfied by the
// wrong implementation. A check that refuses everything passes the four
// below and breaks every MX-only deployment; a check that refuses nothing
// passes the MX case and leaves four listeners whose sessions no operator
// action can stop.

// A store that authenticates and cannot answer afterwards, which is the
// shape a stand-in takes when nobody has had to think about the window
// between a credential being verified and the session ending.
function aStoreThatCannotAnswerAfterwards() {
  return {
    resolve:  function () { return { deliverable: false, local: true, targets: [] }; },
    accounts: { authenticate: async function () { return { ok: false }; } },
    domains:  { list: async function () {
      return [{ domain: DOMAIN, status: "active", dnsAcknowledged: true }];
    } },
    aliases:  { list: function () { return []; } },
  };
}

// The lease hooks are here because the POP3 listener refuses on their
// absence before it reaches anything else, so a stand-in without them
// would report that listener's verdict about the wrong thing.
function aMailStoreWithoutOpinions() {
  return {
    appendMessage:   async function () { return { objectid: "obj_1" }; },
    sieveScripts:    { active: function () { return null; } },
    touchPop3Drop:   function () {},
    releasePop3Drop: function () {},
  };
}

async function onlyThisListener(which) {
  var sections = {
    mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
    submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
    submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
    imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
    pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
    managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
  };
  sections[which].enabled = true;
  return sections;
}

// What one listener does when it is the only one bound and the store
// cannot answer the re-read: `{ bound, text }`.
async function whatOneListenerDoesWithoutTheReaders(which, context) {
  var handle;
  try {
    handle = listeners.create({
      config: {
        hostname:        HOSTNAME,
        dnsAcknowledged: true,
        // Inbound authentication resolves against live DNS at the end of
        // DATA and this process has no resolver. Nothing here transmits a
        // message, so nothing reaches it.
        inbound:         { mode: "monitor" },
        listeners:       await onlyThisListener(which),
      },
      store:       aStoreThatCannotAnswerAfterwards(),
      mailStore:   aMailStoreWithoutOpinions(),
      delivery:    helpers.standInDelivery(),
      certificate: context,
    });
    await handle.start();
  } catch (refusal) {
    return { bound: false, text: (refusal && refusal.message) || String(refusal) };
  }
  try { await handle.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
  catch (_e) { /* drop-silent by design: the verdict is already decided */ }
  return { bound: true, text: "it bound and asked the store for nothing further" };
}

async function theListenersThatReReadAskTheStoreForIt(material) {
  var context = blamepost.tlsContext({
    certFile: material.certFile, keyFile: material.keyFile });

  var inbound = await whatOneListenerDoesWithoutTheReaders("mx", context);
  count("a server that binds only inbound mail composes against a store that cannot answer " +
    "the re-read, because no session is opened on it and nothing ever asks",
    inbound.bound === true, inbound.text);

  var sessionBearing = ["imap", "pop3", "managesieve", "submission"];
  for (var i = 0; i < sessionBearing.length; i += 1) {
    var verdict = await whatOneListenerDoesWithoutTheReaders(sessionBearing[i], context);
    count("the " + sessionBearing[i] + " listener refuses to bind against a store that " +
      "cannot answer it, rather than serving sessions no operator action can stop",
      verdict.bound === false, verdict.text);
    count("and the refusal says which reader was missing, so the gap is repaired rather " +
      "than guessed at (" + sessionBearing[i] + ")",
      verdict.bound === false && verdict.text.indexOf("get()") !== -1, verdict.text);
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("live-session");
  var dataDir = helpers.dataDir(root);
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  var audit    = null;
  var open     = [];

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
    await identity.domains.add({ domain: WITHDRAWN_DOMAIN });

    var vectors = vectorsToDrive();
    var stoodUp = [];
    for (var v = 0; v < vectors.length; v += 1) {
      var row = await identity.accounts.create({
        address: vectors[v].address, password: PASSWORD });
      var actor = actorFor(row);
      var seeded = identity.mailbox.appendMessage("INBOX", seedMail(vectors[v].address),
        { actor: actor });
      stoodUp.push({ row: row, actor: actor, seeded: seeded });
    }

    // Inbound mail takes no credential and holds no session, so the MX
    // listener stays unbound, which also keeps the DNS posture gate out
    // of a run that is not about it.
    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        httpsPort: 0,
        listeners: sections,
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;
    audit = helpers.auditCapture();

    var bound = server.web.bound();
    count("the browser surface took a TLS port, which is the only one a credential may be " +
      "presented on", typeof bound.https === "number" && bound.https > 0,
      JSON.stringify(bound));
    var origin = "https://" + LOOPBACK + ":" + bound.https;

    var ports = {
      imap:        sections.imap.port,
      pop3:        sections.pop3.port,
      managesieve: sections.managesieve.port,
      submission:  sections.submission.port,
    };

    count("five surfaces hold a session, which is what makes this a claim about agreement " +
      "rather than about one listener", vectors.length === OUT_OF_SERVICE.length + 1,
      vectors.map(function (entry) { return entry.name; }).join("; "));

    for (var i = 0; i < vectors.length; i += 1) {
      var vector = vectors[i];
      var stood  = stoodUp[i];
      var sessions = await openSessions(ports, material.caPem, origin, vector.address);
      sessions.caPem = material.caPem;
      open.push(sessions);

      await everySurfaceServesWhileTheMailboxIsInService(sessions, vector);

      var applied = await vector.apply(identity, stood);
      if (!applied) continue;

      await noSurfaceServesTheOpenSessionAfterwards(sessions, vector);
      await theRefusalRowNamesTheReason(audit, stood, vector);

      if (vector.reason === "account-suspended") {
        await theSameSessionsServeAgainOnceTheMailboxIsBack(identity, sessions, stood);
      }
    }

    for (var c = 0; c < open.length; c += 1) open[c].close();
    open = [];

    await theListenersThatReReadAskTheStoreForIt(material);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    for (var k = 0; k < open.length; k += 1) {
      try { open[k].close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (audit) {
      try { audit.release(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
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
  name:      "account-status-live-session",
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
