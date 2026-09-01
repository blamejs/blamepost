// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The role gate as a mail client meets it: over IMAP on 143, POP3 on
 * 110 and ManageSieve on 4190, against bound listeners, in each
 * protocol's own grammar.
 *
 * Two claims, and either one alone is a shipped defect.
 *
 * The gate has to be THERE. `b.mail.agent` checks a scope on every verb
 * it routes and checks nothing when the agent carries no permission
 * table, so a wire listener driving an agent built without one runs with
 * no role check at all while the browser surface next to it runs with
 * one. Nothing about that is visible from a transcript of a session that
 * was going to be allowed anyway, which is why the refusals below are
 * driven rather than reasoned about.
 *
 * The gate has to be SHUT ONLY where it should be. The actor a wire
 * session carries is built once, for every protocol, and
 * `b.permissions` reads an `actor.scopes` ARRAY in preference to
 * `actor.roles`. An empty array there is not "decide from the roles", it
 * is a grant of nothing, so attaching the table to an actor carrying one
 * refuses every delete, every move and every filter upload on all three
 * protocols. That failure looks like a server that is simply broken, and
 * it ships green against any suite that only tests refusals.
 *
 * So each protocol is driven twice. Once on the server an operator gets,
 * where the role this server issues grants the verb and the verb must
 * work. Once on a server whose role table is narrowed, where the same
 * verb must be refused with the code that protocol defines and the mail
 * must still be there afterwards.
 *
 * The narrowed server splits its scopes across the two roles the wire
 * actor can carry, so one bound stack covers both directions on all
 * three protocols: an ordinary account holds the filter scope and not
 * the delete scope, and an administrator holds both.
 *
 * Run standalone: node test/layer-2-integration/permission-wire-gate.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
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
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// RFC 5804 section 4 ends a literal bearing command with a CRLF that
// sits outside the declared octet count, and the vendored listener
// consumes it on both of them, so AUTHENTICATE and a script upload each
// answer once. That count is pinned in
// `sieve-managesieve-wire.test.js`; here it only decides what a read
// waits for.
var ONE_REPLY = /^(?:OK|NO|BYE)[^\r\n]*\r\n/m;

var FILTER = "require [\"fileinto\"];\n" +
  "if header :contains \"X-Category\" \"wired\" { fileinto \"Junk\"; }\n";

var count = helpers.count;

// The sign-in a conforming client sends, RFC 4616 SASL PLAIN. One
// encoder for the whole suite, so no two files can disagree about what a
// credential looks like on the wire.
var plainResponse = wire.saslPlain;

// ---- sessions ---------------------------------------------------------------

async function imapSession(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\* OK \[CAPABILITY[^\r\n]*\r\n/, "greeting");
  session.send("a0 STARTTLS");
  await session.read(/^a0 OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("a1 AUTHENTICATE PLAIN " + plainResponse(address, PASSWORD));
  await session.read(/^a1 OK/m, "authenticated");
  return session;
}

async function pop3Session(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^\+OK /m, "greeting");
  session.send("STLS");
  await session.read(/^\+OK /m, "STLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  session.send("USER " + address);
  await session.read(/^(\+OK|-ERR)/m, "USER answered");
  session.send("PASS " + PASSWORD);
  await session.read(/^\+OK /m, "authenticated");
  return session;
}

function sendLiteral(session, command, payload, note) {
  var bytes = Buffer.byteLength(payload, "utf8");
  session.send(command + " {" + bytes + "+}");
  session.sendRaw(payload + "\r\n", note);
}

function lastReply(text) {
  var replies = String(text).split("\r\n").filter(function (line) {
    return /^(?:OK|NO|BYE)/.test(line);
  });
  return replies.length === 0 ? "" : replies[replies.length - 1];
}

async function manageSieveSession(port, caPem, address, label) {
  var session = await Wire.connect(port, label);
  await session.read(/^OK[^\r\n]*\r\n/m, "capability banner");
  session.send("STARTTLS");
  await session.read(/^OK/m, "STARTTLS accepted");
  await session.upgrade(caPem, HOSTNAME);
  await session.read(/^OK/m, "capabilities re-sent after the upgrade");
  sendLiteral(session, "AUTHENTICATE \"PLAIN\"",
    plainResponse(address, PASSWORD), "<the SASL response>");
  await session.read(ONE_REPLY, "authenticated");
  return session;
}

// ---- planting mail ----------------------------------------------------------

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
    "Message-ID: <" + marker.replace(/[^a-z0-9]/gi, "") + "." +
      to.replace(/[^a-z0-9]/gi, "") + "@example.net>",
    "",
    "Body of " + marker + ".",
    "",
    ".",
    "",
  ].join("\r\n"), "<the message and its terminating dot>");
  var reply = await peer.read(/^\d{3} /m, "message answered");
  peer.send("QUIT");
  peer.close();
  return reply;
}

// How many messages an account's INBOX holds, read the way a client
// reads it rather than out of the database.
async function inboxCount(port, caPem, address, label) {
  var session = await imapSession(port, caPem, address, label);
  session.send("b1 STATUS \"INBOX\" (MESSAGES)");
  var reply = await session.read(/^b1 (OK|NO|BAD)/m, "STATUS answered");
  session.close();
  var match = reply.match(/MESSAGES (\d+)/);
  return match === null ? -1 : parseInt(match[1], 10);
}

// Deliver, then wait for the message to be readable through IMAP. The
// MX listener answers before the append has necessarily landed, so this
// polls the count rather than assuming it.
async function plant(ctx, address, marker, label) {
  var before = await inboxCount(ctx.ports.imap, ctx.caPem, address, label + "-before");
  var reply = await deliver(ctx.ports.mx, ctx.caPem, address, marker);
  count("a peer's message for " + address + " is accepted", /^250 /m.test(reply), visible(reply));
  await helpers.waitUntil(function () {
    return inboxCount(ctx.ports.imap, ctx.caPem, address, label + "-poll")
      .then(function (n) { return n > before; });
  }, {
    timeoutMs: 8000,
    label:     "permission-wire-gate: " + marker + " reaching " + address + "'s INBOX",
  });
  return before + 1;
}

// ---- the MX recipient check -------------------------------------------------

// RFC 5321 section 3.3 answers a mailbox this server does not hold with
// `550 5.1.1`, at RCPT, before the peer sends anything. The alternative
// this composition used to have was to accept every local part on a
// hosted domain and meet the mailbox question at the handoff, after
// `354` and after the whole message: from there the only answers are
// `250`, which tells the peer the message arrived and leaves this
// server owing a report it cannot send, or `451`, which tells a peer
// holding a permanent condition to retry forever.
//
// So the claim has two halves and both are driven. The refusal arrives
// at RCPT, and the peer never reaches DATA, which is what makes it a
// refusal rather than a late apology.
async function anUnknownMailboxIsRefusedAtRcpt(ctx) {
  var peer = await Wire.mx(ctx.ports.mx, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "mx-unknown-mailbox" });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");

  peer.send("RCPT TO:<nobody-here@" + DOMAIN + ">");
  var refusal = await peer.read(/^\d{3} /m, "RCPT TO answered");
  count("a mailbox this server does not hold is refused at RCPT with the 550 5.1.1 " +
    "RFC 5321 section 3.3 defines", /^550 5\.1\.1/m.test(refusal), visible(refusal));
  count("and the refusal says which condition it is, in this server's own words",
    /No mailbox by that name/.test(refusal), visible(refusal));
  count("and carries no second reply line, so a reason cannot forge an acceptance",
    (refusal.match(/^\d{3} /gm) || []).length === 1, visible(refusal));

  // With every recipient refused the transaction holds none, so the
  // peer cannot open DATA at all. That is the half that says the
  // message never traveled.
  peer.send("DATA");
  var data = await peer.read(/^\d{3} /m, "DATA answered");
  count("and DATA is refused, so the peer never transmits a message for it",
    !/^354/m.test(data), visible(data));

  peer.send("QUIT");
  peer.close();
}

// A mailbox that does exist still has to work. The refusal above is
// only correct if it is a verdict about the address rather than about
// every address, and a check that refuses everything passes the case
// above perfectly.
async function aKnownMailboxIsStillAcceptedAtRcpt(ctx, address) {
  var peer = await Wire.mx(ctx.ports.mx, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "mx-known-mailbox" });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");
  peer.send("RCPT TO:<" + address + ">");
  var accepted = await peer.read(/^\d{3} /m, "RCPT TO answered");
  count("a mailbox this server does hold is still accepted at RCPT",
    /^250 /m.test(accepted), visible(accepted));
  peer.send("QUIT");
  peer.close();
}

// The difference between `250` and `550` at RCPT is a mailbox existence
// oracle, so the refusal has to cost the peer the same per source
// budget a relay refusal costs it. Without that, making the refusal
// reachable would hand a scanner a free channel to enumerate every
// account on the server, which is a worse defect than the `451` this
// replaced.
//
// Driven rather than read off the framework: the budget is the reason
// this refusal is safe to ship, and a hook wired without it looks
// identical from every other vector in this file.
var RCPT_FAILURE_CEILING = 50;

async function refusalsAreChargedToTheSourcesBudget(ctx) {
  var peer = await Wire.mx(ctx.ports.mx, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "mx-enumeration" });
  peer.send("MAIL FROM:<" + PEER + ">");
  await peer.read(/^250 /m, "MAIL FROM accepted");

  var stopped = null;
  for (var i = 0; i <= RCPT_FAILURE_CEILING; i += 1) {
    peer.send("RCPT TO:<probe-" + i + "@" + DOMAIN + ">");
    var reply = await peer.read(/^\d{3} /m, "RCPT TO " + i + " answered");
    if (!/^550 /m.test(reply)) { stopped = { at: i, reply: reply }; break; }
  }

  count("a run of refused recipients from one source is stopped before it can " +
    "enumerate the server", stopped !== null,
    stopped === null ? "all " + (RCPT_FAILURE_CEILING + 1) + " probes were answered 550"
      : "stopped at probe " + stopped.at);
  count("and the peer is told it has spent its recipient failure budget rather than " +
    "being given another verdict about a mailbox",
    stopped !== null && /^4\d\d /m.test(stopped.reply),
    stopped === null ? "" : visible(stopped.reply));

  peer.send("QUIT");
  peer.close();
}

// ---- IMAP -------------------------------------------------------------------

// RFC 9051 section 6.4.3 gives EXPUNGE no per message refusal form, so
// a gate that refuses the whole command answers the tagged NO the
// specification defines for a command the server will not carry out.
async function imapExpunge(ctx, address, label) {
  var session = await imapSession(ctx.ports.imap, ctx.caPem, address, label);
  session.send("c1 SELECT \"INBOX\"");
  await session.read(/^c1 (OK|NO|BAD)/m, "SELECT answered");
  session.send("c2 STORE 1 +FLAGS (\\Deleted)");
  await session.read(/^c2 (OK|NO|BAD)/m, "STORE answered");
  session.send("c3 EXPUNGE");
  var reply = await session.read(/^c3 (OK|NO|BAD)/m, "EXPUNGE answered");
  session.send("c4 LOGOUT");
  session.close();
  return reply;
}

async function theWireDeleteRunsWhenTheRoleGrantsIt(ctx, address) {
  var before = await inboxCount(ctx.ports.imap, ctx.caPem, address, "imap-grant-before");
  var reply = await imapExpunge(ctx, address, "imap-grant");
  count("IMAP EXPUNGE is carried out for an account whose role grants the delete scope",
    /^c3 OK/m.test(reply), visible(lastReply(reply) || reply));
  var after = await inboxCount(ctx.ports.imap, ctx.caPem, address, "imap-grant-after");
  count("and the message is gone from the mailbox", after === before - 1,
    before + " before, " + after + " after");
}

async function theWireDeleteIsRefusedWhenTheRoleDoesNot(ctx, address) {
  var before = await inboxCount(ctx.ports.imap, ctx.caPem, address, "imap-refuse-before");
  var reply = await imapExpunge(ctx, address, "imap-refuse");
  count("IMAP EXPUNGE is refused with the tagged NO RFC 9051 defines when the " +
    "account's role does not carry the delete scope",
    /^c3 NO/m.test(reply), visible(reply));
  count("and the refusal names the scope rather than a generic backend error",
    /lacks scope 'mail:expunge'/.test(reply), visible(reply));
  var after = await inboxCount(ctx.ports.imap, ctx.caPem, address, "imap-refuse-after");
  count("and the message is still in the mailbox", after === before,
    before + " before, " + after + " after");
}

// ---- POP3 -------------------------------------------------------------------

// RFC 1939 section 6 does give the UPDATE state a refusal form, so a
// commit the gate would not carry out answers -ERR rather than a
// success the client would act on by forgetting the message.
async function pop3DeleteAndQuit(ctx, address, label) {
  var client = await pop3Session(ctx.ports.pop3, ctx.caPem, address, label);
  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  client.send("DELE 1");
  var dele = await client.read(/^(\+OK|-ERR)/m, "DELE answered");
  client.send("QUIT");
  var quit = await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  client.close();
  return { stat: stat, dele: dele, quit: quit };
}

// The maildrop count, read by opening a whole session. That is the
// point as much as the number is: RFC 1939 section 3 hands one session
// at a time exclusive access, so a refused commit that kept the lock
// makes this connection fail to reach the transaction state at all, and
// the account holder loses POP3 entirely rather than losing one delete.
async function pop3Count(ctx, address, label) {
  var client = await pop3Session(ctx.ports.pop3, ctx.caPem, address, label);
  client.send("STAT");
  var stat = await client.read(/^\+OK \d+ \d+/m, "STAT answered");
  client.send("QUIT");
  await client.read(/^(\+OK|-ERR)/m, "QUIT answered");
  client.close();
  var match = stat.match(/^\+OK (\d+) /m);
  return match === null ? -1 : parseInt(match[1], 10);
}

async function thePop3CommitRunsWhenTheRoleGrantsIt(ctx, address) {
  var before = await pop3Count(ctx, address, "pop3-grant-before");
  var session = await pop3DeleteAndQuit(ctx, address, "pop3-grant");
  count("the mark is accepted, because a POP3 refusal belongs at the commit",
    /^\+OK/m.test(session.dele), visible(session.dele));
  count("POP3 QUIT commits the delete for an account whose role grants the scope",
    /^\+OK/m.test(session.quit), visible(session.quit));
  var after = await pop3Count(ctx, address, "pop3-grant-after");
  count("and the maildrop is one message shorter", after === before - 1,
    before + " before, " + after + " after");
}

async function thePop3CommitIsRefusedWhenTheRoleDoesNot(ctx, address) {
  var before = await pop3Count(ctx, address, "pop3-refuse-before");
  var session = await pop3DeleteAndQuit(ctx, address, "pop3-refuse");
  count("POP3 QUIT is answered -ERR when the account's role does not carry the " +
    "delete scope (RFC 1939 section 6)", /^-ERR/m.test(session.quit), visible(session.quit));
  count("and the refusal names the scope",
    /lacks scope 'mail:expunge'/.test(session.quit), visible(session.quit));
  var after = await pop3Count(ctx, address, "pop3-refuse-after");
  count("and the refused commit handed the maildrop back, so the next session " +
    "reaches the transaction state at all", after >= 0, String(after));
  count("and a client reconnecting still finds the message", after === before,
    before + " before, " + after + " after");
}

// ---- POP3 SASL --------------------------------------------------------------

// RFC 5034 section 4 lets a client send `AUTH PLAIN` with nothing after
// it and be asked for the credential. PLAIN is client first, so the ask
// carries nothing and reaches the client as a bare `+` line.
//
// Being refused instead is not a cosmetic difference. RFC 2449 keeps a
// per-account failure budget behind this verb, and a refusal spends one
// of its slots, so a client that opens the exchange the way the
// specification writes it locks out the account holder it belongs to.
//
// POP3 gets its own vector rather than inheriting the ManageSieve one:
// the two listeners write the same exchange in different syntax, and
// the defect that started this was present on exactly one of them at a
// time.
async function thePop3ChallengePathCompletes(ctx, address) {
  // Upgraded and not yet signed in: AUTH is only legal in the
  // authorization state, and the file's own POP3 ladder has already
  // left it by the time it returns.
  var session = await Wire.pop3(ctx.ports.pop3, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "pop3-challenge" });
  session.send("AUTH PLAIN");
  var invitation = await session.read(/^(?:\+\r\n|\+OK|-ERR)/m,
    "the answer to AUTH with no credential on the line");
  count("POP3 AUTH with no initial response is answered with a continuation rather " +
    "than a refusal (RFC 5034 section 4)",
    /^\+\r\n/m.test(invitation), visible(invitation));

  session.send(plainResponse(address, PASSWORD));
  var verdict = await session.read(/^(\+OK|-ERR)/m, "the verdict on the challenged exchange");
  count("and the credential sent in answer to it authenticates the account",
    /^\+OK/m.test(verdict), visible(verdict));

  session.send("STAT");
  var stat = await session.read(/^(\+OK|-ERR)/m, "STAT answered");
  count("so the session reached the transaction state, not just a +OK",
    /^\+OK \d+ \d+/m.test(stat), visible(stat));
  session.send("QUIT");
  session.close();
}

// RFC 5034 section 4 gives the client a bare `*` to withdraw an
// exchange it opened. A withdrawal is not a wrong password, so it costs
// no budget, and the session that made it is made to sign in afterwards
// to prove the slot came back.
async function thePop3ExchangeIsCancellable(ctx, address) {
  var session = await Wire.pop3(ctx.ports.pop3, {
    caPem: ctx.caPem, servername: HOSTNAME, label: "pop3-cancel" });
  session.send("AUTH PLAIN");
  await session.read(/^(?:\+\r\n|\+OK|-ERR)/m, "the continuation");

  session.send("*");
  var cancelled = await session.read(/^(\+OK|-ERR)/m, "the answer to a cancellation");
  count("an asterisk answering a POP3 continuation is refused as a cancellation",
    /^-ERR/m.test(cancelled), visible(cancelled));
  count("and is not read as a verb the protocol does not define, which is what a " +
    "listener holding no exchange would call it",
    !/unknown verb/.test(cancelled), visible(cancelled));

  session.send("AUTH PLAIN " + plainResponse(address, PASSWORD));
  var verdict = await session.read(/^(\+OK|-ERR)/m, "the verdict after the cancellation");
  count("and the cancelled exchange released what it held, so the same session still " +
    "signs in", /^\+OK/m.test(verdict), visible(verdict));
  session.send("QUIT");
  session.close();
}

// ---- ManageSieve ------------------------------------------------------------

async function sieveUpload(ctx, address, name, label) {
  var session = await manageSieveSession(ctx.ports.managesieve, ctx.caPem, address, label);
  sendLiteral(session, "PUTSCRIPT \"" + name + "\"", FILTER, "<the filter script>");
  var put = await session.read(ONE_REPLY, "PUTSCRIPT answered");
  session.send("LISTSCRIPTS");
  var listing = await session.read(ONE_REPLY, "LISTSCRIPTS answered");
  session.send("LOGOUT");
  session.close();
  return { put: lastReply(put), putRaw: put, listing: listing };
}

async function theFilterUploadRunsWhenTheRoleGrantsIt(ctx, address, name) {
  var outcome = await sieveUpload(ctx, address, name, "sieve-grant");
  count("ManageSieve PUTSCRIPT is accepted for an account whose role grants the " +
    "filter scope", /^OK/.test(outcome.put), visible(outcome.putRaw));
  count("and LISTSCRIPTS names the script that was stored",
    outcome.listing.indexOf("\"" + name + "\"") !== -1, visible(outcome.listing));
}

async function theFilterUploadIsRefusedWhenTheRoleDoesNot(ctx, address, name) {
  var outcome = await sieveUpload(ctx, address, name, "sieve-refuse");
  count("ManageSieve PUTSCRIPT is refused with the NO RFC 5804 defines when the " +
    "account's role does not carry the filter scope",
    /^NO/.test(outcome.put), visible(outcome.putRaw));
  count("and the refusal names the scope", /mail:sieve/.test(outcome.put),
    visible(outcome.put));
  count("and nothing was stored",
    outcome.listing.indexOf("\"" + name + "\"") === -1, visible(outcome.listing));
}

// The activation verb next to it, so the gate is not proved on one verb
// and assumed on the rest of the surface.
async function theFilterActivationFollowsTheSameGate(ctx, address, name, granted) {
  var session = await manageSieveSession(ctx.ports.managesieve, ctx.caPem, address,
    "sieve-activate");
  session.send("SETACTIVE \"" + name + "\"");
  var reply = await session.read(ONE_REPLY, "SETACTIVE answered");
  session.send("LOGOUT");
  session.close();
  if (granted) {
    count("SETACTIVE is accepted when the role carries the filter scope",
      /^OK/.test(lastReply(reply)), visible(reply));
    return;
  }
  count("SETACTIVE is refused when the role does not",
    /^NO/.test(lastReply(reply)), visible(reply));
}

// ---- the two stacks ---------------------------------------------------------

// One bound server, torn down after. `narrowRoles` builds the adapter
// over a role table of the caller's choosing; with none, the adapter is
// the one `store.open` composes, which is what an operator runs.
async function withServer(label, narrowRoles, fn) {
  var root    = helpers.tempDir("perm-wire-" + label);
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
        BLAMEPOST_POP3_ENABLED:     "1",
      },
      cwd: root,
    });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "permission wire test" });
    var holder = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: PASSWORD });
    var operator = await identity.accounts.create({
      address: "adam@" + DOMAIN, password: PASSWORD, isAdmin: true });

    var adapter = identity.mailbox;
    if (narrowRoles) {
      adapter = mailbox.create({
        store:   identity.messageStore,
        dataDir: cfg.paths.dataDir,
        vault:   b.vault,
        agent:   b.mail.agent.create({
          store:       identity.messageStore,
          dispatch:    { mode: "local" },
          permissions: b.permissions.create({ roles: narrowRoles }),
        }),
      });
    }

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort:  0,
        listeners: sections,
        inbound:   { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    adapter,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    await fn({
      identity: identity,
      caPem:    leaf.ca,
      holder:   holder,
      operator: operator,
      ports: {
        mx:          sections.mx.port,
        imap:        sections.imap.port,
        pop3:        sections.pop3.port,
        managesieve: sections.managesieve.port,
      },
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

// ---- runner -----------------------------------------------------------------

async function run() {
  // The server an operator gets. Every verb below is one the role this
  // server issues grants, so every one of them has to work: this is the
  // half that fails if the table is attached to an actor that also
  // carries an empty scopes array.
  await withServer("shipped", null, async function (ctx) {
    var address = ctx.holder.address;
    await plant(ctx, address, "shipped-imap", "shipped-imap");
    await plant(ctx, address, "shipped-pop3", "shipped-pop3");

    await theWireDeleteRunsWhenTheRoleGrantsIt(ctx, address);
    await thePop3CommitRunsWhenTheRoleGrantsIt(ctx, address);
    await theFilterUploadRunsWhenTheRoleGrantsIt(ctx, address, "shipped-filter");
    await theFilterActivationFollowsTheSameGate(ctx, address, "shipped-filter", true);

    // The SASL exchange itself, on the listener an operator gets. Both
    // spellings RFC 5034 allows have to reach the same verdict, because
    // a client that opens the exchange the long way otherwise spends
    // the account's failure budget on a normal round trip.
    await thePop3ChallengePathCompletes(ctx, address);
    await thePop3ExchangeIsCancellable(ctx, address);

    // What a peer meets at RCPT. Driven on the shipped stack rather
    // than the narrowed one, because the recipient check is the
    // store's answer about an address and has nothing to do with the
    // role a session carries.
    await aKnownMailboxIsStillAcceptedAtRcpt(ctx, address);
    await anUnknownMailboxIsRefusedAtRcpt(ctx);
    await refusalsAreChargedToTheSourcesBudget(ctx);
  });

  // The same three protocols against a narrowed table. The ordinary
  // account holds the filter scope and not the delete scope; the
  // administrator holds both, because `admin` is the second role a wire
  // actor can carry and splitting the scopes across the two covers both
  // directions on one bound stack.
  var NARROW = {
    account: ["mail:read", "mail:sieve"],
    admin:   ["mail:read", "mail:sieve", "mail:expunge"],
  };
  await withServer("narrowed", NARROW, async function (ctx) {
    var refused = ctx.holder.address;
    var allowed = ctx.operator.address;

    await plant(ctx, refused, "narrow-refused", "narrow-refused");
    await plant(ctx, allowed, "narrow-allowed-imap", "narrow-allowed-imap");
    await plant(ctx, allowed, "narrow-allowed-pop3", "narrow-allowed-pop3");

    await theFilterUploadRunsWhenTheRoleGrantsIt(ctx, refused, "narrow-filter");
    await theWireDeleteIsRefusedWhenTheRoleDoesNot(ctx, refused);
    await thePop3CommitIsRefusedWhenTheRoleDoesNot(ctx, refused);

    await theWireDeleteRunsWhenTheRoleGrantsIt(ctx, allowed);
    await thePop3CommitRunsWhenTheRoleGrantsIt(ctx, allowed);
  });

  // And once more with the filter scope taken away, so the ManageSieve
  // refusal is driven rather than inferred from the grant above.
  var NO_SIEVE = {
    account: ["mail:read", "mail:expunge"],
    admin:   ["mail:read", "mail:expunge"],
  };
  await withServer("no-filter-scope", NO_SIEVE, async function (ctx) {
    await theFilterUploadIsRefusedWhenTheRoleDoesNot(ctx, ctx.holder.address, "blocked-filter");
    await theFilterActivationFollowsTheSameGate(ctx, ctx.holder.address, "blocked-filter", false);
  });

  return helpers.getChecks();
}

module.exports = {
  name: "permission-wire-gate",
  run:  run,
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
