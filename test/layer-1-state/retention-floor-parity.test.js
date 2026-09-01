// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The two hard-delete gates, seen from both handles that are supposed
 * to hold them.
 *
 * A running server hands the mailbox access agent to two different
 * consumers. The wire adapter routes IMAP EXPUNGE and POP3 QUIT through
 * one; the browser surface routes JMAP `Email/set` `destroyed` and the
 * webmail purge button through whatever `blamepost.create` gives it. If
 * those are two agents holding different options, the same message
 * refuses on one wire and is destroyed on the other, and the operator
 * who set a compliance posture is told a floor is in force that half
 * their clients walk straight past.
 *
 * So this file asks one question in four places: given a posture and a
 * message, do both handles reach the same verdict? It asserts the
 * verdict rather than the wiring, because the wiring can be right in a
 * way that changes next week and the verdict cannot.
 *
 * Each leg gets its own folder. `expungeFolder` takes every message a
 * client flagged deleted in the folder it names, so two legs sharing a
 * folder would be one leg with extra steps.
 *
 * Nothing binds here. `blamepost.create` builds the composition and the
 * listeners stay disabled, so the certificate is an empty context that
 * is never presented to anybody. The same question driven over real
 * sockets, by real clients, on all four protocols, is
 * test/layer-2-integration/retention-floor-parity.test.js.
 *
 * Run standalone: node test/layer-1-state/retention-floor-parity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var mailbox   = require("../../lib/mail/mailbox");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// One folder per leg, so an EXPUNGE aimed at one leg cannot carry
// another leg's message with it.
var WEB_FLOOR_FOLDER  = "INBOX";
var WIRE_FLOOR_FOLDER = "Archive";
var WEB_HOLD_FOLDER   = "Junk";
var WIRE_HOLD_FOLDER  = "Drafts";

var LISTENERS_OFF = Object.freeze({
  mx:          { enabled: false },
  submission:  { enabled: false },
  submissions: { enabled: false },
  imap:        { enabled: false },
  pop3:        { enabled: false },
  managesieve: { enabled: false },
});

// The assertion that quotes the value that produced the verdict. It is
// the shared one rather than a copy, because a private wrapper that
// formats a failure differently is a failure line nobody can grep for.
var count = helpers.count;

function message(subject, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body of " + subject + ".\r\n", "utf8");
}

// The store's name for one of an account's folders. The adapter is the
// only place the mapping is recorded, so it is the only place to ask.
function storeFolderOf(identity, accountId, wireName) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var found = folders.filter(function (f) { return f.name === wireName; })[0];
  return found ? found.storeName : "";
}

function rowsIn(identity, storeFolder) {
  return identity.messageStore.queryByModseq(storeFolder, { sinceModseq: 0 });
}

// ---- one composed server, no listeners -------------------------------------

async function withComposed(label, posture, fn) {
  var root    = helpers.tempDir("floor-parity-" + label);
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  try {
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
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var server = blamepost.create({
      config: Object.assign({}, cfg, { httpPort: 0, listeners: LISTENERS_OFF }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      // Nothing in this file binds a port, so no peer ever sees a
      // certificate. The wire vectors live in the integration layer,
      // where the run mints a real one and the client verifies it.
      tlsContext:   nodeTls.createSecureContext({}),
    });

    await fn({
      server: server, identity: identity, alice: alice, posture: posture, cfg: cfg,
    });
  } finally {
    // The caller owns what it opened. `b.db` is one handle for the whole
    // process, so a second run opening a store while this one is still
    // held would read this run's rows out of its own empty directory.
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

// Four messages, one per leg, with the two hold legs put under a
// preservation order through the store the way an operator answering
// one would.
function plant(identity, alice) {
  var planted = {};
  [
    ["webFloor",  WEB_FLOOR_FOLDER,  "floor via the browser surface"],
    ["wireFloor", WIRE_FLOOR_FOLDER, "floor via the wire adapter"],
    ["webHold",   WEB_HOLD_FOLDER,   "hold via the browser surface"],
    ["wireHold",  WIRE_HOLD_FOLDER,  "hold via the wire adapter"],
  ].forEach(function (leg) {
    identity.mailbox.appendMessage(leg[1], message(leg[2], alice.address),
      { actor: { id: alice.id } });
    var folder = storeFolderOf(identity, alice.id, leg[1]);
    var rows = rowsIn(identity, folder);
    planted[leg[0]] = { folder: folder, objectId: rows[0].objectid, wireName: leg[1] };
  });
  identity.messageStore.setLegalHold(
    [planted.webHold.objectId, planted.wireHold.objectId], { hold: true });
  return planted;
}

// ---- the two handles -------------------------------------------------------

// The browser surface's handle, called exactly as the JMAP mount and
// the purge button call it.
async function throughTheBrowserHandle(server, actor, leg) {
  var verdict = await server.mail.agent.expunge({
    actor: actor, folder: leg.folder, objectIds: [leg.objectId],
  });
  return {
    deleted: (verdict && verdict.deleted) || [],
    refused: (verdict && verdict.refused) || [],
  };
}

// The wire adapter's handle, reached the way IMAP reaches it: flag the
// message deleted, then ask the folder to expunge.
async function throughTheWireHandle(identity, actor, leg) {
  identity.mailbox.storeFlags(actor, leg.wireName, "1:*", "add", ["\\Deleted"]);
  var verdict = await identity.mailbox.expungeFolder(actor, leg.wireName);
  return { expunged: (verdict && verdict.expunged) || [] };
}

// ---- cases -----------------------------------------------------------------

async function theFloorRefusesOnBothHandles(ctx, planted, actor) {
  var web = await throughTheBrowserHandle(ctx.server, actor, planted.webFloor);
  count("a posture refuses a recent hard delete on the browser handle",
    web.deleted.length === 0 && web.refused.length === 1, JSON.stringify(web));
  count("and it names the retention floor as the reason",
    web.refused.length === 1 && web.refused[0].reason === "retention-floor",
    JSON.stringify(web.refused));
  count("the message the browser handle refused is still in the store",
    rowsIn(ctx.identity, planted.webFloor.folder).length === 1,
    String(rowsIn(ctx.identity, planted.webFloor.folder).length));

  var wire = await throughTheWireHandle(ctx.identity, actor, planted.wireFloor);
  count("the wire handle refuses the same delete", wire.expunged.length === 0,
    JSON.stringify(wire));
  count("the message the wire handle refused is still in the store",
    rowsIn(ctx.identity, planted.wireFloor.folder).length === 1,
    String(rowsIn(ctx.identity, planted.wireFloor.folder).length));

  count("both handles reach the same verdict under a posture",
    web.deleted.length === 0 && wire.expunged.length === 0,
    "browser deleted " + web.deleted.length + ", wire expunged " + wire.expunged.length);
}

async function noPostureDeletesOnBothHandles(ctx, planted, actor) {
  var web = await throughTheBrowserHandle(ctx.server, actor, planted.webFloor);
  count("with no posture the browser handle destroys the message",
    web.deleted.length === 1 && web.refused.length === 0, JSON.stringify(web));
  count("and the store agrees it went",
    rowsIn(ctx.identity, planted.webFloor.folder).length === 0,
    String(rowsIn(ctx.identity, planted.webFloor.folder).length));

  var wire = await throughTheWireHandle(ctx.identity, actor, planted.wireFloor);
  count("with no posture the wire handle destroys the message too",
    wire.expunged.length === 1, JSON.stringify(wire));
  count("and the store agrees that one went as well",
    rowsIn(ctx.identity, planted.wireFloor.folder).length === 0,
    String(rowsIn(ctx.identity, planted.wireFloor.folder).length));

  count("both handles reach the same verdict with no posture",
    web.deleted.length === 1 && wire.expunged.length === 1,
    "browser deleted " + web.deleted.length + ", wire expunged " + wire.expunged.length);
}

// A hold outranks the posture in both directions: it is the whole
// refusal on a server with no posture set, which is the configuration
// most operators run, and it is still the reason given on a server that
// has one.
async function aHeldMessageSurvivesOnBothHandles(ctx, planted, actor) {
  var web = await throughTheBrowserHandle(ctx.server, actor, planted.webHold);
  count("a held message is refused on the browser handle",
    web.deleted.length === 0 && web.refused.length === 1, JSON.stringify(web));
  count("and the refusal names the hold rather than the floor",
    web.refused.length === 1 && web.refused[0].reason === "legal-hold",
    JSON.stringify(web.refused));
  count("the held message is still in the store after the browser handle",
    rowsIn(ctx.identity, planted.webHold.folder).length === 1,
    String(rowsIn(ctx.identity, planted.webHold.folder).length));

  var wire = await throughTheWireHandle(ctx.identity, actor, planted.wireHold);
  count("a held message is refused on the wire handle", wire.expunged.length === 0,
    JSON.stringify(wire));
  count("the held message is still in the store after the wire handle",
    rowsIn(ctx.identity, planted.wireHold.folder).length === 1,
    String(rowsIn(ctx.identity, planted.wireHold.folder).length));
}

// One agent for both consumers is the shape this composition is built
// for. A server that quietly built its own instead would be back to two
// handles that can drift, so it is asserted rather than assumed: the
// adapter's agent is the one the browser surface is given, and
// `opts.agent` overrides both for a caller that built the pair itself.
//
// The supplied agent is built through the mailbox module's factory
// rather than by hand, because an agent composed without a permission
// table is an agent with no role gate at all, and the assembly refuses
// one rather than wiring three wire protocols behind nothing.
function theSuppliedAgentIsTheOneUsed(ctx) {
  var withNoAgentNamed = blamepost.create({
    config: Object.assign({}, ctx.cfg, { httpPort: 0, listeners: LISTENERS_OFF }),
    store:        ctx.identity,
    mailStore:    ctx.identity.mailbox,
    messageStore: ctx.identity.messageStore,
    tlsContext:   nodeTls.createSecureContext({}),
  });
  count("with no agent named, the browser surface is given the adapter's own",
    withNoAgentNamed.mail.agent === ctx.identity.mailbox.agent);

  var shared = mailbox.agent({
    store:   ctx.identity.messageStore,
    posture: "soc2",
  });
  var server = blamepost.create({
    config: Object.assign({}, ctx.cfg, { httpPort: 0, listeners: LISTENERS_OFF }),
    store:        ctx.identity,
    mailStore:    ctx.identity.mailbox,
    messageStore: ctx.identity.messageStore,
    agent:        shared,
    tlsContext:   nodeTls.createSecureContext({}),
  });
  count("an agent handed to create is the one the browser surface is given",
    server.mail.agent === shared);

  var thrown = null;
  try {
    blamepost.create({
      config: Object.assign({}, ctx.cfg, { httpPort: 0, listeners: LISTENERS_OFF }),
      store:        ctx.identity,
      mailStore:    ctx.identity.mailbox,
      messageStore: ctx.identity.messageStore,
      agent:        b.mail.agent.create({
        store: ctx.identity.messageStore, posture: "soc2", dispatch: { mode: "local" } }),
      tlsContext:   nodeTls.createSecureContext({}),
    });
  } catch (e) { thrown = e; }
  count("and an agent carrying no role gate is refused rather than wired",
    thrown !== null && /role gate/.test(String(thrown.message)),
    thrown === null ? "nothing was thrown" : thrown.message);
}

// The two halves reading one configuration key is what keeps them in
// step, so a caller that builds the adapter from a different one is
// refused at the point the server is assembled. The alternative is a
// server that starts, answers every call, and destroys on one protocol
// what it refuses on another.
function aPostureDisagreementRefusesToStart(ctx) {
  var mismatched = mailbox.create({
    store:   ctx.identity.messageStore,
    dataDir: ctx.cfg.paths.dataDir,
    vault:   b.vault,
    posture: null,
  });
  var threw = null;
  try {
    blamepost.create({
      config: Object.assign({}, ctx.cfg, { httpPort: 0, listeners: LISTENERS_OFF }),
      store:        ctx.identity,
      mailStore:    mismatched,
      messageStore: ctx.identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({}),
    });
  } catch (e) { threw = e; }
  count("a server whose two halves disagree about the posture refuses to assemble",
    threw !== null, threw ? threw.message.slice(0, 160) : "assembled");
  count("and the refusal names the posture each half is holding",
    threw !== null && /compliance posture/.test(threw.message) &&
      threw.message.indexOf("soc2") !== -1,
    threw ? threw.message.slice(0, 200) : "assembled");
}

// ---- the third consumer of the same gate -----------------------------------

// Erasing an account is the third thing that drives a hard delete, and
// it has to reach the same verdict as the other two. It walks every
// mailbox the account holds rather than one folder a client named, so it
// is the one caller that meets the floor over a whole mailbox at once.
//
// A posture in force makes an erasure partial by design, and that is the
// half worth pinning: the mail stays, the mailbox row holding it stays
// with it, and the caller is told which messages the floor kept rather
// than being handed a clean answer over mail that is still there.
//
// The identity stays with them. It is the record every surface that
// could produce the kept mail resolves through, so erasing it ahead of
// the sweep would leave the floor keeping messages nothing can name an
// owner for. What it does NOT keep is any use: the account is out of
// service from the moment the erasure runs, and the counts below say so
// rather than leaving a working mailbox behind a partial erasure.
async function theFloorHoldsAnErasureBackToo(ctx) {
  var doomed = await ctx.identity.accounts.create({
    address: "doomed@" + DOMAIN, password: ALICE_PASSWORD });
  var actor = { id: doomed.id, roles: ["account"] };
  ctx.identity.mailbox.appendMessage("INBOX", message("too recent to erase", doomed.address),
    { actor: actor });
  var folder = storeFolderOf(ctx.identity, doomed.id, "INBOX");

  var erased = await ctx.identity.accounts["delete"]({
    id: doomed.id, destroy: true, reason: "erasure requested by the account holder" });

  count("an erasure the floor holds back reports itself as partial rather than as a clean " +
    "destruction, because the identity it was asked to erase is still on the table",
    erased.outcome === "partially-erased" && ctx.identity.accounts.get(doomed.id) !== null,
    JSON.stringify(erased.outcome));

  var kept = ctx.identity.accounts.get(doomed.id);
  var signIn = await ctx.identity.accounts.authenticate({
    address: doomed.address, password: ALICE_PASSWORD });
  count("the identity it kept is out of service, so a partial erasure leaves no mailbox " +
    "anybody can sign in to",
    kept.status === "erasing" && signIn.ok !== true,
    JSON.stringify({ status: kept.status, signIn: signIn.ok, reason: signIn.reason }));

  var putBack = null;
  try { await ctx.identity.accounts.reinstate({ id: doomed.id }); }
  catch (e) { putBack = e; }
  count("and it cannot be put back into service, because the mail it held is already gone " +
    "and nothing returns it",
    putBack !== null && putBack.code === "store/account-erasing",
    putBack === null ? "reinstated" : putBack.code);
  count("the floor keeps the message the erasure was asked to destroy, and names itself " +
    "as the reason",
    erased.mailErased === 0 && erased.mailPreserved.length === 1 &&
    erased.mailPreserved[0].reason === "retention-floor" &&
    erased.mailFailed.length === 0,
    JSON.stringify({ erased: erased.mailErased, preserved: erased.mailPreserved,
      failed: erased.mailFailed }));
  count("a message the floor is keeping is reported as preserved rather than as failed, " +
    "because a regulator keeping a record is the system working",
    erased.mailPreserved[0].preserved === true &&
    erased.mailPreserved[0].mailbox === "INBOX",
    JSON.stringify(erased.mailPreserved[0]));
  count("the message is still in the message store, which is what the floor is for",
    rowsIn(ctx.identity, folder).length === 1,
    String(rowsIn(ctx.identity, folder).length) + " row(s)");
  count("and the mailbox holding it kept its row, so the mail is still addressable rather " +
    "than bound to a mailbox nothing can name",
    erased.mailboxesKept === 1 && erased.mailboxesErased > 0,
    JSON.stringify({ kept: erased.mailboxesKept, erased: erased.mailboxesErased }));

  return { id: doomed.id, address: doomed.address, folder: folder };
}

// The half the counts above cannot answer for, and the half the whole
// gate exists to deliver.
//
// A floor keeps a message so that somebody can still produce it: for a
// regulator asking what the mailbox held, or for a court that ordered
// it preserved. The erasure beside this reports the message as kept and
// says so in as many words: the adapter's own description of the verb
// is that the mailbox row survives "so that message stays addressable",
// and the command line prints "It is preserved on purpose and stays
// readable". A count of mailboxes cannot tell either of those apart
// from mail nobody can reach, so this asks the question directly.
//
// Reaching it means one of three things being true, and they are asked
// in the order an operator would try them: find the account the mail
// belongs to, finish the erasure once the floor is satisfied, or have
// the volume agree the mail is held rather than stranded. The account
// row is erased before the mail, so the identity every one of those
// surfaces resolves through is already gone by the time the floor
// speaks.
async function thePreservedMailCanStillBeReached(ctx, erased) {
  count("an operator can still find the account whose mail the floor kept, because " +
    "every surface that could produce that message resolves the account first",
    ctx.identity.accounts.get(erased.id) !== null,
    JSON.stringify(ctx.identity.accounts.get(erased.id)));

  var listed = ctx.identity.accounts.list({}) || [];
  var rows = Array.isArray(listed) ? listed : (listed.accounts || []);
  count("and it is listed, so the mail the floor is keeping is attributable to somebody " +
    "rather than to an identifier nothing resolves",
    rows.some(function (a) { return a.id === erased.id; }),
    JSON.stringify(rows.map(function (a) { return a.address; })));

  // The remediation the command line instructs in as many words: release
  // the order or wait out the floor, then run the same command again to
  // erase what was held back. It has to be runnable.
  var again = null;
  var againErr = null;
  try {
    again = await ctx.identity.accounts["delete"]({
      id: erased.id, destroy: true, reason: "finishing the erasure the floor held back" });
  } catch (e) { againErr = (e && e.code) || String(e); }
  count("the erasure can be run again to reach the mail the floor held back, which is " +
    "what the operator is told to do and the only route left to that mail",
    againErr === null, String(againErr) + " " + JSON.stringify(again));

  // And the volume's own reader has to agree with the verb that wrote
  // this state. `blobs.reconcile` classifies a mailbox whose account row
  // is gone as mail no account holds, which is the opposite of what the
  // erasure reported about the same rows.
  var report = await ctx.identity.blobs.reconcile({ verify: true });
  var stranded = report.unowned.filter(function (u) { return u.account === erased.id; });
  count("the volume reader does not call the kept mail unowned, because the erasure " +
    "reported the same rows as preserved and addressable and the two cannot both be true",
    stranded.length === 0, JSON.stringify(stranded));
}

// The same erasure with no posture set, which is the shipped default. It
// is the other half of the pair: a floor that is not in force must not
// quietly keep anything, or an operator who set no posture is refused a
// deletion by a rule they never turned on.
async function noPostureErasesTheMail(ctx) {
  var doomed = await ctx.identity.accounts.create({
    address: "doomed@" + DOMAIN, password: ALICE_PASSWORD });
  var actor = { id: doomed.id, roles: ["account"] };
  ctx.identity.mailbox.appendMessage("INBOX", message("no floor to stop it", doomed.address),
    { actor: actor });
  var folder = storeFolderOf(ctx.identity, doomed.id, "INBOX");

  var erased = await ctx.identity.accounts["delete"]({
    id: doomed.id, destroy: true, reason: "erasure requested by the account holder" });

  count("with no posture set the erasure reaches the mail, because the floor is zero and " +
    "a hold is the only thing that keeps a message",
    erased.mailErased === 1 && erased.mailPreserved.length === 0 &&
    erased.mailFailed.length === 0,
    JSON.stringify({ erased: erased.mailErased, preserved: erased.mailPreserved }));
  count("the message store no longer holds it", rowsIn(ctx.identity, folder).length === 0,
    String(rowsIn(ctx.identity, folder).length) + " row(s)");
  count("and every mailbox it held went with it",
    erased.mailboxesKept === 0 && erased.mailboxesErased > 0,
    JSON.stringify({ kept: erased.mailboxesKept, erased: erased.mailboxesErased }));
}

// ---- runner ----------------------------------------------------------------

// The floor over a row the mail agent can no longer see.
//
// The agent decides from the message store's row. A destruction that
// took that row and could not take this layer's leaves a row the agent
// has no view of at all, and the delete path finishes that destruction
// on a later run rather than answering about it as an identifier naming
// nothing. Finishing a destruction is still a destruction, so the gates
// have to hold there too, and the only layer that can still see the row
// is the one that has to apply them.
//
// The state is built the way the volume builds it rather than by
// patching the delete: the message store's own hard delete runs, which
// is what the agent calls, and this layer's row survives it exactly as
// it survives a volume that refuses the second act.
//
// Four messages, so the vector proves each gate DISCRIMINATES rather
// than that the path is simply dead. One is inside the window, one is
// older than it, one only CLAIMS to be older, and one is under a
// preservation order; the answer has to differ across all four.
//
// The claim is the third message's whole point. RFC 9051 section 6.3.12
// lets an APPEND set the date a message shows, so that field is the
// client's. A floor measured against it is a floor whose input the
// client supplies, and this asks the question by aging that field and
// nothing else.
async function theFloorHoldsAStrandedRowToo(ctx) {
  var actor = { id: ctx.alice.id, address: ctx.alice.address,
    domain: ctx.alice.domain, roles: ["account"] };
  var folderName = WEB_FLOOR_FOLDER;

  var recent = ctx.identity.mailbox.appendMessage(folderName,
    message("stranded and still inside the window", ctx.alice.address), { actor: actor });
  var older = ctx.identity.mailbox.appendMessage(folderName,
    message("stranded and older than the window", ctx.alice.address), { actor: actor });
  var claimed = ctx.identity.mailbox.appendMessage(folderName,
    message("stranded and dated older by its client", ctx.alice.address), { actor: actor });
  var held = ctx.identity.mailbox.appendMessage(folderName,
    message("stranded and under a preservation order", ctx.alice.address), { actor: actor });

  // Older than the posture's own floor, read from the framework rather
  // than written here: a window this file carried a second copy of would
  // be a window that stops matching the one being enforced.
  var floorMs = b.retention.complianceFloor(ctx.posture);
  count("the posture under test names a floor, so the messages really are on " +
    "opposite sides of one", floorMs > 0, String(floorMs));
  var aged = Date.now() - (floorMs * 2);
  // The clock this server stamped when the message was filed, which is
  // the one the floor measures against.
  var olderRow = b.db.from(mailbox.MESSAGES).where({ objectid: older.objectid }).first();
  b.db.from(mailbox.MESSAGES).where({ _id: olderRow._id })
    .updateOne({ _id: olderRow._id, createdAt: aged });
  // And the date the client asked the message to show, moved on its own.
  var claimedRow = b.db.from(mailbox.MESSAGES).where({ objectid: claimed.objectid }).first();
  b.db.from(mailbox.MESSAGES).where({ _id: claimedRow._id })
    .updateOne({ _id: claimedRow._id, internalDate: aged });

  // The order placed through the verb an operator answering one uses,
  // which is the only spelling that reaches a row the message store has
  // no partner for: it writes the registry record as well as the store's
  // own flag, and the flag has no row to land on once the row is
  // stranded.
  ctx.identity.mailbox.legalHold.place(actor, folderName, [held.objectid], {
    reason:   "preservation order 24-cv-01933",
    citation: "FRCP-26",
  });

  var storeFolder = storeFolderOf(ctx.identity, ctx.alice.id, folderName);
  var subjects = [recent, older, claimed, held];
  var ids = subjects.map(function (msg) { return msg.objectid; });
  var digestOf = {};
  subjects.forEach(function (msg) {
    digestOf[msg.objectid] = b.db.from(mailbox.MESSAGES)
      .where({ objectid: msg.objectid }).first().blobDigest;
  });

  // The store's row destroyed and this layer's left standing, which is
  // what the volume leaves when it takes the first act and refuses the
  // second. The held one is taken out from under its own flag, which is
  // the state that leaves the registry as the only surviving record of
  // the order.
  ctx.identity.messageStore.setLegalHold([held.objectid], { hold: false });
  ctx.identity.messageStore.hardExpunge(storeFolder, ids);
  count("every row is outside the intersection a reader is served from, so no folder " +
    "listing names them",
  ids.every(function (id) {
    return b.db.from(mailbox.MESSAGES).where({ objectid: id }).count() === 1 &&
      ctx.identity.messageStore.fetchByObjectId(storeFolder, id) === null;
  }),
  storeFolder);

  var outcome = await ctx.identity.mailbox.expungeObjects(actor, folderName, ids);
  function refusalFor(objectid) {
    return outcome.refused.filter(function (row) { return row.id === objectid; })[0] || null;
  }
  function stillHere(objectid) {
    return b.db.from(mailbox.MESSAGES).where({ objectid: objectid }).count() === 1 &&
      nodeFs.existsSync(mailbox.blobPathFor(
        ctx.identity.mailbox.describe().blobDir, digestOf[objectid]));
  }

  count("the delete reaches a stranded row rather than answering about it with the reason " +
    "reserved for an identifier that names nothing",
  refusalFor(recent.objectid) !== null &&
    refusalFor(recent.objectid).reason !== "not-in-folder",
  JSON.stringify(outcome.refused));
  count("and the floor is what refuses it, applied on the layer that can still see the row",
    refusalFor(recent.objectid) !== null &&
    refusalFor(recent.objectid).reason === "retention-floor" &&
    refusalFor(recent.objectid).outcome === "preserved",
    JSON.stringify(refusalFor(recent.objectid)));
  count("so the message inside the window is still on the volume, row and octets both",
    stillHere(recent.objectid), recent.objectid);

  count("the message older than the window is destroyed by the same call, so the gate is " +
    "deciding rather than the path being closed",
  outcome.deleted.indexOf(older.objectid) !== -1 &&
    b.db.from(mailbox.MESSAGES).where({ objectid: older.objectid }).count() === 0,
  JSON.stringify(outcome.deleted));
  count("and its octets went with its row",
    !nodeFs.existsSync(mailbox.blobPathFor(
      ctx.identity.mailbox.describe().blobDir, digestOf[older.objectid])),
    digestOf[older.objectid]);

  count("a message whose CLIENT dated it older than the window is still kept, because the " +
    "floor is measured against the clock this server stamped and not against a field an " +
    "APPEND can set",
  refusalFor(claimed.objectid) !== null &&
    refusalFor(claimed.objectid).reason === "retention-floor" &&
    stillHere(claimed.objectid),
  JSON.stringify(refusalFor(claimed.objectid)));

  count("a stranded row under a preservation order is refused, and the order is what " +
    "refuses it rather than the window it is also inside",
  refusalFor(held.objectid) !== null &&
    refusalFor(held.objectid).reason === "legal-hold" &&
    refusalFor(held.objectid).outcome === "preserved",
  JSON.stringify(refusalFor(held.objectid)));
  count("so the held message is still on the volume, row and octets both",
    stillHere(held.objectid), held.objectid);
}

async function run() {
  await withComposed("stranded-floor", "soc2", async function (ctx) {
    await theFloorHoldsAStrandedRowToo(ctx);
  });

  await withComposed("soc2", "soc2", async function (ctx) {
    count("the adapter reports the posture it was given",
      ctx.identity.mailbox.describe().posture === "soc2",
      String(ctx.identity.mailbox.describe().posture));

    theSuppliedAgentIsTheOneUsed(ctx);
    aPostureDisagreementRefusesToStart(ctx);

    var planted = plant(ctx.identity, ctx.alice);
    var actor = { id: ctx.alice.id, roles: ["account"] };
    await theFloorRefusesOnBothHandles(ctx, planted, actor);
    await aHeldMessageSurvivesOnBothHandles(ctx, planted, actor);
    var heldBack = await theFloorHoldsAnErasureBackToo(ctx);
    await thePreservedMailCanStillBeReached(ctx, heldBack);
  });

  await withComposed("none", null, async function (ctx) {
    count("a server with no posture set reports none",
      ctx.identity.mailbox.describe().posture === null,
      String(ctx.identity.mailbox.describe().posture));

    var planted = plant(ctx.identity, ctx.alice);
    var actor = { id: ctx.alice.id, roles: ["account"] };
    await noPostureDeletesOnBothHandles(ctx, planted, actor);
    await aHeldMessageSurvivesOnBothHandles(ctx, planted, actor);
    await noPostureErasesTheMail(ctx);
  });

  return helpers.getChecks();
}

module.exports = { name: "retention-floor-parity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
