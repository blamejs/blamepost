// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The state strings a JMAP client caches against, read off a real
 * session against a running server.
 *
 * RFC 8620 section 5.1 hands every typed answer a state string, and a
 * client treats it as the whole answer to whether its copy is still
 * good. It keeps what it holds for as long as the same string comes
 * back, and refetches when a different one does. Two obligations ride
 * on that, and breaking either one is silent.
 *
 * The string has to CHANGE on every mutation. One that stands still
 * through a change leaves the client showing keywords that were
 * cleared, messages that moved, and mail in a folder it has left.
 * Nothing on the wire reports it, because the client is not failing to
 * refetch: it has been told there is nothing to refetch.
 *
 * The string also has to STAND STILL when nothing has happened, which
 * is what rules a clock reading out of the answer. A string taken off
 * the wall clock differs on every response, so every response
 * invalidates the client's copy and the client refetches a mailbox
 * nothing happened to, for as long as it stays connected.
 *
 * Two types are driven here, because each derives its string from
 * different data and each can go still on its own.
 *
 * Email and Mailbox share one string across the account, and the folder
 * counters behind it are per folder: RFC 7162 gives every mailbox its
 * own modseq, so a change in one folder moves that folder's counter and
 * no other. The configuration that catches a string built from the
 * wrong combination of them is an account whose folders sit at
 * DIFFERENT counters, with the change driven in one that is not the
 * highest. An account with a single folder, or one whose folders happen
 * to be level, reports a pass for a server that never moves. So the
 * mailbox is planted unevenly on purpose and the precondition is
 * asserted before the vector runs.
 *
 * Identity derives from the account record instead. A fixed string
 * there is an address book entry a client caches on first sight and
 * never revisits, so a name a mailbox owner changed reaches nobody who
 * has already looked. It is also the one that must NOT move when the
 * mailbox does: RFC 8620 section 5.1 scopes a state to the data of ONE
 * type, and an identity string that tracked mail would have every
 * client refetching its identities every time a message arrived.
 *
 * Run standalone: node test/layer-1-state/jmap-state-currency.test.js
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
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The uneven plant. The inbox is given several messages and the drafts
// folder one, so the two folder counters sit apart and a state built
// from the highest of them cannot notice the low one moving.
var INBOX_MESSAGES  = 5;
var DRAFTS_MESSAGES = 1;

// The name the account is created with and the one it is changed to.
// There is no verb on any surface that renames an account today, so the
// change is written through the store's own row writer, which is the
// call every account verb in that layer makes. What is under assertion
// is what JMAP reports afterwards, not how the name got there.
var NAME_BEFORE = "Alice Before";
var NAME_AFTER  = "Alice Afterwards";

// The two shared addresses the alias vectors point at this mailbox. Each
// one an operator adds is another address the account may write, so each
// one is another Identity a client is offered and another reading of the
// identity state.
var FIRST_ALIAS  = "first-desk@" + DOMAIN;
var SECOND_ALIAS = "second-desk@" + DOMAIN;

function message(marker, to) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + to + ">\r\n" +
    "Subject: " + marker + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + marker.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "Body of " + marker + ".\r\n", "utf8");
}

// ---- what the server was handed, in the order it handed it over ------------

// Every state string one type answered with, kept in order. Two
// questions are asked of it at the end that no single response can
// answer: whether any value repeated, which is a client told the
// mailbox went back to a version it already cached, and whether the
// readings ever went backwards.
function stateLog(label) {
  var seen = [];
  return {
    label:  label,
    add:    function (value) { seen.push(String(value)); return String(value); },
    all:    function () { return seen.slice(); },
    latest: function () { return seen.length === 0 ? "" : seen[seen.length - 1]; },
    // The distinct values, so a run that read the same unchanged state
    // twice on purpose is not counted as a repeat.
    firstRepeatAfterChange: function () {
      var order = [];
      for (var i = 0; i < seen.length; i += 1) {
        if (order.length === 0 || order[order.length - 1] !== seen[i]) order.push(seen[i]);
      }
      for (var a = 0; a < order.length; a += 1) {
        if (order.indexOf(order[a]) !== a) return order[a];
      }
      return null;
    },
  };
}

// ---- one reader's view of the two state strings ----------------------------

// The account wide string, taken from both types that carry it. They are
// asked together rather than one at a time because this server derives
// them from one counter and pushes one value for both (RFC 8620 section
// 7.4 names a type map in a StateChange), so a client handed two
// different strings would refetch one type against the other's version.
async function accountState(reader, accountId, log) {
  var answer = await reader.jmap([
    ["Mailbox/get", { accountId: accountId }, "s0"],
    ["Email/get",   { accountId: accountId, ids: [] }, "s1"],
  ]);
  count("the state probe is answered", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 200));
  var mailbox = browser.answer(answer, 0)[1];
  var email   = browser.answer(answer, 1)[1];
  count("Mailbox and Email answer with the same account state, because one push " +
    "carries one value for both",
    typeof mailbox.state === "string" && mailbox.state === email.state,
    JSON.stringify(mailbox.state) + " vs " + JSON.stringify(email.state));
  return log.add(mailbox.state);
}

async function identityState(reader, accountId, log) {
  var answer = await reader.jmap([["Identity/get", { accountId: accountId }, "i0"]]);
  count("Identity/get is answered", answer.status === 200,
    answer.status + " " + String(answer.body).slice(0, 200));
  var result = browser.answer(answer, 0)[1];
  // The account's own identity leads the list, and it is the one whose
  // name the rename vectors below are about. Every other entry is an
  // alias the operator pointed at this mailbox, which is what the two
  // alias vectors move.
  count("the account's own identity leads the list",
    Array.isArray(result.list) && result.list.length > 0 && result.list[0].id === accountId,
    JSON.stringify(result.list));
  return {
    state:     log.add(result.state),
    name:      result.list[0].name,
    email:     result.list[0].email,
    addresses: result.list.map(function (identity) { return identity.email; }),
  };
}

// ---- the mailbox the vectors run against -----------------------------------

// The uneven counters, asserted rather than assumed. A run where the two
// folders happen to sit level is a run where a state built from the
// highest counter would move for the wrong reason and read as a pass.
function theFoldersSitAtDifferentCounters(identity, accountId) {
  var folders = identity.mailbox.accountFolders({ id: accountId });
  var inbox  = folders.filter(function (f) { return f.name === "INBOX"; })[0];
  var drafts = folders.filter(function (f) { return f.name === "Drafts"; })[0];
  count("the account has both folders the vectors use",
    inbox !== undefined && drafts !== undefined,
    JSON.stringify(folders.map(function (f) { return f.name; })));
  count("the inbox counter is above the drafts counter, which is the arrangement " +
    "a state built from the highest one cannot see past",
    inbox.modseqMax > drafts.modseqMax,
    "INBOX " + inbox.modseqMax + " vs Drafts " + drafts.modseqMax);
  return { inbox: inbox, drafts: drafts };
}

// ---- the vectors -----------------------------------------------------------

// A reading taken twice with nothing in between. This is the half a
// clock breaks, and it runs first so a later assertion that the string
// moved cannot be satisfied by a string that moves on its own.
async function anIdleAccountKeepsItsState(reader, accountId, log) {
  var first  = await accountState(reader, accountId, log);
  var second = await accountState(reader, accountId, log);
  count("two reads with no mutation between them answer with the same state, so a " +
    "client's cached copy survives an ordinary poll",
    first === second, JSON.stringify(first) + " then " + JSON.stringify(second));
  return second;
}

// The vector this file exists for. The flag change lands in the folder
// whose counter is NOT the account's highest, which is the message a
// client is never told about when the string is built from the highest
// counter alone.
async function aChangeInAQuietFolderMovesTheState(reader, accountId, objectId, before, log) {
  var patch = {};
  patch[objectId] = { "keywords/$flagged": true };
  var answer = await reader.jmap([
    ["Email/set", { accountId: accountId, update: patch }, "u0"],
  ]);
  count("the keyword patch on the quiet folder's message is answered",
    answer.status === 200, answer.status + " " + String(answer.body).slice(0, 200));
  var result = browser.answer(answer, 0)[1];
  count("the update is reported as applied rather than refused",
    Object.prototype.hasOwnProperty.call(result.updated || {}, objectId),
    JSON.stringify(result.notUpdated));

  log.add(result.oldState);
  log.add(result.newState);
  count("Email/set reports a new state that differs from the old one it was asked " +
    "against, which is what tells a client its copy is stale",
    typeof result.newState === "string" && result.newState !== result.oldState,
    JSON.stringify(result.oldState) + " then " + JSON.stringify(result.newState));

  var after = await accountState(reader, accountId, log);
  count("and a client reading the state back afterwards is handed the moved one",
    after !== before, JSON.stringify(before) + " then " + JSON.stringify(after));
  return after;
}

// The control. The same change in the folder that IS the account's
// highest counter, so a server that only ever moved for this one is
// distinguished from a server that moves for both.
async function aChangeInTheBusiestFolderMovesTheState(reader, accountId, objectId, before, log) {
  var patch = {};
  patch[objectId] = { "keywords/$flagged": true };
  var answer = await reader.jmap([
    ["Email/set", { accountId: accountId, update: patch }, "u1"],
  ]);
  var result = browser.answer(answer, 0)[1];
  count("the keyword patch on the busiest folder's message is applied",
    Object.prototype.hasOwnProperty.call(result.updated || {}, objectId),
    JSON.stringify(result.notUpdated));
  log.add(result.oldState);
  log.add(result.newState);

  var after = await accountState(reader, accountId, log);
  count("a change in the folder holding the highest counter moves the state too",
    after !== before, JSON.stringify(before) + " then " + JSON.stringify(after));
  return after;
}

// A move touches two folders at once and is the mutation a client most
// needs to hear about, because the message is somewhere else afterwards
// rather than merely marked.
async function aMoveMovesTheState(reader, accountId, objectId, destination, before, log) {
  var patch = {};
  patch[objectId] = { mailboxIds: {} };
  patch[objectId].mailboxIds[destination] = true;
  var answer = await reader.jmap([
    ["Email/set", { accountId: accountId, update: patch }, "u2"],
  ]);
  var result = browser.answer(answer, 0)[1];
  count("the message is filed into " + destination,
    Object.prototype.hasOwnProperty.call(result.updated || {}, objectId),
    JSON.stringify(result.notUpdated));
  log.add(result.oldState);
  log.add(result.newState);

  var after = await accountState(reader, accountId, log);
  count("filing a message into another folder moves the state",
    after !== before, JSON.stringify(before) + " then " + JSON.stringify(after));
  return after;
}

// ---- the identity string ---------------------------------------------------

async function anIdleIdentityKeepsItsState(reader, accountId, log) {
  var first  = await identityState(reader, accountId, log);
  var second = await identityState(reader, accountId, log);
  count("two identity reads with nothing changed answer with the same state",
    first.state === second.state,
    JSON.stringify(first.state) + " then " + JSON.stringify(second.state));
  count("and the name a client caches is the one the account carries",
    second.name === NAME_BEFORE, JSON.stringify(second.name));
  return second.state;
}

async function aRenamedIdentityMovesItsState(reader, accountId, before, log) {
  tables.updateRow(tables.ACCOUNTS, accountId, {
    displayName: NAME_AFTER,
    updatedAt:   Date.now(),
  });
  var after = await identityState(reader, accountId, log);
  count("the renamed identity is what a client asking now is handed",
    after.name === NAME_AFTER, JSON.stringify(after.name));
  count("and the identity state moved with it, so a client holding the old name " +
    "is told to look again",
    after.state !== before, JSON.stringify(before) + " then " + JSON.stringify(after.state));
  return after.state;
}

// The set of identities is not only the account's own address. RFC 8621
// section 6 is how a client learns which addresses it may write, and
// this server answers with the account's address plus every alias
// pointed at its mailbox, so an alias the operator adds is a new sending
// identity and one they withdraw is a sending identity that is gone. A
// client caching the old list keeps offering an address the server now
// refuses, or never offers one it would accept, until the state tells it
// to look again.
// Two aliases are added and one is withdrawn, rather than one being
// added and taken back. A state derived from content returns to an
// earlier reading when the content does, which is correct and is exactly
// what the repeat check at the end of this run is written to catch in a
// counter. Leaving one alias behind keeps every reading in this run a
// list this account never held before.
async function anAddedAliasMovesTheIdentityState(reader, identity, alice, before, log) {
  await identity.aliases.add({ address: FIRST_ALIAS, destination: alice.address });
  var one = await identityState(reader, alice.id, log);
  count("an alias pointed at this mailbox becomes an identity a client is offered",
    one.addresses.indexOf(FIRST_ALIAS) !== -1, JSON.stringify(one.addresses));
  count("and the identity state moved with it, so a client holding the old set is " +
    "told to look again",
    one.state !== before, JSON.stringify(before) + " then " + JSON.stringify(one.state));

  await identity.aliases.add({ address: SECOND_ALIAS, destination: alice.address });
  var two = await identityState(reader, alice.id, log);
  count("a second alias is offered alongside the first",
    two.addresses.indexOf(FIRST_ALIAS) !== -1 && two.addresses.indexOf(SECOND_ALIAS) !== -1,
    JSON.stringify(two.addresses));
  count("and moves the state again",
    two.state !== one.state, JSON.stringify(one.state) + " then " + JSON.stringify(two.state));
  return two.state;
}

async function aWithdrawnAliasMovesItAgain(reader, identity, alice, before, log) {
  await identity.aliases.remove({
    address: FIRST_ALIAS, destination: alice.address,
    reason:  "the shared address was retired",
  });
  var after = await identityState(reader, alice.id, log);
  count("withdrawing an alias takes the identity away",
    after.addresses.indexOf(FIRST_ALIAS) === -1, JSON.stringify(after.addresses));
  count("while the one that was left alone is still offered",
    after.addresses.indexOf(SECOND_ALIAS) !== -1, JSON.stringify(after.addresses));
  count("and the state moved, so a client is not left offering an address this " +
    "server would now refuse",
    after.state !== before, JSON.stringify(before) + " then " + JSON.stringify(after.state));
  return after.state;
}

// The other half of the same rule. RFC 8620 section 5.1 scopes a state
// string to the data of one type, so mail arriving must not invalidate
// the identity a client cached.
async function mailDoesNotMoveTheIdentityState(reader, identity, alice, before, log) {
  identity.mailbox.appendMessage("INBOX", message("state-witness-arrival", alice.address),
    { actor: { id: alice.id } });
  var after = await identityState(reader, alice.id, log);
  count("a message arriving does not move the identity state, because the identity " +
    "did not change",
    after.state === before, JSON.stringify(before) + " then " + JSON.stringify(after.state));
}

// ---- what the whole run says together --------------------------------------

function noStateThisRunSawEverCameBack(log) {
  var repeated = log.firstRepeatAfterChange();
  count("no " + log.label + " state this run was handed came back after changing, " +
    "which would tell a client the data returned to a version it already cached",
    repeated === null, String(repeated) + " in " + JSON.stringify(log.all()));
}

// This server derives the account string from a counter that only ever
// climbs, so a later reading compares above an earlier one. A reading
// below its predecessor is a client told the mailbox has been rewound,
// and the values are ordinary decimal readings, so the comparison is
// numeric rather than lexical.
function theAccountStateOnlyEverClimbed(log) {
  var values = log.all();
  var digits = values.filter(function (v) { return /^[0-9]+$/.test(v); });
  count("every account state this run saw is a counter reading",
    digits.length === values.length, JSON.stringify(values));
  var backwards = null;
  for (var i = 1; i < values.length; i += 1) {
    if (Number(values[i]) < Number(values[i - 1])) {
      backwards = values[i - 1] + " then " + values[i];
      break;
    }
  }
  count("and no reading was below the one before it", backwards === null,
    String(backwards) + " in " + JSON.stringify(values));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("jmapstate");
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
      address:     "alice@" + DOMAIN,
      password:    ALICE_PASSWORD,
      displayName: NAME_BEFORE,
    });

    var inboxIds = [];
    for (var i = 0; i < INBOX_MESSAGES; i += 1) {
      inboxIds.push(identity.mailbox.appendMessage("INBOX",
        message("inbox-message-" + i, alice.address),
        { actor: { id: alice.id } }).objectid);
    }
    var draftIds = [];
    for (var d = 0; d < DRAFTS_MESSAGES; d += 1) {
      draftIds.push(identity.mailbox.appendMessage("Drafts",
        message("draft-message-" + d, alice.address),
        { actor: { id: alice.id } }).objectid);
    }

    var placed = theFoldersSitAtDifferentCounters(identity, alice.id);
    count("the messages the vectors name were all stored",
      inboxIds.concat(draftIds).filter(function (id) {
        return typeof id === "string" && id.length > 0;
      }).length === INBOX_MESSAGES + DRAFTS_MESSAGES,
      JSON.stringify(placed.drafts.name));

    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var n = 0; n < names.length; n += 1) {
      sections[names[n]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
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

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var reader = browser.browserAt(origin, { ca: material.caPem });
    var landing = await reader.signIn(alice.address, ALICE_PASSWORD);
    count("a reader signs in, because every JMAP method here is behind the door",
      landing.status === 302, landing.status + " " + String(landing.location));

    var accountLog  = stateLog("account");
    var identityLog = stateLog("identity");

    // The identity string first. It is read off the account record and
    // nothing the mailbox vectors below do touches it, so running it
    // ahead of them keeps the two verdicts independent of each other.
    var identityIdle = await anIdleIdentityKeepsItsState(reader, alice.id, identityLog);
    var identityMoved = await aRenamedIdentityMovesItsState(
      reader, alice.id, identityIdle, identityLog);
    var identityGrown = await anAddedAliasMovesTheIdentityState(
      reader, identity, alice, identityMoved, identityLog);
    var identityTrimmed = await aWithdrawnAliasMovesItAgain(
      reader, identity, alice, identityGrown, identityLog);
    await mailDoesNotMoveTheIdentityState(reader, identity, alice, identityTrimmed, identityLog);

    var idle = await anIdleAccountKeepsItsState(reader, alice.id, accountLog);
    var afterQuiet = await aChangeInAQuietFolderMovesTheState(
      reader, alice.id, draftIds[0], idle, accountLog);
    var afterBusy = await aChangeInTheBusiestFolderMovesTheState(
      reader, alice.id, inboxIds[0], afterQuiet, accountLog);
    await aMoveMovesTheState(reader, alice.id, inboxIds[1], "Archive", afterBusy, accountLog);

    noStateThisRunSawEverCameBack(accountLog);
    noStateThisRunSawEverCameBack(identityLog);
    theAccountStateOnlyEverClimbed(accountLog);

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

module.exports = { name: "jmap-state-currency", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
