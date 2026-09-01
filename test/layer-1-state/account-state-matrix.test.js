// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every account state against every rule that reads one.
 *
 * `tables.ACCOUNT_STATUS` declares four: active, suspended, archived and
 * erasing. Three of them are one category, an account out of service,
 * and the rules that gate on that category are the ones this file is
 * about. A gate written as a list of states rather than as a question
 * about the category passes its own test and misses whichever member
 * nobody thought of, and it does it quietly: the verb still works, the
 * refusal it should have made is simply absent, and the only thing that
 * says so is a vector naming the member that was left out.
 *
 * So this file asks one question per rule and asks it in every state,
 * including the states where the answer is meant to be yes. A cell that
 * is deliberately open is pinned here exactly as a cell that is
 * deliberately shut, because an intended asymmetry nobody wrote down is
 * one the next reader closes by accident.
 *
 * Two of the cells were oversights and are the reason the file exists.
 *
 *   - **The operator interface could be granted to a suspended
 *     mailbox.** The refusal named archived and erasing and its own
 *     reasoning named the category: an account that cannot present a
 *     credential is one the role is inert on, and a reversible state is
 *     one the role comes back out of. Both sentences are true of a
 *     suspension word for word, and suspension is the reversible hold an
 *     operator applies to a mailbox they have reason to distrust, which
 *     makes it the state in the category where a grant is least
 *     defensible.
 *
 *   - **Archiving an account that was part way through an erasure put it
 *     back within reach of reinstatement.** Erasing is the one state
 *     nothing returns to service: the mail is destroyed and the row is
 *     kept only to answer for what a preservation order or the retention
 *     floor held back. Every sibling verb refuses it. The archive branch
 *     of delete did not, and archived IS reinstatable, so two ordinary
 *     operator actions in sequence handed back a working mailbox whose
 *     mail is gone and left an outstanding erasure reading as a closed
 *     one.
 *
 * The console drives every vector it can reach, because a handle called
 * directly proves what the handle does and not what an operator can do.
 * Where the console renders no control for a state, the vector goes to
 * the route anyway: the route dispatches on a form field, and a page
 * rendered before the state changed is a form field pointed at a row
 * that has since moved.
 *
 * Run standalone: node test/layer-1-state/account-state-matrix.test.js
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
var ADMIN_PASSWORD   = "an operator passphrase 5512";
var OTHER_PASSWORD   = "another operator passphrase 8841";

// One subject per state, because a single subject would have to be moved
// between states and a verb that refuses in one of them would then be
// measured against a row a previous case had already changed.
var OPERATOR  = "adam@" + DOMAIN;
var SPARE_ADMIN = "beth@" + DOMAIN;
var ACTIVE    = "clara@" + DOMAIN;
var SUSPENDED = "holly@" + DOMAIN;
var ARCHIVED  = "ivy@" + DOMAIN;
var ERASING   = "jack@" + DOMAIN;

// A second suspended subject, held back for the case that measures
// whether a suspended administrator counts toward the set the console
// refuses to empty. It has to hold the role and be out of service at the
// same time, which no other subject here does.
var SUSPENDED_ADMIN = "karl@" + DOMAIN;

// What keeps the erasure from finishing, so the run has a real `erasing`
// row rather than one written by hand. An order names a record and the
// rule keeping it, which is what an operator answering the erasure
// request has to be able to quote.
var HOLD_REASON   = "preservation order 24-cv-01933";
var HOLD_CITATION = "FRCP-26";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The three states that are one category. Written from the frozen list
// rather than spelled out, so a fifth status added to the store arrives
// here as a failing vector rather than as a silent hole: this file
// exists because a category was enumerated by hand once already.
var OUT_OF_SERVICE = tables.ACCOUNT_STATUS.filter(function (name) {
  return name !== "active";
});

function baseEnv(dataDir, material) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    BLAMEPOST_TLS_CERT:         material.certFile,
    BLAMEPOST_TLS_KEY:          material.keyFile,
  };
}

// Every mail listener off. The rules here are read by the identity layer
// and by the browser routes; a bound mail port would only add a reason
// for the run to fail that has nothing to do with them. The wire side of
// the same question, that no listener admits a credential for an account
// out of service, is asked where the sockets are.
async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
  }
  return sections;
}

function noticeOf(answer) {
  var location = String(answer.location || "");
  var at = location.indexOf("notice=");
  return at === -1 ? "" : location.slice(at + "notice=".length).split("&")[0];
}

function statusOf(identity, address) {
  var row = identity.accounts.get(address);
  return (row === null || row === undefined) ? null : row.status;
}

function adminOf(identity, address) {
  var row = identity.accounts.get(address);
  return (row === null || row === undefined) ? null : row.isAdmin;
}

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

// Whatever a call raised, or null. Written once because every refusal
// below is measured the same way and a private copy per case is a second
// idea of what counts as a refusal.
async function raisedBy(fn) {
  try { await fn(); return null; }
  catch (e) { return e; }
}

// ---- standing the four states up -------------------------------------------

// The `erasing` row, produced the way an erasure actually stops rather
// than by writing the status onto a row. A preservation order over one
// message the erasure was asked to destroy keeps the mail, and the mail
// keeps the identity that owns it.
async function makeErasing(identity, address) {
  var doomed = await identity.accounts.create({
    address: address, password: OTHER_PASSWORD });
  var owner = {
    id: doomed.id, address: doomed.address, domain: doomed.domain,
    isAdmin: false, mailboxes: [doomed.address], roles: ["account"],
  };
  var kept = identity.mailbox.appendMessage("INBOX", heldMail(address), { actor: owner });
  await identity.mailbox.legalHold.place(owner, "INBOX", [kept.objectid], {
    reason: HOLD_REASON, citation: HOLD_CITATION });

  var partial = await identity.accounts["delete"]({
    id: doomed.id, destroy: true, reason: "erasure requested by the account holder" });
  count("the run has an account part way through an erasure, left behind by an order " +
    "rather than by a status written onto a row",
    partial.outcome === "partially-erased" && statusOf(identity, address) === "erasing",
    JSON.stringify({ outcome: partial.outcome, status: statusOf(identity, address) }));
  return doomed;
}

// ---- the category, not two of its members ----------------------------------

// The lead. Granting the operator interface refused an archived account
// and one part way through an erasure, and its own reasoning named the
// category rather than those two: an account that cannot present a
// credential is one the role is inert on, and a state that is reversible
// on purpose is one the role comes back out of.
//
// Both are true of a suspension, and the second is more true of it than
// of anything else here. Archiving is reversible because an operator may
// regret it; suspending is reversible because it is MEANT to be lifted,
// and the reason it is applied is a mailbox whose credential may be in
// somebody else's hands. Handing that mailbox the widest grant this
// server makes, to take effect the moment the hold is lifted, is the
// worst member of the category to have left open.
async function theRoleIsNotGrantedToAnyMailboxOutOfService(identity, operator) {
  for (var i = 0; i < OUT_OF_SERVICE.length; i += 1) {
    var state = OUT_OF_SERVICE[i];
    var address = { suspended: SUSPENDED, archived: ARCHIVED, erasing: ERASING }[state];
    count("the run has a subject in every state out of service: " + state,
      typeof address === "string" && statusOf(identity, address) === state,
      String(address) + " is " + String(statusOf(identity, address)));
    if (typeof address !== "string") continue;

    var subject = identity.accounts.get(address);
    var raised = await raisedBy(function () {
      return identity.accounts.setAdmin({
        id: subject.id, isAdmin: true, reason: "cover for the rota" });
    });
    count("granting the operator interface to a " + state + " mailbox is refused, under " +
      "this layer's own code, because it cannot present a credential and the role would " +
      "come back with the mailbox",
      raised !== null && typeof raised.code === "string" &&
        raised.code.indexOf("store/account-") === 0,
      raised === null ? "granted" : String(raised.code));
    count("and the " + state + " mailbox administers nothing afterwards",
      adminOf(identity, address) === false, JSON.stringify(adminOf(identity, address)));

    // The same ask over the route an operator actually drives. The row
    // renders no grant control once the account leaves service, so this
    // is the form a page rendered a moment earlier still carries.
    var posted = await operator.form("/admin/accounts", {
      action: "grant-role", id: subject.id, reason: "cover for the rota" });
    count("the console refuses the same grant on a " + state + " mailbox rather than " +
      "performing it, and says so on the page",
      posted.status === 400 && noticeOf(posted) !== "role-granted",
      posted.status + " " + String(posted.location));
    count("and the console left the " + state + " mailbox administering nothing",
      adminOf(identity, address) === false, JSON.stringify(adminOf(identity, address)));
  }
}

// The other half of the same verb, and the half that must NOT move. The
// role is taken back in every state, including the three where nothing
// else can reach the account, because revocation is the containment this
// verb exists for. Refusing it out of service would strand the role on
// exactly the rows nothing can reach to take it off.
async function theRoleIsTakenBackInEveryState(identity) {
  for (var i = 0; i < OUT_OF_SERVICE.length; i += 1) {
    var state = OUT_OF_SERVICE[i];
    var address = { suspended: SUSPENDED, archived: ARCHIVED, erasing: ERASING }[state];
    if (typeof address !== "string") continue;
    var subject = identity.accounts.get(address);

    // Put the role on the row without going through the verb under test,
    // which is the whole point: these are the states a grant refuses, so
    // the only way a role reaches one of them is a grant that landed
    // while the mailbox was still in service.
    tables.updateRow(tables.ACCOUNTS, subject.id, { isAdmin: 1, updatedAt: Date.now() });
    count("a " + state + " mailbox can be carrying the role, because it was granted " +
      "while the mailbox was still in service",
      adminOf(identity, address) === true, JSON.stringify(adminOf(identity, address)));

    var raised = await raisedBy(function () {
      return identity.accounts.setAdmin({
        id: subject.id, isAdmin: false, reason: "the credential was taken" });
    });
    count("taking the role back from a " + state + " mailbox is allowed, because " +
      "revocation is the containment and refusing it here would strand the role",
      raised === null && adminOf(identity, address) === false,
      raised === null ? "revoked" : String(raised.code));
  }
}

// ---- an erasure is not undone by archiving it ------------------------------

// The second oversight, and the one with a way back out of a state that
// has none.
//
// Erasing is terminal by construction: the mail is destroyed, reinstate
// refuses it in as many words, and the row is kept only to answer for
// what a preservation order or the retention floor held back. Suspending
// it is refused and so is changing its password. Archiving it was not,
// and archived is reinstatable, so archive-then-reinstate returned a
// working mailbox whose mail is gone and closed an erasure that is still
// outstanding.
async function anErasureIsNotArchivedBackIntoService(identity, operator) {
  var subject = identity.accounts.get(ERASING);
  count("the subject is part way through an erasure before anything is asked of it",
    statusOf(identity, ERASING) === "erasing", String(statusOf(identity, ERASING)));

  var raised = await raisedBy(function () {
    return identity.accounts["delete"]({
      id: subject.id, reason: "tidying the account list" });
  });
  count("archiving an account part way through an erasure is refused, under this layer's " +
    "own code, because archiving is reversible and the erasure is not",
    raised !== null && raised.code === "store/account-erasing",
    raised === null ? "archived" : String(raised.code));
  count("and the row is still marked as erasing, so the outstanding erasure still reads " +
    "as one",
    statusOf(identity, ERASING) === "erasing", String(statusOf(identity, ERASING)));

  // The console's archive is two posts: one that asks, and one carrying
  // the address typed back off the page it answered with. Both are sent,
  // because a refusal that only happens at the question would still let
  // a second post through.
  var asked = await operator.form("/admin/accounts", {
    action: "archive", id: subject.id, reason: "tidying the account list" });
  count("the console does not archive an erasing account on the post that asks",
    statusOf(identity, ERASING) === "erasing",
    asked.status + " " + String(statusOf(identity, ERASING)));

  var typed = await operator.form("/admin/accounts", {
    action: "archive", id: subject.id, reason: "tidying the account list",
    confirm: ERASING });
  count("and it refuses the confirmed post rather than performing it",
    typed.status === 400 && noticeOf(typed) !== "archived",
    typed.status + " " + String(typed.location));
  count("the erasure is still outstanding after the console has been asked twice",
    statusOf(identity, ERASING) === "erasing", String(statusOf(identity, ERASING)));

  // The consequence the refusal exists to prevent, measured rather than
  // argued: nothing reached a state the mailbox can be reinstated out of.
  var putBack = await raisedBy(function () {
    return identity.accounts.reinstate({ id: subject.id });
  });
  count("so nothing put the mailbox back in service, which is the whole reason archiving " +
    "it had to be refused: its mail is destroyed and reinstating it would hand its owner " +
    "a working mailbox that no longer holds what they had",
    putBack !== null && putBack.code === "store/account-erasing" &&
      statusOf(identity, ERASING) === "erasing",
    putBack === null ? "reinstated" : String(putBack.code));

  // Running the erasure again is the one thing that must still reach the
  // row, because it is the way the job finishes.
  var rerun = await raisedBy(function () {
    return identity.accounts["delete"]({
      id: subject.id, destroy: true, reason: "erasure requested by the account holder" });
  });
  count("and the rerun that finishes the erasure is not caught by the same refusal, " +
    "because it is the way the outstanding job is closed",
    rerun === null, rerun === null ? "ran" : String(rerun.code));
}

// ---- the cells that are open on purpose ------------------------------------

// A suspension holds the credential and nothing else, so replacing the
// password is allowed while it is held. That is not an oversight, it is
// the containment pair: an operator answering a stolen credential
// suspends the mailbox and resets the password, and refusing the second
// half would leave them holding a mailbox they can only reopen by
// reinstating it with the old password still live.
//
// Archived and erasing are refused, and for reasons that do not apply to
// a suspension: an archived mailbox is closed rather than held, and an
// erasing one no longer holds what its owner had.
async function thePasswordIsReplaceableExactlyWhileTheMailboxIsHeld(identity) {
  var held = identity.accounts.get(SUSPENDED);
  var replaced = await raisedBy(function () {
    return identity.accounts.setPassword({
      id: held.id, password: "a replacement passphrase 2277" });
  });
  count("a suspended mailbox takes a new password, because suspending and resetting is " +
    "one answer to a credential somebody else is holding",
    replaced === null, replaced === null ? "replaced" : String(replaced.code));
  count("and it is still suspended afterwards, so the reset is not a way back into service",
    statusOf(identity, SUSPENDED) === "suspended", String(statusOf(identity, SUSPENDED)));

  var onArchived = await raisedBy(function () {
    return identity.accounts.setPassword({
      id: identity.accounts.get(ARCHIVED).id, password: "a replacement passphrase 2277" });
  });
  count("an archived mailbox does not, and says to reinstate it first",
    onArchived !== null && onArchived.code === "store/account-archived",
    onArchived === null ? "replaced" : String(onArchived.code));

  var onErasing = await raisedBy(function () {
    return identity.accounts.setPassword({
      id: identity.accounts.get(ERASING).id, password: "a replacement passphrase 2277" });
  });
  count("and neither does one part way through an erasure, because a credential on it " +
    "would open a mailbox that no longer holds what its owner had",
    onErasing !== null && onErasing.code === "store/account-erasing",
    onErasing === null ? "replaced" : String(onErasing.code));
}

// One gate, asked in every state, rather than one gate per state. A
// correct password is refused wherever the row is not active, and the
// verdict names which state it was, because telling an account holder
// their mailbox is held is the answer that saves a support round and it
// says nothing to anybody who did not already present the password.
async function aCorrectPasswordIsRefusedInEveryStateOutOfService(identity) {
  for (var i = 0; i < OUT_OF_SERVICE.length; i += 1) {
    var state = OUT_OF_SERVICE[i];
    var address = { suspended: SUSPENDED, archived: ARCHIVED, erasing: ERASING }[state];
    if (typeof address !== "string") continue;
    // The suspended subject's password was replaced above, so the
    // credential presented here is whichever one that case left behind.
    var secret = address === SUSPENDED ? "a replacement passphrase 2277" : OTHER_PASSWORD;
    var verdict = await identity.accounts.authenticate({
      address: address, password: secret, source: "203.0.113.7" });
    count("a correct password on a " + state + " mailbox is refused, and the verdict names " +
      "the state rather than the credential",
      verdict.ok === false && verdict.reason === "account-" + state,
      JSON.stringify({ ok: verdict.ok, reason: verdict.reason }));
  }

  var live = await identity.accounts.authenticate({
    address: ACTIVE, password: OTHER_PASSWORD, source: "203.0.113.7" });
  count("and the same credential on an active mailbox is accepted, so the refusals above " +
    "are about the state rather than about the password",
    live.ok === true, JSON.stringify({ ok: live.ok, reason: live.reason }));
}

// The failure budget is a gate over the credential and the status is a
// different gate, so releasing one says nothing about the other. Reading
// and releasing both answer in every state, and neither moves the row.
async function releasingTheFailureBudgetChangesNoStateAnywhere(identity) {
  var everyState = ["active"].concat(OUT_OF_SERVICE);
  for (var i = 0; i < everyState.length; i += 1) {
    var state = everyState[i];
    var address = {
      active: ACTIVE, suspended: SUSPENDED, archived: ARCHIVED, erasing: ERASING,
    }[state];
    if (typeof address !== "string") continue;
    var before = statusOf(identity, address);
    var read = await identity.accounts.lockoutState({ address: address });
    var released = await identity.accounts.unlock({
      address: address, reason: "the client was sending a stale password" });
    count("the failure budget of a " + state + " mailbox can be read and released, because " +
      "the credential and the status are separate gates",
      read !== null && typeof read.address === "string" && released.address === address,
      JSON.stringify({ read: read && read.address, released: released.address }));
    count("and releasing it left the " + state + " mailbox exactly as it was, so this is " +
      "not a way back into service",
      statusOf(identity, address) === before,
      before + " before, " + String(statusOf(identity, address)) + " after");
  }
}

// Which states come back, and which does not. Reinstate is the only verb
// that reads the category in the other direction, and its answer is the
// one the console renders a button from, so an operator's way back is
// exactly this set.
async function reinstatementReachesTheReversibleStatesAndNoOther(identity) {
  var putBackSuspended = await raisedBy(function () {
    return identity.accounts.reinstate({ id: identity.accounts.get(SUSPENDED).id });
  });
  count("a suspended mailbox comes back into service",
    putBackSuspended === null && statusOf(identity, SUSPENDED) === "active",
    putBackSuspended === null ? String(statusOf(identity, SUSPENDED))
      : String(putBackSuspended.code));

  var putBackArchived = await raisedBy(function () {
    return identity.accounts.reinstate({ id: identity.accounts.get(ARCHIVED).id });
  });
  count("and so does an archived one, because archiving is reversible on purpose: a " +
    "mailbox closed by mistake is a support call rather than a restore",
    putBackArchived === null && statusOf(identity, ARCHIVED) === "active",
    putBackArchived === null ? String(statusOf(identity, ARCHIVED))
      : String(putBackArchived.code));

  var putBackErasing = await raisedBy(function () {
    return identity.accounts.reinstate({ id: identity.accounts.get(ERASING).id });
  });
  count("one part way through an erasure does not, which is the asymmetry every other " +
    "verb in this file is measured against",
    putBackErasing !== null && putBackErasing.code === "store/account-erasing" &&
      statusOf(identity, ERASING) === "erasing",
    putBackErasing === null ? "reinstated" : String(putBackErasing.code));
}

// What an operator sees by default. Archived is the one state left out,
// and the omission is a decision rather than a side effect: the common
// question is which mailboxes are live, and an erasure that could not
// finish is the one state with an outstanding job against it, so leaving
// it out would let an unfinished erasure read as a finished one.
function theDefaultListingLeavesOutArchivedAndNothingElse(identity) {
  var shown = identity.accounts.list({ domain: DOMAIN }).map(function (row) {
    return row.status;
  });
  count("the default listing shows an account part way through an erasure, because it is " +
    "the one state an operator has an outstanding job against",
    shown.indexOf("erasing") !== -1, shown.join(", "));
  count("and it leaves out archived, which is the only state it leaves out",
    shown.indexOf("archived") === -1, shown.join(", "));

  var all = identity.accounts.list({ domain: DOMAIN, includeArchived: true })
    .map(function (row) { return row.status; });
  count("asking for archived rows produces them rather than a second listing verb",
    all.indexOf("archived") !== -1, all.join(", "));
}

// Whether an administrator who cannot sign in counts as one. The console
// refuses to take the role from the last administrator, and the set it
// measures is the set that could still reach these pages: an account out
// of service authenticates nowhere, so counting one would let an
// operator hand the last reachable role away and leave a console nobody
// can open.
async function anAdministratorOutOfServiceIsNotOneTheConsoleCounts(identity, operator) {
  var suspendedAdmin = identity.accounts.get(SUSPENDED_ADMIN);
  count("the run has an administrator whose mailbox is out of service",
    suspendedAdmin !== null && suspendedAdmin.isAdmin === true &&
      suspendedAdmin.status === "suspended",
    JSON.stringify(suspendedAdmin &&
      { isAdmin: suspendedAdmin.isAdmin, status: suspendedAdmin.status }));

  var spare = identity.accounts.get(SPARE_ADMIN);
  var stepBack = await operator.form("/admin/accounts", {
    action: "revoke-role", id: spare.id, reason: "the rota cover has ended" });
  count("the role can be taken from one administrator while another is still able to " +
    "sign in",
    stepBack.status === 302 && adminOf(identity, SPARE_ADMIN) === false,
    stepBack.status + " " + JSON.stringify(adminOf(identity, SPARE_ADMIN)));

  var operatorRow = identity.accounts.get(OPERATOR);
  var lastOne = await operator.form("/admin/accounts", {
    action: "revoke-role", id: operatorRow.id, reason: "stepping back from the rota" });
  count("but the last administrator who can sign in cannot hand the role away, and a " +
    "suspended administrator does not stand in for one",
    lastOne.status === 400 && adminOf(identity, OPERATOR) === true,
    lastOne.status + " " + JSON.stringify(adminOf(identity, OPERATOR)));
  count("and the refusal says what would be left, which is nobody",
    /no administrator/i.test(String(lastOne.body)), String(lastOne.body).slice(0, 400));
}

// ---- what each state is told at the browser door ---------------------------

// The sentence a rendered page carries in its alert, or an empty string.
// Taken off the markup rather than off a handler's return value, because
// the claim is about what an account holder reads.
function alertOn(page) {
  var found = /role="alert"[\s\S]*?<p>([\s\S]*?)<\/p>/.exec(String(page.body || ""));
  return found === null ? "" : found[1].replace(/\s+/g, " ").trim();
}

// The identity layer already answers with the state it refused for, and
// that answer is worth nothing if the page throws it away. Telling an
// account holder their mailbox is held rather than that their password
// is wrong is what saves an operator a support round, and it discloses
// nothing: the state is only reached AFTER the password verified, so an
// address with no account here and a wrong password both end at the same
// generic sentence.
//
// Every state gets a sentence of its own. Two states sharing one is the
// same defect as a state with none, because an account holder reading it
// still cannot tell which hold they are under or who lifts it.
async function theSignInDoorNamesEveryStateItRefusedFor(material, origin) {
  var generic = "";
  var seen = {};
  for (var i = 0; i < OUT_OF_SERVICE.length; i += 1) {
    var state = OUT_OF_SERVICE[i];
    var address = { suspended: SUSPENDED, archived: ARCHIVED, erasing: ERASING }[state];
    if (typeof address !== "string") continue;
    // The suspended subject's password was replaced by the case above,
    // so the credential presented here is whichever one that left behind.
    var secret = address === SUSPENDED ? "a replacement passphrase 2277" : OTHER_PASSWORD;

    // A reader of its own per attempt. One reader carrying a session from
    // a previous attempt would be answering a different question.
    var reader = browser.browserAt(origin, { ca: material.caPem });
    var answer = await reader.signIn(address, secret);
    var said = alertOn(answer);
    seen[state] = said;

    count("the browser door refuses a " + state + " mailbox holding the right password",
      answer.status === 401, answer.status + " " + said);
    count("and it says something about the " + state + " mailbox rather than nothing",
      said.length > 0, JSON.stringify(said));
    count("the account holder is not told their address and password do not match, which " +
      "is the sentence for a credential that is wrong and would send them to reset a " +
      "password that is already right",
      !/do not match an account here/i.test(said), JSON.stringify(said));
    count("and the sentence points at whoever can answer, which is the operator",
      /operator/i.test(said), JSON.stringify(said));
  }

  var sentences = OUT_OF_SERVICE.map(function (state) { return seen[state] || ""; });
  var distinct = sentences.filter(function (text, at) {
    return text.length > 0 && sentences.indexOf(text) === at;
  });
  count("every state that refuses a sign in has a sentence of its own, so an account " +
    "holder can tell which hold they are under",
    distinct.length === OUT_OF_SERVICE.length, JSON.stringify(sentences));
  count("and none of them is the answer for a credential that is simply wrong",
    sentences.every(function (text) { return text !== generic; }) &&
      sentences.every(function (text) { return !/do not match/i.test(text); }),
    JSON.stringify(sentences));
}

// ---- what the console says an act will do ----------------------------------

// The page an operator reads before suspending, which is the only account
// of the act they get. Suspending stops delivery: the routing layer marks
// a suspended account undeliverable and a message already on the wire when
// the suspension lands is not filed. A page saying mail keeps arriving
// sends an operator away believing their mailbox is collecting evidence
// while it is refusing it, which is the opposite of the reason they
// suspended it.
//
// The post carries no reason, so it asks and changes nothing.
async function theSuspendPageSaysWhatSuspendingDoesToDelivery(identity, operator) {
  var subject = identity.accounts.get(ACTIVE);
  var before = statusOf(identity, ACTIVE);
  var asked = await operator.form("/admin/accounts", {
    action: "suspend", id: subject.id });
  var page = String(asked.body || "");

  count("the console asks before suspending and changes nothing on the post that asks",
    statusOf(identity, ACTIVE) === before, before + " before, " +
      String(statusOf(identity, ACTIVE)) + " after");
  count("the page names the account it is about",
    page.indexOf(ACTIVE) !== -1, page.slice(0, 300));
  count("it does not tell the operator that mail addressed to a suspended mailbox is " +
    "still delivered, because the routing layer refuses delivery to one",
    !/still delivered/i.test(page), page.slice(0, 1200));
  count("and it says delivery stops, which is what an operator containing a mailbox " +
    "has to know before they rely on it collecting anything",
    /stops receiving|stops taking|receives nothing|no longer receives|nothing is delivered/i
      .test(page), page.slice(0, 1200));
}

// ---- taking the role back from a mailbox nothing else can reach -------------

// The store allows revocation in every state on purpose, and says why:
// refusing it would strand the role on exactly the accounts nothing else
// can reach to take it off. The console is the only surface that grants
// the role, and the command line names no verb for it by design, so a
// control the console withholds is a revocation nothing can perform.
//
// For a suspended or archived mailbox that leaves one way round, which is
// to reinstate it first and then revoke, and it costs putting a mailbox
// an operator deliberately held back into service to do it. For a mailbox
// part way through an erasure there is no way round at all: reinstatement
// is refused categorically and the row only leaves when the erasure
// finishes.
async function theConsoleTakesTheRoleBackFromAMailboxOutOfService(identity, operator) {
  // The role is put on the rows without going through the verb under
  // test, which is the whole point: these are the states a grant refuses,
  // so the only way a role reaches one of them is a grant that landed
  // while the mailbox was still in service.
  var erasingRow = identity.accounts.get(ERASING);
  tables.updateRow(tables.ACCOUNTS, erasingRow.id, { isAdmin: 1, updatedAt: Date.now() });

  var subjects = [
    { state: "suspended", address: SUSPENDED_ADMIN },
    { state: "erasing",   address: ERASING },
  ];

  var listing = await operator.get("/admin/accounts");
  count("the account list renders for the operator", listing.status === 200,
    String(listing.status));

  for (var i = 0; i < subjects.length; i += 1) {
    var state = subjects[i].state;
    var address = subjects[i].address;
    var row = identity.accounts.get(address);
    count("the run has a " + state + " mailbox carrying the role",
      row !== null && row.isAdmin === true && row.status === state,
      JSON.stringify(row && { isAdmin: row.isAdmin, status: row.status }));

    // The control has to be on the page, because a route that would
    // accept the post is not a way an operator can reach it. The row is
    // located by its own identifier so a control rendered for some other
    // account cannot answer for this one.
    var cell = rowMarkupFor(listing.body, row.id);
    count("the console renders a control that takes the role back from the " + state +
      " mailbox, which is the only surface that can: the command line names no role verb",
      /value="revoke-role"/.test(cell), cell.slice(0, 600));
    count("and it renders no control that would give the role to a " + state + " mailbox, " +
      "which the identity layer refuses",
      !/value="grant-role"/.test(cell), cell.slice(0, 600));

    var taken = await operator.form("/admin/accounts", {
      action: "revoke-role", id: row.id, reason: "the credential was taken" });
    count("taking the role back from the " + state + " mailbox through the console " +
      "succeeds, so the role is not stranded on it",
      taken.status === 302 && adminOf(identity, address) === false,
      taken.status + " " + JSON.stringify(adminOf(identity, address)));
  }
}

// The markup of one account row, located by the identifier the form
// carries. A page-wide match would find a control rendered for any row
// and answer for the wrong account.
function rowMarkupFor(body, id) {
  var rows = String(body || "").split("<tr");
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i].indexOf('value="' + id + '"') !== -1) return rows[i];
  }
  return "";
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("account-state-matrix");
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
    var cfg = config.load({ env: baseEnv(dataDir, material), cwd: root });

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "state matrix run" });

    count("the store declares four account states, which is what this file walks",
      tables.ACCOUNT_STATUS.length === 4 && OUT_OF_SERVICE.length === 3,
      tables.ACCOUNT_STATUS.join(", "));

    await identity.accounts.create({
      address: OPERATOR, password: ADMIN_PASSWORD, isAdmin: true });
    await identity.accounts.create({ address: SPARE_ADMIN, password: OTHER_PASSWORD,
      isAdmin: true });
    await identity.accounts.create({ address: ACTIVE, password: OTHER_PASSWORD });

    var held = await identity.accounts.create({
      address: SUSPENDED, password: OTHER_PASSWORD });
    await identity.accounts.suspend({ id: held.id, reason: "credential reuse reported" });

    var closed = await identity.accounts.create({
      address: ARCHIVED, password: OTHER_PASSWORD });
    await identity.accounts["delete"]({ id: closed.id, reason: "the owner has left" });

    var heldAdmin = await identity.accounts.create({
      address: SUSPENDED_ADMIN, password: OTHER_PASSWORD, isAdmin: true });
    await identity.accounts.suspend({
      id: heldAdmin.id, reason: "credential reuse reported" });

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    // After the server is up, because the erasure walks the mailbox
    // adapter and the composition is what wires the delete path's floor
    // and preservation gate to it.
    await makeErasing(identity, ERASING);

    var bound = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var operator = browser.browserAt(origin, { ca: material.caPem });
    var landed = await operator.signIn(OPERATOR, ADMIN_PASSWORD);
    count("the operator signs in", landed.status === 302,
      landed.status + " " + String(landed.location));

    await theRoleIsNotGrantedToAnyMailboxOutOfService(identity, operator);
    await theRoleIsTakenBackInEveryState(identity);
    await anErasureIsNotArchivedBackIntoService(identity, operator);
    await thePasswordIsReplaceableExactlyWhileTheMailboxIsHeld(identity);
    await aCorrectPasswordIsRefusedInEveryStateOutOfService(identity);
    await theSignInDoorNamesEveryStateItRefusedFor(material, origin);
    await releasingTheFailureBudgetChangesNoStateAnywhere(identity);
    theDefaultListingLeavesOutArchivedAndNothingElse(identity);
    await theSuspendPageSaysWhatSuspendingDoesToDelivery(identity, operator);

    // Ahead of the reinstatement case, which is the one that empties the
    // out-of-service set this file spent every case above filling.
    await anAdministratorOutOfServiceIsNotOneTheConsoleCounts(identity, operator);
    // After the case above, which needs a suspended administrator still
    // holding the role in order to ask whether one counts.
    await theConsoleTakesTheRoleBackFromAMailboxOutOfService(identity, operator);
    await reinstatementReachesTheReversibleStatesAndNoOther(identity);

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
  name: "account-state-matrix", run: run, getChecks: helpers.getChecks,
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
