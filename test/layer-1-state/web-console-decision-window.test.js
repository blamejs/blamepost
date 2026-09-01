// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the operator console decides, and when.
 *
 * Three acts on these pages are decided against a reading and carried
 * out on the far side of a suspension: taking the operator interface
 * away from an account, withdrawing a hosted domain, and cancelling
 * messages off the outbound spool. Every reading taken before a
 * suspension describes the server as it stood rather than as it stands,
 * and each of the three goes wrong in its own way.
 *
 * The claim the first two vectors settle is one sentence: no pair of
 * console requests ends with this server holding no administrator who
 * can sign in. That state is not recoverable from the browser. The
 * console is the only place the role is granted, so once nobody can
 * reach the console there is nothing left to grant it from, and the
 * command line verbs that would undo it open the data volume the
 * running server is holding: the way back begins with stopping every
 * listener and queueing mail at the sending side.
 *
 * The measurement is a statement about a SET, not about the row being
 * changed. Two concurrent revocations each read two administrators and
 * each conclude they are not taking the last one; the row each is about
 * is unchanged in the other, so re-reading it answers a different
 * question. Both cannot be right, and the server they leave has no
 * console.
 *
 * The third is different in kind. Nothing about a stale queue reading is
 * irreversible: the harm is acting on it and then REPORTING the act. A
 * message that leaves the spool while a cancellation is working through
 * the selection gets a row saying it was cancelled and its sender gets a
 * delivery report saying an operator stopped mail that in fact arrived.
 * That report goes to the reverse path, which on mail arriving through a
 * forwarding alias is a value whoever sent the message chose.
 *
 * The interleaving is arranged rather than raced. A run that started two
 * requests and hoped they overlapped would reproduce the failure only
 * sometimes, which is worse than no test at all. Instead one call is
 * wrapped for the length of each vector so that it parks until this file
 * releases it, matched on an argument the vector names, and every other
 * call runs the real primitive untouched. Nothing about the code path
 * changes: the same routes, the same session, the same store, in the
 * same order. Only the moment that one call answers is this file's to
 * choose.
 *
 * Every request is a real form post over a real loopback port with a
 * real operator session, because a handle called directly proves what
 * the handle does and not what the route does.
 *
 * Run standalone: node test/layer-1-state/web-console-decision-window.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";

// Two hosted domains, each holding one administrator. One domain is
// what the domain vectors would have nothing to interleave against:
// withdrawing the only hosted domain is refused before anything
// concurrent is needed.
var DOMAIN       = "example.com";
var OTHER_DOMAIN = "second.example";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ADMIN_PASSWORD   = "an operator passphrase 5512";
var OTHER_PASSWORD   = "another operator passphrase 8841";

// The account holding this run's session, and the second administrator.
// Exactly two, because the fault needs a set of two: a third would leave
// somebody behind whatever the two requests did, and every refusal below
// would be about something else.
var DRIVER = "adam@" + DOMAIN;
var SECOND = "eve@" + OTHER_DOMAIN;

// A mailbox owner administering nothing, so the ordinary-path controls
// have something to move that the guard has no opinion about.
var RESIDENT = "carol@" + DOMAIN;

// How long a parked call may wait for the request that is supposed to
// land inside its window. Generous, because the work landing there opens
// a session, reads sealed rows and writes them back, and a fixed budget
// is what a loaded runner gets wrong.
var PARK_TIMEOUT_MS     = 30000;
var SHUTDOWN_TIMEOUT_MS = 5000;

// The row a cancellation files, under the name the command line files it
// under, because it is the same event whichever surface drove it.
var QUEUE_REMOVED = "blamepost.mail.queue.message_removed";

// The three acts this file examines, printed at the end beside the check
// total. A run that drove one of them and a run that drove all three
// otherwise report the same number and neither says which happened.
var ACTS_EXAMINED = 3;

// Ids in the shape the spool mints, and two senders this server hosts so
// both are written to. Different senders, because the seam below picks
// one report out of the pair by the address it is addressed to.
var FIRST_ID     = "0123456789abcdef0123456789abcdef";
var SECOND_ID    = "fedcba9876543210fedcba9876543210";
var FIRST_SENDER = DRIVER;
var SECOND_SENDER = RESIDENT;
var FIRST_RECIPIENT  = "bob@example.net";
var SECOND_RECIPIENT = "dana@example.net";

var MESSAGE = "From: " + FIRST_SENDER + "\r\nTo: " + FIRST_RECIPIENT + "\r\n" +
  "Subject: waiting to go out\r\n\r\nbody\r\n";

// A resolver that answers no question anybody asks it, so a report this
// console causes gets as far as the outbound spool and stops there. That
// is where the cases below read it, and it keeps every one of them off a
// socket. Refusing rather than answering emptily is deliberate: a domain
// publishing no exchanger is a permanent failure and the report would
// end rather than wait.
var UNANSWERING = {
  queryMx:   function () { return Promise.reject(new Error("no resolver in this test")); },
  queryTxt:  function () { return Promise.reject(new Error("no resolver in this test")); },
  queryTlsa: function () { return Promise.reject(new Error("no resolver in this test")); },
};

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

// One method on one handle, wrapped so a single call parks. Every call
// the vector did not ask for runs the real primitive and answers with
// exactly what it answered before, so the request that lands inside the
// window does its own work exactly as it would in production.
//
// The wrapper stands on the handle the server was built with, which is
// the same object the console holds, so the route reaches it without
// knowing anything happened.
function installCallGate(holder, name, wanted) {
  var real  = holder[name];
  var state = { parked: null, calls: [] };
  holder[name] = function () {
    var args = Array.prototype.slice.call(arguments);
    state.calls.push(args);
    if (state.parked !== null || !wanted(args)) return real.apply(holder, args);
    return new Promise(function (resolve, reject) {
      state.parked = { args: args, resolve: resolve, reject: reject };
    });
  };
  state.release = function () {
    var held = state.parked;
    if (held === null) throw new Error("installCallGate: nothing is parked to release");
    return Promise.resolve(real.apply(holder, held.args)).then(held.resolve, held.reject);
  };
  state.remove = function () { holder[name] = real; };
  return state;
}

// Park until the request under test has actually reached the seam,
// rather than after a budget somebody guessed at.
function parked(gate, label) {
  return helpers.waitUntil(function () { return gate.parked !== null; }, {
    timeoutMs: PARK_TIMEOUT_MS,
    label:     "web-console-decision-window: " + label,
  });
}

// ---------------------------------------------------------------------------
// Readings
// ---------------------------------------------------------------------------

// The claim, as a reading. Who could sign in and reach the console as
// things stand, decided the way `authenticate` decides it: the account
// is active and the domain it belongs to is active too.
function administratorsAbleToSignIn(identity) {
  var live = Object.create(null);
  var domains = identity.domains.list({ status: "active" });
  for (var d = 0; d < domains.length; d += 1) live[domains[d].domain] = true;
  var accounts = identity.accounts.list({ status: "active" });
  var out = [];
  for (var a = 0; a < accounts.length; a += 1) {
    if (accounts[a].isAdmin !== true) continue;
    if (live[accounts[a].domain] !== true) continue;
    out.push(accounts[a].address);
  }
  return out.sort();
}

function statusOfDomain(identity, name) {
  var row = identity.domains.get(name);
  return row === null ? "(absent)" : row.status;
}

function noticeOf(answer) {
  var location = String(answer.location || "");
  var at = location.indexOf("notice=");
  return at === -1 ? "" : location.slice(at + "notice=".length).split("&")[0];
}

function spoolPath(dataDir, name) { return nodePath.join(dataDir, "queue", name); }

// One entry on the spool, written the way the spool writes it. Planting
// the pair rather than driving a send keeps the run off the network and
// keeps the ids known, which is what the assertions below name. The next
// attempt is an hour out so the sweep leaves both alone and every change
// to the spool in this file is one this file made.
function plant(dataDir, id, from, recipient) {
  nodeFs.mkdirSync(nodePath.join(dataDir, "queue"), { recursive: true });
  nodeFs.writeFileSync(spoolPath(dataDir, id + ".eml"), MESSAGE, "utf8");
  nodeFs.writeFileSync(spoolPath(dataDir, id + ".json"), JSON.stringify({
    id:               id,
    from:             from,
    recipient:        recipient,
    attempt:          1,
    nextAttemptAt:    Date.now() + 3600000,
    reason:           "451 4.7.0 the receiver asked for this to be tried later",
    reasonCode:       "4.7.0",
    requireTls:       false,
    queuedAt:         Date.now(),
    attemptsRecorded: 1,
    history:          [],
  }, null, 2), "utf8");
}

function spooled(dataDir, id) {
  return nodeFs.existsSync(spoolPath(dataDir, id + ".json")) ||
         nodeFs.existsSync(spoolPath(dataDir, id + ".eml"));
}

// Who a cancellation actually wrote to, read off the outbound spool.
//
// The report is composed inside the queue's own removal verb, which is
// where the decision about telling a sender is stated and enforced, so
// there is nothing above it to intercept. The spool is where the report
// stops: the resolver this server was built with answers no question, so
// a report is queued and never attempted, and nothing in this file
// reaches a socket.
//
// A report carries the empty reverse path, which is what tells one apart
// from the ordinary mail the fixtures plant.
function reportsOn(dataDir) {
  var dir = nodePath.join(dataDir, "queue");
  if (!nodeFs.existsSync(dir)) return [];
  return nodeFs.readdirSync(dir)
    .filter(function (name) { return name.slice(-5) === ".json"; })
    .map(function (name) {
      try {
        return JSON.parse(nodeFs.readFileSync(nodePath.join(dir, name), "utf8"));
      } catch (_e) {
        return null;
      }
    })
    .filter(function (entry) { return entry !== null && entry.from === ""; });
}

function reportsTo(dataDir, address) {
  return reportsOn(dataDir).filter(function (entry) { return entry.recipient === address; });
}

// A message leaving the spool the way a delivered one leaves it: the
// body and the descriptor gone, with nothing else told.
function leavesTheSpool(dataDir, id) {
  nodeFs.rmSync(spoolPath(dataDir, id + ".eml"), { force: true });
  nodeFs.rmSync(spoolPath(dataDir, id + ".json"), { force: true });
}

function _asRows(value) { return Array.isArray(value) ? value : []; }

async function rowsFor(id) {
  await b.audit.flush();
  var rows = _asRows(await b.audit.query({ action: QUEUE_REMOVED, order: "desc", limit: 100 }));
  return rows.filter(function (row) { return row.resourceId === id; });
}

// ---------------------------------------------------------------------------
// Taking the operator interface away
// ---------------------------------------------------------------------------

// The ordinary path, so the refusal below reads as the window closing
// rather than as the console refusing every revocation it is shown. A
// mailbox owner who holds the role while two other administrators remain
// gives it up without argument.
async function anUncontestedRevocationStillLands(operator, identity) {
  var resident = identity.accounts.get(RESIDENT);
  await identity.accounts.setAdmin({
    id: resident.id, isAdmin: true, reason: "so there is a third role to take back" });
  count("a third account holds the operator interface",
    administratorsAbleToSignIn(identity).length === 3,
    administratorsAbleToSignIn(identity).join(", "));

  var answer = await operator.form("/admin/accounts", {
    action: "revoke-role", id: resident.id, reason: "the ordinary path, uncontested",
  });
  count("an uncontested revocation lands", answer.status === 302 &&
    noticeOf(answer) === "role-revoked",
    answer.status + " " + String(answer.location));
  count("and the account it named no longer administers this server",
    identity.accounts.get(RESIDENT).isAdmin !== true,
    JSON.stringify(identity.accounts.get(RESIDENT).isAdmin));
}

// Two revocations, one of each half of the only pair of administrators
// this server has. Each reads two and concludes it is not taking the
// last. Both cannot be right, and the server they would leave has no
// console anybody can reach.
async function twoRevocationsCannotBothTakeTheLastAdministrator(operator, identity) {
  var driver = identity.accounts.get(DRIVER);
  var second = identity.accounts.get(SECOND);
  count("this server holds exactly two administrators who can sign in",
    administratorsAbleToSignIn(identity).length === 2,
    administratorsAbleToSignIn(identity).join(", "));

  var gate = installCallGate(identity.accounts, "get", function (args) {
    return args[0] === second.id;
  });
  var first;
  try {
    var started = operator.form("/admin/accounts", {
      action: "revoke-role", id: second.id, reason: "withdrawn by one operator",
    });
    var caught = started.then(function (r) { return r; }, function (e) { return e; });
    await parked(gate, "the first revocation reaching the row it names");

    // The second request runs to completion inside the first one's
    // window. It reads two administrators, exactly as the first one did,
    // and takes the other half.
    var other = await operator.form("/admin/accounts", {
      action: "revoke-role", id: driver.id, reason: "withdrawn by another operator",
    });
    count("the second revocation completes while the first is still resolving its row",
      other.status === 302 && noticeOf(other) === "role-revoked",
      other.status + " " + String(other.location));

    await gate.release();
    first = await caught;
  } finally {
    gate.remove();
  }

  count("the first revocation is answered rather than taking the last administrator",
    first && first.status !== undefined && noticeOf(first) !== "role-revoked",
    (first && first.status) + " " + String(first && first.location));

  var left = administratorsAbleToSignIn(identity);
  count("so this server is left with an administrator who can still sign in",
    left.length >= 1, left.join(", ") || "(none)");

  // Put the pair back, because every vector after this one needs a
  // console to drive.
  await identity.accounts.setAdmin({
    id: driver.id, isAdmin: true, reason: "restoring the pair the vector took apart" });
  await identity.accounts.setAdmin({
    id: second.id, isAdmin: true, reason: "restoring the pair the vector took apart" });
}

// ---------------------------------------------------------------------------
// Withdrawing a hosted domain
// ---------------------------------------------------------------------------

// The ordinary path again. A domain holding no administrator is
// withdrawn without argument, so the refusal below is about what would
// be left rather than about withdrawing anything at all.
async function anUncontestedWithdrawalStillLands(operator, identity) {
  var name = "spare.example";
  await identity.domains.add({ domain: name });
  var answer = await operator.form("/admin/domains", {
    action: "disable", domain: name, confirm: name,
    reason: "the ordinary path, uncontested",
  });
  count("an uncontested withdrawal lands", answer.status === 302 &&
    noticeOf(answer) === "domain-saved",
    answer.status + " " + String(answer.location));
  count("and the domain it named stops taking mail",
    statusOfDomain(identity, name) === "disabled", statusOfDomain(identity, name));

  await identity.domains.setStatus({
    domain: name, status: "active", reason: "putting the control back" });
}

// Two withdrawals, one of each domain an administrator's address belongs
// to. Each reads the other domain's administrator and concludes somebody
// is left. Both cannot be right: `authenticate` refuses an account whose
// domain is withdrawn, so the console they would leave refuses every
// credential it holds.
async function twoWithdrawalsCannotBothStrandTheConsole(operator, identity) {
  count("each hosted domain the vector names holds one administrator",
    administratorsAbleToSignIn(identity).length === 2,
    administratorsAbleToSignIn(identity).join(", "));

  // The count the confirmation page reads, which is the one call between
  // the measurement and the write. Matched on the argument that tells it
  // apart from the measurement's own read of the same table.
  var gate = installCallGate(identity.accounts, "list", function (args) {
    return Boolean(args[0]) && args[0].includeArchived === true;
  });
  var first;
  try {
    var started = operator.form("/admin/domains", {
      action: "disable", domain: DOMAIN, confirm: DOMAIN,
      reason: "withdrawn by one operator",
    });
    var caught = started.then(function (r) { return r; }, function (e) { return e; });
    await parked(gate, "the first withdrawal reaching the count its page names");

    var other = await operator.form("/admin/domains", {
      action: "disable", domain: OTHER_DOMAIN, confirm: OTHER_DOMAIN,
      reason: "withdrawn by another operator",
    });
    count("the second withdrawal completes while the first is still counting",
      other.status === 302 && noticeOf(other) === "domain-saved",
      other.status + " " + String(other.location));

    await gate.release();
    first = await caught;
  } finally {
    gate.remove();
  }

  count("the first withdrawal is answered rather than taking the console with it",
    first && noticeOf(first) !== "domain-saved",
    (first && first.status) + " " + String(first && first.location));

  var left = administratorsAbleToSignIn(identity);
  count("so an administrator can still sign in",
    left.length >= 1, left.join(", ") || "(none)");
  count("and the domain that was refused still takes mail",
    statusOfDomain(identity, DOMAIN) === "active", statusOfDomain(identity, DOMAIN));

  await identity.domains.setStatus({
    domain: OTHER_DOMAIN, status: "active", reason: "restoring what the vector withdrew" });
}

// ---------------------------------------------------------------------------
// Cancelling messages off the outbound spool
// ---------------------------------------------------------------------------

// A selection of two, where the second leaves the spool while the first
// one's delivery report is being written. Nothing can be done about the
// message: it has gone. What must not happen is this server telling its
// sender that an operator stopped it, and filing a row saying it was
// erased.
async function aMessageThatLeavesMidCancellationIsNotReportedAsCancelled(
  operator, identity, dataDir, delivery
) {
  count("both messages are waiting on the spool",
    spooled(dataDir, FIRST_ID) && spooled(dataDir, SECOND_ID),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
  count("and both carry a sender this server hosts, so both would be written to",
    identity.domains.get(DOMAIN) !== null, FIRST_SENDER + ", " + SECOND_SENDER);

  // Counted against what this case adds rather than against an empty
  // spool. A report queued by an earlier case is still on the volume,
  // and an assertion written as a total would read one of those as this
  // cancellation's own.
  var toFirstBefore  = reportsTo(dataDir, FIRST_SENDER).length;
  var toSecondBefore = reportsTo(dataDir, SECOND_SENDER).length;

  // Parked on the removal rather than on the report, because that is
  // where the window is now: erasing the message and writing to its
  // sender are one call, so the suspension the selection has to survive
  // is the one that call takes.
  var gate = installCallGate(delivery.queue, "remove", function (args) {
    return args[0] === FIRST_ID;
  });
  var answer;
  try {
    var started = operator.form("/admin/queue", {
      action: "cancel", id: [FIRST_ID, SECOND_ID], confirm: "2",
      reason: "the sender asked for these to be pulled back",
    });
    var caught = started.then(function (r) { return r; }, function (e) { return e; });
    await parked(gate, "the cancellation reaching the first message's removal");

    leavesTheSpool(dataDir, SECOND_ID);
    count("the second message leaves the spool while the first one is being cancelled",
      !spooled(dataDir, SECOND_ID),
      JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));

    await gate.release();
    answer = await caught;
  } finally {
    gate.remove();
  }

  count("the sender of the message that left is NOT told an operator cancelled it",
    reportsTo(dataDir, SECOND_SENDER).length === toSecondBefore,
    JSON.stringify(reportsOn(dataDir).map(function (e) { return e.recipient; })));

  var rows = await rowsFor(SECOND_ID);
  var claimed = rows.filter(function (row) { return row.outcome === "success"; });
  count("and nothing is filed claiming that message was erased",
    claimed.length === 0, JSON.stringify(rows.map(function (r) { return r.outcome; })));

  count("the message that was still waiting is off the volume",
    !spooled(dataDir, FIRST_ID),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
  var firstRows = await rowsFor(FIRST_ID);
  count("and its own row says it was cancelled",
    firstRows.some(function (row) { return row.outcome === "success"; }),
    JSON.stringify(firstRows.map(function (r) { return r.outcome; })));
  count("and its sender was told",
    reportsTo(dataDir, FIRST_SENDER).length === toFirstBefore + 1,
    JSON.stringify(reportsOn(dataDir).map(function (e) { return e.recipient; })));

  count("and the operator is told plainly that not all of the selection was cancelled",
    noticeOf(answer) !== "queue-cancelled" && noticeOf(answer) !== "",
    (answer && answer.status) + " " + String(answer && answer.location));
}

// The ordinary path, so the vector above reads as the window closing
// rather than as the page refusing to cancel anything.
async function anUncontestedCancellationStillErasesTheMessage(operator, dataDir) {
  var id = "abcdef0123456789abcdef0123456789";
  plant(dataDir, id, FIRST_SENDER, "erin@example.net");
  var answer = await operator.form("/admin/queue", {
    action: "cancel", id: id, confirm: "1",
    reason: "the ordinary path, uncontested",
  });
  count("an uncontested cancellation reports that the message was cancelled",
    noticeOf(answer) === "queue-cancelled",
    answer.status + " " + String(answer.location));
  count("and the message is off the volume", !spooled(dataDir, id),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
}

// The same act against a volume that will not give the message up. No
// reading is stale here and nothing raced: the message was waiting when
// the page listed it, it was waiting when the operator confirmed, and
// the erasure did not happen. What the page says next is a claim about a
// volume nothing changed, so an operator working through a compromised
// account's outbound mail is told the message was stopped while the
// sweep goes on retrying it, and its sender is written to about mail
// that is still going out.
async function aCancellationTheVolumeRefusesIsNotReportedAsCancelled(operator, dataDir) {
  var id = "9876543210fedcba9876543210fedcba";
  plant(dataDir, id, FIRST_SENDER, "frank@example.net");

  var before = reportsOn(dataDir).length;
  var fault = helpers.installRemovalFault(id + ".");
  var answer;
  try {
    answer = await operator.form("/admin/queue", {
      action: "cancel", id: id, confirm: "1",
      reason: "the sender asked for this to be pulled back",
    });
  } finally {
    fault.remove();
  }

  count("the message is still on the volume, because the removal did not happen",
    spooled(dataDir, id),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
  count("the operator is answered rather than shown a fault",
    answer.status >= 200 && answer.status < 500,
    answer.status + " " + String(answer.location));
  count("and is not told the message was cancelled",
    noticeOf(answer) !== "queue-cancelled", answer.status + " " + String(answer.location));
  count("its sender is not written to about mail that is still going out",
    reportsOn(dataDir).length === before,
    JSON.stringify(reportsOn(dataDir).map(function (e) { return e.recipient; })));

  var rows = await rowsFor(id);
  var claimed = rows.filter(function (row) { return row.outcome === "success"; });
  count("and nothing is filed claiming it was erased", claimed.length === 0,
    JSON.stringify(rows.map(function (r) { return r.outcome; })));
  count("while the attempt itself is on the trail, because an operator reached for it during " +
    "an incident",
    rows.length >= 1, JSON.stringify(rows.map(function (r) { return r.outcome; })));
}

// The third answer, and the only one where the message is past saving.
// The volume gives up the message and then keeps the file that lists it,
// so what is left is an entry the queue still shows for a message that
// can never be sent. Its sender was not written to and cannot be: the
// text a report would quote is off the volume.
//
// What the operator is told has to differ from both answers above, and
// the reason is not presentational. Both of those end with "reload the
// queue and read what is still listed", and that reading is exactly the
// one that is wrong here: the entry IS still listed, and it is not a
// message waiting to go out. An operator who reads it as a cancellation
// to repeat clears the fault, cancels again, and takes the remainder,
// believing they stopped a message that this server destroyed some time
// earlier without telling anybody.
//
// It takes two faults because one is not enough, and that is the shape
// of the state rather than an artifact of the fixture. A removal that
// keeps the descriptor and successfully puts the message back destroyed
// nothing after all, which is the refusal above. Only a volume that
// will not take the message back leaves the pair half gone.
async function aCancellationThatDestroysTheMessageAndKeepsTheEntrySaysSo(operator, dataDir) {
  var id = "13579bdf02468ace13579bdf02468ace";
  plant(dataDir, id, FIRST_SENDER, "grace@example.net");

  var before = reportsOn(dataDir).length;
  var keptEntry  = helpers.installRemovalFault(id + ".json");
  var noPutBack  = helpers.installWriteFault(id + ".eml");
  var answer;
  try {
    answer = await operator.form("/admin/queue", {
      action: "cancel", id: id, confirm: "1",
      reason: "the sender asked for this to be pulled back",
    });
  } finally {
    noPutBack.remove();
    keptEntry.remove();
  }

  count("the volume gave the message up and kept the file that lists it",
    !nodeFs.existsSync(spoolPath(dataDir, id + ".eml")) &&
      nodeFs.existsSync(spoolPath(dataDir, id + ".json")),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "queue"))));
  count("and it refused the write that would have put the message back",
    noPutBack.attempts.length >= 1, JSON.stringify(noPutBack.attempts));

  count("the operator is answered rather than shown a fault",
    answer.status >= 200 && answer.status < 500,
    answer.status + " " + String(answer.location));
  count("and is told the message was destroyed in part, which is neither of the two answers " +
    "that end in reloading the queue",
  noticeOf(answer) === "queue-part-destroyed",
  answer.status + " " + String(answer.location));

  count("its sender is not written to, because the message a report would quote is off the " +
    "volume",
  reportsOn(dataDir).length === before,
  JSON.stringify(reportsOn(dataDir).map(function (e) { return e.recipient; })));

  var rows = await rowsFor(id);
  var claimed = rows.filter(function (row) { return row.outcome === "success"; });
  count("nothing is filed claiming the message was cancelled", claimed.length === 0,
    JSON.stringify(rows.map(function (r) { return r.outcome; })));
  count("while the attempt itself is on the trail, because this is the state somebody has to " +
    "go and look at",
  rows.length >= 1, JSON.stringify(rows.map(function (r) { return r.outcome; })));
}

// ---------------------------------------------------------------------------

async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = { enabled: false, port: await wire.reservePort(), address: LOOPBACK };
  }
  return sections;
}

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

async function run() {
  var root    = helpers.tempDir("web-console-decision-window");
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
    await identity.domains.add({ domain: OTHER_DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "console decision window run" });
    await identity.domains.acknowledgeDns({
      domain: OTHER_DOMAIN, by: "console decision window run" });

    var driver = await identity.accounts.create({
      address: DRIVER, password: ADMIN_PASSWORD, isAdmin: true });
    await identity.accounts.create({
      address: SECOND, password: OTHER_PASSWORD, isAdmin: true });
    await identity.accounts.create({ address: RESIDENT, password: OTHER_PASSWORD });

    plant(dataDir, FIRST_ID, FIRST_SENDER, FIRST_RECIPIENT);
    plant(dataDir, SECOND_ID, SECOND_SENDER, SECOND_RECIPIENT);

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
      resolver:     UNANSWERING,
    });
    await server.start();
    running = true;

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;
    var operator = browser.browserAt(origin, { ca: material.caPem });
    var landed = await operator.signIn(driver.address, ADMIN_PASSWORD);
    count("the operator signs in", landed.status === 302,
      landed.status + " " + String(landed.location));

    await anUncontestedWithdrawalStillLands(operator, identity);
    await twoWithdrawalsCannotBothStrandTheConsole(operator, identity);

    await anUncontestedRevocationStillLands(operator, identity);
    await twoRevocationsCannotBothTakeTheLastAdministrator(operator, identity);

    await anUncontestedCancellationStillErasesTheMessage(operator, dataDir);
    await aCancellationTheVolumeRefusesIsNotReportedAsCancelled(operator, dataDir);
    await aCancellationThatDestroysTheMessageAndKeepsTheEntrySaysSo(operator, dataDir);
    await aMessageThatLeavesMidCancellationIsNotReportedAsCancelled(
      operator, identity, dataDir, server.mail.delivery);

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
  name:      "web-console-decision-window",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// console act and a run that drove all three otherwise report the same
// total and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + ACTS_EXAMINED + " console-act");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
