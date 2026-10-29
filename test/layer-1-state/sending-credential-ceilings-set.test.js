// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Changing a sending credential's ceilings after it has been issued,
 * driven on a real encrypted store.
 *
 * The wire refusal a credential meets at a ceiling advises two acts:
 * raise the ceiling, or give the window back. `counters.release` is the
 * second. This file drives the first, and the part of it that is easy to
 * ship broken is not the arithmetic.
 *
 * Three things can go wrong in a way nothing reports:
 *
 *   - The write breaks the credential. Both ceilings and the window are
 *     fields the row-binding digest is taken over, so a policy write
 *     that does not recompute that digest leaves a credential that
 *     refuses every message under `binding-mismatch`, which reads as a
 *     tampered row rather than as the operator's own edit.
 *   - The new ceiling is never read. The counters are measured against
 *     numbers taken off the row on every count, so a raise has to reach
 *     the next message with nothing restarted. A cached ceiling would
 *     pass every read-back assertion and refuse the message anyway.
 *   - The window LENGTH moves under counts taken at the old length. The
 *     counters are kept as slices of the window, so a widened window
 *     reads slices that should have rolled off as current volume and a
 *     narrowed one drops volume that should still hold. Neither surfaces
 *     as an error: the numbers are simply wrong afterwards, in the
 *     direction that either refuses an application that is inside its
 *     allowance or admits one that is past it.
 *
 * Two hosted domains, because the audit row this files names the domain
 * the credential speaks for and a row naming the wrong one is right on a
 * server that hosts a single domain.
 *
 * Run standalone: node test/layer-1-state/sending-credential-ceilings-set.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;
var b           = require("../../lib/vendor/blamejs");
var config      = require("../../lib/config");
var store       = require("../../lib/store");
var credentials = require("../../lib/store/credentials");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALPHA = "alpha.example";
var ZULU  = "zulu.example";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The window every case below starts on, and the length it is moved to.
// An hour and two hours rather than two arbitrary numbers: the slices
// are a sixtieth of the window, so doubling the length doubles the slice
// width, which is what makes a key written at the old length land
// somewhere else at the new one.
var HOUR_MS     = b.constants.TIME.hours(1);
var TWO_HOURS_MS = b.constants.TIME.hours(2);

// Assert a call refuses under one stable code. Both halves matter: a
// refusal under the wrong code is a contract change a caller branching
// on the code would not survive.
async function refuses(label, code, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  count(label,
    thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);
}

// The same assertion plus the fragments the message has to carry, for a
// refusal whose whole job is to tell an operator what to do next.
async function refusesNaming(label, code, needles, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  var message = thrown === null ? "" : String(thrown.message);
  var missing = needles.filter(function (n) { return message.indexOf(n) === -1; });
  count(label,
    thrown !== null && thrown.code === code && missing.length === 0,
    thrown === null ? "nothing was thrown"
      : thrown.code + " missing " + JSON.stringify(missing) + " in: " + message);
}

// A clock the ceiling window is measured on, moved by this file rather
// than by waiting. It is the same kind of function the shipped assembly
// passes, so what runs is the shipped code with a different time source.
function movableClock(startMs) {
  var at = startMs;
  var fn = function () { return at; };
  fn.advance = function (ms) { at += ms; };
  return fn;
}

function registryFor(handle, clock) {
  return credentials.create({
    domains:  handle.domains,
    accounts: handle.accounts,
    aliases:  handle.aliases,
    resolve:  handle.resolve,
    clock:    clock,
  });
}

async function seed(handle) {
  await handle.domains.add({ domain: ALPHA });
  await handle.domains.add({ domain: ZULU });
  await handle.accounts.create({
    address: "bounces@" + ALPHA, password: ACCOUNT_PASSWORD });
  await handle.accounts.create({
    address: "bounces@" + ZULU, password: ACCOUNT_PASSWORD });
}

function issue(reg, domain, opts) {
  return reg.create(Object.assign({
    domain:        domain,
    bounceMailbox: "bounces@" + domain,
    reason:        "a credential for the ceiling verb to move",
  }, opts || {}));
}

// ---- what the verb refuses ------------------------------------------------

async function testRefusals(reg) {
  var made = await issue(reg, ALPHA, {
    maxMessages: 10, maxRecipients: 50, windowMs: HOUR_MS });

  await refuses("blamepost.store.credentials.setCeilings refuses without a reason",
    "store/bad-argument", function () {
      return reg.setCeilings({ id: made.id, maxMessages: 20 });
    });

  await refusesNaming("and refuses a call that names none of the three, because it would " +
    "file an operator action in the trail that never happened",
    "store/bad-argument", ["at least one of maxMessages"], function () {
      return reg.setCeilings({ id: made.id, reason: "naming nothing at all" });
    });

  await refuses("and refuses an identifier no credential on this volume carries",
    "store/no-such-sending-credential", function () {
      return reg.setCeilings({
        id: "0123456789abcdef", maxMessages: 20, reason: "an identifier nobody holds" });
    });

  await refuses("and refuses a message ceiling of zero, which would be a credential stopped " +
    "by a number rather than by a revocation",
    "store/bad-argument", function () {
      return reg.setCeilings({ id: made.id, maxMessages: 0, reason: "zero" });
    });

  await refuses("and refuses a ceiling past the largest one this registry writes, because a " +
    "number past it is not a ceiling",
    "store/bad-argument", function () {
      return reg.setCeilings({
        id: made.id, maxRecipients: credentials.MAX_CEILING + 1, reason: "past the bound" });
    });

  await refuses("and refuses a fractional ceiling",
    "store/bad-argument", function () {
      return reg.setCeilings({ id: made.id, maxMessages: 20.5, reason: "half a message" });
    });

  await refuses("and refuses a window shorter than the shortest one this registry measures",
    "store/bad-argument", function () {
      return reg.setCeilings({
        id: made.id, windowMs: credentials.MIN_WINDOW_MS - 1, reason: "too short" });
    });

  await refuses("and refuses a window longer than the longest one",
    "store/bad-argument", function () {
      return reg.setCeilings({
        id: made.id, windowMs: credentials.MAX_WINDOW_MS + 1, reason: "too long" });
    });

  var after = await reg.counters.read(made.id);
  count("and every one of those refusals left the credential's ceilings where they were",
    after.maxMessages === 10 && after.maxRecipients === 50 && after.windowMs === HOUR_MS,
    JSON.stringify(after));
}

// ---- a raise reaches the next message -------------------------------------
//
// The point of the verb. A raise that is stored and never read is the
// shape the wire refusal advises and the server does not perform.

async function testARaiseReachesTheNextMessage(reg) {
  var made = await issue(reg, ALPHA, {
    maxMessages: 2, maxRecipients: 100, windowMs: HOUR_MS });

  await reg.counters.record({ id: made.id, recipients: 1 });
  var second = await reg.counters.record({ id: made.id, recipients: 1 });
  count("a credential set to two messages lets the second through",
    second.exceeded === false, JSON.stringify(second));
  var atCeiling = await reg.counters.read(made.id);
  count("and its window then reads at the ceiling",
    atCeiling.exceeded === true && atCeiling.messagesExceeded === true,
    JSON.stringify(atCeiling));

  await reg.setCeilings({
    id: made.id, maxMessages: 5, reason: "the run was checked and is the application's" });

  var afterRaise = await reg.counters.read(made.id);
  count("raising the message ceiling leaves what was already sent counted",
    afterRaise.messages === 2, JSON.stringify(afterRaise));
  count("and the credential is inside the new ceiling with nothing restarted",
    afterRaise.exceeded === false && afterRaise.maxMessages === 5,
    JSON.stringify(afterRaise));

  var next = await reg.counters.record({ id: made.id, recipients: 1 });
  count("and the next message is measured against the ceiling that was just set, which is " +
    "the whole of what the wire refusal advises",
    next.exceeded === false && next.messages === 3, JSON.stringify(next));

  // The other direction. An operator holding a credential down during an
  // incident is asking for exactly this, so it is a supported answer
  // rather than an accident of the bound being two-sided.
  await reg.setCeilings({
    id: made.id, maxMessages: 3, reason: "holding it down while the traffic is looked at" });
  var held = await reg.counters.read(made.id);
  count("a ceiling set below what the window already holds refuses the next message",
    held.exceeded === true && held.messagesExceeded === true, JSON.stringify(held));

  // The recipient ceiling answers separately, which is the half a single
  // counter cannot see.
  await reg.setCeilings({
    id: made.id, maxMessages: 100, maxRecipients: 4,
    reason: "the fan-out is what is being bounded, not the message count" });
  var fanOut = await reg.counters.record({ id: made.id, recipients: 40 });
  count("and the recipient ceiling set on the same call is what the fan-out is measured " +
    "against",
    fanOut.recipientsExceeded === true && fanOut.messagesExceeded === false,
    JSON.stringify(fanOut));
}

// ---- the credential still works afterwards --------------------------------
//
// Both ceilings and the window are fields the row-binding digest is taken
// over. A write that stored the numbers without recomputing that digest
// would leave a credential refusing every message under
// `binding-mismatch`, which an operator reads as somebody having edited
// the volume.

async function testTheCredentialStillVerifies(reg) {
  var made = await issue(reg, ZULU, {
    maxMessages: 10, maxRecipients: 50, windowMs: HOUR_MS });

  await reg.setCeilings({
    id: made.id, maxMessages: 7, maxRecipients: 99,
    reason: "moving both halves in one call" });

  var verdict = await reg.verify(made.token);
  count("a credential whose ceilings were changed still verifies, so the write recomputed " +
    "the binding the row carries rather than leaving one that reads as a tampered row",
    verdict.ok === true, JSON.stringify({ ok: verdict.ok, reason: verdict.reason }));
  count("and the verify hands back the ceilings that were set",
    verdict.maxMessages === 7 && verdict.maxRecipients === 99,
    verdict.maxMessages + "/" + verdict.maxRecipients);

  var standing = await reg.stillSending(made.id);
  count("and it is still one this server sends for",
    standing.ok === true, JSON.stringify(standing));

  var shown = await reg.show(made.id);
  count("and the operator-facing read agrees with the wire about what it may send",
    shown.bindingHolds === true && shown.maxMessages === 7 && shown.maxRecipients === 99,
    JSON.stringify({ holds: shown.bindingHolds, m: shown.maxMessages, r: shown.maxRecipients }));
  count("and the refusal list and the bounce mailbox came through the write untouched",
    shown.bounceMailbox === "bounces@" + ZULU &&
      shown.refusedLocalParts.indexOf("postmaster") !== -1,
    JSON.stringify({ bounce: shown.bounceMailbox, refused: shown.refusedLocalParts }));
}

// Both verbs replace the whole policy row, so two of them sent together
// for one credential each read it, and the later write would carry the
// earlier read. They run one at a time per credential, so both changes
// land whichever finishes first.
async function testARefusalChangeAndACeilingChangeBothLand(reg) {
  var made = await issue(reg, ZULU, {
    maxMessages: 10, maxRecipients: 50, windowMs: HOUR_MS });
  var before = await reg.show(made.id);
  var wanted = before.refusedLocalParts.concat(["support-replies"]);

  await Promise.all([
    reg.setRefusedLocalParts({ id: made.id, localParts: wanted,
      reason: "this mailbox answers on its own" }),
    reg.setCeilings({ id: made.id, maxMessages: 4,
      reason: "a lower ceiling while the list is changing" }),
  ]);

  var shown = await reg.show(made.id);
  count("a refusal change and a ceiling change sent together for one credential both land",
    shown.maxMessages === 4 && shown.refusedLocalParts.indexOf("support-replies") !== -1,
    JSON.stringify({ m: shown.maxMessages, refused: shown.refusedLocalParts }));
  var verdict = await reg.verify(made.token);
  count("and the credential still verifies after both writes", verdict.ok === true,
    JSON.stringify({ ok: verdict.ok, reason: verdict.reason }));
}

// ---- the window length, and the counts taken at the old one ---------------

async function testTheWindowLengthWaitsForTheWindow(reg, clock) {
  var made = await issue(reg, ALPHA, {
    maxMessages: 100, maxRecipients: 100, windowMs: HOUR_MS });

  await reg.counters.record({ id: made.id, recipients: 3 });

  await refusesNaming("changing the window length while the window still holds volume is " +
    "refused, because a count taken at one length is misread at another",
    "store/sending-credential-window-in-use",
    ["1 message(s) to 3 recipient(s)", "Give the window back first"], function () {
      return reg.setCeilings({
        id: made.id, windowMs: TWO_HOURS_MS, reason: "widening it mid-incident" });
    });

  var unmoved = await reg.counters.read(made.id);
  count("and the refusal left the length and the counts exactly as they were, rather than " +
    "moving one of them",
    unmoved.windowMs === HOUR_MS && unmoved.messages === 1 && unmoved.recipients === 3,
    JSON.stringify(unmoved));

  // The two ceilings are not the window, so they move while it holds
  // volume. Refusing them here would make the verb useless during the
  // only incident anybody reaches for it in.
  await reg.setCeilings({
    id: made.id, maxMessages: 7,
    reason: "the ceilings move while the window holds, because the slices do not depend " +
      "on them" });
  var moved = await reg.counters.read(made.id);
  count("while a ceiling moves with volume in the window, because a ceiling is a comparison " +
    "and the slices do not depend on it",
    moved.maxMessages === 7 && moved.messages === 1 && moved.windowMs === HOUR_MS,
    JSON.stringify(moved));

  // Give the window back, which is the act the refusal names, and the
  // length then moves.
  await reg.counters.release({ id: made.id, reason: "giving the window back before widening" });
  await reg.setCeilings({
    id: made.id, windowMs: TWO_HOURS_MS, reason: "the application bursts on a two-hour cycle" });
  var widened = await reg.counters.read(made.id);
  count("giving the window back is what lets the length move, which is the act the refusal " +
    "names",
    widened.windowMs === TWO_HOURS_MS, JSON.stringify(widened));
  count("and the widened window starts from nothing rather than from slices counted at the " +
    "old length",
    widened.messages === 0 && widened.recipients === 0, JSON.stringify(widened));

  // The same property with the window left to roll rather than released.
  // A slice counted under an hour sits two hours inside a two-hour
  // window, so a length that moved without dropping what was counted
  // under the old one would read volume that has already rolled off as
  // current.
  var rolled = await issue(reg, ALPHA, {
    maxMessages: 100, maxRecipients: 100, windowMs: HOUR_MS });
  await reg.counters.record({ id: rolled.id, recipients: 5 });
  clock.advance(HOUR_MS + b.constants.TIME.minutes(1));
  var empty = await reg.counters.read(rolled.id);
  count("a window left to roll reads empty once the volume in it is past the length",
    empty.messages === 0 && empty.recipients === 0, JSON.stringify(empty));

  await reg.setCeilings({
    id: rolled.id, windowMs: TWO_HOURS_MS,
    reason: "widening a window that has already rolled" });
  var widenedAfterRoll = await reg.counters.read(rolled.id);
  count("and widening it does not bring the rolled-off volume back, which is what a length " +
    "moved over slices counted at the old one would do",
    widenedAfterRoll.messages === 0 && widenedAfterRoll.recipients === 0,
    JSON.stringify(widenedAfterRoll));
  count("and the next message is counted against the new length",
    (await reg.counters.record({ id: rolled.id, recipients: 2 })).recipients === 2);
}

// ---- the trail ------------------------------------------------------------

async function testTheTrail(reg) {
  var made = await issue(reg, ZULU, {
    maxMessages: 10, maxRecipients: 50, windowMs: HOUR_MS });

  var capture = helpers.auditCapture();
  try {
    await reg.setCeilings({
      id:            made.id,
      maxMessages:   400,
      maxRecipients: 900,
      reason:        "the announcement run was checked against the application's own log",
    });
  } finally { capture.release(); }

  var rows = capture.forAction("domain.sending_credential_ceilings_set");
  count("changing a credential's ceilings writes a row", rows.length === 1,
    "rows " + rows.length);
  count("and the row is filed against the domain the credential speaks for, not the other " +
    "one this server hosts",
    rows.length === 1 && rows[0].resourceId === ZULU,
    rows.length === 1 ? String(rows[0].resourceId) : "no row");
  count("and it carries the reason the operator gave",
    rows.length === 1 && String(rows[0].reason)
      .indexOf("checked against the application's own log") !== -1,
    rows.length === 1 ? String(rows[0].reason) : "no row");

  var meta = rows.length === 1 ? helpers.metadataOf(rows[0]) : {};
  count("and it names the credential",
    meta.credentialId === made.id, JSON.stringify(meta.credentialId));
  count("and it carries BOTH readings of every number, because a row holding only the new " +
    "ones cannot tell a raise from a cut",
    meta.maxMessagesFrom === 10 && meta.maxMessagesTo === 400 &&
    meta.maxRecipientsFrom === 50 && meta.maxRecipientsTo === 900 &&
    meta.windowMsFrom === HOUR_MS && meta.windowMsTo === HOUR_MS,
    JSON.stringify(meta));
  count("and says whether the slices went with the length, because a window that reads zero " +
    "because it was released and one that reads zero because it was re-measured are " +
    "different acts",
    meta.slicesDropped === false, JSON.stringify(meta.slicesDropped));
  count("and the row holds no secret",
    rows.length === 1 &&
      JSON.stringify(rows[0]).indexOf(made.token.split("_")[3]) === -1);
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("sending-credential-ceilings-set");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside this run's own tree keeps the encrypted-at-rest path
  // exactly as it ships.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var registry = null;
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         "mx.example.com",
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    var handle = await store.open(cfg);
    await seed(handle);

    var clock = movableClock(Date.now());
    registry = registryFor(handle, clock);

    await testRefusals(registry);
    await testARaiseReachesTheNextMessage(registry);
    await testTheCredentialStillVerifies(registry);
    await testARefusalChangeAndACeilingChangeBothLand(registry);
    await testTheWindowLengthWaitsForTheWindow(registry, clock);
    await testTheTrail(registry);
  } finally {
    if (registry !== null) registry.close();
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "sending-credential-ceilings-set",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count. Keep the token.
if (require.main === module) {
  run().then(function (n) {
    console.log("CHECKS " + n);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
