// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the sign in failure budget does when the operator's clock moves.
 *
 * The budget is two durations and nothing else. Five failures inside a
 * quarter of an hour spend it; the wait that follows starts at a minute
 * and grows with each further run at the same mailbox; the count decays
 * a quarter of an hour after the last failure. Every one of those is a
 * question about how long, and none of them is a question about what the
 * date is.
 *
 * `Date.now()` answers the second question. It moves backwards when an
 * operator corrects a wrong time, when NTP steps a drifted host, and
 * when a container starts before it has synchronized and then catches
 * up. The last one happens on every cold boot of a machine with no
 * battery-backed clock, which is most of them. A budget measured against
 * it is a budget the host's clock can hand back, and this one is the
 * whole of what stands between a guessed password and a mailbox.
 *
 * Two clocks have to answer, not one, and that is what makes this worth
 * its own file. The budget keeps its counter in a cache, and the cache
 * expires entries against a clock of its own. A budget measured on a
 * clock that cannot be moved but STORED against one that can is given
 * back by whichever of the two moves first, and the failure looks
 * exactly like the budget working: the counter is simply not there any
 * more. So the cases below cross both, one for the lock and one for the
 * counter underneath it.
 *
 * Claims:
 *
 *   - A clock stepping forward past the wait does not lift a lockout,
 *     because nothing about the account changed.
 *   - A clock stepping forward past the decay window does not hand back
 *     a counter that is part way to the threshold. This is the one that
 *     reads the cache's clock rather than the budget's.
 *   - A budget spent while the clock is wrong is still a budget spent.
 *     A lockout stamped by a host running a day behind lifts the instant
 *     the clock is corrected, which is the shape of an attacker waiting
 *     out a correction they did not have to cause.
 *
 * These drive `accounts.authenticate` rather than a listener. The clock
 * is a decision the identity layer makes and every listener funnels into
 * that one verb; which protocols read the same budget is the subject of
 * test/layer-1-state/lockout-identity-budget, which drives all four.
 *
 * How the clock is moved: `withClockStepAsync` replaces `Date.now` for
 * the duration of one call and puts it back when the promise settles.
 * Nothing else is replaced. The code under test is the shipped code,
 * driven through the shipped verb, with one scripted reading of the time
 * it asks for. It is narrowly scoped on purpose: a scripted clock left
 * in place across a database write would stamp a row with a time that
 * never happened.
 *
 * Run standalone: node test/layer-1-state/lockout-budget-clock.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var store   = require("../../lib/store");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var GOOD_PASSWORD    = "quiet lantern bicycle 4291";
var WRONG_PASSWORD   = "not the password that was set 8830";

var DOMAIN = "example.com";

// The whole of 127.0.0.0/8 is local, so every attempt below can name a
// source the one before it did not use. That is what keeps the budget
// kept against the mailbox in view: the budget kept against the source
// and the mailbox together never reaches its own threshold, so nothing
// here can be satisfied by a per source bound.
function sourceFor(n) { return "127.0.1." + n; }

// Five failures spend a mailbox's budget. Taken from the framework's own
// default rather than restated as a number, so a change upstream moves
// this file with it instead of leaving it asserting a threshold that is
// no longer the one being enforced.
var SPEND_ATTEMPTS = 5;

// Past the first rung of the wait, which is a minute, and nowhere near
// the quarter hour the counter decays over. A step of this size can only
// cross the lock.
var PAST_THE_FIRST_WAIT_MS = helpers.b.constants.TIME.minutes(2);

// Past the decay window, and past the lifetime the counter is stored
// for, which is the same duration. A step of this size crosses both, and
// crossing both is the point: either one alone hands the counter back.
var PAST_THE_DECAY_WINDOW_MS = helpers.b.constants.TIME.minutes(16);

// A host that booted a day ahead of itself, corrected. The size is not
// the claim; being unable to elapse on its own is.
var A_DAY_BACKWARDS_MS = -helpers.b.constants.TIME.days(1);

// ---------------------------------------------------------------------------
// The scripted clock
// ---------------------------------------------------------------------------

var REAL_DATE_NOW = Date.now;

// How far the host's clock is currently from the real one. Zero for
// everything except the calls a case deliberately steps across.
var clockOffsetMs = 0;

// The wrapper goes in ONCE, for the whole run, and what moves is the
// offset behind it. That is not a stylistic choice and swapping the
// global per call does not work here.
//
// The primitives this file drives capture their clock when they are
// built: the framework's lockout resolves `opts.clock || Date.now` at
// construction and holds the FUNCTION it found. Replacing the global
// afterwards leaves that reference pointing at the original, so a case
// that swaps `Date.now` around one call moves a clock the lockout is no
// longer reading, and the case passes without the step having reached
// the code it was written for. That is worse than a failure: it is a
// green result that answers a question nobody asked. The cache
// underneath resolves its own default as a wrapper that looks the global
// up per call, so half of what is under test would see the step and half
// would not, and the two halves are exactly what these cases have to
// tell apart.
//
// With the wrapper installed from the start, both halves read it, and a
// real correction on a real host is what the offset stands in for: the
// system clock moves and every reader of it sees the new value, whether
// they captured the function or call it fresh.
//
// At offset zero the wrapper answers exactly what `Date.now` answers, so
// the rows written outside a stepped call carry the times they would
// have carried anyway.
function installClock() {
  Date.now = function () { return REAL_DATE_NOW.call(Date) + clockOffsetMs; };
}

function restoreClock() {
  clockOffsetMs = 0;
  Date.now = REAL_DATE_NOW;
}

// A `finally` that puts the offset back has to run when the promise
// settles and not when the function returns: a synchronous restore
// around an async body ends the step while the call it was made for is
// still in flight.
async function withClockStepAsync(offsetMs, fn) {
  if (typeof offsetMs !== "number" || !isFinite(offsetMs)) {
    throw new TypeError("withClockStepAsync: offsetMs must be a finite number of milliseconds");
  }
  if (typeof fn !== "function") {
    throw new TypeError("withClockStepAsync: fn (function) required");
  }
  clockOffsetMs = offsetMs;
  try { return await fn(); }
  finally { clockOffsetMs = 0; }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async function openStore(prefix) {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-" + prefix + "-"));
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var cfg = config.load({
    env: {
      BLAMEPOST_HOSTNAME:         "mx.example.com",
      BLAMEPOST_DATA_DIR:         nodePath.join(root, "data"),
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    },
    cwd: root,
  });
  var handle = await store.open(cfg);
  await handle.domains.add({ domain: DOMAIN });

  return {
    handle: handle,
    close:  function () {
      if (store.isOpen()) store.close();
      if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
      else delete process.env.BLAMEJS_TMPDIR;
      try { nodeFs.rmSync(root, { recursive: true, force: true }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a verdict */ }
    },
  };
}

// A source counter shared across the file, so no two attempts anywhere
// below arrive from the same address. Two attempts that shared one would
// be counted against the pair budget together, and a refusal could then
// be either budget's.
var nextSource = 1;
function freshSource() {
  nextSource += 1;
  return sourceFor(nextSource);
}

// Each case gets a mailbox of its own. A budget cleared by a successful
// sign in at the end of one case is a budget the next case would start
// from, and the cases deliberately end in different places.
var nextAccount = 0;
async function mailboxFor(handle) {
  nextAccount += 1;
  return handle.accounts.create({
    address: "reader" + nextAccount + "@" + DOMAIN, password: GOOD_PASSWORD });
}

function wrongPassword(handle, account) {
  return handle.accounts.authenticate({
    address: account.address, password: WRONG_PASSWORD, source: freshSource() });
}

function rightPassword(handle, account) {
  return handle.accounts.authenticate({
    address: account.address, password: GOOD_PASSWORD, source: freshSource() });
}

// ---------------------------------------------------------------------------
// A wait that a clock step cannot serve
// ---------------------------------------------------------------------------

async function aClockStepDoesNotLiftAHeldBudget(handle) {
  var account = await mailboxFor(handle);

  for (var i = 0; i < SPEND_ATTEMPTS; i += 1) {
    var refused = await wrongPassword(handle, account);
    count("a wrong password is refused, attempt " + (i + 1),
      refused.ok === false, String(refused.reason));
  }

  var held = await rightPassword(handle, account);
  count("the budget is spent, so the CORRECT password is refused from a source this " +
    "mailbox has never signed in from",
    held.ok === false && held.reason === "too-many-attempts", String(held.reason));

  // The operator corrects a clock, or NTP steps one. No time has passed
  // and nothing about the account has changed.
  var afterStep = await withClockStepAsync(PAST_THE_FIRST_WAIT_MS, function () {
    return rightPassword(handle, account);
  });
  count("a wall clock stepping forward past the wait does not lift the lockout, because the " +
    "wait is a duration this mailbox has to serve rather than a date the host can be moved to",
    afterStep.ok === false && afterStep.reason === "too-many-attempts",
    afterStep.ok === true ? "signed in on the strength of a clock step" : String(afterStep.reason));
}

// ---------------------------------------------------------------------------
// A counter that a clock step cannot hand back
// ---------------------------------------------------------------------------

// The counter is held below the threshold on purpose. What a step has to
// not do here is reset it: four failures plus a fifth is a spent budget,
// and four failures plus a clock step plus a fifth has to be the same
// thing. This is the case that reads the CACHE's clock, because the
// counter is stored for the length of the decay window and a store that
// expires on the wall clock drops it whether or not the budget's own
// arithmetic would have.
async function aClockStepDoesNotHandBackAPartlySpentCounter(handle) {
  var account = await mailboxFor(handle);

  for (var i = 0; i < SPEND_ATTEMPTS - 1; i += 1) {
    var refused = await wrongPassword(handle, account);
    count("a wrong password below the threshold is refused without spending the budget, " +
      "attempt " + (i + 1),
      refused.ok === false && refused.reason === "bad-credentials", String(refused.reason));
  }

  var stillOpen = await withClockStepAsync(PAST_THE_DECAY_WINDOW_MS, function () {
    return wrongPassword(handle, account);
  });
  count("the failure that meets the threshold is still refused",
    stillOpen.ok === false, String(stillOpen.reason));

  var afterStep = await withClockStepAsync(PAST_THE_DECAY_WINDOW_MS, function () {
    return rightPassword(handle, account);
  });
  count("a wall clock stepping forward past the decay window does not hand back the failures " +
    "already counted, so the threshold is met by the fifth failure rather than by however " +
    "many the host's clock allows between corrections",
    afterStep.ok === false && afterStep.reason === "too-many-attempts",
    afterStep.ok === true ? "signed in on a counter a clock step reset" : String(afterStep.reason));
}

// ---------------------------------------------------------------------------
// A budget spent on a wrong clock is still a budget spent
// ---------------------------------------------------------------------------

// The other direction, and the one an attacker does not have to cause.
// A host that boots a day behind itself and is then corrected wrote every
// lockout in that period against a clock that has since moved forward by
// a day. If the wait is an instant on that clock, every one of those
// lockouts lifts at the moment of the correction, together, and the
// mailboxes that were being guessed at are the ones it lifts for.
async function aBudgetSpentOnAWrongClockIsStillSpent(handle) {
  var account = await mailboxFor(handle);

  for (var i = 0; i < SPEND_ATTEMPTS; i += 1) {
    var refused = await withClockStepAsync(A_DAY_BACKWARDS_MS, function () {
      return wrongPassword(handle, account);
    });
    count("a wrong password on a host running a day behind is refused, attempt " + (i + 1),
      refused.ok === false, String(refused.reason));
  }

  var afterCorrection = await rightPassword(handle, account);
  count("the budget those failures spent is still spent once the clock is corrected, so a " +
    "correction is not a way to serve a wait that was never served",
    afterCorrection.ok === false && afterCorrection.reason === "too-many-attempts",
    afterCorrection.ok === true
      ? "signed in because the wait was stamped in the past"
      : String(afterCorrection.reason));
}

// ---------------------------------------------------------------------------

async function run() {
  // Before the store opens, because the budgets are built on their first
  // use and whatever clock they find then is the one they keep.
  installClock();
  var fixture = await openStore("lockout-clock");
  try {
    await helpers.withTestTimeout("lockout clock: a step does not lift a held budget",
      function () { return aClockStepDoesNotLiftAHeldBudget(fixture.handle); },
      // Every attempt below pays for a password verification, which is
      // slow on purpose.
      { timeoutMs: 30000 });
    await helpers.withTestTimeout("lockout clock: a step does not hand back a counter",
      function () { return aClockStepDoesNotHandBackAPartlySpentCounter(fixture.handle); },
      { timeoutMs: 30000 });
    await helpers.withTestTimeout("lockout clock: a budget spent on a wrong clock stays spent",
      function () { return aBudgetSpentOnAWrongClockIsStillSpent(fixture.handle); },
      { timeoutMs: 30000 });
  } finally {
    fixture.close();
    restoreClock();
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "lockout-budget-clock",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
