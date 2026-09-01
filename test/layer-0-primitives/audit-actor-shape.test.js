// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The identity an audit row records, on its own: `blamepost.store.actor`
 * with nothing composed around it.
 *
 * `test/layer-1-state/audit-actor-attribution.test.js` drives the two
 * surfaces end to end and asks whether the rows they write name who
 * acted. This file asks the questions that are about the shape rather
 * than about a row, and they are the ones that decide whether the
 * answer over there can be relied on:
 *
 *   - The read at an emit can never throw. Every caller is an audit
 *     emit, and an emit runs inside a sink that drops what it cannot
 *     write precisely so a failed record does not end the delivery or
 *     the deletion that produced it. A read that could raise would put
 *     the failure back exactly where it was designed out of, so the
 *     shape is settled where a scope is opened and refused loudly
 *     there, and the read afterwards is a property access on an object
 *     whose fields are always present.
 *   - Two pieces of work in flight do not read each other's operator.
 *     A server answers several requests at once, and an identity held
 *     for the process rather than for the work labels one operator's
 *     action with another operator's name. That is worse than no name
 *     at all: an empty column reads as unknown, and a wrong one reads
 *     as evidence.
 *   - Two of the four fields arrive from whoever connected, so they
 *     are bounded and stripped of anything a terminal would act on
 *     rather than print.
 *
 * Run standalone: node test/layer-0-primitives/audit-actor-shape.test.js
 */

var helpers    = require("../helpers");
var b          = require("../../lib/vendor/blamejs");
var auditActor = require("../../lib/store/actor");

var count = helpers.count;

// A control character, built from its code point so this file carries
// none of its own.
var BELL = String.fromCharCode(7);

// A namespace the store registers, so an action written here is one the
// framework will accept, and one that nothing registers, so the refusal
// the framework raises for itself can be exercised too.
var REGISTERED_NAMESPACE   = "domain";
var UNREGISTERED_NAMESPACE = "nothingregistersthis";

function theShapeIsAlwaysTheSame() {
  var full = auditActor.build({
    userId: "acc-1", ip: "203.0.113.4", userAgent: "a client", sessionId: "s-1",
  });
  count("an actor carries the four fields the chain writes",
    full.userId === "acc-1" && full.ip === "203.0.113.4" &&
    full.userAgent === "a client" && full.sessionId === "s-1",
    JSON.stringify(full));

  var partial = auditActor.build({ ip: "203.0.113.4" });
  count("a field nobody supplied is present and empty rather than missing, so a " +
    "reader never has to test for it",
    Object.prototype.hasOwnProperty.call(partial, "userId") && partial.userId === null &&
    partial.userAgent === null && partial.sessionId === null,
    JSON.stringify(partial));

  count("an actor built from nothing at all is still the same shape",
    JSON.stringify(auditActor.build()) === JSON.stringify(auditActor.build({})),
    JSON.stringify(auditActor.build()));

  var frozen = auditActor.build({ userId: "acc-1" });
  try { frozen.userId = "acc-2"; } catch (_e) { /* strict mode refuses the write */ }
  count("and it cannot be edited after it is built, so the row cannot be renamed " +
    "between the emit and the write", frozen.userId === "acc-1", frozen.userId);

  count("nothing beyond the four fields is enumerable, so whatever serializes the " +
    "actor on its way to a row sees only what the row has columns for",
    Object.keys(frozen).join(",") === "userId,ip,userAgent,sessionId",
    Object.keys(frozen).join(","));
}

// Two of the fields are chosen by whoever connected.
function whatArrivesFromAPeerIsBounded() {
  var long = auditActor.build({ userAgent: "u".repeat(4000), ip: "i".repeat(4000) });
  count("an agent string is bounded rather than letting a peer choose how large " +
    "this server's audit rows are",
    long.userAgent.length > 0 && long.userAgent.length <= 256, long.userAgent.length);
  count("and so is the address it arrived from",
    long.ip.length > 0 && long.ip.length <= 64, long.ip.length);

  var noisy = auditActor.build({ userAgent: "curl/8" + BELL + "and the rest" });
  count("a character a terminal would act on rather than print ends the field there",
    noisy.userAgent === "curl/8", JSON.stringify(noisy.userAgent));

  var allNoise = auditActor.build({ userAgent: BELL + BELL });
  count("and a field that is nothing else records an absence rather than the noise",
    allNoise.userAgent === null, JSON.stringify(allNoise.userAgent));

  var padded = auditActor.build({ userId: "   ", ip: "  203.0.113.4  " });
  count("whitespace on its own is an absence, and whitespace around a value is not " +
    "part of it", padded.userId === null && padded.ip === "203.0.113.4",
    JSON.stringify(padded));
}

// A shell user is not an account, and the column carries both.
function theCommandLineNamesWhatItCanEstablish() {
  var operator = auditActor.forCommandLine();
  count("the command line's identity is marked as one, so a filter on the column can " +
    "tell an operator at a terminal from an account that signed in",
    typeof operator.userId === "string" &&
    operator.userId.indexOf(auditActor.COMMAND_LINE_MARK) === 0, operator.userId);
  count("it names a user and a host rather than one or the other",
    /^cli:[^@]+@.+$/.test(operator.userId), operator.userId);
  count("it records the binary the operator was driving",
    typeof operator.userAgent === "string" && operator.userAgent.indexOf("blamepost/") === 0,
    operator.userAgent);
  count("and the process the command ran in",
    operator.sessionId === "pid:" + process.pid, operator.sessionId);
  count("and it invents no peer address, because a command run at a terminal arrived " +
    "from nowhere", operator.ip === null, JSON.stringify(operator.ip));
  count("it is resolved once for the process rather than on every row",
    auditActor.forCommandLine() === operator, "two reads returned different objects");
}

// The framework owns the reading of a request, so a peer address behind
// a socket, a connection or a proxy-set property is found the same way
// every other surface finds it.
function aRequestNamesItsAccountAndItsPeer() {
  var signedIn = auditActor.forRequest({
    ip:      "203.0.113.4",
    method:  "POST",
    url:     "/admin/accounts",
    headers: { "user-agent": "a browser" },
    user:    { id: "acc-1" },
  });
  count("a request with a session names the account behind it",
    signedIn.userId === "acc-1", JSON.stringify(signedIn));
  count("and the peer it arrived from and what it was driving",
    signedIn.ip === "203.0.113.4" && signedIn.userAgent === "a browser",
    JSON.stringify(signedIn));

  var anonymous = auditActor.forRequest({
    socket:  { remoteAddress: "198.51.100.9" },
    headers: { "user-agent": "something else" },
  });
  count("a request with no session still records where it came from, which is the " +
    "whole of what a refusal is read for",
    anonymous.userId === null && anonymous.ip === "198.51.100.9",
    JSON.stringify(anonymous));

  count("and something that is not a request at all is an absence rather than a throw",
    auditActor.forRequest(null).userId === null &&
    auditActor.forRequest(undefined).ip === null,
    JSON.stringify(auditActor.forRequest(null)));
}

// The split that keeps a throw out of the emit path.
function aScopeRefusesAnActorItDidNotBuild() {
  var thrown = null;
  try { auditActor.runAs({ userId: "acc-1" }, function () { return 1; }); }
  catch (e) { thrown = e; }
  count("a scope refuses an actor assembled somewhere else, loudly and where the " +
    "scope is opened", thrown !== null && thrown instanceof TypeError,
    thrown === null ? "nothing was thrown" : String(thrown.message).slice(0, 120));

  var missing = null;
  try { auditActor.enterAs(null); }
  catch (e2) { missing = e2; }
  count("and so does the other way of opening one",
    missing !== null && missing instanceof TypeError,
    missing === null ? "nothing was thrown" : String(missing.message).slice(0, 120));

  var noWork = null;
  try { auditActor.runAs(auditActor.build({ userId: "acc-1" }), "not a function"); }
  catch (e3) { noWork = e3; }
  count("a scope with no work to run inside it is refused too",
    noWork !== null && noWork instanceof TypeError,
    noWork === null ? "nothing was thrown" : String(noWork.message).slice(0, 120));
}

function theReadNeverThrowsAndNeverInvents() {
  var outside = auditActor.current();
  count("read outside any scope, the identity is an absence rather than a failure",
    outside !== null && outside.userId === null, JSON.stringify(outside));

  var inside = auditActor.build({ userId: "acc-1" });
  var seen = auditActor.runAs(inside, function () { return auditActor.current(); });
  count("read inside one, it is the identity that scope was opened with",
    seen === inside, JSON.stringify(seen));
  count("and the scope closes when the work finishes rather than outliving it",
    auditActor.current().userId === null, JSON.stringify(auditActor.current()));
}

// The vector a single-operator run cannot see.
async function twoPiecesOfWorkDoNotReadEachOthersOperator() {
  var first  = auditActor.build({ userId: "acc-first" });
  var second = auditActor.build({ userId: "acc-second" });
  var reached = { first: null, second: null };
  var arrived = 0;

  function work(actor, into) {
    return auditActor.runAs(actor, async function () {
      // Both are in flight across the same await, which is the shape an
      // identity held for the process gets wrong.
      arrived += 1;
      await helpers.waitUntil(function () { return arrived >= 2; }, {
        timeoutMs: 5000,
        label:     "audit-actor-shape: both pieces of work are in flight together",
      });
      reached[into] = auditActor.current().userId;
    });
  }

  await Promise.all([work(first, "first"), work(second, "second")]);
  count("each piece of work reads the operator it was opened for",
    reached.first === "acc-first" && reached.second === "acc-second",
    JSON.stringify(reached));
}

// ---- runner ------------------------------------------------------------------

// ---- writing the row ---------------------------------------------------------

// The writer every verb in the store goes through, on its own.
//
// Its whole reason for existing is what it does when the sink refuses,
// and no test that drives a verb reaches that by accident: a caller-side
// check sees the verb succeed and cannot tell whether the row was
// written, dropped or never attempted. So the sink is driven directly
// here, in the framework's redirect mode, where the store the events are
// handed to is the one this file supplies and a failure in it is the
// framework's own documented path to the caller.
//
// A wrapper that swallowed everything would pass a check that only
// asked whether it throws, so what reaches a working sink is checked
// first and the refusals after it.
function withSink(record) {
  b.audit.registerNamespace(REGISTERED_NAMESPACE);
  var seen = [];
  b.audit.useStore({
    replaceChain: true,
    record:       function (row) {
      seen.push(row);
      return record(row);
    },
  });
  return function landed() { return seen; };
}

async function theRowStillReachesASinkThatWorks() {
  var landed = withSink(function () { return null; });
  try {
    var wrote = await auditActor.record({
      action:   REGISTERED_NAMESPACE + ".added",
      outcome:  "success",
      actor:    auditActor.build({ userId: "acc-1" }),
      resource: { kind: "domain", id: "d-1" },
      metadata: { domain: "example.com" },
    });
    count("and it says the row was written, which is the half of the verdict a caller " +
      "with somewhere to report it needs",
      wrote === true, JSON.stringify(wrote));
    var rows = landed();
    count("a row written through the store's writer reaches the sink",
      rows.length === 1, String(rows.length));
    count("and arrives carrying the action, the outcome and who acted, so the writer is " +
      "passing the event on rather than quietly discarding it",
      rows.length === 1 && rows[0].action === REGISTERED_NAMESPACE + ".added" &&
      rows[0].outcome === "success" && rows[0].actorUserId === "acc-1",
      JSON.stringify(rows[0] && {
        action: rows[0].action, outcome: rows[0].outcome, actor: rows[0].actorUserId,
      }));
  } finally {
    b.audit.useStore(null);
  }
}

// Four ways the write can fail, and one answer to all of them. The
// values that are not errors are the ones that matter beyond the first:
// a handler that inspected what it caught would be a second way for the
// same call to raise, on a path whose entire purpose is that it cannot.
//
// They arrive as rejections rather than as bare throws because that is
// the path either one takes. The framework calls the sink from inside a
// resolved promise, so a synchronous throw and a rejection reach the
// wrapper's catch as the same thing, and a rejection is also what an
// async sink actually produces.
async function aSinkThatRefusesChangesNothingForTheCaller() {
  var refusals = [
    { label: "throws",                 thrown: function () { throw new Error("the sink is gone"); } },
    { label: "rejects with an error",  thrown: function () { return Promise.reject(new Error("gone")); } },
    { label: "rejects with a string",  thrown: function () { return Promise.reject("the sink is gone"); } },
    { label: "rejects with nothing",   thrown: function () { return Promise.reject(null); } },
  ];

  for (var i = 0; i < refusals.length; i += 1) {
    var landed = withSink(refusals[i].thrown);
    var raised = null;
    var returned;
    try {
      returned = await auditActor.record({
        action:  REGISTERED_NAMESPACE + ".added",
        outcome: "success",
        actor:   auditActor.build({ userId: "acc-1" }),
      });
    } catch (e) {
      raised = e;
    } finally {
      b.audit.useStore(null);
    }
    count("a sink that " + refusals[i].label + " does not raise at the caller",
      raised === null,
      raised === null ? "returned" : String((raised && raised.message) || raised));
    count("and the write was really attempted against it, rather than skipped",
      landed().length === 1, String(landed().length));
    // What comes back is a verdict about the ROW and never about the
    // operation the row describes. It is false rather than the error,
    // and false rather than the row, because either of those is a value
    // a caller could read as a result and act on; the one thing a caller
    // may learn here is that the trail has no entry, which a command
    // line can say to the operator in front of it and a wire protocol
    // has no field for and ignores.
    count("and what comes back says the row was not written, not what went wrong with it",
      returned === false, JSON.stringify(returned));
  }
}

// The framework refuses an action under a namespace nothing registered,
// and it refuses before it reaches any sink. That refusal is a coding
// mistake rather than an operational one, so it is caught by the static
// gates; what it must never do is take down the operation whose row it
// is, and that is what is checked here.
async function aRefusalTheFrameworkRaisesIsDroppedToo() {
  var raised = null;
  try {
    await auditActor.record({
      action:  UNREGISTERED_NAMESPACE + ".added",
      outcome: "success",
      actor:   auditActor.build({ userId: "acc-1" }),
    });
  } catch (e) {
    raised = e;
  }
  count("an action the framework itself refuses does not raise at the caller either",
    raised === null,
    raised === null ? "returned" : String((raised && raised.message) || raised));

  var malformed = null;
  try {
    await auditActor.record({ action: REGISTERED_NAMESPACE + ".added", outcome: "not-an-outcome" });
  } catch (e) {
    malformed = e;
  }
  count("nor does an outcome outside the three the chain accepts",
    malformed === null,
    malformed === null ? "returned" : String((malformed && malformed.message) || malformed));

  var empty = null;
  try { await auditActor.record(undefined); }
  catch (e) { empty = e; }
  count("nor does an event that is not there at all",
    empty === null, empty === null ? "returned" : String((empty && empty.message) || empty));
}

async function run() {
  theShapeIsAlwaysTheSame();
  whatArrivesFromAPeerIsBounded();
  theCommandLineNamesWhatItCanEstablish();
  aRequestNamesItsAccountAndItsPeer();
  aScopeRefusesAnActorItDidNotBuild();
  theReadNeverThrowsAndNeverInvents();
  await twoPiecesOfWorkDoNotReadEachOthersOperator();
  await theRowStillReachesASinkThatWorks();
  await aSinkThatRefusesChangesNothingForTheCaller();
  await aRefusalTheFrameworkRaisesIsDroppedToo();
  return helpers.getChecks();
}

module.exports = { name: "audit-actor-shape", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
