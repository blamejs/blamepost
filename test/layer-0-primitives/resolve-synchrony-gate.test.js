// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * resolve-synchrony-gate: the construction check that a recipient lookup
 * answers without suspending, and how much of the lookup it actually
 * reaches.
 *
 * Whether a recipient still has somewhere to land is decided again at the
 * instant a copy is filed, so that the answer and the write are one run
 * nothing can be interleaved with. That only holds while the lookup
 * answers synchronously: a lookup that suspends is one an operator's
 * suspension can land inside, and the mailbox they closed while the
 * message was arriving would receive it anyway.
 *
 * `blamepost.mail.listeners.create` therefore probes the lookup at
 * construction rather than asserting the property in prose, and refuses a
 * handle that answers with a promise.
 *
 * What the probe ASKS is what this file measures, because a probe reaches
 * only the branches its own input reaches. A recipient that does not
 * parse is answered by the first line of the lookup, before a domain row,
 * an alias row or an account row has been read, so a probe made only of
 * that one exercises the single branch that touches no storage. Every
 * branch the delivery path's own re-read takes is on the far side of
 * those reads. A handle that answers synchronously where such a probe
 * looks and asynchronously where the rows are is the shape the check is
 * expected to catch and the shape it is least able to see, so two of the
 * vectors below are that handle at two different depths rather than one
 * that suspends everywhere.
 *
 * The acceptance control is load-bearing and sits with them: without a
 * lookup that is synchronous on every branch and is BUILT, a refusal that
 * fired on every composition would satisfy every other vector here.
 *
 * The last part records what the protected call site does when a
 * suspended answer reaches it, because the two answers are worth keeping
 * apart: a check that can be walked past matters differently depending on
 * whether the thing behind it fails open or closed.
 *
 * No sockets, no database, no disk. It constructs a listener handle that
 * is expected never to be built.
 *
 * Run standalone: node test/layer-0-primitives/resolve-synchrony-gate.test.js
 */

var helpers   = require("../helpers");
var listeners = require("../../lib/mail/listeners");

var count = helpers.count;

var HOSTNAME = "mx.example.com";

// A domain the stand-in store reports as hosted, so the construction
// probe has one to ask its deepest question about.
var HOSTED = "hosted.example.org";

// The lookup's own answer shape, so a stand-in cannot pass by being
// shaped differently from the thing it stands in for.
function verdict(fields) {
  return Object.assign({
    local:       false,
    deliverable: false,
    reason:      null,
    kind:        null,
    address:     null,
    written:     null,
    localPart:   null,
    domain:      null,
    tag:         null,
    accountId:   null,
    status:      null,
    targets:     [],
    loops:       [],
  }, fields);
}

// A recipient that reaches a mailbox, as the lookup answers one.
function reachable(recipient) {
  return verdict({
    local:       true,
    deliverable: true,
    kind:        "account",
    address:     recipient,
    accountId:   "acct_1",
    status:      "active",
    targets:     [{
      address: recipient, mailbox: recipient, local: true,
      accountId: "acct_1", status: "active", deliverable: true, reason: null,
    }],
  });
}

// Synchronous where the probe looks and suspended everywhere a row is
// read. Not a contrivance: it is the shape any lookup takes the day its
// storage stops answering in the same run, because the guard clause on a
// recipient that does not parse is above every read and stays above them.
function aLookupThatSuspendsOnlyWhereItReadsRows() {
  return {
    resolve: function (recipient) {
      if (typeof recipient !== "string" || recipient.indexOf("@") === -1) {
        return verdict({ reason: "invalid-address" });
      }
      return Promise.resolve(reachable(recipient));
    },
    accounts: { authenticate: function () { return Promise.resolve(null); } },
    domains:  { list: function () { return []; } },
    aliases:  { list: function () { return []; } },
  };
}

// Suspended one read deeper than the handle above, and synchronous
// everywhere a cheaper question can reach.
//
// It answers a recipient that does not parse from its guard clause, and
// a recipient at a domain it does not host off the domain row, both in
// the same run. Only once the domain is one it hosts, which is where the
// alias rows and the account row are read, does it suspend. A probe that
// stops at the first parseable recipient it can think of reads this
// handle as synchronous, and every message it then files is filed on an
// answer that arrived after the write was authorized.
function aLookupThatSuspendsOnlyBeyondTheDomainRow() {
  return {
    resolve: function (recipient) {
      if (typeof recipient !== "string" || recipient.indexOf("@") === -1) {
        return verdict({ reason: "invalid-address" });
      }
      var domain = recipient.slice(recipient.lastIndexOf("@") + 1).toLowerCase();
      if (domain !== HOSTED) {
        return verdict({ reason: "unknown-domain", domain: domain });
      }
      return Promise.resolve(reachable(recipient));
    },
    accounts: { authenticate: function () { return Promise.resolve(null); } },
    domains:  { list: function () { return [{ domain: HOSTED, status: "active" }]; } },
    aliases:  { list: function () { return []; } },
  };
}

// Synchronous on every branch, including the ones behind a row. This is
// the handle the composition is meant to ACCEPT, and it hosts a domain
// so that the probe's deepest question is asked of it too.
function aLookupThatAnswersInOneRun() {
  return {
    resolve: function (recipient) {
      if (typeof recipient !== "string" || recipient.indexOf("@") === -1) {
        return verdict({ reason: "invalid-address" });
      }
      return verdict({ local: true, reason: "no-such-mailbox", address: recipient });
    },
    accounts: { authenticate: function () { return Promise.resolve(null); } },
    domains:  { list: function () { return [{ domain: HOSTED, status: "active" }]; } },
    aliases:  { list: function () { return []; } },
  };
}

function compositionOver(store) {
  return {
    config:      { hostname: HOSTNAME, dnsAcknowledged: true },
    store:       store,
    mailStore:   {
      appendMessage: function () { return {}; },
      sieveScripts:  { active: function () { return null; } },
    },
    // The loader handle rather than a context: the composition reads
    // `secureContext` per connection and refuses anything else.
    certificate: { secureContext: {} },
    delivery:    helpers.standInDelivery(),
  };
}

// ---------------------------------------------------------------------------

// The property the construction check exists to establish, asked about
// the branches the delivery path actually takes rather than about the one
// the probe reaches.
function aLookupThatSuspendsWhereItMattersIsRefusedAtConstruction() {
  var thrown = null;
  try { listeners.create(compositionOver(aLookupThatSuspendsOnlyWhereItReadsRows())); }
  catch (e) { thrown = e; }

  count("a recipient lookup that suspends on every branch that reads a row is refused at " +
    "construction, because those are the branches the re-read at the write takes",
    thrown !== null && /synchronous/i.test(String(thrown.message || "")),
    thrown === null
      ? "the composition was accepted"
      : String(thrown.message).slice(0, 200));
}

// The same check against a lookup that suspends everywhere, which is what
// the probe does catch. Without this the vector above would pass on a
// composition that refuses every store, which proves nothing about the
// probe.
function aLookupThatSuspendsEverywhereIsRefused() {
  var store = aLookupThatSuspendsOnlyWhereItReadsRows();
  store.resolve = function (recipient) { return Promise.resolve(reachable(recipient)); };

  var thrown = null;
  try { listeners.create(compositionOver(store)); }
  catch (e) { thrown = e; }

  count("a lookup that suspends on every branch is refused, and the refusal says the " +
    "lookup has to answer synchronously",
    thrown !== null && /synchronous/i.test(String(thrown.message || "")),
    thrown === null
      ? "the composition was accepted"
      : String(thrown.message).slice(0, 200));
}

// The same question one read deeper, which is where a probe that only
// learned to ask a parseable recipient would stop seeing.
function aLookupThatSuspendsPastTheDomainRowIsRefusedAtConstruction() {
  var thrown = null;
  try { listeners.create(compositionOver(aLookupThatSuspendsOnlyBeyondTheDomainRow())); }
  catch (e) { thrown = e; }

  count("a recipient lookup synchronous at a domain this server does not host and suspended " +
    "at one it does is refused at construction, because the hosted domain is where the alias " +
    "and account rows are read",
    thrown !== null && /synchronous/i.test(String(thrown.message || "")),
    thrown === null
      ? "the composition was accepted"
      : String(thrown.message).slice(0, 200));
}

// The control the refusals above are worthless without. A construction
// check that refused every composition would satisfy all three of them,
// so one lookup that answers in a single run on every branch has to be
// built rather than refused.
function aLookupThatAnswersInOneRunIsAccepted() {
  var thrown = null;
  try { listeners.create(compositionOver(aLookupThatAnswersInOneRun())); }
  catch (e) { thrown = e; }

  count("a recipient lookup that answers every branch in one run is not refused for the " +
    "synchrony reason, so the refusals above are decisions about the handle rather than a " +
    "check that fires on everything",
    thrown === null || !/synchronous/i.test(String(thrown.message || "")),
    thrown === null ? "built" : String(thrown.message).slice(0, 200));
}

// What a suspended answer does at the call site the check protects. The
// re-read reads `targets` off whatever the lookup handed back, and a
// promise carries none, so every local recipient reads as one with
// nowhere to land. Recorded because a check that can be walked past
// matters differently depending on which way the thing behind it fails,
// and this one fails toward refusing mail rather than toward filing it
// into a mailbox somebody closed.
function aSuspendedAnswerReadsAsNowhereToLand() {
  var store = aLookupThatSuspendsOnlyWhereItReadsRows();
  var answered = store.resolve("bob@example.com");
  var live = (answered.targets || []).filter(function (t) { return t.deliverable === true; });

  count("a suspended answer carries no reachable target, so the re-read at the write " +
    "refuses the recipient rather than filing on a stale answer",
    live.length === 0 && answered.deliverable !== true,
    JSON.stringify({ deliverable: answered.deliverable, targets: live.length }));
}

// ---------------------------------------------------------------------------

function run() {
  aLookupThatSuspendsEverywhereIsRefused();
  aLookupThatSuspendsWhereItMattersIsRefusedAtConstruction();
  aLookupThatSuspendsPastTheDomainRowIsRefusedAtConstruction();
  aLookupThatAnswersInOneRunIsAccepted();
  aSuspendedAnswerReadsAsNowhereToLand();
  return helpers.getChecks();
}

module.exports = {
  name:      "resolve-synchrony-gate",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  try {
    var total = run();
    console.log("CHECKS " + total);
  } catch (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  }
}
