// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether the account re-read in front of a signed-in session's commands
 * covers every command there is.
 *
 * `lib/mail/listeners.js` refuses a command once the account behind the
 * session has left service, and it wires that refusal onto the MAILBOX
 * ADAPTER rather than onto each handler, because the framework
 * dispatches most of the verbs itself and this repository overrides the
 * rest. The wiring is a list of verb names. A list is only as complete
 * as the last person to read it, and the source it has to agree with is
 * `lib/vendor/blamejs/`, which `scripts/vendor-update.sh` rewrites whole.
 * A refresh that teaches a listener one new adapter call adds a command
 * that reaches the mailbox with nobody asking whether the account is
 * still in service, and every behavioral test goes on passing, because a
 * test can only drive the verbs its author knew about.
 *
 * So the agreement is read off both sides here rather than believed:
 *
 *   - Every adapter verb the vendored IMAP, POP3 and ManageSieve
 *     listeners call is gated, or is named below with the reason it is
 *     not. A verb that is neither is reported by name.
 *   - Every gated verb is called by one of those listeners or by
 *     `lib/mail/listeners.js` itself. A list may not carry entries
 *     nothing reaches: they cost nothing to add and make the coverage
 *     read wider than it is.
 *   - Inside `lib/mail/listeners.js`, no gated verb is reached through
 *     the raw adapter. A handler written against `mailStore` instead of
 *     the gated handle is the same hole reintroduced one override at a
 *     time, and it reads as ordinary code.
 *
 * The declarations are located by name, and a declaration this file
 * cannot find is a failure rather than an empty set quietly passing: a
 * verdict over nothing answers for no part of the tree. Every claim
 * publishes how many verbs it examined for the same reason.
 *
 * Each of the three findings is also planted on a source written here
 * and read back, so a reader that stopped recognizing its shape fails
 * rather than reporting a clean tree. That proof says the readers still
 * fire and says nothing about whether they reached the tree, which is
 * what the counts beside every claim answer.
 *
 * Run standalone: node test/layer-0-primitives/session-store-gate-coverage.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");

var count = helpers.count;

var LISTENERS = nodePath.join(helpers.REPO_ROOT, "lib", "mail", "listeners.js");

// The three listeners that hand an adapter a signed-in session's work.
// The MX listener is absent because inbound mail carries no session: a
// message for a mailbox that is out of service is refused at RCPT.
var VENDORED_LISTENERS = [
  "mail-server-imap.js",
  "mail-server-pop3.js",
  "mail-server-managesieve.js",
];

// Verbs the vendored listeners name that are deliberately outside the
// gate, each with the reason. An entry here is a decision somebody wrote
// down; a verb that is neither gated nor listed is the finding.
var UNGATED_BY_DESIGN = Object.freeze({
  create: "not a call on the adapter at all. It is `b.mailStore.create` quoted inside the " +
    "sentence a listener throws when its mailStore option is missing.",
  quota: "takes a folder name and no actor, so there is no account to read. It is reached " +
    "only on the APPEND path, whose own verb is gated.",
  appendCatenate: "is absent from this repository's adapter, so the framework's own " +
    "fallback answers and no command reaches a mailbox through it.",
  subscribeNotify: "is absent for the reason appendCatenate is: RFC 5465 NOTIFY needs a " +
    "push channel from the store to a live connection, which this adapter does not offer.",
});

// The one gated verb `lib/mail/listeners.js` may still reach through the
// raw adapter. Inbound delivery files an arriving message under an actor
// this server builds for the recipient rather than under a session, and
// whether that mailbox accepts mail is decided at RCPT.
var RAW_ADAPTER_BY_DESIGN = Object.freeze({
  appendMessage: "inbound delivery files an arriving message under an actor built for the " +
    "recipient rather than under a session, and a held mailbox is answered at RCPT.",
});

// ---- reading the two sides -------------------------------------------------

// A line that is prose rather than code. The vendored sources quote
// adapter calls inside their own documentation blocks, and a scan that
// counted those would report verbs no listener calls.
function isProse(line) {
  var trimmed = line.trim();
  return trimmed.indexOf("*") === 0 || trimmed.indexOf("//") === 0 ||
    trimmed.indexOf("/*") === 0;
}

// The raw adapter, and the handle that has the account re-read wired
// onto it. They are read apart: what a listener CALLS and what it calls
// it THROUGH are different questions, and folding them together would
// let a handler reaching past the gate read as one that goes through it.
var RAW_HANDLE   = "mailStore";
var GATED_HANDLE = "_sessionStore\\(\\)";

// Every `<handle>.<verb>(` and `<handle>.sieveScripts.<verb>(` in one
// source, as two sets. The lookbehind drops `opts.mailStore` and
// `b.mailStore`, since neither is the adapter a session reaches.
function adapterCallsIn(source, handle) {
  var sieveCall = new RegExp("(?<![A-Za-z0-9_.])" + handle +
    "\\.sieveScripts\\.([A-Za-z0-9_]+)\\s*\\(", "g");
  var topCall = new RegExp("(?<![A-Za-z0-9_.])" + handle +
    "\\.([A-Za-z0-9_]+)\\s*\\(", "g");
  var top   = Object.create(null);
  var sieve = Object.create(null);
  source.split(/\r?\n/).forEach(function (line) {
    if (isProse(line)) return;
    var found;
    sieveCall.lastIndex = 0;
    while ((found = sieveCall.exec(line)) !== null) sieve[found[1]] = true;
    topCall.lastIndex = 0;
    while ((found = topCall.exec(line)) !== null) {
      if (found[1] !== "sieveScripts") top[found[1]] = true;
    }
  });
  return { top: Object.keys(top).sort(), sieve: Object.keys(sieve).sort() };
}

// One frozen array of verb names out of the listener source, by the name
// it is declared under. Null when the declaration is not there, so the
// caller reports a rename rather than measuring an empty set.
function frozenListNamed(source, name) {
  var declaration = new RegExp("var\\s+" + name + "\\s*=\\s*Object\\.freeze\\(\\[([\\s\\S]*?)\\]\\)");
  var found = declaration.exec(source);
  if (found === null) return null;
  var quoted = found[1].match(/"[A-Za-z0-9_]+"/g) || [];
  return quoted.map(function (entry) { return entry.slice(1, -1); }).sort();
}

// The same for the one declared as an object, whose keys are the verbs.
function frozenKeysNamed(source, name) {
  var declaration = new RegExp("var\\s+" + name + "\\s*=\\s*Object\\.freeze\\(\\{([\\s\\S]*?)\\}\\)");
  var found = declaration.exec(source);
  if (found === null) return null;
  var keys = found[1].match(/([A-Za-z0-9_]+)\s*:/g) || [];
  return keys.map(function (entry) { return entry.replace(/\s*:$/, ""); }).sort();
}

function union(lists) {
  var seen = Object.create(null);
  lists.forEach(function (list) {
    list.forEach(function (name) { seen[name] = true; });
  });
  return Object.keys(seen).sort();
}

function missingFrom(wanted, held) {
  return wanted.filter(function (name) { return held.indexOf(name) === -1; });
}

// ---- the readers, proven on a planted source -------------------------------

// Each of the three findings below, planted and read back.
//
// Planted here rather than in the shipped listener, for a reason beyond
// tidiness: every one of these holes is a real weakening of the server
// while it sits in the tree, and a proof that requires the working copy
// to hold one for the length of a test run is a proof nobody should run
// twice. The readers are pure functions over source text, so a source
// written here exercises the same code path the shipped one does.
//
// This is a canary and it does not stand in for the counts. Every claim
// below publishes how many verbs it examined, because a canary says the
// readers still fire on a planted shape and says nothing about whether
// they reached the tree.
var PLANTED_LISTENER = [
  'var SESSION_ACTOR_FIRST_VERBS = Object.freeze([',
  '  "listFolders", "reachedByNothing",',
  "]);",
  'var SESSION_SIEVE_VERBS = Object.freeze(["list"]);',
  "var SESSION_OPTS_ACTOR_VERBS = Object.freeze({ appendMessage: 2 });",
  "// a handler that reaches the raw adapter, which is the shape claim three finds",
  "function _plantedHandler(state) { return mailStore.listFolders(state.actor); }",
].join("\n");

var PLANTED_VENDORED = [
  " *   mailStore.quota(folderName) is quoted in a documentation block",
  "function _plantedAppend(n, b, o) { return mailStore.appendMessage(n, b, o); }",
  "function _plantedVerb(state) { return mailStore.storeFlags(state.actor, 1); }",
  'function _plantedScript(state) { return mailStore.sieveScripts.rename(state.actor); }',
].join("\n");

function theReadersFindAPlantedHole() {
  var planted = {
    actorFirst: frozenListNamed(PLANTED_LISTENER, "SESSION_ACTOR_FIRST_VERBS"),
    sieve:      frozenListNamed(PLANTED_LISTENER, "SESSION_SIEVE_VERBS"),
    optsActor:  frozenKeysNamed(PLANTED_LISTENER, "SESSION_OPTS_ACTOR_VERBS"),
  };
  count("a declaration this file cannot find reads as absent rather than as an empty list, " +
    "which is what keeps a renamed gate from passing over nothing",
    frozenListNamed(PLANTED_LISTENER, "SESSION_VERBS_UNDER_ANOTHER_NAME") === null,
    String(frozenListNamed(PLANTED_LISTENER, "SESSION_VERBS_UNDER_ANOTHER_NAME")));

  var vendored = adapterCallsIn(PLANTED_VENDORED, RAW_HANDLE);
  count("an adapter call quoted inside a documentation block is not read as a call, so the " +
    "comparison is against what a listener does rather than what it describes",
    vendored.top.indexOf("quota") === -1, vendored.top.join(" "));

  var covered = union([planted.actorFirst, planted.optsActor])
    .concat(Object.keys(UNGATED_BY_DESIGN));
  count("a verb a listener calls and the gate does not cover is reported by name",
    missingFrom(vendored.top, covered).join(" ") === "storeFlags",
    missingFrom(vendored.top, covered).join(" "));
  count("and so is a filter-script verb the gate does not cover",
    missingFrom(vendored.sieve, planted.sieve).join(" ") === "rename",
    missingFrom(vendored.sieve, planted.sieve).join(" "));

  var plantedRaw = adapterCallsIn(PLANTED_LISTENER, RAW_HANDLE);
  var live = union([vendored.top, plantedRaw.top]);
  count("a gated verb nothing reaches is reported by name, so the list cannot grow entries " +
    "that make the coverage read wider than it is",
    missingFrom(union([planted.actorFirst, planted.optsActor]), live)
      .join(" ") === "reachedByNothing",
    missingFrom(union([planted.actorFirst, planted.optsActor]), live).join(" "));

  var past = plantedRaw.top.filter(function (name) {
    return union([planted.actorFirst, planted.optsActor]).indexOf(name) !== -1 &&
      !Object.prototype.hasOwnProperty.call(RAW_ADAPTER_BY_DESIGN, name);
  });
  count("and a handler reaching a gated verb through the raw adapter is reported by name",
    past.join(" ") === "listFolders", past.join(" "));
}

// ---- the cases -------------------------------------------------------------

function theGateDeclaresWhatItCovers(gate) {
  count("lib/mail/listeners.js declares which adapter verbs a signed-in session's commands " +
    "are gated on, under the names this file reads them by",
    gate.actorFirst !== null && gate.sieve !== null && gate.optsActor !== null,
    "actor-first: " + (gate.actorFirst === null ? "not found" : gate.actorFirst.length) +
    ", sieve: " + (gate.sieve === null ? "not found" : gate.sieve.length) +
    ", actor-on-options: " + (gate.optsActor === null ? "not found" : gate.optsActor.length));
  if (gate.actorFirst === null || gate.sieve === null || gate.optsActor === null) return false;
  count("and none of the three is empty, so this file is reading a gate rather than " +
    "reporting a clean verdict over nothing",
    gate.actorFirst.length > 0 && gate.sieve.length > 0 && gate.optsActor.length > 0,
    gate.actorFirst.length + " + " + gate.sieve.length + " + " + gate.optsActor.length +
    " verbs examined");
  return true;
}

function everyVerbTheListenersCallIsGated(called, gate) {
  var covered   = union([gate.actorFirst, gate.optsActor]);
  var exempt    = Object.keys(UNGATED_BY_DESIGN);
  var uncovered = missingFrom(called.top, covered.concat(exempt));
  count("every adapter verb the vendored IMAP, POP3 and ManageSieve listeners call is " +
    "either gated on the account or named as ungated with a reason",
    uncovered.length === 0,
    uncovered.length === 0
      ? called.top.length + " verbs examined: " + called.top.join(" ")
      : "reaches the mailbox with nobody re-reading the account: " + uncovered.join(" "));

  var uncoveredScripts = missingFrom(called.sieve, gate.sieve);
  count("and every filter-script verb ManageSieve calls is gated the same way",
    uncoveredScripts.length === 0,
    uncoveredScripts.length === 0
      ? called.sieve.length + " verbs examined: " + called.sieve.join(" ")
      : "reaches the scripts with nobody re-reading the account: " + uncoveredScripts.join(" "));
}

function everyGatedVerbIsReachedBySomething(called, listenerCalls, gatedCalls, gate) {
  var live   = union([called.top, listenerCalls.top, gatedCalls.top]);
  var gated  = union([gate.actorFirst, gate.optsActor]);
  var unused = missingFrom(gated, live);
  count("every gated verb is one a listener actually calls, so the list cannot carry " +
    "entries that make the coverage read wider than it is",
    unused.length === 0,
    unused.length === 0
      ? gated.length + " verbs examined"
      : "gated and reached by nothing: " + unused.join(" "));

  var liveScripts   = union([called.sieve, listenerCalls.sieve, gatedCalls.sieve]);
  var unusedScripts = missingFrom(gate.sieve, liveScripts);
  count("and so is every gated filter-script verb",
    unusedScripts.length === 0,
    unusedScripts.length === 0
      ? gate.sieve.length + " verbs examined"
      : "gated and reached by nothing: " + unusedScripts.join(" "));
}

function noHandlerReachesPastTheGate(listenerCalls, gate) {
  var gated = union([gate.actorFirst, gate.optsActor]);
  var past  = listenerCalls.top.filter(function (name) {
    return gated.indexOf(name) !== -1 &&
      !Object.prototype.hasOwnProperty.call(RAW_ADAPTER_BY_DESIGN, name);
  });
  count("no handler in lib/mail/listeners.js reaches a gated verb through the raw adapter, " +
    "which is how one override at a time reopens what the gate closed",
    past.length === 0,
    past.length === 0
      ? listenerCalls.top.length + " raw adapter calls examined: " + listenerCalls.top.join(" ")
      : "reached through the raw adapter: " + past.join(" "));

  var pastScripts = listenerCalls.sieve.filter(function (name) {
    return gate.sieve.indexOf(name) !== -1;
  });
  count("and none reaches a gated filter-script verb that way either",
    pastScripts.length === 0,
    pastScripts.length === 0
      ? listenerCalls.sieve.length + " raw filter-script calls examined"
      : "reached through the raw adapter: " + pastScripts.join(" "));
}

// ---- runner ----------------------------------------------------------------

function run() {
  theReadersFindAPlantedHole();

  var listenerSource = nodeFs.readFileSync(LISTENERS, "utf8");

  var gate = {
    actorFirst: frozenListNamed(listenerSource, "SESSION_ACTOR_FIRST_VERBS"),
    sieve:      frozenListNamed(listenerSource, "SESSION_SIEVE_VERBS"),
    optsActor:  frozenKeysNamed(listenerSource, "SESSION_OPTS_ACTOR_VERBS"),
  };
  if (!theGateDeclaresWhatItCovers(gate)) return helpers.getChecks();

  var vendored = { top: [], sieve: [] };
  VENDORED_LISTENERS.forEach(function (name) {
    var read = adapterCallsIn(
      nodeFs.readFileSync(nodePath.join(helpers.VENDOR_ROOT, "lib", name), "utf8"),
      RAW_HANDLE);
    vendored.top   = union([vendored.top, read.top]);
    vendored.sieve = union([vendored.sieve, read.sieve]);
  });
  count("the vendored listeners were read and they call the adapter, so the comparison " +
    "below is against something", vendored.top.length > 0,
    VENDORED_LISTENERS.length + " sources, " + vendored.top.length + " verbs");

  var listenerCalls = adapterCallsIn(listenerSource, RAW_HANDLE);
  var gatedCalls    = adapterCallsIn(listenerSource, GATED_HANDLE);

  everyVerbTheListenersCallIsGated(vendored, gate);
  everyGatedVerbIsReachedBySomething(vendored, listenerCalls, gatedCalls, gate);
  noHandlerReachesPastTheGate(listenerCalls, gate);

  return helpers.getChecks();
}

module.exports = {
  name:      "session-store-gate-coverage",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  try {
    console.log("CHECKS " + run());
  } catch (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  }
}
