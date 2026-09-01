// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * helpers-single-source: one reader per thing the tests read.
 *
 * A test helper that gets copied does not stay a copy. The two versions
 * drift, and the moment they disagree about what a greeting, a sign-in
 * or a boot transcript looks like, one of them stops catching things
 * while still reporting green. That failure is invisible from either
 * file on its own, because each one passes.
 *
 * The boot-line filter is the case this file was written for. The
 * framework writes JSON log lines around every command, and they have to
 * come out of a transcript before anything is asserted about it:
 * otherwise a log line can satisfy a check about what the operator was
 * told, and the check passes on output the operator never gets. Three
 * separate copies of that filter existed, one of them reachable only
 * through a container. Whichever copy someone corrects, the other two
 * keep the old behavior.
 *
 * What is asserted:
 *
 *   - `test/helpers/cli.js` exports the filter, so there is something to
 *     share rather than a private function each caller must re-derive.
 *   - The filter removes framework boot lines and leaves operator output
 *     alone, including a body that is itself JSON.
 *   - Every other caller holds the SAME function object. Behavioral
 *     equivalence is not enough: two functions that agree today are
 *     exactly the pair that drifts tomorrow, and identity is what a
 *     re-added private copy fails.
 *   - No second boot-line filter exists anywhere under `test/`. This is
 *     anchored on the framework's log-line prefix, which is a frozen
 *     shape rather than a renameable symbol, so the check survives every
 *     helper rename and fails on a fresh copy under any name.
 *   - The same question for the two other readers that had drifted: the
 *     assertion that quotes a failing value, and the SASL PLAIN encoder
 *     that says what a sign-in looks like on the wire.
 *   - Every resolver builder in `test/helpers/dns-zone.js` honors the
 *     same markers. Three builders read one zone vocabulary, and a
 *     marker each of them tests for itself is a marker one of them can
 *     be handed and quietly not honor. That is the worst thing a fixture
 *     can do: a stall fixture that answers immediately leaves the test
 *     which asked for a stall passing without one.
 *
 * Two files are allowed their own credential bytes and both are named
 * below with the reason. Neither is a copy of a convenience: one is
 * testing the encoding itself and must not use the shared helper as its
 * own oracle, and the other decodes rather than encodes.
 *
 * Each source scan carries a canary, so a matcher that has quietly
 * stopped matching fails here rather than reporting a clean tree.
 *
 * No sockets, no containers, no disk beyond reading source text.
 *
 * Run standalone: node test/layer-0-primitives/helpers-single-source.test.js
 */

var helpers = require("../helpers");
var cli     = require("../helpers/cli");
var wire    = require("../helpers/wire");
var dnsZone = require("../helpers/dns-zone");
var harness = require("../layer-2-integration/container-harness");

var check = helpers.check;
var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var TEST_ROOT = path.join(helpers.REPO_ROOT, "test");

// The framework's boot lines are JSON objects whose first key is
// `timestamp`, measured against the shipped binary rather than assumed:
// every line the framework emits around a command starts with this, and
// no line an operator reads does. A CLI verb that prints JSON pretty
// prints it, so its first line is a bare brace and never collides.
//
// This is the RUNTIME form, for asserting on a transcript.
var BOOT_PREFIX = "{\"timestamp\"";

// And this is the SOURCE form, for finding a copy of the filter in a
// file. The two are not the same bytes and assuming they were is how the
// first version of this scan passed over a planted copy: a source file
// spells the prefix inside a double quoted literal, so the inner quote
// arrives escaped as a backslash. Searching source for the runtime
// string matches nothing, anywhere, ever, and reports a clean tree.
// The optional backslash covers both spellings.
var BOOT_PREFIX_IN_SOURCE = /\{\\?"timestamp/;

// Files allowed to carry the prefix. `helpers/cli.js` owns the filter;
// this file quotes it in order to search for it.
var PREFIX_OWNERS = [
  path.join("test", "helpers", "cli.js"),
  path.join("test", "layer-0-primitives", "helpers-single-source.test.js"),
];

// How long a call is watched before it counts as unanswered.
//
// The window only has to outlast a settlement, never a stall. A promise
// that is already resolved or already rejected runs its continuation on
// the next microtask tick, which is ahead of any timer, so a builder
// that answers is seen answering however loaded the runner is. Nothing
// here waits for the window unless the call genuinely never comes back.
var MARKER_WINDOW_MS = 150;

// What a call that never came back is reported as, kept as an object
// identity so it cannot collide with a value a builder answered with.
var PENDING = { pending: true };

// Whether a call settled at all, and how.
//
// One builder answers through an `async` function and another through a
// synchronous `query` that throws, so a throw on the way in is an
// outcome rather than a fault in the observation.
function outcomeOf(makeCall, label) {
  var call;
  try { call = Promise.resolve(makeCall()); }
  catch (thrown) { return Promise.resolve({ settled: true, error: thrown }); }
  return Promise.race([
    call.then(
      function (value) { return { settled: true, value: value }; },
      function (err)   { return { settled: true, error: err }; }
    ),
    helpers.passiveObserve(MARKER_WINDOW_MS, label).then(function () { return PENDING; }),
  ]);
}

// An outcome in one line of a failure log, so a builder that answered
// says what it answered rather than printing as an empty object.
function describeOutcome(outcome) {
  if (outcome === PENDING) return "still unanswered";
  if (outcome.error) {
    return "raised " + ((outcome.error && outcome.error.code) || String(outcome.error));
  }
  return "answered " + JSON.stringify(outcome.value);
}

function listJsFiles(dir, acc) {
  acc = acc || [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    var full = path.join(dir, entry.name);
    if (entry.isDirectory()) return void listJsFiles(full, acc);
    if (entry.isFile() && full.endsWith(".js")) acc.push(full);
  });
  return acc;
}

async function run() {
  // ---- The filter is shared surface ----

  check("test/helpers/cli.js exports withoutBootLines",
    typeof cli.withoutBootLines === "function");

  // ---- It removes what it claims to, and nothing else ----

  var transcript = [
    "{\"timestamp\":\"2026-08-24T15:13:05.449Z\",\"level\":\"info\",\"message\":\"first boot\"}",
    "address              status",
    "{\"timestamp\":\"2026-08-24T15:13:05.531Z\",\"level\":\"info\",\"message\":\"ntp: ok\"}",
    "alice@example.com    active",
  ].join("\n");

  var cleaned = cli.withoutBootLines(transcript);

  count("the filter removes every framework boot line",
    cleaned.indexOf(BOOT_PREFIX) === -1, cleaned);
  count("the filter keeps the operator's header row",
    cleaned.indexOf("address              status") !== -1, cleaned);
  count("the filter keeps the operator's data row",
    cleaned.indexOf("alice@example.com    active") !== -1, cleaned);

  // A verb that prints JSON pretty prints it, so the body opens with a
  // bare brace. Stripping that would delete the answer the verb gave.
  var jsonBody = ["{", "  \"timestamp\": \"kept\",", "  \"hostname\": \"mx.example.com\"", "}"].join("\n");
  var keptJson = cli.withoutBootLines(jsonBody);
  count("a pretty printed JSON body survives the filter intact",
    keptJson === jsonBody, keptJson);

  // Absent and empty input are ordinary here rather than a fault: a
  // command that wrote nothing to a stream hands this an empty string.
  check("the filter tolerates an absent stream", cli.withoutBootLines(undefined) === "");
  check("the filter tolerates an empty stream", cli.withoutBootLines("") === "");

  // ---- Every caller holds the same function ----

  count("the container harness reuses the helper's filter rather than a copy",
    harness.withoutBootLines === cli.withoutBootLines,
    typeof harness.withoutBootLines);

  // ---- No second copy anywhere under test/ ----

  // Canary first. A scan that has stopped matching reports the same
  // clean tree as one with nothing to find, and this one already did
  // exactly that once.
  check("the boot-prefix matcher fires on the escaped source spelling",
    BOOT_PREFIX_IN_SOURCE.test("var P = \"{\\\"timestamp\\\"\";"));
  check("the boot-prefix matcher fires on the bare spelling",
    BOOT_PREFIX_IN_SOURCE.test("var P = '{\"timestamp\"';"));
  check("the boot-prefix matcher is silent on ordinary source",
    BOOT_PREFIX_IN_SOURCE.test("var P = \"{\\\"level\\\"\";") === false);

  var offenders = [];
  listJsFiles(TEST_ROOT).forEach(function (full) {
    var rel = path.relative(helpers.REPO_ROOT, full);
    if (PREFIX_OWNERS.indexOf(rel) !== -1) return;
    if (BOOT_PREFIX_IN_SOURCE.test(fs.readFileSync(full, "utf8"))) offenders.push(rel);
  });

  count("no file under test/ carries a second boot-line filter. " +
    "The filter lives in test/helpers/cli.js and is imported from there, " +
    "because two filters that disagree let a log line satisfy a check " +
    "about what the operator was told",
  offenders.length === 0, offenders.join(", ") || "none");

  // ---- The assertion helper is shared too ----

  // `count` already lives in test/helpers. A file that redefines it
  // privately is a second assertion with its own idea of how much of the
  // failing value to quote, which is how a failure log stops carrying
  // the part that explains it.
  var LOCAL_COUNT_RE = /^function count\(label, condition, detail\)/m;
  var countCopies = [];
  listJsFiles(TEST_ROOT).forEach(function (full) {
    var rel = path.relative(helpers.REPO_ROOT, full);
    if (rel === path.join("test", "helpers", "index.js")) return;
    if (rel === path.join("test", "layer-0-primitives", "helpers-single-source.test.js")) return;
    if (LOCAL_COUNT_RE.test(fs.readFileSync(full, "utf8"))) countCopies.push(rel);
  });

  count("no test file redefines count() privately. " +
    "helpers.count is the shared assertion and takes a detail bound, " +
    "so a caller that wants more of the value passes it rather than " +
    "forking the function",
  countCopies.length === 0, countCopies.join(", ") || "none");

  // The bound is a documented parameter rather than a per-file constant.
  // The two bounds that used to exist in the tree differed by accident,
  // so the default keeps the more generous one and no caller lost any
  // of the value its failures quote.
  var longDetail = "y".repeat(600);
  var threw = false;
  try { helpers.count("limit is a parameter", true, longDetail, { limit: 500 }); }
  catch (_e) { threw = true; }
  check("count takes a documented detail bound", threw === false);

  var refused = false;
  try { helpers.count("bad bound", true, "x", { limit: -1 }); }
  catch (_e2) { refused = true; }
  check("count refuses a non-positive detail bound", refused);

  // ---- One encoder for what a sign-in looks like ----

  check("test/helpers/wire.js exports saslPlain",
    typeof wire.saslPlain === "function");

  // Built here from its code point rather than taken from the helper, so
  // this comparison is an independent statement of RFC 4616 section 2
  // and not the encoder agreeing with itself.
  var sep = String.fromCharCode(0);
  var expected = Buffer.from(sep + "alice@example.com" + sep + "pw", "utf8")
    .toString("base64");
  count("saslPlain produces the RFC 4616 section 2 encoding",
    wire.saslPlain("alice@example.com", "pw") === expected,
    wire.saslPlain("alice@example.com", "pw"));

  // Stronger than the copies it replaced, which took anything: a
  // credential built from an undefined password would otherwise sign in
  // as the four characters "undefined".
  var rejected = false;
  try { wire.saslPlain("alice@example.com", undefined); }
  catch (_e3) { rejected = true; }
  check("saslPlain refuses a non-string credential", rejected);

  // ---- No second SASL PLAIN encoder ----

  // The shape rather than a name: a four term concatenation encoded to
  // base64. A copy under any name matches; a rename of the helper does
  // not stop it matching.
  var ENCODER_RE =
    /Buffer\.from\(\s*\w+\s*\+\s*\w+\s*\+\s*\w+\s*\+\s*\w+\s*,\s*"utf8"\s*\)\s*\n?\s*\.toString\("base64"\)/;

  // Canary: a matcher that has stopped matching would report a clean
  // tree, which is the worst way for this check to fail.
  check("the encoder matcher fires on a planted copy",
    ENCODER_RE.test("Buffer.from(N + a + N + p, \"utf8\").toString(\"base64\")"));
  check("the encoder matcher is silent on ordinary code",
    ENCODER_RE.test("Buffer.from(body, \"utf8\").toString(\"base64\")") === false);

  // wire.js owns the encoder. Two files build credential bytes for
  // reasons that are not convenience, and neither may be quietly turned
  // into a third copy without this list saying so.
  var ENCODER_OWNERS = {};
  ENCODER_OWNERS[path.join("test", "helpers", "wire.js")] =
    "owns the encoder";
  ENCODER_OWNERS[path.join("test", "layer-2-integration", "wire-sasl-canonical.test.js")] =
    "the encoding itself is what this file tests, so its expected bytes " +
    "are built by hand rather than taken from the helper it is checking";
  ENCODER_OWNERS[path.join("test", "layer-0-primitives", "helpers-single-source.test.js")] =
    "quotes the shape in order to search for it";

  var encoderCopies = [];
  listJsFiles(TEST_ROOT).forEach(function (full) {
    var rel = path.relative(helpers.REPO_ROOT, full);
    if (Object.prototype.hasOwnProperty.call(ENCODER_OWNERS, rel)) return;
    if (ENCODER_RE.test(fs.readFileSync(full, "utf8"))) encoderCopies.push(rel);
  });

  count("no test file rolls its own SASL PLAIN encoder. " +
    "wire.saslPlain is the one statement of what a credential looks " +
    "like on the wire, and two files that disagree about it is how a " +
    "sign-in test stops testing the sign-in",
  encoderCopies.length === 0, encoderCopies.join(", ") || "none");

  // ---- no test file defines a function a helper already exports ----

  // The three checks above each name ONE reader and hunt for copies of
  // it. That catches a copy of something somebody thought to write a
  // check for, and it is silent on every other helper, which is how
  // three functions called `installRemovalFault` came to exist in this
  // tree, two of them patching `fs.promises.rm` and the third patching
  // `fs.rmSync`, so the same name meant two different faults. Every
  // check in this file passed on that, because none of them was about
  // that name.
  //
  // So the question is asked generally instead, off the helper module's
  // OWN export table rather than off a hand-written list of names to
  // watch. A helper gains an export and this gate starts guarding it
  // with no second edit, which is the property the three checks above do
  // not have.
  //
  // A shadowing definition is a finding whichever way it is resolved,
  // and the two ways are opposite. If it does the same thing, it is a
  // copy and it drifts: import the helper. If it does something
  // DIFFERENT, importing it is worse than the copy, because folding it
  // in silently stops the file faulting anything while it goes on
  // reporting green: give it a name that says what it does.
  var HELPER_MODULES = [
    { rel: path.join("test", "helpers", "index.js"),    api: helpers },
    { rel: path.join("test", "helpers", "cli.js"),      api: cli },
    { rel: path.join("test", "helpers", "wire.js"),     api: wire },
    { rel: path.join("test", "helpers", "dns-zone.js"), api: dnsZone },
  ];

  var guardedNames = [];
  HELPER_MODULES.forEach(function (mod) {
    Object.keys(mod.api).forEach(function (name) {
      if (typeof mod.api[name] !== "function") return;
      if (guardedNames.indexOf(name) === -1) guardedNames.push(name);
    });
  });

  count("the shadowing check reads the helper modules' own exports, so a helper added " +
    "later is guarded without a second edit here",
  guardedNames.length > 0 && guardedNames.indexOf("installRemovalFault") !== -1,
  guardedNames.length + " exported function(s)");

  function definitionOf(name) {
    // A function declaration or a name bound to one. Both are a second
    // thing under a shared name; the binding form is how an alias for a
    // DIFFERENT helper reintroduces the collision this exists to stop.
    //
    // Anchored at column 0, which is the structural boundary that says
    // "module scope" in this tree. A `var` inside a function body is a
    // local reusing a common word, `var check = body.checks[...]` in a
    // reader, and it is visible to nothing outside its block, so it is
    // not a second helper under a shared name and must not be reported
    // as one. A check that always names the same innocent line is one
    // that gets skimmed.
    return new RegExp("^(?:function\\s+" + name + "\\s*\\(|var\\s+" + name + "\\s*=)", "m");
  }

  check("the shadowing matcher fires on a declaration",
    definitionOf("installRemovalFault").test("function installRemovalFault(fragment) {"));
  check("the shadowing matcher fires on a binding",
    definitionOf("installRemovalFault").test("var installRemovalFault = other.thing;"));
  check("the shadowing matcher is silent on a call",
    definitionOf("installRemovalFault").test("var f = installRemovalFault(id);") === false);
  check("the shadowing matcher is silent on a local inside a function body",
    definitionOf("check").test("function readOne(body) {\n  var check = body.checks.one;\n}")
      === false);

  // A file may bind a helper to its own name, which is an import rather
  // than a copy: `var count = helpers.count;` is the ordinary opening of
  // almost every file here. The module is bound under whatever local
  // name the file chose, so what is matched is the TAIL: a binding whose
  // property name is the same as the local name is that helper under its
  // own name and nothing else. `var installRemovalFault =
  // helpers.installSyncRemovalFault;` is not, and it is the exact shape
  // that puts two functions under one name.
  function bindsTheHelperItself(source, name) {
    return new RegExp("^var\\s+" + name + "\\s*=\\s*[\\w$.]*\\." + name + "\\s*;", "m")
      .test(source);
  }

  // Canaries for the exemption, both directions. A rule that let
  // everything through would report the same clean tree as one with
  // nothing to find, and the exemption is the half most likely to widen
  // by accident.
  check("the import exemption accepts a helper bound under its own name",
    bindsTheHelperItself("var installRemovalFault = anyLocal.installRemovalFault;",
      "installRemovalFault"));
  check("the import exemption refuses a different helper bound under that name",
    bindsTheHelperItself("var installRemovalFault = helpers.installSyncRemovalFault;",
      "installRemovalFault") === false);

  var shadows = [];
  listJsFiles(TEST_ROOT).forEach(function (full) {
    var rel = path.relative(helpers.REPO_ROOT, full);
    if (rel === path.join("test", "layer-0-primitives", "helpers-single-source.test.js")) return;
    for (var i = 0; i < HELPER_MODULES.length; i += 1) {
      if (rel === HELPER_MODULES[i].rel) return;
    }
    var source = fs.readFileSync(full, "utf8");
    guardedNames.forEach(function (name) {
      if (!definitionOf(name).test(source)) return;
      if (bindsTheHelperItself(source, name)) return;
      shadows.push(rel + ":" + name);
    });
  });

  count("no test file defines its own function under a name a shared helper already " +
    "exports. Two things under one name is the failure the copies above each get their " +
    "own check for, and it is worse than a plain copy when the two differ: the reader " +
    "who folds them together stops one of them faulting anything, and it goes on " +
    "reporting green. Import the helper when it is the same function, and rename when " +
    "it is not",
  shadows.length === 0, shadows.join(", ") || "none",
  // The whole list, because every entry is a separate decision about a
  // separate function and a truncated one sends the reader back for
  // another run to see the rest.
  { limit: 4000 });

  // ---- one marker vocabulary across every resolver builder ----

  // `test/helpers/dns-zone.js` builds three DNS handles over the same
  // zone tables and the same markers. The three answer in different
  // shapes because their consumers take different shapes, and that is
  // the whole reason they are separate functions. What they must not
  // differ about is which entries are markers at all.
  //
  // `FAILING` is a lookup that could not complete, and every builder
  // raises it. `HANGING` is a question accepted and never answered, and
  // it is the one entry that asks whether the caller holds a bound of
  // its own rather than what it does with an answer. A builder that
  // settles it does not merely answer differently, it deletes the
  // question: the caller gets a prompt reply, the bound never comes
  // near firing, and the test written to prove the bound exists reports
  // green against a fixture that never stalled.
  //
  // So both markers are asserted on all three builders rather than on
  // the one that introduced them.

  var STALLED = "stalled.example.com";

  var builders = [
    {
      name: "resolverOver",
      call: function (marker) {
        var z = {};
        z[STALLED] = marker;
        return dnsZone.resolverOver(z).queryTxt(STALLED);
      },
    },
    {
      name: "lookupOver",
      call: function (marker) {
        var z = {};
        z[STALLED] = marker;
        return dnsZone.lookupOver(z)(STALLED, "TXT");
      },
    },
    {
      name: "pinnedResolverOver",
      call: function (marker) {
        var z = {};
        z[STALLED + "|TXT"] = marker;
        return dnsZone.pinnedResolverOver(z).queryTxt(STALLED);
      },
    },
  ];

  var hanging = await Promise.all(builders.map(function (builder) {
    return outcomeOf(function () { return builder.call(dnsZone.HANGING); },
      "dns-zone " + builder.name + ": a HANGING entry must not answer");
  }));

  builders.forEach(function (builder, i) {
    count("dns-zone " + builder.name + " leaves a HANGING entry unanswered. " +
      "A builder that settles the marker hands a stall test a prompt reply, so " +
      "the bound it was written to prove is never asked for and the test passes " +
      "against a fixture that never stalled",
    hanging[i] === PENDING, describeOutcome(hanging[i]));
  });

  var failing = await Promise.all(builders.map(function (builder) {
    return outcomeOf(function () { return builder.call(dnsZone.FAILING); },
      "dns-zone " + builder.name + ": a FAILING entry must be raised");
  }));

  builders.forEach(function (builder, i) {
    var outcome = failing[i];
    count("dns-zone " + builder.name + " raises a FAILING entry as a lookup that " +
      "could not complete, under the code the shipped resolver uses for one",
    outcome !== PENDING && !!outcome.error &&
      outcome.error.code === "resolver/upstream-failed",
    describeOutcome(outcome));
  });

  // The structural half. The parity above says the three builders agree
  // today; this says they cannot quietly stop agreeing, because one
  // reader decides what a marker means rather than three. A marker added
  // to that reader is honored by every builder at once, which is exactly
  // the property that was missing when the second one was introduced.
  // Both directions of the comparison. A builder that reads a marker by
  // excluding it, the shape `entry !== FAILING && ...`, is reading it
  // just as much as one that matches it, and it was half of how the
  // second marker fell through: the exclusion named one marker and said
  // nothing about the other.
  var MARKER_READ_RE = /[=!]==\s*(?:FAILING|HANGING)\b/g;

  check("the marker matcher fires on a marker comparison",
    /[=!]==\s*(?:FAILING|HANGING)\b/.test("if (entry === HANGING) return unanswered();"));
  check("the marker matcher fires on a marker exclusion",
    /[=!]==\s*(?:FAILING|HANGING)\b/.test("if (entry !== FAILING && !rows.length) return null;"));
  check("the marker matcher is silent on ordinary source",
    /[=!]==\s*(?:FAILING|HANGING)\b/.test("if (entry === undefined) return null;") === false);

  var zoneSource = fs.readFileSync(path.join(TEST_ROOT, "helpers", "dns-zone.js"), "utf8");
  var markerReads = zoneSource.match(MARKER_READ_RE) || [];

  ["FAILING", "HANGING"].forEach(function (marker) {
    var reads = markerReads.filter(function (m) { return m.indexOf(marker) !== -1; });
    count("test/helpers/dns-zone.js reads " + marker + " in exactly one place. " +
      "Three builders each reading the markers for themselves is three chances to " +
      "be handed a new one and not honor it, and a fixture that does not do what " +
      "its marker says reports green from a test that proved nothing",
    reads.length === 1, reads.join(", ") + " (" + reads.length + " reads)");
  });
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
