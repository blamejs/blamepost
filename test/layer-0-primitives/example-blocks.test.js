// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * example-blocks: `scripts/validate-source-comment-blocks.js` checks the
 * `@example` bodies of each primitive block, and reads the `@opts` and
 * `@example` bodies for a description line written after a multi-line tag.
 *
 * Each vector writes a fixture tree holding one module block and one
 * primitive block that pass every other rule, changes the examples or the
 * options, and runs the gate over the tree. The gate must report exactly the
 * findings the vector is about:
 *
 *   - a primitive block with no `@example`;
 *   - an example that does not compile, a second example that does not
 *     compile after a first that does, and a sentence written as an example;
 *   - an example carrying each mark in EXAMPLE_MARKERS, with one vector for
 *     every mark the gate declares;
 *   - a sentence inside an `@opts` body.
 *
 * The canaries run the same tree with examples that must pass. Two of them
 * compile only as the body of an async function: a top-level `await` and a
 * top-level `return`. Each is first shown to be refused by the compiler as a
 * plain script, so a gate that passes them compiled them inside the wrapper
 * it documents. A body the compiler refuses in any form is shown refused
 * through the gate's own compile function, so a compile step that accepted
 * everything fails here. Examples that resemble a mark without being one
 * pass as well.
 *
 * The gate is also run over this repository's lib/. It must report no
 * example or ordering finding, and the counts it publishes must equal the
 * numbers the shared reader gives for the same tree.
 *
 * Run standalone: node test/layer-0-primitives/example-blocks.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeVm   = require("node:vm");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");
var gate     = require("../../scripts/validate-source-comment-blocks.js");

var sourcePrimitives = require("../../scripts/source-primitives.js");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var REPO_ROOT      = helpers.REPO_ROOT;
var RUN_CEILING_MS = 60000;

var MODULE_TOKEN    = "blamepost.fixture.widgets";
var PRIMITIVE_TOKEN = MODULE_TOKEN + ".spin";
var FIXTURE_FILE    = "lib/widgets.js";

var EXAMPLE_UNITS = [
  "primitives-checked-for-an-example",
  "examples-parse-checked",
  "example-marker-scans",
  "tag-bodies-read-for-prose",
];

// The option lines and the example of a block that passes every check. A
// vector passes its own lists in place of these.
var GOOD_OPTS = Object.freeze(["speed: number,   // turns for each call, default 1"]);
var GOOD_EXAMPLE = Object.freeze([
  "var turns = widgets.spin(3, { speed: 2 });",
  "turns;",
  "// 3",
]);

// ---- fixtures -------------------------------------------------------------

function _write(root, rel, text) {
  var abs = nodePath.join(root, rel);
  nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
  nodeFs.writeFileSync(abs, text, "utf8");
}

var MODULE_BLOCK = [
  "/**",
  " * @module   " + MODULE_TOKEN,
  " * @nav      " + gate.NAV_GROUPS[0],
  " * @title    Widgets",
  " *",
  " * @intro",
  " *   The fixture module, described at enough length to read as an overview.",
  " */",
].join("\n");

// The primitive block over `spin`. `examples` is a list of example bodies,
// each a list of lines, and `opts` is a list of option lines or null.
function _primitiveBlock(examples, opts) {
  var lines = [
    "/**",
    " * @primitive " + PRIMITIVE_TOKEN,
    " * @signature widgets.spin(count, opts)",
    " * @since     0.1.0",
    " * @status    experimental",
    " * @spec      internal (design: fixture)",
    " *",
    " * Spins the fixture widget the given number of times and returns the count.",
  ];
  if (opts !== null) {
    lines.push(" *", " * @opts");
    opts.forEach(function (l) { lines.push(" *   " + l); });
  }
  examples.forEach(function (body) {
    lines.push(" *", " * @example");
    body.forEach(function (l) { lines.push(" *   " + l); });
  });
  lines.push(" */", "function spin(count, opts) {", "  return [count, opts];", "}");
  return lines.join("\n");
}

// The source of lib/widgets.js for one vector.
function _source(examples, opts) {
  return ["\"use strict\";", MODULE_BLOCK, "", _primitiveBlock(examples, opts), "",
    "module.exports = { spin: spin };", ""].join("\n");
}

// The 1-based line of the primitive block's opener in `source`.
function _openerLine(source) {
  return source.split("\n").indexOf(" * @primitive " + PRIMITIVE_TOKEN);
}

// Runs the gate over a tree whose lib/widgets.js is `_source(examples, opts)`
// and whose test corpus names the primitive. `opts` defaults to GOOD_OPTS.
function _validate(prefix, examples, opts) {
  var root = helpers.tempDir(prefix);
  var source = _source(examples, opts === undefined ? GOOD_OPTS : opts);
  try {
    _write(root, FIXTURE_FILE, source);
    _write(root, "test/widgets.test.js", "// Drives " + PRIMITIVE_TOKEN + ".\n");
    var result = gate.validate({ root: root });
    result.openerLine = _openerLine(source);
    return result;
  } finally {
    helpers.removeTempDir(root);
  }
}

function _kinds(result) {
  return result.findings.map(function (f) { return f.kind; }).sort();
}

function _only(result, kinds) {
  return JSON.stringify(_kinds(result)) === JSON.stringify(kinds.slice().sort());
}

function _names(result, f) {
  return f !== undefined && f.file === FIXTURE_FILE && f.primitive === PRIMITIVE_TOKEN &&
    f.line === result.openerLine;
}

// True when `text` compiles as a script of its own.
function _compilesAsScript(text) {
  try {
    void new nodeVm.Script(text, { filename: "fixture.js" });
    return true;
  } catch (_e) {
    return false;
  }
}

// ---- canaries -------------------------------------------------------------

function aBlockWithAnExampleThatCompilesPasses() {
  var result = _validate("examples-good", [GOOD_EXAMPLE]);
  count("canary: a block with options and an example that compiles passes",
    result.findings.length === 0, JSON.stringify(result.findings));
  count("canary: the one block was checked for an example and its example compiled",
    result.examined["primitive-blocks"] === 1 &&
    result.examined["primitives-checked-for-an-example"] === 1 &&
    result.examined["examples-parse-checked"] === 1, JSON.stringify(result.examined));
  count("canary: every mark was tested against the example",
    gate.EXAMPLE_MARKERS.length > 0 &&
    result.examined["example-marker-scans"] === gate.EXAMPLE_MARKERS.length, JSON.stringify(result.examined));
  count("canary: the options body and the example body were both read for a sentence",
    result.examined["tag-bodies-read-for-prose"] === 2, JSON.stringify(result.examined));
}

function theCompileCheckCompilesTheBodyInsideAnAsyncFunction() {
  var ONLY_IN_AN_ASYNC_BODY = [
    { name: "a top-level await",
      body: ["var zone = await client.zoneId(\"example.com\");", "zone;"] },
    { name: "a top-level return",
      body: ["if (!ready) return;", "widgets.spin(1, {});"] },
  ];
  ONLY_IN_AN_ASYNC_BODY.forEach(function (v) {
    var text = v.body.join("\n");
    count("compile canary: " + v.name + " is refused by the compiler as a plain script",
      _compilesAsScript(text) === false, text);
    count("compile canary: " + v.name + " compiles through the gate's own compile function",
      gate.compileExample(text) === null, String(gate.compileExample(text)));
    var result = _validate("examples-async", [v.body]);
    count("compile canary: an example holding " + v.name + " passes the gate",
      result.findings.length === 0 && result.examined["examples-parse-checked"] === 1,
      JSON.stringify(result.findings) + " " + JSON.stringify(result.examined));
  });

  var awaitText = ONLY_IN_AN_ASYNC_BODY[0].body.join("\n");
  count("compile canary: a top-level await is refused inside a function that is not async",
    _compilesAsScript("(function () {\n" + awaitText + "\n});") === false, awaitText);

  ["var turns = ;", "widgets.spin(3, {", "}"].forEach(function (text) {
    var refusal = gate.compileExample(text);
    count("compile canary: `" + text + "` is refused by the gate's own compile function",
      typeof refusal === "string" && refusal.length > 0, String(refusal));
  });
}

function examplesThatResembleAMarkPass() {
  var RESEMBLING = [
    { name: "a comparison and a result comment",
      body: ["var turns = widgets.spin(3, {});", "turns >= 3;", "// true"] },
    { name: "lower case markup inside a string",
      body: ["widgets.spin(3, { label: \"<b>bold</b>\" });"] },
    { name: "an ellipsis inside a result comment",
      body: ["blocks.relative(file);   // \"lib/...\""] },
    { name: "a comment that is a full sentence",
      body: ["// Spin three times.", "widgets.spin(3, {});"] },
  ];
  RESEMBLING.forEach(function (v) {
    var result = _validate("examples-resemble", [v.body]);
    count("canary: an example holding " + v.name + " passes",
      result.findings.length === 0, JSON.stringify(result.findings));
  });

  var sentenceComment = _validate("examples-optscomment",
    [GOOD_EXAMPLE], ["speed: number,   // Turns for each call.", "// Defaults to one turn."]);
  count("canary: an options body whose sentences are comments passes",
    sentenceComment.findings.length === 0, JSON.stringify(sentenceComment.findings));
}

// ---- refusals -------------------------------------------------------------

function aPrimitiveWithNoExampleIsRefused() {
  var result = _validate("examples-none", []);
  count("missing: a primitive block with no @example is refused, and nothing else is",
    _only(result, ["missing-example"]), JSON.stringify(result.findings));
  var f = result.findings[0];
  count("missing: the finding names the file, the block's line and the primitive",
    _names(result, f), JSON.stringify(f) + " opener " + result.openerLine);
  count("missing: the finding says to add an example written against the signature",
    f !== undefined && f.msg.indexOf("@example") !== -1 && f.msg.indexOf("@signature") !== -1,
    f && f.msg);
  count("missing: the block was checked, no body was compiled, and the options body was read",
    result.examined["primitives-checked-for-an-example"] === 1 &&
    result.examined["examples-parse-checked"] === 0 &&
    result.examined["example-marker-scans"] === 0 &&
    result.examined["tag-bodies-read-for-prose"] === 1, JSON.stringify(result.examined));
}

function anExampleThatDoesNotCompileIsRefused() {
  var broken = ["var turns = widgets.spin(3, { speed: 2 };", "turns;"];
  var result = _validate("examples-broken", [broken]);
  count("compile: an example that does not compile is refused, and nothing else is",
    _only(result, ["example-does-not-parse"]), JSON.stringify(result.findings));
  var f = result.findings[0];
  var compilerSays = null;
  try {
    void new nodeVm.Script("(async function () {\n" + broken.join("\n") + "\n});");
  } catch (e) {
    compilerSays = e.message;
  }
  count("compile: the finding names the file, the block's line and the primitive",
    _names(result, f), JSON.stringify(f) + " opener " + result.openerLine);
  count("compile: the finding numbers the example and quotes the compiler's message",
    f !== undefined && typeof compilerSays === "string" && f.msg.indexOf("@example #1") !== -1 &&
    f.msg.indexOf(compilerSays) !== -1, (f && f.msg) + " / compiler: " + compilerSays);

  var second = _validate("examples-second", [GOOD_EXAMPLE, ["widgets.spin(3, {"]]);
  count("compile: a second example that does not compile is refused under its own number",
    _only(second, ["example-does-not-parse"]) && second.findings[0].msg.indexOf("@example #2") !== -1,
    JSON.stringify(second.findings));
  count("compile: both examples were compiled and every mark was tested against each",
    second.examined["examples-parse-checked"] === 2 &&
    second.examined["example-marker-scans"] === 2 * gate.EXAMPLE_MARKERS.length,
    JSON.stringify(second.examined));

  var sentence = _validate("examples-sentence", [["Spins the widget three times."]]);
  count("compile: a sentence written as an example is refused as code and as a sentence",
    _only(sentence, ["example-does-not-parse", "prose-after-multi-line-tag"]),
    JSON.stringify(sentence.findings));
}

// One vector for each mark. The unfinished-work comment is built from two
// string halves, because the unfinished-work detector scans this file.
var MARK_VECTORS = [
  { id: "ascii-arrow",     body: ["widgets.spin(3, {});", "// > 3"] },
  { id: "unfinished-work", body: ["widgets.spin(3, {});   // TO" + "DO choose a count"] },
  { id: "pseudocode",      body: ["// pseudocode", "widgets.spin(count, {});"] },
  { id: "fill-in",         body: ["widgets.spin(3, { speed: speed });   // ... fill in the speed"] },
  { id: "angle-bracket",   body: ["widgets.spin(\"<COUNT>\", {});"] },
  { id: "replace-me",      body: ["widgets.spin([REPLACE-ME], {});"] },
];

function anExampleCarryingEachMarkIsRefused() {
  var declared = gate.EXAMPLE_MARKERS.map(function (m) { return m.id; }).sort();
  var covered = MARK_VECTORS.map(function (v) { return v.id; }).sort();
  count("marks: every mark the gate declares has a vector here, and no vector names another",
    declared.length > 0 && JSON.stringify(declared) === JSON.stringify(covered),
    "declared " + JSON.stringify(declared) + ", covered " + JSON.stringify(covered));

  MARK_VECTORS.forEach(function (v) {
    var text = v.body.join("\n");
    count("marks: the " + v.id + " vector compiles, so only its mark can refuse it",
      gate.compileExample(text) === null, String(gate.compileExample(text)));
    var result = _validate("examples-mark", [v.body]);
    count("marks: an example carrying the " + v.id + " mark is refused, and nothing else is",
      _only(result, ["example-marker"]), JSON.stringify(result.findings));
    var f = result.findings[0];
    count("marks: the " + v.id + " finding names the mark and the block",
      _names(result, f) && f.msg.indexOf(v.id) !== -1 && f.msg.indexOf("@example #1") !== -1,
      JSON.stringify(f));
  });
}

function aSentenceInsideAnOptionsBodyIsRefused() {
  var opts = ["speed: number,   // turns for each call, default 1", "Spins faster when speed is higher."];
  var result = _validate("examples-optsprose", [GOOD_EXAMPLE], opts);
  count("ordering: a sentence inside an @opts body is refused, and nothing else is",
    _only(result, ["prose-after-multi-line-tag"]), JSON.stringify(result.findings));
  var f = result.findings[0];
  count("ordering: the finding names the block, the tag and the sentence",
    _names(result, f) && f.msg.indexOf("@opts") !== -1 &&
    f.msg.indexOf("Spins faster when speed is higher.") !== -1, JSON.stringify(f));
}

// ---- this repository ------------------------------------------------------

function _examined(stdout) {
  var out = {};
  String(stdout).split(/\r?\n/).forEach(function (line) {
    var m = /^EXAMINED\s+(\d+)\s+([a-z0-9-]+)$/.exec(line.trim());
    if (m) out[m[2]] = Number(m[1]);
  });
  return out;
}

async function theLiveTreeCarriesAnExampleOnEveryPrimitiveAndSaysSo() {
  var result = gate.validate();
  var kinds = gate.EXAMPLE_FINDING_KINDS.concat(gate.ORDERING_FINDING_KINDS);
  var found = result.findings.filter(function (f) { return kinds.indexOf(f.kind) !== -1; });
  count("live tree: no example finding and no ordering finding",
    found.length === 0, found.map(function (f) {
      return f.kind + " " + f.file + ":" + f.line + " " + f.primitive;
    }).join("; "));

  var records = sourcePrimitives.collectPrimitives();
  var examples = 0;
  var optsBodies = 0;
  records.forEach(function (p) {
    examples += p.examples.length;
    if (typeof p.opts === "string") optsBodies += 1;
  });
  var expected = {
    "primitives-checked-for-an-example": records.length,
    "examples-parse-checked":            examples,
    "example-marker-scans":              examples * gate.EXAMPLE_MARKERS.length,
    "tag-bodies-read-for-prose":         examples + optsBodies,
  };
  count("live tree: the reader returned primitives, examples and options bodies to check",
    records.length > 0 && examples > 0 && optsBodies > 0,
    records.length + " primitives, " + examples + " examples, " + optsBodies + " options bodies");
  count("live tree: every primitive carries at least one example",
    records.every(function (p) { return p.examples.length > 0; }),
    records.filter(function (p) { return p.examples.length === 0; })
      .map(function (p) { return p.token; }).join(", "));
  EXAMPLE_UNITS.forEach(function (unit) {
    count("live tree: " + unit + " equals the number the shared reader gives",
      result.examined[unit] === expected[unit],
      "gate " + result.examined[unit] + ", reader " + expected[unit]);
  });

  var run = await spawnRun.runNodeScript(
    [nodePath.join(REPO_ROOT, "scripts", "validate-source-comment-blocks.js")],
    { cwd: REPO_ROOT, ceilingMs: RUN_CEILING_MS });
  var published = _examined(run.out);
  EXAMPLE_UNITS.forEach(function (unit) {
    count("live tree: the gate publishes " + unit,
      published[unit] === expected[unit], tail(run.out, 12));
  });
  var units = Object.keys(result.examined);
  var lines = String(run.out).trim().split(/\r?\n/).slice(-units.length);
  count("live tree: every published count is among the last lines of stdout, in order",
    lines.length === units.length && lines.every(function (l, i) {
      var parts = l.trim().split(/\s+/);
      return parts.length === 3 && parts[0] === "EXAMINED" && /^\d+$/.test(parts[1]) && parts[2] === units[i];
    }), tail(run.out, units.length + 1));
}

// ---- runner ---------------------------------------------------------------

async function run() {
  aBlockWithAnExampleThatCompilesPasses();
  theCompileCheckCompilesTheBodyInsideAnAsyncFunction();
  examplesThatResembleAMarkPass();
  aPrimitiveWithNoExampleIsRefused();
  anExampleThatDoesNotCompileIsRefused();
  anExampleCarryingEachMarkIsRefused();
  aSentenceInsideAnOptionsBodyIsRefused();
  await theLiveTreeCarriesAnExampleOnEveryPrimitiveAndSaysSo();
  return helpers.getChecks();
}

module.exports = { name: "example-blocks", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
