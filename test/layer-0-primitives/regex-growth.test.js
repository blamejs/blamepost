// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * regex-growth: the gate that times every regex literal in lib/ and bin/
 * and refuses one whose cost grows faster than its input.
 *
 * The failure it covers was live in this tree. An HTML body was reduced to
 * text with a tag matcher carrying no start anchor, so a run of unclosed
 * angle brackets cost 22 ms at 8 KiB, 350 ms at 32 KiB and 5522 ms at
 * 128 KiB, against a stored body an unauthenticated sender may make 25 MiB
 * long, in a request handler with a five second budget. Nothing lexical
 * finds that: the pattern reads as ordinary and the input that hurts it is
 * one nobody writes by hand.
 *
 * WHAT IS DRIVEN, and why it is driven that way. The gate is a
 * MEASUREMENT, so the thing that can be wrong about it is not one verdict
 * but the whole instrument: a scanner that stops finding literals, an
 * alphabet that stops naming the characters a pattern is bad at, a subject
 * builder that stops producing the shape that hurts, a threshold that
 * drifts past every real pattern. Each of those leaves a gate that runs,
 * exits clean, and answers for nothing.
 *
 * So the cases here are built the way the gate builds its own self-proof,
 * one level out: synthetic repository roots, each carrying its own lib/,
 * bin/ and planted fixture, driven through the gate as a child process
 * whose exit code and transcript are the verdict. Half of them break the
 * instrument rather than the tree, and each asserts the gate fails loudly
 * instead of reporting a clean sweep.
 *
 * ABSENCE IS A VECTOR. A missing planted fixture, a fixture with nothing
 * growing in it, a literal carrying no expectation, a lib tree with no
 * source under it: every one of those is a run that would otherwise pass
 * having measured nothing worth measuring, and every one of them is a case
 * below.
 *
 * The live tree is a case in its own right. The gate runs against this
 * repository, exits zero, and publishes both of its counts non-empty. That
 * is what makes the rest of the file worth having.
 *
 * No sockets, no database, no network. It spawns node processes, writes
 * fixture trees under a temporary directory, and reads what the processes
 * printed.
 *
 * Run standalone:
 * node test/layer-0-primitives/regex-growth.test.js
 */

var fs    = require("node:fs");
var path  = require("node:path");
var spawn = require("node:child_process").spawn;

var helpers = require("../helpers");
var check   = helpers.check;
var count   = helpers.count;

var examinedCounts = require("../../scripts/examined-counts.js");
var gate = require("../../scripts/check-regex-growth.js");

var REPO_ROOT = helpers.REPO_ROOT;
var GATE      = path.join(REPO_ROOT, "scripts", "check-regex-growth.js");
var PKG       = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));

// The chain the workflow executes. A gate nothing runs is not a gate, and
// package.json is where this repository declares which ones run.
var CHAIN_KEY = "gates";

// Fixture runs are isolated children over their own directories, so they
// have nothing to contend for beyond CPU.
var LANES = 4;

// ---------------------------------------------------------------------------
// Running the gate
// ---------------------------------------------------------------------------

function runGate(args, env) {
  return new Promise(function (resolve) {
    var child = spawn(process.execPath, [GATE].concat(args || []), {
      cwd:   REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      env:   Object.assign({}, process.env, env || {}),
    });
    var out = "";
    var stdout = "";
    child.stdout.on("data", function (d) { out += d.toString(); stdout += d.toString(); });
    child.stderr.on("data", function (d) { out += d.toString(); });
    child.on("error", function (e) { resolve({ code: -1, out: "spawn failed: " + e.message, stdout: "" }); });
    child.on("close", function (code) { resolve({ code: code, out: out, stdout: stdout }); });
  });
}

function materialize(root, tree) {
  Object.keys(tree).forEach(function (rel) {
    var abs = path.join(root, rel.split("/").join(path.sep));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, tree[rel], "utf8");
  });
}

// ---------------------------------------------------------------------------
// Fixture trees
// ---------------------------------------------------------------------------

// The cheapest shape that is unambiguously refused, so a fixture root costs
// a fraction of a second rather than several. It backtracks exponentially,
// which the gate catches at a length where it is still cheap.
var CHEAP_GROWS = "/^(a+)+$/";
var CHEAP_FLAT  = "/^[a-z]+$/";

function plantedFixture(lines) {
  return '"use strict";\n' +
    "// A planted set for one fixture root.\n" +
    lines.join("\n") + "\n";
}

/**
 * A synthetic repository root the gate can be pointed at: two shipped
 * source files carrying ordinary linear patterns, and a planted fixture
 * holding one shape of each kind. Every case below takes this and breaks
 * exactly one thing, so a failure names the defect the case introduced
 * rather than a fixture bug.
 */
function coherentRoot() {
  var tree = {};
  tree["lib/config/index.js"] = '"use strict";\n' +
    "var LINE = /\\r?\\n/;\n" +
    "var WORD = /^[A-Za-z0-9_-]{1,64}$/;\n" +
    "module.exports = { LINE: LINE, WORD: WORD };\n";
  tree["bin/tool.js"] = '"use strict";\n' +
    "function isDigits(s) { return /^[0-9]+$/.test(s); }\n" +
    "module.exports = { isDigits: isDigits };\n";
  tree[gate.PLANTED_FIXTURE] = plantedFixture([
    "var GROWING = " + CHEAP_GROWS + ";   // " + gate.MARK_GROWS,
    "var FLATTER = " + CHEAP_FLAT + ";   // " + gate.MARK_FLAT,
    "module.exports = { GROWING: GROWING, FLATTER: FLATTER };",
  ]);
  return tree;
}

// A case is { label, expect, mutate, names }. `expect` is "pass" or "fail";
// `names` is a fragment the transcript must carry, so a failing case cannot
// be satisfied by the gate failing for some unrelated reason.
var CASES = [
  {
    label:  "a tree whose patterns are all linear passes",
    expect: "pass",
    mutate: function () { /* the coherent root is the case */ },
  },
  {
    label:  "an unanchored negated-class matcher in lib/ is named",
    expect: "fail",
    names:  "superlinear",
    mutate: function (tree) {
      tree["lib/web/index.js"] = '"use strict";\n' +
        "function stripTags(html) { return String(html).replace(/<[^>]*>/g, \" \"); }\n" +
        "module.exports = { stripTags: stripTags };\n";
    },
  },
  {
    label:  "a pattern too expensive to measure at 8192 characters is named",
    expect: "fail",
    names:  "over-budget",
    mutate: function (tree) {
      tree["bin/tool.js"] += "var NESTED = /^(x+)+$/;\nmodule.exports.NESTED = NESTED;\n";
    },
  },
  {
    label:  "a pattern in lib/vendor/ is left to the vendor refresh",
    expect: "pass",
    mutate: function (tree) {
      tree["lib/vendor/blamejs/lib/thing.js"] = '"use strict";\n' +
        "var TAGS = /<[^>]*>/g;\nmodule.exports = { TAGS: TAGS };\n";
    },
  },
  {
    label:  "a planted growing shape the instrument fails to name fails the run",
    expect: "fail",
    names:  gate.MARK_GROWS,
    mutate: function (tree) {
      tree[gate.PLANTED_FIXTURE] = plantedFixture([
        "var GROWING = /^[a-z]+$/;   // " + gate.MARK_GROWS,
        "var FLATTER = /\\r?\\n/;   // " + gate.MARK_FLAT,
        "module.exports = { GROWING: GROWING, FLATTER: FLATTER };",
      ]);
    },
  },
  {
    label:  "a planted flat shape the instrument does name fails the run",
    expect: "fail",
    names:  gate.MARK_FLAT,
    mutate: function (tree) {
      tree[gate.PLANTED_FIXTURE] = plantedFixture([
        "var GROWING = " + CHEAP_GROWS + ";   // " + gate.MARK_GROWS,
        "var FLATTER = /(y+)+$/;   // " + gate.MARK_FLAT,
        "module.exports = { GROWING: GROWING, FLATTER: FLATTER };",
      ]);
    },
  },
  {
    label:  "a missing planted fixture fails the run rather than being skipped",
    expect: "fail",
    names:  "absent or unreadable",
    mutate: function (tree) { delete tree[gate.PLANTED_FIXTURE]; },
  },
  {
    label:  "a planted fixture with nothing growing in it fails the run",
    expect: "fail",
    names:  "plants no " + gate.MARK_GROWS,
    mutate: function (tree) {
      tree[gate.PLANTED_FIXTURE] = plantedFixture([
        "var FLATTER = " + CHEAP_FLAT + ";   // " + gate.MARK_FLAT,
        "module.exports = { FLATTER: FLATTER };",
      ]);
    },
  },
  {
    label:  "a planted fixture with nothing flat in it fails the run",
    expect: "fail",
    names:  "plants no " + gate.MARK_FLAT,
    mutate: function (tree) {
      tree[gate.PLANTED_FIXTURE] = plantedFixture([
        "var GROWING = " + CHEAP_GROWS + ";   // " + gate.MARK_GROWS,
        "module.exports = { GROWING: GROWING };",
      ]);
    },
  },
  {
    label:  "a planted literal carrying no expectation fails the run",
    expect: "fail",
    names:  "no " + gate.MARK_GROWS + " or " + gate.MARK_FLAT + " marker",
    mutate: function (tree) {
      tree[gate.PLANTED_FIXTURE] = plantedFixture([
        "var GROWING = " + CHEAP_GROWS + ";   // " + gate.MARK_GROWS,
        "var FLATTER = " + CHEAP_FLAT + ";   // " + gate.MARK_FLAT,
        "var UNSAID = /^[0-9]+$/;",
        "module.exports = { GROWING: GROWING, FLATTER: FLATTER, UNSAID: UNSAID };",
      ]);
    },
  },
  {
    label:  "a planted expectation describing no literal fails the run",
    expect: "fail",
    names:  "marker and no regex literal",
    mutate: function (tree) {
      tree[gate.PLANTED_FIXTURE] = plantedFixture([
        "var GROWING = " + CHEAP_GROWS + ";   // " + gate.MARK_GROWS,
        "var FLATTER = " + CHEAP_FLAT + ";   // " + gate.MARK_FLAT,
        "var COUNT = 3;   // " + gate.MARK_FLAT,
        "module.exports = { GROWING: GROWING, FLATTER: FLATTER, COUNT: COUNT };",
      ]);
    },
  },
  {
    label:  "two planted literals under one expectation fail the run",
    expect: "fail",
    names:  "regex literals under one marker",
    mutate: function (tree) {
      tree[gate.PLANTED_FIXTURE] = plantedFixture([
        "var GROWING = " + CHEAP_GROWS + ";   // " + gate.MARK_GROWS,
        "var PAIR = [/^[a-z]+$/, /^[0-9]+$/];   // " + gate.MARK_FLAT,
        "module.exports = { GROWING: GROWING, PAIR: PAIR };",
      ]);
    },
  },
  {
    label:  "shipped trees with no source under them are refused, not passed",
    expect: "fail",
    names:  "nothing to measure",
    mutate: function (tree) {
      delete tree["lib/config/index.js"];
      delete tree["bin/tool.js"];
    },
  },
];

// ---------------------------------------------------------------------------

async function run() {
  // ---- The scanner ----
  //
  // Anchored on shapes this scanner has been blind to rather than on a
  // count, because a count moves whenever anybody edits a source file.

  var afterReturn = gate.extractLiterals(
    'function isReply(s) { return /^re:/i.test(s); }\n');
  count("a literal written after `return` is found, not read as division",
    afterReturn.length === 1 && afterReturn[0].source === "^re:",
    JSON.stringify(afterReturn));

  var divided = gate.extractLiterals("var ratio = total / count / 2;\n");
  count("a division is not read as a literal", divided.length === 0,
    JSON.stringify(divided));

  var shebang = gate.extractLiterals("#!/usr/bin/env node\nvar x = 1;\n");
  count("an interpreter line is not read as a literal", shebang.length === 0,
    JSON.stringify(shebang));

  var quoted = gate.extractLiterals('var s = "a/b/c";\nvar t = 1;\n');
  count("a slash inside a string is not read as a literal", quoted.length === 0,
    JSON.stringify(quoted));

  var commented = gate.extractLiterals("// var dead = /a+b/;\nvar live = /c+d/;\n");
  count("a literal inside a comment is not measured", commented.length === 1 &&
    commented[0].source === "c+d", JSON.stringify(commented));

  // ---- The alphabet ----
  //
  // The escaped-punctuation case is the one this instrument has already got
  // wrong: reading `\/` as nothing left the pattern measured against
  // letters it rejects at the first character of every position, so it was
  // read and nothing about it was measured.

  var slashes = gate.alphabetOf("\\/+$");
  check("an escaped punctuation mark is collected as a literal of itself",
    slashes.alpha.indexOf("/") !== -1 && slashes.derived === true);

  var negated = gate.alphabetOf("<[^>]*>");
  check("a negated class contributes both what it excludes and what it does not",
    negated.alpha.indexOf("<") !== -1 && negated.terms.indexOf(">") !== -1);

  var anchors = gate.alphabetOf("^$");
  check("a pattern naming no characters falls back and says so",
    anchors.derived === false && anchors.alpha.length > 0);

  // ---- The judge, called directly ----

  var quadratic = gate.measurePattern({ source: "<[^>]*>", flags: "g" });
  count("an unanchored negated-class matcher measures superlinear",
    quadratic.verdict === "superlinear",
    quadratic.verdict + " slope=" + quadratic.slope + " top=" + quadratic.topMs);
  check("its measured growth exponent is at or above the floor",
    typeof quadratic.slope === "number" && quadratic.slope >= gate.SLOPE_FLOOR);

  var linear = gate.measurePattern({ source: "^[a-z]+$", flags: "" });
  count("an anchored class matcher is left alone",
    gate.PASSING_VERDICTS.indexOf(linear.verdict) !== -1,
    linear.verdict + " top=" + linear.topMs);

  var broken = gate.measurePattern({ source: "(", flags: "" });
  check("a literal that does not compile is refused rather than skipped",
    broken.verdict === "uncompilable" && broken.measured === false);

  // ---- The chain ----

  var chain = String((PKG.scripts || {})[CHAIN_KEY] || "");
  check("the gate is named in the declared static-gate chain",
    chain.indexOf("scripts/check-regex-growth.js") !== -1);

  // ---- Argument handling ----

  var scratch = helpers.tempDir("regexgrowth");

  var badRoot = await runGate(["--root", path.join(scratch, "absent")]);
  check("a --root that does not exist fails rather than reporting a clean tree",
    badRoot.code === 2);

  var noValue = await runGate(["--root"]);
  check("--root with no value is refused", noValue.code === 2);

  var unknown = await runGate(["--measure-everything"]);
  check("an unrecognized argument is refused", unknown.code === 2);

  // ---- The live tree ----

  var live = await runGate([], {
    BLAMEPOST_REGEX_GROWTH_DIR: path.join(scratch, "live-output"),
  });
  var liveFlat = live.out.replace(/\s+/g, " ").trim();
  count("this repository's own lib/ and bin/ hold no pattern that grows faster " +
    "than its input (exit 0)", live.code === 0, liveFlat.slice(0, 400));

  var published = examinedCounts.publishedCounts(live.stdout);
  count("the gate publishes what it examined", published.length >= 2,
    examinedCounts.format(published));
  count("no unit came back empty", examinedCounts.emptyUnits(published).length === 0,
    examinedCounts.format(published));

  var units = published.map(function (c) { return c.unit; });
  check("it answers for the patterns it MEASURED, which is the number a " +
    "scanner that stopped finding literals would empty",
    units.indexOf("regex-patterns") !== -1);
  check("it answers for the planted shapes it NAMED, which is the number a " +
    "judge that stopped separating them would empty while the first stayed full",
    units.indexOf("planted-shapes") !== -1);

  // ---- The fixture roots ----

  var dir = helpers.tempDir("regexgrowth");
  var results = [];
  var next = 0;

  async function lane() {
    for (;;) {
      var i = next;
      next += 1;
      if (i >= CASES.length) return;
      var c = CASES[i];
      var root = path.join(dir, "case-" + i);
      var tree = coherentRoot();
      c.mutate(tree);
      materialize(root, tree);
      results[i] = await runGate(["--root", root], {
        BLAMEPOST_REGEX_GROWTH_DIR: path.join(root, ".measure"),
      });
    }
  }

  await Promise.all(Array.from({ length: Math.min(LANES, CASES.length) }, lane));

  CASES.forEach(function (c, i) {
    var r = results[i];
    var flat = r.out.replace(/\s+/g, " ").trim();
    if (c.expect === "pass") {
      count(c.label + " (exit 0)", r.code === 0, flat.slice(0, 400));
      return;
    }
    count(c.label + " (non-zero exit)", r.code === 1, flat.slice(0, 400));
    count(c.label + ": the finding names " + JSON.stringify(c.names),
      flat.indexOf(c.names) !== -1, flat.slice(0, 400));
  });
}

module.exports = { name: "regex-growth", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
