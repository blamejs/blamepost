// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * wiki-block-reader: the documentation block reader under lib/web/wiki is
 * the one reader of the blocks in lib/. The documentation gates read it
 * through `scripts/source-primitives.js`, and the reference wiki reads it
 * when the server builds the wiki.
 *
 * ONE READER. `scripts/source-primitives.js` loads lib/web/wiki/blocks.js
 * and exports its functions: its `tagMap` is the reader's function object,
 * its walk is the reader's walk, and its records over the real tree are the
 * reader's records field for field, `signature` and `end` included.
 *
 * ONE VERDICT. Each fixture tree below is run through both paths: the gate,
 * `scripts/validate-source-comment-blocks.js`, and the wiki, `build` from
 * lib/web/wiki. For every tree the two reach the verdict written beside it.
 * The trees the wiki builds carry parse edge cases, and over them the gate
 * reads the same primitives the wiki builds pages for. The trees the wiki
 * refuses to build are refused by the gate too, so a tree the gates pass is a
 * tree the wiki builds. The gate refuses more trees than the wiki does, since
 * it also requires tags the wiki renders without, and no vector here depends
 * on the reverse.
 *
 * PARSE. A fixture tree built to carry the edge cases (a tag repeated, a tag
 * line inside an example body, a missing tag, CRLF line endings, an opener
 * with no closer, and a vendored directory) is parsed and checked against
 * the documented record shape.
 *
 * Primitives driven: `blamepost.web.wiki.blocks.at`,
 * `blamepost.web.wiki.blocks.libSources`, `blamepost.web.wiki.blocks.relative`,
 * `blamepost.web.wiki.blocks.collect`,
 * `blamepost.web.wiki.blocks.collectPrimitives`,
 * `blamepost.web.wiki.blocks.collectModules` and
 * `blamepost.web.wiki.blocks.tagMap`.
 *
 * Run standalone: node test/layer-1-state/wiki-block-reader.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;

var blocks           = require("../../lib/web/wiki/blocks.js");
var wiki             = require("../../lib/web/wiki");
var sourcePrimitives = require("../../scripts/source-primitives.js");
var gate             = require("../../scripts/validate-source-comment-blocks.js");

var CRLF = String.fromCharCode(13) + String.fromCharCode(10);

function _firstDifference(a, b) {
  var n = Math.max(a.length, b.length);
  for (var i = 0; i < n; i += 1) {
    var left = JSON.stringify(a[i]);
    var right = JSON.stringify(b[i]);
    if (left !== right) return "record " + i + ": gates " + left + " reader " + right;
  }
  return "none";
}

function _write(root, rel, text) {
  var abs = nodePath.join(root, rel);
  nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
  nodeFs.writeFileSync(abs, text, "utf8");
  return abs;
}

function _threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

// ---- one reader --------------------------------------------------------------

function theGatesReadThroughTheLibReader() {
  var scriptModule = require.cache[require.resolve("../../scripts/source-primitives.js")];
  var readerFile = require.resolve("../../lib/web/wiki/blocks.js");
  count("scripts/source-primitives.js loads lib/web/wiki/blocks.js",
    scriptModule !== undefined && scriptModule.children.some(function (c) { return c.filename === readerFile; }),
    scriptModule ? scriptModule.children.map(function (c) { return c.filename; }).join(", ") : "not loaded");
  count("the gates' tagMap is the reader's function object",
    sourcePrimitives.tagMap === blocks.tagMap, "tagMap");

  var scriptFiles = sourcePrimitives.libSources();
  var libFiles = blocks.libSources();
  count("the gates walk the reader's lib sources",
    JSON.stringify(scriptFiles) === JSON.stringify(libFiles),
    scriptFiles.length + " and " + libFiles.length);
  count("the walk reached the tree", libFiles.length > 0, libFiles.length + " files");

  var fromGates = sourcePrimitives.collect();
  var fromReader = blocks.collect();
  count("the real tree carries primitive blocks and module blocks to compare",
    fromReader.primitives.length > 0 && fromReader.modules.length > 0,
    fromReader.primitives.length + " primitives, " + fromReader.modules.length + " modules");
  count("every field of every primitive record the gates read is the reader's",
    JSON.stringify(fromGates.primitives) === JSON.stringify(fromReader.primitives),
    _firstDifference(fromGates.primitives, fromReader.primitives));
  count("every field of every module record the gates read is the reader's",
    JSON.stringify(fromGates.modules) === JSON.stringify(fromReader.modules),
    _firstDifference(fromGates.modules, fromReader.modules));
  count("every primitive record carries its signature field and the offset its block ends at",
    fromReader.primitives.every(function (p) {
      return (p.signature === null || typeof p.signature === "string") && typeof p.end === "number" && p.end > p.line;
    }), "signature and end");

  var scriptRelative = scriptFiles.map(function (f) { return sourcePrimitives.relative(f); });
  var libRelative = libFiles.map(function (f) { return blocks.relative(f); });
  count("relative names every source the way the gates do",
    JSON.stringify(scriptRelative) === JSON.stringify(libRelative),
    _firstDifference(scriptRelative, libRelative));
  count("and every name opens with lib/ and carries no backslash",
    libRelative.every(function (r) { return r.indexOf("lib/") === 0 && r.indexOf("\\") === -1; }),
    libRelative.slice(0, 3).join(" "));

  count("collectPrimitives returns the primitive half of one collect",
    JSON.stringify(blocks.collectPrimitives()) === JSON.stringify(fromReader.primitives),
    fromReader.primitives.length + " primitives");
  count("collectModules returns the module half of one collect",
    JSON.stringify(blocks.collectModules()) === JSON.stringify(fromReader.modules),
    fromReader.modules.length + " modules");
}

// ---- one verdict ---------------------------------------------------------------

// A primitive block over a function named for the token's last segment, with
// every tag the gate requires.
function _primitive(token) {
  var name = token.slice(token.lastIndexOf(".") + 1);
  return [
    "/**",
    " * @primitive " + token,
    " * @signature " + name + "(input)",
    " * @since     0.1.0",
    " * @status    experimental",
    " * @spec      internal (design: fixture)",
    " *",
    " * Reads the fixture input once and returns it to the caller unchanged.",
    " *",
    " * @example",
    " *   " + name.replace(/\W/g, "_") + "(\"input\");",
    " */",
    "function " + name.replace(/\W/g, "_") + "(input) {",
    "  return input;",
    "}",
    "",
  ];
}

// A module block with every tag the gate requires, plus `extra` tag lines.
function _module(token, extra) {
  return ["/**", " * @module " + token, " * @nav    " + gate.NAV_GROUPS[0], " * @title  Fixture " + token]
    .concat(extra || [], [" *", " * The fixture module, described at enough length to read as prose.", " */", ""]);
}

// The lines of a source file: the strict-mode directive, then each part's
// lines in order.
function _source(parts) {
  var lines = ["\"use strict\";"];
  parts.forEach(function (part) { lines = lines.concat(part); });
  return lines;
}

// Each shape is a set of files and the verdict both paths must reach. The
// test corpus written beside the files names every primitive the reader
// returns, so the gate's tested-ness rule does not decide a verdict.
var SHAPES = [
  {
    label: "a module and a primitive written in full",
    verdict: "builds",
    files: { "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.run")]).join("\n") },
  },
  {
    label: "an opener with no closer after a closed block",
    verdict: "builds",
    files: {
      "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.run"),
        ["/**", " * @primitive blamepost.a.neverClosed", " * @since     0.1.0", ""]]).join("\n"),
    },
  },
  {
    label: "CRLF line endings",
    verdict: "builds",
    files: { "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.run")]).join(CRLF) },
  },
  {
    label: "a tag line inside an example body",
    verdict: "builds",
    files: {
      "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.run").slice(0, 8)
        .concat([" *", " * @example", " *   run(1);", " * @since     9.9.9", " */",
          "function run(input) {", "  return input;", "}", ""])]).join("\n"),
    },
  },
  {
    label: "a block opener written inside a block's prose",
    verdict: "builds",
    files: {
      "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.run").slice(0, 7)
        .concat([" * Reads the input; the text /** inside this sentence opens nothing.", " *",
          " * @example", " *   run(\"input\");", " */",
          "function run(input) {", "  return input;", "}", ""])]).join("\n"),
    },
  },
  {
    label: "a primitive tag with no value",
    verdict: "builds",
    files: {
      "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.run"),
        ["/**", " * @primitive", " * @since     0.1.0", " *", " * A block naming no primitive.", " */", ""]]).join("\n"),
    },
  },
  {
    label: "a module slug that is the specification index",
    verdict: "refused",
    files: { "lib/a.js": _source([_module("blamepost.a", [" * @slug   specs"]), _primitive("blamepost.a.run")]).join("\n") },
  },
  {
    label: "a module slug the wiki cannot address",
    verdict: "refused",
    files: {
      "lib/a.js": _source([_module("blamepost.a", [" * @slug   ../../elsewhere"]), _primitive("blamepost.a.run")]).join("\n"),
    },
  },
  {
    label: "a file declaring two module blocks",
    verdict: "refused",
    files: {
      "lib/a.js": _source([_module("blamepost.a"), _module("blamepost.b"), _primitive("blamepost.a.run")]).join("\n"),
    },
  },
  {
    label: "two modules that would share a page",
    verdict: "refused",
    files: {
      "lib/a.js": _source([_module("blamepost.a", [" * @slug   same"]), _primitive("blamepost.a.run")]).join("\n"),
      "lib/b.js": _source([_module("blamepost.b", [" * @slug   same"]), _primitive("blamepost.b.run")]).join("\n"),
    },
  },
  {
    label: "a primitive token that is not a dotted identifier",
    verdict: "refused",
    files: { "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.two words")]).join("\n") },
  },
  {
    label: "a primitive declared in two blocks",
    verdict: "refused",
    files: {
      "lib/a.js": _source([_module("blamepost.a"), _primitive("blamepost.a.run")]).join("\n"),
      "lib/b.js": _source([_primitive("blamepost.a.run")]).join("\n"),
    },
  },
];

function theGateAndTheWikiReachOneVerdict() {
  SHAPES.forEach(function (shape, i) {
    var root = helpers.tempDir("one-verdict-" + i);
    try {
      Object.keys(shape.files).forEach(function (rel) { _write(root, rel, shape.files[rel]); });
      var declared = sourcePrimitives.reader.at(root).collectPrimitives().map(function (p) { return p.token; });
      _write(root, "test/fixture.test.js", "// Drives " + declared.join(", ") + ".\n");

      var result = gate.validate({ root: root });
      var built = null;
      var refusal = _threw(function () { built = wiki.build({ root: root }); });
      var gateVerdict = result.findings.length === 0 ? "builds" : "refused";
      var wikiVerdict = refusal === null ? "builds" : "refused";
      count(shape.label + ": the gate and the wiki both reach `" + shape.verdict + "`",
        gateVerdict === shape.verdict && wikiVerdict === shape.verdict,
        "gate " + gateVerdict + " " + JSON.stringify(result.findings.map(function (f) { return f.kind; })) +
        ", wiki " + wikiVerdict + (refusal ? " (" + refusal.message + ")" : ""));

      if (shape.verdict === "refused") {
        count(shape.label + ": the gate's refusal carries the wiki's own message",
          result.findings.some(function (f) {
            return f.kind === "wiki-build-refused" && refusal !== null && f.msg.indexOf(refusal.message) !== -1;
          }), JSON.stringify(result.findings));
        return;
      }

      var gateTokens = sourcePrimitives.reader.at(root).collectPrimitives()
        .map(function (p) { return p.token; }).sort();
      var pageTokens = built.paths().map(built.page)
        .filter(function (page) { return page.kind === "primitive"; })
        .map(function (page) { return page.subject.token; }).sort();
      count(shape.label + ": the gate read exactly the primitives the wiki built pages for",
        gateTokens.length > 0 && JSON.stringify(gateTokens) === JSON.stringify(pageTokens) &&
        result.examined["primitive-blocks"] === built.counts.primitives,
        "gate " + JSON.stringify(gateTokens) + ", wiki " + JSON.stringify(pageTokens));
    } finally {
      helpers.removeTempDir(root);
    }
  });
}

// ---- a fixture tree built to carry the parse edge cases ----------------------

function _fixtureTree() {
  var root = helpers.tempDir("wiki-reader");
  _write(root, "lib/alpha.js", [
    "\"use strict\";",
    "/**",
    " * @module   blamepost.alpha",
    " * @title    Alpha",
    " *",
    " * @intro",
    " *   First paragraph of the intro.",
    " *",
    " *   ## A heading",
    " *   Second paragraph.",
    " */",
    "",
    "/**",
    " * @primitive blamepost.alpha.one",
    " * @signature blamepost.alpha.one(opts)",
    " * @since     0.1.0",
    " * @status    stable",
    " * @spec      RFC 5322 section 3.4",
    " * @related   blamepost.alpha.two, blamepost.alpha.three",
    " * @related   blamepost.alpha.four",
    " *",
    " * The description of one, long enough to count as a description.",
    " *",
    " * @opts",
    " *   limit: number,   // default 10",
    " *",
    " * @example",
    " *   var x = one({ limit: 1 });",
    " *     nested();",
    " * @since     9.9.9",
    " */",
    "function one() {}",
    "",
    "/**",
    " * @primitive blamepost.alpha.two",
    " * @since     0.1.0",
    " *",
    " * Two declares no status and no spec, and its description is here.",
    " */",
    "function two() {}",
    "",
  ].join("\n"));

  _write(root, "lib/sub/crlf.js", [
    "\"use strict\";",
    "/**",
    " * @primitive blamepost.sub.crlf",
    " * @since     0.1.0",
    " * @status    experimental",
    " * @spec      internal (design: line endings)",
    " *",
    " * A block written with CRLF line endings reads the same as LF.",
    " */",
    "function crlf() {}",
    "",
  ].join(CRLF));

  _write(root, "lib/sub/unclosed.js", [
    "\"use strict\";",
    "/**",
    " * @primitive blamepost.sub.closed",
    " * @since     0.1.0",
    " *",
    " * This block closes and is read.",
    " */",
    "function closed() {}",
    "/**",
    " * @primitive blamepost.sub.neverClosed",
    " * @since     0.1.0",
    "",
  ].join("\n"));

  _write(root, "lib/vendor/upstream.js", [
    "/**",
    " * @primitive upstream.ignored",
    " * @since 0.1.0",
    " */",
    "",
  ].join("\n"));

  return root;
}

function theGatesAndTheWikiReadTheEdgeCaseTreeAlike(root) {
  var fromGates = sourcePrimitives.reader.at(root).collect();
  var fromReader = blocks.at(root).collect();
  count("on the edge case tree every record the gates read is the reader's",
    JSON.stringify(fromGates) === JSON.stringify(fromReader),
    _firstDifference(fromGates.primitives, fromReader.primitives));

  var built = wiki.build({ root: root });
  var pageTokens = built.paths().map(built.page)
    .filter(function (page) { return page.kind === "primitive"; })
    .map(function (page) { return page.subject.token; });
  count("on the edge case tree the wiki built a page for each primitive the gates read, in order",
    JSON.stringify(pageTokens) === JSON.stringify(fromGates.primitives.map(function (p) { return p.token; })),
    JSON.stringify(pageTokens));
}

function theFixtureParsesAsDocumented(root) {
  var reader = blocks.at(root);
  var rels = reader.libSources().map(reader.relative);
  count("the walk skips lib/vendor and orders by name",
    JSON.stringify(rels) === JSON.stringify(["lib/alpha.js", "lib/sub/crlf.js", "lib/sub/unclosed.js"]),
    JSON.stringify(rels));

  var got = reader.collect();
  var tokens = got.primitives.map(function (p) { return p.token; });
  count("an opener with no closer yields no record and loses nothing before it",
    JSON.stringify(tokens) ===
    JSON.stringify(["blamepost.alpha.one", "blamepost.alpha.two", "blamepost.sub.crlf", "blamepost.sub.closed"]),
    JSON.stringify(tokens));

  var one = got.primitives[0];
  count("the first value of a repeated tag wins, even after a tag line inside an example",
    one.since === "0.1.0", one.since);
  count("repeated related lines flatten in order",
    JSON.stringify(one.related) ===
    JSON.stringify(["blamepost.alpha.two", "blamepost.alpha.three", "blamepost.alpha.four"]),
    JSON.stringify(one.related));
  count("the signature is read", one.signature === "blamepost.alpha.one(opts)", one.signature);
  count("the description excludes the options and the example",
    one.description === "The description of one, long enough to count as a description.",
    JSON.stringify(one.description));
  count("the options body is dedented", one.opts === "limit: number,   // default 10",
    JSON.stringify(one.opts));
  count("the example body is dedented and keeps its inner indentation",
    one.examples.length === 1 && one.examples[0] === "var x = one({ limit: 1 });\n  nested();",
    JSON.stringify(one.examples));
  count("the line is the opener's line", one.line === 13, one.line);

  var alphaText = nodeFs.readFileSync(nodePath.join(root, "lib", "alpha.js"), "utf8");
  var closer = "*" + "/";
  count("the end is the offset just past the block's closing delimiter, and the function follows it",
    alphaText.slice(one.end - closer.length, one.end) === closer &&
    alphaText.slice(one.end).indexOf("\nfunction one()") === 0,
    JSON.stringify(alphaText.slice(one.end - 4, one.end + 16)));

  var two = got.primitives[1];
  count("an absent tag is null", two.status === null && two.spec === null && two.signature === null,
    JSON.stringify(two));
  count("an absent example is an empty list", Array.isArray(two.examples) && two.examples.length === 0,
    JSON.stringify(two.examples));

  var crlf = got.primitives[2];
  count("a CRLF block reads its tags and its description",
    crlf.status === "experimental" && crlf.spec === "internal (design: line endings)" &&
    crlf.description === "A block written with CRLF line endings reads the same as LF.",
    JSON.stringify(crlf));
  count("a CRLF block reports the file relative to the root with forward slashes",
    crlf.file === "lib/sub/crlf.js", crlf.file);
  var crlfText = nodeFs.readFileSync(nodePath.join(root, "lib", "sub", "crlf.js"), "utf8");
  count("a CRLF block's end is the offset just past its closing delimiter",
    crlfText.slice(crlf.end - 2, crlf.end) === "*" + "/" && crlfText.slice(crlf.end, crlf.end + 2) === CRLF,
    String(crlf.end));

  count("the fixture declares one module", got.modules.length === 1, got.modules.length);
  count("collectModules on the fixture returns that module and nothing else",
    JSON.stringify(reader.collectModules()) === JSON.stringify(got.modules),
    JSON.stringify(reader.collectModules().map(function (m) { return m.token; })));
  var mod = got.modules[0];
  count("the module record carries its title and leaves absent tags null",
    mod.token === "blamepost.alpha" && mod.title === "Alpha" && mod.nav === null &&
    mod.order === null && mod.slug === null && mod.featured === null,
    JSON.stringify(mod));
  count("the module intro is dedented and keeps its blank lines",
    mod.intro === "First paragraph of the intro.\n\n## A heading\nSecond paragraph.",
    JSON.stringify(mod.intro));
}

function aRootMustBeAbsolute() {
  var failure = null;
  try { blocks.at("relative/root"); } catch (e) { failure = e; }
  count("a relative root is refused at construction", failure instanceof TypeError,
    failure ? failure.message : "accepted");
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root = null;
  try {
    theGatesReadThroughTheLibReader();
    theGateAndTheWikiReachOneVerdict();
    root = _fixtureTree();
    theGatesAndTheWikiReadTheEdgeCaseTreeAlike(root);
    theFixtureParsesAsDocumented(root);
    aRootMustBeAbsolute();
  } finally {
    if (root !== null) helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "wiki-block-reader", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
