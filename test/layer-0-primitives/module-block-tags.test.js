// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * module-block-tags: `scripts/validate-source-comment-blocks.js` checks the
 * tags on each `@module` block against what the reference wiki reads.
 *
 * Each vector writes a fixture tree holding one module block and one
 * primitive block that pass every other rule, changes one tag, and runs the
 * gate over the tree. The gate must report exactly the finding the vector is
 * about:
 *
 *   - `@featured` set on a module with no `@card`;
 *   - `@featured` set to a value the wiki does not read as featured;
 *   - `@nav` naming a group outside NAV_GROUPS, and `@nav` absent;
 *   - `@title` absent;
 *   - `@order` holding a value the wiki does not sort by as written;
 *   - a module slug the wiki refuses to build, and a file declaring two
 *     modules, both reported from the wiki's own refusal.
 *
 * The canaries run the same tree unchanged, and with each spelling the wiki
 * reads as featured, and must report nothing. The gate is also run over this
 * repository's lib/, where it must report no module finding and must publish
 * the number of module blocks it read.
 *
 * Run standalone: node test/layer-0-primitives/module-block-tags.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");
var gate     = require("../../scripts/validate-source-comment-blocks.js");

var sourcePrimitives = require("../../scripts/source-primitives.js");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var REPO_ROOT      = helpers.REPO_ROOT;
var RUN_CEILING_MS = 60000;

var MODULE_TOKEN = "blamepost.fixture.widgets";

// The module tags of a block that passes every check. A vector copies these
// and changes one; a null value leaves the tag out.
var GOOD_TAGS = Object.freeze({
  nav:      gate.NAV_GROUPS[0],
  title:    "Widgets",
  order:    "10",
  slug:     null,
  featured: "true",
  card:     "Widgets for the fixture, described in one sentence for the index.",
});

// ---- fixtures -------------------------------------------------------------

function _write(root, rel, text) {
  var abs = nodePath.join(root, rel);
  nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
  nodeFs.writeFileSync(abs, text, "utf8");
}

function _tags(overrides) {
  var out = {};
  Object.keys(GOOD_TAGS).forEach(function (k) { out[k] = GOOD_TAGS[k]; });
  Object.keys(overrides || {}).forEach(function (k) { out[k] = overrides[k]; });
  return out;
}

function _moduleBlock(token, tags) {
  var lines = ["/**", " * @module   " + token];
  ["nav", "title", "order", "slug", "featured"].forEach(function (name) {
    if (tags[name] !== null) lines.push(" * @" + name + " " + tags[name]);
  });
  lines.push(" *", " * @intro", " *   The fixture module, described at enough length to read as an overview.");
  if (tags.card !== null) lines.push(" *", " * @card", " *   " + tags.card);
  lines.push(" */");
  return lines.join("\n");
}

var PRIMITIVE_BLOCK = [
  "/**",
  " * @primitive " + MODULE_TOKEN + ".spin",
  " * @signature widgets.spin(count)",
  " * @since     0.1.0",
  " * @status    experimental",
  " * @spec      internal (design: fixture)",
  " *",
  " * Spins the fixture widget the given number of times and returns the count.",
  " *",
  " * @example",
  " *   widgets.spin(3);",
  " */",
  "function spin(count) {",
  "  return count;",
  "}",
].join("\n");

// A tree whose lib/widgets.js holds the module block built from `tags` and
// the primitive block, with a test corpus naming the primitive. `extraModule`
// adds a second module block to the same file.
function _tree(prefix, tags, extraModule) {
  var root = helpers.tempDir(prefix);
  var parts = ["\"use strict\";", _moduleBlock(MODULE_TOKEN, tags)];
  if (extraModule) parts.push(_moduleBlock(extraModule, _tags({ featured: null, card: null })));
  parts.push("", PRIMITIVE_BLOCK, "", "module.exports = { spin: spin };", "");
  _write(root, "lib/widgets.js", parts.join("\n"));
  _write(root, "test/widgets.test.js", "// Drives " + MODULE_TOKEN + ".spin.\n");
  return root;
}

function _validate(prefix, tags, extraModule) {
  var root = _tree(prefix, tags, extraModule);
  try {
    return gate.validate({ root: root });
  } finally {
    helpers.removeTempDir(root);
  }
}

function _kinds(result) {
  return result.findings.map(function (f) { return f.kind; });
}

function _only(result, kind) {
  return JSON.stringify(_kinds(result)) === JSON.stringify([kind]);
}

// ---- canaries -------------------------------------------------------------

function aModuleBlockWrittenInFullPasses() {
  var result = _validate("modtags-good", _tags());
  count("canary: a module block with every tag the wiki reads passes",
    result.findings.length === 0, JSON.stringify(result.findings));
  count("canary: the gate read the one module block",
    result.examined["module-blocks"] === 1, JSON.stringify(result.examined));

  ["true", "yes", "1", "TRUE"].forEach(function (value) {
    var r = _validate("modtags-featured", _tags({ featured: value }));
    count("canary: `@featured " + value + "` is read as featured and passes",
      r.findings.length === 0, JSON.stringify(r.findings));
  });

  var plain = _validate("modtags-plain", _tags({ featured: null, card: null }));
  count("canary: a module that is not featured needs no card",
    plain.findings.length === 0, JSON.stringify(plain.findings));

  var negative = _validate("modtags-negorder", _tags({ order: "-5" }));
  count("canary: a negative whole number is an order the wiki sorts by as written",
    negative.findings.length === 0, JSON.stringify(negative.findings));
}

// ---- refusals -------------------------------------------------------------

function aFeaturedModuleWithNoCardIsRefused() {
  var result = _validate("modtags-nocard", _tags({ card: null }));
  count("featured: a featured module with no @card is refused, and nothing else is",
    _only(result, "featured-without-card"), JSON.stringify(result.findings));
  var f = result.findings[0];
  count("featured: the finding names the module and its file and line",
    f !== undefined && f.module === MODULE_TOKEN && f.file === "lib/widgets.js" && f.line === 2,
    JSON.stringify(f));
}

function aFeaturedValueTheWikiDoesNotReadIsRefused() {
  ["ture", "false", "no", "on"].forEach(function (value) {
    var result = _validate("modtags-badfeat", _tags({ featured: value }));
    count("featured: `@featured " + value + "` is refused as a value the wiki does not read as featured",
      _only(result, "featured-not-read"), JSON.stringify(result.findings));
  });
}

function aNavGroupOutsideTheDeclaredSetIsRefused() {
  var typo = _validate("modtags-navtypo", _tags({ nav: "Sendng" }));
  count("nav: a misspelled group is refused rather than listed as a group of its own",
    _only(typo, "unknown-nav"), JSON.stringify(typo.findings));
  count("nav: the refusal names the declared groups",
    typo.findings.length === 1 && typo.findings[0].msg.indexOf(gate.NAV_GROUPS[1]) !== -1,
    JSON.stringify(typo.findings));

  var cased = _validate("modtags-navcase", _tags({ nav: gate.NAV_GROUPS[0].toLowerCase() }));
  count("nav: a declared group written in another letter case is refused",
    _only(cased, "unknown-nav"), JSON.stringify(cased.findings));

  var absent = _validate("modtags-nonav", _tags({ nav: null }));
  count("nav: a module with no @nav is refused",
    _only(absent, "missing-nav"), JSON.stringify(absent.findings));

  count("nav: every group a module in this repository names is declared",
    sourcePrimitives.collectModules().every(function (m) { return gate.NAV_GROUPS.indexOf(m.nav) !== -1; }),
    JSON.stringify(sourcePrimitives.collectModules().map(function (m) { return m.nav; })));
}

function aModuleWithNoTitleIsRefused() {
  var result = _validate("modtags-notitle", _tags({ title: null }));
  count("title: a module with no @title is refused",
    _only(result, "missing-title"), JSON.stringify(result.findings));
}

function anOrderTheWikiDoesNotSortByIsRefused() {
  ["soon", "1O", "05", "10.5"].forEach(function (value) {
    var result = _validate("modtags-badorder", _tags({ order: value }));
    count("order: `@order " + value + "` is refused because the wiki does not sort by it as written",
      _only(result, "order-not-read"), JSON.stringify(result.findings));
  });
}

function aModuleTheWikiRefusesToBuildIsRefused() {
  var reserved = _validate("modtags-specs", _tags({ slug: "specs" }));
  count("build: a module slug the wiki reserves is refused from the wiki's own refusal",
    _only(reserved, "wiki-build-refused"), JSON.stringify(reserved.findings));
  count("build: the refusal carries the wiki's message naming the file and line",
    reserved.findings.length === 1 && reserved.findings[0].msg.indexOf("lib/widgets.js:2") !== -1,
    JSON.stringify(reserved.findings));

  var badSlug = _validate("modtags-badslug", _tags({ slug: "Not_A_Slug" }));
  count("build: a slug the wiki cannot address is refused",
    _only(badSlug, "wiki-build-refused"), JSON.stringify(badSlug.findings));

  var two = _validate("modtags-twomods", _tags(), "blamepost.fixture.other");
  count("build: a file declaring two modules is refused",
    _only(two, "wiki-build-refused"), JSON.stringify(two.findings));
  count("build: both module blocks were still read and counted",
    two.examined["module-blocks"] === 2, JSON.stringify(two.examined));
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

async function theLiveTreePassesAndPublishesItsModuleBlocks() {
  var result = gate.validate();
  var kinds = gate.MODULE_FINDING_KINDS.concat(gate.WIKI_FINDING_KINDS);
  var found = result.findings.filter(function (f) { return kinds.indexOf(f.kind) !== -1; });
  count("live tree: no module block and no wiki build finding",
    found.length === 0, JSON.stringify(found));

  var modules = sourcePrimitives.collectModules().length;
  count("live tree: the gate read every module block the shared reader returns",
    modules > 0 && result.examined["module-blocks"] === modules,
    result.examined["module-blocks"] + " of " + modules);

  var run = await spawnRun.runNodeScript(
    [nodePath.join(REPO_ROOT, "scripts", "validate-source-comment-blocks.js")],
    { cwd: REPO_ROOT, ceilingMs: RUN_CEILING_MS });
  count("live tree: the gate publishes the module blocks it read",
    _examined(run.out)["module-blocks"] === modules, tail(run.out, 6));
}

// ---- runner ---------------------------------------------------------------

async function run() {
  aModuleBlockWrittenInFullPasses();
  aFeaturedModuleWithNoCardIsRefused();
  aFeaturedValueTheWikiDoesNotReadIsRefused();
  aNavGroupOutsideTheDeclaredSetIsRefused();
  aModuleWithNoTitleIsRefused();
  anOrderTheWikiDoesNotSortByIsRefused();
  aModuleTheWikiRefusesToBuildIsRefused();
  await theLiveTreePassesAndPublishesItsModuleBlocks();
  return helpers.getChecks();
}

module.exports = { name: "module-block-tags", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
