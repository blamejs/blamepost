// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * wiki-pages: every documentation block in lib/ produces a wiki page, and
 * a block added to a tree produces a page with no edit to the wiki.
 *
 * Over the real tree: each primitive record the block reader returns has a
 * primitive page carrying its token, source position and status, and each
 * module record has a module page. The counts are taken from the reader on
 * this run rather than written here, so a primitive added tomorrow is
 * covered by the same assertions.
 *
 * Over fixture trees: a module block without `nav`, `title`, `order` or
 * `slug` gets the documented defaults, a primitive in a file with no module
 * block is placed by token prefix or under its namespace, a new block
 * appears as a new page on the next build, and the shapes `build` refuses
 * are refused by name.
 *
 * The handle `build` returns is driven directly: `page` answers null for
 * a value that is not a string and for a path that differs from a page's
 * path only by a trailing slash, and `paths` returns a new array on every
 * call.
 *
 * Primitives driven: `blamepost.web.wiki.build`,
 * `blamepost.web.wiki.build.page` and `blamepost.web.wiki.build.paths`.
 *
 * Run standalone: node test/layer-1-state/wiki-pages.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;

var blocks = require("../../lib/web/wiki/blocks.js");
var wiki   = require("../../lib/web/wiki");

function _write(root, rel, text) {
  var abs = nodePath.join(root, rel);
  nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
  nodeFs.writeFileSync(abs, text, "utf8");
  return abs;
}

function _append(root, rel, text) {
  nodeFs.appendFileSync(nodePath.join(root, rel), text, "utf8");
}

function _text(spans) {
  return spans.map(function (s) { return s.text; }).join("");
}

function _pages(site) {
  return site.paths().map(function (p) { return site.page(p); });
}

function _facts(page) {
  var out = {};
  page.sections[0].blocks[0].rows.forEach(function (row) { out[row.label] = row.spans; });
  return out;
}

function _section(page, heading) {
  for (var i = 0; i < page.sections.length; i += 1) {
    if (page.sections[i].heading === heading) return page.sections[i];
  }
  return null;
}

function _threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

// A block as source lines, with each line decorated the way lib/ writes it.
function _block(lines) {
  return ["/**"].concat(lines.map(function (l) { return l.length > 0 ? " * " + l : " *"; }), [" */"])
    .join("\n") + "\n";
}

function _primitiveBlock(token, status, spec, description) {
  return _block([
    "@primitive " + token,
    "@signature " + token + "(input)",
    "@since     0.1.0",
    "@status    " + status,
    "@spec      " + spec,
    "",
    description,
  ]) + "function f() {}\n";
}

// ---- the real tree -------------------------------------------------------------

function everyBlockOnTheRealTreeHasAPage() {
  var records = blocks.collect();
  var site = wiki.build();
  var pages = _pages(site);

  count("the reader found primitive blocks on the real tree", records.primitives.length > 0,
    records.primitives.length + " primitives");
  count("the reader found module blocks on the real tree", records.modules.length > 0,
    records.modules.length + " modules");

  var primitivePages = new Map();
  var modulePages = new Map();
  pages.forEach(function (page) {
    if (page.kind === "primitive") primitivePages.set(page.subject.token, page);
    if (page.kind === "module") modulePages.set(page.subject.token, page);
  });

  var missing = [];
  var wrongSource = [];
  var wrongStatus = [];
  records.primitives.forEach(function (p) {
    var page = primitivePages.get(p.token);
    if (page === undefined) { missing.push(p.token); return; }
    if (page.subject.file !== p.file || page.subject.line !== p.line) wrongSource.push(p.token);
    if (_text(_facts(page).Status) !== p.status) wrongStatus.push(p.token);
  });
  count("every one of the " + records.primitives.length + " primitives has a primitive page",
    missing.length === 0, missing.join(", ") || "none missing");
  count("each primitive page names the block's file and line", wrongSource.length === 0,
    wrongSource.join(", ") || "all match");
  count("each primitive page shows the block's status", wrongStatus.length === 0,
    wrongStatus.join(", ") || "all match");
  count("there is one primitive page per primitive record, and no more",
    primitivePages.size === records.primitives.length,
    primitivePages.size + " pages for " + records.primitives.length + " records");

  var missingModules = records.modules.filter(function (m) { return !modulePages.has(m.token); })
    .map(function (m) { return m.token; });
  count("every one of the " + records.modules.length + " modules has a module page",
    missingModules.length === 0, missingModules.join(", ") || "none missing");
  count("the counts report every primitive and every module the reader returned",
    site.counts.primitives === records.primitives.length &&
    site.counts.modules >= records.modules.length,
    JSON.stringify(site.counts));

  var tally = { stable: 0, experimental: 0, deprecated: 0 };
  records.primitives.forEach(function (p) { if (tally[p.status] !== undefined) tally[p.status] += 1; });
  var index = site.page("/wiki");
  var indexFacts = _facts(index);
  count("the index shows how many primitives are stable, from the blocks",
    _text(indexFacts.Stable) === String(tally.stable), _text(indexFacts.Stable) + " vs " + tally.stable);
  count("the index shows how many primitives are experimental, from the blocks",
    _text(indexFacts.Experimental) === String(tally.experimental),
    _text(indexFacts.Experimental) + " vs " + tally.experimental);

  // Each module page's table shows each primitive's status beside it.
  var statusMismatches = [];
  modulePages.forEach(function (page) {
    var sec = _section(page, "Primitives");
    var table = sec.blocks[0];
    if (table.kind !== "table") return;
    table.rows.forEach(function (row) {
      var token = _text(row.cells[0]);
      var record = records.primitives.filter(function (p) { return p.token === token; })[0];
      if (!record || _text(row.cells[1]) !== record.status) statusMismatches.push(token);
    });
  });
  count("each module page lists its primitives with their status", statusMismatches.length === 0,
    statusMismatches.join(", ") || "all match");
}

function theHandleAnswersOnlyExactPaths() {
  var site = wiki.build();
  var first = site.paths();
  count("paths opens with the index", first[0] === wiki.BASE_PATH, first[0]);
  first.push("/wiki/added-by-a-caller");
  var second = site.paths();
  count("paths returns a new array on every call, so a caller's change does not reach the next",
    second.indexOf("/wiki/added-by-a-caller") === -1 && second.length === first.length - 1,
    first.length + " then " + second.length);

  count("page answers the index at its exact path", site.page(wiki.BASE_PATH) !== null &&
    site.page(wiki.BASE_PATH).kind === "index", String(site.page(wiki.BASE_PATH)));
  count("page answers null for a trailing slash the page's path does not carry",
    site.page(wiki.BASE_PATH + "/") === null && site.page("/wiki/specs/") === null, "trailing slash");
  count("page answers null for a value that is not a string",
    site.page(null) === null && site.page(undefined) === null && site.page(42) === null &&
    site.page({ toString: function () { return wiki.BASE_PATH; } }) === null, "non-strings");
  count("page answers null for a path held in a different letter case",
    site.page("/WIKI") === null && site.page("/wiki/SPECS") === null, "case");
}

// ---- tag defaults and placement ----------------------------------------------

function _defaultsTree() {
  var root = helpers.tempDir("wiki-defaults");
  _write(root, "lib/alpha.js", "\"use strict\";\n" +
    _block(["@module blamepost.fixture.dmarcPolicy", "", "This module declares no navigation tags."]) +
    _primitiveBlock("blamepost.fixture.dmarcPolicy.evaluate", "stable", "RFC 7489 section 7.2",
      "Evaluates one report against the policy in force for its domain."));
  _write(root, "lib/beta.js", "\"use strict\";\n" +
    _block([
      "@module   blamepost.fixture.beta",
      "@nav      Mail",
      "@title    Beta tools",
      "@order    5",
      "@slug     beta-tools",
      "@featured yes",
      "",
      "@card",
      "  Beta card text.",
    ]) +
    _primitiveBlock("blamepost.fixture.beta.run", "experimental", "internal (design: fixture)",
      "Runs the beta fixture once and reports what it did."));
  _write(root, "lib/gamma.js", "\"use strict\";\n" +
    _block(["@module blamepost.fixture.gamma", "@nav    Mail", "@title  Gamma", "@order  soon"]));
  _write(root, "lib/helpers/extra.js", "\"use strict\";\n" +
    _primitiveBlock("blamepost.fixture.dmarcPolicy.extra.parse", "experimental",
      "internal (design: fixture)", "Parses the extra fixture input into a record."));
  _write(root, "lib/orphan.js", "\"use strict\";\n" +
    _primitiveBlock("blamepost.loose.thing", "experimental", "internal (design: fixture)",
      "A primitive whose namespace no module block declares."));
  return root;
}

function missingTagsTakeTheDocumentedDefaults(root) {
  var site = wiki.build({ root: root });

  var alpha = site.page("/wiki/fixture-dmarc-policy");
  count("a module without slug is addressed by its kebab-cased token", alpha !== null,
    site.paths().join(" "));
  count("a module without nav falls into the default group",
    alpha !== null && alpha.subject.nav === wiki.DEFAULT_NAV && wiki.DEFAULT_NAV === "Other",
    alpha && alpha.subject.nav);
  count("a module without title is titled by its token",
    alpha !== null && alpha.title === "blamepost.fixture.dmarcPolicy", alpha && alpha.title);
  count("a module without order sorts at 100",
    alpha !== null && alpha.subject.order === 100 && wiki.DEFAULT_ORDER === 100,
    alpha && alpha.subject.order);

  var beta = site.page("/wiki/beta-tools");
  count("declared nav, title, order and slug are used as written",
    beta !== null && beta.subject.nav === "Mail" && beta.title === "Beta tools" && beta.subject.order === 5,
    beta && JSON.stringify(beta.subject));

  var gamma = site.page("/wiki/fixture-gamma");
  count("an order that is not an integer sorts at 100",
    gamma !== null && gamma.subject.order === 100, gamma && gamma.subject.order);
  count("a module with no primitives still has a page saying so",
    gamma !== null && _text(_section(gamma, "Primitives").blocks[0].spans) ===
    "This module documents no primitives.", gamma && JSON.stringify(_section(gamma, "Primitives")));

  count("a primitive in a file with no module block is placed under the longest module prefix",
    site.page("/wiki/fixture-dmarc-policy/extra.parse") !== null, site.paths().join(" "));
  count("a primitive whose namespace no module declares gets a page under that namespace",
    site.page("/wiki/loose/thing") !== null && site.page("/wiki/loose") !== null,
    site.paths().join(" "));
  count("the counts include the namespace page",
    site.counts.modules === 4 && site.counts.primitives === 4, JSON.stringify(site.counts));

  var index = site.page("/wiki");
  var headings = index.sections.map(function (s) { return s.heading; });
  count("the index lists featured modules first, named groups next, and the default group last",
    JSON.stringify(headings) === JSON.stringify([null, "Start here", "Mail", "Other"]),
    JSON.stringify(headings));
  var start = _section(index, "Start here").blocks[0];
  count("a featured module is listed with its card text",
    start.items.length === 1 && _text(start.items[0]) === "Beta tools: Beta card text.",
    JSON.stringify(start.items));
  var mail = _section(index, "Mail").blocks[0];
  count("modules within a group sort by order",
    mail.rows.map(function (r) { return _text(r.cells[0]); }).join(",") === "Beta tools,Gamma",
    JSON.stringify(mail.rows.map(function (r) { return _text(r.cells[0]); })));
}

function aNewBlockProducesANewPage(root) {
  var before = wiki.build({ root: root });
  var beforePaths = before.paths();

  _append(root, "lib/beta.js",
    _primitiveBlock("blamepost.fixture.beta.stop", "stable", "internal (design: fixture)",
      "Stops the beta fixture and reports whether it was running."));
  _write(root, "lib/delta.js", "\"use strict\";\n" +
    _block(["@module blamepost.fixture.delta", "@title  Delta", "", "@intro", "  A module added later."]) +
    _primitiveBlock("blamepost.fixture.delta.open", "experimental", "internal (design: fixture)",
      "Opens the delta fixture for reading."));

  var after = wiki.build({ root: root });
  var afterPaths = after.paths();
  var added = afterPaths.filter(function (p) { return beforePaths.indexOf(p) === -1; }).sort();
  count("the new primitive block and the new module file produce exactly their pages",
    JSON.stringify(added) ===
    JSON.stringify(["/wiki/beta-tools/stop", "/wiki/fixture-delta", "/wiki/fixture-delta/open"]),
    JSON.stringify(added));
  count("no page that existed before went away",
    beforePaths.every(function (p) { return afterPaths.indexOf(p) !== -1; }),
    beforePaths.length + " before, " + afterPaths.length + " after");

  var beta = after.page("/wiki/beta-tools");
  var tokens = _section(beta, "Primitives").blocks[0].rows.map(function (r) { return _text(r.cells[0]); });
  count("the module page lists the new primitive in source order",
    JSON.stringify(tokens) === JSON.stringify(["blamepost.fixture.beta.run", "blamepost.fixture.beta.stop"]),
    JSON.stringify(tokens));
  count("the new module's intro is on its page",
    _text(_section(after.page("/wiki/fixture-delta"), "Overview").blocks[0].spans) ===
    "A module added later.", "overview");
}

// ---- refusals ----------------------------------------------------------------

function _refusedTree(prefix, files) {
  var root = helpers.tempDir(prefix);
  Object.keys(files).forEach(function (rel) { _write(root, rel, files[rel]); });
  var failure = _threw(function () { wiki.build({ root: root }); });
  helpers.removeTempDir(root);
  return failure;
}

function theShapesBuildRefusesAreRefusedByName() {
  var reserved = _refusedTree("wiki-reserved", {
    "lib/a.js": _block(["@module blamepost.a", "@slug specs"]),
  });
  count("a module slug that is the specification index is refused",
    reserved instanceof TypeError && reserved.message.indexOf("lib/a.js:1") !== -1 &&
    reserved.message.indexOf("specification index") !== -1,
    reserved ? reserved.message : "accepted");

  var badSlug = _refusedTree("wiki-badslug", {
    "lib/a.js": _block(["@module blamepost.a", "@slug ../../elsewhere"]),
  });
  count("a slug that is not lowercase letters and digits joined by hyphens is refused",
    badSlug instanceof TypeError && badSlug.message.indexOf("../../elsewhere") !== -1,
    badSlug ? badSlug.message : "accepted");

  var twoModules = _refusedTree("wiki-twomodules", {
    "lib/a.js": _block(["@module blamepost.a"]) + _block(["@module blamepost.b"]),
  });
  count("a file declaring two module blocks is refused",
    twoModules instanceof TypeError && twoModules.message.indexOf("declares one module") !== -1,
    twoModules ? twoModules.message : "accepted");

  var collision = _refusedTree("wiki-collision", {
    "lib/a.js": _block(["@module blamepost.a", "@slug same"]),
    "lib/b.js": _block(["@module blamepost.b", "@slug same"]),
  });
  count("two modules that would share a path are refused, naming both",
    collision instanceof TypeError && collision.message.indexOf("blamepost.a") !== -1 &&
    collision.message.indexOf("blamepost.b") !== -1 && collision.message.indexOf("/wiki/same") !== -1,
    collision ? collision.message : "accepted");

  var badName = _refusedTree("wiki-badname", {
    "lib/a.js": _block(["@module blamepost.a"]) +
      _primitiveBlock("blamepost.a.two words", "stable", "internal (design: x)", "A token with a space."),
  });
  count("a primitive token that is not a dotted identifier is refused",
    badName instanceof TypeError && badName.message.indexOf("dotted identifier") !== -1,
    badName ? badName.message : "accepted");
}

// ---- runner ------------------------------------------------------------------

async function run() {
  var root = null;
  try {
    everyBlockOnTheRealTreeHasAPage();
    theHandleAnswersOnlyExactPaths();
    root = _defaultsTree();
    missingTagsTakeTheDocumentedDefaults(root);
    aNewBlockProducesANewPage(root);
    theShapesBuildRefusesAreRefusedByName();
  } finally {
    if (root !== null) helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "wiki-pages", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
