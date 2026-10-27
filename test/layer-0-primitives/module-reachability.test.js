// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * module-reachability: a module nothing requires does not run, and every
 * gate it holds still passes.
 *
 * The failure has no symptom from inside the file. The comment-block
 * validator reads the module and is satisfied. The freeze coverage gate
 * reads its exported surface and is satisfied. Its own tests drive it
 * directly and pass. Nothing asks whether anything CALLS it, so a
 * complete, documented, green module can sit in `lib/` composed by
 * nothing, and the first report of it is an operator opening a console
 * page that renders empty while the table behind the page exists and the
 * mail that would have filled it was filed as ordinary mail.
 *
 * This file asks the question none of the others ask. Starting from the
 * two entry points an operator actually invokes, `lib/index.js` and
 * `bin/blamepost.js`, which modules does `require` reach.
 *
 * REACHABILITY IS TRANSITIVE. A module reached only through three other
 * modules is reached. A rule demanding that `lib/index.js` require every
 * module directly would report most of the tree and be switched off,
 * which answers less than not asking, so the walk takes the closure over
 * require edges rather than reading one file's import list.
 *
 * WHAT AN EDGE IS. A `require()` call carrying a relative string literal,
 * read from source with its comment lines removed. The comments are
 * removed because nearly every module here carries an `@example` block
 * that requires itself by name, and an edge taken out of one would make
 * every documented module reachable from its own documentation. A require
 * written inside a closure is still an edge, which is what makes
 * `b.lazyRequire` visible: the documented circular-dependency form wraps a
 * literal require in a function body, so the walk follows it with no case
 * of its own.
 *
 * WHAT IS NOT A MODULE, each verified against the tree rather than
 * assumed. `lib/vendor/` is the vendored framework. `lib/web/public/`
 * holds browser assets that a page loads by URL, so each island is held
 * against the view that names it instead of against a require edge.
 * `lib/web/views/` holds HTML templates and carries no JavaScript at all,
 * which is asserted here rather than taken on trust, because the day one
 * appears there it would be a module outside the walk.
 *
 * COUNTS. Three, because they fail independently. `lib-modules-discovered`
 * is what the directory walk found, `require-edges-followed` is what the
 * source reader extracted, and `lib-modules-reached` is where the closure
 * arrived. A reader that stopped matching takes the edge count to zero
 * while discovery stays healthy; a discovery resolved against a wrong
 * directory takes the first to zero while the closure still reports a
 * clean verdict over nothing. Zero in any of the three is refused.
 *
 * The walk is exported and driven over fixture trees written to a
 * temporary directory, so the finding, the transitive case, the closure
 * case, the documentation case and the empty-set refusal are each proven
 * on a tree built to carry one of them. Planting an orphan module in
 * `lib/` to prove the gate fires would leave in the shipped tree exactly
 * what the gate exists to refuse.
 *
 * A require edge is necessary and not sufficient: a module required into
 * a binding nobody reads is reachable here and composed by nothing. That
 * shape is what `no-unused-vars` refuses under `npm run lint`, and the
 * two questions are left where each can be answered.
 *
 * No sockets, no database, no network. It reads source text and writes
 * fixture trees to a temporary directory.
 *
 * Run standalone:
 * node test/layer-0-primitives/module-reachability.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;
var count   = helpers.count;

var REPO_ROOT = helpers.REPO_ROOT;

// ---------------------------------------------------------------------------
// Where the walk starts
// ---------------------------------------------------------------------------

// The two paths an operator's process actually enters by. `bin/blamepost.js`
// is the command line and `lib/index.js` is the composition facade the
// command line and every embedder load. Both are frozen contracts: the
// binary is what `package.json` publishes and the facade is what `main`
// names, so neither is a symbol a rename could quietly move.
var ENTRY_POINTS = [
  "lib/index.js",
  "bin/blamepost.js",
];

// ---------------------------------------------------------------------------
// Paths under lib/ that are not modules, and why
// ---------------------------------------------------------------------------

/**
 * NOT_MODULES names each prefix the walk neither counts as a module nor
 * follows edges out of. Each carries the mechanism that puts it outside a
 * require graph, because a prefix with no reason beside it is a hole
 * somebody widens the next time the gate is inconvenient.
 *
 * Both entries are checked against the tree below: a prefix matching no
 * JavaScript file at all is a note describing something that is no longer
 * there, and it is removed rather than kept.
 */
var NOT_MODULES = [
  {
    prefix: "lib/vendor/",
    reason: "The vendored framework, written whole by scripts/vendor-update.sh " +
      "and read-only in this repository. Its internal require graph is the " +
      "upstream project's to answer for, and a refresh replaces every file in " +
      "it, so a finding here would be one nobody in this tree may act on.",
  },
  {
    prefix: "lib/web/public/",
    reason: "Browser assets. A view loads an island with a script tag naming " +
      "its URL under /static, which is a mechanism no require walk can see, so " +
      "each island is held against the view that names it instead. Nothing " +
      "here is loaded by the server process at all.",
  },
];

/**
 * REACHED_AT_RUNTIME names a module the static walk cannot see an edge to,
 * with the runtime mechanism that reaches it.
 *
 * The bar is that a real mechanism carries the module into a running
 * process: a path assembled at load time, a directory read at boot, a
 * handle registered by name. "Nobody has wired it yet" is the finding this
 * file exists to report and is not an entry here.
 *
 * The checks below hold every entry to both edges: it has to name a file
 * that exists, argue its case in a sentence, and be genuinely unreachable,
 * because an entry on a module the walk already reaches is a note asserting
 * something untrue about the tree.
 */
var REACHED_AT_RUNTIME = {
  "lib/store/migrations/0001-dmarc-reports-unique-by-organization.js":
    "A schema migration. lib/store/index.js hands the migrations directory to b.db.init " +
    "as migrationDir on every writable open, and the framework reads that directory at " +
    "boot and requires each file it has not recorded as applied, so no require names it.",
};

// A reason has to be an argument rather than a label, held to the same
// length the invocation exemptions are held to.
var MIN_REASON = 80;

// ---------------------------------------------------------------------------
// Reading source
// ---------------------------------------------------------------------------

// A comment-only line, in the two forms this repository writes: the `//`
// note and the interior of a block header. Line based rather than a real
// comment parser, and the direction of its remaining error is the safe
// one: dropping a line it should have kept costs an edge and produces a
// loud finding somebody goes and reads, while keeping a documentation
// example would invent an edge and hide an orphan.
var COMMENT_ONLY_RE = /^\s*(?:\/\/|\*|\/\*)/;

// The call itself, which is CommonJS syntax rather than anything this
// repository names. A specifier is taken only when it is a plain string
// literal, so a computed require is left to the unresolved report instead
// of being guessed at.
var REQUIRE_CALL_RE = /require\(\s*(["'])([^"']+)\1\s*\)/g;

function _withoutComments(source) {
  var kept = [];
  String(source).split(/\r?\n/).forEach(function (line) {
    if (!COMMENT_ONLY_RE.test(line)) kept.push(line);
  });
  return kept.join("\n");
}

function _specifiersIn(source) {
  var text  = _withoutComments(source);
  var found = [];
  var hit;
  REQUIRE_CALL_RE.lastIndex = 0;
  while ((hit = REQUIRE_CALL_RE.exec(text)) !== null) found.push(hit[2]);
  return found;
}

// ---------------------------------------------------------------------------
// Walking the tree
// ---------------------------------------------------------------------------

function _posix(root, abs) {
  return nodePath.relative(root, abs).split(nodePath.sep).join("/");
}

// Whether a path names a file that is there. A candidate that is absent is
// the ordinary case for a resolver: two of the three forms CommonJS tries
// never exist for any given specifier, so the absence is an answer rather
// than a fault, and the next form is tried.
function _isFile(abs) {
  try { return nodeFs.statSync(abs).isFile(); }
  catch (_e) { return false; }
}

function _outsideTheGraph(rel) {
  var withSlash = rel + "/";
  for (var i = 0; i < NOT_MODULES.length; i += 1) {
    if (withSlash.indexOf(NOT_MODULES[i].prefix) === 0) return true;
  }
  return false;
}

function _gatherJs(root, dirAbs, acc) {
  var entries;
  try { entries = nodeFs.readdirSync(dirAbs, { withFileTypes: true }); }
  catch (_e) { return acc; }
  for (var i = 0; i < entries.length; i += 1) {
    var entry = entries[i];
    var abs   = nodePath.join(dirAbs, entry.name);
    var rel   = _posix(root, abs);
    if (_outsideTheGraph(rel)) continue;
    if (entry.isDirectory()) { _gatherJs(root, abs, acc); continue; }
    if (entry.isFile() && /\.js$/.test(entry.name)) acc.push(rel);
  }
  return acc;
}

/**
 * _resolveEdge(root, fromRel, spec) answers what a specifier points at.
 *
 * `{ kind: "external" }` for a builtin or a bare package name, which no
 * question here is about. `{ kind: "file", rel }` for a relative
 * specifier that lands on a file, resolved the three ways CommonJS
 * resolves one. `{ kind: "unresolved" }` for a relative specifier that
 * lands on nothing, which is a broken require and reported as its own
 * finding rather than folded into the reachability answer.
 */
function _resolveEdge(root, fromRel, spec) {
  if (spec.charAt(0) !== ".") return { kind: "external", rel: "" };
  var base = nodePath.resolve(nodePath.dirname(nodePath.join(root, fromRel)), spec);
  var candidates = [base, base + ".js", nodePath.join(base, "index.js")];
  for (var i = 0; i < candidates.length; i += 1) {
    if (_isFile(candidates[i])) return { kind: "file", rel: _posix(root, candidates[i]) };
  }
  return { kind: "unresolved", rel: "" };
}

/**
 * reachability(opts) walks the require closure from the entry points and
 * reports what it found, what it reached, and what it did not.
 *
 * opts.root     the tree to read, absolute.
 * opts.entries  the entry points, relative to root. Defaults to the two
 *               an operator invokes.
 *
 * Two inputs are refused rather than absorbed, because both produce a
 * clean verdict over nothing: a tree the discovery walk found no module
 * in, and an entry point that is not there. A gate answering "everything
 * is reachable" for a directory it could not read is worse than one that
 * is not run, because somebody believes it.
 */
function reachability(opts) {
  opts = opts || {};
  var root = opts.root;
  if (typeof root !== "string" || root.length === 0) {
    throw new TypeError("reachability: opts.root (absolute path) required");
  }
  var entries = opts.entries === undefined ? ENTRY_POINTS : opts.entries;
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new TypeError("reachability: opts.entries must be a non-empty array");
  }

  var discovered = _gatherJs(root, nodePath.join(root, "lib"), []).sort();
  if (discovered.length === 0) {
    throw new Error("reachability: no module found under lib/ in " + root +
      ". A walk that read nothing answers for no part of the tree, so this is " +
      "refused rather than reported as a tree with nothing unreachable in it.");
  }

  var absentEntries = entries.filter(function (rel) {
    return !nodeFs.existsSync(nodePath.join(root, rel));
  });
  if (absentEntries.length > 0) {
    throw new Error("reachability: entry point(s) absent: " + absentEntries.join(", ") +
      ". The closure starts nowhere, so every module would read as unreachable.");
  }

  var seen       = Object.create(null);
  var queue      = entries.slice();
  var unresolved = [];
  var unreadable = [];
  var edges      = 0;

  while (queue.length > 0) {
    var current = queue.shift();
    if (seen[current] === true) continue;
    seen[current] = true;

    var source = null;
    // A file the walk arrived at and could not open would otherwise
    // contribute no edges and read as a module with no dependencies, so
    // everything behind it reads as unreachable and the reason is nowhere
    // in the answer. It is reported instead.
    try { source = nodeFs.readFileSync(nodePath.join(root, current), "utf8"); }
    catch (e) { unreadable.push(current + ": " + ((e && e.code) || String(e))); }
    if (source === null) continue;

    _specifiersIn(source).forEach(function (spec) {
      var target = _resolveEdge(root, current, spec);
      if (target.kind === "external") return;
      if (target.kind === "unresolved") {
        unresolved.push(current + " requires " + spec);
        return;
      }
      // A relative specifier that climbs out of the tree under
      // examination is somebody else's file. Reading it would follow the
      // graph off the edge of the question being asked.
      if (target.rel.indexOf("..") === 0) return;
      if (_outsideTheGraph(target.rel)) return;
      if (!/\.js$/.test(target.rel)) return;
      edges += 1;
      if (seen[target.rel] !== true) queue.push(target.rel);
    });
  }

  var reached = discovered.filter(function (rel) { return seen[rel] === true; });

  return {
    discovered:  discovered,
    reached:     reached,
    unreachable: discovered.filter(function (rel) { return seen[rel] !== true; }),
    unresolved:  unresolved,
    unreadable:  unreadable,
    edges:       edges,
  };
}

// ---------------------------------------------------------------------------
// Fixture trees
// ---------------------------------------------------------------------------

// Written at run time rather than committed, for the reason the whole file
// exists: an orphan module sitting in `lib/` to prove the gate fires is
// the defect, and a committed one would be found by every other gate as
// well.
function _writeTree(root, tree) {
  var paths = Object.keys(tree);
  for (var i = 0; i < paths.length; i += 1) {
    var abs = nodePath.join(root, paths[i].split("/").join(nodePath.sep));
    nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
    nodeFs.writeFileSync(abs, tree[paths[i]], "utf8");
  }
  return root;
}

// A tree carrying one of each shape the walk has to get right: a chain
// three modules deep, an edge written inside a closure body, an edge
// written only in a documentation example, a vendored subtree, a browser
// asset, and two modules nothing requires.
function _shapedTree() {
  return {
    "bin/blamepost.js":
      '"use strict";\n' +
      'var blamepost = require("../lib");\n' +
      "module.exports = blamepost;\n",

    "lib/index.js":
      '"use strict";\n' +
      "/**\n" +
      " * @example\n" +
      ' *   var documented = require("./store/documented-only");\n' +
      " */\n" +
      'var listeners = require("./mail/listeners");\n' +
      'var b = require("./vendor/blamejs");\n' +
      "module.exports = { listeners: listeners, b: b };\n",

    "lib/mail/listeners.js":
      '"use strict";\n' +
      'var posture = require("./posture");\n' +
      'var mailboxModule = b.lazyRequire(function () { return require("./mailbox"); });\n' +
      "module.exports = { posture: posture, mailboxModule: mailboxModule };\n",

    "lib/mail/posture.js":
      '"use strict";\n' +
      'var address = require("../store/address");\n' +
      "module.exports = { address: address };\n",

    "lib/mail/mailbox.js": '"use strict";\nmodule.exports = {};\n',
    "lib/store/address.js": '"use strict";\nmodule.exports = {};\n',

    // Required by nothing. This is the shape the gate is for.
    "lib/mail/reports.js": '"use strict";\nmodule.exports = {};\n',

    // Named only from the documentation example above.
    "lib/store/documented-only.js": '"use strict";\nmodule.exports = {};\n',

    "lib/vendor/blamejs/index.js":
      '"use strict";\n' +
      'var inner = require("./inner");\n' +
      "module.exports = { inner: inner };\n",
    "lib/vendor/blamejs/inner.js": '"use strict";\nmodule.exports = {};\n',

    "lib/web/public/islands/theme.js": '"use strict";\n',
  };
}

// ---------------------------------------------------------------------------
// The readers, driven directly
// ---------------------------------------------------------------------------

// Both readers decide what every answer below is made of, so each is
// asserted on its own. A comment stripper that dropped everything and an
// edge matcher that found nothing would together report a tree where every
// module is unreachable, and a stripper that kept comments would report one
// where nothing ever is.
function theReadersReadWhatTheyClaimTo() {
  var stripped = _withoutComments([
    '// var fromALineComment = require("./a");',
    ' * var fromABlockBody = require("./b");',
    '/* var fromABlockOpener = require("./c"); */',
    'var fromCode = require("./d");',
  ].join("\n"));

  count("the comment reader drops a line comment", stripped.indexOf("./a") === -1, stripped);
  count("the comment reader drops a block-comment body line",
    stripped.indexOf("./b") === -1, stripped);
  count("the comment reader drops a block-comment opener",
    stripped.indexOf("./c") === -1, stripped);
  count("the comment reader keeps the code beside them",
    stripped.indexOf("./d") !== -1, stripped);

  var plain = _specifiersIn('var a = require("./a");\n');
  count("the edge matcher reads a plain require", JSON.stringify(plain) === '["./a"]',
    JSON.stringify(plain));

  var tail = _specifiersIn('var codes = require("./dkim").CODES;\n');
  count("the edge matcher reads a require whose value is reached through a property",
    JSON.stringify(tail) === '["./dkim"]', JSON.stringify(tail));

  var lazy = _specifiersIn(
    'var m = b.lazyRequire(function () { return require("./compose"); });\n');
  count("the edge matcher reads a require written inside a closure, which is the " +
    "documented circular-dependency form", JSON.stringify(lazy) === '["./compose"]',
  JSON.stringify(lazy));

  var single = _specifiersIn("var a = require('./a');\n");
  count("the edge matcher reads either quote", JSON.stringify(single) === '["./a"]',
    JSON.stringify(single));

  var documented = _specifiersIn(' *   var config = require("./lib/config");\n');
  count("an example inside a documentation block is not an edge",
    documented.length === 0, JSON.stringify(documented));

  var computed = _specifiersIn("var m = require(names[i]);\n");
  count("a computed require yields no specifier to guess at",
    computed.length === 0, JSON.stringify(computed));
}

// ---------------------------------------------------------------------------
// The finding, on a tree built to carry it
// ---------------------------------------------------------------------------

function anOrphanIsNamedAndAReachedModuleIsNot() {
  var root = helpers.tempDir("reachred");
  try {
    _writeTree(root, _shapedTree());
    var rv = reachability({ root: root });

    count("shaped tree: a module nothing requires is named",
      rv.unreachable.indexOf("lib/mail/reports.js") !== -1, JSON.stringify(rv.unreachable));

    count("shaped tree: a module named only by a documentation example is named too",
      rv.unreachable.indexOf("lib/store/documented-only.js") !== -1,
      JSON.stringify(rv.unreachable));

    count("shaped tree: those two are the whole finding, so nothing reached is reported",
      rv.unreachable.length === 2, JSON.stringify(rv.unreachable));

    // The trap this design exists to avoid. `lib/store/address.js` is
    // three edges from the nearest entry point and is required by
    // `lib/index.js` nowhere.
    count("shaped tree: a module reached only through three others is reached",
      rv.reached.indexOf("lib/store/address.js") !== -1, JSON.stringify(rv.reached));

    count("shaped tree: a module reached only through a closure body is reached",
      rv.reached.indexOf("lib/mail/mailbox.js") !== -1, JSON.stringify(rv.reached));

    count("shaped tree: the module the command line reaches through the facade is reached",
      rv.reached.indexOf("lib/mail/listeners.js") !== -1, JSON.stringify(rv.reached));

    var vendored = rv.discovered.filter(function (rel) {
      return rel.indexOf("lib/vendor/") === 0;
    });
    count("shaped tree: the vendored subtree is not a module population",
      vendored.length === 0, JSON.stringify(vendored));

    var assets = rv.discovered.filter(function (rel) {
      return rel.indexOf("lib/web/public/") === 0;
    });
    count("shaped tree: a browser asset is not a module either",
      assets.length === 0, JSON.stringify(assets));

    count("shaped tree: the two counts disagree, which is what a finding looks like",
      rv.discovered.length === 7 && rv.reached.length === 5,
      rv.discovered.length + " discovered, " + rv.reached.length + " reached");

    count("shaped tree: the edges the closure followed are counted",
      rv.edges === 5, String(rv.edges));

    count("shaped tree: no edge went unresolved", rv.unresolved.length === 0,
      JSON.stringify(rv.unresolved));
  } finally {
    helpers.removeTempDir(root);
  }
}

// The control. Without it every claim above is satisfied by a walk that
// reports the whole tree unreachable.
function wiringTheOrphanSilencesTheFinding() {
  var root = helpers.tempDir("reachgreen");
  try {
    var tree = _shapedTree();
    tree["lib/index.js"] = tree["lib/index.js"].replace(
      'var listeners = require("./mail/listeners");',
      'var listeners = require("./mail/listeners");\n' +
      'var reports = require("./mail/reports");\n' +
      'var documented = require("./store/documented-only");');
    _writeTree(root, tree);

    var rv = reachability({ root: root });
    count("wired tree: nothing is reported unreachable", rv.unreachable.length === 0,
      JSON.stringify(rv.unreachable));
    count("wired tree: the two counts agree",
      rv.discovered.length === rv.reached.length && rv.discovered.length === 7,
      rv.discovered.length + " discovered, " + rv.reached.length + " reached");
  } finally {
    helpers.removeTempDir(root);
  }
}

// A require that lands on nothing is a broken module rather than an
// unreachable one, and reporting it as unreachable would send the reader
// to the wrong file.
function aRequireThatLandsOnNothingIsItsOwnFinding() {
  var root = helpers.tempDir("reachbroken");
  try {
    var tree = _shapedTree();
    tree["lib/mail/posture.js"] = '"use strict";\nvar gone = require("./was-here");\n' +
      "module.exports = { gone: gone };\n";
    _writeTree(root, tree);

    var rv = reachability({ root: root });
    count("broken edge: the specifier that resolved to nothing is reported",
      rv.unresolved.length === 1 && rv.unresolved[0].indexOf("./was-here") !== -1,
      JSON.stringify(rv.unresolved));
    count("broken edge: the module holding it is named",
      rv.unresolved[0].indexOf("lib/mail/posture.js") === 0, JSON.stringify(rv.unresolved));
  } finally {
    helpers.removeTempDir(root);
  }
}

// Both ways the walk can answer over nothing, refused where they happen
// rather than left for a caller to notice.
function aWalkThatReadNothingIsRefused() {
  var empty = helpers.tempDir("reachempty");
  try {
    nodeFs.mkdirSync(nodePath.join(empty, "lib", "web", "public"), { recursive: true });
    nodeFs.writeFileSync(nodePath.join(empty, "lib", "web", "public", "island.js"),
      '"use strict";\n', "utf8");
    var refusedEmpty = "";
    try { reachability({ root: empty }); }
    catch (e) { refusedEmpty = String(e && e.message); }
    count("a tree whose lib/ holds no module is refused rather than reported clean",
      /no module found under lib\//.test(refusedEmpty), refusedEmpty);
    count("the refusal says why a clean verdict over nothing is not one",
      /answers for no part of the tree/.test(refusedEmpty), refusedEmpty);
  } finally {
    helpers.removeTempDir(empty);
  }

  var noEntry = helpers.tempDir("reachnoentry");
  try {
    _writeTree(noEntry, _shapedTree());
    nodeFs.rmSync(nodePath.join(noEntry, "bin", "blamepost.js"), { force: true });
    var refusedEntry = "";
    try { reachability({ root: noEntry }); }
    catch (e2) { refusedEntry = String(e2 && e2.message); }
    count("an absent entry point is refused rather than starting the closure short",
      /entry point\(s\) absent/.test(refusedEntry) &&
      refusedEntry.indexOf("bin/blamepost.js") !== -1, refusedEntry);
  } finally {
    helpers.removeTempDir(noEntry);
  }

  var refusedRoot = "";
  try { reachability({}); }
  catch (e3) { refusedRoot = String(e3 && e3.message); }
  check("a walk with no root is refused", /opts\.root/.test(refusedRoot));

  var refusedEntries = "";
  try { reachability({ root: REPO_ROOT, entries: [] }); }
  catch (e4) { refusedEntries = String(e4 && e4.message); }
  check("a walk with no entry point is refused", /non-empty array/.test(refusedEntries));
}

// ---------------------------------------------------------------------------
// The exclusions, held against the tree they describe
// ---------------------------------------------------------------------------

// The first JavaScript file at any depth under a directory, or the empty
// string when there is none. It stops at the first hit rather than
// building a list, because the vendored subtree holds thousands of files
// and the question asked of it is only whether it holds any.
function _firstJsUnder(dirAbs) {
  var entries;
  try { entries = nodeFs.readdirSync(dirAbs, { withFileTypes: true }); }
  catch (_e) { return ""; }
  var subdirectories = [];
  for (var i = 0; i < entries.length; i += 1) {
    if (entries[i].isFile() && /\.js$/.test(entries[i].name)) {
      return nodePath.join(dirAbs, entries[i].name);
    }
    if (entries[i].isDirectory()) subdirectories.push(nodePath.join(dirAbs, entries[i].name));
  }
  for (var j = 0; j < subdirectories.length; j += 1) {
    var found = _firstJsUnder(subdirectories[j]);
    if (found !== "") return found;
  }
  return "";
}

function _filesUnder(dirAbs, pattern, acc) {
  var entries;
  try { entries = nodeFs.readdirSync(dirAbs, { withFileTypes: true }); }
  catch (_e) { return acc; }
  for (var i = 0; i < entries.length; i += 1) {
    var abs = nodePath.join(dirAbs, entries[i].name);
    if (entries[i].isDirectory()) { _filesUnder(abs, pattern, acc); continue; }
    if (entries[i].isFile() && pattern.test(entries[i].name)) acc.push(abs);
  }
  return acc;
}

function everyExclusionStillDescribesSomething() {
  NOT_MODULES.forEach(function (excluded) {
    var sample = _firstJsUnder(nodePath.join(REPO_ROOT, excluded.prefix));
    count("the exclusion for " + excluded.prefix + " still names a part of the tree " +
      "that holds JavaScript, so it is a decision rather than a note left behind",
    sample !== "", sample === "" ? "(nothing under it)" : nodePath.relative(REPO_ROOT, sample));

    count("the exclusion for " + excluded.prefix + " carries the mechanism that puts " +
      "it outside a require graph", excluded.reason.length >= MIN_REASON,
    excluded.reason.length + " characters");
  });

  // The templates. They hold no JavaScript today, so nothing excludes
  // them and nothing needs to. The day one appears there it is a module
  // the walk would open and count, so the absence is asserted rather than
  // assumed.
  var viewsDir = nodePath.join(REPO_ROOT, "lib", "web", "views");
  count("the view directory still exists to be asked about",
    nodeFs.existsSync(viewsDir), viewsDir);

  var viewFiles = _filesUnder(viewsDir, /\.html$/, []);
  count("the view scan still finds templates", viewFiles.length > 0,
    viewFiles.length + " template(s)");

  var moduleInViews = _firstJsUnder(viewsDir);
  count("the view directory holds templates and no module, so nothing there is " +
    "outside the walk without saying so", moduleInViews === "",
  moduleInViews === "" ? "none" : nodePath.relative(REPO_ROOT, moduleInViews));

  // The islands, held against the mechanism their exclusion names. An
  // island no view loads is the same defect one directory over: shipped,
  // documented, and never fetched.
  var islandsDir = nodePath.join(REPO_ROOT, "lib", "web", "public", "islands");
  var islands = _filesUnder(islandsDir, /\.js$/, []);
  count("the island scan still finds browser assets to hold against the views",
    islands.length > 0, islands.length + " island(s)");

  var viewText = viewFiles.map(function (abs) {
    return nodeFs.readFileSync(abs, "utf8");
  }).join("\n");

  var unloaded = islands.filter(function (abs) {
    return viewText.indexOf("islands/" + nodePath.basename(abs)) === -1;
  }).map(function (abs) { return nodePath.relative(REPO_ROOT, abs); });

  count("every island is loaded by a view, which is the mechanism its exclusion from " +
    "the require walk rests on", unloaded.length === 0, unloaded.join(", "));
}

// ---------------------------------------------------------------------------
// The tree that ships
// ---------------------------------------------------------------------------

function theTableOfRuntimeReachesIsHonest(report) {
  var declared = Object.keys(REACHED_AT_RUNTIME);

  var vanished = declared.filter(function (rel) {
    return !nodeFs.existsSync(nodePath.join(REPO_ROOT, rel));
  });
  count("every module declared reachable at runtime is still in the tree",
    vanished.length === 0, vanished.join(", "));

  var stale = declared.filter(function (rel) {
    return report.unreachable.indexOf(rel) === -1;
  });
  count("no module is declared reachable at runtime while the walk already reaches it",
    stale.length === 0, stale.join(", "));

  var unargued = declared.filter(function (rel) {
    return String(REACHED_AT_RUNTIME[rel]).trim().length < MIN_REASON;
  });
  count("every declaration names the mechanism rather than the path",
    unargued.length === 0, unargued.join(", "));
}

function everyModuleThatShipsIsReached(report) {
  count("both entry points are in the tree",
    ENTRY_POINTS.every(function (rel) {
      return nodeFs.existsSync(nodePath.join(REPO_ROOT, rel));
    }), ENTRY_POINTS.join(", "));

  // Canaries. Each of the three counts can go to zero on its own, and a
  // zero in any of them is a clean verdict reached by reading nothing.
  count("the discovery walk still finds modules under lib/", report.discovered.length > 1,
    report.discovered.length + " module(s)");
  count("the edge reader still finds require edges to follow", report.edges > 1,
    report.edges + " edge(s)");
  count("the closure still arrives somewhere", report.reached.length > 1,
    report.reached.length + " module(s)");

  count("every relative require in the reached tree resolves to a file",
    report.unresolved.length === 0, report.unresolved.join("; "), { limit: 2000 });

  count("every module the closure arrived at could be opened, so nothing behind an " +
    "unreadable file reads as unreachable for a reason the answer does not carry",
  report.unreadable.length === 0, report.unreadable.join("; "), { limit: 2000 });

  var unexplained = report.unreachable.filter(function (rel) {
    return !Object.prototype.hasOwnProperty.call(REACHED_AT_RUNTIME, rel);
  });

  count("every module under lib/ is reached from an entry point. A module nothing " +
    "requires is composed by nothing: it passes its own gates, ships in the tarball, " +
    "and does not run. Wire it into the module that owns its domain, delete it, or " +
    "name the runtime mechanism that reaches it",
  unexplained.length === 0, unexplained.join(", "), { limit: 2000 });
}

// ---------------------------------------------------------------------------

function run() {
  // The live report is taken first and its counts published immediately,
  // so the run says what it looked at whether the assertions below pass or
  // fail. A gate that publishes only on the clean path stops publishing at
  // the moment its number is worth reading.
  var report = reachability({ root: REPO_ROOT });
  console.log("EXAMINED " + report.discovered.length + " lib-modules-discovered");
  console.log("EXAMINED " + report.edges + " require-edges-followed");
  console.log("EXAMINED " + report.reached.length + " lib-modules-reached");

  theReadersReadWhatTheyClaimTo();

  anOrphanIsNamedAndAReachedModuleIsNot();
  wiringTheOrphanSilencesTheFinding();
  aRequireThatLandsOnNothingIsItsOwnFinding();
  aWalkThatReadNothingIsRefused();

  everyExclusionStillDescribesSomething();

  theTableOfRuntimeReachesIsHonest(report);
  everyModuleThatShipsIsReached(report);

  return helpers.getChecks();
}

module.exports = {
  name:         "module-reachability",
  run:          run,
  getChecks:    helpers.getChecks,
  reachability: reachability,
};

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
