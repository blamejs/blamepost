// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * supply-chain-vendor-integrity: a hand-edit to the vendored tree is a
 * finding, and a gate that cannot measure the tree says so.
 *
 * `lib/vendor/blamejs/` is read-only by rule. The next vendor refresh
 * replaces it wholesale, so a patch applied in place works, passes every
 * behavioral test, and vanishes the day somebody runs the refresh. Nothing
 * announces the loss. `lib/vendor/MANIFEST.json` records a SHA-256 hash
 * over the extracted tree at refresh time, and re-hashing the bytes on
 * disk is what turns that silent loss into a failing check on the commit
 * that introduced it.
 *
 * `scripts/check-vendor-integrity.js` is that check, in the static gate
 * chain rather than at boot. Two reasons it belongs there. An operator
 * gains nothing from a server that re-hashes the framework on every start,
 * and a tree that has already been tampered with is a tree that can rewrite
 * the boot check that measures it.
 *
 * The half this file exists for is the half that is easy to get wrong.
 * A gate that reports a mismatch is useful; a gate that reports success
 * because the manifest was deleted, or because the tree could not be read,
 * has stopped gating and says the opposite in its own log line. Absence is
 * the case that matters, so most of the cases below remove something rather
 * than corrupt it.
 *
 * Every case is offline and writes only inside a temporary directory. The
 * fixture builds a small repository-shaped tree, hashes it with the same
 * implementation the refresh tool uses, and then breaks exactly one thing.
 * One case runs the gate against the real repository, because a fixture the
 * test builds and hashes itself proves the two implementations agree with
 * each other and says nothing about the manifest that shipped.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/supply-chain-vendor-integrity.test.js`.
 */

var fs   = require("node:fs");
var path = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;

// The shared loopback runner. A second spawn wrapper is a second set of
// assumptions about environment inheritance and stream capture.
var shared = require("./vendor-refresh-atomicity.test.js");

// The refresh tool owns the hashing. Requiring it runs nothing: its main()
// sits behind a require.main guard. The fixture uses it so the recorded
// hash is produced by the implementation the gate has to agree with.
var refresh = require("../../scripts/refresh-vendor-manifest.js");

var integrity = require("../../scripts/check-vendor-integrity.js");

var REPO_ROOT     = helpers.REPO_ROOT;
var GATE_SCRIPT   = path.join(REPO_ROOT, "scripts", "check-vendor-integrity.js");
var REAL_MANIFEST = path.join(REPO_ROOT, "lib", "vendor", "MANIFEST.json");

var PACKAGE_KEY  = "blamejs";
var TREE_SLOT    = "server";
var TREE_REL     = "lib/vendor/blamejs/";

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

function _writeFile(abs, contents) {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, contents);
}

/**
 * _fixture(label) builds a repository-shaped temporary tree carrying a
 * vendored package and a manifest whose recorded hash matches it. The
 * caller breaks one thing and runs the gate.
 */
function _fixture(label) {
  var root         = helpers.tempDir("vendorint-" + label);
  var vendorDir    = path.join(root, "lib", "vendor");
  var treeAbs      = path.join(vendorDir, PACKAGE_KEY);
  var manifestPath = path.join(vendorDir, "MANIFEST.json");

  _writeFile(path.join(treeAbs, "package.json"),
    JSON.stringify({ name: "@blamejs/core", version: "0.18.51" }, null, 2) + "\n");
  _writeFile(path.join(treeAbs, "index.js"),
    "\"use strict\";\nmodule.exports = { version: \"0.18.51\" };\n");
  _writeFile(path.join(treeAbs, "lib", "mail-server-mx.js"),
    "\"use strict\";\nmodule.exports = { create: function () { return {}; } };\n");

  var manifest = {
    packages: {},
  };
  manifest.packages[PACKAGE_KEY] = {
    version:   "0.18.51",
    npm:       "@blamejs/core",
    license:   "Apache-2.0",
    source:    "https://registry.npmjs.org/@blamejs/core/-/core-0.18.51.tgz",
    integrity: "sha512-" + "A".repeat(86) + "==",
    bundledAt: "2026-08-23T00:00:00Z",
    files:     {},
    hashes:    {},
  };
  manifest.packages[PACKAGE_KEY].files[TREE_SLOT]  = TREE_REL;
  manifest.packages[PACKAGE_KEY].hashes[TREE_SLOT] = refresh.hashTree(treeAbs);

  _writeManifest(manifestPath, manifest);

  return {
    root:         root,
    treeAbs:      treeAbs,
    manifestPath: manifestPath,
    manifest:     manifest,
  };
}

function _writeManifest(manifestPath, manifest) {
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
}

function _readManifest(manifestPath) {
  return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
}

function _runGate(manifestPath, args) {
  return shared.runCommand(process.execPath,
    [GATE_SCRIPT, "--manifest", manifestPath].concat(args || []),
    { cwd: REPO_ROOT });
}

function _transcript(result) {
  return "exit=" + String(result.status) +
    " stdout: " + String(result.stdout || "").replace(/\s+/g, " ").slice(-500) +
    " stderr: " + String(result.stderr || "").replace(/\s+/g, " ").slice(-400);
}

function _statuses(result) {
  var doc = JSON.parse(String(result.stdout));
  return doc.results.map(function (r) { return r.status; });
}

// ---------------------------------------------------------------------------
// Cases: the tree still matches what the refresh recorded
// ---------------------------------------------------------------------------

async function _cleanCases() {
  var fx = _fixture("clean");
  var r  = await _runGate(fx.manifestPath, ["--json"]);
  check("clean fixture: the gate exits 0. " + _transcript(r), r.status === 0);
  check("clean fixture: every slot verifies. " + _transcript(r),
    _statuses(r).every(function (s) { return s === "verified"; }));

  // The shipped tree, measured through the shipped invocation. This is the
  // one case whose recorded hash this file did not write.
  var live = await shared.runCommand(process.execPath, [GATE_SCRIPT], { cwd: REPO_ROOT });
  check("the repository's own vendored tree matches its manifest. " + _transcript(live),
    live.status === 0);
  check("the shipped run names the package it measured. " + _transcript(live),
    String(live.stdout).indexOf(PACKAGE_KEY) !== -1);

  await _realTreeCases();
}

/**
 * _realTreeCases() points the gate at the shipped vendored tree through a
 * manifest copy in a temporary directory, once with the recorded hash the
 * refresh wrote and once with a single character of it changed.
 *
 * The fixture cases above prove the mechanism on a tree this file built and
 * hashed itself, which establishes that the two implementations agree with
 * each other. This establishes the thing that actually matters: one byte of
 * difference across the real framework, tens of megabytes of it, is a
 * failing check rather than a rounding error. Nothing here writes into
 * `lib/vendor/`, which is read-only by rule. The copy declares the tree by
 * absolute path so the temporary manifest addresses the shipped bytes
 * without a second copy of them.
 */
async function _realTreeCases() {
  var shipped = JSON.parse(fs.readFileSync(REAL_MANIFEST, "utf8"));
  var realTree = path.join(REPO_ROOT, "lib", "vendor", PACKAGE_KEY) + path.sep;
  var recorded = shipped.packages[PACKAGE_KEY].hashes[TREE_SLOT];

  function _copyPointingAtTheRealTree(label, hash) {
    var dir  = helpers.tempDir("vendorint-" + label);
    var copy = JSON.parse(JSON.stringify(shipped));
    copy.packages[PACKAGE_KEY].files[TREE_SLOT]  = realTree;
    copy.packages[PACKAGE_KEY].hashes[TREE_SLOT] = hash;
    var at = path.join(dir, "MANIFEST.json");
    _writeManifest(at, copy);
    return at;
  }

  var honest = await _runGate(_copyPointingAtTheRealTree("realok", recorded), ["--json"]);
  check("the shipped tree hashes to the value the refresh recorded. " + _transcript(honest),
    honest.status === 0 && _statuses(honest).indexOf("verified") !== -1);

  // Flip one hex digit of the recorded value. That stands in for one byte
  // of the tree having moved, which is what a hand-edit produces.
  var head = recorded.slice(0, recorded.length - 1);
  var last = recorded.slice(-1);
  var flipped = head + (last === "0" ? "1" : "0");
  var moved = await _runGate(_copyPointingAtTheRealTree("realmoved", flipped), ["--json"]);
  check("one character of difference across the shipped tree fails the gate. " +
    _transcript(moved), moved.status === 1);
  check("one character of difference reports a mismatch. " + _transcript(moved),
    _statuses(moved).indexOf("mismatch") !== -1);
}

// ---------------------------------------------------------------------------
// Cases: the tree was changed outside the vendor refresh
// ---------------------------------------------------------------------------

async function _handEditCases() {
  // A byte changed in a vendored file. This is the patch-in-place that
  // works until the next refresh discards it.
  var edited = _fixture("edited");
  fs.writeFileSync(path.join(edited.treeAbs, "lib", "mail-server-mx.js"),
    "\"use strict\";\nmodule.exports = { create: function () { return { patched: true }; } };\n");
  var r1 = await _runGate(edited.manifestPath, ["--json"]);
  check("a hand-edited file fails the gate. " + _transcript(r1), r1.status === 1);
  check("a hand-edited file reports a mismatch. " + _transcript(r1),
    _statuses(r1).indexOf("mismatch") !== -1);

  // A file added to the tree. The hash covers directory membership, so an
  // addition that touches no existing byte still moves it.
  var added = _fixture("added");
  _writeFile(path.join(added.treeAbs, "lib", "extra.js"), "\"use strict\";\n");
  var r2 = await _runGate(added.manifestPath, ["--json"]);
  check("a file added to the tree fails the gate. " + _transcript(r2), r2.status === 1);
  check("a file added to the tree reports a mismatch. " + _transcript(r2),
    _statuses(r2).indexOf("mismatch") !== -1);

  // A file removed from the tree.
  var removed = _fixture("removed");
  fs.rmSync(path.join(removed.treeAbs, "lib", "mail-server-mx.js"), { force: true });
  var r3 = await _runGate(removed.manifestPath, ["--json"]);
  check("a file removed from the tree fails the gate. " + _transcript(r3), r3.status === 1);
  check("a file removed from the tree reports a mismatch. " + _transcript(r3),
    _statuses(r3).indexOf("mismatch") !== -1);

  // The mismatch line has to name the slot and both values, or an operator
  // reading the failure cannot tell which vendored tree moved.
  var human = await _runGate(edited.manifestPath, []);
  check("the human output names the slot that moved. " + _transcript(human),
    String(human.stdout).indexOf(TREE_SLOT) !== -1);
  check("the human output names the recorded hash. " + _transcript(human),
    String(human.stdout).indexOf(edited.manifest.packages[PACKAGE_KEY].hashes[TREE_SLOT].slice(0, 24)) !== -1);
}

// ---------------------------------------------------------------------------
// Cases: the gate could not measure. Absence fails.
// ---------------------------------------------------------------------------

async function _unmeasuredCases() {
  // The manifest is gone. This is the case that matters: a check that
  // cannot find its own record must not report success.
  var gone = _fixture("nomanifest");
  fs.rmSync(gone.manifestPath, { force: true });
  var r1 = await _runGate(gone.manifestPath, ["--json"]);
  check("a missing manifest fails the gate. " + _transcript(r1), r1.status === 1);
  check("a missing manifest reports missing-manifest. " + _transcript(r1),
    _statuses(r1).indexOf("missing-manifest") !== -1);
  check("a missing manifest never prints the passing line. " + _transcript(r1),
    String(r1.stdout).indexOf("every vendored tree matches") === -1);

  // The manifest is there and cannot be parsed.
  var broken = _fixture("badjson");
  fs.writeFileSync(broken.manifestPath, "{ not json at all\n");
  var r2 = await _runGate(broken.manifestPath, ["--json"]);
  check("an unparseable manifest fails the gate. " + _transcript(r2), r2.status === 1);
  check("an unparseable manifest reports unreadable-manifest. " + _transcript(r2),
    _statuses(r2).indexOf("unreadable-manifest") !== -1);

  // The manifest parses and declares nothing. An empty packages map is a
  // manifest that measures no tree at all, which passes a per-package loop
  // by having nothing to loop over.
  var empty = _fixture("nopackages");
  _writeManifest(empty.manifestPath, { packages: {} });
  var r3 = await _runGate(empty.manifestPath, ["--json"]);
  check("a manifest declaring no packages fails the gate. " + _transcript(r3), r3.status === 1);
  check("a manifest declaring no packages reports no-packages. " + _transcript(r3),
    _statuses(r3).indexOf("no-packages") !== -1);

  // A package that declares no file slots. Same hole one level down.
  var noslots = _fixture("noslots");
  var m4 = _readManifest(noslots.manifestPath);
  m4.packages[PACKAGE_KEY].files  = {};
  m4.packages[PACKAGE_KEY].hashes = {};
  _writeManifest(noslots.manifestPath, m4);
  var r4 = await _runGate(noslots.manifestPath, ["--json"]);
  check("a package declaring no file slots fails the gate. " + _transcript(r4), r4.status === 1);
  check("a package declaring no file slots reports no-file-slots. " + _transcript(r4),
    _statuses(r4).indexOf("no-file-slots") !== -1);

  // The refresh tool writes the string MISSING when a declared path is not
  // on disk. A recorded hash that measures nothing is not a recorded hash.
  var marker = _fixture("missingmarker");
  var m5 = _readManifest(marker.manifestPath);
  m5.packages[PACKAGE_KEY].hashes[TREE_SLOT] = "MISSING";
  _writeManifest(marker.manifestPath, m5);
  var r5 = await _runGate(marker.manifestPath, ["--json"]);
  check("the missing-file marker as a recorded hash fails the gate. " + _transcript(r5),
    r5.status === 1);
  check("the missing-file marker reports no-recorded-hash. " + _transcript(r5),
    _statuses(r5).indexOf("no-recorded-hash") !== -1);

  // A slot with no recorded hash at all.
  var nohash = _fixture("nohash");
  var m6 = _readManifest(nohash.manifestPath);
  delete m6.packages[PACKAGE_KEY].hashes[TREE_SLOT];
  _writeManifest(nohash.manifestPath, m6);
  var r6 = await _runGate(nohash.manifestPath, ["--json"]);
  check("a slot with no recorded hash fails the gate. " + _transcript(r6), r6.status === 1);
  check("a slot with no recorded hash reports no-recorded-hash. " + _transcript(r6),
    _statuses(r6).indexOf("no-recorded-hash") !== -1);

  // The manifest is intact and the tree it names is gone.
  var notree = _fixture("notree");
  fs.rmSync(notree.treeAbs, { recursive: true, force: true });
  var r7 = await _runGate(notree.manifestPath, ["--json"]);
  check("a vendored tree that is not on disk fails the gate. " + _transcript(r7),
    r7.status === 1);
  check("a vendored tree that is not on disk reports missing-tree. " + _transcript(r7),
    _statuses(r7).indexOf("missing-tree") !== -1);

  // The declared path is a directory and a regular file is standing where
  // it should be. Reading it as a directory throws, and the gate has to
  // convert that throw into a verdict rather than a stack trace.
  var unreadable = _fixture("unreadable");
  fs.rmSync(unreadable.treeAbs, { recursive: true, force: true });
  fs.writeFileSync(unreadable.treeAbs, "not a directory\n");
  var r8 = await _runGate(unreadable.manifestPath, ["--json"]);
  check("a vendored tree that cannot be read fails the gate. " + _transcript(r8),
    r8.status === 1);
  check("a vendored tree that cannot be read reports unreadable-tree. " + _transcript(r8),
    _statuses(r8).indexOf("unreadable-tree") !== -1);
  check("an unreadable tree exits with the gate's own code rather than crashing. " +
    _transcript(r8), String(r8.stderr).indexOf("at Object.") === -1);
}

// ---------------------------------------------------------------------------
// Cases: the advisory run changes the exit code and never the claim
// ---------------------------------------------------------------------------

async function _warnCases() {
  var gone = _fixture("warn");
  fs.rmSync(gone.manifestPath, { force: true });
  var r = await _runGate(gone.manifestPath, ["--warn"]);
  check("--warn exits 0 on a missing manifest. " + _transcript(r), r.status === 0);
  check("--warn still reports the manifest as unmeasured. " + _transcript(r),
    /UNKNOWN/.test(String(r.stdout)));
}

// ---------------------------------------------------------------------------
// Cases: invocation
// ---------------------------------------------------------------------------

async function _invocationCases() {
  var r = await shared.runCommand(process.execPath, [GATE_SCRIPT, "--manifest"], { cwd: REPO_ROOT });
  check("--manifest with no path is refused rather than defaulted. " + _transcript(r),
    r.status === 2);
}

// ---------------------------------------------------------------------------
// The verdict function, exercised without a filesystem
// ---------------------------------------------------------------------------

function _verdictCases() {
  check("the gate exports a verdict function", typeof integrity._verdict === "function");

  var allGood = integrity._verdict([{ status: "verified" }, { status: "verified" }]);
  check("every slot verified is exit 0", allGood.code === 0);

  var oneBad = integrity._verdict([{ status: "verified" }, { status: "mismatch" }]);
  check("a mismatch is exit 1", oneBad.code === 1);
  check("a mismatch summary says the tree changed",
    /change|mismatch|moved/i.test(oneBad.summary));

  // The whole point of the file: each unmeasured status is a failure, and
  // it reads as unknown rather than as a mismatch, because an operator
  // chasing a mismatch looks at the tree and an operator chasing an
  // unknown looks at the gate.
  integrity.UNMEASURED_STATUSES.forEach(function (status) {
    var v = integrity._verdict([{ status: status }]);
    check("status '" + status + "' is exit 1", v.code === 1);
    check("status '" + status + "' reads as UNKNOWN", /UNKNOWN/.test(v.summary));
    check("status '" + status + "' counts as unmeasured",
      integrity._isUnmeasured({ status: status }) === true);
  });

  check("a verified slot is not unmeasured",
    integrity._isUnmeasured({ status: "verified" }) === false);
  check("a mismatch is not unmeasured",
    integrity._isUnmeasured({ status: "mismatch" }) === false);

  // An empty result set is the shape a manifest with nothing in it
  // produces. Nothing measured is not everything verified.
  var nothing = integrity._verdict([]);
  check("measuring nothing is exit 1", nothing.code === 1);

  check("the unmeasured list covers every status the walk can emit",
    integrity.UNMEASURED_STATUSES.indexOf("missing-manifest") !== -1 &&
    integrity.UNMEASURED_STATUSES.indexOf("unreadable-manifest") !== -1 &&
    integrity.UNMEASURED_STATUSES.indexOf("no-packages") !== -1 &&
    integrity.UNMEASURED_STATUSES.indexOf("no-file-slots") !== -1 &&
    integrity.UNMEASURED_STATUSES.indexOf("no-recorded-hash") !== -1 &&
    integrity.UNMEASURED_STATUSES.indexOf("missing-tree") !== -1 &&
    integrity.UNMEASURED_STATUSES.indexOf("unreadable-tree") !== -1);
}

// ---------------------------------------------------------------------------
// The gate is wired into the static chain
// ---------------------------------------------------------------------------

function _wiringCases() {
  var pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));
  var gates = String(pkg.scripts && pkg.scripts.gates);
  check("the static gate chain runs the vendored-tree integrity check. gates=" + gates,
    gates.indexOf("check-vendor-integrity.js") !== -1);
}

// ---------------------------------------------------------------------------

async function run() {
  _verdictCases();
  _wiringCases();
  await _cleanCases();
  await _handEditCases();
  await _unmeasuredCases();
  await _warnCases();
  await _invocationCases();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
