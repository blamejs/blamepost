// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * empty-set-refusal: a checker that found nothing to look at must not
 * report a clean tree.
 *
 * "OK, no findings" is byte-identical whether a checker read every file it
 * governs or none of them. A glob that stopped matching, a walk pointed at a
 * directory that moved, a filter that emptied its own input, a reader that
 * stopped recognizing the shape it reads: every one of them lands on a passing
 * exit code, and the passing sentence beside it is true of the empty run in the
 * same words it uses over a full one.
 *
 * `scripts/run-gates.js` and `scripts/release.js` already refuse a published
 * zero, and they cover the gates they SPAWN. The checkers here are invoked
 * bare instead: by a workflow step, by an npm lifecycle hook, by a line in the
 * release flow that wants a verdict and not a transcript. Nothing captures
 * their stdout, so for them a published count protects nothing and the exit
 * code is the whole of what they say. Each one therefore refuses its own empty
 * set, and these are the cases that hold it to that.
 *
 * WHAT IS DRIVEN. The checker, as its caller invokes it: a child process over a
 * constructed input, asserted on the exit code and the transcript. Nothing here
 * reaches into a checker's internals except where the thing that was wrong IS a
 * pure function, which is the case for the two currency verdicts; those are
 * called directly because calling them is what their own caller does.
 *
 * The inputs are built rather than found. An empty set that has to be waited
 * for is a case that passes for the wrong reason on a slow machine, so every
 * vector here constructs the emptiness it is about: a release-notes directory
 * with nothing hand-written in it, a lib tree with no source under it, a
 * manifest that declares no package, a document that names no file, a probe
 * list that every filter has emptied.
 *
 * WHY PORT 1. Two service vectors need a listener that is reliably ABSENT.
 * Binding an ephemeral port and closing it leaves a window where something else
 * can take it, and a vector that depends on that window is the flake this
 * suite's own rules forbid. Port 1 needs administrative privilege to bind and
 * carries a service nothing here runs, so a loopback connection to it is
 * refused by the kernel every time. The only socket in this file is that
 * refusal, made by the checker under test, which is the behavior being
 * asserted.
 *
 * No database and no network. It spawns node processes, writes fixtures under a
 * temporary directory, and reads what the processes printed.
 *
 * Run standalone:
 * node test/layer-0-primitives/empty-set-refusal.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");

var examinedCounts = require("../../scripts/examined-counts.js");
var vendorCurrency = require("../../scripts/check-vendor-currency.js");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var REPO_ROOT   = helpers.REPO_ROOT;
var SCRIPTS_DIR = nodePath.join(REPO_ROOT, "scripts");

// `npm pack` and `git` both run inside one of the fixtures, and a cold npm on
// a loaded machine is slower than the shared default allows for.
var PACK_CEILING_MS = 180000;
var RUN_CEILING_MS  = 60000;

// A port nothing can be listening on without administrative privilege, so a
// connection to it is refused rather than answered. See WHY PORT 1 above.
var CLOSED_PORT = "1";

// A `zeroIs` long enough to be the argument `publish` requires of one. What
// it says is a fixture's business; what matters here is that the mechanism
// refuses a reason too short to be an argument, so a vector exercising the
// allowance has to hand it a real one.
var FIXTURE_ZERO_IS =
  "the fold prunes these between cuts, so an empty set is the ordinary state here rather " +
  "than a discovery that stopped matching, and the series count beside it is refused at " +
  "zero and is what proves this run read anything at all";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// A throwaway repository root carrying the scripts a vector drives. Every one
// of them resolves the tree it reads from its own location, so a copy beside a
// constructed tree reads that tree and nothing else.
function _fixture(prefix, scripts) {
  var root = helpers.tempDir(prefix);
  nodeFs.mkdirSync(nodePath.join(root, "scripts"));
  scripts.concat(["examined-counts.js"]).forEach(function (name) {
    nodeFs.copyFileSync(nodePath.join(SCRIPTS_DIR, name), nodePath.join(root, "scripts", name));
  });
  return root;
}

function _write(root, rel, text) {
  var abs = nodePath.join(root, rel);
  nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
  nodeFs.writeFileSync(abs, text, "utf8");
  return abs;
}

function _writeJson(root, rel, value) {
  return _write(root, rel, JSON.stringify(value, null, 2) + "\n");
}

function _run(root, script, args, opts) {
  opts = opts || {};
  return spawnRun.runNodeScript([nodePath.join(root, "scripts", script)].concat(args || []), {
    cwd:       root,
    env:       opts.env || process.env,
    ceilingMs: opts.ceilingMs || RUN_CEILING_MS,
  });
}

// A capture that satisfies the one method `publish` calls on a stream, so the
// published lines can be read back without a file or a child process.
function _sink() {
  var text = "";
  return {
    write: function (chunk) { text += String(chunk); return true; },
    text:  function () { return text; },
  };
}

// A release document that satisfies every rule the notes schema carries.
function _release(version, tag) {
  return {
    version:  version,
    date:     "2026-08-29",
    headline: "Release " + version + " carries the " + tag + " change",
    summary:  "What " + tag + " changes for an operator, in one sentence.",
    sections: [{
      heading: "Fixed",
      items:   [{
        title: "The " + tag + " path",
        body:  "The " + tag + " path reports its refusal instead of returning a default.",
      }],
    }],
  };
}

// ---------------------------------------------------------------------------
// The publisher and the reader are one contract
// ---------------------------------------------------------------------------

// Every gate below routes its counts through `publish`, so a defect in it is a
// defect in all of them at once. The property that matters is agreement with
// the reader: a line this writes has to be a line `publishedCounts` reads, and
// a zero this lets through has to be a zero `emptyUnits` lets through, or a
// gate would call itself clean by a rule its caller does not share.
function theCountsThePublisherWritesAreTheCountsTheReaderReads() {
  var out = _sink();
  var code = examinedCounts.publish([
    { unit: "lib-source-files", n: 22 },
    { unit: "primitive-blocks", n: 118 },
  ], { stream: out, diagnostics: _sink() });

  count("publish: a run that examined something returns a passing code", code === 0, String(code));

  var read = examinedCounts.publishedCounts(out.text());
  count("publish: the reader parses back exactly what was published",
    read.length === 2 &&
    read[0].n === 22 && read[0].unit === "lib-source-files" &&
    read[1].n === 118 && read[1].unit === "primitive-blocks",
    JSON.stringify(read));
  count("publish: the reader finds nothing empty in a passing publish",
    examinedCounts.emptyUnits(read).length === 0, JSON.stringify(read));
}

function aUnitThatCameBackEmptyIsRefusedByName() {
  var out  = _sink();
  var diag = _sink();
  var code = examinedCounts.publish([
    { unit: "lib-source-files", n: 22 },
    { unit: "primitive-blocks", n: 0 },
  ], { stream: out, diagnostics: diag, tag: "[fixture]" });

  count("publish: one empty unit among several fails the run", code === 1, String(code));
  count("publish: the refusal names the unit that emptied",
    /REFUSED: 0 primitive-blocks/.test(diag.text()), diag.text().slice(0, 200));
  count("publish: the healthy unit is still published beside the refusal",
    /EXAMINED 22 lib-source-files/.test(out.text()), out.text());
  count("publish: the empty unit is not published as a zero the reader would refuse",
    out.text().indexOf("primitive-blocks") === -1, out.text());
}

// The one way past the refusal, and the property that keeps it from becoming
// the way this defect class returns: a stated zero is stated in prose and never
// published, because a published `EXAMINED 0` means "refuse me" to every caller
// that spawns the gate.
function aStatedZeroIsSaidOutLoudAndNeverPublished() {
  var out  = _sink();
  var diag = _sink();
  var code = examinedCounts.publish([
    { unit: "series-releases",        n: 3 },
    { unit: "cross-checked-releases", n: 0, zeroIs: FIXTURE_ZERO_IS },
  ], { stream: out, diagnostics: diag, tag: "[fixture]" });

  count("publish: a zero with a written reason does not fail the run", code === 0, String(code));
  count("publish: the reason is printed rather than passed over silently",
    /0 cross-checked-releases, which is expected here: the fold prunes these between cuts/
      .test(diag.text()), diag.text().slice(0, 200));
  count("publish: no line the reader would refuse is emitted for it",
    examinedCounts.emptyUnits(examinedCounts.publishedCounts(out.text())).length === 0 &&
    out.text().indexOf("cross-checked-releases") === -1, out.text());

  var everything = _sink();
  var allSuppressed = examinedCounts.publish([
    { unit: "cross-checked-releases", n: 0, zeroIs: FIXTURE_ZERO_IS },
  ], { stream: everything, diagnostics: _sink() });
  count("publish: a run where every unit was suppressed published nothing and fails",
    allSuppressed === 1 && everything.text() === "", String(allSuppressed) + " " + everything.text());
}

// The allowance is the way this defect class comes back, so the bar it has to
// clear is the point of it. A reason that asserts instead of arguing is
// refused at the write, beside the unit names the reader cannot parse, rather
// than accepted and discovered later by somebody reading a gate that stopped
// answering. "n/a" is a non-empty string; so is the unit's own name.
function aStatedZeroHasToArgueRatherThanAssert() {
  [
    "n/a",
    "expected",
    "cross-checked-releases",
    "zero is fine here, it always has been",
  ].forEach(function (weak) {
    var threw = false;
    try {
      examinedCounts.publish([
        { unit: "series-releases",        n: 3 },
        { unit: "cross-checked-releases", n: 0, zeroIs: weak },
      ], { stream: _sink(), diagnostics: _sink() });
    } catch (e) { threw = e instanceof TypeError; }
    count("publish: refuses " + JSON.stringify(weak) + " as a reason an empty set is expected",
      threw, weak.length + " characters");
  });

  count("publish: and the floor it holds them to is the one the gate declarations use",
    examinedCounts.MIN_ZERO_IS === 80, String(examinedCounts.MIN_ZERO_IS));

  // Canary. A floor that refused every reason would take the allowance away
  // rather than make it cost something, and the gates that legitimately reach
  // zero would have nowhere left to say so.
  var out = _sink();
  var accepted = examinedCounts.publish([
    { unit: "series-releases",        n: 3 },
    { unit: "cross-checked-releases", n: 0, zeroIs: FIXTURE_ZERO_IS },
  ], { stream: out, diagnostics: _sink() });
  count("publish: canary, a reason that argues its case is still accepted",
    accepted === 0 && /EXAMINED 3 series-releases/.test(out.text()), out.text());
}

// A unit name the reader cannot parse is a gate talking to itself, and it is
// refused where it is written rather than discovered by a caller that read no
// counts at all.
function aUnitTheReaderCouldNotParseIsRefusedAtTheWrite() {
  var bad = [
    { unit: "Primitive Blocks", n: 3 },
    { unit: "lib-source-files", n: -1 },
    { unit: "lib-source-files", n: 1.5 },
    { unit: "lib-source-files", n: 0, zeroIs: "   " },
  ];
  bad.forEach(function (u) {
    var threw = false;
    try { examinedCounts.publish([u], { stream: _sink(), diagnostics: _sink() }); }
    catch (e) { threw = e instanceof TypeError; }
    count("publish: refuses the unpublishable unit " + JSON.stringify(u), threw, JSON.stringify(u));
  });

  var empty = false;
  try { examinedCounts.publish([], { stream: _sink(), diagnostics: _sink() }); }
  catch (e) { empty = e instanceof TypeError; }
  count("publish: a gate naming no unit at all is refused", empty, "publish([])");

  // One unit answered for twice is two claims a reader cannot tell apart, and
  // it is how a healthy count could stand in for an empty one sharing its name.
  var twice = false;
  try {
    examinedCounts.publish([
      { unit: "lib-source-files", n: 22 },
      { unit: "lib-source-files", n: 0 },
    ], { stream: _sink(), diagnostics: _sink() });
  } catch (e) { twice = e instanceof TypeError; }
  count("publish: a unit answered for twice is refused", twice, "duplicate lib-source-files");
}

// ---------------------------------------------------------------------------
// The release-notes consolidation gate
// ---------------------------------------------------------------------------

function _notesFixture(files) {
  var root = _fixture("emptyset-notes", ["consolidate-release-notes.js"]);
  nodeFs.mkdirSync(nodePath.join(root, "release-notes"));
  Object.keys(files).forEach(function (name) {
    _writeJson(root, nodePath.join("release-notes", name), files[name]);
  });
  return root;
}

function _series(minor, releases) {
  return {
    "$schema":  "../scripts/release-notes-consolidated-schema.json",
    "minor":    minor,
    "releases": releases,
  };
}

// The state this repository is in between cuts, and the one the gate used to
// pass over in silence. The fold prunes the hand-written file, the cross-check
// loop then iterates zero times, and the run printed the same clean sentence it
// prints having compared a dozen releases.
async function theSteadyStateAfterAFoldSaysWhyItComparedNothing() {
  var root = _notesFixture({ "v0.1.x.json": _series("0.1", [_release("0.1.0", "first")]) });
  var rv = await _run(root, "consolidate-release-notes.js", ["--check"]);

  count("notes: a pruned tree still passes", rv.code === 0, tail(rv.out, 4));
  count("notes: and says out loud that it cross-checked nothing",
    /0 cross-checked-releases, which is expected here/.test(rv.out), tail(rv.out, 4));
  count("notes: while publishing the releases it DID verify",
    /EXAMINED 1 series-files/.test(rv.out) && /EXAMINED 1 series-releases/.test(rv.out),
    tail(rv.out, 4));
  count("notes: and publishes no zero the release battery would refuse",
    examinedCounts.emptyUnits(examinedCounts.publishedCounts(rv.out)).length === 0,
    tail(rv.out, 4));
}

// The half underneath the zero, and the one that made "zero is expected here"
// impossible to trust. A release document neither name pattern places was
// dropped before the cross-check loop ever saw it, so a release the operator
// wrote by hand could sit in the directory, folded into no series and rendered
// into no CHANGELOG entry, while the gate reported that every hand-written
// release agreed with its series.
async function aReleaseFileTheScanCannotPlaceIsNamedRatherThanDropped() {
  var root = _notesFixture({ "v0.1.x.json": _series("0.1", [_release("0.1.0", "first")]) });
  _writeJson(root, nodePath.join("release-notes", "0.1.1.json"), _release("0.1.1", "second"));

  var rv = await _run(root, "consolidate-release-notes.js", ["--check"]);
  count("notes: a release file matching neither pattern fails the gate",
    rv.code === 1, tail(rv.out, 3));
  count("notes: and the refusal names the file it could not place",
    rv.out.indexOf("0.1.1.json") !== -1, tail(rv.out, 3));
}

// Canary. Every case above would also be reported by a gate that refused
// everything, and a gate that refused everything would fail the tree it exists
// to admit. A hand-written release that agrees with its series is the shape the
// cross-check was written for, and it has to be accepted AND counted.
async function aHandWrittenReleaseThatAgreesIsAcceptedAndCounted() {
  var root = _notesFixture({
    "v0.1.x.json":  _series("0.1", [_release("0.1.1", "second"), _release("0.1.0", "first")]),
    "v0.1.1.json":  _release("0.1.1", "second"),
  });

  var rv = await _run(root, "consolidate-release-notes.js", ["--check"]);
  count("notes: canary, an agreeing hand-written release passes", rv.code === 0, tail(rv.out, 4));
  count("notes: canary, and the cross-check it ran is published as a count",
    /EXAMINED 1 cross-checked-releases/.test(rv.out) &&
    /EXAMINED 2 series-releases/.test(rv.out), tail(rv.out, 4));
}

// ---------------------------------------------------------------------------
// The CHANGELOG rebuild
// ---------------------------------------------------------------------------

function _genFixture(files) {
  var root = _fixture("emptyset-gen", ["generate-changelog-entry.js"]);
  _writeJson(root, "package.json", { name: "gen-fixture", version: "0.1.0", private: true });
  nodeFs.mkdirSync(nodePath.join(root, "release-notes"));
  Object.keys(files).forEach(function (name) {
    _writeJson(root, nodePath.join("release-notes", name), files[name]);
  });
  return root;
}

// The half the CHANGELOG generator shared with its sibling and did not
// refuse. A release document the name scan cannot place is dropped before
// anything renders, so the release is in no entry, and `--check` then reports
// that the committed file matches the notes, which it does, because the
// notes it matched are the ones it read.
async function aReleaseTheChangelogCannotPlaceIsNamedRatherThanDropped() {
  var root = _genFixture({ "v0.1.0.json": _release("0.1.0", "first") });
  var built = await _run(root, "generate-changelog-entry.js", ["--rebuild"]);
  count("changelog: the fixture rebuilds before anything is asked of it", built.code === 0,
    tail(built.out, 3));

  _writeJson(root, nodePath.join("release-notes", "0.1.1.json"), _release("0.1.1", "second"));

  var rv = await _run(root, "generate-changelog-entry.js", ["--check"]);
  count("changelog: a release document neither pattern places fails the check",
    rv.code === 1, tail(rv.out, 4));
  count("changelog: and the refusal names the file it could not place",
    rv.out.indexOf("0.1.1.json") !== -1, tail(rv.out, 4));
  count("changelog: rather than reporting that the committed file matches the notes",
    rv.out.indexOf("matches the rebuild") === -1, tail(rv.out, 4));
}

// The count that catches the other direction. Releases can be loaded and
// rendered while the sweep that reads their prose descends into none of
// them, and zero findings is the healthy answer, so nothing in the verdict
// can tell that apart from a clean tree.
async function aChangelogCheckPublishesWhatItReadAndWhatItSwept() {
  var root = _genFixture({
    "v0.1.x.json": _series("0.1", [_release("0.1.1", "second"), _release("0.1.0", "first")]),
  });
  await _run(root, "generate-changelog-entry.js", ["--rebuild"]);

  var rv = await _run(root, "generate-changelog-entry.js", ["--check"]);
  count("changelog: canary, a placeable tree still passes", rv.code === 0, tail(rv.out, 4));
  count("changelog: and both the releases rendered and the strings swept are published",
    /EXAMINED 2 rendered-releases/.test(rv.out) && /EXAMINED \d+ swept-prose-strings/.test(rv.out),
    tail(rv.out, 4));
  count("changelog: and neither is a zero the release battery would refuse",
    examinedCounts.emptyUnits(examinedCounts.publishedCounts(rv.out)).length === 0,
    tail(rv.out, 4));
}

// ---------------------------------------------------------------------------
// The published-release extract
// ---------------------------------------------------------------------------

function _extractFixture(changelog) {
  var root = _fixture("emptyset-extract", ["check-changelog-extract.js"]);
  _writeJson(root, "package.json", { name: "extract-fixture", version: "0.1.0", private: true });
  _write(root, "CHANGELOG.md", changelog);
  return root;
}

// The block this gate extracts becomes the published release body. A header
// with nothing under it extracts as one line and matches the canonical shape,
// so the run reported an entry extracting cleanly and the workflow behind it
// would publish a release page carrying a title and no notes.
async function anEntryWithNoBodyUnderItsHeaderIsRefused() {
  var root = _extractFixture("# Changelog\n\n## v0.1.x\n\n### v0.1.0 — 2026-08-29\n");
  var rv = await _run(root, "check-changelog-extract.js", []);

  count("extract: a header with nothing under it fails the gate", rv.code === 1, tail(rv.out, 4));
  count("extract: and the body is the unit named as empty",
    /REFUSED: 0 entry-body-lines/.test(rv.out), tail(rv.out, 4));
  count("extract: while the block length it DID read is published beside it",
    /EXAMINED 1 changelog-entry-lines/.test(rv.out), tail(rv.out, 4));
  count("extract: and the passing sentence is not printed above its own refusal",
    rv.out.indexOf("extracts cleanly") === -1, tail(rv.out, 4));
}

// Canary. A gate that refused everything would fail the entry it exists to
// admit, and the numbers behind that verdict have to be published rather than
// asserted.
async function anEntryWithABodyIsAcceptedAndCounted() {
  var root = _extractFixture("# Changelog\n\n## v0.1.x\n\n### v0.1.0 — 2026-08-29\n\n" +
    "A headline for the release\n\n#### Fixed\n\n- **A path** — It reports its refusal now.\n");
  var rv = await _run(root, "check-changelog-extract.js", []);

  count("extract: canary, an entry with a body under it passes", rv.code === 0, tail(rv.out, 4));
  count("extract: canary, and both the block and its body are published",
    /EXAMINED 7 changelog-entry-lines/.test(rv.out) && /EXAMINED 3 entry-body-lines/.test(rv.out),
    tail(rv.out, 4));
}

// ---------------------------------------------------------------------------
// The migration document
// ---------------------------------------------------------------------------

function _migratingFixture(sources) {
  var root = _fixture("emptyset-migrating", ["gen-migrating.js"]);
  nodeFs.mkdirSync(nodePath.join(root, "lib"), { recursive: true });
  Object.keys(sources).forEach(function (rel) { _write(root, rel, sources[rel]); });
  return root;
}

// MIGRATING.md is committed and read as a statement about the code, so the
// run that writes it has to have read the code. "No active deprecations" is
// byte-identical whether the walk read every source file and found none or
// read nothing at all, and the second is what a moved directory produces.
async function aMigrationDocumentIsNotWrittenFromAWalkThatReadNothing() {
  var root = _migratingFixture({});
  var rv = await _run(root, "gen-migrating.js", []);

  count("migrating: a walk that read no source fails the run", rv.code === 1, tail(rv.out, 4));
  count("migrating: and the source count is the unit named as empty",
    /REFUSED: 0 lib-source-files/.test(rv.out), tail(rv.out, 4));
  count("migrating: and no document is committed from it",
    nodeFs.existsSync(nodePath.join(root, "MIGRATING.md")) === false, tail(rv.out, 4));
}

// Canary, and the reason the deprecation count carries a written allowance
// rather than a refusal. A tree with source in it and no deprecation is the
// ordinary state of this repository, and the document exists to say so.
async function aTreeWithNoDeprecationStillWritesItsDocument() {
  var root = _migratingFixture({
    "lib/thing.js": "\"use strict\";\nmodule.exports = { thing: 1 };\n",
  });
  var rv = await _run(root, "gen-migrating.js", []);

  count("migrating: canary, source with no deprecation in it still writes the document",
    rv.code === 0 && nodeFs.existsSync(nodePath.join(root, "MIGRATING.md")), tail(rv.out, 4));
  count("migrating: canary, and the empty half is stated out loud rather than passed over",
    /0 declared-deprecations, which is expected here/.test(rv.out), tail(rv.out, 4));
  count("migrating: canary, while the source count that proves it looked is published",
    /EXAMINED 1 lib-source-files/.test(rv.out), tail(rv.out, 4));
  count("migrating: canary, and no zero the release battery would refuse is emitted",
    examinedCounts.emptyUnits(examinedCounts.publishedCounts(rv.out)).length === 0,
    tail(rv.out, 4));
}

// ---------------------------------------------------------------------------
// The vendor-currency verdict
// ---------------------------------------------------------------------------

// Pure, and called the way the gate calls it. "OK, every checked package
// matches its latest upstream release" is true of a run that checked none, and
// the sibling actions-currency gate has carried this guard all along.
function aCurrencyRunThatMeasuredNothingIsNotCurrent() {
  var nothing = vendorCurrency._verdict([]);
  count("vendor-currency: no result at all is UNKNOWN, not current",
    nothing.code === 1 && /no vendored package was measured/.test(nothing.summary),
    JSON.stringify(nothing));

  var allSkipped = vendorCurrency._verdict([{ key: "blamejs", status: "skipped" }]);
  count("vendor-currency: a manifest whose every entry is skipped measured nothing",
    allSkipped.code === 1 && /no vendored package was measured/.test(allSkipped.summary),
    JSON.stringify(allSkipped));

  var measured = vendorCurrency._verdict([{ key: "blamejs", status: "current" }]);
  count("vendor-currency: canary, one package actually compared still passes",
    measured.code === 0, JSON.stringify(measured));

  var stale = vendorCurrency._verdict([{ key: "blamejs", status: "stale" }]);
  count("vendor-currency: canary, a stale pin still reports as stale rather than as unmeasured",
    stale.code === 1 && /behind the latest upstream release/.test(stale.summary),
    JSON.stringify(stale));
}

// ---------------------------------------------------------------------------
// The prepack guard
// ---------------------------------------------------------------------------

function _packFixture(docs) {
  var root = _fixture("emptyset-pack", ["check-pack-against-gitignore.js"]);
  _writeJson(root, "package.json", {
    name:    "empty-set-pack-fixture",
    version: "0.0.0",
    private: true,
    files:   Object.keys(docs),
  });
  Object.keys(docs).forEach(function (name) { _write(root, name, docs[name]); });
  // `git check-ignore` answers about a repository, so the fixture is one.
  nodeFs.mkdirSync(nodePath.join(root, ".git"), { recursive: true });
  nodeFs.rmSync(nodePath.join(root, ".git"), { recursive: true, force: true });
  return root;
}

async function _gitInit(root) {
  return await spawnRun.runNodeScript(
    ["-e", "var c=require('node:child_process');" +
           "c.spawnSync('git',['init','-q','.'],{cwd:process.cwd(),stdio:'ignore'});"],
    { cwd: root, ceilingMs: RUN_CEILING_MS });
}

// A tarball whose documents resolved no link at all. The passing sentence is
// the same one printed over a tarball whose every link was followed, and the
// document-set floor above it does not catch this: it proves documents were
// FOUND, not that a single one of them was READ.
async function aTarballWhoseDocumentsNamedNothingIsRefused() {
  var root = _packFixture({
    "README.md": "# Fixture\n\nA shipped document that names no file beside it.\n",
  });
  await _gitInit(root);

  var rv = await _run(root, "check-pack-against-gitignore.js", [], { ceilingMs: PACK_CEILING_MS });
  count("prepack: a document set with no link in it fails the guard",
    rv.code === 1, tail(rv.out, 4));
  count("prepack: and the refusal says the link check answered for nothing",
    /not one link was found/.test(rv.out), tail(rv.out, 4));
}

// Canary. The guard has to keep admitting a tarball whose links resolve, and it
// has to publish the counts behind that verdict rather than assert it bare.
async function aTarballWhoseLinksResolveIsAcceptedAndCounted() {
  var root = _packFixture({
    "README.md":   "# Fixture\n\nSee [the guide](./GUIDE.md) and [its section](./GUIDE.md#usage).\n",
    "GUIDE.md":    "# Guide\n\n## Usage\n\nWhat to do.\n",
  });
  await _gitInit(root);

  var rv = await _run(root, "check-pack-against-gitignore.js", [], { ceilingMs: PACK_CEILING_MS });
  count("prepack: canary, a tarball whose links resolve still passes", rv.code === 0, tail(rv.out, 6));
  count("prepack: canary, and the links and sections it read are published",
    /EXAMINED 2 document-links/.test(rv.out) && /EXAMINED 1 document-sections/.test(rv.out),
    tail(rv.out, 6));
}

// ---------------------------------------------------------------------------
// The service pre-flight
// ---------------------------------------------------------------------------

function _services(args, env) {
  return spawnRun.runNodeScript(
    [nodePath.join("scripts", "check-services.js")].concat(args || []), {
      cwd:       REPO_ROOT,
      env:       Object.assign({}, process.env, env || {}),
      ceilingMs: RUN_CEILING_MS,
    });
}

// Four filters can empty the probe list, and an empty list probes nothing and
// then reports that nothing was down. That verdict is what the interop suite
// waits on, so the gate would clear a whole suite to run against a stack it
// never contacted.
async function aProbeListEmptiedByItsOwnFiltersIsRefused() {
  var rv = await _services(["--plain", "--tls"]);
  count("services: a filter pair that selects nothing fails the gate",
    rv.code === 2, tail(rv.out, 3));
  count("services: and says probing nothing is not a stack that is up",
    /no endpoint left to probe/.test(rv.out), tail(rv.out, 3));
}

// The same hole reached with a non-empty list. `down` counts REQUIRED endpoints
// that failed, so a list of optional listeners that are all absent takes it to
// zero without one row having been this server: the summary reported that zero
// endpoints answered as blamepost and exited 0, the count contradicting the
// verdict printed beside it.
async function aProbeListOfAbsentOptionalListenersIsRefused() {
  var rv = await _services(["pop3", "imaps", "pop3s", "https"], {
    BLAMEPOST_SERVICE_HOST:  "127.0.0.1",
    BLAMEPOST_SERVICE_PORTS: "pop3=" + CLOSED_PORT + ",imaps=" + CLOSED_PORT +
                             ",pop3s=" + CLOSED_PORT + ",https=" + CLOSED_PORT,
    BLAMEPOST_SERVICE_PROBE_TIMEOUT_MS: "1500",
  });
  count("services: a run that identified nothing fails the gate", rv.code === 2, tail(rv.out, 4));
  count("services: and says it identified nothing rather than that nothing was down",
    /identified nothing and proved nothing/.test(rv.out), tail(rv.out, 4));
}

// Canary. A gate that refused everything would fail the stack it exists to
// admit, and it would also swallow the ordinary verdict. A required listener
// that is genuinely down is a different answer from a run that probed nothing,
// and the two have to keep their own exit codes.
async function aRequiredListenerThatIsDownKeepsItsOwnVerdict() {
  var rv = await _services(["mx"], {
    BLAMEPOST_SERVICE_HOST:  "127.0.0.1",
    BLAMEPOST_SERVICE_PORTS: "mx=" + CLOSED_PORT,
    BLAMEPOST_SERVICE_PROBE_TIMEOUT_MS: "1500",
  });
  count("services: canary, a required listener that is down still exits 1, not 2",
    rv.code === 1, tail(rv.out, 4));
  count("services: canary, and is reported as unreachable rather than as unprobed",
    /required endpoint\(s\) unreachable or not this server/.test(rv.out), tail(rv.out, 4));
}

// ---------------------------------------------------------------------------
// The vendored SBOM
// ---------------------------------------------------------------------------

function _sbomFixture(packages) {
  var root = _fixture("emptyset-sbom", ["build-vendored-sbom.js"]);
  _writeJson(root, "package.json", {
    name:    "@blamejs/blamepost",
    version: "0.1.0",
    private: true,
  });
  _writeJson(root, nodePath.join("lib", "vendor", "MANIFEST.json"), { packages: packages });
  return root;
}

// This document is a trust root: signed, provenanced, and read by an operator
// to learn what code ships inside the tarball. With no components it is a
// signed assertion that this package vendors nothing, false about every release
// this repository can cut and false in the one direction a reader cannot
// detect.
async function aZeroComponentSbomIsRefusedRatherThanEmitted() {
  var root = _sbomFixture({});
  var rv = await _run(root, "build-vendored-sbom.js", []);

  count("sbom: a manifest declaring no package fails the build", rv.code === 1, tail(rv.out, 4));
  count("sbom: and both empty units are named",
    /REFUSED: 0 manifest-packages/.test(rv.out) && /REFUSED: 0 sbom-components/.test(rv.out),
    tail(rv.out, 4));
  count("sbom: no document is written for a later job to sign",
    rv.out.indexOf("\"bomFormat\"") === -1, tail(rv.out, 4));
}

// Canary. The builder has to keep emitting a document for a manifest that
// declares one, and the counts it publishes go to stderr because stdout is the
// artifact.
async function aManifestWithOnePackageStillBuildsItsDocument() {
  var root = _sbomFixture({
    blamejs: { version: "0.18.57", npm: "@blamejs/core", license: "Apache-2.0" },
  });
  var rv = await _run(root, "build-vendored-sbom.js", []);

  count("sbom: canary, one declared package still builds", rv.code === 0, tail(rv.out, 3));
  count("sbom: canary, and the document carries the component",
    /"bomFormat": "CycloneDX"/.test(rv.out) && /pkg:npm\/%40blamejs\/core@0\.18\.57/.test(rv.out),
    tail(rv.out, 3));
  count("sbom: canary, and what it examined is published beside it",
    /EXAMINED 1 manifest-packages/.test(rv.out) && /EXAMINED 1 sbom-components/.test(rv.out),
    tail(rv.out, 3));
}

// ---------------------------------------------------------------------------
// The swallow gate
// ---------------------------------------------------------------------------

// An lcov report and a lib tree with no source under it. "Every lib swallow
// re-throws, is execution-covered, or is explicitly marked" is true of that run
// in the same words, and three chain gates publishing the same walk do not
// answer for this one: the coverage script that drives it is not in the chain.
async function anEmptyLibWalkIsRefusedByTheSwallowGate() {
  var root = _fixture("emptyset-swallow", ["check-swallow-coverage.js", "source-primitives.js"]);
  nodeFs.mkdirSync(nodePath.join(root, "lib"));
  _write(root, nodePath.join("coverage", "lcov.info"),
    "TN:\nSF:lib/moved-away.js\nDA:1,1\nLF:1\nLH:1\nend_of_record\n");

  var rv = await _run(root, "check-swallow-coverage.js", []);
  count("swallows: a walk that read no source fails the gate", rv.code === 1, tail(rv.out, 4));
  count("swallows: and both units it answers for are named",
    /REFUSED: 0 lib-source-files/.test(rv.out) && /REFUSED: 0 lib-swallows/.test(rv.out),
    tail(rv.out, 4));
  count("swallows: and the passing sentence is not printed above its own refusal",
    rv.out.indexOf("every lib swallow re-throws") === -1, tail(rv.out, 4));
}

// The unit that catches the other direction. A finder that stopped matching
// leaves every file read and recognizes no catch in any of them, which reports
// a healthy file count beside a verdict about nothing.
async function aLibTreeWithNoSwallowInItIsRefusedToo() {
  var root = _fixture("emptyset-noswallow", ["check-swallow-coverage.js", "source-primitives.js"]);
  _write(root, nodePath.join("lib", "clean.js"),
    "\"use strict\";\nfunction f() { return 1; }\nmodule.exports = { f: f };\n");
  _write(root, nodePath.join("coverage", "lcov.info"),
    "TN:\nSF:lib/clean.js\nDA:2,1\nLF:1\nLH:1\nend_of_record\n");
  // The gate refuses to answer from a report older than the sources it
  // describes, so the report is touched forward of them.
  var lcov = nodePath.join(root, "coverage", "lcov.info");
  var future = new Date(Date.now() + 60000);
  nodeFs.utimesSync(lcov, future, future);

  var rv = await _run(root, "check-swallow-coverage.js", []);
  count("swallows: a tree read in full with no swallow recognized in it fails too",
    rv.code === 1, tail(rv.out, 4));
  count("swallows: and the file count is published while the swallow count is refused",
    /EXAMINED 1 lib-source-files/.test(rv.out) && /REFUSED: 0 lib-swallows/.test(rv.out),
    tail(rv.out, 4));
}

// Canary. A swallow the suite drives has to keep passing, or the gate is one
// that refuses everything.
async function aCoveredSwallowStillPasses() {
  var root = _fixture("emptyset-swallowok", ["check-swallow-coverage.js", "source-primitives.js"]);
  _write(root, nodePath.join("lib", "sink.js"), [
    "\"use strict\";",
    "function emit(fn) {",
    "  try { return fn(); }",
    "  catch (e) {",
    "    return null;",
    "  }",
    "}",
    "module.exports = { emit: emit };",
    "",
  ].join("\n"));
  // Line 5 is the catch body's own line, which the try opener cannot reach.
  _write(root, nodePath.join("coverage", "lcov.info"),
    "TN:\nSF:lib/sink.js\nDA:3,1\nDA:5,1\nLF:2\nLH:2\nend_of_record\n");
  var lcov = nodePath.join(root, "coverage", "lcov.info");
  var future = new Date(Date.now() + 60000);
  nodeFs.utimesSync(lcov, future, future);

  var rv = await _run(root, "check-swallow-coverage.js", []);
  count("swallows: canary, an execution-covered swallow still passes", rv.code === 0, tail(rv.out, 4));
  count("swallows: canary, and the counts behind that verdict are published",
    /EXAMINED 1 lib-source-files/.test(rv.out) && /EXAMINED 1 lib-swallows/.test(rv.out),
    tail(rv.out, 4));
}

// ---------------------------------------------------------------------------

async function run() {
  theCountsThePublisherWritesAreTheCountsTheReaderReads();
  aUnitThatCameBackEmptyIsRefusedByName();
  aStatedZeroIsSaidOutLoudAndNeverPublished();
  aStatedZeroHasToArgueRatherThanAssert();
  aUnitTheReaderCouldNotParseIsRefusedAtTheWrite();

  await theSteadyStateAfterAFoldSaysWhyItComparedNothing();
  await aReleaseFileTheScanCannotPlaceIsNamedRatherThanDropped();
  await aHandWrittenReleaseThatAgreesIsAcceptedAndCounted();

  await aReleaseTheChangelogCannotPlaceIsNamedRatherThanDropped();
  await aChangelogCheckPublishesWhatItReadAndWhatItSwept();

  await anEntryWithNoBodyUnderItsHeaderIsRefused();
  await anEntryWithABodyIsAcceptedAndCounted();

  await aMigrationDocumentIsNotWrittenFromAWalkThatReadNothing();
  await aTreeWithNoDeprecationStillWritesItsDocument();

  aCurrencyRunThatMeasuredNothingIsNotCurrent();

  await aTarballWhoseDocumentsNamedNothingIsRefused();
  await aTarballWhoseLinksResolveIsAcceptedAndCounted();

  await aProbeListEmptiedByItsOwnFiltersIsRefused();
  await aProbeListOfAbsentOptionalListenersIsRefused();
  await aRequiredListenerThatIsDownKeepsItsOwnVerdict();

  await aZeroComponentSbomIsRefusedRatherThanEmitted();
  await aManifestWithOnePackageStillBuildsItsDocument();

  await anEmptyLibWalkIsRefusedByTheSwallowGate();
  await aLibTreeWithNoSwallowInItIsRefusedToo();
  await aCoveredSwallowStillPasses();

  return helpers.getChecks();
}

module.exports = { name: "empty-set-refusal", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
