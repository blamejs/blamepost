// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * release-notes-shape: the structured release notes, the minor series
 * file they fold into, and the CHANGELOG derived from both.
 *
 * Every release here is a patch unless somebody decides otherwise, so
 * one hand-authored file per release means a minor line accumulates one
 * file per release forever. The fix is a series file, `v<X>.<Y>.x.json`,
 * holding every released version of that line newest first, and a
 * consolidation step that folds a per-release file into it. The
 * hand-authored step does not move: an operator still writes
 * `release-notes/v<X>.<Y>.<Z>.json` and the tooling folds it.
 *
 * Three tools have to agree about that arrangement, and the interesting
 * failures are all failures of agreement:
 *
 *   - `consolidate-release-notes.js --check` has to notice when a
 *     per-release file and its folded copy say different things. Two
 *     copies of one release that disagree is the whole risk the series
 *     file introduces, and it is silent by nature.
 *   - `generate-changelog-entry.js --check` has to notice when
 *     CHANGELOG.md no longer matches what the notes would render. A
 *     mode that accepts an unknown flag and prints something anyway
 *     passes that gate on every tree there is.
 *   - `check-changelog-extract.js` has to find the block the release
 *     workflow publishes, bounded by the next release rather than
 *     running into it.
 *
 * The cases below drive the three scripts as an operator and the
 * workflow drive them: a real child process, a real directory, real
 * exit codes. A fixture directory carries its own `package.json`,
 * `release-notes/` and a copy of each script, so the scripts resolve
 * their repository root to the fixture and no case writes into the
 * working tree.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/release-notes-shape.test.js`.
 */

var fs   = require("node:fs");
var path = require("node:path");
var proc = require("node:child_process");

var helpers = require("../helpers");
var check   = helpers.check;
var count   = helpers.count;

var REPO_ROOT   = helpers.REPO_ROOT;
var SCRIPTS_DIR = path.join(REPO_ROOT, "scripts");
var NOTES_DIR   = path.join(REPO_ROOT, "release-notes");
var CHANGELOG   = path.join(REPO_ROOT, "CHANGELOG.md");

var PER_RELEASE_SCHEMA  = path.join(SCRIPTS_DIR, "release-notes-schema.json");
var CONSOLIDATED_SCHEMA = path.join(SCRIPTS_DIR, "release-notes-consolidated-schema.json");

// The three scripts under test. A fixture gets a copy of each, because
// every one of them resolves its repository root from its own location.
var TOOLS = [
  "generate-changelog-entry.js",
  "consolidate-release-notes.js",
  "check-changelog-extract.js",
];

// What the tools require from beside themselves. `examined-counts.js` owns both
// halves of the published-count contract, and the consolidation gate publishes
// what it verified through it, so a fixture without it is a fixture where the
// tool cannot load at all.
var TOOL_SIBLINGS = ["examined-counts.js"];

// The separator the renderers emit inside a release header and between a
// bullet's title and its body. Built from its code point so this file's
// own source stays free of the character the house prose rule is about.
var EM = String.fromCharCode(0x2014);

// One of the tokens the generator's leak sweep exists to refuse, built
// from its code points rather than written out. A file proving the
// sweep catches internal sequencing vocabulary is still a file carrying
// that vocabulary, and the detector guarding this tree is right to say
// so. The sweep assembles its own patterns the same way, for the same
// reason.
var LEAK_TOKEN = String.fromCharCode(112, 104, 97, 115, 101) + " 4";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function _readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function _writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n", "utf8");
}

/**
 * A minimal release document that satisfies every rule the generator
 * enforces: a capitalized headline with no trailing punctuation, a
 * summary that ends a sentence, and one section whose item carries both
 * a title and a body long enough to be worth reading.
 */
function _release(version, date, tag) {
  return {
    version:  version,
    date:     date,
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

function _series(minor, releases) {
  return {
    "$schema":  "../scripts/release-notes-consolidated-schema.json",
    "minor":    minor,
    "releases": releases,
  };
}

/**
 * Build a throwaway repository root: `package.json`, `scripts/` holding a
 * copy of each tool, `release-notes/` holding whatever the case needs,
 * and optionally a CHANGELOG.md to start from.
 */
function _fixture(spec) {
  spec = spec || {};
  var root = helpers.tempDir("relnotes");
  fs.mkdirSync(path.join(root, "scripts"));
  fs.mkdirSync(path.join(root, "release-notes"));
  TOOLS.concat(TOOL_SIBLINGS).forEach(function (name) {
    fs.copyFileSync(path.join(SCRIPTS_DIR, name), path.join(root, "scripts", name));
  });
  _writeJson(path.join(root, "package.json"), {
    name:    "release-notes-fixture",
    version: spec.version || "0.1.0",
    private: true,
  });
  Object.keys(spec.notes || {}).forEach(function (name) {
    _writeJson(path.join(root, "release-notes", name), spec.notes[name]);
  });
  if (typeof spec.changelog === "string") {
    fs.writeFileSync(path.join(root, "CHANGELOG.md"), spec.changelog, "utf8");
  }
  return root;
}

/**
 * Run a tool the way the release flow runs it. The status comes from the
 * spawn itself: a shell pipeline would report the last command's exit
 * code and a correct refusal would read as success.
 */
function _tool(root, name, args) {
  var rv = proc.spawnSync(process.execPath,
    [path.join(root, "scripts", name)].concat(args || []),
    { cwd: root, encoding: "utf8" });
  return {
    status: rv.status,
    stdout: String(rv.stdout || ""),
    stderr: String(rv.stderr || ""),
    text:   String(rv.stdout || "") + String(rv.stderr || ""),
  };
}

function _transcript(rv) {
  return "exit=" + String(rv.status) + " " + rv.text.replace(/\s+/g, " ").slice(0, 400);
}

function _changelogOf(root) {
  return fs.readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
}

// ---------------------------------------------------------------------------
// The two schemas describe one release object
// ---------------------------------------------------------------------------

function _schemaCases() {
  var b = helpers.b;

  var consolidated;
  try { consolidated = _readJson(CONSOLIDATED_SCHEMA); }
  catch (e) {
    throw new Error("FAIL: scripts/release-notes-consolidated-schema.json is missing or malformed: " +
      helpers.formatErr(e));
  }
  var perRelease = _readJson(PER_RELEASE_SCHEMA);

  count("the consolidated schema declares the same dialect as the per-release schema",
    consolidated.$schema === perRelease.$schema, consolidated.$schema);
  count("the consolidated schema requires the series fields",
    Array.isArray(consolidated.required) &&
    consolidated.required.indexOf("minor") !== -1 &&
    consolidated.required.indexOf("releases") !== -1,
    JSON.stringify(consolidated.required));

  // The series file holds release objects, so the two schemas have to
  // agree about what a release object is. Anchoring on the required
  // field set and the heading vocabulary rather than on a definition
  // name keeps the comparison alive through a rename.
  var release = (consolidated.$defs || {}).release || {};
  count("the consolidated schema's release requires what a per-release file requires",
    JSON.stringify((release.required || []).slice().sort()) ===
    JSON.stringify((perRelease.required || []).slice().sort()),
    JSON.stringify(release.required) + " vs " + JSON.stringify(perRelease.required));

  var conHeadings = (((release.properties || {}).sections || {}).items || {});
  var conEnum = ((((consolidated.$defs || {}).section || {}).properties || {}).heading || {}).enum;
  var perEnum = ((((perRelease.$defs || {}).section || {}).properties || {}).heading || {}).enum;
  count("both schemas admit the same section headings",
    JSON.stringify(conEnum) === JSON.stringify(perEnum),
    JSON.stringify(conEnum));
  check("the consolidated release's sections point at a section definition",
    conHeadings && typeof conHeadings.$ref === "string");

  // A release object must not carry its own $schema pointer: the wrapper
  // carries it once for the series.
  count("the consolidated release object refuses a nested $schema",
    release.additionalProperties === false &&
    !Object.prototype.hasOwnProperty.call(release.properties || {}, "$schema"),
    JSON.stringify(Object.keys(release.properties || {})));

  // Every series file in the tree validates against it, and every
  // release inside one validates against the per-release schema.
  fs.readdirSync(NOTES_DIR).forEach(function (name) {
    if (!/^v\d+\.\d+\.x\.json$/.test(name)) return;
    var doc = _readJson(path.join(NOTES_DIR, name));
    var rv  = b.jsonSchema.validate(consolidated, doc);
    count("release-notes/" + name + " validates against the consolidated schema",
      rv.valid === true, JSON.stringify(rv.errors).slice(0, 300));
    doc.releases.forEach(function (r) {
      var one = b.jsonSchema.validate(perRelease, r);
      count("release-notes/" + name + " release v" + r.version + " validates as a release",
        one.valid === true, JSON.stringify(one.errors).slice(0, 300));
    });
  });
}

// ---------------------------------------------------------------------------
// The repository as it stands
// ---------------------------------------------------------------------------

function _liveTreeCases() {
  var names = fs.readdirSync(NOTES_DIR).filter(function (n) { return /\.json$/.test(n); });
  var seriesNames = names.filter(function (n) { return /^v\d+\.\d+\.x\.json$/.test(n); });
  count("release-notes/ carries at least one minor series file",
    seriesNames.length >= 1, names.join(" "));

  // Every release the tree knows about, per-release files and series
  // files alike.
  var releases = [];
  names.forEach(function (n) {
    var doc = _readJson(path.join(NOTES_DIR, n));
    if (/^v\d+\.\d+\.x\.json$/.test(n)) releases = releases.concat(doc.releases);
    else releases.push(doc);
  });
  check("release-notes/ describes at least one release", releases.length >= 1);

  var changelog = fs.readFileSync(CHANGELOG, "utf8");

  releases.forEach(function (r) {
    // Nothing the notes say may be missing from the rendered CHANGELOG:
    // the file is a view of the notes, not a summary of them.
    r.sections.forEach(function (s) {
      count("CHANGELOG.md carries the " + s.heading + " heading for v" + r.version,
        changelog.indexOf("#### " + s.heading) !== -1 ||
        changelog.indexOf("### " + s.heading) !== -1, s.heading);
      s.items.forEach(function (it) {
        count("CHANGELOG.md carries v" + r.version + " item title " + JSON.stringify(it.title),
          changelog.indexOf(it.title) !== -1, it.title);
        count("CHANGELOG.md carries the body behind " + JSON.stringify(it.title),
          changelog.indexOf(it.body) !== -1, it.body.slice(0, 80));
      });
    });
    (r.references || []).forEach(function (ref) {
      count("CHANGELOG.md carries the v" + r.version + " reference " + JSON.stringify(ref.label),
        changelog.indexOf(ref.url) !== -1, ref.url);
    });

    var extract = _tool(REPO_ROOT, "check-changelog-extract.js", [r.version]);
    count("check-changelog-extract.js finds v" + r.version + " in CHANGELOG.md",
      extract.status === 0, _transcript(extract));
  });

  // The minor grouping is what lets a reader upgrading across several
  // patches read one line per tag under one heading.
  var minors = {};
  releases.forEach(function (r) { minors[r.version.replace(/\.\d+$/, "")] = true; });
  Object.keys(minors).forEach(function (m) {
    count("CHANGELOG.md groups the " + m + " line under its own heading",
      changelog.indexOf("\n## v" + m + ".x\n") !== -1, "## v" + m + ".x");
  });

  var rebuilt = _tool(REPO_ROOT, "generate-changelog-entry.js", ["--check"]);
  count("generate-changelog-entry.js --check accepts the committed CHANGELOG.md",
    rebuilt.status === 0, _transcript(rebuilt));

  var folded = _tool(REPO_ROOT, "consolidate-release-notes.js", ["--check"]);
  count("consolidate-release-notes.js --check accepts the committed release notes",
    folded.status === 0, _transcript(folded));
}

// ---------------------------------------------------------------------------
// A minor series with several releases, rendered newest first
// ---------------------------------------------------------------------------

function _renderCases() {
  var root = _fixture({
    version: "0.2.1",
    notes: {
      "v0.1.x.json": _series("0.1", [
        _release("0.1.2", "2026-03-03", "third"),
        _release("0.1.1", "2026-02-02", "second"),
        _release("0.1.0", "2026-01-01", "first"),
      ]),
      "v0.2.0.json": _release("0.2.0", "2026-04-04", "fourth"),
      "v0.2.1.json": _release("0.2.1", "2026-05-05", "fifth"),
    },
  });

  var built = _tool(root, "generate-changelog-entry.js", ["--rebuild"]);
  count("--rebuild writes a CHANGELOG for a mixed tree", built.status === 0, _transcript(built));

  var md = _changelogOf(root);

  // Grouping: one heading per minor, highest first.
  var iMinor2 = md.indexOf("## v0.2.x");
  var iMinor1 = md.indexOf("## v0.1.x");
  count("both minor lines get a heading", iMinor2 !== -1 && iMinor1 !== -1,
    "0.2.x@" + iMinor2 + " 0.1.x@" + iMinor1);
  count("the newer minor line is rendered first", iMinor2 < iMinor1,
    "0.2.x@" + iMinor2 + " 0.1.x@" + iMinor1);

  // Ordering within a line: newest patch first, and every release
  // present exactly once even though 0.1.x holds three of them.
  var order = ["0.2.1", "0.2.0", "0.1.2", "0.1.1", "0.1.0"];
  var positions = order.map(function (v) { return md.indexOf("### v" + v + " " + EM); });
  positions.forEach(function (p, i) {
    count("v" + order[i] + " has a release header", p !== -1, "index " + p);
  });
  for (var i = 1; i < positions.length; i += 1) {
    count("v" + order[i - 1] + " is rendered before v" + order[i],
      positions[i - 1] < positions[i], positions[i - 1] + " < " + positions[i]);
  }
  order.forEach(function (v) {
    var re = new RegExp("^### v" + v.replace(/\./g, "\\.") + " ", "gm");
    count("v" + v + " is rendered exactly once", (md.match(re) || []).length === 1,
      String((md.match(re) || []).length));
  });

  // The rebuild is a pure function of the notes.
  var again = _tool(root, "generate-changelog-entry.js", ["--rebuild"]);
  count("--rebuild is byte stable across runs",
    again.status === 0 && _changelogOf(root) === md, _transcript(again));

  var accepted = _tool(root, "generate-changelog-entry.js", ["--check"]);
  count("--check accepts the file --rebuild just wrote", accepted.status === 0, _transcript(accepted));

  // Each version resolves, whether it lives in a per-release file or
  // inside the series file.
  order.forEach(function (v) {
    var one = _tool(root, "generate-changelog-entry.js", [v]);
    count("v" + v + " renders on its own", one.status === 0, _transcript(one));
    count("the v" + v + " render carries its own header",
      one.stdout.indexOf("### v" + v + " " + EM) === 0, one.stdout.slice(0, 80));

    var extracted = _tool(root, "check-changelog-extract.js", [v]);
    count("check-changelog-extract.js finds v" + v, extracted.status === 0, _transcript(extracted));
  });

  // The extract has to stop at the next release rather than swallow it.
  var block = _tool(root, "check-changelog-extract.js", ["0.1.1"]);
  count("the v0.1.1 extract reports a bounded block",
    block.status === 0 && /\b([2-9]|\d{2,}) line/.test(block.stdout + block.stderr),
    _transcript(block));
  count("the v0.1.1 extract does not run into v0.1.0",
    (block.stdout + block.stderr).indexOf("v0.1.0") === -1, _transcript(block));
}

// ---------------------------------------------------------------------------
// --check has to fail on a CHANGELOG that no longer matches the notes
// ---------------------------------------------------------------------------

function _driftCases() {
  var root = _fixture({
    version: "0.1.0",
    notes: { "v0.1.0.json": _release("0.1.0", "2026-01-01", "first") },
  });
  _tool(root, "generate-changelog-entry.js", ["--rebuild"]);

  var clean = _tool(root, "generate-changelog-entry.js", ["--check"]);
  count("--check passes on a freshly rebuilt CHANGELOG", clean.status === 0, _transcript(clean));

  var file = path.join(root, "CHANGELOG.md");
  fs.writeFileSync(file, _changelogOf(root) + "\n- a line nobody generated\n", "utf8");
  var appended = _tool(root, "generate-changelog-entry.js", ["--check"]);
  count("--check refuses a CHANGELOG with a hand-added line",
    appended.status !== 0, _transcript(appended));

  // A rewritten headline is the drift that matters most, because it
  // reads as intentional.
  _tool(root, "generate-changelog-entry.js", ["--rebuild"]);
  fs.writeFileSync(file, _changelogOf(root).replace("carries the first change", "carries something else"), "utf8");
  var reworded = _tool(root, "generate-changelog-entry.js", ["--check"]);
  count("--check refuses a CHANGELOG whose prose was edited in place",
    reworded.status !== 0, _transcript(reworded));

  // An absent CHANGELOG is a refusal, never a pass.
  fs.rmSync(file);
  var missing = _tool(root, "generate-changelog-entry.js", ["--check"]);
  count("--check refuses when CHANGELOG.md is absent", missing.status !== 0, _transcript(missing));

  // An unknown flag must not read as "no version given, render the
  // current one", which is how a gate stops gating without saying so.
  var unknown = _tool(root, "generate-changelog-entry.js", ["--not-a-mode"]);
  count("an unknown flag is refused rather than ignored", unknown.status !== 0, _transcript(unknown));
}

// ---------------------------------------------------------------------------
// Two copies of one release that disagree
// ---------------------------------------------------------------------------

function _agreementCases() {
  // Same release in both places, saying the same thing.
  var agreeing = _fixture({
    version: "0.1.1",
    notes: {
      "v0.1.x.json":  _series("0.1", [_release("0.1.0", "2026-01-01", "first")]),
      "v0.1.0.json":  _release("0.1.0", "2026-01-01", "first"),
    },
  });
  var ok = _tool(agreeing, "consolidate-release-notes.js", ["--check"]);
  count("--check accepts a per-release file that matches its folded copy",
    ok.status === 0, _transcript(ok));

  // Same release in both places, saying different things.
  var conflicting = _fixture({
    version: "0.1.1",
    notes: {
      "v0.1.x.json":  _series("0.1", [_release("0.1.0", "2026-01-01", "first")]),
      "v0.1.0.json":  _release("0.1.0", "2026-01-01", "different"),
    },
  });
  var clash = _tool(conflicting, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses a per-release file that contradicts its folded copy",
    clash.status !== 0, _transcript(clash));
  count("the refusal names the version that disagrees",
    clash.text.indexOf("0.1.0") !== -1, _transcript(clash));

  // A date that moved is a disagreement too, and the quietest one.
  var redated = _fixture({
    version: "0.1.1",
    notes: {
      "v0.1.x.json": _series("0.1", [_release("0.1.0", "2026-01-01", "first")]),
      "v0.1.0.json": _release("0.1.0", "2026-01-02", "first"),
    },
  });
  var moved = _tool(redated, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses a folded copy whose date moved", moved.status !== 0, _transcript(moved));

  // A per-release file nobody folded yet.
  var unfolded = _fixture({
    version: "0.1.1",
    notes: {
      "v0.1.x.json": _series("0.1", [_release("0.1.0", "2026-01-01", "first")]),
      "v0.1.1.json": _release("0.1.1", "2026-02-02", "second"),
    },
  });
  var pending = _tool(unfolded, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses a per-release file that was never folded",
    pending.status !== 0, _transcript(pending));
  count("the refusal names the version awaiting a fold",
    pending.text.indexOf("0.1.1") !== -1, _transcript(pending));

  // A rebuild must not render one release twice, and must refuse rather
  // than pick a side when the two copies disagree.
  var rebuiltClash = _tool(conflicting, "generate-changelog-entry.js", ["--rebuild"]);
  count("--rebuild refuses two copies of one release that disagree",
    rebuiltClash.status !== 0, _transcript(rebuiltClash));

  var rebuiltAgree = _tool(agreeing, "generate-changelog-entry.js", ["--rebuild"]);
  count("--rebuild accepts two copies that agree", rebuiltAgree.status === 0, _transcript(rebuiltAgree));
  var md = _changelogOf(agreeing);
  count("a release held in both places is rendered once",
    (md.match(/^### v0\.1\.0 /gm) || []).length === 1,
    String((md.match(/^### v0\.1\.0 /gm) || []).length));
}

// ---------------------------------------------------------------------------
// Series files that are malformed on their own terms
// ---------------------------------------------------------------------------

function _seriesShapeCases() {
  var wrongMinor = _fixture({
    version: "0.1.0",
    notes: { "v0.1.x.json": _series("0.2", [_release("0.1.0", "2026-01-01", "first")]) },
  });
  var mislabeled = _tool(wrongMinor, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses a series file whose minor contradicts its name",
    mislabeled.status !== 0, _transcript(mislabeled));

  var strayVersion = _fixture({
    version: "0.1.0",
    notes: { "v0.1.x.json": _series("0.1", [_release("0.2.0", "2026-01-01", "first")]) },
  });
  var stray = _tool(strayVersion, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses a release filed under the wrong minor line",
    stray.status !== 0, _transcript(stray));

  var outOfOrder = _fixture({
    version: "0.1.0",
    notes: {
      "v0.1.x.json": _series("0.1", [
        _release("0.1.0", "2026-01-01", "first"),
        _release("0.1.1", "2026-02-02", "second"),
      ]),
    },
  });
  var unsorted = _tool(outOfOrder, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses a series file that is not newest first",
    unsorted.status !== 0, _transcript(unsorted));

  var duplicated = _fixture({
    version: "0.1.0",
    notes: {
      "v0.1.x.json": _series("0.1", [
        _release("0.1.0", "2026-01-01", "first"),
        _release("0.1.0", "2026-01-01", "first"),
      ]),
    },
  });
  var twice = _tool(duplicated, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses a series file listing one release twice",
    twice.status !== 0, _transcript(twice));
}

// ---------------------------------------------------------------------------
// Folding a hand-authored file into the series
// ---------------------------------------------------------------------------

function _foldCases() {
  var root = _fixture({
    version: "0.1.2",
    notes: {
      "v0.1.x.json": _series("0.1", [_release("0.1.0", "2026-01-01", "first")]),
      "v0.1.1.json": _release("0.1.1", "2026-02-02", "second"),
      "v0.1.2.json": _release("0.1.2", "2026-03-03", "third"),
    },
  });

  var fold = _tool(root, "consolidate-release-notes.js", []);
  count("consolidation folds the hand-authored files", fold.status === 0, _transcript(fold));

  var series = _readJson(path.join(root, "release-notes", "v0.1.x.json"));
  count("the series holds every release of the line",
    series.releases.map(function (r) { return r.version; }).join(" ") === "0.1.2 0.1.1 0.1.0",
    series.releases.map(function (r) { return r.version; }).join(" "));
  count("the release already folded is preserved word for word",
    JSON.stringify(series.releases[2]) === JSON.stringify(_release("0.1.0", "2026-01-01", "first")),
    JSON.stringify(series.releases[2]).slice(0, 200));
  count("the folded release carries no nested schema pointer",
    series.releases.every(function (r) {
      return !Object.prototype.hasOwnProperty.call(r, "$schema");
    }), JSON.stringify(Object.keys(series.releases[0])));
  count("the series names its own minor line", series.minor === "0.1", String(series.minor));

  // A plain fold leaves the hand-authored files in place, and the two
  // copies agree, so the gate is quiet.
  check("a plain fold leaves the hand-authored file on disk",
    fs.existsSync(path.join(root, "release-notes", "v0.1.1.json")));
  var quiet = _tool(root, "consolidate-release-notes.js", ["--check"]);
  count("--check is quiet once the fold has run", quiet.status === 0, _transcript(quiet));

  // Folding twice changes nothing.
  var before = fs.readFileSync(path.join(root, "release-notes", "v0.1.x.json"), "utf8");
  var second = _tool(root, "consolidate-release-notes.js", []);
  count("folding twice is a no-op",
    second.status === 0 &&
    fs.readFileSync(path.join(root, "release-notes", "v0.1.x.json"), "utf8") === before,
    _transcript(second));

  // With --prune the hand-authored files go, and the series still says
  // everything they said.
  var pruned = _tool(root, "consolidate-release-notes.js", ["--prune"]);
  count("--prune removes the hand-authored files it folded", pruned.status === 0, _transcript(pruned));
  check("v0.1.1.json is gone", !fs.existsSync(path.join(root, "release-notes", "v0.1.1.json")));
  check("v0.1.2.json is gone", !fs.existsSync(path.join(root, "release-notes", "v0.1.2.json")));
  count("the series survived the prune unchanged",
    fs.readFileSync(path.join(root, "release-notes", "v0.1.x.json"), "utf8") === before,
    "series bytes");

  var afterPrune = _tool(root, "consolidate-release-notes.js", ["--check"]);
  count("--check is quiet after a prune", afterPrune.status === 0, _transcript(afterPrune));

  // An edited hand-authored file folds its edit in rather than being
  // ignored because the version is already present.
  _writeJson(path.join(root, "release-notes", "v0.1.2.json"), _release("0.1.2", "2026-03-03", "corrected"));
  var stale = _tool(root, "consolidate-release-notes.js", ["--check"]);
  count("--check catches the edit before it is folded", stale.status !== 0, _transcript(stale));
  var refold = _tool(root, "consolidate-release-notes.js", ["--prune"]);
  count("re-folding carries the edit into the series", refold.status === 0, _transcript(refold));
  var corrected = _readJson(path.join(root, "release-notes", "v0.1.x.json"));
  count("the series now carries the corrected release",
    corrected.releases[0].headline.indexOf("corrected") !== -1,
    corrected.releases[0].headline);
  count("re-folding did not disturb the release order",
    corrected.releases.map(function (r) { return r.version; }).join(" ") === "0.1.2 0.1.1 0.1.0",
    corrected.releases.map(function (r) { return r.version; }).join(" "));

  // Nothing to fold at all is a refusal, not a silent success: an empty
  // release-notes directory means the release has no notes.
  var empty = _fixture({ version: "0.1.0" });
  var nothing = _tool(empty, "consolidate-release-notes.js", ["--check"]);
  count("--check refuses an empty release-notes directory", nothing.status !== 0, _transcript(nothing));
}

// ---------------------------------------------------------------------------
// The release page the publish workflow attaches
// ---------------------------------------------------------------------------

function _releasePageCases() {
  var withRefs = _release("0.1.0", "2026-01-01", "first");
  withRefs.references = [
    { label: "The framework", url: "https://github.com/blamejs/blamejs" },
  ];
  var root = _fixture({ version: "0.1.0", notes: { "v0.1.0.json": withRefs } });

  var page = _tool(root, "generate-changelog-entry.js", ["0.1.0", "--release-page"]);
  count("--release-page renders", page.status === 0, _transcript(page));
  var md = page.stdout;

  count("the page opens with the headline rather than a changelog header",
    md.indexOf("### v0.1.0") === -1 && md.indexOf(withRefs.headline) !== -1,
    md.slice(0, 120));
  count("the page carries the summary", md.indexOf(withRefs.summary) !== -1, md.slice(0, 200));
  count("each section becomes a heading on the page",
    md.indexOf("## Fixed") !== -1, md.slice(0, 400));
  count("each item becomes a bullet with its title and body",
    md.indexOf("- **The first path** " + EM + " ") !== -1, md.slice(0, 600));
  count("references reach the page",
    md.indexOf("## References") !== -1 &&
    md.indexOf("https://github.com/blamejs/blamejs") !== -1,
    md.slice(-300));

  // The page is big enough for the workflow's own floor.
  count("the page clears the workflow's minimum size", md.length >= 64, String(md.length));

  // Modes are exclusive: two of them at once is a refusal, not a
  // coin flip about which one wins.
  var both = _tool(root, "generate-changelog-entry.js", ["--rebuild", "--check"]);
  count("--rebuild and --check together are refused", both.status !== 0, _transcript(both));

  // The release title. The publish workflow asks for it rather than
  // reading a fixed path, because a released version moves into its
  // minor series file the moment the fold runs, so it has to resolve
  // from both shapes.
  var titled = _tool(root, "generate-changelog-entry.js", ["0.1.0", "--headline"]);
  count("--headline reports the headline from a hand-written file",
    titled.status === 0 && titled.stdout === withRefs.headline + "\n",
    _transcript(titled));

  var folded = _fixture({
    version: "0.1.0",
    notes: { "v0.1.x.json": _series("0.1", [withRefs]) },
  });
  var foldedTitle = _tool(folded, "generate-changelog-entry.js", ["0.1.0", "--headline"]);
  count("--headline reports the same headline once the release is folded",
    foldedTitle.status === 0 && foldedTitle.stdout === titled.stdout,
    _transcript(foldedTitle));

  var foldedPage = _tool(folded, "generate-changelog-entry.js", ["0.1.0", "--release-page"]);
  count("--release-page renders the same page once the release is folded",
    foldedPage.status === 0 && foldedPage.stdout === md, _transcript(foldedPage));

  var absent = _tool(folded, "generate-changelog-entry.js", ["0.1.9", "--headline"]);
  count("--headline refuses a version the notes do not describe",
    absent.status !== 0, _transcript(absent));
}

// ---------------------------------------------------------------------------
// The validator refuses what the schema refuses
// ---------------------------------------------------------------------------

function _validationCases() {
  function _refuses(label, mutate) {
    var doc = _release("0.1.0", "2026-01-01", "first");
    mutate(doc);
    var root = _fixture({ version: "0.1.0", notes: { "v0.1.0.json": doc } });
    var rv = _tool(root, "generate-changelog-entry.js", ["--rebuild"]);
    count(label, rv.status !== 0, _transcript(rv));
  }

  _refuses("a release with no date is refused", function (d) { delete d.date; });
  _refuses("a release dated in the wrong format is refused", function (d) { d.date = "01/01/2026"; });
  _refuses("a headline ending in a full stop is refused", function (d) { d.headline += "."; });
  _refuses("a lower-case headline is refused", function (d) { d.headline = "first release of the server"; });
  _refuses("an unlisted section heading is refused", function (d) { d.sections[0].heading = "Notes"; });
  _refuses("an item with no body is refused", function (d) { delete d.sections[0].items[0].body; });
  _refuses("a body that trails off without punctuation is refused",
    function (d) { d.sections[0].items[0].body = "The first path reports its refusal"; });
  _refuses("a section keyed by heading instead of listed is refused",
    function (d) { d.sections = { Fixed: ["The first path reports its refusal instead of a default."] }; });
  _refuses("a duplicated section heading is refused", function (d) {
    d.sections.push({ heading: "Fixed", items: [{ title: "Another path", body: "The other path refuses too, and says so." }] });
  });
  _refuses("internal sequencing vocabulary in a body is refused", function (d) {
    d.sections[0].items[0].body = "Closed in " + LEAK_TOKEN + " of the delivery work, and it now refuses.";
  });
  _refuses("a version that disagrees with its file name is refused", function (d) { d.version = "0.1.9"; });
}

// ---------------------------------------------------------------------------

async function run() {
  await helpers.withTestTimeout("release notes shape", async function () {
    _schemaCases();
    _liveTreeCases();
    _renderCases();
    _driftCases();
    _agreementCases();
    _seriesShapeCases();
    _foldCases();
    _releasePageCases();
    _validationCases();
  }, { timeoutMs: 240000 });
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
