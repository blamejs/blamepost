#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/consolidate-release-notes.js
 *
 * Fold a hand-written `release-notes/v<X>.<Y>.<Z>.json` into the minor
 * series file `release-notes/v<X>.<Y>.x.json`, which holds every
 * released version of that line, newest first.
 *
 * An operator writes one file for the release being cut, with the fields
 * scripts/release-notes-schema.json names. This is the step that files it:
 * without it a minor line accumulates one JSON per patch and never gives
 * them back, and every release here is a patch unless somebody decides
 * otherwise.
 *
 * Series file shape, described by scripts/release-notes-consolidated-schema.json:
 *   {
 *     "$schema": "../scripts/release-notes-consolidated-schema.json",
 *     "minor":   "0.1",
 *     "releases": [
 *       { ...same shape as a per-release v<X>.<Y>.<Z>.json, without its
 *         own $schema... },
 *       ...                    // newest first
 *     ]
 *   }
 *
 * `scripts/generate-changelog-entry.js` reads both shapes, so a version
 * still resolves after its hand-written file is gone.
 *
 * Usage:
 *   node scripts/consolidate-release-notes.js            # fold, keeping the hand-written files
 *   node scripts/consolidate-release-notes.js --prune    # fold, then delete the files it folded
 *   node scripts/consolidate-release-notes.js --check    # verify, change nothing
 *
 * What `--check` refuses, and why each one matters:
 *
 *   a hand-written file the series does not carry      the fold has not
 *                                                      run, so the
 *                                                      series is behind
 *   a hand-written file the series contradicts         two copies of one
 *                                                      release saying
 *                                                      different things,
 *                                                      which is the risk
 *                                                      a second copy
 *                                                      introduces and is
 *                                                      silent by nature
 *   a series naming a minor its file name does not     the grouping in
 *                                                      the CHANGELOG
 *                                                      would be wrong
 *   a release filed under the wrong line               same
 *   a series that is not newest first                  the render is the
 *                                                      order as written,
 *                                                      and a reader
 *                                                      upgrading reads
 *                                                      down it
 *   a version listed twice in one series               one of them is
 *                                                      unreachable and
 *                                                      nobody knows which
 *
 * Every mode also refuses a JSON file in release-notes/ that is neither
 * shape. Nothing reads one, so a release written into a mistyped name is
 * folded into no series and rendered into no CHANGELOG entry, and the
 * verification below would report agreement across a set that never
 * contained it.
 *
 * `--check` publishes what it answered for as the last lines of stdout,
 * in the form the release battery reads:
 *
 *   EXAMINED <n> series-files
 *   EXAMINED <n> series-releases
 *   EXAMINED <n> cross-checked-releases
 *
 * The last of those is absent on a run that had no hand-written file to
 * compare, which is the steady state between cuts, and the run says so in
 * words instead of printing a zero somebody has to interpret.
 *
 * Folding is idempotent: running it twice with no edits in between
 * changes nothing, and re-running after an edit to a hand-written file
 * carries that edit into the series.
 */

var fs   = require("node:fs");
var path = require("node:path");

var examinedCounts = require("./examined-counts.js");

var ROOT      = path.resolve(__dirname, "..");
var NOTES_DIR = path.join(ROOT, "release-notes");

var PER_RELEASE_RE = /^v(\d+\.\d+\.\d+)\.json$/;
var SERIES_RE      = /^v(\d+\.\d+)\.x\.json$/;

function _exit(msg) {
  process.stderr.write("[consolidate-release-notes] " + msg + "\n");
  process.exit(1);
}

function _readJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) { _exit("cannot read " + label + " (" + filePath + "): " + ((e && e.message) || e)); }
  try { return JSON.parse(raw); }
  catch (e) { _exit("malformed JSON in " + label + " (" + filePath + "): " + ((e && e.message) || e)); }
  return null;   // unreachable
}

function _minorOf(version) {
  return String(version).replace(/\.\d+$/, "");
}

function _compareVersionsDesc(a, b) {
  var ap = String(a).split(".").map(Number);
  var bp = String(b).split(".").map(Number);
  for (var i = 0; i < 3; i += 1) {
    if (ap[i] !== bp[i]) return bp[i] - ap[i];
  }
  return 0;
}

// A release object with its keys in a stable order and no $schema
// pointer, so two copies are compared on what they say rather than on
// how they were serialized. The wrapper carries the pointer once for the
// whole series.
function _canonical(value) {
  if (Array.isArray(value)) return value.map(_canonical);
  if (value && typeof value === "object") {
    var out = {};
    Object.keys(value).sort().forEach(function (k) {
      if (k === "$schema") return;
      out[k] = _canonical(value[k]);
    });
    return out;
  }
  return value;
}

function _same(a, b) {
  return JSON.stringify(_canonical(a)) === JSON.stringify(_canonical(b));
}

// Strip the $schema pointer while keeping the author's key order, which
// is what lands in the series file. _canonical sorts keys and is for
// comparison only; writing a sorted copy would reorder every release the
// first time this ran and make the diff unreadable.
function _stripSchema(release) {
  var out = {};
  Object.keys(release).forEach(function (k) {
    if (k === "$schema") return;
    out[k] = release[k];
  });
  return out;
}

// ---------------------------------------------------------------------------
// Reading the directory
// ---------------------------------------------------------------------------

function _scan() {
  var entries;
  try { entries = fs.readdirSync(NOTES_DIR); }
  catch (e) {
    if (e && e.code === "ENOENT") _exit("release-notes/ does not exist");
    _exit("cannot read release-notes/: " + ((e && e.message) || e));
  }

  var perRelease   = [];     // [{ version, minor, file, payload }]
  var series       = {};     // minor -> { file, payload }
  var unclassified = [];     // names this scan could not place

  entries.forEach(function (name) {
    if (!/\.json$/.test(name)) return;
    var sm = name.match(SERIES_RE);
    if (sm) {
      series[sm[1]] = { file: name, payload: _readJson(path.join(NOTES_DIR, name), "release-notes/" + name) };
      return;
    }
    var pm = name.match(PER_RELEASE_RE);
    if (!pm) { unclassified.push(name); return; }
    var payload = _readJson(path.join(NOTES_DIR, name), "release-notes/" + name);
    if (payload.version !== pm[1]) {
      _exit("release-notes/" + name + " declares version " + JSON.stringify(payload.version) +
        ", which is not the version its file name names");
    }
    perRelease.push({ version: pm[1], minor: _minorOf(pm[1]), file: name, payload: payload });
  });

  perRelease.sort(function (a, b) { return _compareVersionsDesc(a.version, b.version); });

  // A release document neither pattern places is DROPPED by every path below,
  // silently, and the drop is invisible in exactly the direction that matters:
  // the fold leaves it out of the series, the verification loop never reaches
  // it, and the run then reports that every hand-written release agrees with
  // its series file. A release the operator wrote by hand sits in this
  // directory, unread, while the gate certifies the set it did not include it
  // in. Nothing else lives here, so a name this cannot place is a finding
  // rather than a file to skip past.
  if (unclassified.length > 0) {
    _exit("release-notes/ holds " + unclassified.length + " JSON file(s) that are neither a " +
      "per-release v<X>.<Y>.<Z>.json nor a series v<X>.<Y>.x.json: " + unclassified.join(", ") +
      ". Nothing reads them, so a release written into one is folded into no series, rendered " +
      "into no CHANGELOG entry, and reported by nothing. Rename it to the shape it is, or " +
      "remove it.");
  }

  if (perRelease.length === 0 && Object.keys(series).length === 0) {
    _exit("no per-release OR series release notes found in " + path.relative(ROOT, NOTES_DIR));
  }
  return { perRelease: perRelease, series: series };
}

// Everything wrong with one series file, as operator-readable lines.
function _seriesProblems(minor, entry) {
  var problems = [];
  var doc = entry.payload;
  if (doc.minor !== minor) {
    problems.push("release-notes/" + entry.file + " names minor " + JSON.stringify(doc.minor) +
      " but its file name says " + JSON.stringify(minor));
  }
  if (!Array.isArray(doc.releases) || doc.releases.length === 0) {
    problems.push("release-notes/" + entry.file + " has no `releases` array");
    return problems;
  }
  var seen = {};
  var previous = null;
  doc.releases.forEach(function (r, i) {
    var v = (r && r.version) || "";
    if (!/^\d+\.\d+\.\d+$/.test(v)) {
      problems.push("release-notes/" + entry.file + " releases[" + i + "] has no strict-semver `version`");
      return;
    }
    if (_minorOf(v) !== minor) {
      problems.push("release-notes/" + entry.file + " lists v" + v + ", which is not on the " + minor + " line");
    }
    if (seen[v]) problems.push("release-notes/" + entry.file + " lists v" + v + " twice");
    seen[v] = true;
    if (previous !== null && _compareVersionsDesc(previous, v) > 0) {
      problems.push("release-notes/" + entry.file + " lists v" + previous + " before v" + v +
        ", but a series reads newest first");
    }
    previous = v;
  });
  return problems;
}

// ---------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------

function _check(scan) {
  var problems = [];

  Object.keys(scan.series).sort().forEach(function (minor) {
    problems = problems.concat(_seriesProblems(minor, scan.series[minor]));
  });

  scan.perRelease.forEach(function (e) {
    var entry = scan.series[e.minor];
    if (!entry) {
      problems.push("v" + e.version + " is only in release-notes/" + e.file +
        ", and the " + e.minor + " line has no series file yet");
      return;
    }
    var releases = Array.isArray(entry.payload.releases) ? entry.payload.releases : [];
    var folded = null;
    for (var i = 0; i < releases.length; i += 1) {
      if (releases[i] && releases[i].version === e.version) { folded = releases[i]; break; }
    }
    if (folded === null) {
      problems.push("v" + e.version + " is in release-notes/" + e.file +
        " but not in release-notes/" + entry.file + ", so the fold has not run");
      return;
    }
    if (!_same(folded, e.payload)) {
      problems.push("v" + e.version + " reads differently in release-notes/" + e.file +
        " and in release-notes/" + entry.file + ", so one of the two is stale");
    }
  });

  var seriesFiles = Object.keys(scan.series);
  var seriesReleases = seriesFiles.reduce(function (n, minor) {
    var doc = scan.series[minor].payload;
    return n + (Array.isArray(doc.releases) ? doc.releases.length : 0);
  }, 0);

  // The units this run answers for, decided before the verdict sentence is
  // written, so a run that examined nothing never prints the passing sentence
  // above its own refusal.
  //
  // Built ONCE and used twice: the sentence below asks whether any of them is
  // empty, and the publish at the end emits them. A second copy of this list
  // would be a second copy of a `zeroIs`, and the run would then be able to
  // print a passing sentence under one set of rules and publish its counts
  // under another.
  var units = [
    { unit: "series-files",    n: seriesFiles.length },
    { unit: "series-releases", n: seriesReleases },
    {
      unit:   "cross-checked-releases",
      n:      scan.perRelease.length,
      zeroIs: "every --check in the release flow runs after the fold has pruned the " +
              "hand-written files, so between cuts there is no second copy of a release left " +
              "to disagree with its series. A file the scan could not place is refused before " +
              "this count is taken, so zero here means the directory holds none rather than " +
              "that this run could not see one",
    },
  ];

  var failed = problems.length > 0;
  if (failed) {
    process.stderr.write("[consolidate-release-notes] CHECK FAIL, " + problems.length + " problem(s):\n");
    problems.forEach(function (p) { process.stderr.write("  " + p + "\n"); });
    process.stderr.write("[consolidate-release-notes] Run `node scripts/consolidate-release-notes.js --prune` " +
      "to fold the hand-written files in, or fix the series file by hand where it was edited directly.\n");
  } else if (examinedCounts.emptyUnits(units).length === 0) {
    process.stderr.write("[consolidate-release-notes] OK, every hand-written release agrees with its series file (" +
      seriesFiles.length + " line(s), " + seriesReleases + " released version(s), " +
      scan.perRelease.length + " hand-written file(s)).\n");
  }

  // What this run answered for, published whatever the verdict, because the
  // number belongs beside the problems as much as beside a pass.
  //
  // The unit that had to grow teeth is `series-releases` and not the count of
  // FILES. A series file whose `releases` array emptied still reads as one
  // line, and the sentence above would report a line's worth of agreement over
  // no release at all.
  //
  // `cross-checked-releases` is the one that legitimately reaches zero, and it
  // is worth being precise about why, because "expected" is the word this whole
  // class of defect hides behind. Every `--check` in the flow runs AFTER the
  // fold: scripts/release.js regenerates artifacts by running `--prune` and
  // then `--check`, and the workflows read the tree that regeneration left. So
  // no hand-written file surviving to be cross-checked is the steady state
  // between cuts rather than a discovery that stopped working. What the count
  // adds is anyone saying so: without it the loop iterates zero times and the
  // run prints the same clean sentence it prints having compared a dozen.
  //
  // The hole underneath it is not the zero. It is a hand-written release the
  // scan cannot NAME being dropped before this loop ever sees it, which _scan
  // refuses outright, so a zero here means the directory holds no
  // hand-written release rather than that this reader could not see one.
  var code = examinedCounts.publish(units, { tag: "[consolidate-release-notes]" });

  process.exit(failed ? 1 : code);
}

// ---------------------------------------------------------------------------
// Folding
// ---------------------------------------------------------------------------

function _fold(scan, prune) {
  // A series file that is malformed on its own terms is not something to
  // merge into. Refuse before writing anything.
  var problems = [];
  Object.keys(scan.series).sort().forEach(function (minor) {
    problems = problems.concat(_seriesProblems(minor, scan.series[minor]));
  });
  if (problems.length > 0) {
    process.stderr.write("[consolidate-release-notes] FAIL, the series files are not fit to fold into:\n");
    problems.forEach(function (p) { process.stderr.write("  " + p + "\n"); });
    process.exit(1);
  }

  var byMinor = {};
  scan.perRelease.forEach(function (e) {
    if (!byMinor[e.minor]) byMinor[e.minor] = [];
    byMinor[e.minor].push(e);
  });

  var wrote  = [];
  var pruned = 0;

  Object.keys(byMinor).sort().forEach(function (minor) {
    var existing = scan.series[minor]
      ? scan.series[minor].payload.releases.slice()
      : [];

    var added   = 0;
    var updated = 0;
    byMinor[minor].forEach(function (e) {
      var incoming = _stripSchema(e.payload);
      var at = -1;
      for (var i = 0; i < existing.length; i += 1) {
        if (existing[i].version === e.version) { at = i; break; }
      }
      if (at === -1) { existing.push(incoming); added += 1; return; }
      if (!_same(existing[at], incoming)) updated += 1;
      existing[at] = incoming;
    });

    existing.sort(function (a, b) { return _compareVersionsDesc(a.version, b.version); });

    var doc = {
      "$schema":  "../scripts/release-notes-consolidated-schema.json",
      "minor":    minor,
      "releases": existing,
    };
    var outPath = path.join(NOTES_DIR, "v" + minor + ".x.json");
    var next    = JSON.stringify(doc, null, 2) + "\n";
    var before  = null;
    try { before = fs.readFileSync(outPath, "utf8"); }
    catch (e) {
      if (!e || e.code !== "ENOENT") _exit("cannot read " + outPath + ": " + ((e && e.message) || e));
    }
    if (before !== next) fs.writeFileSync(outPath, next, "utf8");

    wrote.push(minor + ".x now holds " + existing.length + " release(s) (" +
      added + " added, " + updated + " updated, " +
      (before === next ? "file unchanged" : "file rewritten") + ")");

    if (prune) {
      byMinor[minor].forEach(function (e) {
        fs.unlinkSync(path.join(NOTES_DIR, e.file));
        pruned += 1;
      });
    }
  });

  if (wrote.length === 0) {
    process.stderr.write("[consolidate-release-notes] OK, nothing to fold: no hand-written release files on disk.\n");
    return;
  }
  wrote.forEach(function (w) { process.stderr.write("[consolidate-release-notes] FOLD   " + w + "\n"); });
  process.stderr.write("[consolidate-release-notes] DONE, folded " + scan.perRelease.length +
    " hand-written file(s) into " + wrote.length + " series file(s), pruned " + pruned +
    (prune ? "" : ". Pass `--prune` to delete the hand-written files after folding") + "\n");
}

function main() {
  var prune     = process.argv.indexOf("--prune") !== -1;
  var checkOnly = process.argv.indexOf("--check") !== -1;
  if (prune && checkOnly) _exit("--prune and --check are mutually exclusive");

  var unknown = process.argv.slice(2).filter(function (a) {
    return a.startsWith("--") && a !== "--prune" && a !== "--check";
  });
  if (unknown.length > 0) {
    _exit("unknown option(s) " + unknown.join(" ") + ". Known options: --prune --check");
  }

  var scan = _scan();
  if (checkOnly) { _check(scan); return; }
  _fold(scan, prune);
}

main();
