// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// check-swallow-coverage: the execution-traced swallow gate.
//
// A `catch (e) { ... }` that does NOT re-throw is a SWALLOW: it converts a thrown fault
// into a returned value or a recorded verdict. A swallow is only safe if it fails CLOSED,
// and the way this gate proves that, WITHOUT an allowlist of "known-good" swallows, is by
// EXECUTION: every swallow's catch body MUST be exercised by the test suite (its lines
// carry a non-zero hit in the c8 lcov report). A test that drives the error path and still
// passes is live proof the swallow behaves as the suite asserts; a swallow no test ever
// enters is an unproven fail-open risk.
//
// So the gate is: for every lib swallow, either
//   - the catch RE-THROWS (it propagates, so it is fail-closed by construction), or
//   - the catch body is COVERED (a test drives it, asserting its fail-closed verdict), or
//   - it carries an `allow:swallow-unverified <reason>` marker (a deliberate, documented
//     drop-silent sink, the escape hatch of last resort and never the default).
// An uncovered, unmarked, non-re-throwing swallow FAILS the gate: add a RED vector that
// drives the catch, or re-throw.
//
// Runs AFTER `npm run coverage` (which writes coverage/lcov.info). Reads that report; it
// does not run the suite itself.
//
// WHAT THE RUN EXAMINED is published as the last lines of stdout, on a passing run and a
// failing one alike:
//
//   EXAMINED <n> lib-source-files
//   EXAMINED <n> lib-swallows
//
// Either at zero is refused, because "every lib swallow re-throws, is execution-covered, or
// is explicitly marked" is true in those exact words of a run that read no source and of a
// run that read all of it and recognized no catch. The two are published apart because they
// empty independently: a walk pointed somewhere the sources are not takes the first to zero,
// and a swallow finder that stopped matching leaves the first healthy and the second at
// nothing, which is the shape that reads as a clean bill of health.

var fs = require("fs");
var path = require("path");

// The one shared walk over this project's own lib sources, nested directories
// included and the vendored tree excluded. A swallow one directory down is the same
// fail-open risk as one at the top level.
var libSources = require("./source-primitives.js").libSources;

var examinedCounts = require("./examined-counts.js");

var REPO_ROOT = path.resolve(__dirname, "..");
var LIB_DIR = path.join(REPO_ROOT, "lib");
var LCOV = path.join(REPO_ROOT, "coverage", "lcov.info");

// ---- lcov: per-file { line -> hitCount } -----------------------------------
function parseLcov(text) {
  var byFile = {};
  var cur = null;
  text.split(/\r?\n/).forEach(function (line) {
    if (line.indexOf("SF:") === 0) { cur = {}; byFile[_norm(line.slice(3))] = cur; return; }
    if (line.indexOf("DA:") === 0 && cur) {
      var parts = line.slice(3).split(",");
      cur[parseInt(parts[0], 10)] = parseInt(parts[1], 10);
    }
  });
  return byFile;
}
// Normalize a path to its repo-relative lib/<...> key (an lcov SF line and a walked
// source path may both be absolute, and either may be backslash-separated on Windows).
// Both sides of the lookup go through this, so a nested source and the report entry that
// covers it agree on one spelling.
function _norm(p) {
  p = p.replace(/\\/g, "/");
  var i = p.indexOf("lib/");
  return i >= 0 ? p.slice(i) : p;
}

// ---- static: enumerate catch swallows --------------------------------------
// Strip line comments + block comments + string/regex literals so a `throw`/`return`
// inside a comment or string never counts. (A light strip: enough for catch bodies.)
function _strip(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, function (m) { return m.replace(/[^\n]/g, " "); })
    .replace(/\/\/[^\n]*/g, "")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, "``");
}

function findSwallows(rel, src) {
  var stripped = _strip(src);
  var out = [];
  var re = /catch\s*\(([^)]*)\)\s*\{/g, m;
  while ((m = re.exec(stripped))) {
    // Brace-match the catch body in the STRIPPED source (so string braces don't confuse).
    var i = m.index + m[0].length, depth = 1;
    while (i < stripped.length && depth > 0) { var c = stripped[i]; if (c === "{") depth++; else if (c === "}") depth--; if (depth > 0) i++; }
    var bodyStart = m.index + m[0].length, bodyEnd = i;
    var body = stripped.slice(bodyStart, bodyEnd);
    var startLine = stripped.slice(0, m.index).split("\n").length;
    var endLine = stripped.slice(0, bodyEnd).split("\n").length;
    // A catch that propagates the fault is fail-closed, not a swallow. It propagates via a
    // literal `throw`, a returned rejected promise, or a call to the schema `fail(...)`
    // throw-helper (the `fail(msg, cause?)` convention always throws the caller's typed code).
    var noValueReturn = !/\breturn\s+(?!Promise\.reject)/.test(body);
    var reThrows = /\bthrow\b/.test(body) && noValueReturn;
    var rejectsOnly = /return\s+Promise\.reject\b/.test(body) && noValueReturn;
    var throwsViaHelper = /\bfail\s*\(/.test(body) && noValueReturn;
    if (reThrows || rejectsOnly || throwsViaHelper) continue;   // safe: propagates the fault
    // Otherwise it is a swallow: it must be exercised (covered) or explicitly marked.
    out.push({ startLine: startLine, endLine: endLine, param: m[1].trim() });
  }
  return out;
}

// A per-line `allow:swallow-unverified` marker on any line of the catch body (or up to 2
// lines above the catch), matching the codebase-patterns marker convention.
function isMarked(srcLines, startLine, endLine) {
  for (var ln = startLine - 2; ln <= endLine; ln++) {
    var s = srcLines[ln - 1];
    if (s && /\ballow:swallow-unverified\b/.test(s)) return true;
  }
  return false;
}

function main() {
  if (!fs.existsSync(LCOV)) {
    console.error("[check-swallow-coverage] coverage/lcov.info not found -- run `npm run coverage` first.");
    process.exit(2);
  }
  // The report records LINE NUMBERS; the swallows are found by re-reading the source now. If a lib
  // file changed after the report was written, the two describe different code, and this gate
  // fails in BOTH directions: it reports a swallow that has since moved (noise), and it can mark a
  // genuinely unproven swallow as covered because some unrelated line now sits at that number
  // (a gate that passes while proving nothing). Refuse to run rather than answer from stale data.
  var lcovAt = fs.statSync(LCOV).mtimeMs;
  var sources = libSources(LIB_DIR);
  var stale = sources.filter(function (f) {
    return fs.statSync(f).mtimeMs > lcovAt;
  }).map(function (f) { return _norm(f); });
  if (stale.length) {
    console.error("[check-swallow-coverage] STALE: " + stale.length + " lib file(s) changed after coverage/lcov.info was written"
      + " (" + stale.slice(0, 3).join(", ") + (stale.length > 3 ? ", ..." : "") + ").");
    console.error("[check-swallow-coverage] Line numbers would not line up with the source. Re-run `npm run coverage` first.");
    process.exit(2);
  }
  var cov = parseLcov(fs.readFileSync(LCOV, "utf8"));
  var bad = [];
  var swallowCount = 0, coveredCount = 0, markedCount = 0;
  sources.forEach(function (file) {
    var rel = _norm(file);
    var src = fs.readFileSync(file, "utf8");
    var srcLines = src.split(/\r?\n/);
    var fileCov = cov[rel] || {};
    findSwallows(rel, src).forEach(function (sw) {
      swallowCount++;
      // Covered iff a line that belongs ONLY to the catch body carries a non-zero hit. A line
      // shared with the `try` opener (a single-line `try { ... } catch (e) { ... }`) is
      // EXCLUDED: c8 records a hit for it on the successful try path even when the catch never
      // runs, so counting it would false-pass an untested swallow. A single-line try/catch thus
      // has no catch-only line and must re-throw, reformat the catch body onto its own line, or
      // carry a marker. Proving the catch executed needs a line the try cannot reach.
      var covered = false;
      for (var ln = sw.startLine; ln <= sw.endLine; ln++) {
        var t = srcLines[ln - 1] || "";
        var tryAt = t.search(/\btry\b\s*\{/), catchAt = t.indexOf("catch");
        if (tryAt !== -1 && catchAt !== -1 && tryAt < catchAt) continue;   // single-line try+catch: ambiguous
        if (fileCov[ln] > 0) { covered = true; break; }
      }
      if (covered) { coveredCount++; return; }
      if (isMarked(srcLines, sw.startLine, sw.endLine)) { markedCount++; return; }
      bad.push({ file: rel, line: sw.startLine, param: sw.param });
    });
  });
  console.log("[check-swallow-coverage] swallows=" + swallowCount + " covered=" + coveredCount + " marked=" + markedCount + " unverified=" + bad.length);

  // The units this run answers for, decided before the verdict sentence is
  // written. A run that examined nothing must not print the passing sentence
  // and then refuse underneath it: the sentence is the claim, and a transcript
  // carrying both says the gate disagreed with itself.
  var units = [
    { unit: "lib-source-files", n: sources.length },
    { unit: "lib-swallows",     n: swallowCount },
  ];
  var empty = examinedCounts.emptyUnits(units);

  if (bad.length) {
    console.error("\nUnverified swallows (no test drives the catch; not re-throwing; not marked):");
    bad.forEach(function (b) {
      console.error("  " + b.file + ":" + b.line + "  catch (" + b.param + ") -- add a RED vector that drives this catch, re-throw, or mark `allow:swallow-unverified <reason>`");
    });
  } else if (empty.length === 0) {
    console.log("[check-swallow-coverage] OK -- every lib swallow re-throws, is execution-covered, or is explicitly marked.");
  }

  // What this run answered for, published whatever the verdict.
  //
  // The sentence above is true of a run that walked no source at all, and it
  // is the same sentence in the same words. Three gates in the declared chain
  // publish this same walk as `lib-source-files`, so an empty one there would
  // be caught, but "caught somewhere else" is not the same as answered for: a
  // coverage run and this gate are invoked together through one npm script
  // that nothing in the chain drives, so on that path this verdict is the only
  // one there is.
  //
  // Both units, because they empty independently and in opposite directions. A
  // walk pointed at a directory that moved takes `lib-source-files` to zero.
  // A `findSwallows` that stopped matching leaves every file read and finds no
  // catch in any of them, which reports a healthy file count beside a verdict
  // about nothing, which is the one this gate exists to give.
  var code = examinedCounts.publish(units, { tag: "[check-swallow-coverage]" });

  process.exit(bad.length ? 1 : code);
}

// Exported for hermetic unit tests. The swallow finder and the marker reader
// are pure, read no report and touch no network, and they are the load-bearing
// logic: `lib-swallows` reaching zero is this finder having stopped matching,
// so a case that holds it to a known shape is what keeps that count honest.
// Requiring this file runs nothing.
module.exports = {
  findSwallows: findSwallows,
  isMarked:     isMarked,
  parseLcov:    parseLcov,
};

if (require.main === module) main();
