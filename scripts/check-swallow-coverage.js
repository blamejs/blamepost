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
// A marker answers for ONE swallow. A marker line that excused two is refused by name and
// both swallows are printed, because a sentence written about one catch cannot be the
// recorded decision for another one that happens to sit near it.
//
// Runs AFTER `npm run coverage` (which writes coverage/lcov.info). Reads that report; it
// does not run the suite itself. CI runs the instrumented suite and then this gate as the
// next step, so a pull request answers it; `npm run coverage:gated` is the same pair
// locally.
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

// A per-line `allow:swallow-unverified` marker, in the three places it is attached to a
// catch: on the catch's own line, in the comment that OPENS its body, or in the comment
// block written directly above it. Anywhere else in the file it belongs to some other
// statement, and one marker answering for two swallows is one swallow nobody looked at.
//
// The block above is walked rather than counted off in lines. The rule here used to be a
// fixed two lines above the catch, which decided whether a marker belonged to a swallow by
// how long its reason happened to be: a reason that wrapped onto a third line put the
// marker one line out of reach, the gate reported the swallow as unmarked, and the
// sentence explaining why it fails closed was sitting in the file directly above it. That
// is the layout-coupled bound this project bans in a detector, in the direction that turns
// a written decision into noise.
//
// The walk steps over a single-line `try { ... }` opener between the block and the catch,
// because the comment is written for the statement rather than for whichever half of it
// the `catch` keyword landed on. It steps over THAT opener only: a line that begins `try`
// and also carries a `catch` or a `finally` is a complete statement of its own, and
// stepping over one of those puts no bound on how far the marker reaches. A run of
// adjacent single-line try/catch statements is then silenced end to end by the one marker
// written above the first of them. The walk otherwise stops at the first line that is
// neither a comment nor that opener, so a marker cannot reach past ordinary code to a
// catch it was not written for.
//
// The body scan stops at the first line of code for the same reason in the other
// direction. A catch body can hold a whole try/catch statement of its own, and a scan over
// the catch's full span reads the INNER statement's marker as the enclosing catch's: the
// reason a reader would check describes the cleanup, and the fault the outer catch
// actually swallows has nothing written about it at all.
var MARKER_RE = /\ballow:swallow-unverified\b/;
var COMMENT_RE = /^(?:\/\/|\*|\/\*)/;
var TRY_OPENER_RE = /^\}?\s*try\b/;

// The opener of the try statement this catch belongs to, as opposed to a complete
// try/catch or try/finally statement that merely starts with the same word.
function _isOwnTryOpener(s) {
  return TRY_OPENER_RE.test(s) && !/\bcatch\b/.test(s) && !/\bfinally\b/.test(s);
}

/**
 * markerLineFor(srcLines, startLine, endLine) -> the 1-based line carrying the marker
 * this catch is excused by, or 0 when it carries none.
 *
 * The LINE rather than a yes, because which swallow a marker answers for is the whole
 * question here, and a boolean cannot be checked for having answered twice. `main` keys
 * the shared-marker refusal on what this returns.
 */
function markerLineFor(srcLines, startLine, endLine) {
  var ln, s;
  // On the catch's own line, which is where a single-line catch carries it.
  s = srcLines[startLine - 1];
  if (s && MARKER_RE.test(s)) return startLine;
  // In the comment that opens the body, up to the first line of code.
  for (ln = startLine + 1; ln <= endLine; ln++) {
    s = String(srcLines[ln - 1] === undefined ? "" : srcLines[ln - 1]).trim();
    if (!COMMENT_RE.test(s)) break;
    if (MARKER_RE.test(s)) return ln;
  }
  // In the comment block written directly above the catch.
  for (ln = startLine - 1; ln >= 1; ln--) {
    s = String(srcLines[ln - 1] === undefined ? "" : srcLines[ln - 1]).trim();
    if (s === "") break;                       // the block is not attached to this catch
    if (_isOwnTryOpener(s)) continue;          // the statement's own opener
    if (!COMMENT_RE.test(s)) break;
    if (MARKER_RE.test(s)) return ln;
  }
  return 0;
}

function isMarked(srcLines, startLine, endLine) {
  return markerLineFor(srcLines, startLine, endLine) !== 0;
}

/**
 * sharedMarkers(claims) -> [ { marker, swallows } ], for every marker line that excused
 * more than one swallow.
 *
 * `claims` maps `<file>:<marker line>` to the swallows that were let through by it.
 *
 * The reach rules above decide, one catch at a time, which marker is attached to it. This
 * asks the same invariant from the other end, where no reach rule is involved and none can
 * grant more than it says: a written reason answers for ONE swallow. Two swallows behind
 * one sentence means
 * the sentence describes at most one of them, and the other was let through by an
 * explanation of something else. Reporting it names both, which is what a reader needs to
 * decide which one the reason was for and what the other one still owes.
 */
function sharedMarkers(claims) {
  var out = [];
  Object.keys(claims || {}).sort().forEach(function (key) {
    if (claims[key].length > 1) out.push({ marker: key, swallows: claims[key].slice() });
  });
  return out;
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
  // Which marker line let which swallow through, recorded only for the swallows that
  // actually reached the marker read. A covered swallow never consults one, so a marker
  // it happens to sit near is not a reason it was let through and does not count as a
  // claim on it.
  var claims = {};
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
      var markerLine = markerLineFor(srcLines, sw.startLine, sw.endLine);
      if (markerLine !== 0) {
        markedCount++;
        var key = rel + ":" + markerLine;
        if (!claims[key]) claims[key] = [];
        claims[key].push(rel + ":" + sw.startLine + " catch (" + sw.param + ")");
        return;
      }
      bad.push({ file: rel, line: sw.startLine, param: sw.param });
    });
  });
  var shared = sharedMarkers(claims);
  console.log("[check-swallow-coverage] swallows=" + swallowCount + " covered=" + coveredCount
    + " marked=" + markedCount + " unverified=" + bad.length + " shared-markers=" + shared.length);

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
  }
  if (shared.length) {
    console.error("\nMarkers excusing more than one swallow (a written reason answers for one):");
    shared.forEach(function (s) {
      console.error("  " + s.marker + " excused " + s.swallows.length + ":");
      s.swallows.forEach(function (w) { console.error("      " + w); });
      console.error("    One of these is what the reason describes. Give the others their own"
        + " marker with their own reason, or a RED vector that drives the catch.");
    });
  }
  if (bad.length === 0 && shared.length === 0 && empty.length === 0) {
    console.log("[check-swallow-coverage] OK -- every lib swallow re-throws, is execution-covered, or carries a marker of its own.");
  }

  // What this run answered for, published whatever the verdict.
  //
  // The sentence above is true of a run that walked no source at all, and it
  // is the same sentence in the same words. Three gates in the declared chain
  // publish this same walk as `lib-source-files`, so an empty one there would
  // be caught, but "caught somewhere else" is not the same as answered for.
  // This gate is invoked bare, as its own step after the instrumented suite,
  // and nothing captures its stdout: the exit code is the whole of what it
  // says, so the refusal of an empty set has to be its own.
  //
  // Both units, because they empty independently and in opposite directions. A
  // walk pointed at a directory that moved takes `lib-source-files` to zero.
  // A `findSwallows` that stopped matching leaves every file read and finds no
  // catch in any of them, which reports a healthy file count beside a verdict
  // about nothing, which is the one this gate exists to give.
  var code = examinedCounts.publish(units, { tag: "[check-swallow-coverage]" });

  process.exit(bad.length || shared.length ? 1 : code);
}

// Exported for hermetic unit tests. The swallow finder, the marker reader and the
// shared-marker refusal are pure, read no report and touch no network, and they are the
// load-bearing logic: `lib-swallows` reaching zero is this finder having stopped matching,
// so a case that holds it to a known shape is what keeps that count honest.
// Requiring this file runs nothing.
module.exports = {
  findSwallows:   findSwallows,
  isMarked:       isMarked,
  markerLineFor:  markerLineFor,
  sharedMarkers:  sharedMarkers,
  parseLcov:      parseLcov,
};

if (require.main === module) main();
