#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * check-regex-growth: every regex literal in lib/ and bin/, timed against
 * inputs it is built to be bad at, and refused when its cost grows faster
 * than its input.
 *
 * A pattern whose cost is quadratic in the length of the subject is a
 * denial of service wherever the subject arrives from the wire. This server
 * accepts a stored message body up to 25 MiB from an unauthenticated
 * sender, and the account holder pays that cost on the request that opens
 * the message. One pattern in this tree already had that shape: an HTML
 * body was reduced to text with a tag matcher that carried no start anchor,
 * so a run of unclosed angle brackets cost 22 ms at 8 KiB, 350 ms at 32 KiB
 * and 5522 ms at 128 KiB, inside a handler with a five second budget.
 *
 * A lexical sweep does not find that. The pattern reads as ordinary, its
 * quantifier is bounded by a negated class, and the shape that hurts it is
 * an input nobody writes by hand. What finds it is measurement.
 *
 * HOW A PATTERN IS MEASURED.
 *
 *   Alphabet   The characters the pattern itself names, read out of its
 *              source: literals, class members, range endpoints, escapes,
 *              and for a negated class both the excluded characters and one
 *              that is not excluded. An escaped punctuation mark is a
 *              literal of that character and is collected as one. Dropping
 *              those left `/\/+$/` with an empty alphabet and a subject of
 *              letters it rejects at the first character of every position,
 *              so the pattern was read and nothing about it was measured.
 *   Subjects   A run of one alphabet character is usually the wrong
 *              subject: it often matches on the first attempt and never
 *              backtracks. What forces the engine to retry the run from
 *              every position is a run followed, or preceded, by a
 *              character that makes the rest of the pattern fail. So each
 *              alphabet character produces a plain run, a run with each
 *              terminator appended, a run with each terminator in front,
 *              and a repeated pair of the two, alongside a cycle of the
 *              whole alphabet.
 *   Ladder     Each subject shape is timed at every rung from 4 characters
 *              to 8192. A shape stops climbing at the first rung that costs
 *              more than the per-probe budget, so a pattern that backtracks
 *              catastrophically is caught at a length where it is still
 *              cheap instead of running to completion at a length where it
 *              is not.
 *   Growth     The two worst shapes are timed again up the same ladder,
 *              taking the MINIMUM of several runs at each rung. Minimum
 *              rather than mean, because contention only ever adds time: on
 *              a loaded machine the mean drifts and the minimum converges
 *              on the same value it has on an idle one. A least-squares
 *              line through those readings, in log length against log cost,
 *              is the growth exponent the verdict is taken from.
 *
 * WHAT IS REFUSED. The verdict is a RATIO, not a wall-clock number, because
 * milliseconds are a property of the machine and a gate pinned to them
 * fails differently on every runner. Doubling the input roughly doubles a
 * linear pattern's cost and roughly quadruples a quadratic one, so the
 * slope of cost against length in log space separates them: 1.0 for linear,
 * 2.0 for quadratic. The slope is FITTED across every rung of the ladder
 * rather than taken between two of them, so no single reading decides it.
 * A pattern is refused when it is BOTH expensive at the top of the ladder
 * and growing at a slope no linear pattern reaches. Load scales every rung
 * together and leaves the slope where it was, which is what makes the
 * threshold portable; the cost floor is what keeps a slope from being
 * fitted to readings small enough that noise is most of them.
 *
 * Two other verdicts fail the run. A pattern that costs more than the
 * per-probe budget at a length below the top of the ladder is refused on
 * that alone, whatever its slope: it is already too expensive for input
 * this server accepts. That one IS a wall-clock assertion, which is why a
 * reading over the budget is never believed on its own; extra matches are
 * taken until one comes back under it, and only a reading that survives all
 * of them is a verdict. And a pattern the run could not measure at all is
 * refused rather than skipped, because a pattern nobody timed is not a
 * pattern that passed.
 *
 * THE SELF-PROOF, on every run. Silence over this tree is worth nothing
 * until the instrument has been shown to speak. `test/fixtures/regex-growth-
 * planted.js` carries regex literals in ordinary code positions, each
 * marked `GROWS` or `FLAT` on its own line. Every run measures them through
 * the same extractor, the same alphabet, the same subjects and the same
 * judge as the tree, and requires every GROWS to be named and every FLAT to
 * be left alone. A run that cannot separate the planted shapes fails
 * loudly, which is the honest failure for an instrument on a machine too
 * loaded to measure anything: the alternative is a tree sweep passing for a
 * reason that has nothing to do with the tree.
 *
 * WHY A CHILD PROCESS. A regex match cannot be interrupted from inside the
 * process running it, so a pattern with catastrophic backtracking would
 * hang this gate rather than be reported by it. The measurement therefore
 * runs in a child with a wall-clock ceiling, journaling each pattern to
 * disk with synchronous writes before it starts on it. A child that is
 * killed leaves the pattern it was measuring named in the journal, and that
 * pattern becomes the finding.
 *
 * SCOPE: lib/ and bin/, which are the two trees that ship and the two that
 * read input from a socket, a message or an operator's command line.
 * `lib/vendor/` is excluded: it is read-only here and replaced wholesale by
 * the vendor refresh, so a finding in it is filed upstream rather than
 * fixed. `scripts/` and `test/` are excluded because neither ships and
 * neither reads wire input; a slow pattern there costs a maintainer seconds
 * on their own machine, which is not the failure this gate is about.
 *
 * Run:
 *   node scripts/check-regex-growth.js
 *   node scripts/check-regex-growth.js --json
 *   node scripts/check-regex-growth.js --root <dir>
 *
 * Exit codes:
 *   0  every pattern was measured, and none grows faster than its input
 *   1  a pattern grows superlinearly, exceeded the probe budget, or could
 *      not be measured; or the self-proof did not separate the planted set
 *   2  the run could not be performed
 */

var fs        = require("node:fs");
var path      = require("node:path");
var spawnSync = require("node:child_process").spawnSync;

var counts = require("./examined-counts.js");

var ROOT_DEFAULT = path.resolve(__dirname, "..");
var LABEL = "[regex-growth] ";

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

var SCAN_DIRS = ["lib", "bin"];

// Named rather than implied, and printed on every run, so a skip nobody
// chose cannot hide inside a walk.
var SCAN_EXCLUSIONS = [
  {
    match:  /^lib\/vendor\//,
    reason: "the vendored framework is read-only here and replaced wholesale by the vendor refresh, so a pattern in it is filed upstream rather than fixed in this tree",
  },
  {
    match:  /(?:^|\/)node_modules\//,
    reason: "installed development tooling, which never ships and never reads wire input",
  },
];

var SOURCE_EXT_RE = /\.js$/;

// The planted set the instrument proves itself against, and the two markers
// a planted literal may carry. Both are frozen contracts: the fixture is
// read by this gate alone, and a marker it does not recognize is a fixture
// that has stopped saying what it expects.
var PLANTED_FIXTURE = "test/fixtures/regex-growth-planted.js";
var MARK_GROWS = "GROWS";
var MARK_FLAT  = "FLAT";
var MARK_RE    = /\/\/\s*(GROWS|FLAT)\b/;

// ---------------------------------------------------------------------------
// Measurement constants
// ---------------------------------------------------------------------------

// The ladder. It ends at 8192, which is long enough for a quadratic pattern
// to stand several hundred times clear of a linear one while still costing
// this gate a few milliseconds per shape. What decides the bottom of it is a
// different problem: a pattern whose cost is exponential rather than
// quadratic is already unmeasurable in the thirties, so the rungs are close
// together down there and only spread out once a doubling is affordable.
//
// A climb stops at the first rung over the probe budget, so the spacing at
// the bottom is what bounds the overrun of the probe that ends it: from a
// rung costing at most the budget, four more characters of a doubling
// pattern is sixteen times the budget and eight more is two hundred and
// fifty six. Measured on `/^(a+)+$/`, a ladder stepping from 24 to 32 spent
// 6.3 seconds on the probe that ended the climb; stepping by four caps that
// near four hundred milliseconds.
var RUNGS = [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 64, 96, 128, 192,
  256, 384, 512, 1024, 2048, 4096, 8192];

// Where the screen stops and the growth measurement begins. Every subject
// shape is screened up to this length; only the worst two climb past it.
// Running all of them to the top would multiply the cost of exactly the
// patterns that are already expensive, which is the wrong direction.
var SCREEN_MAX = 512;
var KEEP_SHAPES = 2;

// Repeats at each rung, taking the minimum. Minimum rather than mean:
// contention only ever adds time, so the smallest of several readings
// converges on the cost the pattern has on an idle machine.
//
// The screen gets fewer than the growth measurement and it gets them for a
// different reason. Its readings decide only which shapes are worth
// climbing, and a shape ranked one place out is not a wrong verdict. What
// it must not do is let ONE preempted reading trip the probe budget, which
// is the one wall-clock assertion in this gate. Measured on a machine
// running 40 busy processes on 32 cores, a screen taking a single reading
// per rung reported an ordinary pattern as over budget in three runs out of
// eight, on a reading of 38 to 53 ms for a match that costs a twenty
// thousandth of that.
var REPEATS        = 3;
var SCREEN_REPEATS = 2;

// Matches taken after a reading exceeds the probe budget, before that
// reading is believed. The loop stops at the first one that comes back
// under budget, so a scheduling artifact costs one extra match and a
// pattern that really is that expensive costs all of them.
var CONFIRM_PROBES = 3;

// A single probe that costs more than this stops its shape climbing. It is
// also the threshold above which a probe below the top rung is a finding on
// its own. The worst reading any pattern in lib/ or bin/ produced at 8192
// characters was 0.031 ms, so 8 ms at a SHORTER length is two and a half
// orders of magnitude outside what this tree's linear patterns cost, and
// the number is low enough that the probe which ends a catastrophic climb
// is measured in hundreds of milliseconds rather than seconds.
var RUNG_BUDGET_MS = 8;

// The PROCESSOR TIME a single pattern may consume across all of its shapes
// before the run gives up on it and reports it as over budget.
//
// Spent in processor time rather than on the wall clock because the
// measuring child competes for the processor with everything else on the
// machine. A wall-clock budget counts the time this process was not
// running, so a climb that has done almost no work stops anyway and the
// pattern comes back unmeasured, which reads as a finding and is not one.
// A pattern that is genuinely expensive burns processor time, which is the
// thing being measured. The probe budget beside this one asserts a
// wall-clock number and is hardened differently, by taking the smallest of
// several readings in `settle`.
var PATTERN_BUDGET_MS = 4000;

// The whole child, killed by the parent past this. Nothing on a healthy
// tree comes close; it exists so a pattern that backtracks catastrophically
// is a named finding rather than a hung gate.
var CHILD_CEILING_MS = 180000;

// THE VERDICT.
//
// `SLOPE_FLOOR` is the exponent of cost against length. A linear pattern
// measures 1.0 and a quadratic one 2.0, so the floor sits between them,
// nearer the linear end because a real quadratic measures above 1.9 and the
// margin is better spent on not missing one.
//
// `MS_FLOOR` is what keeps the slope honest, and it is not a second-best
// wall-clock assertion sneaking in beside the first. A slope taken across
// readings near the resolution of the timer is a slope of noise: measured
// under 40 busy processes on 32 cores, ordinary patterns in this tree
// produced slopes as high as 1.87 on readings of six hundredths of a
// millisecond. Above the floor the three points a slope is taken across are
// all in the milliseconds, where the same noise is a rounding error. So the
// floor decides WHETHER a pattern is worth a growth verdict, and the slope
// decides what that verdict is.
//
// The slope is FITTED across every timeable rung rather than taken from
// the two ends of the ladder, and `MIN_FIT_POINTS` is how many readings it
// takes before one is computed at all. An endpoint ratio is decided by
// exactly two readings, so one of them being wrong is the whole answer
// being wrong, in either direction: a rule asking every consecutive pair to
// grow was vetoed by one inflated middle reading and reported a planted
// quadratic as linear at 1.59 during a chain run. A fit over five or six
// rungs gives any single reading a fraction of the weight, and the rungs
// below the top are cheap to measure, so there is no reason to decide on
// two of them.
//
// Measured on this tree at the time these were set: every one of the 74
// patterns in lib/ and bin/ came in between 0.83 and 1.17 on an idle
// machine, reaching at most 0.03 ms at 8192 characters. The planted
// quadratic shapes came in between 1.97 and 2.10, reaching 19 to 26 ms. So
// the floors sit in a gap of two orders of magnitude in cost and eight
// tenths of an exponent in growth.
var SLOPE_FLOOR    = 1.55;
var MS_FLOOR       = 2;
var MIN_FIT_POINTS = 3;

// A reading below this is at the resolution of the timer plus the cost of
// the call itself, so a ratio taken across it is a ratio of noise. Points
// under it are not used to compute a slope.
var MIN_TIMEABLE_MS = 0.004;

// How much of a pattern's own alphabet is turned into subject shapes, and
// how many characters are tried as the terminator that makes the rest of
// the pattern fail. Both are caps on the shape count rather than judgments
// about which characters matter: the alphabet is walked in the order the
// pattern writes it, so the cap keeps the characters the pattern leads
// with.
var MAX_ALPHA = 6;
var MAX_TERMS = 3;

// Terminators every pattern is tried against, on top of anything its own
// negated classes exclude.
var FIXED_TERMS = ["x", "!", " "];

// The fallback alphabet for a pattern that names no characters at all,
// which `/^$/` and `/^\s*$/`-shaped anchors legitimately do. It is counted
// and reported separately rather than folded in, because an alphabet that
// emptied for a pattern that DOES name characters is the failure this
// instrument has already had once.
var FALLBACK_ALPHA = ["a"];

// ---------------------------------------------------------------------------
// Reading regex literals out of a source file
// ---------------------------------------------------------------------------

// The words after which a `/` opens a regular expression rather than
// dividing. Without them `return /^re:/i.test(s)` reads as division and the
// pattern is never seen: the character before the slash is a letter, and a
// letter is what an identifier ends with too.
var REGEX_AFTER_WORD = {
  "return": true, "typeof": true, "instanceof": true, "in": true, "of": true,
  "new": true, "delete": true, "void": true, "throw": true, "case": true,
  "do": true, "else": true, "yield": true, "await": true,
};

var IDENT_START_RE = /[A-Za-z_$]/;
var IDENT_PART_RE  = /[A-Za-z0-9_$]/;
var DIGIT_RE       = /[0-9]/;
var NUMBER_PART_RE = /[0-9a-fA-FxXoObBn._]/;
var SPACE_RE       = /\s/;
var FLAG_RE        = /[dgimsuvy]/;

/**
 * extractLiterals(src) -> [ { source, flags, at, line } ]
 *
 * A state machine rather than a pattern, so a `/` inside a string, a
 * comment or a template is not read as one. Two shapes are deliberately
 * outside it and are named here rather than left to be discovered: a regex
 * written inside a template literal's `${}` is skipped with the template,
 * and a regex immediately following `)` is read as division, which is what
 * `(a) / b` is and what `if (x) /re/.test(y)` is not. Neither shape occurs
 * in this tree, and both would have to be handled by a parser rather than a
 * scanner.
 */
function extractLiterals(src) {
  var out = [];
  var i = 0;
  var n = src.length;
  var prevChar = "";
  var prevWord = "";

  // A leading `#!` line is not JavaScript. Reading it as such turns the
  // interpreter path into a regex literal, and `/usr/` then joins the
  // report as a pattern nobody wrote.
  if (src.charAt(0) === "#" && src.charAt(1) === "!") {
    while (i < n && src.charAt(i) !== "\n") i += 1;
  }

  while (i < n) {
    var c = src.charAt(i);

    if (c === "/" && src.charAt(i + 1) === "/") {
      while (i < n && src.charAt(i) !== "\n") i += 1;
      continue;
    }
    if (c === "/" && src.charAt(i + 1) === "*") {
      var endComment = src.indexOf("*/", i + 2);
      i = endComment === -1 ? n : endComment + 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      var quote = c;
      i += 1;
      while (i < n) {
        if (src.charAt(i) === "\\") { i += 2; continue; }
        if (src.charAt(i) === quote) { i += 1; break; }
        i += 1;
      }
      prevChar = quote;
      prevWord = "";
      continue;
    }
    if (IDENT_START_RE.test(c)) {
      var wordEnd = i;
      while (wordEnd < n && IDENT_PART_RE.test(src.charAt(wordEnd))) wordEnd += 1;
      prevWord = src.slice(i, wordEnd);
      prevChar = src.charAt(wordEnd - 1);
      i = wordEnd;
      continue;
    }
    if (DIGIT_RE.test(c)) {
      var numEnd = i;
      while (numEnd < n && NUMBER_PART_RE.test(src.charAt(numEnd))) numEnd += 1;
      prevWord = "";
      prevChar = "0";
      i = numEnd;
      continue;
    }

    if (c === "/") {
      var closesValue = prevChar === ")" || prevChar === "]" ||
        prevChar === '"' || prevChar === "'" || prevChar === "`" ||
        IDENT_PART_RE.test(prevChar);
      var isDivision = closesValue &&
        !(prevWord !== "" && REGEX_AFTER_WORD[prevWord] === true);
      if (isDivision) {
        i += 1;
        prevChar = "/";
        prevWord = "";
        continue;
      }

      var start = i;
      var inClass = false;
      var j = i + 1;
      var closed = false;
      while (j < n) {
        var d = src.charAt(j);
        if (d === "\\") { j += 2; continue; }
        if (d === "\n") break;
        if (d === "[") inClass = true;
        else if (d === "]") inClass = false;
        else if (d === "/" && !inClass) { closed = true; break; }
        j += 1;
      }
      if (!closed) { i += 1; prevChar = "/"; prevWord = ""; continue; }

      var body = src.slice(start + 1, j);
      var k = j + 1;
      var flags = "";
      while (k < n && FLAG_RE.test(src.charAt(k))) { flags += src.charAt(k); k += 1; }
      if (body.length > 0) out.push({ source: body, flags: flags, at: start });
      i = k;
      prevChar = "/";
      prevWord = "";
      continue;
    }

    if (!SPACE_RE.test(c)) { prevChar = c; prevWord = ""; }
    i += 1;
  }

  var lineStarts = [0];
  for (var p = 0; p < n; p += 1) {
    if (src.charCodeAt(p) === 10) lineStarts.push(p + 1);
  }
  out.forEach(function (lit) {
    var lo = 0;
    var hi = lineStarts.length - 1;
    while (lo < hi) {
      var mid = Math.ceil((lo + hi) / 2);
      if (lineStarts[mid] <= lit.at) lo = mid; else hi = mid - 1;
    }
    lit.line = lo + 1;
  });
  return out;
}

// ---------------------------------------------------------------------------
// The alphabet a pattern is measured against
// ---------------------------------------------------------------------------

// What a class escape stands for: characters it accepts, and characters it
// refuses. The refusals matter as much as the acceptances, because a
// terminator is exactly a character the pattern will not take.
var CLASS_ESCAPES = {
  d: { inside: ["0", "5"],           outside: ["a"] },
  D: { inside: ["a"],                outside: ["0"] },
  w: { inside: ["a", "_", "9"],      outside: ["-"] },
  W: { inside: ["-", " "],           outside: ["a"] },
  s: { inside: [" ", "\t"],          outside: ["a"] },
  S: { inside: ["a"],                outside: [" "] },
};

// `\0` is a null character, and it is BUILT rather than written. A raw
// control byte in a source file is a byte no diff and no review renders,
// which is why this repository refuses one.
var SIMPLE_ESCAPES = {
  n: "\n", r: "\r", t: "\t", f: "\f", v: "\v", "0": String.fromCharCode(0),
};

var HEX4_RE = /^[0-9a-fA-F]{4}$/;
var HEX2_RE = /^[0-9a-fA-F]{2}$/;

// Characters offered as "not in this negated class", first one that the
// class does not exclude.
var NOT_IN_CANDIDATES = ["a", "<", "0", " ", "z", "!", "~"];

/**
 * readEscape(src, i) -> { next, inside, outside }
 *
 * One backslash escape, at index `i`. `inside` is what it can match and
 * `outside` is what it cannot. The last branch is the one that matters
 * most: an escaped punctuation mark is a literal of that character, and it
 * is the character a run has to be built from.
 */
function readEscape(src, i) {
  var e = src.charAt(i + 1);
  if (e === "") return { next: i + 1, inside: [], outside: [] };

  if (Object.prototype.hasOwnProperty.call(CLASS_ESCAPES, e)) {
    var expansion = CLASS_ESCAPES[e];
    return { next: i + 2, inside: expansion.inside.slice(), outside: expansion.outside.slice() };
  }
  if (Object.prototype.hasOwnProperty.call(SIMPLE_ESCAPES, e)) {
    return { next: i + 2, inside: [SIMPLE_ESCAPES[e]], outside: [] };
  }
  if (e === "u") {
    if (src.charAt(i + 2) === "{") {
      var close = src.indexOf("}", i + 3);
      var body = close === -1 ? "" : src.slice(i + 3, close);
      var cp = parseInt(body, 16);
      if (close !== -1 && isFinite(cp) && cp >= 0 && cp <= 0x10ffff) {
        return { next: close + 1, inside: [String.fromCodePoint(cp)], outside: [] };
      }
      return { next: close === -1 ? i + 2 : close + 1, inside: [], outside: [] };
    }
    var hex4 = src.substr(i + 2, 4);
    if (HEX4_RE.test(hex4)) {
      return { next: i + 6, inside: [String.fromCharCode(parseInt(hex4, 16))], outside: [] };
    }
    return { next: i + 2, inside: [], outside: [] };
  }
  if (e === "x") {
    var hex2 = src.substr(i + 2, 2);
    if (HEX2_RE.test(hex2)) {
      return { next: i + 4, inside: [String.fromCharCode(parseInt(hex2, 16))], outside: [] };
    }
    return { next: i + 2, inside: [], outside: [] };
  }
  if (e === "c") return { next: i + 3, inside: [], outside: [] };
  if (e === "p" || e === "P") {
    var braceEnd = src.indexOf("}", i + 2);
    return {
      next:    braceEnd === -1 ? i + 2 : braceEnd + 1,
      inside:  ["a", "0"],
      outside: [],
    };
  }
  if (e === "k") {
    var nameEnd = src.indexOf(">", i + 2);
    return { next: nameEnd === -1 ? i + 2 : nameEnd + 1, inside: [], outside: [] };
  }
  if (e === "b" || e === "B") return { next: i + 2, inside: [], outside: [] };
  if (DIGIT_RE.test(e)) {
    var digitEnd = i + 1;
    while (digitEnd < src.length && DIGIT_RE.test(src.charAt(digitEnd))) digitEnd += 1;
    return { next: digitEnd, inside: [], outside: [] };
  }
  return { next: i + 2, inside: [e], outside: [] };
}

function _pushUnique(list, seen, chars) {
  chars.forEach(function (ch) {
    if (typeof ch !== "string" || ch.length === 0) return;
    if (seen[ch]) return;
    seen[ch] = true;
    list.push(ch);
  });
}

function _notIn(members) {
  var blocked = Object.create(null);
  members.forEach(function (ch) { blocked[ch] = true; });
  for (var i = 0; i < NOT_IN_CANDIDATES.length; i += 1) {
    if (!blocked[NOT_IN_CANDIDATES[i]]) return NOT_IN_CANDIDATES[i];
  }
  return "";
}

/**
 * alphabetOf(source) -> { alpha, terms, derived }
 *
 * `alpha` is what subjects are built out of, in the order the pattern names
 * them, so a cap keeps the characters it leads with. `terms` is what a run
 * is terminated by: whatever the pattern refuses, plus a fixed set.
 * `derived` is false when the pattern named no characters at all and the
 * fallback was used, which is a legitimate answer for a pure anchor and a
 * fault for anything else.
 */
function alphabetOf(source) {
  var inside = [];
  var insideSeen = Object.create(null);
  var outside = [];
  var outsideSeen = Object.create(null);

  var i = 0;
  var n = source.length;
  while (i < n) {
    var c = source.charAt(i);

    if (c === "\\") {
      var esc = readEscape(source, i);
      _pushUnique(inside, insideSeen, esc.inside);
      _pushUnique(outside, outsideSeen, esc.outside);
      i = esc.next;
      continue;
    }

    if (c === "[") {
      var negated = source.charAt(i + 1) === "^";
      var j = i + 1 + (negated ? 1 : 0);
      var members = [];
      var refused = [];
      if (source.charAt(j) === "]") { members.push("]"); j += 1; }
      while (j < n && source.charAt(j) !== "]") {
        if (source.charAt(j) === "\\") {
          var memberEsc = readEscape(source, j);
          members = members.concat(memberEsc.inside);
          refused = refused.concat(memberEsc.outside);
          j = memberEsc.next;
          continue;
        }
        if (source.charAt(j + 1) === "-" && j + 2 < n &&
            source.charAt(j + 2) !== "]" && source.charAt(j + 2) !== "\\") {
          var lo = source.charCodeAt(j);
          var hi = source.charCodeAt(j + 2);
          if (hi >= lo) {
            members.push(String.fromCharCode(lo));
            members.push(String.fromCharCode(Math.floor((lo + hi) / 2)));
            members.push(String.fromCharCode(hi));
          } else {
            members.push(source.charAt(j));
            members.push(source.charAt(j + 2));
          }
          j += 3;
          continue;
        }
        members.push(source.charAt(j));
        j += 1;
      }
      i = j < n ? j + 1 : n;

      if (negated) {
        _pushUnique(outside, outsideSeen, members);
        _pushUnique(inside, insideSeen, refused);
        _pushUnique(inside, insideSeen, [_notIn(members)]);
      } else {
        _pushUnique(inside, insideSeen, members);
        _pushUnique(outside, outsideSeen, refused);
      }
      continue;
    }

    if (c === ".") { _pushUnique(inside, insideSeen, ["a"]); i += 1; continue; }
    if ("^$*+?()|{}".indexOf(c) !== -1) { i += 1; continue; }

    _pushUnique(inside, insideSeen, [c]);
    i += 1;
  }

  var derived = inside.length > 0;
  var alpha = derived ? inside.slice(0, MAX_ALPHA) : FALLBACK_ALPHA.slice();

  var terms = [];
  var termsSeen = Object.create(null);
  _pushUnique(terms, termsSeen, outside);
  _pushUnique(terms, termsSeen, FIXED_TERMS);

  return { alpha: alpha, terms: terms.slice(0, MAX_TERMS), derived: derived };
}

// ---------------------------------------------------------------------------
// Subject shapes
// ---------------------------------------------------------------------------

// Both build by repeating a unit rather than by appending a character at a
// time. A subject is rebuilt at every rung of every shape, so the loop that
// looks harmless at 16 characters is run tens of thousands of times at
// 8192.
function _run(ch, len) {
  if (len <= 0) return "";
  return ch.repeat(len);
}

function _cycle(chars, len) {
  if (len <= 0) return "";
  var unit = chars.join("");
  return unit.repeat(Math.ceil(len / unit.length)).slice(0, len);
}

function _quote(ch) {
  return JSON.stringify(ch).slice(1, -1);
}

/**
 * shapesFor(alpha, terms) -> [ { label, make(len) } ]
 *
 * Every subject the pattern is tried against, as a label and a builder, so
 * the same shape can be rebuilt at each rung of the ladder without holding
 * a string per rung per shape in memory.
 */
function shapesFor(alpha, terms) {
  var shapes = [];
  var seen = Object.create(null);

  function add(label, make) {
    if (seen[label]) return;
    seen[label] = true;
    shapes.push({ label: label, make: make });
  }

  add("cycle(" + alpha.map(_quote).join("") + ")", function (len) {
    return _cycle(alpha, len);
  });

  alpha.forEach(function (ch) {
    add("run(" + _quote(ch) + ")", function (len) { return _run(ch, len); });
    terms.forEach(function (t) {
      if (t === ch) return;
      add("run(" + _quote(ch) + ")+" + _quote(t), function (len) {
        return _run(ch, len - 1) + t;
      });
      add(_quote(t) + "+run(" + _quote(ch) + ")", function (len) {
        return t + _run(ch, len - 1);
      });
    });
  });

  if (alpha.length > 1) {
    add("alt(" + _quote(alpha[0]) + _quote(alpha[1]) + ")", function (len) {
      return _cycle([alpha[0], alpha[1]], len);
    });
    add("run(" + _quote(alpha[0]) + ")+" + _quote(alpha[1]), function (len) {
      return _run(alpha[0], len - 1) + alpha[1];
    });
  }

  // A repeated PAIR of a wanted character and a refused one, which is the
  // subject a quantified group wants when the group itself spans both. A
  // run of one character never reaches that shape, and neither does a cycle
  // of the whole alphabet once the alphabet has three or more members in
  // it.
  alpha.slice(0, 2).forEach(function (ch) {
    terms.slice(0, 1).forEach(function (t) {
      if (t === ch) return;
      var pair = _quote(ch) + _quote(t);
      add("pairs(" + pair + ")", function (len) { return _cycle([ch, t], len); });
      add("pairs(" + pair + ")+" + _quote(ch), function (len) {
        return _cycle([ch, t], len - 1) + ch;
      });
    });
  });

  return shapes;
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/**
 * compileProbe(source, flags) -> RegExp or null
 *
 * `g` and `y` are dropped because both carry `lastIndex` between calls, so
 * a repeated probe would measure a different subject each time. `d` is
 * dropped because recording capture indices costs time that says nothing
 * about how the pattern backtracks.
 */
function compileProbe(source, flags) {
  try { return new RegExp(source, String(flags || "").replace(/[gyd]/g, "")); }
  catch (_e) { return null; }
}

function _once(re, subject) {
  var t0 = process.hrtime.bigint();
  re.test(subject);
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

function probe(re, subject, repeats) {
  re.lastIndex = 0;
  re.test(subject);
  var best = Infinity;
  for (var i = 0; i < repeats; i += 1) {
    var dt = _once(re, subject);
    if (dt < best) best = dt;
  }
  return best;
}

/**
 * settle(re, subject, ms) -> the reading to believe.
 *
 * Called only when a reading came in over the probe budget, which is the
 * one place this gate asserts a wall-clock number and therefore the one
 * place a preempted thread can produce a verdict on its own. Extra matches
 * are taken until one comes back under budget, and the smallest reading
 * wins. A pattern that is genuinely that expensive stays over budget
 * however many times it is asked.
 */
function settle(re, subject, ms) {
  var best = ms;
  for (var i = 0; i < CONFIRM_PROBES; i += 1) {
    var dt = _once(re, subject);
    if (dt < best) best = dt;
    if (best <= RUNG_BUDGET_MS) return best;
  }
  return best;
}

/**
 * climb(re, shape, maxLen, repeats, spent) -> { points, overBudgetAt,
 * deadlineAt }
 *
 * `spent` answers how much processor time this pattern has used so far, in
 * milliseconds.
 *
 * One shape up the ladder. It stops at `maxLen`, at the first rung whose
 * probe cost more than the probe budget, or when the pattern's own
 * wall-clock budget is gone. The two stops are reported separately because
 * they are different findings: one says the pattern is too expensive at a
 * length this server accepts, the other says the whole pattern ate its
 * measurement budget before a verdict was reached.
 */
function climb(re, shape, maxLen, repeats, spent) {
  var points = [];
  var overBudgetAt = 0;
  var deadlineAt = 0;
  for (var i = 0; i < RUNGS.length; i += 1) {
    var len = RUNGS[i];
    if (len > maxLen) break;
    if (spent() > PATTERN_BUDGET_MS) { deadlineAt = len; break; }
    var subject = shape.make(len);
    var ms = probe(re, subject, repeats);
    if (ms > RUNG_BUDGET_MS) ms = settle(re, subject, ms);
    points.push({ len: len, ms: ms });
    if (ms > RUNG_BUDGET_MS) { overBudgetAt = len; break; }
  }
  return { points: points, overBudgetAt: overBudgetAt, deadlineAt: deadlineAt };
}

/**
 * slopeOf(points) -> { slope, span, n } or null
 *
 * The exponent of cost against length: the least-squares slope of log cost
 * against log length, over every reading far enough above the resolution of
 * the timer to mean anything. A linear pattern fits 1.0 and a quadratic one
 * 2.0.
 *
 * A fit rather than a ratio between two rungs, because a ratio is decided
 * by two readings and a fit is decided by all of them. `span` is the
 * endpoint ratio the fit replaces, reported alongside so a reader can see
 * both; nothing is judged on it.
 *
 * Fewer than `MIN_FIT_POINTS` readings above the noise floor gives no
 * slope at all, and a pattern with no slope is reported as one that could
 * not be judged rather than as one that passed.
 */
function slopeOf(points) {
  var usable = points.filter(function (p) { return p.ms >= MIN_TIMEABLE_MS; });
  if (usable.length < MIN_FIT_POINTS) return null;

  var n = usable.length;
  var sx = 0;
  var sy = 0;
  var sxx = 0;
  var sxy = 0;
  usable.forEach(function (p) {
    var x = Math.log(p.len);
    var y = Math.log(p.ms);
    sx += x;
    sy += y;
    sxx += x * x;
    sxy += x * y;
  });
  var denominator = (n * sxx) - (sx * sx);
  if (denominator === 0) return null;
  var slope = ((n * sxy) - (sx * sy)) / denominator;
  if (!isFinite(slope)) return null;

  var first = usable[0];
  var last = usable[n - 1];
  var span = last.len > first.len
    ? Math.log(last.ms / first.ms) / Math.log(last.len / first.len)
    : null;

  return { slope: slope, span: span, n: n };
}

// ---------------------------------------------------------------------------
// Measuring one pattern
// ---------------------------------------------------------------------------

/**
 * measurePattern(entry) -> result
 *
 * The whole instrument for one literal: compile, alphabet, shapes, screen,
 * climb, judge. `measured` is false only when the pattern could not be
 * compiled or no probe ran at all, and a pattern that comes back unmeasured
 * is a finding rather than a skip.
 */
function measurePattern(entry) {
  var re = compileProbe(entry.source, entry.flags);
  if (re === null) {
    return {
      measured: false,
      verdict:  "uncompilable",
      why:      "the literal does not compile as a regular expression on this runtime, so nothing about it could be timed",
      shapes:   0,
      probes:   0,
    };
  }

  var alphabet = alphabetOf(entry.source);
  var shapes = shapesFor(alphabet.alpha, alphabet.terms);
  // Processor time this pattern has spent, measured from here. `cpuUsage`
  // answers in microseconds and counts only this process, so time the
  // machine gave to something else is not charged against the budget.
  var budgetMark = process.cpuUsage();
  function spent() {
    var used = process.cpuUsage(budgetMark);
    return (used.user + used.system) / 1000;
  }
  var probes = 0;

  var breach = null;
  var deadlineHit = 0;

  function noteStop(shape, climbed) {
    if (climbed.deadlineAt !== 0 && deadlineHit === 0) deadlineHit = climbed.deadlineAt;
    if (climbed.overBudgetAt === 0) return;
    var here = { at: climbed.overBudgetAt, label: shape.label, ms: 0 };
    if (climbed.points.length > 0) here.ms = climbed.points[climbed.points.length - 1].ms;
    if (breach === null || here.at < breach.at) breach = here;
  }

  var topRung = RUNGS[RUNGS.length - 1];

  // A breach below the top rung already decides the verdict, so the screen
  // stops on the first one rather than walking the rest of the shapes. A
  // pattern that backtracks catastrophically usually has several shapes
  // that do it, each costing the overrun of the probe that ends its climb,
  // and measuring the fourth of them adds nothing to a verdict the first
  // one settled.
  function decided() { return breach !== null && breach.at < topRung; }

  var screened = [];
  for (var s = 0; s < shapes.length && !decided(); s += 1) {
    var climbed = climb(re, shapes[s], SCREEN_MAX, SCREEN_REPEATS, spent);
    probes += climbed.points.length * SCREEN_REPEATS;
    noteStop(shapes[s], climbed);
    var top = climbed.points.length ? climbed.points[climbed.points.length - 1] : { len: 0, ms: 0 };
    screened.push({ shape: shapes[s], top: top });
  }

  var ranked = screened.slice().sort(function (a, b) {
    if (b.top.ms !== a.top.ms) return b.top.ms - a.top.ms;
    return a.top.len - b.top.len;
  });

  var carried = [];
  if (!decided()) {
    ranked.slice(0, KEEP_SHAPES).forEach(function (candidate) {
      if (decided()) return;
      var grown = climb(re, candidate.shape, topRung, REPEATS, spent);
      probes += grown.points.length * REPEATS;
      noteStop(candidate.shape, grown);
      if (grown.points.length === 0) return;
      carried.push({
        label:  candidate.shape.label,
        points: grown.points,
        growth: slopeOf(grown.points),
      });
    });
  }

  var result = {
    measured: probes > 0,
    shapes:   shapes.length,
    probes:   probes,
    alphabet: alphabet,
    verdict:  "linear",
    why:      "",
    topLen:    null,
    topMs:     null,
    slope:     null,
    span:      null,
    fitPoints: 0,
    worst:     null,
  };

  // A pattern that ran a probe past the budget at a length below the top of
  // the ladder is refused on that alone, ahead of any question about its
  // slope. It is already costing more for a fraction of an 8 KiB input than
  // this gate is willing to spend on a whole one, and a pattern in that
  // state is usually one whose slope cannot be measured at all because the
  // ladder cannot be climbed far enough to take one.
  if (decided()) {
    result.verdict = "over-budget";
    result.topLen = breach.at;
    result.topMs = breach.ms;
    result.why = "one match against " + breach.at + " characters of " + breach.label +
      " cost " + breach.ms.toFixed(1) + " ms, past the " + RUNG_BUDGET_MS +
      " ms probe budget and still past it on every retry. A pattern that expensive on " +
      breach.at + " characters needs no growth measurement to be a denial of service on " +
      "the input this server accepts";
    return result;
  }

  if (carried.length === 0) {
    result.verdict = deadlineHit !== 0 ? "over-budget" : "unmeasured";
    result.why = deadlineHit !== 0
      ? "the pattern used its whole " + PATTERN_BUDGET_MS + " ms of processor time on the " +
        "screening pass and reached no reading above " + deadlineHit + " characters"
      : "no subject shape produced a reading at all";
    return result;
  }

  // The worst shape decides, and worst means the highest cost reached.
  var worst = carried.slice().sort(function (a, b) {
    return b.points[b.points.length - 1].ms - a.points[a.points.length - 1].ms;
  })[0];
  var topPoint = worst.points[worst.points.length - 1];

  result.worst = { label: worst.label, points: worst.points };
  result.topLen = topPoint.len;
  result.topMs = topPoint.ms;
  result.slope = worst.growth ? worst.growth.slope : null;
  result.span = worst.growth ? worst.growth.span : null;
  result.fitPoints = worst.growth ? worst.growth.n : 0;

  if (deadlineHit !== 0) {
    result.verdict = "over-budget";
    result.why = "the pattern used its whole " + PATTERN_BUDGET_MS +
      " ms of processor time before the ladder was finished, having reached " +
      topPoint.ms.toFixed(1) + " ms at " + topPoint.len + " characters of " + worst.label;
    return result;
  }

  // Below the cost floor the pattern is not a denial of service at any
  // length this server accepts, whatever its slope, and a slope taken over
  // readings at the resolution of the timer is a slope of noise. This is
  // where every pattern in the tree lands: the highest reading in lib/ and
  // bin/ is three hundredths of a millisecond at 8192 characters.
  if (topPoint.ms < MS_FLOOR) {
    result.verdict = "cheap";
    result.why = "the worst subject found for it costs " + topPoint.ms.toFixed(4) +
      " ms at " + topPoint.len + " characters, below the " + MS_FLOOR + " ms floor";
    return result;
  }

  var growth = worst.growth;
  if (growth === null) {
    result.verdict = "unjudged";
    result.why = "it reaches " + topPoint.ms.toFixed(1) + " ms at " + topPoint.len +
      " characters of " + worst.label + " and yet has fewer than " + MIN_FIT_POINTS +
      " readings above " + MIN_TIMEABLE_MS + " ms, so no growth exponent can be fitted to it";
    return result;
  }

  if (growth.slope >= SLOPE_FLOOR) {
    result.verdict = "superlinear";
    result.why = "cost grows as length to the power of " + growth.slope.toFixed(2) +
      " against " + worst.label + ", fitted across " + growth.n + " rungs and reaching " +
      topPoint.ms.toFixed(1) + " ms at " + topPoint.len +
      " characters. A linear pattern measures 1.00 and a quadratic one 2.00";
    return result;
  }

  return result;
}

// ---------------------------------------------------------------------------
// The child that does the measuring
// ---------------------------------------------------------------------------

// A pattern is journaled before it is measured and again after, with
// synchronous writes, so a child killed mid-match leaves the pattern it was
// on named on disk. That is the only way a match that cannot be interrupted
// becomes a finding instead of a hang.
function _journalWrite(fd, obj) {
  fs.writeSync(fd, JSON.stringify(obj) + "\n");
}

function runChild(jobPath, journalPath) {
  var job = JSON.parse(fs.readFileSync(jobPath, "utf8"));
  fs.mkdirSync(path.dirname(journalPath), { recursive: true });
  var fd = fs.openSync(journalPath, "w");
  try {
    job.entries.forEach(function (entry, index) {
      _journalWrite(fd, { event: "start", index: index });
      var measured = measurePattern(entry);
      _journalWrite(fd, { event: "result", index: index, result: measured });
    });
    _journalWrite(fd, { event: "done", n: job.entries.length });
  } finally {
    fs.closeSync(fd);
  }
  return 0;
}

function _readJournal(journalPath, total) {
  var results = new Array(total);
  var started = new Array(total);
  var completed = false;
  var raw;
  try { raw = fs.readFileSync(journalPath, "utf8"); }
  catch (_e) { return { results: results, started: started, completed: false }; }
  raw.split(/\r?\n/).forEach(function (line) {
    if (line.trim() === "") return;
    var record;
    try { record = JSON.parse(line); }
    catch (_e) { return; }
    if (record.event === "start") started[record.index] = true;
    else if (record.event === "result") results[record.index] = record.result;
    else if (record.event === "done") completed = true;
  });
  return { results: results, started: started, completed: completed };
}

// ---------------------------------------------------------------------------
// Collecting what is measured
// ---------------------------------------------------------------------------

function _toPosix(p) { return p.split(path.sep).join("/"); }

function _excluded(rel) {
  for (var i = 0; i < SCAN_EXCLUSIONS.length; i += 1) {
    if (SCAN_EXCLUSIONS[i].match.test(rel)) return true;
  }
  return false;
}

function sourceFiles(root) {
  var out = [];

  function walk(absDir, relDir) {
    var entries;
    try { entries = fs.readdirSync(absDir, { withFileTypes: true }); }
    catch (_e) { return; }
    entries.sort(function (a, b) { return a.name < b.name ? -1 : 1; });
    entries.forEach(function (e) {
      var abs = path.join(absDir, e.name);
      var rel = relDir ? relDir + "/" + e.name : e.name;
      if (e.isDirectory()) { if (!_excluded(rel + "/")) walk(abs, rel); return; }
      if (!e.isFile()) return;
      if (!SOURCE_EXT_RE.test(e.name)) return;
      if (_excluded(rel)) return;
      out.push({ abs: abs, rel: rel });
    });
  }

  SCAN_DIRS.forEach(function (d) {
    var abs = path.join(root, d.split("/").join(path.sep));
    if (fs.existsSync(abs)) walk(abs, d);
  });
  return out;
}

function collectTree(root, problems) {
  var files = sourceFiles(root);
  if (files.length === 0) {
    problems.push({
      file:    SCAN_DIRS.join(" and "),
      message: "hold no source files, so there is nothing to measure. The scan is pointed somewhere the shipped trees are not.",
    });
  }
  var entries = [];
  files.forEach(function (f) {
    var src;
    try { src = fs.readFileSync(f.abs, "utf8"); }
    catch (_e) {
      problems.push({ file: f.rel, message: "unreadable, so every pattern in it went unmeasured." });
      return;
    }
    extractLiterals(src).forEach(function (lit) {
      entries.push({
        kind:   "tree",
        file:   f.rel,
        line:   lit.line,
        source: lit.source,
        flags:  lit.flags,
      });
    });
  });
  return { files: files.length, entries: entries };
}

/**
 * collectPlanted(root, problems) reads the fixture the instrument proves
 * itself against.
 *
 * Every literal in the fixture carries its expectation on its own line, so
 * there is no second list of what is planted to fall out of step with what
 * is written. A literal with no marker, a marker with no literal, or two
 * literals on one marked line are all faults in the fixture, and a fixture
 * that cannot say what it expects proves nothing.
 */
function collectPlanted(root, problems) {
  var rel = PLANTED_FIXTURE;
  var abs = path.join(root, rel.split("/").join(path.sep));
  var src;
  try { src = fs.readFileSync(abs, "utf8"); }
  catch (_e) {
    problems.push({
      file:    rel,
      message: "absent or unreadable. It carries the planted shapes this gate proves itself against, and without it a silent run over the tree says nothing about whether the instrument works.",
    });
    return { entries: [], grows: 0, flat: 0 };
  }

  var lines = src.split(/\r?\n/);
  var literals = extractLiterals(src);
  var byLine = Object.create(null);
  literals.forEach(function (lit) {
    byLine[lit.line] = (byLine[lit.line] || []).concat([lit]);
  });

  var entries = [];
  var grows = 0;
  var flat = 0;

  lines.forEach(function (text, index) {
    var lineNo = index + 1;
    var mark = MARK_RE.exec(text);
    var here = byLine[lineNo] || [];
    if (mark === null) {
      if (here.length > 0) {
        problems.push({
          file:    rel,
          line:    lineNo,
          message: "carries a regex literal with no " + MARK_GROWS + " or " + MARK_FLAT +
            " marker, so the fixture does not say what the instrument is supposed to conclude about it.",
        });
      }
      return;
    }
    if (here.length === 0) {
      problems.push({
        file:    rel,
        line:    lineNo,
        message: "carries a " + mark[1] + " marker and no regex literal, so the marker describes nothing.",
      });
      return;
    }
    if (here.length > 1) {
      problems.push({
        file:    rel,
        line:    lineNo,
        message: "carries " + here.length + " regex literals under one marker, so a verdict on this " +
          "line cannot be attributed to a pattern. Write one literal per marked line.",
      });
      return;
    }
    if (mark[1] === MARK_GROWS) grows += 1; else flat += 1;
    entries.push({
      kind:   "planted",
      file:   rel,
      line:   lineNo,
      source: here[0].source,
      flags:  here[0].flags,
      expect: mark[1],
    });
  });

  if (grows === 0) {
    problems.push({
      file:    rel,
      message: "plants no " + MARK_GROWS + " shape, so a run of this gate proves nothing about whether the instrument can still find one.",
    });
  }
  if (flat === 0) {
    problems.push({
      file:    rel,
      message: "plants no " + MARK_FLAT + " shape, so nothing holds the thresholds away from a setting that names every pattern in the tree.",
    });
  }

  return { entries: entries, grows: grows, flat: flat };
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// The two verdicts a pattern may hold and still pass. Everything else is
// refused, including the ones that mean the instrument could not reach an
// answer: a pattern nobody managed to time is not a pattern that passed.
var PASSING_VERDICTS = ["linear", "cheap"];

function _refused(verdict) { return PASSING_VERDICTS.indexOf(verdict) === -1; }

function _outputDir(root) {
  return process.env.BLAMEPOST_REGEX_GROWTH_DIR ||
    path.join(root, ".test-output");
}

function evaluate(root, opts) {
  opts = opts || {};
  var problems = [];
  var tree = collectTree(root, problems);
  var planted = collectPlanted(root, problems);

  var entries = tree.entries.concat(planted.entries);
  var dir = _outputDir(root);
  var jobPath = path.join(dir, "regex-growth-job.json");
  var journalPath = path.join(dir, "regex-growth-journal.jsonl");

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(jobPath, JSON.stringify({ entries: entries }));

  var spawned = spawnSync(process.execPath,
    [__filename, "--measure", jobPath, "--journal", journalPath], {
      cwd:        root,
      stdio:      ["ignore", "pipe", "pipe"],
      encoding:   "utf8",
      timeout:    CHILD_CEILING_MS,
      killSignal: "SIGKILL",
      maxBuffer:  8 * 1024 * 1024,
    });

  var journal = _readJournal(journalPath, entries.length);

  if (spawned.error || spawned.signal || spawned.status !== 0) {
    var stalled = -1;
    for (var i = 0; i < entries.length; i += 1) {
      if (journal.started[i] && journal.results[i] === undefined) { stalled = i; break; }
    }
    if (stalled !== -1) {
      var e = entries[stalled];
      problems.push({
        file:    e.file,
        line:    e.line,
        message: "/" + e.source + "/" + e.flags + " did not finish a bounded measurement. The " +
          "measuring process was stopped after " + CHILD_CEILING_MS + " ms while it was on this " +
          "pattern, which is what a match that cannot be interrupted looks like from outside.",
      });
    } else {
      problems.push({
        file:    "scripts/check-regex-growth.js",
        message: "the measuring process ended without a verdict (" +
          (spawned.signal ? "killed by " + spawned.signal :
            spawned.error ? String(spawned.error && spawned.error.message) :
              "exit " + spawned.status) + "). Its output: " +
          String(spawned.stderr || "").trim().slice(0, 400),
      });
    }
  }

  var findings = [];
  var measuredTree = 0;
  var measuredPlanted = 0;
  var namedGrows = 0;
  var fallbackAlphabets = 0;
  var totalProbes = 0;
  var perPattern = [];

  entries.forEach(function (entry, index) {
    var result = journal.results[index];
    if (result === undefined) {
      if (!journal.started[index] || journal.completed) {
        findings.push({
          file:    entry.file,
          line:    entry.line,
          source:  "/" + entry.source + "/" + entry.flags,
          verdict: "unmeasured",
          why:     "the measuring process produced no reading for it, so nothing is known about how it grows",
        });
      }
      return;
    }

    totalProbes += result.probes || 0;
    if (result.alphabet && result.alphabet.derived === false) fallbackAlphabets += 1;

    if (result.measured) {
      if (entry.kind === "tree") measuredTree += 1; else measuredPlanted += 1;
    }

    perPattern.push({
      kind:    entry.kind,
      file:    entry.file,
      line:    entry.line,
      source:  "/" + entry.source + "/" + entry.flags,
      expect:  entry.expect || null,
      verdict: result.verdict,
      topLen:  result.topLen === undefined ? null : result.topLen,
      topMs:   result.topMs === undefined ? null : result.topMs,
      slope:   result.slope === undefined ? null : result.slope,
      span:      result.span === undefined ? null : result.span,
      fitPoints: result.fitPoints || 0,
      shape:     result.worst ? result.worst.label : null,
    });

    if (entry.kind === "tree") {
      if (_refused(result.verdict)) {
        findings.push({
          file:    entry.file,
          line:    entry.line,
          source:  "/" + entry.source + "/" + entry.flags,
          verdict: result.verdict,
          why:     result.why,
        });
      }
      return;
    }

    // The planted half. Both directions are held: a GROWS that is not named
    // means the instrument has stopped working, and a FLAT that IS named
    // means the thresholds have drifted down to where ordinary patterns
    // trip them, which would make every verdict over the tree worthless in
    // the other direction.
    if (entry.expect === MARK_GROWS) {
      if (result.verdict === "superlinear" || result.verdict === "over-budget") {
        namedGrows += 1;
      } else {
        findings.push({
          file:    entry.file,
          line:    entry.line,
          source:  "/" + entry.source + "/" + entry.flags,
          verdict: "self-proof",
          why:     "planted as " + MARK_GROWS + " and read as " + result.verdict +
            (result.slope === null || result.slope === undefined ? "" :
              " at slope " + Number(result.slope).toFixed(2) + " reaching " +
              Number(result.topMs).toFixed(1) + " ms at " + result.topLen + " characters") +
            ". Until the instrument names its own planted shapes, its silence over lib/ and bin/ says nothing",
        });
      }
      return;
    }

    if (_refused(result.verdict)) {
      findings.push({
        file:    entry.file,
        line:    entry.line,
        source:  "/" + entry.source + "/" + entry.flags,
        verdict: "self-proof",
        why:     "planted as " + MARK_FLAT + " and read as " + result.verdict +
          ". A threshold that names an ordinary pattern is one people learn to route around",
      });
    }
  });

  findings.sort(function (x, y) {
    if (x.file !== y.file) return x.file < y.file ? -1 : 1;
    return (x.line || 0) - (y.line || 0);
  });

  return {
    problems:          problems,
    findings:          findings,
    perPattern:        opts.detail ? perPattern : undefined,
    files:             tree.files,
    treeRead:          tree.entries.length,
    treeMeasured:      measuredTree,
    plantedRead:       planted.entries.length,
    plantedMeasured:   measuredPlanted,
    plantedGrows:      planted.grows,
    plantedFlat:       planted.flat,
    namedGrows:        namedGrows,
    fallbackAlphabets: fallbackAlphabets,
    probes:            totalProbes,
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  var opts = { root: ROOT_DEFAULT, json: false, measure: null, journal: null };
  for (var i = 0; i < argv.length; i += 1) {
    var a = argv[i];
    if (a === "--json") { opts.json = true; continue; }
    if (a === "--root") {
      i += 1;
      if (i >= argv.length) throw new TypeError("--root requires a directory path");
      opts.root = path.resolve(argv[i]);
      continue;
    }
    if (a === "--measure") {
      i += 1;
      if (i >= argv.length) throw new TypeError("--measure requires a job file path");
      opts.measure = argv[i];
      continue;
    }
    if (a === "--journal") {
      i += 1;
      if (i >= argv.length) throw new TypeError("--journal requires a file path");
      opts.journal = argv[i];
      continue;
    }
    throw new TypeError("unrecognized argument: " + a);
  }
  if (opts.measure !== null && opts.journal === null) {
    throw new TypeError("--measure requires --journal");
  }
  var stat;
  try { stat = fs.statSync(opts.root); }
  catch (_e) { throw new TypeError("--root is not a readable directory: " + _toPosix(opts.root)); }
  if (!stat.isDirectory()) throw new TypeError("--root is not a directory: " + _toPosix(opts.root));
  return opts;
}

function formatFinding(f) {
  return LABEL + f.file + (f.line ? ":" + f.line : "") +
    (f.source ? "  " + f.source : "") + "\n" +
    LABEL + "  " + f.verdict + ": " + f.why;
}

function main(argv) {
  var opts;
  try { opts = parseArgs(argv); }
  catch (e) {
    process.stderr.write(LABEL + ((e && e.message) || String(e)) + "\n");
    return 2;
  }

  if (opts.measure !== null) {
    try { return runChild(opts.measure, opts.journal); }
    catch (e) {
      process.stderr.write(LABEL + "measurement failed: " + ((e && e.message) || String(e)) + "\n");
      return 2;
    }
  }

  var res;
  try { res = evaluate(opts.root, { detail: opts.json }); }
  catch (e) {
    process.stderr.write(LABEL + ((e && e.message) || String(e)) + "\n");
    return 2;
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      thresholds: {
        slopeFloor:    SLOPE_FLOOR,
        msFloor:       MS_FLOOR,
        minFitPoints:  MIN_FIT_POINTS,
        rungBudgetMs:  RUNG_BUDGET_MS,
        rungs:         RUNGS,
        screenMax:     SCREEN_MAX,
        repeats:       REPEATS,
      },
      files:             res.files,
      treeRead:          res.treeRead,
      treeMeasured:      res.treeMeasured,
      plantedRead:       res.plantedRead,
      plantedMeasured:   res.plantedMeasured,
      plantedGrows:      res.plantedGrows,
      namedGrows:        res.namedGrows,
      fallbackAlphabets: res.fallbackAlphabets,
      probes:            res.probes,
      problems:          res.problems,
      findings:          res.findings,
      patterns:          res.perPattern || [],
    }) + "\n");
    return (res.problems.length || res.findings.length) ? 1 : 0;
  }

  SCAN_EXCLUSIONS.forEach(function (x) {
    process.stdout.write(LABEL + "not measured: " + String(x.match) + ", because " + x.reason + ".\n");
  });

  res.problems.forEach(function (p) {
    process.stderr.write(LABEL + p.file + (p.line ? ":" + p.line : "") + ": " + p.message + "\n");
  });
  res.findings.forEach(function (f) { process.stderr.write(formatFinding(f) + "\n"); });

  var bad = res.problems.length + res.findings.length;
  if (bad === 0) {
    process.stdout.write(LABEL + "OK, no pattern in " + SCAN_DIRS.join("/ or ") +
      "/ grows faster than its input.\n");
    process.stdout.write(LABEL + "measured: " + res.treeMeasured + " pattern(s) across " +
      res.files + " file(s) over " + res.probes + " timed match(es), " +
      res.fallbackAlphabets + " of them against the fallback alphabet because the pattern names " +
      "no characters of its own.\n");
    process.stdout.write(LABEL + "self-proof: " + res.namedGrows + " of " + res.plantedGrows +
      " planted growing shape(s) named, " + res.plantedFlat +
      " planted flat shape(s) left alone, at slope floor " + SLOPE_FLOOR + ".\n");
  } else {
    process.stderr.write(LABEL + bad + " pattern(s) or fixture problem(s) refused.\n");
  }

  // WHAT THE RUN EXAMINED:
  //
  //   EXAMINED <n> regex-patterns
  //   EXAMINED <n> planted-shapes
  //
  // Both, because they fail independently and each is empty in a different
  // fault. `regex-patterns` is patterns MEASURED, not patterns read: a
  // literal the scanner found and the instrument never timed is a finding
  // above and is not in this number, so the two cannot come apart in the
  // direction where a clean verdict covers a pattern nobody looked at. It
  // goes to zero when discovery breaks, which is a walk pointed at a
  // directory that moved or a scanner that stopped recognizing a literal.
  //
  // `planted-shapes` is the growing shapes the instrument NAMED out of the
  // fixture. Discovery can be perfectly healthy while the judge is not: a
  // threshold raised past every real pattern, a subject builder that
  // stopped producing the shape that hurts, a ladder that no longer climbs.
  // Every one of those leaves the first number full and takes this one to
  // zero, and a silent sweep of a tree by an instrument that cannot find a
  // planted quadratic is the pass this contract exists to refuse.
  var published = counts.publish([
    { unit: "regex-patterns", n: res.treeMeasured },
    { unit: "planted-shapes", n: res.namedGrows },
  ], { tag: LABEL });

  return (bad === 0 && published === 0) ? 0 : 1;
}

module.exports = {
  evaluate:         evaluate,
  extractLiterals:  extractLiterals,
  alphabetOf:       alphabetOf,
  shapesFor:        shapesFor,
  measurePattern:   measurePattern,
  slopeOf:          slopeOf,
  compileProbe:     compileProbe,
  SCAN_DIRS:        SCAN_DIRS,
  SCAN_EXCLUSIONS:  SCAN_EXCLUSIONS,
  PLANTED_FIXTURE:  PLANTED_FIXTURE,
  MARK_GROWS:       MARK_GROWS,
  MARK_FLAT:        MARK_FLAT,
  RUNGS:            RUNGS,
  SLOPE_FLOOR:      SLOPE_FLOOR,
  MS_FLOOR:         MS_FLOOR,
  MIN_FIT_POINTS:   MIN_FIT_POINTS,
  RUNG_BUDGET_MS:   RUNG_BUDGET_MS,
  PASSING_VERDICTS: PASSING_VERDICTS,
};

if (require.main === module) process.exit(main(process.argv.slice(2)));
