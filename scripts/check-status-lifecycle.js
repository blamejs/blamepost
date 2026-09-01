// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Drives the @status lifecycle: experimental -> stable -> deprecated. Nothing
// else forces these transitions, so this gate surfaces them on every release.
//
// Reads each @primitive block's @status + @since, computes how many releases the
// primitive has run, and enforces conscious transitions through a ledger
// (lifecycle-reviews.json):
//
//   - An `experimental` primitive older than REVIEW_AFTER releases must carry a
//     dated `keep-experimental` decision in the ledger (with a future `reviewBy`
//     version). Otherwise the gate FAILS until it is graduated to `stable` or
//     the decision is re-recorded. This is the driver: silence is not an option.
//   - A `deprecated` primitive must declare `@deprecated <remove-by-version>`,
//     and the gate FAILS once that version is reached. A deprecation that
//     outlives its own removal version is a promise the project broke.
//
// The graduation criterion: a primitive becomes `stable` once the standard it
// implements is settled AND a real client has driven it through the
// integration harness, not on a timer. The timer only forces the DECISION to
// be made and recorded.
//
// WHAT THE RUN EXAMINED is published as the last lines of every run, pass or
// fail, in the form the release battery reads:
//
//   EXAMINED <n> lib-source-files
//   EXAMINED <n> primitive-blocks
//
// This gate's whole verdict is per-primitive, so a run that parsed no primitive
// finds no transition due and prints "OK, no @status transitions overdue" while
// having pressed nothing at all. The two numbers separate the two ways to get
// there: a walk that found no source, and a walk that found source carrying no
// block. They are the same units scripts/validate-source-comment-blocks.js
// publishes, over the same walk, so a run where the two gates disagree about how
// much lib/ there is says so in one log rather than in nobody's.

var fs = require("fs");
var path = require("path");

// The one shared walk over this project's own lib sources, and the one reader
// of the `@primitive` blocks they carry. Reused here rather than reimplemented
// so a primitive documented in a nested directory is under the same lifecycle
// pressure as one at the top level, and so this gate presses on exactly the set
// the documentation gate validates. A gate with its own parse governs its own
// list, and the primitives outside it are ungoverned without saying so.
var sourcePrimitives = require("./source-primitives.js");
var libSources = sourcePrimitives.libSources;

var ROOT = path.resolve(__dirname, "..");
var LIB_DIR = path.join(ROOT, "lib");
var LEDGER_PATH = path.join(ROOT, "lifecycle-reviews.json");
var CURRENT = require(path.join(ROOT, "package.json")).version;

// Releases an experimental primitive may run before a graduation review is due.
// Pre-1.0 every ship is a patch, so "releases" is measured in patch increments.
var REVIEW_AFTER = 6;

var SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)$/;

function parseSemver(v) {
  var m = SEMVER_RE.exec(String(v || ""));
  return m ? { major: +m[1], minor: +m[2], patch: +m[3] } : null;
}

function cmpSemver(a, b) {
  var pa = parseSemver(a), pb = parseSemver(b);
  if (!pa || !pb) return NaN;
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  return pa.patch - pb.patch;
}

// Number of releases between `since` and `current`. Pre-1.0 (same major.minor)
// that is the patch delta; a minor/major bump counts as "well past review".
function releaseAge(since, current) {
  var ps = parseSemver(since), pc = parseSemver(current);
  if (!ps || !pc) return NaN;
  if (ps.major !== pc.major || ps.minor !== pc.minor) return REVIEW_AFTER + Math.max(0, pc.patch - ps.patch) + 100;
  return pc.patch - ps.patch;
}

function loadLedger() {
  if (!fs.existsSync(LEDGER_PATH)) return {};
  return JSON.parse(fs.readFileSync(LEDGER_PATH, "utf8"));
}

// Pure evaluation (exported for the test): returns { failures, reminders }.
var KNOWN_STATUSES = { experimental: 1, stable: 1, deprecated: 1 };

function evaluate(primitives, ledger, current) {
  var failures = [], reminders = [];
  primitives.forEach(function (p) {
    // Every documented primitive MUST declare a recognized @status. A missing
    // or misspelled one is not silently skipped. Otherwise deleting the tag on
    // an overdue experimental primitive would make it vanish from this gate.
    if (!p.status || !KNOWN_STATUSES[p.status]) {
      failures.push(p.token + " has a missing or unrecognized @status (" + (p.status || "none") + "). Declare @status experimental|stable|deprecated.");
      return;
    }
    if (p.status === "experimental") {
      if (!p.since) { failures.push(p.token + " is @status experimental but has no @since to age from."); return; }
      var age = releaseAge(p.since, current);
      if (isNaN(age)) { failures.push(p.token + " has an unparseable @since (" + p.since + ")."); return; }
      if (age < REVIEW_AFTER) return;
      var entry = ledger[p.token];
      // A conscious documented decision requires ALL of: keep-experimental, a
      // non-empty reason, the version it was reviewedAt, and a future reviewBy.
      // A bare { decision, reviewBy } is not a review, and must not pass the gate.
      var acknowledged = entry
        && entry.decision === "keep-experimental"
        && typeof entry.reason === "string" && entry.reason.trim().length > 0
        && entry.reviewedAt && parseSemver(entry.reviewedAt)
        && entry.reviewBy && parseSemver(entry.reviewBy) && cmpSemver(current, entry.reviewBy) < 0;
      if (!acknowledged) {
        failures.push(p.token + " has been experimental since " + p.since + " (" + age + " releases) and is due for a graduation review. Graduate it to `stable` (drop @status experimental) if its standard is settled and it is interop-proven, OR record a dated keep-experimental decision in lifecycle-reviews.json with a future reviewBy.");
      } else {
        reminders.push(p.token + " kept experimental by decision (re-review by " + entry.reviewBy + ").");
      }
    } else if (p.status === "deprecated") {
      if (!p.deprecated) { failures.push(p.token + " is @status deprecated but declares no `@deprecated <remove-by-version>`."); return; }
      if (!parseSemver(p.deprecated)) { failures.push(p.token + " @deprecated remove-by (" + p.deprecated + ") is not semver."); return; }
      if (cmpSemver(current, p.deprecated) >= 0) {
        failures.push(p.token + " is deprecated with remove-by " + p.deprecated + ", reached at " + current + ". Remove it now; the removal version was published to operators.");
      } else {
        reminders.push(p.token + " deprecated; scheduled for removal at " + p.deprecated + ".");
      }
    }
  });
  // A ledger entry for a primitive that is no longer experimental is stale noise.
  Object.keys(ledger).forEach(function (name) {
    var p = primitives.filter(function (x) { return x.token === name; })[0];
    if (!p) reminders.push("ledger entry for unknown primitive `" + name + "`. Drop it.");
    else if (p.status !== "experimental") reminders.push("ledger entry for `" + name + "` is stale (now @status " + p.status + "). Drop it.");
  });
  return { failures: failures, reminders: reminders };
}

// Last, and on every path. The verdict says whether a transition is due; these
// say how many primitives there were to press, which is the half a clean verdict
// cannot carry on its own.
function reportExamined(files, primitives) {
  console.log("EXAMINED " + files.length + " lib-source-files");
  console.log("EXAMINED " + primitives.length + " primitive-blocks");
}

function main() {
  var files = libSources(LIB_DIR);
  var primitives = sourcePrimitives.collectPrimitives(files);
  var res = evaluate(primitives, loadLedger(), CURRENT);
  res.reminders.forEach(function (r) { console.log("[status-lifecycle] note: " + r); });
  if (res.failures.length) {
    res.failures.forEach(function (r) { console.error("[status-lifecycle] DUE: " + r); });
    console.error("[status-lifecycle] " + res.failures.length + " @status transition(s) due. Graduate, deprecate, or record the decision in lifecycle-reviews.json.");
    reportExamined(files, primitives);
    process.exit(1);
  }
  console.log("[status-lifecycle] OK, no @status transitions overdue (current " + CURRENT + ").");
  reportExamined(files, primitives);
}

module.exports = { evaluate: evaluate, releaseAge: releaseAge, cmpSemver: cmpSemver, REVIEW_AFTER: REVIEW_AFTER };

if (require.main === module) main();
