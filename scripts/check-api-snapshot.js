// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/check-api-snapshot.js
 *
 * CI gate. Captures the current public surface and compares it against
 * the committed api-snapshot.json baseline. Fails on breaking changes
 * (removed members, kind changes, arity changes); logs additive changes
 * for visibility without failing.
 *
 * Two questions, over two different readings of the tree, and both are
 * needed because neither sees the other's half:
 *
 *   - The SURFACE tree is what `require("../lib/index.js")` yields, walked
 *     as exports. It answers what a consumer reaches by requiring the
 *     package, and a removed member or a changed arity fails the build.
 *   - The @since map is what the source DOCUMENTS, read out of the
 *     `@primitive` blocks. It answers which callables the project has
 *     promised an introduction version for, and it reaches the members of
 *     the handle `create()` returns, which the export walk cannot see at
 *     all because nothing instantiates the handle here. A static gate must
 *     not boot the application to find out what it ships.
 *
 * Exit codes:
 *   0  no breaking changes (additive changes printed but not failing)
 *   1  breaking changes or an @since contract violation
 *   2  script-level error (missing baseline, IO failure, etc.)
 *
 * Operators see this gate as a CI promise: removed methods or changed
 * signatures fail the build before they reach a published release.
 *
 * Usage:
 *   node scripts/check-api-snapshot.js
 */

var path = require("node:path");
var snap = require("./refresh-api-snapshot.js");
var sourcePrimitives = require("./source-primitives.js");
var blamepost = require("../lib/index.js");
var pkg  = require("../package.json");

// WHAT THE RUN EXAMINED, published as the last lines of stdout on every path
// that reaches a verdict, in the form the release battery reads:
//
//   EXAMINED <n> lib-source-files
//   EXAMINED <n> frozen-primitives
//
// Both, because they fail independently and the second is the one that was
// silently wrong. `lib-source-files` is the walk: a moved lib directory or a
// source filter that stopped matching takes it to zero and nothing below has
// anything left to read. `frozen-primitives` is the honest count of what this
// run actually COMPARED, which is the documented tokens the committed snapshot
// also holds a record for. It is deliberately not the size of either map on its
// own: a documented token the baseline never recorded is governed by no freeze,
// and counting it would report the tree as covered by exactly the record that
// is missing.
// A third unit joins them once an exported array has to SAY what kind of
// list it is: `exported-arrays` is the set that rule applies to, and it can
// reach zero on its own. A walk that stopped finding arrays would report
// every declaration as governing nothing while reporting no array as
// undeclared, and both halves of that verdict read clean.
function _publishExamined(counts) {
  console.log("EXAMINED " + counts.files + " lib-source-files");
  console.log("EXAMINED " + counts.frozen + " frozen-primitives");
  console.log("EXAMINED " + counts.arrays + " exported-arrays");
}

// One exit for every verdict that has counts to publish, so the contract
// cannot hold on the passing path and lapse on a failing one. A gate is
// expected to say what it looked at whatever its answer, because the number
// belongs beside the findings rather than only beside a pass.
function _refuse(counts, heading, violations, hint) {
  console.error("[check-api-snapshot] " + heading);
  violations.forEach(function (m) { console.error("  - " + m); });
  console.error("[check-api-snapshot] " + hint);
  _publishExamined(counts);
  process.exit(1);
}

try {
  var baselinePath = path.join(__dirname, "..", "api-snapshot.json");
  var baseline;
  try {
    baseline = snap.read(baselinePath);
  } catch (e) {
    console.error("[check-api-snapshot] baseline missing or unreadable: " +
      ((e && e.message) || String(e)));
    console.error("[check-api-snapshot] generate one with " +
      "`node scripts/refresh-api-snapshot.js` and commit it.");
    process.exit(2);
  }

  var libFiles         = sourcePrimitives.libSources();
  var sinceByPrimitive = snap.extractSince();
  var baselineSince    = baseline.sinceByPrimitive || {};
  var counts = {
    files:  libFiles.length,
    frozen: Object.keys(sinceByPrimitive).filter(function (tok) {
      return Object.prototype.hasOwnProperty.call(baselineSince, tok);
    }).length,
  };

  var current = snap.capture(blamepost, {
    packageVersion:    pkg.version,
    sinceByPrimitive:  sinceByPrimitive,
    removedPrimitives: baseline.removedPrimitives || {},
  });
  counts.arrays = snap.arrayPaths(current).length;

  // What each exported array asserts, which decides which direction of a
  // membership change takes something away. Validated before it is used: a
  // declaration is the one input here that can make the gate quieter, so a
  // stale or unreadable one is refused rather than falling through to the
  // default and reading as though it governed something. The same validation
  // refuses an array that declares NOTHING, because the default it would
  // otherwise fall to is right for one kind of list and wrong for the other.
  var membershipRecords = snap.extractMembership();
  var membershipViolations = snap.checkMembership(membershipRecords, current);
  if (membershipViolations.length > 0) {
    _refuse(counts, "@membership declaration(s) that govern nothing:", membershipViolations,
      "an @membership declaration names the exported array it governs and one of " +
      sourcePrimitives.MEMBERSHIP_POLARITIES.join(" / ") +
      "; correct the path or remove the declaration.");
  }

  var membership = sourcePrimitives.membershipMap(membershipRecords);

  // The polarity, held to the one the snapshot recorded. checkMembership
  // above asks whether every array says WHAT KIND of list it is; this asks
  // whether it still says the same thing. The word is the single input that
  // decides whether a shrinking list reads as surface lost or as a
  // limitation lifted, so re-declaring one is how a removal is made to read
  // as an improvement, and it is a one-word edit to a comment.
  //
  // A baseline that carries no record at all is refused rather than read as
  // a first run: this gate exits 2 on an absent baseline, so a snapshot that
  // is present and simply missing the field is a record that was edited, and
  // treating that as a bootstrap would unfreeze every polarity in the tree by
  // deleting one key.
  if (!baseline.membershipByArray || typeof baseline.membershipByArray !== "object") {
    _refuse(counts, "the committed snapshot records no @membership polarity:",
      ["api-snapshot.json carries no membershipByArray map, so no exported array's polarity " +
        "is frozen by anything and re-declaring one would contradict no record"],
      "regenerate the baseline with `node scripts/refresh-api-snapshot.js` and commit it.");
  }
  var polarityViolations = snap.checkMembershipFrozen(baseline.membershipByArray, membership);
  if (polarityViolations.length > 0) {
    _refuse(counts, "@membership polarity violation(s):", polarityViolations,
      "a declared polarity is immutable once shipped; a list does not change what kind of " +
      "list it is. Restore the declaration, or make the change deliberately by refreshing " +
      "the baseline so it lands in a committed diff.");
  }

  // The other direction, and the one the polarity check above cannot see. That
  // asks whether a RECORDED polarity still matches; this asks whether a
  // DECLARED one is recorded at all. A polarity declared in source and never
  // committed is governed by nothing, and a later edit of that single word
  // re-classifies every past and future change to the list with no baseline
  // entry to contradict it. Refreshing the baseline is what records it, so this
  // belongs here rather than in the refresh, which would then refuse the only
  // thing that can clear it.
  var untrackedPolarities = snap.checkMembershipUntracked(
    baseline.membershipByArray, membership);
  if (untrackedPolarities.length > 0) {
    _refuse(counts, "declared @membership polarity absent from the snapshot:",
      untrackedPolarities,
      "regenerate the baseline with `node scripts/refresh-api-snapshot.js` and commit it, so " +
      "each declared polarity is recorded and frozen.");
  }

  var diff = snap.compare(baseline, current, { membership: membership });

  console.log(snap.formatDiff(diff));

  if (diff.breaking.length > 0) {
    _refuse(counts, "BREAKING change(s) detected:", diff.breaking,
      "If intentional, regenerate the baseline with `node scripts/refresh-api-snapshot.js` " +
      "and commit it alongside the version bump the project's versioning policy calls for.");
  }

  // @since contract: a shipped primitive's introduction version is immutable
  // and never exceeds the package version. (A newly-added primitive is gated
  // against the introducing version at refresh time, where the pre-refresh
  // baseline is still on disk. See refresh-api-snapshot.js.)
  var sinceViolations = snap.checkSince(baselineSince, sinceByPrimitive, pkg.version);
  if (sinceViolations.length > 0) {
    _refuse(counts, "@since contract violation(s):", sinceViolations,
      "a shipped primitive's @since is immutable and cannot exceed the package version; " +
      "fix the source @since tag.");
  }

  // The declarations that can excuse a dropped introduction record, held to
  // the record before they are allowed to excuse anything. Each names the ONE
  // token it answers for: an introduction version is shared by every
  // primitive that shipped in a release, so a declaration matched on the
  // version alone answers for all of them, and the fix a refusal recommends
  // must never be a way to silence the rule tree-wide.
  var originatedMap  = snap.extractOriginated();
  var removalRecords = snap.extractRemovals();
  // The current export walk goes to checkRemovals, so a tombstone is held to
  // the CALLABLE and not only to the documentation beside it. Deleting a
  // @primitive block and adding an @removed line is one commit, and without
  // the surface it records a live exported callable as gone.
  var declViolations = snap
    .checkOriginatedDeclarations(originatedMap, baselineSince, sinceByPrimitive)
    .concat(snap.checkRemovals(removalRecords, baselineSince, sinceByPrimitive,
      baseline.removedPrimitives || {}, current.surface));
  if (declViolations.length > 0) {
    _refuse(counts, "removal-record violation(s):", declViolations,
      "an @originated or @removed declaration names the primitive it answers for and the " +
      "version the snapshot records for it; correct the declaration, or remove it.");
  }

  // Deleting a documented primitive's @since line must not vacate the
  // immutability freeze: every token the committed baseline records must
  // still be documented in source, or answered for by a declaration that
  // names it: @originated when the documented path moved, @removed when the
  // primitive was deleted outright. checkSince alone iterates only the
  // CURRENT map, so a deleted tag would otherwise vanish without a verdict.
  var droppedViolations = snap.checkSinceDropped(
    baselineSince, sinceByPrimitive, originatedMap, removalRecords);
  if (droppedViolations.length > 0) {
    _refuse(counts, "@since deletion violation(s):", droppedViolations,
      "restore the @since tag, declare @originated on the corrected path, or declare " +
      "@removed beside what replaced it. A shipped primitive's introduction record is " +
      "immutable, and a deletion is recorded rather than silent.");
  }

  // The other direction, and the one nothing else asks. A primitive
  // documented after the last refresh satisfies checkSince trivially, because
  // the @since a freshly written block carries IS the current package version,
  // so it passes every run while the snapshot holds no record of it. Nothing is
  // then frozen: the introduction version is whatever source says today, and
  // editing that line later changes it with no baseline entry to disagree.
  var untrackedViolations = snap.checkSinceUntracked(baselineSince, sinceByPrimitive);
  if (untrackedViolations.length > 0) {
    _refuse(counts, "documented primitive(s) missing from the snapshot:", untrackedViolations,
      "regenerate the baseline with `node scripts/refresh-api-snapshot.js` and commit it, " +
      "so every documented primitive's introduction version is recorded and frozen.");
  }

  if (diff.additive.length > 0) {
    console.log("[check-api-snapshot] " + diff.additive.length +
      " additive change(s). Refresh the baseline at the next release " +
      "(`node scripts/refresh-api-snapshot.js`) so the new surfaces are tracked.");
  }
  _publishExamined(counts);
  process.exit(0);
} catch (e) {
  console.error("[check-api-snapshot] error: " + ((e && e.stack) || e));
  process.exit(2);
}
