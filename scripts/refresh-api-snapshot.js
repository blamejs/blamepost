// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/refresh-api-snapshot.js
 *
 * Captures the public API surface of lib/index.js (namespaces, function
 * names, and arities) and writes it to api-snapshot.json at the repo root.
 *
 * The CI gate (scripts/check-api-snapshot.js) compares the live surface
 * against the committed baseline on every PR: removed members, kind
 * changes, or arity changes fail the build; additive changes are logged
 * for visibility so the baseline is refreshed at the next release.
 *
 * Run this script:
 *   - Locally before tagging a release that intentionally changes the
 *     surface (a new primitive, a renamed export, a removed method).
 *   - After every release commit so the baseline tracks the published
 *     version.
 *
 * Usage:
 *   node scripts/refresh-api-snapshot.js
 *
 * The capture / compare / read / write / formatDiff functions are also
 * exported so scripts/check-api-snapshot.js reuses the exact walk that
 * produced the baseline (one source of truth for the surface shape).
 */

var fs   = require("node:fs");
var path = require("node:path");

// The one reader of the `@primitive` documentation blocks. The since map and
// the originated map below are projections of exactly what it found, so the
// set this snapshot freezes and the set the documentation gate validates are
// the same set by construction. Two independent scans agree only while
// nobody adds a block one of them cannot see.
var sourcePrimitives = require("./source-primitives.js");

// Walk cap. The public surface is a shallow tree of namespaces holding
// functions and small data tables. A cap well above the real depth keeps
// a pathological self-referential value from spinning the walker without
// coupling the snapshot to an exact layout.
var MAX_DEPTH = 8;

// The word that turns a missing baseline from a refusal into a first run.
// Spelled here rather than at the one site that reads it, because the
// refusal names it back to the operator and the two must not drift.
var BOOTSTRAP_FLAG = "--bootstrap";

// An exported array's surface is the set of things it NAMES, so the
// descriptor records them when it can. A bare count is not a membership:
// it cannot say which member left, and a swap that keeps the count
// (`["a"]` becoming `["b"]`) reads as a surface that did not change at
// all.
//
// Only a scalar element can be compared by identity across two runs. An
// array of objects or of functions has no stable member to name, so its
// descriptor keeps the length alone and the comparison falls back to what
// a count can support. Returns null for anything not wholly scalar.
function _scalarMembers(value) {
  var out = [];
  for (var i = 0; i < value.length; i += 1) {
    var el = value[i];
    var t  = typeof el;
    if (el !== null && t !== "string" && t !== "number" && t !== "boolean") return null;
    out.push(el);
  }
  return out;
}

// Serialize one value into a stable descriptor node:
//   function  -> { kind: "function", arity: N }
//   array     -> { kind: "array", length: N, members?: [ <scalars> ] }
//   object    -> { kind: "object", members: { <sorted keys> } }
//   primitive -> { kind: <typeof> }
// `ancestors` is the set of objects on the current path. It is a cycle guard
// that still lets the same object appear under two different keys (the
// `C` / `constants` alias, for instance) rather than silently dropping
// the second reference.
function _describe(value, depth, ancestors) {
  var t = typeof value;
  if (t === "function") {
    return { kind: "function", arity: value.length };
  }
  if (value === null || t !== "object") {
    return { kind: t };
  }
  if (Array.isArray(value)) {
    var elements = _scalarMembers(value);
    return elements === null
      ? { kind: "array", length: value.length }
      : { kind: "array", length: value.length, members: elements };
  }
  if (depth >= MAX_DEPTH || ancestors.indexOf(value) !== -1) {
    // Bounded: record the shape without descending further.
    return { kind: "object", members: {} };
  }
  var nextAncestors = ancestors.concat([value]);
  var members = {};
  Object.keys(value).sort().forEach(function (k) {
    members[k] = _describe(value[k], depth + 1, nextAncestors);
  });
  return { kind: "object", members: members };
}

// Capture the whole exported surface. `rootExports` is the object returned
// by require("../lib/index.js"); `meta.packageVersion` stamps the snapshot for
// human diffing (it is NOT part of the surface comparison, and a version bump
// alone never counts as a breaking change). `meta.sinceByPrimitive` records
// each documented primitive's @since so the introduction version can be
// gated (see checkSince): a primitive's @since is immutable once shipped and
// a newly-added primitive's @since must equal the version introducing it.
function capture(rootExports, meta) {
  meta = meta || {};
  var surface = {};
  Object.keys(rootExports).sort().forEach(function (k) {
    surface[k] = _describe(rootExports[k], 0, []);
  });
  return {
    generator:        "scripts/refresh-api-snapshot.js",
    packageVersion:   meta.packageVersion || null,
    surface:          surface,
    sinceByPrimitive: meta.sinceByPrimitive || {},
    // The primitives this project has deliberately deleted, as
    // { "<token>": { since, removedIn } }. A token leaves sinceByPrimitive
    // when its block goes, and without this it would leave the record
    // altogether: nothing would then contradict a later re-add that gave the
    // same name a new introduction version. It is also what keeps the source
    // declaration checkable after the refresh that consumed it.
    removedPrimitives: meta.removedPrimitives || {},
    // What each exported array DECLARED itself to be, as
    // { "<surface path>": "capability" | "constraint" }, frozen for the same
    // reason an introduction version is frozen. The polarity decides which
    // direction of a membership change takes something away, so it is the
    // one word that can turn a loss into a gain, and until this was recorded
    // it was an unchecked self-assertion: editing `capability` to
    // `constraint` in a comment made dropping a member read as additive, and
    // no gate in the tree had an earlier value to disagree with. Recording
    // it makes a re-declaration a visible diff to this file rather than a
    // one-word edit nobody sees.
    membershipByArray: meta.membershipByArray || {},
  };
}

// Each documented primitive's introduction version, as { "<token>": "<ver>" },
// read out of the shared comment block records rather than scanned again here.
// Sourcing it from the same parse the documentation gate uses is what makes the
// documented surface and the frozen surface one set: a primitive that gets a
// block gets a freeze in the same breath, with no second pattern that has to be
// taught about it separately.
function extractSince(libDir) {
  return sourcePrimitives.tagMap(
    sourcePrimitives.collectPrimitives(sourcePrimitives.libSources(libDir)), "since");
}

// Parse a plain "X.Y.Z" version into comparable numbers. Returns null for a
// non-semver string so callers can flag it rather than mis-order it.
function _verParts(v) {
  if (typeof v !== "string" || !/^\d+\.\d+\.\d+$/.test(v)) return null;
  return v.split(".").map(Number);
}

// -1 / 0 / 1 for a<b / a==b / a>b; null if either side is un-parseable.
function _cmpVer(a, b) {
  var pa = _verParts(a), pb = _verParts(b);
  if (!pa || !pb) return null;
  for (var i = 0; i < 3; i++) { if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1; }
  return 0;
}

// Gate the @since map against the introduction-version contract. `oldMap` is
// the prior on-disk snapshot's sinceByPrimitive, which is undefined or null on
// the first run that seeds the field. In that bootstrap case the immutability
// and new-primitive checks that need a baseline are skipped, while the
// always-valid ≤ bound is still enforced.
// Returns an array of human-readable violation strings (empty = clean):
//   (a) any primitive whose @since is not valid semver or is > packageVersion
//       (a primitive cannot be introduced in a future version);
//   (b) a primitive present in both maps whose @since changed (immutable once
//       shipped);
//   (c) a primitive absent from oldMap (newly added) whose @since is not
//       exactly packageVersion (this is the registerFamily-@since-0.1.1 class).
function checkSince(oldMap, newMap, packageVersion) {
  var violations = [];
  var haveBaseline = oldMap && typeof oldMap === "object";
  Object.keys(newMap).sort().forEach(function (tok) {
    var since = newMap[tok];
    var cmp = _cmpVer(since, packageVersion);
    if (cmp === null) {
      violations.push(tok + ": @since " + JSON.stringify(since) + " is not a valid X.Y.Z version");
      return;
    }
    if (cmp > 0) {
      violations.push(tok + ": @since " + since + " is later than the package version " +
        packageVersion + " (a primitive cannot be introduced in a future version)");
    }
    if (haveBaseline && Object.prototype.hasOwnProperty.call(oldMap, tok)) {
      if (oldMap[tok] !== since) {
        violations.push(tok + ": @since changed " + oldMap[tok] + " -> " + since +
          " (a shipped primitive's introduction version is immutable)");
      }
    } else if (haveBaseline && cmp !== 0) {
      violations.push(tok + ": new primitive @since " + since + " must equal the introducing " +
        "version " + packageVersion + " (set @since to the release that adds it)");
    }
  });
  return violations;
}

// The `@membership` declarations, read from the same source walk as
// everything else here. Returns the records rather than the map, because a
// caller validating them needs the file and line to point at and a caller
// classifying a diff needs only the map, which membershipMap projects.
function extractMembership(libDir) {
  return sourcePrimitives.collectMembership(sourcePrimitives.libSources(libDir));
}

// The `@removed` declarations, read from the same walk. Records rather than a
// map, for the same reason: a refusal has to point at the line that wrote it.
function extractRemovals(libDir) {
  return sourcePrimitives.collectRemovals(sourcePrimitives.libSources(libDir));
}

// A DECLARATION that answers for a token other than the one it sits on:
// `@originated <token> <version>` on a corrected documentation path, and
// `@removed <token> <version>` beside whatever replaced a deleted primitive.
// Both halves of the value are load-bearing.
//
// The TOKEN is what makes a declaration answer for one primitive. Matching on
// the version alone was the defect this shape replaces: an introduction
// version is shared by every primitive that shipped in that release, so one
// declaration anywhere in lib/ satisfied the check for all of them and for
// every later drop at that version. The remedy the refusal recommended was
// therefore a tree-wide off switch for the rule printing it.
//
// The VERSION is what keeps the declaration honest about which record it
// carries forward. A token named at a version the snapshot disagrees with is
// a record being rewritten rather than preserved.
var DECLARED_TOKEN_RE = /^([A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*)\s+(\d+\.\d+\.\d+)$/;

function _parseDeclaredToken(value) {
  var text = value === null || value === undefined ? "" : String(value);
  var m = DECLARED_TOKEN_RE.exec(text.trim());
  return m ? { token: m[1], version: m[2] } : null;
}

// The tokens the `@originated` declarations answer for, as
// { "<named token>": { version, by } }. A value that does not read as a token
// and a version answers for nothing here and is reported by name in
// checkOriginatedDeclarations, so an unreadable declaration cannot fall
// through into an excuse.
function _originatedIndex(originatedMap) {
  var out = {};
  Object.keys(originatedMap || {}).sort().forEach(function (by) {
    var p = _parseDeclaredToken(originatedMap[by]);
    if (p && !Object.prototype.hasOwnProperty.call(out, p.token)) {
      out[p.token] = { version: p.version, by: by };
    }
  });
  return out;
}

// The root name every documented token is written under. It is the package's
// own name in the documentation rather than a path, so it is stripped before
// a token is resolved against the captured surface tree.
var TOKEN_ROOT = "blamepost.";

/**
 * resolvesInSurface(surface, token) says whether the EXPORT WALK still
 * reaches the callable a documented token names.
 *
 * It answers in ONE DIRECTION only, and the asymmetry is the whole point.
 * TRUE means the token is definitely still shipping: requiring the package
 * yields it, so any record saying it is gone is contradicted by the tree
 * itself. FALSE means only that the export walk cannot see it, which is
 * equally true of every primitive reachable through the handle `create()`
 * returns, and a static gate must not boot the application to find out
 * which. So a false is never read as proof of absence and nothing refuses
 * on one.
 */
function resolvesInSurface(surface, token) {
  var name = String(token === null || token === undefined ? "" : token);
  if (name.indexOf(TOKEN_ROOT) !== 0) return false;
  var parts = name.slice(TOKEN_ROOT.length).split(".");
  if (parts.length === 0 || parts[0] === "") return false;
  var node = (surface || {})[parts[0]];
  for (var i = 1; i < parts.length; i += 1) {
    if (!node || node.kind !== "object") return false;
    node = (node.members || {})[parts[i]];
  }
  return node !== undefined;
}

// The same index over the `@removed` records the source reader produces.
function _removalIndex(removals) {
  var out = {};
  (removals || []).forEach(function (r) {
    if (r && r.token && !Object.prototype.hasOwnProperty.call(out, r.token)) {
      out[r.token] = { version: r.version, file: r.file, line: r.line };
    }
  });
  return out;
}

// Whether some declaration answers for `tok` at the version the record holds.
// The two tags are read identically here on purpose: they differ in what they
// ASSERT about the callable, not in how specifically they have to name it.
function _excused(tok, recordedVersion, orig, tomb) {
  var o = orig[tok];
  if (o && o.version === recordedVersion) return true;
  var r = tomb[tok];
  return !!(r && r.version === recordedVersion);
}

// What an author is told when a documented introduction record disappears.
// All three true answers, because the old refusal named two and one of them
// was false for a deletion, which left reaching for the false one as the only
// way to make the gate stop talking.
function _droppedRefusal(tok, version) {
  return tok + ": documented @since " + version + " was removed from source (a shipped " +
    "primitive's introduction record cannot be deleted). If the block is still there, restore " +
    "the tag. If its documented PATH was corrected, declare `@originated " + tok + " " +
    version + "` on the block that replaces it. If the primitive was deleted outright, declare " +
    "`@removed " + tok + " " + version + "` beside what replaced it. Each names this token, so " +
    "none of them answers for anything else.";
}

// The @originated map, mirroring extractSince and read from the same records.
// @originated records the earlier version a callable was already reachable at,
// when the documented path naming it was later corrected. Returns
// { "<token>": "<ver>" } for the primitives that declare it.
function extractOriginated(libDir) {
  return sourcePrimitives.tagMap(
    sourcePrimitives.collectPrimitives(sourcePrimitives.libSources(libDir)), "originated");
}

// Enforce the @originated contract: when a documented @primitive path is REMOVED
// from the since-map while the exported SURFACE is unchanged, the removal is
// either a documentation-path CORRECTION (the callable still ships) or a
// deliberate DELETION whose callable never reached the export walk, and either
// way the origin version must not be lost. Some declaration must name the token.
// `surfaceUnchanged` is compare(old,new) reporting zero breaking + zero additive.
// A real surface change is governed by the breaking-change flow, not this gate.
// Returns human-readable violation strings (empty = clean).
function checkOriginated(oldSince, newSince, originatedMap, removals, surfaceUnchanged) {
  if (!oldSince || !surfaceUnchanged) return [];
  var orig = _originatedIndex(originatedMap);
  var tomb = _removalIndex(removals);
  var violations = [];
  Object.keys(oldSince).sort().forEach(function (tok) {
    if (Object.prototype.hasOwnProperty.call(newSince, tok)) return;   // still documented
    if (_excused(tok, oldSince[tok], orig, tomb)) return;              // answered for, by name
    violations.push(_droppedRefusal(tok, oldSince[tok]) +
      " The exported surface did not change, so nothing else in this run records that this " +
      "primitive went.");
  });
  return violations;
}

// Gate against silent deletion of a documented primitive's introduction
// record: every token in the prior map must still be present in the new map,
// or answered for by a declaration that NAMES it: `@originated` when the
// documented path was corrected, `@removed` when the primitive was deleted.
// Deleting the @since line would otherwise vacate the immutability freeze for
// that primitive, letting a later re-add pass the new-primitive check with a
// rewritten introduction version.
// Returns human-readable violation strings (empty = clean).
function checkSinceDropped(oldMap, newMap, originatedMap, removals) {
  if (!oldMap || typeof oldMap !== "object") return [];
  var orig = _originatedIndex(originatedMap);
  var tomb = _removalIndex(removals);
  var violations = [];
  Object.keys(oldMap).sort().forEach(function (tok) {
    if (Object.prototype.hasOwnProperty.call(newMap, tok)) return;   // still documented
    if (_excused(tok, oldMap[tok], orig, tomb)) return;              // answered for, by name
    violations.push(_droppedRefusal(tok, oldMap[tok]));
  });
  return violations;
}

/**
 * checkOriginatedDeclarations holds the `@originated` declarations to the
 * record, the way checkMembership holds `@membership` to the surface.
 *
 * A declaration is the one input here that can make the gate quieter, so it
 * has to name something the record holds, say something the reader can parse,
 * and there may only be one of it per token. Each of the three is a way a
 * declaration outlives what it was written about, and the first is the one
 * with no verdict of its own: an unreadable value excuses nothing while its
 * author believes it is in force.
 *
 * Returns human-readable violation strings (empty = clean).
 */
function checkOriginatedDeclarations(originatedMap, oldSince, newSince) {
  var violations = [];
  var seen  = {};
  var since = oldSince || {};

  Object.keys(originatedMap || {}).sort().forEach(function (by) {
    var raw = originatedMap[by];
    var p   = _parseDeclaredToken(raw);
    if (!p) {
      violations.push(by + ": @originated " + JSON.stringify(raw) + " does not read as " +
        "`<token> <X.Y.Z>`, so it names no primitive and preserves no origin. A version on " +
        "its own would answer for every primitive that shipped in that release.");
      return;
    }
    if (Object.prototype.hasOwnProperty.call(seen, p.token)) {
      violations.push(p.token + ": named by @originated on more than one primitive (" +
        seen[p.token] + " and " + by + "), so two blocks claim one origin");
      return;
    }
    seen[p.token] = by;

    if (Object.prototype.hasOwnProperty.call(newSince || {}, p.token)) {
      violations.push(by + ": @originated names " + p.token + ", which is still documented " +
        "as a @primitive, so no path was corrected and the declaration governs nothing");
      return;
    }
    if (!Object.prototype.hasOwnProperty.call(since, p.token)) {
      violations.push(by + ": @originated names " + p.token + ", for which the committed " +
        "snapshot holds no introduction record, so the declaration governs nothing");
      return;
    }
    if (since[p.token] !== p.version) {
      violations.push(by + ": @originated " + p.token + " " + p.version + " but the snapshot " +
        "records " + since[p.token] + " as the version that token shipped at");
    }
  });

  return violations;
}

/**
 * checkRemovals holds the `@removed` declarations to the record, in both
 * directions.
 *
 * FORWARD: a tombstone names a token the record actually holds, at the
 * version it holds for it, that is not still documented as a `@primitive`,
 * that the export walk no longer reaches, and there is exactly one of it. An
 * unreadable value is refused rather than skipped, because a declaration
 * nothing reads is one the author believes is in force.
 *
 * STILL DOCUMENTED and STILL SHIPPING are two questions, and answering the
 * first says nothing about the second. A commit that DELETES the
 * `@primitive` block and adds an `@removed` line beside it satisfies the
 * documentation question trivially: the block is gone, so nothing
 * contradicts the record. The callable is
 * still exported and still callable, and the frozen surface now says it is
 * gone. Every later change to it is then governed by a record that has
 * already written it off. Measured on this tree, `blamepost.resolver` was
 * declarable removed with zero findings from every gate.
 *
 * REVERSE: every removal the snapshot records still carries its declaration
 * in source. The snapshot is the durable half of this record and nobody reads
 * it; the sentence beside the code is the half a maintainer meets. Letting
 * that half be deleted returns the removal to being silent, which is the
 * thing the record exists to prevent.
 *
 * WHAT NEITHER DIRECTION REACHES, stated here so the next reader does not
 * spend the afternoon rediscovering it. The two directions are a PAIR check:
 * each half refuses the deletion of the other. Deleting BOTH in one commit,
 * the source `@removed` line and the `removedPrimitives` entry together,
 * passes every gate, because the working tree it leaves behind is
 * byte-identical to a tree where the removal never happened. No static check
 * over a checkout can tell those apart: distinguishing them needs the
 * previous commit, and every anchor that could hold the earlier value lives
 * in the same generated file the deletion edits.
 *
 * So it is not closed here, and it is not left to luck either. The doors
 * that made it easy are shut: a refresh refuses to mint a snapshot over an
 * absent baseline (see BOOTSTRAP_FLAG), so the record cannot be reset by
 * deleting a file and re-running the tool, and both halves surviving means a
 * deliberate hand-edit of a generated artifact. That edit is visible in a
 * branch diff, which is where `codex review --base main` reads, and it is
 * the one review that sees deleted lines at all.
 *
 * `oldSince` is the committed snapshot's introduction map, `newSince` what
 * source documents today, `priorRemovals` the snapshot's own record of what
 * has already been removed, which is where a token lives once the refresh
 * that recorded it has dropped it from the since map, and `surface` the
 * CURRENT captured export tree, against which a tombstone is held to the
 * callable rather than only to the documentation.
 *
 * `surface` is optional and its absence only makes this quieter, so every
 * caller that has one passes it. It is deliberately not required: the pure
 * vectors that drive this checker are about the record, and a checker that
 * refused to answer without an export walk would make them build one.
 *
 * Returns human-readable violation strings (empty = clean).
 */
function checkRemovals(records, oldSince, newSince, priorRemovals, surface) {
  var violations = [];
  var seen       = {};
  var recorded   = priorRemovals || {};
  var since      = oldSince || {};
  var documented = newSince || {};

  (records || []).forEach(function (r) {
    var where = " (" + r.file + ":" + r.line + ")";

    if (!r.token || !r.version) {
      violations.push("@removed " + JSON.stringify(r.value) + " does not read as " +
        "`<token> <X.Y.Z>`, so it names no primitive and records no removal" + where);
      return;
    }
    if (Object.prototype.hasOwnProperty.call(seen, r.token)) {
      violations.push(r.token + ": declared @removed more than once, so two records answer " +
        "for one removal" + where);
      return;
    }
    seen[r.token] = true;

    if (Object.prototype.hasOwnProperty.call(documented, r.token)) {
      violations.push(r.token + ": declared @removed while it is still documented as a " +
        "@primitive in source, so the record contradicts the block beside it" + where);
      return;
    }

    // The other half of the same question, and the half nothing asked. A
    // tombstone is a statement about the CALLABLE, not about the paragraph
    // above it: deleting the documentation does not remove anything, and a
    // record that a primitive is gone while requiring the package still
    // yields it is simply false. Only a true resolution refuses, because the
    // export walk cannot see a handle member and a false says nothing.
    if (resolvesInSurface(surface, r.token)) {
      violations.push(r.token + ": declared @removed while the export walk still reaches it, " +
        "so the record says this primitive is gone and requiring the package still yields it. " +
        "A removal is recorded when the callable goes, not when its documentation does: delete " +
        "the export, or restore the @primitive block and drop the declaration" + where);
      return;
    }

    var known = Object.prototype.hasOwnProperty.call(since, r.token)
      ? since[r.token]
      : (recorded[r.token] && recorded[r.token].since);
    if (!known) {
      violations.push(r.token + ": @removed names no primitive the committed snapshot ever " +
        "recorded an introduction version for, so the declaration governs nothing" + where);
      return;
    }
    if (known !== r.version) {
      violations.push(r.token + ": @removed " + r.version + " but the snapshot records " +
        known + " as the version it shipped at" + where);
    }
  });

  Object.keys(recorded).sort().forEach(function (tok) {
    if (Object.prototype.hasOwnProperty.call(seen, tok)) return;
    violations.push(tok + ": the snapshot records this primitive as removed in " +
      ((recorded[tok] && recorded[tok].removedIn) || "an earlier release") + ", but source " +
      "carries no @removed declaration for it, so the sentence explaining the removal is gone " +
      "from the place a maintainer reads");
  });

  return violations;
}

// The removals this refresh should record, which is everything already
// recorded plus every declaration answering for a token leaving the since map
// on this run. Prior entries are carried through byte-identical: the version a
// removal was made in is as immutable as the version a primitive arrived in.
function nextRemovals(records, oldSince, newSince, priorRemovals, packageVersion) {
  var out = {};
  var prior = priorRemovals || {};
  Object.keys(prior).sort().forEach(function (tok) { out[tok] = prior[tok]; });

  (records || []).forEach(function (r) {
    if (!r.token || !r.version) return;
    if (Object.prototype.hasOwnProperty.call(out, r.token)) return;
    if (Object.prototype.hasOwnProperty.call(newSince || {}, r.token)) return;
    if (!Object.prototype.hasOwnProperty.call(oldSince || {}, r.token)) return;
    out[r.token] = { since: r.version, removedIn: packageVersion };
  });

  var sorted = {};
  Object.keys(out).sort().forEach(function (tok) { sorted[tok] = out[tok]; });
  return sorted;
}

// The mirror of checkSinceDropped, and the direction that was missing. That one
// asks whether every FROZEN token is still documented; this one asks whether
// every DOCUMENTED token is frozen. Without it a primitive documented after the
// last refresh is governed by nothing: checkSince walks the current map and is
// satisfied by an @since equal to the package version, which is what a
// just-written block carries, so the token passes every run without ever being
// recorded. Its introduction version is then whatever source says today, and a
// later edit of that line changes it with no baseline entry to contradict.
// Returns human-readable violation strings (empty = clean).
function checkSinceUntracked(oldMap, newMap) {
  if (!oldMap || typeof oldMap !== "object") return [];
  var violations = [];
  Object.keys(newMap).sort().forEach(function (tok) {
    if (Object.prototype.hasOwnProperty.call(oldMap, tok)) return;
    violations.push(tok + ": documented with @since " + newMap[tok] + " but absent from the " +
      "committed snapshot, so its introduction version is frozen by nothing");
  });
  return violations;
}

// Compare two captured snapshots. Only the `surface` tree is compared, and
// packageVersion drift is ignored on purpose. Returns:
//   { breaking: [ "<path>: <reason>" ], additive: [ "<path>: added" ] }
// A removed member, a kind change, or a function-arity change is breaking;
// a newly-present member is additive.
//
// `opts.membership` is { "<surface path>": "capability" | "constraint" },
// read from the `@membership` declarations in source. It decides which
// DIRECTION of a membership change takes something away, for the tables
// that say so; a table absent from the map is read as a capability list,
// which is the strict reading.
function compare(baseline, current, opts) {
  var breaking = [];
  var additive = [];
  _diffNode("blamepost", (baseline && baseline.surface) || {},
    (current && current.surface) || {}, breaking, additive, true,
    (opts && opts.membership) || {});
  return { breaking: breaking, additive: additive };
}

// The polarity governing one surface path, defaulting to the strict
// reading. Undeclared means "every member is something this package
// offers", so losing one is breaking. A table only becomes lenient in one
// direction by SAYING it is that kind of table.
function _polarityFor(membership, surfacePath) {
  var declared = membership && membership[surfacePath];
  return declared === "constraint" ? "constraint" : "capability";
}

/**
 * _diffArray classifies a change to an exported array.
 *
 * The rule this replaces read the direction of the length: shorter meant
 * members were removed and therefore breaking, longer meant additive. That
 * is sound for a list of things the package OFFERS and exactly inverted for
 * a list of things it REQUIRES or admits it cannot do, and the two are
 * indistinguishable from a count. Both misreadings have been seen on this
 * tree: a list of required handle methods reported as breaking when a
 * requirement MOVED to a sibling list, and a list of the listeners a
 * certificate rotation could not reach reported as breaking when the last
 * entry was FIXED and the list emptied. In the second case the gate
 * reported the removal of a defect as a removal of surface.
 *
 * So the direction is not inferred. The membership is compared member by
 * member, and which direction takes something away comes from what the
 * table declares itself to be.
 */
function _diffArray(surfacePath, b, c, breaking, additive, membership) {
  var polarity   = _polarityFor(membership, surfacePath);
  var hadMembers = Array.isArray(b.members);
  var hasMembers = Array.isArray(c.members);

  // A MEMBERSHIP LIST THAT DISAPPEARED, which is the one edit that removes
  // the ability to see any of the above and that nothing else here reports.
  // `_scalarMembers` returns null for an array that is not wholly
  // scalar, so the descriptor falls back to a length; the length rule below
  // then returns silently whenever the two lengths agree. Without this
  // branch, rewriting one of the exported arrays from strings to objects
  // reports ZERO findings, the refresh freezes a length-only descriptor,
  // and from that commit onward every same-length membership change to
  // that array is invisible forever. An array that never had a members
  // list is a different case and is not this one: what is refused here is
  // a list that HAD one and lost it.
  //
  // It is breaking whatever the polarity says, and the polarity is not
  // consulted. Polarity decides which DIRECTION of a membership change takes
  // something away; this is not a change of membership but a change of what
  // the elements ARE, and the only way a scalar array stops being scalar is
  // that every consumer indexing it now gets something of another type.
  if (hadMembers && !hasMembers) {
    breaking.push(surfacePath + ": membership list lost (" + b.members.length +
      " named member(s) -> length only, length " + b.length + " -> " + c.length +
      "). The elements stopped being comparable by identity, so every consumer reading " +
      "them by value gets something of another type, and no later change to this array's " +
      "membership can be seen again.");
    return;
  }

  // The other direction: an array that could not be named and now can. Not a
  // loss, and reported so the refresh records the members rather than
  // freezing another length. The length rule still runs underneath, because
  // a length is all the baseline supports.
  if (!hadMembers && hasMembers) {
    additive.push(surfacePath + ": membership became comparable (length-only baseline -> " +
      c.members.length + " named member(s))");
  }

  // A descriptor written before members were recorded, or an array whose
  // elements are not comparable by identity. The count is all there is, so
  // the count is all that is claimed. It is still classified by polarity
  // rather than by the assumption that shorter means worse.
  if (!hadMembers || !hasMembers) {
    if (b.length === c.length) return;
    var shrank  = c.length < b.length;
    var lengthMsg = surfacePath + ": array length changed (" + b.length + " -> " + c.length + ")";
    if (polarity === "constraint") {
      (shrank ? additive : breaking).push(lengthMsg +
        (shrank ? " — a declared constraint list got shorter, so a limitation was lifted"
                : " — a declared constraint list got longer, so a limitation was imposed"));
    } else {
      (shrank ? breaking : additive).push(lengthMsg);
    }
    return;
  }

  var removed = b.members.filter(function (m) { return c.members.indexOf(m) === -1; });
  var added   = c.members.filter(function (m) { return b.members.indexOf(m) === -1; });
  if (removed.length === 0 && added.length === 0) return;   // a reorder is not a change of membership

  function _render(verb, names) {
    return surfacePath + ": " + verb + " " + JSON.stringify(names);
  }

  if (polarity === "constraint") {
    // Growing a constraint list takes something away: a requirement a
    // caller did not have to meet, or a limitation that did not apply.
    if (added.length > 0) {
      breaking.push(_render("constraint(s) imposed", added) +
        " (a declared constraint list, so growth is what takes something away)");
    }
    if (removed.length > 0) {
      additive.push(_render("constraint(s) lifted", removed));
    }
    return;
  }

  if (removed.length > 0) breaking.push(_render("member(s) removed", removed));
  if (added.length   > 0) additive.push(_render("member(s) added", added));
}

// `isRoot` distinguishes the top-level namespace map (whose entries are
// keyed directly) from an object node (whose entries live under `.members`).
function _diffNode(pathPrefix, baseNode, curNode, breaking, additive, isRoot, membership) {
  var baseMembers = isRoot ? baseNode : ((baseNode && baseNode.members) || {});
  var curMembers  = isRoot ? curNode  : ((curNode  && curNode.members)  || {});

  Object.keys(baseMembers).forEach(function (k) {
    var childPath = pathPrefix + "." + k;
    var b = baseMembers[k];
    var c = curMembers[k];
    if (!Object.prototype.hasOwnProperty.call(curMembers, k) || c === undefined) {
      breaking.push(childPath + ": removed");
      return;
    }
    if (b.kind !== c.kind) {
      breaking.push(childPath + ": kind changed (" + b.kind + " -> " + c.kind + ")");
      return;
    }
    if (b.kind === "function" && b.arity !== c.arity) {
      breaking.push(childPath + ": arity changed (" + b.arity + " -> " + c.arity + ")");
    }
    // An exported array's membership is part of the surface. Which
    // direction of a change takes something away is a property of what the
    // table asserts, not of the count, so the classification is delegated.
    if (b.kind === "array") {
      _diffArray(childPath, b, c, breaking, additive, membership);
    }
    if (b.kind === "object") {
      _diffNode(childPath, b, c, breaking, additive, false, membership);
    }
  });

  Object.keys(curMembers).forEach(function (k) {
    if (!Object.prototype.hasOwnProperty.call(baseMembers, k)) {
      additive.push(pathPrefix + "." + k + ": added");
    }
  });
}

// Every dotted path in a captured snapshot whose descriptor is an array,
// used to hold the `@membership` declarations against the surface they
// claim to govern.
function arrayPaths(snapshot) {
  var out = [];
  (function walk(prefix, members) {
    Object.keys(members || {}).forEach(function (k) {
      var node = members[k];
      if (!node || typeof node !== "object") return;
      var here = prefix + "." + k;
      if (node.kind === "array")  out.push(here);
      if (node.kind === "object") walk(here, node.members);
    });
  }("blamepost", (snapshot && snapshot.surface) || {}));
  return out.sort();
}

/**
 * checkMembership(records, snapshot) holds the `@membership` declarations
 * to the surface.
 *
 * A declaration is a standing instruction to read one direction of a
 * membership change as harmless, so it is the one thing here that can make
 * the gate quieter. That earns it the same treatment the static-gate
 * exemptions get: it has to name something that exists, it has to say
 * something the reader understands, and there may only be one of it.
 *
 * Each of the three is a way a declaration outlives what it was written
 * about. A path that no longer names an array is a rename or a deletion
 * that left its license behind. An unrecognized polarity would otherwise
 * fall through to the default and read as governing when it governs
 * nothing. Two declarations for one path is two answers with no rule for
 * picking between them.
 *
 * The fourth rule reads the first one backwards: an exported array that
 * NOTHING declares. The strict default is the right default and it is not a
 * license to leave the question unanswered, because it is only right for one
 * of the two kinds of list. Measured on this tree while every array was
 * undeclared, it classified one list correctly and two incorrectly, and the
 * two it got wrong were requirement lists that had GROWN: a handle the
 * package stops accepting, reported as a capability gained. A default
 * that is right by luck is not a rule anybody chose, so
 * the array says what kind it is or the gate refuses to classify it.
 *
 * Returns human-readable violation strings (empty = clean).
 */
function checkMembership(records, snapshot) {
  var violations = [];
  var known      = arrayPaths(snapshot);
  var seen       = {};

  (records || []).forEach(function (r) {
    var where = " (" + r.file + ":" + r.line + ")";

    if (sourcePrimitives.MEMBERSHIP_POLARITIES.indexOf(r.polarity) === -1) {
      violations.push(r.path + ": @membership " + JSON.stringify(r.polarity) +
        " is not one of " + sourcePrimitives.MEMBERSHIP_POLARITIES.join(", ") + where);
    }
    if (Object.prototype.hasOwnProperty.call(seen, r.path)) {
      violations.push(r.path + ": declared @membership more than once, so two " +
        "declarations govern one table" + where);
    }
    seen[r.path] = true;
    if (known.indexOf(r.path) === -1) {
      violations.push(r.path + ": @membership names no exported array in the current " +
        "surface, so the declaration governs nothing" + where);
    }
  });

  known.forEach(function (p) {
    if (Object.prototype.hasOwnProperty.call(seen, p)) return;
    violations.push(p + ": exported array with no @membership declaration, so which " +
      "direction of a change to it takes something away is decided by a default rather " +
      "than by anybody. Declare it `capability` when the members are things this package " +
      "offers, or `constraint` when they are things it requires or cannot yet do.");
  });

  return violations;
}

/**
 * checkMembershipFrozen(oldMap, newMap) holds a declared polarity to the one
 * the committed snapshot recorded.
 *
 * `checkMembership` already refuses a declaration that names no array and an
 * array that declares nothing, so every exported array says what kind of
 * list it is. What neither of them asks is whether it still says the same
 * thing it said last time. The polarity is the single word deciding whether
 * a shrinking list reads as surface lost or as a limitation lifted, so
 * flipping it is how a removal is made to read as an improvement, and it is
 * a one-word edit to a comment. `RATE_LIMIT_KEYS` is this tree's only
 * `capability` list: re-declaring it a constraint would have made dropping a
 * rate-limit key report as additive, and nothing anywhere held a prior value
 * to contradict it.
 *
 * Two directions, the same reasoning the `@since` freeze uses:
 *
 *   CHANGED. A polarity the snapshot records and source now spells
 *   differently. Immutable once shipped; a genuine correction is made by
 *   refreshing the baseline, which puts the change in a committed diff where
 *   it is read rather than in a comment where it is not.
 *
 *   UNTRACKED. An array declaring a polarity the snapshot never recorded, so
 *   it is frozen by nothing and the first value it is given is whatever
 *   source says on the day somebody looks. The same hole `checkSinceUntracked`
 *   closed for introduction versions.
 *
 * An absent `oldMap` is the bootstrap and reports nothing; the gate refuses a
 * missing baseline earlier and with its own message.
 *
 * Returns human-readable violation strings (empty = clean).
 */
function checkMembershipFrozen(oldMap, newMap) {
  if (!oldMap || typeof oldMap !== "object") return [];
  var violations = [];
  var current = newMap || {};
  Object.keys(current).sort().forEach(function (p) {
    if (!Object.prototype.hasOwnProperty.call(oldMap, p)) {
      violations.push(p + ": declared @membership " + current[p] + " but absent from the " +
        "committed snapshot, so which direction of a change to it takes something away is " +
        "frozen by nothing");
      return;
    }
    if (oldMap[p] !== current[p]) {
      violations.push(p + ": @membership changed " + oldMap[p] + " -> " + current[p] +
        " (a declared polarity is immutable once shipped: it decides whether shrinking this " +
        "list reads as surface lost or as a limitation lifted, so changing it re-classifies " +
        "every past and future change to it)");
    }
  });
  return violations;
}

function formatDiff(diff) {
  var lines = [];
  if (diff.breaking.length === 0 && diff.additive.length === 0) {
    return "[api-snapshot] surface unchanged.";
  }
  if (diff.breaking.length > 0) {
    lines.push("[api-snapshot] BREAKING (" + diff.breaking.length + "):");
    diff.breaking.forEach(function (m) { lines.push("  - " + m); });
  }
  if (diff.additive.length > 0) {
    lines.push("[api-snapshot] additive (" + diff.additive.length + "):");
    diff.additive.forEach(function (m) { lines.push("  + " + m); });
  }
  return lines.join("\n");
}

function read(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

// Read the committed baseline, distinguishing "absent" from "unreadable":
// only ENOENT bootstraps (returns null). A corrupted or merge-conflicted
// baseline rethrows so the @since / @originated gates never degrade to
// first-run mode and overwrite the record they exist to protect.
function readBaselineIfPresent(p) {
  try {
    return read(p);
  } catch (e) {
    if (e && e.code === "ENOENT") return null;
    throw e;
  }
}

function write(snapshot, p) {
  fs.writeFileSync(p, JSON.stringify(snapshot, null, 2) + "\n");
}

module.exports = {
  capture:      capture,
  compare:      compare,
  formatDiff:   formatDiff,
  extractSince: extractSince,
  checkSince:   checkSince,
  checkSinceDropped:   checkSinceDropped,
  checkSinceUntracked: checkSinceUntracked,
  extractOriginated: extractOriginated,
  checkOriginated:   checkOriginated,
  checkOriginatedDeclarations: checkOriginatedDeclarations,
  arrayPaths:        arrayPaths,
  extractMembership: extractMembership,
  checkMembership:   checkMembership,
  checkMembershipFrozen: checkMembershipFrozen,
  extractRemovals:   extractRemovals,
  checkRemovals:     checkRemovals,
  nextRemovals:      nextRemovals,
  resolvesInSurface: resolvesInSurface,
  TOKEN_ROOT:        TOKEN_ROOT,
  read:         read,
  readBaselineIfPresent: readBaselineIfPresent,
  write:        write,
};

if (require.main === module) {
  var blamepost = require("../lib/index.js");
  var pkg = require("../package.json");
  var outPath = path.join(__dirname, "..", "api-snapshot.json");
  var sinceByPrimitive = extractSince();

  // Gate @since against the prior on-disk snapshot BEFORE overwriting it.
  // This is the only point where "what existed before this refresh" is still
  // readable, so a newly-added primitive with the wrong introduction version
  // (or a mutated @since) is refused here rather than silently baked in.
  var prior = readBaselineIfPresent(outPath);   // null ONLY when genuinely absent

  // AN ABSENT BASELINE IS A REFUSAL, not a bootstrap.
  //
  // Every gate in this file compares source against the committed record,
  // and every one of them treats a null baseline as the first run and
  // reports nothing: the immutability freeze, the dropped-record refusal,
  // the untracked-primitive refusal, the removal record, the polarity
  // freeze. So `rm api-snapshot.json` followed by a refresh re-mints all of
  // them from whatever source happens to say that day, silently, and
  // announces it in one line of stdout that reads exactly like an ordinary
  // refresh. Measured on this tree, that is 118 frozen introduction versions
  // and one recorded removal re-derived with nothing left to disagree.
  //
  // A genuinely new snapshot still has to be creatable, so the bootstrap is
  // a thing somebody TYPES rather than a state the tool infers from a
  // missing file. Deleting a file is not a declaration; passing the flag is.
  if (prior === null && process.argv.indexOf(BOOTSTRAP_FLAG) === -1) {
    process.stderr.write("[refresh-api-snapshot] no committed baseline at " + outPath + ".\n");
    process.stderr.write("[refresh-api-snapshot] refusing to mint one. Every record this file " +
      "freezes is checked against that baseline, so writing a fresh snapshot over its absence " +
      "re-derives all of them from whatever source says today and contradicts nothing: " +
      "introduction versions, the removal record, and the @membership polarities all reset " +
      "at once.\n");
    process.stderr.write("[refresh-api-snapshot] if the baseline was deleted, restore it " +
      "(`git checkout -- api-snapshot.json`). If this repository genuinely has no snapshot " +
      "yet, say so: `node scripts/refresh-api-snapshot.js " + BOOTSTRAP_FLAG + "`.\n");
    process.exit(2);
  }
  if (prior === null) {
    process.stdout.write("[refresh-api-snapshot] " + BOOTSTRAP_FLAG + ": minting a first " +
      "snapshot. " + Object.keys(sinceByPrimitive).length + " introduction version(s) are " +
      "being recorded from source with no baseline to check them against.\n");
  }

  var sinceViolations = checkSince(prior && prior.sinceByPrimitive, sinceByPrimitive, pkg.version);
  if (sinceViolations.length > 0) {
    process.stderr.write("[refresh-api-snapshot] @since violations (fix the source @since tags):\n");
    sinceViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
    process.exit(2);
  }

  // The same deletion contract the gate enforces, enforced here too.
  //
  // checkSince above walks the CURRENT map, so it cannot see a token that
  // left it: a documented @since deleted from source satisfies it by not
  // being there. check-api-snapshot.js calls checkSinceDropped for exactly
  // that reason, and this path calls it for the same one: without it the
  // freeze carries a hole in the shape of the one command that rewrites
  // the record. A refresh whose surface ALSO changed skips the @originated
  // gate below, because that one only speaks when the surface is
  // unchanged, and would then write a baseline with the token simply
  // missing. Nothing fails and nothing prints; the primitive's
  // introduction version is frozen by nothing, and a later re-add can give
  // it any version it likes.
  //
  // A refresh is precisely when the surface has changed, so that hole
  // would be open on every run that matters.
  // The declarations that can excuse a dropped record, validated BEFORE they
  // are allowed to excuse one. Both are inputs that only ever make this
  // quieter, so a stale or unreadable one is refused here rather than
  // falling through and reading as though it governed something.
  var priorSince    = (prior && prior.sinceByPrimitive) || null;
  var priorRemovals = (prior && prior.removedPrimitives) || {};
  var originatedMap = extractOriginated();
  var removalRecords = extractRemovals();

  // The export walk, captured ONCE and before the declaration checks, because
  // a tombstone is held to the callable and not only to the documentation
  // beside it. The meta the snapshot carries is filled in below rather than
  // passed here: none of it changes the surface, and walking twice would
  // leave the tree the checks read and the tree the file records as two
  // things that agree by luck.
  var snapshot = capture(blamepost, { packageVersion: pkg.version });

  var declViolations = checkOriginatedDeclarations(originatedMap, priorSince, sinceByPrimitive)
    .concat(checkRemovals(removalRecords, priorSince || {}, sinceByPrimitive, priorRemovals,
      snapshot.surface));
  if (declViolations.length > 0) {
    process.stderr.write("[refresh-api-snapshot] removal-record violations " +
      "(a declaration must name a primitive the record holds, at the version it holds):\n");
    declViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
    process.exit(2);
  }

  var droppedViolations = checkSinceDropped(
    priorSince, sinceByPrimitive, originatedMap, removalRecords);
  if (droppedViolations.length > 0) {
    process.stderr.write("[refresh-api-snapshot] @since deletion violations " +
      "(a shipped primitive's introduction record cannot be dropped by a refresh):\n");
    droppedViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
    process.exit(2);
  }

  // The meta this refresh records, written onto the snapshot captured above.
  // `capture` seeded each of these empty and in this order, so assigning them
  // here keeps the committed file's key order stable across refreshes: a
  // reordered artifact is a diff nobody can read.
  snapshot.sinceByPrimitive = sinceByPrimitive;
  // What this refresh carries forward plus what it records for the first
  // time. A token leaves the since map on the run that deletes its block,
  // and this is the only run on which the version it shipped at is still
  // readable, so it is written down here or it is lost.
  snapshot.removedPrimitives = nextRemovals(
    removalRecords, priorSince || {}, sinceByPrimitive, priorRemovals, pkg.version);

  // @originated gate: when this refresh removes a documented @primitive path while
  // the exported surface is unchanged, the path was CORRECTED (not deleted), so
  // the origin version must be preserved via an @originated tag in source.
  var membershipRecords = extractMembership();
  var membershipViolations = checkMembership(membershipRecords, snapshot);
  if (membershipViolations.length > 0) {
    process.stderr.write("[refresh-api-snapshot] @membership violations " +
      "(a declaration must name an exported array and a known polarity):\n");
    membershipViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
    process.exit(2);
  }
  var membership = sourcePrimitives.membershipMap(membershipRecords);

  // The polarity, held to what the record already says BEFORE the record is
  // overwritten. This is the only point where the previous value is still
  // readable, which is exactly why the @since freeze is enforced here too: a
  // refresh is the one command that can rewrite the thing every other gate
  // compares against.
  var polarityViolations = checkMembershipFrozen(
    prior && prior.membershipByArray, membership);
  if (polarityViolations.length > 0) {
    process.stderr.write("[refresh-api-snapshot] @membership polarity violations " +
      "(a declared polarity is immutable once shipped):\n");
    polarityViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
    process.stderr.write("[refresh-api-snapshot] a list does not change what kind of list it " +
      "is. If this is a genuine correction, it is a surface change: say so in the release " +
      "notes and remove the recorded entry deliberately rather than by editing one word.\n");
    process.exit(2);
  }
  snapshot.membershipByArray = membership;

  if (prior) {
    var diff = compare(prior, snapshot, { membership: membership });
    var surfaceUnchanged = diff.breaking.length === 0 && diff.additive.length === 0;
    var origViolations = checkOriginated(
      prior.sinceByPrimitive, sinceByPrimitive, originatedMap, removalRecords, surfaceUnchanged);
    if (origViolations.length > 0) {
      process.stderr.write("[refresh-api-snapshot] @originated violations (a corrected path must preserve its origin):\n");
      origViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
      process.exit(2);
    }
  }

  write(snapshot, outPath);
  process.stdout.write("[refresh-api-snapshot] wrote " + outPath +
    " (packageVersion=" + snapshot.packageVersion + ")\n");
}
