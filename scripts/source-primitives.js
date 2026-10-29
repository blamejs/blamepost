// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/source-primitives is how the gates read the documentation blocks in
// lib/ and walk the sources that carry them. Every gate that governs a
// primitive or a module block takes its list from here.
//
// The walk and the block parse are lib/web/wiki/blocks.js, bound here to the
// directory above this one. The reference wiki renders its pages from the
// same module when the server builds it, so a block the gates read is the
// block the wiki reads: one parse produces both. This file holds no block
// parse of its own.
//
// Three gates ask different questions about the same blocks:
// scripts/check-api-snapshot.js freezes each primitive's introduction version,
// scripts/check-status-lifecycle.js forces a graduation or removal decision on
// schedule, and scripts/validate-source-comment-blocks.js checks that the block
// is well formed in the first place. Each gate governs exactly the set it
// reads, and all three read it here.
//
// The parse is BLOCK scoped rather than line scoped. A tag is read only from
// the `/** ... */` block that declares the `@primitive`, so a block that omits
// a tag reports null for it rather than the next block's value.
//
// The two line-scoped declaration readers below, `@membership` and
// `@removed`, are read by the gates alone and stay in this file, over the same
// walk.
//
// Pure module. No side effects, no network, and it reads the source tree only
// when a caller asks it to.

var fs   = require("node:fs");
var path = require("node:path");

var ROOT   = path.resolve(__dirname, "..");
var reader = require("../lib/web/wiki/blocks.js").at(ROOT);

var LIB_DIR    = reader.LIB_DIR;
var libSources = reader.libSources;
var relative   = reader.relative;

// The polarity words an `@membership` declaration may carry. Frozen here
// because two readers ask about them: the api-snapshot gate classifies a
// membership change with them, and the same gate refuses a declaration
// carrying anything else rather than guessing which was meant.
var MEMBERSHIP_POLARITIES = ["capability", "constraint"];

// An `@membership` line, in either comment style. The path is written out
// in full, the way `@primitive` writes its token, so the declaration says
// which exported table it governs instead of being matched to one by the
// identifier it happens to sit above. That is what makes it survive a
// rename in the safe direction: rename the constant without moving the
// declaration and the path stops matching anything, the table falls back
// to the strict default, and the gate gets louder. There is no spelling of
// this that goes quiet.
var MEMBERSHIP_RE =
  /^(?:\/\/+|\*|\/\*\*)?\s*@membership\s+([A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*)\s+(\S+)\s*$/;

/**
 * collectMembership(files) returns one record per `@membership` declaration.
 *
 * An exported array's SURFACE is the set of things it names, and what a
 * change to that set means depends on what the set asserts. A list of the
 * things this package OFFERS loses something when it shrinks. A list of the
 * things it REQUIRES, or of the things it cannot yet do, loses something
 * when it GROWS: a limitation added takes a capability away, and a
 * limitation lifted gives one back. The two run in opposite directions and
 * no property of the array itself distinguishes them, which is why the
 * direction of a count is not evidence about either one.
 *
 * So the array declares which kind it is, once, beside itself:
 *
 *   // @membership blamepost.mail.listeners.STALE_AFTER_ROTATION constraint
 *
 * A table that declares nothing is read as `capability`, which is the
 * strict reading: any member lost is breaking. Silence therefore costs a
 * false alarm rather than a missed one, and no table can be made quieter by
 * leaving something out.
 *
 *   path      the dotted surface path the declaration governs
 *   polarity  capability or constraint, as written
 *   file      repository relative path
 *   line      1-based line the declaration sits on
 */
function collectMembership(files) {
  var out = [];
  (files || libSources()).forEach(function (file) {
    var lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    lines.forEach(function (line, i) {
      var m = MEMBERSHIP_RE.exec(line.trim());
      if (!m) return;
      out.push({
        path:     m[1],
        polarity: m[2],
        file:     relative(file),
        line:     i + 1,
      });
    });
  });
  return out;
}

// An `@removed` line, in either comment style. The value is captured whole
// rather than matched into shape here, and that is deliberate: a declaration
// the READER cannot parse is one the author believes is in force and nothing
// is reading, so it is carried to the checker and refused there by name. A
// reader that only matched well-formed declarations would drop a malformed
// one silently, which is the failure mode this whole record exists to close.
var REMOVAL_RE = /^(?:\/\/+|\*|\/\*\*)?\s*@removed\s+(.+?)\s*$/;

// The shape a well-formed value carries: the token whose removal is being
// recorded, and the introduction version the committed snapshot froze it at.
var REMOVAL_VALUE_RE = /^([A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*)\s+(\d+\.\d+\.\d+)$/;

/**
 * collectRemovals(files) returns one record per `@removed` declaration.
 *
 * A shipped primitive's introduction record is immutable, and there are
 * three true things that can happen to the block that carries it. It can
 * stay. Its documented PATH can be corrected, which is a rename of the
 * documentation and not of the callable, and `@originated` on the corrected
 * block preserves the origin. Or the primitive can be DELETED: the mechanism
 * replaced, the callable gone, nothing left to document.
 *
 * The third had no way to be said. Restoring the `@since` re-documents a
 * callable that no longer ships, and `@originated` asserts the opposite of a
 * deletion: that the path moved and the callable is still reachable. So a
 * genuine removal could only be recorded by a false statement, and the
 * pressure was to reach for whichever tag made the gate stop talking.
 *
 * A removal that leaves no surface diff is exactly the one that should not
 * be silent. Pre-1.0 means a removal is ALLOWED, not that it is invisible.
 *
 *   // The scratch directory this derived went with the mechanism.
 *   // @removed blamepost.store.snapshotPathFor 0.1.0
 *
 * The declaration names the token and the version the record holds for it,
 * so it answers for exactly one primitive. A declaration carrying a version
 * alone would be satisfied by every primitive that shipped in that release.
 *
 *   token     the dotted token whose removal is recorded, or null when the
 *             value does not read as one
 *   version   the introduction version it names, or null likewise
 *   value     the value as written, so a refusal can quote it back
 *   file      repository relative path
 *   line      1-based line the declaration sits on
 */
function collectRemovals(files) {
  var out = [];
  (files || libSources()).forEach(function (file) {
    var lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    lines.forEach(function (line, i) {
      var m = REMOVAL_RE.exec(line.trim());
      if (!m) return;
      var parsed = REMOVAL_VALUE_RE.exec(m[1].trim());
      out.push({
        token:   parsed ? parsed[1] : null,
        version: parsed ? parsed[2] : null,
        value:   m[1].trim(),
        file:    relative(file),
        line:    i + 1,
      });
    });
  });
  return out;
}

/**
 * membershipMap(records) projects the records onto { path: polarity }.
 *
 * A path declared twice keeps the LAST record, and the api-snapshot gate
 * refuses the duplicate separately rather than here, so a table governed by
 * two disagreeing declarations is reported instead of resolved by whichever
 * file the walk reached second.
 */
function membershipMap(records) {
  var out = {};
  records.forEach(function (r) { out[r.path] = r.polarity; });
  return out;
}

// `reader` is lib/web/wiki/blocks.js bound to this repository. A gate that
// reads a fixture tree binds the same reader there with `reader.at(root)`.
// `collect`, `collectPrimitives`, `collectModules` and `tagMap` are the
// reader's own functions: the records every gate governs are the records the
// wiki renders.
module.exports = {
  ROOT:                   ROOT,
  LIB_DIR:                LIB_DIR,
  MEMBERSHIP_POLARITIES:  MEMBERSHIP_POLARITIES,
  reader:                 reader,
  libSources:             libSources,
  relative:               relative,
  collect:                reader.collect,
  collectPrimitives:      reader.collectPrimitives,
  collectModules:         reader.collectModules,
  collectMembership:      collectMembership,
  collectRemovals:        collectRemovals,
  membershipMap:          membershipMap,
  tagMap:                 reader.tagMap,
};
