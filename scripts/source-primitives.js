// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/source-primitives is the ONE reader of the `@primitive`
// documentation blocks in lib/, and the one walk over the sources that carry
// them. Every gate that governs a primitive takes its list from here.
//
// Why one reader. Three gates ask different questions about the same blocks:
// scripts/check-api-snapshot.js freezes each primitive's introduction version,
// scripts/check-status-lifecycle.js forces a graduation or removal decision on
// schedule, and scripts/validate-source-comment-blocks.js checks that the block
// is well formed in the first place. A gate that finds its own primitives,
// with its own regular expressions, governs exactly the set it
// found. Two lists built by two walks agree only by luck, and the failure is
// silent in the direction that matters: a primitive one gate cannot see is a
// primitive that gate reports nothing about, and its verdict still reads clean.
// Sourcing all three here makes the governed set and the documented set the
// same set by construction rather than by coincidence.
//
// The parse is BLOCK scoped rather than line scoped. A tag is
// read only from the `/** ... */` block that declares the `@primitive`, so a
// block that omits a tag cannot silently borrow the next block's: a line walk
// that remembers the last `@primitive` it saw and waits for an `@since` binds
// the wrong version onto the wrong token the moment one block leaves the tag
// out, and reports a value for a primitive that never declared one.
//
// Pure module. No side effects, no network, and it reads the source tree only
// when a caller asks it to.

var fs   = require("node:fs");
var path = require("node:path");

var ROOT    = path.resolve(__dirname, "..");
var LIB_DIR = path.join(ROOT, "lib");

// Every .js file this project ships under lib/, at any depth, in a stable
// order. The vendored tree is skipped: it is upstream's source, its comment
// blocks are upstream's, and it is refreshed wholesale rather than edited.
// Shared by every gate so a primitive documented in lib/mail/ is read exactly
// like one documented at the top level.
function libSources(libDir) {
  libDir = libDir || LIB_DIR;
  var out = [];
  (function walk(dir) {
    if (!fs.existsSync(dir)) return;
    fs.readdirSync(dir, { withFileTypes: true })
      .sort(function (a, b) { return a.name.localeCompare(b.name); })
      .forEach(function (e) {
        if (e.isDirectory()) {
          if (e.name !== "vendor" && e.name !== "node_modules") walk(path.join(dir, e.name));
        } else if (e.isFile() && /\.js$/.test(e.name)) {
          out.push(path.join(dir, e.name));
        }
      });
  }(libDir));
  return out;
}

function relative(file) {
  return path.relative(ROOT, file).split(path.sep).join("/");
}

// Every /** ... */ block in a source, with the 1-based line its opener sits on
// so a finding points at something a reader can jump to.
function _blocks(src) {
  var out = [];
  var re = /\/\*\*[\s\S]*?\*\//g;
  var m;
  while ((m = re.exec(src)) !== null) {
    out.push({ text: m[0], line: src.slice(0, m.index).split(/\r?\n/).length });
  }
  return out;
}

// Strip the leading ` * ` decoration so tag matching and prose detection both
// see the author's actual text.
function _lines(blockText) {
  return blockText
    .replace(/^\/\*\*/, "")
    .replace(/\*\/$/, "")
    .split(/\r?\n/)
    .map(function (l) { return l.replace(/^\s*\*\s?/, "").trimEnd(); });
}

function _tag(lines, name) {
  var re = new RegExp("^@" + name + "\\s+(.+)$");
  for (var i = 0; i < lines.length; i += 1) {
    var m = re.exec(lines[i].trim());
    if (m) return m[1].trim();
  }
  return null;
}

// Every whitespace or comma separated value across all repeats of one tag,
// which is how `@related` names more than one target.
function _allTagValues(lines, name) {
  var re = new RegExp("^@" + name + "\\s+(.+)$");
  var out = [];
  lines.forEach(function (l) {
    var m = re.exec(l.trim());
    if (m) {
      m[1].split(/[,\s]+/).forEach(function (tok) {
        if (tok.length > 0) out.push(tok);
      });
    }
  });
  return out;
}

// Prose is any line that is neither a tag nor empty. A block whose only content
// is tags describes nothing, and the reader it was written for is the one
// deciding whether to call the thing.
function _proseLength(lines) {
  return lines
    .filter(function (l) { return l.trim().length > 0 && l.trim().charAt(0) !== "@"; })
    .join(" ")
    .trim()
    .length;
}

/**
 * collectPrimitives(files) returns one record per `@primitive` block.
 *
 * `files` is the walk to read, so a caller that has to report how wide the walk
 * was can take its length without walking twice. Omitting it reads lib/.
 *
 * Every record carries every tag any gate reads, whether or not the calling
 * gate uses it. A per caller projection would put the parse back where it
 * started, with each gate deciding for itself what a block says.
 *
 *   token       the dotted name the block declares
 *   file        repository relative path
 *   line        1-based line of the block opener
 *   since       @since, the introduction version
 *   status      @status, one of experimental / stable / deprecated
 *   spec        @spec, the standard it implements
 *   deprecated  @deprecated, the version it is removed by
 *   originated  @originated, the earlier version a corrected path preserves
 *   related     @related targets, flattened across repeats
 *   prose       length in characters of the non tag description
 */
function collectPrimitives(files) {
  var out = [];
  (files || libSources()).forEach(function (file) {
    var src = fs.readFileSync(file, "utf8");
    _blocks(src).forEach(function (b) {
      var lines = _lines(b.text);
      var token = _tag(lines, "primitive");
      if (!token) return;
      out.push({
        token:      token,
        file:       relative(file),
        line:       b.line,
        since:      _tag(lines, "since"),
        status:     _tag(lines, "status"),
        spec:       _tag(lines, "spec"),
        deprecated: _tag(lines, "deprecated"),
        originated: _tag(lines, "originated"),
        related:    _allTagValues(lines, "related"),
        prose:      _proseLength(lines),
      });
    });
  });
  return out;
}

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

/**
 * tagMap(primitives, tag) projects the records onto { token: value }, keeping
 * only the ones that declared the tag.
 *
 * The api snapshot stores its freeze in exactly this shape, and reading it off
 * the shared records is what keeps the frozen set and the documented set the
 * same set. A duplicate token is refused by the comment block gate rather than
 * here, so the last one wins in the interim and the gate names it.
 */
function tagMap(primitives, tag) {
  var out = {};
  primitives.forEach(function (p) {
    if (p[tag]) out[p.token] = p[tag];
  });
  return out;
}

module.exports = {
  ROOT:                   ROOT,
  LIB_DIR:                LIB_DIR,
  MEMBERSHIP_POLARITIES:  MEMBERSHIP_POLARITIES,
  libSources:             libSources,
  relative:               relative,
  collectPrimitives:      collectPrimitives,
  collectMembership:      collectMembership,
  collectRemovals:        collectRemovals,
  membershipMap:          membershipMap,
  tagMap:                 tagMap,
};
