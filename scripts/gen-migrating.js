// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/gen-migrating.js: generate MIGRATING.md from deprecate() calls
// across lib/. Walks the tree, finds every `deprecate.warn|wrap|alias`
// invocation, extracts the opts literal, groups by removeIn major.
//
// Re-run before each release; the file is committed so operators can read
// the diff against the prior tag.
//
// The document it writes is read as a statement about the code, so the run
// that writes it has to have read the code. "No active deprecations" is
// byte-identical whether this walked every source file and found no
// deprecation or walked nothing at all, and the second is what a moved
// directory or a wrong base produces. Both numbers are published for that
// reason, and the source count is refused at zero: an empty walk stops the
// run instead of committing an assertion nothing measured.
//
// Limitation: opts must be an object literal (the common case). Calls that
// pass a variable as opts won't be captured. The script logs those with a
// [gen-migrating] note and skips the entry. Switch to a module-hook
// capture if that ever becomes the dominant pattern.

var fs   = require("node:fs");
var path = require("node:path");

var examinedCounts = require("./examined-counts.js");

var ROOT    = path.resolve(__dirname, "..");
var LIB_DIR = path.join(ROOT, "lib");
var TARGET  = path.join(ROOT, "MIGRATING.md");

function _walk(dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var full = path.join(dir, e.name);
    if (e.isDirectory()) {
      // Vendored bundles are third-party; never scan them for deprecations.
      if (e.name !== "vendor") _walk(full, out);
    } else if (e.isFile() && e.name.endsWith(".js")) {
      out.push(full);
    }
  });
  return out;
}

// Find the closing brace of an object literal that starts at index i
// (where src[i] === "{"). Tracks nesting + quoted strings + escapes.
// Returns the index AFTER the closing brace, or -1 if unterminated.
function _findObjectEnd(src, i) {
  var depth = 0;
  var inStr = null;
  var esc = false;
  for (; i < src.length; i++) {
    var c = src[i];
    if (esc) { esc = false; continue; }
    if (inStr) {
      if (c === "\\") esc = true;
      else if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === "\"" || c === "`") { inStr = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function _evalOpts(src) {
  try { return Function("return " + src)(); }
  catch (_e) { return null; }
}

function _extractDeprecations(src, fileLabel) {
  var out = [];

  // .warn("name", { ... })
  for (var m of src.matchAll(/(?:^|[^.\w])deprecate\.warn\s*\(\s*"([^"]+)"\s*,\s*\{/g)) {
    var braceAt = m.index + m[0].length - 1;
    var end = _findObjectEnd(src, braceAt);
    if (end < 0) continue;
    var opts = _evalOpts(src.slice(braceAt, end));
    if (!opts) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.warn(\"" + m[1] + "\")\n");
      continue;
    }
    out.push({ kind: "warn", name: m[1], opts: opts });
  }

  // .wrap(<fn>, "name", { ... })
  for (var w of src.matchAll(/(?:^|[^.\w])deprecate\.wrap\s*\(/g)) {
    var startW = w.index + w[0].length;
    var nameMatchW = src.slice(startW).match(/"([^"]+)"\s*,/);
    if (!nameMatchW) continue;
    var afterNameW = startW + nameMatchW.index + nameMatchW[0].length;
    var openBraceW = src.indexOf("{", afterNameW);
    if (openBraceW < 0) continue;
    var endW = _findObjectEnd(src, openBraceW);
    if (endW < 0) continue;
    var optsW = _evalOpts(src.slice(openBraceW, endW));
    if (!optsW) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.wrap(\"" + nameMatchW[1] + "\")\n");
      continue;
    }
    out.push({ kind: "wrap", name: nameMatchW[1], opts: optsW });
  }

  // .alias(<obj>, "old", "new", { ... })
  for (var a of src.matchAll(/(?:^|[^.\w])deprecate\.alias\s*\(/g)) {
    var startA = a.index + a[0].length;
    var aliasMatchA = src.slice(startA).match(/"([^"]+)"\s*,\s*"([^"]+)"\s*,/);
    if (!aliasMatchA) continue;
    var afterAliasA = startA + aliasMatchA.index + aliasMatchA[0].length;
    var openBraceA = src.indexOf("{", afterAliasA);
    if (openBraceA < 0) continue;
    var endA = _findObjectEnd(src, openBraceA);
    if (endA < 0) continue;
    var optsA = _evalOpts(src.slice(openBraceA, endA));
    if (!optsA) {
      process.stderr.write("[gen-migrating] " + fileLabel + ": could not parse opts for deprecate.alias(\"" + aliasMatchA[1] + "\")\n");
      continue;
    }
    out.push({ kind: "alias", name: aliasMatchA[1], renamedTo: aliasMatchA[2], opts: optsA });
  }

  return out;
}

function _majorOf(version) {
  var m = String(version || "").match(/^(\d+)\.(\d+)/);
  if (!m) return null;
  return Number(m[1]) === 0 ? "v0.x" : "v" + m[1] + ".x";
}

// What the last _gather() read, for the counts published at the end. It is
// filled where the walk happens rather than recomputed, so the number
// published is the number the document was built from.
var EXAMINED = { sourceFiles: 0, deprecations: 0 };

function _gather() {
  var files = _walk(LIB_DIR, []);
  EXAMINED.sourceFiles = files.length;
  var entries = [];
  files.forEach(function (f) {
    var src = fs.readFileSync(f, "utf8");
    var rel = path.relative(ROOT, f).replace(/\\/g, "/");
    _extractDeprecations(src, rel).forEach(function (d) {
      if (!d.opts.since || !d.opts.removeIn) {
        process.stderr.write("[gen-migrating] " + rel + ": " + d.kind + " call for \"" + d.name + "\" missing since/removeIn \u2014 skipped\n");
        return;
      }
      entries.push({
        name:      d.name,
        kind:      d.kind,
        since:     d.opts.since,
        removeIn:  d.opts.removeIn,
        message:   d.opts.message || null,
        hint:      d.opts.hint || null,
        renamedTo: d.renamedTo || null,
        file:      rel,
      });
    });
  });
  EXAMINED.deprecations = entries.length;
  return entries;
}

function _build() {
  var entries = _gather();
  var byRemove = new Map();
  entries.forEach(function (e) {
    var major = _majorOf(e.removeIn);
    if (!major) return;
    if (!byRemove.has(major)) byRemove.set(major, []);
    byRemove.get(major).push(e);
  });

  var lines = [];
  lines.push("# Migrating");
  lines.push("");
  lines.push("One migration recipe per breaking change. Every deprecated surface listed here also warns from the running process before its removal version, with `BLAMEJS_DEPRECATIONS=warn` set or by default outside production. This file ships in the repository, so you can diff it against the tag you are upgrading from.");
  lines.push("");
  lines.push("Some breaking changes cannot warn at runtime: an on-disk format break, a database migration, or a change to what a listener accepts on the wire has no in-process call to attach a warning to. Those are listed below alongside the runtime deprecations, so the full upgrade path is here rather than spread through the changelog.");
  lines.push("");

  if (entries.length === 0) {
    lines.push("## No active deprecations");
    lines.push("");
    lines.push("No `deprecate()`-marked surface is awaiting removal.");
    lines.push("");
    _appendOutOfBand(lines);
    return lines.join("\n");
  }

  var majors = Array.from(byRemove.keys()).sort();
  majors.forEach(function (m) {
    lines.push("## Removed in " + m);
    lines.push("");
    var rows = byRemove.get(m).slice().sort(function (a, b) {
      if (a.since !== b.since) return a.since < b.since ? -1 : 1;
      return a.name < b.name ? -1 : 1;
    });
    rows.forEach(function (e) {
      lines.push("### `" + e.name + "`");
      lines.push("");
      lines.push("- **Since:** " + e.since);
      lines.push("- **Removed in:** " + e.removeIn);
      lines.push("- **Defined at:** [`" + e.file + "`](" + e.file + ")");
      if (e.kind === "alias" && e.renamedTo) {
        lines.push("- **Renamed to:** `" + e.renamedTo + "`");
      }
      if (e.message) {
        lines.push("");
        lines.push(e.message);
      }
      if (e.hint) {
        lines.push("");
        lines.push(e.hint);
      }
      lines.push("");
    });
  });

  _appendOutOfBand(lines);
  return lines.join("\n");
}

// OUT_OF_BAND_BREAKS carries the on-disk and wire-encoding breaks that
// cannot be expressed through `deprecate()`, because there is no in-process
// runtime surface to warn from. Append an entry as a release ships one.
//
// Each entry:
//   release:    git tag of the release that introduced the break
//   surface:    operator-visible API or on-disk artifact affected
//   summary:    one-line operator-facing description
//   migration:  multi-line markdown migration recipe
// Empty until a release ships one. An entry here is written by hand, at the
// time the break lands, in the same commit. Nothing derives it from a diff,
// because the recipe is the judgement about what an operator has to DO, and a
// diff cannot say that.
var OUT_OF_BAND_BREAKS = [];

function _appendOutOfBand(lines) {
  if (!OUT_OF_BAND_BREAKS.length) return;
  lines.push("---");
  lines.push("");
  lines.push("## Out-of-band breaking changes");
  lines.push("");
  lines.push("Listed newest-first.");
  lines.push("");
  // Semver-aware sort - `v0.9.10` must sort newer than `v0.9.9` (a naive
  // lexicographic compare would order the digit `1` before `9`). Strip the
  // leading `v`, split on `.`, compare each numeric component.
  function _semverCmp(a, b) {
    var as = String(a).replace(/^v/, "").split(".").map(Number);
    var bs = String(b).replace(/^v/, "").split(".").map(Number);
    for (var i = 0; i < Math.max(as.length, bs.length); i += 1) {
      var ai = i < as.length ? as[i] : 0;
      var bi = i < bs.length ? bs[i] : 0;
      if (ai !== bi) return ai - bi;
    }
    return 0;
  }
  var sorted = OUT_OF_BAND_BREAKS.slice().sort(function (a, b) {
    return _semverCmp(b.release, a.release);   // newest first
  });
  sorted.forEach(function (e) {
    lines.push("### " + e.release + " \u2014 `" + e.surface + "`");
    lines.push("");
    lines.push(e.summary);
    lines.push("");
    lines.push(e.migration);
    lines.push("");
  });
}

var document = _build();

// The counts decide whether the document gets written. A run that read no
// source has nothing to say about deprecations, and writing the document
// anyway commits an operator-facing assertion produced by a measurement
// that did not happen. The refusal comes first for the same reason a gate's
// refusal precedes its passing sentence.
var exitCode = examinedCounts.publish([
  { unit: "lib-source-files", n: EXAMINED.sourceFiles },
  {
    unit:   "declared-deprecations",
    n:      EXAMINED.deprecations,
    zeroIs: "a tree that has deprecated nothing yet is the ordinary state of this " +
            "repository, and the document says so in as many words. The number that " +
            "proves this run measured anything is the source count beside it, which is " +
            "refused at zero; nothing an author does can take that one to zero while " +
            "the walk is still working",
  },
], { tag: "[gen-migrating]" });

if (exitCode !== 0) {
  process.stderr.write("[gen-migrating] " + TARGET + " was NOT written. It is committed and " +
    "read as a statement about the code, so it is not written from a run that read none.\n");
  process.exit(1);
}

fs.writeFileSync(TARGET, document, "utf8");
// On stderr, so the count lines above stay the last word on stdout. A gate's
// counts are read from the END of what it printed, and a progress line after
// them would leave a caller reading none.
process.stderr.write("[gen-migrating] wrote " + TARGET + "\n");
