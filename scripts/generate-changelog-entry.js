#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/generate-changelog-entry.js
 *
 * CHANGELOG.md is a derived artifact. The source of truth is the JSON
 * under `release-notes/`, and this script is the only thing that renders
 * it. Operators edit the JSON, run `--rebuild`, and commit both.
 *
 * Two shapes of source file feed it, and both are read the same way:
 *
 *   release-notes/v<X>.<Y>.<Z>.json   one release, hand-written for the
 *                                     version being cut
 *   release-notes/v<X>.<Y>.x.json     one minor line, holding every
 *                                     released version of that line
 *                                     newest first, written by
 *                                     scripts/consolidate-release-notes.js
 *
 * The rendered CHANGELOG groups by minor line, newest line first, with
 * one block per released tag inside it. That grouping is what an
 * operator upgrading across several patches actually reads: the line
 * they are on, then every release between there and here.
 *
 * The structured source keeps the entry operator-facing by construction:
 * every field has a known semantic (headline, summary, sections[heading],
 * items[title, body]), and each string runs through a leak-vocabulary
 * validator before render. Hand-written prose can drift into
 * internal-process narrative (phase / sweep / batch numbering,
 * AI-tooling vocabulary); this pipeline refuses such input at validation
 * time.
 *
 * Usage:
 *   node scripts/generate-changelog-entry.js --rebuild        # write CHANGELOG.md from release-notes/
 *   node scripts/generate-changelog-entry.js --check          # rebuild in memory, diff against disk
 *   node scripts/generate-changelog-entry.js                  # render one version, from package.json
 *   node scripts/generate-changelog-entry.js 0.1.0            # render one version, explicit
 *   node scripts/generate-changelog-entry.js 0.1.0 --release-page
 *   node scripts/generate-changelog-entry.js 0.1.0 --headline
 *
 * Output:
 *   --rebuild        rewrites CHANGELOG.md and says how many bytes it wrote
 *   --check          exits non-zero when CHANGELOG.md drifts from the notes
 *   default          the one version's CHANGELOG block, to stdout
 *   --release-page   the same release as multi-section markdown for a
 *                    release page, where the version and date are already
 *                    the page title. Sections become headings and items
 *                    become bullets, so each one is scannable instead of
 *                    buried in a paragraph.
 *   --headline       just the headline, on one line, for a caller
 *                    building a release title. It exists so nothing has
 *                    to guess which of the two file shapes currently
 *                    holds a given version: this script already knows,
 *                    and a caller reading a fixed path breaks the day
 *                    the release is folded into its series.
 *
 * Exit codes:
 *   0  rendered, written, or verified
 *   1  release notes missing, malformed, failed validation, or the
 *      committed CHANGELOG.md no longer matches them
 */

var fs   = require("node:fs");
var path = require("node:path");

var examinedCounts = require("./examined-counts.js");

var ROOT         = path.resolve(__dirname, "..");
var PACKAGE_JSON = path.join(ROOT, "package.json");
var NOTES_DIR    = path.join(ROOT, "release-notes");
var CHANGELOG    = path.join(ROOT, "CHANGELOG.md");

// Keep a Changelog's canonical section order, plus the two headings this
// project adds. Render order follows this list whatever order the JSON
// declares, so entries are structurally identical across releases.
var SECTION_ORDER = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security", "Detectors", "Migration"];

// The separator inside a release header and between a bullet's title and
// its body. It belongs to this generator's output format rather than to
// prose, and scripts/check-changelog-extract.js matches the header shape
// it produces, so changing the character would make that gate reject
// every entry this tool has ever emitted. Built from its code point so
// the source stays pure ASCII.
var EM = String.fromCharCode(0x2014);

// The preamble. Written here rather than preserved from the existing
// file, because a derived artifact that keeps a hand-edited header is
// only partly derived, and the hand-edited part is the part that rots.
var PREAMBLE = [
  "All notable changes to `@blamejs/blamepost` are documented here, grouped by",
  "minor line with one entry per released tag. Latest first.",
  "",
  "Pre-1.0 there are no compatibility shims, so any release can change something",
  "operators depend on. Read every entry between the version you run and the one",
  "you are moving to. This project follows",
  "[Semantic Versioning](https://semver.org/spec/v2.0.0.html).",
];

// LEAK_PATTERNS holds the tokens that signal internal-process narrative
// instead of operator-facing description. The `claude`-file token is
// assembled from char codes so the literal string doesn't appear in this
// validator's own source either.
function _leakPatterns() {
  var cfg = [67, 76, 65, 85, 68, 69]
    .map(function (c) { return String.fromCharCode(c); })
    .join("");
  return [
    new RegExp("\\b" + cfg + "\\.md\\b"),
    new RegExp("\\bper\\s+" + cfg + "\\b"),
    /\bper\s+project\s+rule\s+§/,
    /\bper\s+rule\s+§\d/,
    /\bphase\s+\d/i,
    /\bsweep\s+\d/i,
    /\btier[- ]?[abc]\b/i,
    /\bbatch\s+\d/i,
    /\bgroup\s+[a-h]\b/i,
    /\bslice\s+\d/i,
    /\baudit[- ]derived\b/i,
    /\bpost[- ]audit\b/i,
    /\b(?:anthropic|chatgpt|openai|copilot|sonnet|opus|haiku|gemini|co[- ]authored[- ]by|llm[- ]generated|ai[- ]generated)\b/i,
  ];
}

function _exit(msg) {
  process.stderr.write("[generate-changelog-entry] " + msg + "\n");
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

// Strict semver gate at the trust boundary. Every downstream use of
// `version` builds a path segment or a `v<version>` string. Refuse
// anything that isn't `\d+.\d+.\d+` before it reaches a path join.
function _requireSemver(version, label) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) {
    _exit(label + " is not strict semver `\\d+.\\d+.\\d+`: " + JSON.stringify(version));
  }
  return version;
}

function _readPackageVersion() {
  return _readJson(PACKAGE_JSON, "package.json").version;
}

function _minorOf(version) {
  return String(version).replace(/\.\d+$/, "");
}

// Newest first, on the three numeric components.
function _compareVersionsDesc(a, b) {
  var ap = String(a).split(".").map(Number);
  var bp = String(b).split(".").map(Number);
  for (var i = 0; i < 3; i += 1) {
    if (ap[i] !== bp[i]) return bp[i] - ap[i];
  }
  return 0;
}

// Two release objects say the same thing when their canonical JSON is
// identical. Key order is normalized first, so a re-serialized copy that
// reordered its keys is not reported as a contradiction.
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    var out = {};
    Object.keys(value).sort().forEach(function (k) {
      if (k === "$schema") return;
      out[k] = canonicalize(value[k]);
    });
    return out;
  }
  return value;
}

function sameRelease(a, b) {
  return JSON.stringify(canonicalize(a)) === JSON.stringify(canonicalize(b));
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Returns the number of STRINGS it swept, which is what the caller
// publishes. A leak sweep reports "no internal narrative found" in the same
// words whether it read every field of every release or descended into
// none of them, and the second is what a walker that stopped recognizing a
// shape does. The finding count cannot tell them apart, because zero
// findings is the healthy answer; only the number of strings reached can.
function _walkForLeaks(node, basePath, patterns, out) {
  if (typeof node === "string") {
    for (var i = 0; i < patterns.length; i += 1) {
      if (patterns[i].test(node)) out.push({ path: basePath, pattern: patterns[i].source });
    }
    return 1;
  }
  var swept = 0;
  if (Array.isArray(node)) {
    for (var j = 0; j < node.length; j += 1) {
      swept += _walkForLeaks(node[j], basePath + "[" + j + "]", patterns, out);
    }
    return swept;
  }
  if (node && typeof node === "object") {
    var keys = Object.keys(node);
    for (var k = 0; k < keys.length; k += 1) {
      if (keys[k] === "$schema") continue;
      swept += _walkForLeaks(node[keys[k]], basePath + "." + keys[k], patterns, out);
    }
  }
  return swept;
}

// Validate one release against scripts/release-notes-schema.json as
// prose rules rather than as a document check: the schema states the
// shape, and these are the same rules stated where the renderer can act
// on them. Refuses loud on any problem, so a malformed entry never
// renders half-formed. Returns the number of strings the leak sweep read,
// which is what a caller publishes as the count behind its verdict.
function validate(notes, version, where) {
  var errs = [];
  var at   = where ? " (" + where + ")" : "";

  if (notes.version !== version) {
    errs.push("`version` is " + JSON.stringify(notes.version) + " but expected " + JSON.stringify(version));
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(notes.date || ""))) {
    errs.push("`date` must be `YYYY-MM-DD`; got " + JSON.stringify(notes.date) +
      ". It is fixed once the version ships so a rebuild stays reproducible");
  }
  if (typeof notes.headline !== "string" || notes.headline.length < 8) {
    errs.push("`headline` missing or shorter than 8 characters");
  } else {
    if (notes.headline !== notes.headline.trim()) errs.push("`headline` has leading/trailing whitespace");
    if (/[.!?]$/.test(notes.headline)) errs.push("`headline` must not end with sentence punctuation");
    if (!/^[A-Z`]/.test(notes.headline)) {
      errs.push("`headline` must start with a capital letter or backtick; got " +
        JSON.stringify(notes.headline.slice(0, 24)));
    }
  }
  if (notes.summary !== undefined) {
    if (typeof notes.summary !== "string") errs.push("`summary` must be a string when present");
    else if (notes.summary !== notes.summary.trim()) errs.push("`summary` has leading/trailing whitespace");
    else if (notes.summary.length > 0 && !/[.!?]$/.test(notes.summary)) {
      errs.push("`summary` must end with sentence punctuation");
    }
  }

  if (!Array.isArray(notes.sections) || notes.sections.length === 0) {
    errs.push("`sections` must be a non-empty array of { heading, items }");
  } else {
    var seen = {};
    for (var s = 0; s < notes.sections.length; s += 1) {
      var sec = notes.sections[s] || {};
      var pfx = "sections[" + s + "]";
      if (typeof sec.heading !== "string") {
        errs.push(pfx + ".heading missing");
        continue;
      }
      if (SECTION_ORDER.indexOf(sec.heading) === -1) {
        errs.push(pfx + ".heading " + JSON.stringify(sec.heading) +
          " not in allowlist: " + SECTION_ORDER.join(" / "));
      }
      if (seen[sec.heading]) {
        errs.push(pfx + ".heading " + JSON.stringify(sec.heading) +
          " appears twice, so consolidate its items under one section");
      }
      seen[sec.heading] = true;
      if (!Array.isArray(sec.items) || sec.items.length === 0) {
        errs.push(pfx + " (" + sec.heading + ") `items` missing or empty");
        continue;
      }
      for (var t = 0; t < sec.items.length; t += 1) {
        var it  = sec.items[t] || {};
        var ipx = pfx + ".items[" + t + "]";
        if (typeof it.title !== "string" || it.title.length === 0) {
          errs.push(ipx + ".title missing");
        } else {
          if (it.title !== it.title.trim()) errs.push(ipx + ".title has leading/trailing whitespace");
          if (/[.!?]$/.test(it.title))      errs.push(ipx + ".title must not end with sentence punctuation");
          if (!/^[A-Za-z`]/.test(it.title)) errs.push(ipx + ".title must start with a letter or backtick");
        }
        if (typeof it.body !== "string" || it.body.length === 0) {
          errs.push(ipx + ".body missing");
        } else {
          if (it.body !== it.body.trim()) errs.push(ipx + ".body has leading/trailing whitespace");
          if (!/[.!?]$/.test(it.body))    errs.push(ipx + ".body must end with sentence punctuation");
          if (it.body.length < 16) {
            errs.push(ipx + ".body is shorter than 16 characters, so it describes nothing an operator can act on");
          }
        }
      }
    }
  }

  if (notes.references !== undefined) {
    if (!Array.isArray(notes.references)) {
      errs.push("`references` must be an array when present");
    } else {
      for (var r = 0; r < notes.references.length; r += 1) {
        var ref = notes.references[r] || {};
        var rpx = "references[" + r + "]";
        if (typeof ref.label !== "string" || ref.label.length === 0) errs.push(rpx + ".label missing");
        if (typeof ref.url !== "string" || !/^https:\/\//.test(ref.url)) {
          errs.push(rpx + ".url must be an https:// URL");
        }
      }
    }
  }

  var hits  = [];
  var swept = _walkForLeaks(notes, "$", _leakPatterns(), hits);
  if (hits.length > 0) {
    process.stderr.write("[generate-changelog-entry] FAIL: leak-vocabulary tokens in v" +
      notes.version + at + ":\n");
    for (var h = 0; h < hits.length; h += 1) {
      process.stderr.write("  " + hits[h].path + "  <-  pattern /" + hits[h].pattern + "/\n");
    }
    process.stderr.write("[generate-changelog-entry] Each field must be operator-facing. Strip internal-process narrative + rewrite.\n");
    process.exit(1);
  }

  if (errs.length > 0) {
    process.stderr.write("[generate-changelog-entry] FAIL: v" + version + at + "\n");
    for (var e = 0; e < errs.length; e += 1) process.stderr.write("  - " + errs[e] + "\n");
    process.exit(1);
  }

  return swept;
}

// Sections in canonical order, whatever order the JSON declared them.
function _orderedSections(sections) {
  return sections.slice().sort(function (a, b) {
    return SECTION_ORDER.indexOf(a.heading) - SECTION_ORDER.indexOf(b.heading);
  });
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// Read one series file and refuse anything that would make the CHANGELOG
// lie about the line: a wrapper naming a different minor than its own
// file, a release filed under the wrong line, or a version listed twice.
function _readSeries(name) {
  var doc   = _readJson(path.join(NOTES_DIR, name), "release-notes/" + name);
  var minor = name.replace(/^v/, "").replace(/\.x\.json$/, "");
  if (doc.minor !== minor) {
    _exit("release-notes/" + name + " names minor " + JSON.stringify(doc.minor) +
      " but its file name says " + JSON.stringify(minor));
  }
  if (!Array.isArray(doc.releases) || doc.releases.length === 0) {
    _exit("release-notes/" + name + " has no `releases` array");
  }
  var seen = {};
  doc.releases.forEach(function (r) {
    var v = (r && r.version) || "";
    _requireSemver(v, "release-notes/" + name + " release version");
    if (_minorOf(v) !== minor) {
      _exit("release-notes/" + name + " lists v" + v + ", which is not on the " + minor + " line");
    }
    if (seen[v]) _exit("release-notes/" + name + " lists v" + v + " twice");
    seen[v] = true;
  });
  return doc;
}

// Every release the tree describes, from both file shapes, newest first.
//
// A version may legitimately appear twice while a hand-written file is
// still on disk beside the series entry it was folded into. Two copies
// that agree render once; two copies that disagree are the drift the
// series file makes possible, so they stop the rebuild rather than let
// it pick a side.
function _loadAllReleases() {
  var entries;
  try { entries = fs.readdirSync(NOTES_DIR); }
  catch (e) {
    if (e && e.code === "ENOENT") _exit("release-notes/ does not exist");
    _exit("cannot read release-notes/: " + ((e && e.message) || e));
  }

  var byVersion = {};
  var sourceOf  = {};

  function _accept(release, source) {
    var v = (release && release.version) || "";
    _requireSemver(v, source + " release version");
    if (Object.prototype.hasOwnProperty.call(byVersion, v)) {
      if (!sameRelease(byVersion[v], release)) {
        _exit("v" + v + " is described twice and the two copies disagree: " +
          sourceOf[v] + " and " + source + ". Run " +
          "`node scripts/consolidate-release-notes.js --prune` to fold the hand-written " +
          "file in, or delete whichever copy is stale");
      }
      return;
    }
    byVersion[v] = release;
    sourceOf[v]  = source;
  }

  // A `.json` file under release-notes/ that neither name pattern places is
  // named rather than passed over. Dropping it silently is how a release an
  // operator wrote by hand sits in the directory, renders into no CHANGELOG
  // entry, and leaves `--check` reporting that the committed file matches
  // the notes, which it does, because the notes it matched are the ones
  // that were read.
  var unplaceable = [];

  entries.forEach(function (name) {
    if (!/\.json$/.test(name)) return;
    if (/^v\d+\.\d+\.x\.json$/.test(name)) {
      var series = _readSeries(name);
      series.releases.forEach(function (r) {
        _accept(r, "release-notes/" + name);
      });
      return;
    }
    var m = name.match(/^v(\d+\.\d+\.\d+)\.json$/);
    if (!m) {
      unplaceable.push(name);
      return;
    }
    var doc = _readJson(path.join(NOTES_DIR, name), "release-notes/" + name);
    if (doc.version !== m[1]) {
      _exit("release-notes/" + name + " declares version " + JSON.stringify(doc.version) +
        ", which is not the version its file name names");
    }
    _accept(doc, "release-notes/" + name);
  });

  if (unplaceable.length > 0) {
    _exit("release-notes/ holds " + unplaceable.length + " JSON file(s) this reader cannot " +
      "place: " + unplaceable.join(", ") + ". A release document is named " +
      "`v<X>.<Y>.<Z>.json` for one release or `v<X>.<Y>.x.json` for a minor line; anything " +
      "else renders into no CHANGELOG entry while every check here still passes. Rename it, " +
      "or move it out of release-notes/");
  }

  var all = Object.keys(byVersion).sort(_compareVersionsDesc).map(function (v) { return byVersion[v]; });
  if (all.length === 0) _exit("no releases found in release-notes/");
  return all;
}

// One version, per-release file first, then the series file for its
// line. `version` is pre-validated strict semver, so the path
// concatenation carries no metacharacters.
function _loadOne(version) {
  var perPatch = path.join(NOTES_DIR, "v" + version + ".json");
  var raw = null;
  try { raw = fs.readFileSync(perPatch, "utf8"); }
  catch (e) {
    if (!e || e.code !== "ENOENT") {
      _exit("cannot read release-notes/v" + version + ".json: " + ((e && e.message) || e));
    }
  }
  if (raw !== null) {
    var doc;
    try { doc = JSON.parse(raw); }
    catch (e2) { _exit("malformed JSON in release-notes/v" + version + ".json: " + ((e2 && e2.message) || e2)); }
    return { notes: doc, source: "v" + version + ".json" };
  }

  var minor = _minorOf(version);
  var seriesName = "v" + minor + ".x.json";
  var seriesPath = path.join(NOTES_DIR, seriesName);
  if (!fs.readdirSync(NOTES_DIR).some(function (n) { return n === seriesName; })) {
    _exit("cannot find release notes for v" + version + ". Looked at " +
      "release-notes/v" + version + ".json AND release-notes/" + seriesName);
  }
  var series = _readSeries(seriesName);
  for (var i = 0; i < series.releases.length; i += 1) {
    if (series.releases[i].version === version) {
      return { notes: series.releases[i], source: seriesName + " (releases[" + i + "])" };
    }
  }
  _exit("v" + version + " is not in release-notes/" + seriesName +
    ", so either the fold has not run or the version does not exist. " +
    "(" + seriesPath + ")");
  return null;   // unreachable
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// One release as its CHANGELOG block. The release header sits a level
// below the minor-line heading it lives under, so the document nests the
// way it reads: line, then release, then section.
function renderEntry(notes) {
  var out = [];
  out.push("### v" + notes.version + " " + EM + " " + notes.date);
  out.push("");
  out.push(notes.headline);
  out.push("");
  if (notes.summary) {
    out.push(notes.summary);
    out.push("");
  }
  _orderedSections(notes.sections).forEach(function (s) {
    out.push("#### " + s.heading);
    out.push("");
    s.items.forEach(function (it) {
      out.push("- **" + it.title + "** " + EM + " " + it.body);
    });
    out.push("");
  });
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    out.push("#### References");
    out.push("");
    notes.references.forEach(function (ref) {
      out.push("- [" + ref.label + "](" + ref.url + ")");
    });
    out.push("");
  }
  return out;
}

// The same release for a release page, where the version and date are
// already the page title. Headings move up a level and the header line
// is dropped.
function renderReleasePage(notes) {
  var out = [];
  out.push(notes.headline);
  out.push("");
  if (notes.summary) {
    out.push(notes.summary);
    out.push("");
  }
  _orderedSections(notes.sections).forEach(function (s) {
    out.push("## " + s.heading);
    out.push("");
    s.items.forEach(function (it) {
      out.push("- **" + it.title + "** " + EM + " " + it.body);
    });
    out.push("");
  });
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    out.push("## References");
    out.push("");
    notes.references.forEach(function (ref) {
      out.push("- [" + ref.label + "](" + ref.url + ")");
    });
    out.push("");
  }
  return out.join("\n").replace(/\n+$/, "\n");
}

// The whole file. Every release is validated before anything is
// rendered, so a drifted JSON anywhere in the tree fails the rebuild
// loud rather than producing a silently broken document.
// `stats`, when given, comes back carrying what this run read: how many
// releases it rendered and how many strings the leak sweep reached inside
// them. The caller publishes both.
function rebuildChangelog(stats) {
  var releases = _loadAllReleases();
  var swept    = 0;
  releases.forEach(function (r) { swept += validate(r, r.version); });
  if (stats) {
    stats.releases = releases.length;
    stats.swept    = swept;
  }

  var byMinor    = {};
  var minorOrder = [];
  releases.forEach(function (r) {
    var minor = _minorOf(r.version);
    if (!byMinor[minor]) {
      byMinor[minor] = [];
      minorOrder.push(minor);   // releases are newest first, so this is too
    }
    byMinor[minor].push(r);
  });

  var out = ["# Changelog", ""].concat(PREAMBLE, [""]);
  minorOrder.forEach(function (minor) {
    out.push("## v" + minor + ".x");
    out.push("");
    byMinor[minor].forEach(function (r) {
      out = out.concat(renderEntry(r));
    });
  });
  return out.join("\n").replace(/\n+$/, "\n");
}

// ---------------------------------------------------------------------------

/**
 * _publishCounts(stats, stream) publishes what this run read, and exits
 * non-zero when either number came back empty.
 *
 * Two units, because they fail apart. `rendered-releases` is what was
 * loaded: a discovery pointed at a directory that moved takes it to zero
 * while every rendering rule still holds over the nothing it read.
 * `swept-prose-strings` is what the leak sweep reached inside them: a
 * walker that stopped descending takes THAT to zero while the release count
 * stays healthy, and the operator-facing check reports a clean tree having
 * read no sentence in it.
 *
 * `stream` is stdout in the modes that write no artifact there, and stderr
 * in the three that do. Under `--release-page` and `--headline` the stdout
 * of this script IS the release body a workflow redirects into a file, so a
 * count line printed on it would arrive inside the published document. The
 * refusal still reaches the exit code, which is the half that gates.
 */
function _publishCounts(stats, stream) {
  var code = examinedCounts.publish([
    { unit: "rendered-releases",   n: stats.releases },
    { unit: "swept-prose-strings", n: stats.swept },
  ], { stream: stream, tag: "[generate-changelog-entry]" });
  if (code !== 0) process.exit(1);
}

function main() {
  var argv = process.argv.slice(2);
  var known = ["--rebuild", "--check", "--release-page", "--headline"];
  var explicitVersion = null;
  for (var a = 0; a < argv.length; a += 1) {
    if (argv[a].startsWith("--")) {
      // An unknown flag is refused rather than skipped. A gate invoked
      // with a flag this script does not implement would otherwise fall
      // through to "no version given, render the current one" and pass
      // on every tree there is.
      if (known.indexOf(argv[a]) === -1) {
        _exit("unknown option " + JSON.stringify(argv[a]) + ". Known options: " + known.join(" "));
      }
      continue;
    }
    if (explicitVersion === null) explicitVersion = argv[a];
  }

  var rebuildMode  = argv.indexOf("--rebuild") !== -1;
  var checkMode    = argv.indexOf("--check") !== -1;
  var pageMode     = argv.indexOf("--release-page") !== -1;
  var headlineMode = argv.indexOf("--headline") !== -1;
  if ([rebuildMode, checkMode, pageMode, headlineMode].filter(Boolean).length > 1) {
    _exit("--rebuild, --check, --release-page and --headline are mutually exclusive");
  }

  if (rebuildMode) {
    var rebuildStats = {};
    var rebuilt = rebuildChangelog(rebuildStats);
    fs.writeFileSync(CHANGELOG, rebuilt, "utf8");
    process.stderr.write("[generate-changelog-entry] OK, rebuilt CHANGELOG.md (" +
      rebuilt.length + " bytes) from release-notes/\n");
    _publishCounts(rebuildStats, process.stdout);
    return;
  }

  if (checkMode) {
    // Line endings are normalized before the comparison. The rebuilder
    // always emits LF; a checkout on a Windows runner can rewrite the
    // committed file to CRLF, and that is not drift in the notes.
    var checkStats = {};
    var expected = rebuildChangelog(checkStats);
    var actual;
    try { actual = fs.readFileSync(CHANGELOG, "utf8"); }
    catch (e) {
      if (e && e.code === "ENOENT") _exit("CHANGELOG.md does not exist. Run `--rebuild` to write it");
      _exit("cannot read CHANGELOG.md: " + ((e && e.message) || e));
    }
    if (expected.replace(/\r\n/g, "\n") === actual.replace(/\r\n/g, "\n")) {
      process.stderr.write("[generate-changelog-entry] OK, CHANGELOG.md matches the rebuild from release-notes/\n");
      _publishCounts(checkStats, process.stdout);
      return;
    }
    _exit("CHANGELOG.md drifts from release-notes/. Edit the JSON, then run " +
      "`node scripts/generate-changelog-entry.js --rebuild` and commit both");
  }

  var version = _requireSemver(
    explicitVersion || _readPackageVersion(),
    explicitVersion ? "version argument" : "package.json#version"
  );
  var loaded = _loadOne(version);
  // One release, and the strings the sweep read inside it. Published on
  // stderr below, because stdout carries the rendered artifact in every one
  // of the three modes that follow.
  var oneStats = { releases: 1, swept: validate(loaded.notes, version, loaded.source) };

  if (headlineMode) {
    process.stdout.write(loaded.notes.headline + "\n");
    process.stderr.write("[generate-changelog-entry] OK, v" + version +
      " headline from " + loaded.source + "\n");
    _publishCounts(oneStats, process.stderr);
    return;
  }

  if (pageMode) {
    var page = renderReleasePage(loaded.notes);
    process.stdout.write(page);
    process.stderr.write("[generate-changelog-entry] OK, rendered the v" + version +
      " release page (" + page.length + " chars) from " + loaded.source + "\n");
    _publishCounts(oneStats, process.stderr);
    return;
  }

  var block = renderEntry(loaded.notes).join("\n").replace(/\n+$/, "\n");
  process.stdout.write(block);
  process.stderr.write("[generate-changelog-entry] OK, rendered the v" + version +
    " entry (" + block.length + " chars) from " + loaded.source +
    ". Use --rebuild to write CHANGELOG.md, --check to gate drift, " +
    "--release-page for release-page markdown.\n");
  _publishCounts(oneStats, process.stderr);
}

main();
