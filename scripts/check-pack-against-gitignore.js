// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// prepack guard: two questions about the tarball, both asked against the
// file list `npm pack` actually produces rather than against the `files`
// array somebody wrote.
//
// 1. Is any packed path gitignored, in the repository or globally? A file
//    that reaches the tarball while the repository refuses to track it is
//    a local artifact being published by accident.
//
// 2. Does every document in the tarball resolve its own links inside the
//    tarball? A relative link in a shipped document is a promise that the
//    file sits beside it. When it does not, the reader who installed the
//    package and followed its own instructions gets nothing, and the
//    document most likely to be linked that way is the one the project
//    wrote to be honest about what is unfinished.
//
// The second question is asked by resolving links rather than by holding
// a list of documents that ought to ship. A list is the part that goes
// stale: it was `files` in package.json, and it stayed correct-looking
// while three documents the README, SECURITY.md, the operator guide and
// the changelog all point at were absent from every tarball.
//
// `--ignore-scripts` on the inner pack call avoids re-triggering this
// hook.

var cp   = require("node:child_process");
var fs   = require("node:fs");
var path = require("node:path");

var examinedCounts = require("./examined-counts.js");

var ROOT = path.resolve(__dirname, "..");

// Generated artifacts intended to ship in the tarball. These are
// gitignored on purpose (so a stray local generation doesn't pollute
// the repo) but are listed in package.json `files` because the CI
// workflow generates them just-in-time before publish. Skip the guard
// for these specific paths.
var GENERATED_ALLOWED = new Set([
  "sbom.cdx.json",
]);

// Every way a markdown document names something to open: the inline
// link, which is also the image form, a reference definition, and the
// HTML attributes markdown lets through untouched. All four are matched
// because a document only has to reach for one of them to make a promise
// the tarball cannot keep.
// A form the reader does not know is not reported as a broken link. It is
// reported as nothing, and the run prints the same clean sentence it
// prints over a document with nothing wrong in it, so every form left out
// here is one a document may use freely without ever being checked.
var LINK_FORMS = [
  /\[[^\]]*\]\(\s*<?([^)>\s]+)>?(?:\s+["'][^"']*["'])?\s*\)/g,
  /^\s*\[[^\]]+\]:\s*<?([^>\s]+)>?/g,
  // An attribute, quoted either way or not at all. Markdown passes the
  // tag through untouched and a browser does not care which quote was
  // used, so a reader that knows only one of the three answers for
  // whichever spelling the author happened to pick.
  /(?:href|src)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))/g,
  // A destination wrapped in angle brackets, which is how CommonMark
  // section 6.3 lets a path carry a space. The inline form above stops at
  // the first space, so `[the guide](<./docs/operator guide.md>)` reaches
  // it as a target that ends mid-name and resolves to a file nobody
  // meant. Both forms match the bracketed shape without a space in it and
  // the duplicate is dropped below, so this one is free to be the
  // permissive half.
  /\[[^\]]*\]\(\s*<([^>]+)>\s*\)/g,
  /^\s*\[[^\]]+\]:\s*<([^>]+)>\s*$/g,
];

// There is deliberately no autolink form here, and the reason is worth
// keeping because the shape invites one.
//
// CommonMark section 6.5 makes an autolink an absolute URI: `<...>` is a
// link only when what it wraps carries a scheme. So every autolink a
// document can contain is one `_isExternal` drops, and a form written to
// catch them can only ever match something that is NOT an autolink. What
// it matches instead is ordinary markup. `</a>` and `</div>` begin with a
// slash and look exactly like a relative path, so the finding it produces
// is confident, precise and about nothing: a badge row reported as seven
// missing files named `a` and `div`.
//
// A relative target in angle brackets is not a link on any renderer this
// project's documents are read on. It renders as the literal text
// somebody typed, so there is no promise there to keep.

// Text that is not prose and cannot be a link. Inside a fence and inside
// a backticked span the characters are literal, so `arr[a](x)` in a code
// sample has the shape of a link and is a subscript followed by a call.
// Reading them as links reports findings nobody can fix without breaking
// the sample.
//
// The fence is tracked by its character and its length rather than by a
// boolean, because CommonMark section 4.5 closes a fence only with the
// same character at the same length or longer. A single flag flipped by
// either character closes a backtick fence with a tilde one, and from
// that line on the document is read inside out: prose counts as code and
// every link in it goes unread. That failure is silent and it lands on
// the largest documents first, because they hold the most fences.
var FENCE_OPEN_RE  = /^ {0,3}(`{3,}|~{3,})/;
var INLINE_CODE_RE = /`[^`\n]*`/g;

// A heading, and the anchor a renderer gives it. Both halves are needed:
// a link naming a section is a promise about a place in a document, and
// resolving the file half while dropping the fragment answers a question
// nobody asked. The reader who follows it opens the right document at the
// top and hunts for a section that is not there.
var HEADING_RE = /^ {0,3}(#{1,6})\s+(.*)$/;

// A section reached without a heading, which is how a document names a
// place a renderer would not have given an anchor to.
var EXPLICIT_ANCHOR_RE = /(?:id|name)\s*=\s*(?:"([^"]+)"|'([^']+)')/g;

// The vendored framework, whose documents are upstream's and are read
// only here. They link within their own published layout, and this
// repository ships a subset of it, so a target they name that the
// tarball does not carry is a fact about that subset rather than a
// promise this repository made. Nothing here can fix one, and a gate
// reporting what it forbids anybody to change is a gate people learn to
// skip past.
var VENDOR_PREFIX = "lib/vendor/";

// A target this guard cannot answer for, and must not pretend to. An
// absolute URL leaves the tarball by design, a fragment names a heading
// in the document holding it, and a scheme is somebody else's namespace.
function _isExternal(target) {
  return target === "" || /^[a-z][a-z0-9+.-]*:/i.test(target);
}

// The fence state of a line, given the state before it. Returns the fence
// that is open after this line, or null when none is.
function _fenceAfter(open, rawLine) {
  if (open === null) {
    var opened = FENCE_OPEN_RE.exec(rawLine);
    if (!opened) return null;
    return { marker: opened[1].charAt(0), length: opened[1].length };
  }
  var closing = FENCE_OPEN_RE.exec(rawLine);
  if (closing && closing[1].charAt(0) === open.marker &&
      closing[1].length >= open.length &&
      rawLine.slice(rawLine.indexOf(closing[1]) + closing[1].length).trim() === "") {
    return null;
  }
  return open;
}

// The anchor a renderer gives one heading. Markdown that renders as
// something else is rendered first, because the anchor is built from what
// a reader sees: inline code shows its contents, a link shows its text,
// an inline tag shows nothing. What is left is lowercased, stripped of
// the punctuation an anchor cannot carry, and joined with hyphens.
function _slug(heading) {
  var text = String(heading)
    .replace(/`([^`]*)`/g, "$1")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/[*_~]/g, "")
    .replace(/\s+#+\s*$/, "")
    .trim()
    .toLowerCase();
  return text.replace(/[^a-z0-9 \-_]/g, "").replace(/\s/g, "-");
}

// Every place in a document a link may name. Headings give one each, and
// two that slug alike are numbered the way a renderer numbers them, so a
// link to the second is answerable rather than reported as broken. An
// explicit `id` or `name` counts too, because that is how a document
// names a place no heading covers.
//
// Fenced lines are skipped for the same reason `_targetsIn` skips them: a
// `## heading` inside a code sample is a sample, and treating it as an
// anchor would let a broken link resolve against a place no reader can
// reach.
function _anchorsIn(text) {
  var out  = [];
  var seen = new Map();
  var open = null;
  String(text).split(/\r?\n/).forEach(function (rawLine) {
    var before = open;
    open = _fenceAfter(open, rawLine);
    if (before !== null || open !== null) return;

    var heading = HEADING_RE.exec(rawLine);
    if (heading) {
      var slug = _slug(heading[2]);
      if (slug !== "") {
        var already = seen.get(slug) || 0;
        seen.set(slug, already + 1);
        out.push(already === 0 ? slug : slug + "-" + already);
      }
    }

    EXPLICIT_ANCHOR_RE.lastIndex = 0;
    var m;
    while ((m = EXPLICIT_ANCHOR_RE.exec(rawLine)) !== null) {
      var id = m[1] || m[2];
      if (id) out.push(String(id).toLowerCase());
    }
  });
  return out;
}

function _run(cmd, args, opts) {
  return cp.spawnSync(cmd, args, Object.assign({ encoding: "utf8" }, opts || {}));
}

function _fail(lines) {
  lines.forEach(function (l) { process.stderr.write(l + "\n"); });
  process.exit(1);
}

// The packed file list, straight from npm.
function _packedPaths() {
  // shell-form: Node 22+ rejects spawning npm.cmd directly on Windows,
  // and `shell: true` with a separate args array trips DEP0190.
  var pack = _run("npm pack --dry-run --ignore-scripts --json", [], { shell: true });
  if (pack.status !== 0) {
    _fail(["[prepack-guard] npm pack --dry-run failed:", pack.stderr || ""]);
  }
  var info;
  try { info = JSON.parse(pack.stdout); }
  catch (_e) {
    _fail(["[prepack-guard] could not parse npm pack output"]);
  }
  var entry = Array.isArray(info) ? info[0] : info;
  var files = (entry && entry.files) || [];
  if (files.length === 0) {
    _fail(["[prepack-guard] npm pack reported zero files"]);
  }
  return files.map(function (f) { return String(f.path).replace(/\\/g, "/"); });
}

// ---------------------------------------------------------------------------

function _checkNotGitignored(packed) {
  var paths = packed.filter(function (p) { return !GENERATED_ALLOWED.has(p); });

  // Nothing left to ask about. `npm pack` reporting no file at all is refused
  // upstream of here, so reaching this means the filter above consumed the
  // whole list: a tarball made of nothing but generated artifacts, or a
  // GENERATED_ALLOWED that grew until it covered everything. Either way the
  // sentence below would report that every packed path was checked and none
  // was gitignored, over a list of none.
  if (paths.length === 0) {
    _fail([
      "[prepack-guard] every packed path is on the generated-artifact allowlist, so there was " +
      "nothing left to check against .gitignore. A tarball carrying no source file is the " +
      "finding, and so is an allowlist that grew to cover the whole pack list.",
    ]);
  }

  var check = _run("git", ["check-ignore", "--verbose", "--no-index", "--stdin"], {
    input: paths.join("\n") + "\n",
  });

  if (check.status === 1) {
    process.stdout.write(
      "[prepack-guard] ok, " + paths.length + " paths checked, none gitignored\n");
    return paths.length;
  }
  if (check.status !== 0) {
    _fail(["[prepack-guard] git check-ignore failed:", check.stderr || ""]);
  }

  // `git check-ignore -v` reports the LAST matching gitignore line,
  // including negation (`!`) rules, but the command exits 0 even
  // when the matching line UNIGNORES the path. A `!`-prefixed pattern
  // means the file is NOT actually ignored, so it's safe to ship in
  // the tarball. Output format: `.gitignore:LINE:PATTERN<TAB>PATH`.
  var lines = (check.stdout || "").split("\n").filter(Boolean);
  var actuallyIgnored = lines.filter(function (l) {
    var m = l.match(/^[^:]+:\d+:([^\t]*)\t/);
    if (!m) return true;
    return m[1].charAt(0) !== "!";
  });
  if (actuallyIgnored.length > 0) {
    _fail(["[prepack-guard] gitignored paths in tarball:"].concat(
      actuallyIgnored.map(function (l) { return "  " + l; })));
  }
  process.stdout.write(
    "[prepack-guard] ok, " + paths.length + " paths checked, " +
    lines.length + " matched a `!`-negation rule (allowed)\n");
  return paths.length;
}

// ---------------------------------------------------------------------------

// The separator inside the dedup key below, built rather than typed so
// this file carries no control byte of its own. A control character
// cannot appear in a line index or in a link target, so a key joined on
// one cannot collide with a target that happens to contain the
// separator.
var KEY_SEPARATOR = String.fromCharCode(0);

// Every link target a document names, with the line it sits on, so a
// finding points at the sentence rather than at the file.
function _targetsIn(text) {
  var out  = [];
  var seen = new Set();
  var open = null;
  text.split(/\r?\n/).forEach(function (rawLine, i) {
    // Both delimiters and everything between them are code rather than
    // prose, so a line carries links only when no fence was open before
    // it and none is open after it. Tracking the marker and its length
    // through `_fenceAfter` rather than toggling a boolean is what keeps
    // a nested or longer fence from closing the wrong block.
    var before = open;
    open = _fenceAfter(open, rawLine);
    if (before !== null || open !== null) return;
    var line = rawLine.replace(INLINE_CODE_RE, " ");
    LINK_FORMS.forEach(function (form) {
      form.lastIndex = 0;
      var m;
      while ((m = form.exec(line)) !== null) {
        // One capture group per spelling of the same form, so the target
        // is whichever of them matched.
        var target = m[1] === undefined ? (m[2] === undefined ? m[3] : m[2]) : m[1];
        if (target === undefined || _isExternal(target)) continue;
        // Two forms can describe one link: a bracketed destination with
        // no space in it matches the permissive form and the inline one
        // alike. Counting it twice would inflate what this run says it
        // examined, and report one broken link as two.
        if (seen.has(i + KEY_SEPARATOR + target)) continue;
        seen.add(i + KEY_SEPARATOR + target);
        out.push({ target: target, line: i + 1 });
      }
    });
  });
  return out;
}

// True when the tarball carries the thing a target names, as a file or
// as a directory somebody linked to with a trailing slash.
function _packedCarries(packed, rel) {
  if (packed.has(rel)) return true;
  var asDir = rel.replace(/\/+$/, "") + "/";
  var found = false;
  packed.forEach(function (p) { if (p.indexOf(asDir) === 0) found = true; });
  return found;
}

// The pack list, read once. Two callers ask for it and `npm pack` is not
// cheap, so the answer is kept rather than asked for twice; nothing here
// writes, so one reading is the same as two.
var _packedOnce = null;

function _packed() {
  if (_packedOnce === null) _packedOnce = _packedPaths();
  return _packedOnce;
}

// The documents the tarball carries and this repository is answerable
// for.
function _packedMarkdown() {
  return _packed().filter(function (p) {
    return /\.md$/i.test(p) && p.indexOf(VENDOR_PREFIX) !== 0;
  });
}

// A document's text, read once per run.
var _textCache = new Map();

function _textOf(rel) {
  if (_textCache.has(rel)) return _textCache.get(rel);
  var text;
  // A document the pack list names and the working tree will not open is
  // reported by the caller rather than thrown from here, so a null is an
  // answer this returns rather than a failure it raises.
  try { text = fs.readFileSync(path.join(ROOT, rel), "utf8"); }
  catch (_e) { text = null; }
  _textCache.set(rel, text);
  return text;
}

// A fragment as the document holding it spells it. Percent-encoding is
// decoded because a browser decodes it before matching, and a fragment
// that will not decode is left alone rather than guessed at.
function _fragmentOf(target) {
  var hash = target.indexOf("#");
  if (hash === -1) return "";
  var raw = target.slice(hash + 1);
  try { return decodeURIComponent(raw); } catch (_e) { return raw; }
}

/**
 * Every promise the shipped documents make that the tarball does not
 * keep, as lines a reader can act on.
 *
 * A link has two halves and both are a promise. The file half says the
 * document is beside this one; the section half says there is a place in
 * it to land on. Resolving the first and discarding the second answers a
 * question nobody asked: the reader follows the link, the right document
 * opens at the top, and they hunt for a section that is not there.
 */
function _brokenLinks(docs) {
  var packed = new Set(_packed());
  var broken = [];
  var links  = 0;
  var frags  = 0;

  docs.forEach(function (doc) {
    var text = _textOf(doc);
    if (text === null) {
      broken.push(doc + ": packed but unreadable from the working tree");
      return;
    }
    _targetsIn(text).forEach(function (hit) {
      links += 1;
      var rel      = hit.target.split("#")[0].split("?")[0];
      var fragment = _fragmentOf(hit.target);
      var where    = doc + ":" + hit.line + ": " + hit.target;

      // A bare fragment names a place in the document holding it, which
      // is what a table of contents is built out of.
      var inDocument = rel === "";
      var resolved = inDocument ? doc : path.posix.normalize(
        path.posix.join(path.posix.dirname(doc), rel)).replace(/^\.\//, "");

      if (!inDocument) {
        if (!_packedCarries(packed, resolved)) {
          broken.push(where + " is not in the tarball (resolves to " + resolved + ")");
          return;
        }
      }
      if (fragment === "") return;

      // Only a markdown document has anchors this can read. A fragment on
      // anything else is somebody else's format, and reporting one would
      // be a verdict over a file this cannot open.
      if (!/\.md$/i.test(resolved)) return;
      var targetText = inDocument ? text : _textOf(resolved);
      if (targetText === null) return;

      frags += 1;
      if (_anchorsIn(targetText).indexOf(fragment) === -1) {
        broken.push(where + " names a section " +
          (inDocument ? "of its own document" : "of " + resolved) +
          " that does not exist");
      }
    });
  });

  _brokenLinks.lastCounts = { links: links, fragments: frags };
  return broken;
}

function _checkLinksResolve() {
  var docs = _packedMarkdown();
  if (docs.length === 0) {
    _fail([
      "[prepack-guard] the tarball carries no markdown document, so the link check " +
      "answered for nothing. Either the pack list stopped resolving or every document " +
      "was dropped from it, and both of those are the finding.",
    ]);
  }

  var broken = _brokenLinks(docs);
  var counts = _brokenLinks.lastCounts;

  // A document set that resolved no link at all. The sentence below is true of
  // that run in the same words it uses over a tarball whose every link was
  // followed, and the document set being non-empty is not the same assurance:
  // the walk above proves documents were FOUND, this proves they were READ.
  // Every way the reader can stop matching lands here rather than on a finding:
  // a LINK_FORMS entry that stopped compiling to what markdown now emits, a
  // fence tracker that swallowed the body of every file, an `_isExternal` that
  // widened until it dropped every relative path. Each leaves a confident
  // report about nothing.
  //
  // This repository's shipped documents link to each other by construction: the
  // README, SECURITY.md, the operator guide and the changelog all name files
  // beside them, which is the promise this check exists to hold them to. Zero is
  // therefore never the healthy answer here, and it is refused rather than
  // stated.
  if (counts.links === 0) {
    _fail([
      "[prepack-guard] " + docs.length + " packed document(s) were read and not one link was " +
      "found in any of them, so the link check answered for nothing. Every shipped document " +
      "here names files beside it, so this is the link reader having stopped matching rather " +
      "than a tarball with nothing to check.",
    ]);
  }

  if (broken.length > 0) {
    _fail([
      "[prepack-guard] shipped documents make promises the tarball does not keep:",
    ].concat(broken.map(function (l) { return "  " + l; })).concat([
      "",
      "Add the file to package.json `files`, or stop linking to it from a document " +
      "that ships. A relative link in the tarball is a promise the file is beside it, " +
      "and the part after a # is a promise about a place inside it.",
    ]));
  }
  process.stdout.write(
    "[prepack-guard] ok, " + counts.links + " links in " + docs.length +
    " packed document(s) all resolve inside the tarball, " + counts.fragments +
    " of them naming a section that is there\n");
  return { docs: docs.length, links: counts.links, fragments: counts.fragments };
}

// ---------------------------------------------------------------------------

function main() {
  var checked = _checkNotGitignored(_packed());
  var resolved = _checkLinksResolve();

  // What this run looked at, so a clean verdict over an empty set is
  // visible as the zero it is rather than as a pass.
  //
  // The sections are counted apart from the links carrying them. A run
  // that read every link and resolved no section at all is a shape one
  // number covering both would report as healthy.
  //
  // Publishing them is not the same as gating on them, and this script is
  // where that difference bites. It runs as the `prepack` hook, so its
  // caller is `npm publish` and its caller reads an exit code and nothing
  // else: a count printed for a reader that never arrives protects
  // nothing. The refusal therefore reaches the exit code here, in the
  // gate, and the published lines are what a caller that DOES capture
  // stdout can hold it to as well.
  //
  // Three of the four are refused outright. `document-sections` is the one
  // that is stated instead, and the line between them is whether the
  // repository controls the number. Paths, documents and links exist by
  // construction in anything this package can ship. A fragment is a choice
  // the author of a sentence made, and there are five of them; a correct
  // documentation edit could take that to zero, and a gate that failed the
  // publish for it would be asking somebody to add a `#anchor` to a link
  // that did not need one, purely so a check would stop talking.
  var code = examinedCounts.publish([
    { unit: "packed-paths",      n: checked },
    { unit: "packed-documents",  n: resolved.docs },
    { unit: "document-links",    n: resolved.links },
    {
      unit:   "document-sections",
      n:      resolved.fragments,
      zeroIs: "a fragment is a property of the shipped prose rather than of this reader, and " +
              "the documents carry only a handful. Zero means no link named a section, which a " +
              "correct documentation edit can produce; the links themselves are refused at zero " +
              "and they are what proves the reader still matches",
    },
  ], { tag: "[prepack-guard]" });

  if (code !== 0) process.exit(1);
}

module.exports = {
  _targetsIn:      _targetsIn,
  _isExternal:     _isExternal,
  _packedCarries:  _packedCarries,
  _anchorsIn:      _anchorsIn,
  _slug:           _slug,
  _packedMarkdown: _packedMarkdown,
  _brokenLinks:    _brokenLinks,
};

if (require.main === module) main();
