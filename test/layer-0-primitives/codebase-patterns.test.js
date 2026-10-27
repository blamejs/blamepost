// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * codebase-patterns: the repository's own static gate.
 *
 * Some disciplines are about the SHAPE of the source rather than the
 * behavior of one primitive, so no unit test can express them. Each
 * one is encoded here as a scan over the tree, and a regression is
 * caught at commit time instead of in review.
 *
 * A detector is four things, and none of them is optional:
 *
 *   name         the identifier an allow marker names, and the label
 *                the summary prints
 *   description  the invariant, why breaking it is a bug, and what to
 *                write instead
 *   scan         the matcher, run over one file record at a time
 *   red          at least one fixture the matcher MUST fire on
 *
 * The red fixtures run on every invocation, before the live scan, from
 * strings held in this file rather than from files on disk. A detector
 * that has quietly stopped matching is the worst failure mode there is,
 * because it reports green forever, so proving each matcher fires is
 * part of the run rather than a thing someone did once. Where a near
 * miss is instructive, a `green` fixture pins the shape that must NOT
 * fire.
 *
 * Scope is per detector, declared as the top-level directories it
 * walks. `lib/vendor/` is skipped everywhere: the vendored framework is
 * read-only and its conventions are upstream's. A detector that reads
 * prose rather than code widens that scope two ways: `exts` replaces the
 * default JavaScript-only file filter, and `includeRepoRoot` adds the
 * files sitting directly in the repository root, which is where the
 * README, the governance documents and most of the configuration live.
 *
 * A matcher that has to know where a block ends, which argument of a
 * call is the first one, or which object literal a key sits inside does
 * not do it with a regular expression and a character budget. It walks
 * brackets instead, over the masked copy of the source built below,
 * because a budget standing in for a structural boundary stops matching
 * as soon as the code it reads grows past the budget, and a matcher
 * that has quietly stopped matching reports green forever.
 *
 * A few detectors carry one permitted site rather than one permitted
 * directory, where the rule is about which module owns an operation.
 * Those are named as paths in SITE_EXCEPTIONS and printed with the rest,
 * so an exclusion is visible in the run.
 *
 * Exceptions are written down at the site that needs them, never here:
 *
 *   1. File-level, within the first 50 lines of the file:
 *        // codebase-patterns:allow-file <name> reason
 *      Skips every match of that detector in that file.
 *
 *   2. Per line, on the match line or up to two lines above it:
 *        ... // allow:<name> reason
 *      Skips that single match.
 *
 * Both forms name a REGISTERED detector, and a marker naming an
 * unregistered one is itself a violation: a typo suppresses nothing,
 * so the code it was meant to cover ships unflagged.
 *
 * This file excludes itself from every scan. It holds each matcher's
 * literals and each red fixture by construction, so scanning it would
 * report the detector definitions as violations of themselves.
 *
 * Run it on its own with `node test/layer-0-primitives/codebase-patterns.test.js`.
 * Full output lands in `.test-output/codebase-patterns.log`.
 */

var fs      = require("node:fs");
var path    = require("node:path");
var helpers = require("../helpers");
var check   = helpers.check;

// The schema declaration, for the one detector below that derives its
// matcher from a frozen list rather than spelling the list out. Reading
// the source of truth is what keeps a status added to the store from
// arriving here as a hole nobody edits.
var tables  = require("../../lib/store/tables");

// The vocabulary gate, for its `word` decoder. The input-validation labels
// end in a word that gate refuses in every file, so the detector below
// that names those labels builds the word from parts with `word`.
var vocabulary = require("../../scripts/check-forbidden-vocabulary.js");

var REPO_ROOT = helpers.REPO_ROOT;
var SELF_REL  = "test/layer-0-primitives/codebase-patterns.test.js";

// Built rather than typed, so this file's own bytes stay free of the
// punctuation the detector refuses.
var EM_DASH = String.fromCharCode(0x2014);
var EN_DASH = String.fromCharCode(0x2013);

// The same construction, for the control characters. A red fixture for
// `raw-control-byte-in-text` has to CARRY the byte it proves the matcher
// fires on, and typing one here would make this file the next thing the
// detector reports. Building it is also the convention the detector
// exists to enforce, so the fixtures are written the way the tree is.
var NUL       = String.fromCharCode(0x00);
var VTAB      = String.fromCharCode(0x0b);
var ESCAPE    = String.fromCharCode(0x1b);
var DELETE_CH = String.fromCharCode(0x7f);

// ---------------------------------------------------------------------------
// File-tree walking
// ---------------------------------------------------------------------------

var SKIP_DIRS = {
  "vendor":       1,
  "node_modules": 1,
  ".git":         1,
  ".test-output": 1,
  ".scratch":     1,
  ".references":  1,
  "data":         1,
};

// The default file filter. Most detectors read JavaScript, so a
// detector that says nothing about extensions gets exactly that.
var JS_EXT_RE = /\.js$/;

// The file filter a prose detector uses: every text format the tree
// carries an operator-readable sentence in. The extensionless and
// dot-prefixed names are listed separately because a name like
// `.editorconfig` or `NOTICE` has no extension to match on.
var PROSE_EXT_RE  = /\.(?:js|mjs|cjs|md|ya?ml|json|toml|sh|html|css)$/;
var PROSE_NAME_RE = /^(?:Dockerfile|NOTICE|LICENSE|Caddyfile|\.editorconfig|\.dockerignore|\.gitattributes|\.gitignore|\.npmrc|\.nvmrc)$/;

function _matchesFilter(name, extRe, nameRe) {
  if (extRe.test(name)) return true;
  return nameRe ? nameRe.test(name) : false;
}

function _walk(dir, files, extRe, nameRe) {
  files = files || [];
  extRe = extRe || JS_EXT_RE;
  if (SKIP_DIRS[path.basename(dir)]) return files;
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return files; }
  for (var i = 0; i < entries.length; i++) {
    var full = path.join(dir, entries[i].name);
    if (entries[i].isDirectory()) _walk(full, files, extRe, nameRe);
    else if (_matchesFilter(entries[i].name, extRe, nameRe)) files.push(full);
  }
  return files;
}

// The files sitting directly in the repository root, without descending.
// `_walk` cannot do this: from the root it would walk the whole tree,
// including the directories no detector declares.
function _rootFiles(extRe, nameRe) {
  var out = [];
  var entries;
  try { entries = fs.readdirSync(REPO_ROOT, { withFileTypes: true }); }
  catch (_e) { return out; }
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].isDirectory()) continue;
    if (!_matchesFilter(entries[i].name, extRe, nameRe)) continue;
    out.push(path.join(REPO_ROOT, entries[i].name));
  }
  return out;
}

function _relPath(absPath) {
  return path.relative(REPO_ROOT, absPath).replace(/\\/g, "/");
}

var _fileCache = {};

// One record per file: the relative path for reporting, the raw text
// for content-shape matchers, and the split lines for line matchers.
function _readRecord(abs) {
  var rel = _relPath(abs);
  if (_fileCache[rel]) return _fileCache[rel];
  var text;
  // A read fault is refused rather than answered with empty text. Empty text
  // is a file every detector reads as clean, and it still counts toward the
  // total each one publishes, so a locked or vanished file would buy itself a
  // pass from all 100 at once with nothing in the output to say so.
  try { text = fs.readFileSync(abs, "utf8"); }
  catch (e) {
    throw new Error("codebase-patterns: " + rel + " was found by the walk and could not be " +
      "read (" + (e && e.code ? e.code : "read fault") + "). A file this gate cannot open is " +
      "not a file it can report clean.");
  }
  var rec = { rel: rel, abs: abs, text: text, lines: text.split(/\r?\n/) };
  _fileCache[rel] = rec;
  return rec;
}

var _dirCache = {};

function _filesUnder(dirNames, opts) {
  opts = opts || {};
  var extRe  = opts.exts || JS_EXT_RE;
  var nameRe = opts.exts ? PROSE_NAME_RE : null;
  var key = dirNames.join(",") + "|" + extRe.source + "|" + (opts.includeRepoRoot ? "root" : "");
  if (_dirCache[key]) return _dirCache[key];
  var out = [];
  var seen = {};
  function _take(abs) {
    var rec = _readRecord(abs);
    if (rec.rel === SELF_REL) return;
    if (seen[rec.rel]) return;
    seen[rec.rel] = 1;
    out.push(rec);
  }
  dirNames.forEach(function (d) {
    _walk(path.join(REPO_ROOT, d), [], extRe, nameRe).forEach(_take);
  });
  if (opts.includeRepoRoot) _rootFiles(extRe, nameRe).forEach(_take);
  out.sort(function (a, b) { return a.rel < b.rel ? -1 : (a.rel > b.rel ? 1 : 0); });
  _dirCache[key] = out;
  return out;
}

// ---------------------------------------------------------------------------
// Line classification
// ---------------------------------------------------------------------------

// True when the whole line is comment text: a `//` line, a `/*` opener,
// or a `*` continuation inside a block comment.
function _isCommentLine(line) {
  return /^\s*(?:\/\/|\*|\/\*)/.test(line);
}

// The comment portion of a line, or "" when there is none. A trailing
// `//` counts only when the quotes before it balance, so a `//` inside
// a string literal (a URL, a path fragment) is left alone.
function _commentOf(line) {
  if (_isCommentLine(line)) return line.trim();
  var i = line.indexOf("//");
  while (i !== -1) {
    var before = line.slice(0, i);
    var dq = (before.match(/"/g) || []).length;
    var sq = (before.match(/'/g) || []).length;
    var bt = (before.match(/`/g) || []).length;
    if (dq % 2 === 0 && sq % 2 === 0 && bt % 2 === 0 && !/[A-Za-z]:$/.test(before)) {
      return line.slice(i);
    }
    i = line.indexOf("//", i + 2);
  }
  return "";
}

// The code portion of a line: the comment tail removed, so a detector
// scanning code does not fire on prose describing the shape it bans.
function _codeOf(line) {
  if (_isCommentLine(line)) return "";
  var comment = _commentOf(line);
  return comment ? line.slice(0, line.length - comment.length) : line;
}

// What a line holds when the whole line is a `//` comment: the marker
// and the indentation removed, or "" when the line is anything else.
//
// The three comment surfaces are different places and this reads one of
// them. Code is disabled by commenting the lines it occupies, which puts
// the disabled statement at the head of its own line. A block comment is
// where a usage example is written, so whole call statements appear
// there verbatim under `@example` and mean the opposite thing. A comment
// on the end of a line of code sits beside a statement that still runs.
function _lineCommentBody(line) {
  if (!/^\s*\/\//.test(line)) return "";
  return line.trim().replace(/^\/\/+\s?/, "").trim();
}

// Whether a fragment leaves a parenthesis open, so whatever it begins
// carries on past the end of it.
function _leavesParenOpen(text) {
  var open = 0;
  for (var i = 0; i < text.length; i += 1) {
    var c = text.charAt(i);
    if (c === "(") open += 1;
    else if (c === ")") open -= 1;
  }
  return open > 0;
}

// ---------------------------------------------------------------------------
// Prose runs
// ---------------------------------------------------------------------------
//
// A detector that reads a SENTENCE rather than a token cannot read one
// line at a time. Prose in this tree wraps at the comment margin, so the
// word that decides what a phrase means is routinely on the line above
// it: "before it is / used to narrow anything" is an instrument and
// "so frozen rows / used to make every message" is a claim about the
// past, and the two are the same four characters once the line break has
// thrown the subject away.
//
// So the two places a source file carries a sentence are collected into
// runs first. A run is the consecutive lines that each carry prose of one
// kind, joined with a space, with the source line every character came
// from recorded beside it, so a match still reports the line it sits on.
// Everything else on the line is dropped rather than masked: an
// identifier and a call are not sentences, and reading them is how a
// prose matcher fires on code.

// The decoration at the head of a comment line, and the tail of a block
// comment. Removed so the run reads as the sentence somebody wrote.
var COMMENT_HEAD_RE = /^\s*(?:\/\*+|\*+\/|\/\/+|\*+)\s?/;
var COMMENT_TAIL_RE = /\s*\*+\/\s*$/;

function _commentProse(line) {
  var text = _commentOf(line);
  if (!text) return "";
  return text.replace(COMMENT_HEAD_RE, "").replace(COMMENT_TAIL_RE, "").trim();
}

// The contents of every string literal on the line, which is where an
// operator-facing sentence lives when it is a refusal, a report line or
// a check label rather than a comment. A literal left open at the end of
// the line contributes nothing, which is the safe direction: a matcher
// reading past the quote would be reading code.
var STRING_LITERAL_RE = /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`([^`\\]|\\.)*`/g;

function _stringProse(line) {
  var code = _codeOf(line);
  if (!code) return "";
  var out = [];
  STRING_LITERAL_RE.lastIndex = 0;
  var m;
  while ((m = STRING_LITERAL_RE.exec(code)) !== null) {
    var body = m[1] !== undefined ? m[1] : m[2];
    if (body === undefined) body = m[0].slice(1, -1);
    if (body) out.push(body);
    if (m.index === STRING_LITERAL_RE.lastIndex) STRING_LITERAL_RE.lastIndex += 1;
  }
  return out.join(" ");
}

// One run: the joined text, and a parallel array holding the source line
// each character came from. The array is built alongside the string
// rather than recomputed by counting newlines, because the run has no
// newlines left in it to count.
function _joinRun(chunks) {
  var text  = "";
  var index = [];
  chunks.forEach(function (c, i) {
    var k;
    if (i > 0) { text += " "; index.push(c.line); }
    text += c.text;
    for (k = 0; k < c.text.length; k++) index.push(c.line);
  });
  return { text: text, index: index };
}

function _proseRuns(file) {
  var runs = [];
  [_commentProse, _stringProse].forEach(function (extract) {
    var chunks = [];
    function flush() {
      if (chunks.length) { runs.push(_joinRun(chunks)); chunks = []; }
    }
    for (var i = 0; i < file.lines.length; i++) {
      var text = extract(file.lines[i]);
      if (text) chunks.push({ text: text, line: i + 1 });
      else flush();
    }
    flush();
  });
  return runs;
}

// How much of the run either side of a match is reported. A bare match
// of four words names the shape and not the sentence, and the reader of
// the log is deciding whether a sentence is a claim about the past or a
// participle, which takes the clause around it.
var PROSE_CONTEXT_BEFORE = 48;
var PROSE_CONTEXT_AFTER  = 64;

// Runs every named shape over every run in the file. Shapes are
// `{ name, re }` with a global regular expression; a place two shapes
// both reach is reported once.
function _proseShapeMatcher(shapes) {
  return function (file) {
    var out  = [];
    var seen = {};
    _proseRuns(file).forEach(function (run) {
      shapes.forEach(function (shape) {
        shape.re.lastIndex = 0;
        var m;
        while ((m = shape.re.exec(run.text)) !== null) {
          var line = run.index[m.index];
          var key  = line + "|" + m.index + "|" + m[0];
          if (!seen[key]) {
            seen[key] = 1;
            var from = Math.max(0, m.index - PROSE_CONTEXT_BEFORE);
            var to   = Math.min(run.text.length, m.index + m[0].length + PROSE_CONTEXT_AFTER);
            out.push({
              file:    file.rel,
              line:    line,
              content: "[" + shape.name + "] " + (from > 0 ? "..." : "") +
                       run.text.slice(from, to).replace(/\s+/g, " ").trim(),
            });
          }
          if (m.index === shape.re.lastIndex) shape.re.lastIndex += 1;
        }
      });
    });
    out.sort(function (a, b) { return a.line - b.line; });
    return out;
  };
}

// ---------------------------------------------------------------------------
// Matcher builders
// ---------------------------------------------------------------------------

// where: "any" scans the whole line, "code" the code portion, "comment"
// the comment portion.
function _lineMatcher(regex, where) {
  return function (file) {
    var out = [];
    for (var i = 0; i < file.lines.length; i++) {
      var line = file.lines[i];
      var subject = line;
      if (where === "comment") subject = _commentOf(line);
      else if (where === "code") subject = _codeOf(line);
      if (subject && regex.test(subject)) {
        out.push({ file: file.rel, line: i + 1, content: line.trim() });
      }
    }
    return out;
  };
}

function _lineOfIndex(text, index) {
  var upTo = text.slice(0, index);
  return upTo.split(/\r?\n/).length;
}

// For shapes that span lines. The regex must carry the `g` flag; its
// lastIndex is reset per file so state never leaks between files.
function _contentMatcher(regex) {
  return function (file) {
    var out = [];
    regex.lastIndex = 0;
    var m;
    while ((m = regex.exec(file.text)) !== null) {
      var line = _lineOfIndex(file.text, m.index);
      out.push({
        file:    file.rel,
        line:    line,
        content: String(m[0]).replace(/\s+/g, " ").trim(),
      });
      if (m.index === regex.lastIndex) regex.lastIndex += 1;
    }
    return out;
  };
}

// ---------------------------------------------------------------------------
// Structure mask
// ---------------------------------------------------------------------------
//
// Several detectors have to know where a block ends, which argument of a
// call is the first one, or which object literal a key sits inside. No
// regular expression answers any of those, and a character budget
// standing in for the answer stops matching the moment the code it reads
// grows past the budget, which is a matcher that reports green forever.
// So those matchers walk brackets, over a masked copy of the source in
// which nothing that is not code structure can unbalance the walk.
//
// In the mask, comments and regular-expression literals become spaces.
// String and template literals keep their characters, because a matcher
// still has to read a value such as an action name out of one, but the
// brackets and the quotes inside them are blanked so a brace in a
// sentence cannot close a block. Every replacement is one character
// wide, so an offset into the mask is the same offset into the source
// and a match still reports the line it came from.

var MASK_BLANK_IN_STRING = {
  "{": 1, "}": 1, "(": 1, ")": 1, "[": 1, "]": 1, "\"": 1, "'": 1, "`": 1,
};

// A slash opens a regular expression unless the thing before it was a
// value. A closing parenthesis or bracket ends a value, and so does a
// name, except where the name is one of the keywords an expression may
// follow.
var REGEX_CANNOT_FOLLOW    = { ")": 1, "]": 1 };
var REGEX_MAY_FOLLOW_WORD  = {
  "return": 1, "typeof": 1, "instanceof": 1, "in": 1, "of": 1, "case": 1,
  "delete": 1, "void": 1, "new": 1, "throw": 1, "do": 1, "else": 1,
  "yield": 1, "await": 1,
};

function _regexMayStart(text, idx) {
  var i = idx - 1;
  while (i >= 0 && /\s/.test(text[i])) i -= 1;
  if (i < 0) return true;
  if (/[A-Za-z0-9_$]/.test(text[i])) {
    var end = i + 1;
    while (i >= 0 && /[A-Za-z0-9_$]/.test(text[i])) i -= 1;
    return REGEX_MAY_FOLLOW_WORD[text.slice(i + 1, end)] === 1;
  }
  return REGEX_CANNOT_FOLLOW[text[i]] !== 1;
}

function _buildMask(text) {
  var out = text.split("");
  var i = 0;
  while (i < text.length) {
    var ch = text[i];
    if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") {
        if (text[i] !== "\r") out[i] = " ";
        i += 1;
      }
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) {
        if (text[i] !== "\n" && text[i] !== "\r") out[i] = " ";
        i += 1;
      }
      if (i < text.length) { out[i] = " "; out[i + 1] = " "; i += 2; }
      continue;
    }
    if (ch === "\"" || ch === "'" || ch === "`") {
      i += 1;
      while (i < text.length) {
        var c = text[i];
        if (c === "\\") {
          out[i] = " ";
          if (i + 1 < text.length && text[i + 1] !== "\n") out[i + 1] = " ";
          i += 2;
          continue;
        }
        if (c === ch) { i += 1; break; }
        if (MASK_BLANK_IN_STRING[c] === 1) out[i] = " ";
        i += 1;
      }
      continue;
    }
    if (ch === "/" && _regexMayStart(text, i)) {
      out[i] = " ";
      i += 1;
      var inClass = false;
      while (i < text.length) {
        var r = text[i];
        if (r === "\\") {
          out[i] = " ";
          if (i + 1 < text.length) out[i + 1] = " ";
          i += 2;
          continue;
        }
        if (r === "\n") break;
        if (r === "[") inClass = true;
        else if (r === "]") inClass = false;
        else if (r === "/" && !inClass) { out[i] = " "; i += 1; break; }
        out[i] = " ";
        i += 1;
      }
      while (i < text.length && /[a-z]/.test(text[i])) { out[i] = " "; i += 1; }
      continue;
    }
    i += 1;
  }
  return out.join("");
}

function _maskOf(file) {
  if (typeof file._mask !== "string") file._mask = _buildMask(file.text);
  return file._mask;
}

// The index of the bracket closing the one at `openIdx`, or -1.
function _matchingBracket(mask, openIdx) {
  var open  = mask[openIdx];
  var close = open === "{" ? "}" : (open === "(" ? ")" : "]");
  var depth = 0;
  for (var i = openIdx; i < mask.length; i += 1) {
    if (mask[i] === open) depth += 1;
    else if (mask[i] === close) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// The innermost brace pair containing `idx`, which for a key inside an
// object literal is that literal.
function _enclosingBraces(mask, idx) {
  var depth = 0;
  for (var i = idx; i >= 0; i -= 1) {
    if (mask[i] === "}") depth += 1;
    else if (mask[i] === "{") {
      if (depth === 0) {
        var end = _matchingBracket(mask, i);
        return end === -1 ? null : { start: i, end: end };
      }
      depth -= 1;
    }
  }
  return null;
}

// Every argument of a call, as text slices, cut at the commas sitting at
// the call's own bracket depth. A nested call, an array or an object
// literal carrying commas of its own is one argument rather than
// several, and the walk runs over the mask, so a comma inside a string
// literal cuts nothing. A call with no arguments answers with one empty
// slice, which is what an argument list of nothing looks like.
function _callArguments(mask, openParenIdx) {
  var end = _matchingBracket(mask, openParenIdx);
  if (end === -1) return null;
  var out   = [];
  var depth = 0;
  var at    = openParenIdx + 1;
  for (var i = openParenIdx + 1; i < end; i += 1) {
    var c = mask[i];
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if (c === ")" || c === "]" || c === "}") depth -= 1;
    else if (c === "," && depth === 0) { out.push(mask.slice(at, i)); at = i + 1; }
  }
  out.push(mask.slice(at, end));
  return out;
}

// The text of a call's first argument, read by bracket depth rather
// than by splitting on the first comma, so a nested call carrying
// commas of its own does not truncate it.
function _firstArgument(mask, openParenIdx) {
  var args = _callArguments(mask, openParenIdx);
  return args === null ? null : args[0];
}

// The brace span of the object literal one named key of an object
// literal holds, or null when the literal does not name that key at its
// own depth or holds something other than a literal under it.
//
// A key of the same name nested inside a sibling's value belongs to that
// sibling and answers a different question, so the walk counts brackets
// and reads only the keys at depth zero. The span is bounded by the
// matching brace rather than by a character budget, so a configuration
// block that grows is still read whole.
//
// Walked over the mask, so a name written in a comment or inside a
// string is not a key, and a brace inside either cannot end the literal
// early.
function _objectValueBraces(mask, braces, key) {
  var base  = braces.start + 1;
  var slice = mask.slice(base, braces.end);
  var depth = 0;
  var re    = /[A-Za-z_$][\w$]*|[{}[\]()]/g;
  var m;
  while ((m = re.exec(slice)) !== null) {
    var tok = m[0];
    if (tok === "{" || tok === "[" || tok === "(") { depth += 1; continue; }
    if (tok === "}" || tok === "]" || tok === ")") { depth -= 1; continue; }
    if (depth !== 0 || tok !== key) continue;
    if (mask[base + m.index - 1] === ".") continue;
    var at = re.lastIndex;
    while (at < slice.length && /\s/.test(slice[at])) at += 1;
    if (slice[at] !== ":") continue;
    at += 1;
    while (at < slice.length && /\s/.test(slice[at])) at += 1;
    if (slice[at] !== "{") continue;
    var open = base + at;
    var end  = _matchingBracket(mask, open);
    if (end === -1) continue;
    return { start: open, end: end };
  }
  return null;
}

// How many arguments a call carries, when the answer has to survive a
// comma inside a string literal.
//
// The mask keeps the characters of a string and blanks only its
// brackets and quotes, because a matcher still has to read a value out
// of one. A comma therefore survives into the mask, and `_callArguments`
// cuts on it: a two-argument call whose label reads "the queue drains,
// then the listener stops" counts as three. Every assertion label in
// this tree is a sentence, so that is the common case rather than the
// corner.
//
// So this walks the source instead, tracking its own quote state, and
// consults the mask only to skip what the mask blanked. Outside a
// string the mask differs from the source at exactly two things, a
// comment and a regular-expression literal, so a position that is blank
// in one and not the other is one of those and carries no argument
// boundary.
//
// A comma inside a template literal's substitution is passed over with
// the rest of the literal. That undercounts a call written that way,
// which leaves it unreported rather than reported wrongly, and no call
// in this tree is written that way.
function _argumentCount(text, mask, openParenIdx) {
  var end = _matchingBracket(mask, openParenIdx);
  if (end === -1) return -1;
  var args  = 1;
  var depth = 0;
  var q     = null;
  for (var i = openParenIdx + 1; i < end; i += 1) {
    var c = text[i];
    if (q !== null) {
      if (c === "\\") { i += 1; continue; }
      if (c === q) q = null;
      continue;
    }
    if (mask[i] === " " && c !== " " && c !== "\t" && c !== "\n" && c !== "\r") continue;
    if (c === "\"" || c === "'" || c === "`") { q = c; continue; }
    if (c === "(" || c === "[" || c === "{") { depth += 1; continue; }
    if (c === ")" || c === "]" || c === "}") { depth -= 1; continue; }
    if (c === "," && depth === 0) args += 1;
  }
  return args;
}

// Every braced loop body in a file, as offsets into the mask. A loop
// written without braces carries one statement and cannot hold the
// two-part shape any detector here looks for, so it is passed over.
function _loopBodies(mask) {
  var out = [];
  var re  = /\b(?:for|while)\s*\(/g;
  var m;
  while ((m = re.exec(mask)) !== null) {
    var openParen  = m.index + m[0].length - 1;
    var closeParen = _matchingBracket(mask, openParen);
    if (closeParen === -1) continue;
    var j = closeParen + 1;
    while (j < mask.length && /\s/.test(mask[j])) j += 1;
    if (mask[j] !== "{") continue;
    var end = _matchingBracket(mask, j);
    if (end === -1) continue;
    out.push({ header: m.index, start: j + 1, end: end });
  }
  return out;
}

// Every braced function body in a file, as offsets into the mask.
//
// A shape that spans two tokens has to be bounded to one function, and
// the bracket walk is what bounds it. A character budget standing in for
// the boundary stops matching the moment the function it reads grows
// past the budget, and a matcher that has gone quiet passes green
// forever over the code it was written to read.
//
// The body brace is found from the end of the parameter list rather than
// from the keyword, so a default value or a destructured parameter
// carrying a brace of its own cannot be mistaken for the body.
function _functionBodies(mask) {
  var out = [];
  var re  = /\bfunction\b/g;
  var m;
  while ((m = re.exec(mask)) !== null) {
    var openParen = mask.indexOf("(", m.index);
    if (openParen === -1) continue;
    var closeParen = _matchingBracket(mask, openParen);
    if (closeParen === -1) continue;
    var open = mask.indexOf("{", closeParen);
    if (open === -1) continue;
    // Nothing but whitespace stands between the parameter list and the
    // body of a function that has one; anything else is a signature
    // without a body, which holds no shape to find.
    if (/\S/.test(mask.slice(closeParen + 1, open))) continue;
    var end = _matchingBracket(mask, open);
    if (end === -1) continue;
    out.push({ start: open + 1, end: end });
  }
  return out;
}

// Every match of `regex` inside `body`, as absolute offsets into the
// mask, with the capture groups kept.
//
// A match is attributed to the INNERMOST function that contains it, and
// nothing else. Every function nested inside another one is inside its
// parent's braces too, so a scan that read each body whole would see
// every token of every sibling below it: two functions that each do one
// half of a shape would be reported as one function doing both, which is
// a finding nobody can act on because the code it names does not exist.
function _matchesIn(mask, bodies, body, regex) {
  var text = mask.slice(body.start, body.end);
  var out  = [];
  regex.lastIndex = 0;
  var m;
  while ((m = regex.exec(text)) !== null) {
    var offset = body.start + m.index;
    if (_innermostBody(bodies, offset) === body.start) {
      out.push({ offset: offset, groups: m });
    }
    if (m.index === regex.lastIndex) regex.lastIndex += 1;
  }
  return out;
}

// The start offset of the innermost function body containing `offset`,
// or -1. The innermost one is the one that starts latest.
function _innermostBody(bodies, offset) {
  var best = -1;
  for (var i = 0; i < bodies.length; i += 1) {
    if (offset < bodies[i].start || offset >= bodies[i].end) continue;
    if (bodies[i].start > best) best = bodies[i].start;
  }
  return best;
}

// The source of a function body with every nested function removed, for
// a test that asks whether THIS function does something rather than
// whether anything below it does.
function _ownText(mask, bodies, body) {
  var out = "";
  var at  = body.start;
  for (var i = 0; i < bodies.length; i += 1) {
    var inner = bodies[i];
    if (inner.start <= body.start || inner.end > body.end) continue;
    // Bodies arrive in ascending order, so skipping an outer nested
    // function carries its own nested functions with it.
    if (inner.start < at) continue;
    out += mask.slice(at, inner.start);
    at = inner.end;
  }
  return out + mask.slice(at, body.end);
}

// The statement a match sits in: from the previous statement terminator,
// or from the opening of the block or literal it is written inside, to
// the next one at the same nesting depth.
//
// This is the unit that emits. A count and the value the count describes
// leave together or they do not, and the statement is where "together"
// is decidable: a length written into an object literal that does not
// also carry the value is a length of something the caller never
// receives, while a length written beside the value it frames describes
// exactly what follows it.
//
// Walked over the mask rather than the source, so a brace or a
// parenthesis inside a string literal cannot end the statement early.
function _statementAround(mask, idx, body) {
  var depth = 0;
  var start = body.start;
  var end   = body.end;
  var i;
  var c;
  for (i = idx; i >= body.start; i -= 1) {
    c = mask[i];
    if (c === ")" || c === "]" || c === "}") depth += 1;
    else if (c === "(" || c === "[" || c === "{") {
      if (depth === 0) { start = i + 1; break; }
      depth -= 1;
    } else if (c === ";" && depth === 0) { start = i + 1; break; }
  }
  depth = 0;
  for (i = idx; i < body.end; i += 1) {
    c = mask[i];
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) { end = i; break; }
      depth -= 1;
    } else if (c === ";" && depth === 0) { end = i; break; }
  }
  return { start: start, end: end };
}

// How many times a name is written in a span, as a name rather than as
// the tail of a longer one or as a property of something else.
function _wholeWordCount(text, name) {
  var re = new RegExp("(?:^|[^\\w$.])" + name + "(?![\\w$])", "g");
  var seen = 0;
  while (re.exec(text) !== null) seen += 1;
  return seen;
}

// The name of the function a match sits inside, for the report. The
// header has to be the one immediately in front of the brace, which is
// what the trailing part of the pattern pins, so a sibling declared
// earlier in the same scope cannot be picked up by mistake. A match is
// reported whether or not a name is found: this is a courtesy to
// whoever reads the output, never part of the matcher.
var FN_HEADER_RE =
  /(?:^|[^\w$])(?:function\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s+)?function)[^{]*$/;

function _enclosingFunction(mask, offset) {
  var at = offset;
  for (var out = 0; out < 12; out += 1) {
    var braces = _enclosingBraces(mask, at);
    if (!braces) return null;
    var m = FN_HEADER_RE.exec(mask.slice(Math.max(0, braces.start - 240), braces.start));
    if (m) return m[1] || m[2];
    at = braces.start - 1;
    if (at < 0) return null;
  }
  return null;
}

// The brace span of the function body enclosing `offset`, or null.
// `_enclosingFunction` above answers which function an offset is in;
// this answers where that function starts and ends, which is what a
// matcher needs to ask whether two offsets share one body. Same outward
// walk, same bound on it, so the two agree on which block is the
// function rather than differing by one nesting level.
function _enclosingFunctionSpan(mask, offset) {
  var at = offset;
  for (var out = 0; out < 12; out += 1) {
    var braces = _enclosingBraces(mask, at);
    if (!braces) return null;
    if (FN_HEADER_RE.test(mask.slice(Math.max(0, braces.start - 240), braces.start))) {
      return braces;
    }
    at = braces.start - 1;
    if (at < 0) return null;
  }
  return null;
}

// Whether a statement at `fromIdx` can still be running when control
// arrives at `toIdx` later in the same function body.
//
// It answers one thing a pair of offsets does not: a verb whose first
// branch does its work and returns has emits above the later branch's
// code that no execution ever reaches from. Reading the two as ordered
// text calls that a sequence, which is how a matcher ends up naming the
// wrong half of a function.
//
// The block holding the earlier statement either contains the later one,
// in which case they are on one path, or it closes first, in which case
// the only way through is out of the bottom of it. So a return, a throw
// or a loop jump between the statement and its block's closing brace is
// the answer that the path does not continue.
function _reachesLater(mask, fromIdx, toIdx) {
  var block = _enclosingBraces(mask, fromIdx);
  if (!block) return true;
  if (block.end > toIdx) return true;
  return !/\b(?:return|throw|continue|break)\b/.test(mask.slice(fromIdx, block.end));
}

// How far a `catch` header may sit from the `try` block it closes: the
// closing brace, a space and the keyword, plus room for a comment
// between them. A pure bound on the search, never the precision
// mechanism, which is the bracket walk below it.
var CATCH_LOOKAHEAD_CHARS = 400;

// How many enclosing blocks the walk below will climb through. A pure
// backstop on a pathological nesting, set far above any real one; the
// function body is what actually stops the walk.
var MAX_ENCLOSING_BLOCKS = 12;

// The brace pairs enclosing `offset`, innermost first, stopping at the
// body of the function it sits in. `test` is asked of each in turn and
// the first truthy answer ends the walk.
//
// Every question asked about where a statement sits in a nesting is this
// same climb with a different test at the top of it, so the climb is
// written once. Walking outward to the function boundary rather than
// matching a layout is what makes those questions survive a body that
// grows: a character budget standing in for the boundary stops matching
// the moment the function passes it, and a matcher that has gone quiet
// passes green forever over the code it was written to read.
// `floorAt` raises that boundary for a caller asking a narrower
// question. Whether a statement is guarded before it leaves the FUNCTION
// and whether it is guarded before it leaves ONE TURN OF A LOOP are
// different questions with different answers, and the second is what a
// per-item verdict rests on: a guard wrapped around a whole loop settles
// the fault and still abandons every item after the one that raised it.
// Raising the floor to the loop body asks the narrower question over the
// same climb, so the two readings cannot drift apart. It only ever
// raises the boundary, so a caller cannot climb out past the function by
// passing one.
function _walkEnclosingBlocks(mask, offset, test, floorAt) {
  var span  = _enclosingFunctionSpan(mask, offset);
  var floor = span ? span.start : 0;
  if (typeof floorAt === "number" && floorAt > floor) floor = floorAt;
  var at    = offset;
  for (var out = 0; out < MAX_ENCLOSING_BLOCKS; out += 1) {
    var braces = _enclosingBraces(mask, at);
    if (!braces || braces.start < floor) return false;
    if (test(braces, floor)) return true;
    at = braces.start - 1;
    if (at < floor) return false;
  }
  return false;
}

// Whether a throw at `offset` is caught before it leaves the function
// it is in.
//
// An emit nested inside a branch or a loop that is itself inside the try
// is still covered, and an emit in a sibling block is not.
//
// A catch that rethrows does not count. The value still leaves, which is
// the whole of what is being asked, and a handler that logs and rethrows
// reads at a glance like one that swallows.
//
// `opts.converted` asks the other question over the same walk: whether
// the fault is TRANSLATED before it leaves. There a handler that raises
// something of its own has done the job, because what continues outward
// is a value this layer composed, and only a handler that hands the
// caught binding straight back leaves the original in flight. Two
// questions, one walk, so a body that grows or a branch that nests
// cannot make one of them right and the other wrong.
//
// `opts.floor` narrows what "leaves" means, for the caller asking about
// one turn of a loop rather than about the whole function. A try wrapped
// around the loop settles the fault and abandons the rest of the set, so
// a question about a per-item verdict has to stop at the loop body.
function _caughtBeforeLeaving(mask, offset, opts) {
  var converted = !!(opts && opts.converted === true);
  var floorAt   = opts && typeof opts.floor === "number" ? opts.floor : undefined;
  return _walkEnclosingBlocks(mask, offset, function (braces, floor) {
    if (!/\btry\s*$/.test(mask.slice(Math.max(floor, braces.start - 240), braces.start))) {
      return false;
    }
    var after  = mask.slice(braces.end + 1, braces.end + 1 + CATCH_LOOKAHEAD_CHARS);
    var caught = /^\s*catch\s*\(/.exec(after);
    if (!caught) return false;
    var openParen  = braces.end + 1 + caught[0].length - 1;
    var closeParen = _matchingBracket(mask, openParen);
    if (closeParen === -1) return false;
    var j = closeParen + 1;
    while (j < mask.length && /\s/.test(mask[j])) j += 1;
    var end = mask[j] === "{" ? _matchingBracket(mask, j) : -1;
    return end !== -1 && _handlerSettles(mask.slice(j, end),
      mask.slice(openParen + 1, closeParen).trim(), converted);
  }, floorAt);
}

// The header a catch block carries, matched against the text immediately
// in front of a block's opening brace. The binding is optional, which is
// what a handler written without one has.
var CATCH_HEADER_RE = /\bcatch\s*(?:\([^()]{0,200}\))?\s*$/;

// The promise form of the same thing, matched against the text in front
// of the callback body's opening brace. A function handed to `.catch()`
// runs for exactly the reason a catch block does, and a matcher that
// read only the keyword would go quiet the moment a handler was written
// the other way. Both the function and the arrow spelling, because which
// one a file uses says nothing about what the handler is.
var PROMISE_CATCH_RE =
  /\.catch\s*\(\s*(?:async\s+)?(?:function\b[^{]{0,200}|\(?[\w$,\s]{0,80}\)?\s*=>\s*)$/;

// Whether `offset` sits inside a handler that runs because something
// failed, at any nesting depth within the function it is in.
//
// The third question over the same walk. `_caughtBeforeLeaving` asks
// whether a statement is inside the GUARDED block; this asks whether it
// is inside the HANDLER, which is the half that only runs because the
// work did not happen.
// Both spellings are read off the same place, the text immediately in
// front of a block's opening brace, so the walk asks one question per
// enclosing block and an anonymous callback is reached as a block rather
// than as a function. It has to be: a function with no name is not a
// boundary the enclosing-function walk recognizes, so a handler passed
// to `.catch()` is only ever seen from here as the block it is.
function _insideCatchHandler(mask, offset) {
  return _walkEnclosingBlocks(mask, offset, function (braces, floor) {
    var before = mask.slice(Math.max(floor, braces.start - CATCH_LOOKAHEAD_CHARS), braces.start);
    return CATCH_HEADER_RE.test(before) || PROMISE_CATCH_RE.test(before);
  });
}

// Whether one catch body answers the question being asked of it. Without
// `converted` the handler has to let nothing out at all; with it, the
// handler may raise its own and only a bare rethrow of the caught
// binding fails. A binding this cannot read as a plain name is treated
// as a rethrow, so an unusual handler is reported rather than assumed
// to be doing the right thing.
function _handlerSettles(body, bound, converted) {
  if (!converted) return !/\bthrow\b/.test(body);
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(bound)) return false;
  return !new RegExp("\\bthrow\\s+" + bound + "(?![A-Za-z0-9_$])").test(body);
}

// A match reported from a mask offset, with the enclosing function and
// the source line beside it.
function _atOffset(file, offset, label) {
  var line = _lineOfIndex(file.text, offset);
  var fn   = _enclosingFunction(_maskOf(file), offset);
  var body = label || String(file.lines[line - 1] || "").trim();
  return {
    file:    file.rel,
    line:    line,
    content: (fn ? "in " + fn + "(): " : "") + body,
  };
}

// The same enrichment for a matcher that works line by line.
function _named(file, matches) {
  var mask = _maskOf(file);
  return matches.map(function (m) {
    var upTo = file.lines.slice(0, m.line).join("\n").length;
    var fn = _enclosingFunction(mask, Math.max(0, upTo - 1));
    return fn ? { file: m.file, line: m.line, content: "in " + fn + "(): " + m.content } : m;
  });
}

// Every function body containing `offset`, innermost first.
function _bodiesAround(bodies, offset) {
  var out = [];
  for (var i = 0; i < bodies.length; i += 1) {
    if (offset >= bodies[i].start && offset < bodies[i].end) out.push(bodies[i]);
  }
  out.sort(function (left, right) { return right.start - left.start; });
  return out;
}

// A row destroyed without the material it named being destroyed first.
//
// Two detectors read the same shape over two different pairs, so the
// walk lives here once. `spec.row` is the destruction of a row that
// NAMES something outside the database; `spec.material` is the verb that
// destroys the thing it named. Both are frozen contracts rather than
// local symbols, so a rename of either makes this fire rather than go
// quiet, which is the direction a check has to fail in.
//
// Two findings, and they are different faults. A body that destroys the
// row and never reaches the material leaves that material with nothing
// left to name it: no listing shows it, no report counts it, and the one
// code path that could erase it finds its subject through the row that
// is now gone. A body that does both in the wrong order is the same
// outcome whenever the second half does not complete, because the handle
// on the material is already gone by the time anything can be retried.
//
// The material counts when it is written on the path the row deletion
// runs on: in the same body, or directly in one that encloses it. A row
// deleted inside a transaction callback is deleted by the function
// holding that callback, and the erasure that has to precede it belongs
// above the callback rather than inside a database transaction, which
// cannot carry a filesystem write anyway. `_matchesIn` still attributes
// every match to its own innermost body, so a SIBLING function doing the
// erasing satisfies nothing here: nothing calls it on this path.
//
// Order is read off the offsets of matches this walk already found,
// never off the distance between them, so a body that grows, gains a
// branch or is reindented moves both and changes nothing. Correct order
// puts every erasure ahead of every row deletion, so the first deletion
// standing ahead of the last erasure is the finding.
function _rowAheadOfItsMaterial(file, spec) {
  var mask   = _maskOf(file);
  var bodies = _functionBodies(mask);
  var out = [];
  for (var i = 0; i < bodies.length; i += 1) {
    var rows = _matchesIn(mask, bodies, bodies[i], spec.row);
    if (rows.length === 0) continue;

    var around = spec.enclosing === true
      ? _bodiesAround(bodies, bodies[i].start)
      : [bodies[i]];
    var material = [];
    for (var a = 0; a < around.length; a += 1) {
      material = material.concat(_matchesIn(mask, bodies, around[a], spec.material));
    }
    material.sort(function (left, right) { return left.offset - right.offset; });

    if (material.length === 0) {
      for (var e = 0; e < rows.length; e += 1) {
        out.push(_atOffset(file, rows[e].offset, spec.missing));
      }
      continue;
    }
    if (rows[0].offset < material[material.length - 1].offset) {
      out.push(_atOffset(file, rows[0].offset, spec.late));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// A URL this application hands the browser, read for whether it was built
//
// The browser surface turns a value into a URL in two places, and the two
// take different forms.
//
//   - A redirect is an absolute path on this server, passed through a
//     helper that refuses anything else.
//   - A view field is what a template writes AFTER a slash of its own, so
//     it is that same path with its leading slash removed. A second helper
//     composes the first, takes the slash off, and refuses a value whose
//     remainder begins with a slash or a backslash, because the template's
//     slash followed by either one names another host.
//
// The two forms are not interchangeable. A path handed to a template
// renders as `//mail/INBOX`, which a browser reads as a host called mail,
// and a view field handed to a redirect is a relative target.
//
// Reading which helper built a value needs a handful of small readers: one
// that finds where an assigned expression ends, one that takes the first
// argument of a call, one that splits a conditional into the values it can
// produce, one that finds the view field builders a file defines, and the
// classifiers for each form.
//
// None of them names a helper. A redirect target counts as built when it
// BEGINS with a call, which is the shape a built target has under every
// name the helper could be given. A view field counts as built when it IS
// one call to a function the same file defines with the view field
// builder's shape: a body that removes one leading character, compares
// what is left against a slash and against a backslash, and throws. The
// cost of anchoring on the shape is that a call reaching no refusal reads
// the same as one that does, and that is the question the deep read of this
// surface answers by walking each builder to what it returns. These readers
// answer the questions that walk cannot reach: whether the value was built
// at all, and whether it was built into the form the place it lands on
// takes.
// ---------------------------------------------------------------------------

var LINK_TICK = String.fromCharCode(96);

// A value that is already screened by construction begins with a call.
// The callee may be a plain name or a property path, because the helper
// is reached under both spellings.
var LINK_CALL_RE    = /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\(/;
var LINK_LITERAL_RE = /^(["'])((?:[^\\]|\\.)*)\1$/;

// An absolute path on this server: one leading slash, and no second
// slash or backslash behind it to start an authority. The deep read of
// this surface drives the framework's resolver over these same shapes;
// what is needed here is only whether the text was written as a path.
var LINK_ROOT_RELATIVE_RE = /^\/(?![/\\])[^\\]*$/;
// A control byte inside a path splices a response header onto it or
// hides an authority from whoever reads the link, so a literal carrying
// one is not a path. Written as escapes, so this file carries none.
var LINK_CONTROL_RE       = new RegExp("[\\u0000-\\u001F\\u007F]");

// Characters that cannot end a complete expression, so a line break
// after one continues the statement.
var LINK_DANGLING_RE  = /[+\-*/%?:&|^,=!<>.([{]$/;
// Characters that can open a continuation of the expression above, so a
// line break before one continues the statement too.
var LINK_CONTINUES_RE = /[?:+\-*/%&|^.,)(\]}=<>!]/;

// The first character of `text` at or after `from` that is neither space
// nor comment, or "" when there is none.
function _linkNextMeaningful(text, from) {
  var i = from;
  while (i < text.length) {
    var c = text.charAt(i);
    if (c === " " || c === "\t" || c === "\r" || c === "\n") { i += 1; continue; }
    if (c === "/" && text.charAt(i + 1) === "/") {
      var nl = text.indexOf("\n", i);
      if (nl === -1) return "";
      i = nl + 1;
      continue;
    }
    if (c === "/" && text.charAt(i + 1) === "*") {
      var close = text.indexOf("*/", i);
      if (close === -1) return "";
      i = close + 2;
      continue;
    }
    return c;
  }
  return "";
}

// The expression starting at `from`, up to the semicolon that closes the
// statement. Depth and quote aware, so a semicolon inside a call's
// arguments or inside a string does not end it, and a value written
// across several lines is read whole. Comments inside the expression
// contribute nothing, so prose between two branches of a conditional
// neither ends the read nor reaches the classifier. `stopAtComma` reads a
// property value inside an object literal, which a comma at its own depth
// ends as well.
function _linkExpressionAt(text, from, stopAtComma) {
  var depth = 0;
  var quote = "";
  var out = "";
  for (var i = from; i < text.length; i += 1) {
    var c = text.charAt(i);
    if (quote) {
      out += c;
      if (c === "\\") { out += text.charAt(i + 1); i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "/" && text.charAt(i + 1) === "/") {
      var nl = text.indexOf("\n", i);
      if (nl === -1) break;
      i = nl - 1;
      continue;
    }
    if (c === "/" && text.charAt(i + 1) === "*") {
      var close = text.indexOf("*/", i);
      if (close === -1) break;
      i = close + 1;
      continue;
    }
    if (c === "\"" || c === "'" || c === LINK_TICK) { quote = c; out += c; continue; }
    if (c === "(" || c === "[" || c === "{") { depth += 1; out += c; continue; }
    if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) break;
      depth -= 1;
      out += c;
      continue;
    }
    if (c === ";" && depth === 0) break;
    if (c === "," && depth === 0 && stopAtComma === true) break;
    if (c === "\n" && depth === 0) {
      var sofar = out.replace(/\s+$/, "");
      if (sofar.length > 0 && !LINK_DANGLING_RE.test(sofar) &&
          !LINK_CONTINUES_RE.test(_linkNextMeaningful(text, i + 1))) {
        break;
      }
    }
    out += c;
  }
  return out.trim();
}

// The first argument of the call whose opening parenthesis is at `from`.
function _linkFirstArgument(text, from) {
  var depth = 0;
  var quote = "";
  var out = "";
  for (var i = from; i < text.length; i += 1) {
    var c = text.charAt(i);
    if (quote) {
      out += c;
      if (c === "\\") { out += text.charAt(i + 1); i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === LINK_TICK) { quote = c; out += c; continue; }
    if (c === "(" || c === "[" || c === "{") {
      depth += 1;
      if (depth > 1) out += c;
      continue;
    }
    if (c === ")" || c === "]" || c === "}") {
      depth -= 1;
      if (depth === 0) break;
      out += c;
      continue;
    }
    if (c === "," && depth === 1) break;
    out += c;
  }
  return out.trim();
}

// An expression wrapped whole in one pair of parentheses, unwrapped. A
// nested conditional is ordinarily written that way, and a reader that
// refused it would fire on the correct shape, which teaches people to
// route around the gate. Unwrapping weakens nothing, because a
// concatenation in parentheses is still a concatenation once they come
// off.
function _linkUnwrap(expr) {
  var s = expr.trim();
  if (s.charAt(0) !== "(") return s;
  var depth = 0;
  var quote = "";
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === LINK_TICK) { quote = c; continue; }
    if (c === "(") { depth += 1; continue; }
    if (c !== ")") continue;
    depth -= 1;
    if (depth > 0) continue;
    return i === s.length - 1 ? _linkUnwrap(s.slice(1, -1)) : s;
  }
  return s;
}

// The values a conditional can produce, with the condition discarded. A
// non-conditional expression is one value. `?.` and `??` are not
// conditionals and are stepped over rather than split on.
function _linkBranches(expr) {
  var depth = 0;
  var quote = "";
  var qAt = -1;
  var cAt = -1;
  var pending = 0;
  for (var i = 0; i < expr.length; i += 1) {
    var c = expr.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === LINK_TICK) { quote = c; continue; }
    if (c === "(" || c === "[" || c === "{") { depth += 1; continue; }
    if (c === ")" || c === "]" || c === "}") { depth -= 1; continue; }
    if (depth !== 0) continue;
    if (c === "?") {
      var next = expr.charAt(i + 1);
      if (next === "." || next === "?") { i += 1; continue; }
      if (qAt === -1) qAt = i; else pending += 1;
      continue;
    }
    if (c !== ":" || qAt === -1) continue;
    if (pending > 0) { pending -= 1; continue; }
    cAt = i;
    break;
  }
  if (qAt === -1 || cAt === -1) return [expr.trim()];
  return _linkBranches(expr.slice(qAt + 1, cAt))
    .concat(_linkBranches(expr.slice(cAt + 1)));
}

// One value a URL expression can produce, classified. Returns null when
// the value is constrained by construction, and the reason it is not
// otherwise. Every branch of a conditional is classified, so one good
// branch does not answer for the other.
function _linkTargetNotBuilt(branch) {
  var expr = _linkUnwrap(branch);
  if (expr.length === 0) return null;

  var parts = _linkBranches(expr);
  if (parts.length > 1) {
    for (var i = 0; i < parts.length; i += 1) {
      var why = _linkTargetNotBuilt(parts[i]);
      if (why !== null) return why;
    }
    return null;
  }

  var literal = LINK_LITERAL_RE.exec(expr);
  if (literal !== null) {
    var body = literal[2];
    // An empty value renders no link and sends the browser nowhere.
    if (body.length === 0) return null;
    if (LINK_ROOT_RELATIVE_RE.test(body) && !LINK_CONTROL_RE.test(body)) return null;
    return "the literal " + JSON.stringify(body) +
      ", which is not an absolute path on this server";
  }

  if (LINK_CALL_RE.test(expr)) return null;

  return "the expression " + JSON.stringify(expr.replace(/\s+/g, " ").slice(0, 90)) +
    ", which is neither built by a call nor written as an absolute path on this server";
}

// Every value an expression can produce, with each conditional split and
// each wrapping pair of parentheses removed, however deeply they nest.
function _linkLeaves(expr) {
  var parts = _linkBranches(_linkUnwrap(expr));
  if (parts.length === 1) return [_linkUnwrap(parts[0])];
  var out = [];
  for (var i = 0; i < parts.length; i += 1) out = out.concat(_linkLeaves(parts[i]));
  return out;
}

// The callee a value begins with, spaces removed, or null.
var LINK_CALLEE_RE = /^([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/;

// Whether `expr` is one call with nothing written after its closing
// parenthesis. Quote aware, so a parenthesis inside a string argument does
// not close the call.
function _linkIsOneCall(expr) {
  var depth = 0;
  var quote = "";
  for (var i = expr.indexOf("("); i !== -1 && i < expr.length; i += 1) {
    var c = expr.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "\"" || c === "'" || c === LINK_TICK) { quote = c; continue; }
    if (c === "(" || c === "[" || c === "{") { depth += 1; continue; }
    if (c !== ")" && c !== "]" && c !== "}") continue;
    depth -= 1;
    if (depth === 0) return expr.slice(i + 1).trim().length === 0;
  }
  return false;
}

// The view field builder's shape, read off a function body. It removes one
// leading character, compares what is left against a slash and against a
// backslash, and throws. The slash and the throw are read off the mask, so
// prose cannot supply them; the backslash is read off the source, because
// the mask blanks the escape that spells one.
var LINK_FUNCTION_RE       = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
var LINK_TAIL_TRIM_RE      = /\.\s*(?:slice|substring|substr)\s*\(\s*1\s*\)/;
var LINK_TAIL_SLASH_RE     = /===\s*"\/"|"\/"\s*===/;
var LINK_TAIL_BACKSLASH_RE = /===\s*"\\\\"|"\\\\"\s*===/;
var LINK_THROW_RE          = /\bthrow\b/;

// The functions in one file whose body has the view field builder's shape.
function _linkShapedIn(file) {
  var mask = _maskOf(file);
  var out = {};
  LINK_FUNCTION_RE.lastIndex = 0;
  var m;
  while ((m = LINK_FUNCTION_RE.exec(mask)) !== null) {
    var params = _matchingBracket(mask, m.index + m[0].length - 1);
    var open   = params === -1 ? -1 : mask.indexOf("{", params);
    var close  = open === -1 ? -1 : _matchingBracket(mask, open);
    if (close === -1) continue;
    var code = mask.slice(open, close);
    if (LINK_TAIL_TRIM_RE.test(code) && LINK_TAIL_SLASH_RE.test(code) && LINK_THROW_RE.test(code) &&
        LINK_TAIL_BACKSLASH_RE.test(file.text.slice(open, close))) {
      out[m[1]] = true;
    }
  }
  return out;
}

// The local modules a file requires, as file records. Only a relative
// require resolves, and the vendored tree is left out: the framework is
// read-only and a walk into it would answer for code this repository does
// not write. A require naming no file here resolves to nothing, which
// leaves a call through it unbuilt, which is the verdict a typo deserves.
var LINK_LOCAL_REQUIRE_RE =
  /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*"(\.[^"]*)"\s*\)/g;

// The path a file record stands for. A fixture record writes the detector
// and the fixture's index in front of the path it is written as, so a
// require inside one resolves from the directory the fixture says it sits
// in rather than from a directory nothing holds.
var LINK_FIXTURE_REL_RE = /^fixture:[^/]*\//;

function _linkRequiredModules(file) {
  var from = path.dirname(path.join(REPO_ROOT, file.rel.replace(LINK_FIXTURE_REL_RE, "")));
  var out = [];
  LINK_LOCAL_REQUIRE_RE.lastIndex = 0;
  var m;
  while ((m = LINK_LOCAL_REQUIRE_RE.exec(file.text)) !== null) {
    var base = path.resolve(from, m[2]);
    var tries = [base + ".js", path.join(base, "index.js")];
    for (var i = 0; i < tries.length; i += 1) {
      var rel = _relPath(tries[i]);
      if (rel.indexOf("lib/vendor/") === 0 || rel.indexOf("..") === 0) continue;
      var isFile;
      try { isFile = fs.statSync(tries[i]).isFile(); }
      catch (_missing) {
        // Drop-silent by design: a path that is not a file is not the
        // module, and the next candidate spelling is tried.
        continue;
      }
      if (!isFile) continue;
      out.push({ name: m[1], file: _readRecord(tries[i]) });
      break;
    }
  }
  return out;
}

// The functions that are a local NAME for a builder already known: every
// return is exactly one call to one, and there is at least one return. A
// function with a second return that is not built is not a name for a
// builder, it is a branch that reaches a template unscreened.
function _linkDelegatesIn(file, known) {
  var mask = _maskOf(file);
  var out = [];
  LINK_FUNCTION_RE.lastIndex = 0;
  var m;
  while ((m = LINK_FUNCTION_RE.exec(mask)) !== null) {
    if (known[m[1]] === true) continue;
    var params = _matchingBracket(mask, m.index + m[0].length - 1);
    var open   = params === -1 ? -1 : mask.indexOf("{", params);
    var close  = open === -1 ? -1 : _matchingBracket(mask, open);
    if (close === -1) continue;
    var returns = 0;
    var built = 0;
    var re = /\breturn\b/g;
    re.lastIndex = open;
    var r;
    while ((r = re.exec(mask)) !== null && r.index < close) {
      returns += 1;
      var expr = _linkExpressionAt(file.text, r.index + r[0].length).trim();
      var callee = LINK_CALLEE_RE.exec(expr);
      if (callee === null) continue;
      if (known[callee[1].replace(/\s+/g, "")] !== true) continue;
      if (!_linkIsOneCall(expr)) continue;
      built += 1;
    }
    if (returns > 0 && returns === built) out.push(m[1]);
  }
  return out;
}

// Every name a file can build a link value through. Read once per file.
//
// Three sources, because the rule lives in one file and the surfaces that
// compose it keep their own names for it. A function in THIS file with the
// shape. A function with the shape in a module this file requires, named
// `module.function`. And a local name for either: a function whose every
// return is one call to a builder already named, which is what a surface
// writes so that its call sites do not have to move when the rule moves.
// The third is taken to a fixed point, so a name for a name still resolves.
function _linkTailBuilders(file) {
  if (file._linkTails) return file._linkTails;
  var out = _linkShapedIn(file);
  _linkRequiredModules(file).forEach(function (mod) {
    var shaped = _linkShapedIn(mod.file);
    Object.keys(shaped).forEach(function (fn) { out[mod.name + "." + fn] = true; });
  });
  var added = true;
  while (added) {
    added = false;
    _linkDelegatesIn(file, out).forEach(function (name) {
      if (out[name] !== true) { out[name] = true; added = true; }
    });
  }
  file._linkTails = out;
  return out;
}

// One view field value, classified. Null when every value it can produce
// is empty or is exactly one call to a view field builder this file
// defines, and the reason otherwise.
function _linkViewFieldNotBuilt(expr, tails) {
  var leaves = _linkLeaves(expr);
  for (var i = 0; i < leaves.length; i += 1) {
    var leaf = leaves[i].trim();
    if (leaf.length === 0) continue;
    var literal = LINK_LITERAL_RE.exec(leaf);
    if (literal !== null) {
      if (literal[2].length === 0) continue;
      return "the literal " + JSON.stringify(literal[2]) + ". A template writes a slash of its " +
        "own in front of a view field, so a literal reaches the page unscreened, and one that " +
        "begins with a slash renders as two and names another host";
    }
    var callee = LINK_CALLEE_RE.exec(leaf);
    if (callee === null) {
      return "the expression " + JSON.stringify(leaf.replace(/\s+/g, " ").slice(0, 90)) +
        ", which no view field builder produced";
    }
    var name = callee[1].replace(/\s+/g, "");
    if (tails[name] !== true) {
      return "a value from " + name + "(), which is not a view field builder this file " +
        "defines. A path built for a redirect begins with a slash, and the template's own " +
        "slash in front of it renders a link to another host";
    }
    if (!_linkIsOneCall(leaf)) {
      return "a value from " + name + "() with more written after the call, which the " +
        "builder never screened";
    }
  }
  return null;
}

// One redirect target, classified: built as `_linkTargetNotBuilt` reads it,
// and never by a view field builder, whose value is relative to the page
// once a redirect sends it.
function _linkRedirectNotBuilt(expr, tails) {
  var why = _linkTargetNotBuilt(expr);
  if (why !== null) return why;
  var leaves = _linkLeaves(expr);
  for (var i = 0; i < leaves.length; i += 1) {
    var callee = LINK_CALLEE_RE.exec(leaves[i].trim());
    if (callee !== null && tails[callee[1].replace(/\s+/g, "")] === true) {
      return "a value from " + callee[1] + "(), which builds a view field without its leading " +
        "slash, so the browser resolves the redirect against the page it was on";
    }
  }
  return null;
}

// A path refusal and a view field builder over it, for the fixtures below.
// Both are written under names the tree does not use, so what the reader
// recognizes is the shape rather than a spelling it was handed.
var LINK_PATH_REFUSAL_SOURCE =
  "function _p(v) {\n" +
  "  if (typeof v === \"string\" && v.charAt(0) === \"/\" &&\n" +
  "      b.safeRedirect.resolve(v, { fallback: \"\" }) === v) {\n" +
  "    return v;\n" +
  "  }\n" +
  "  throw new TypeError(\"not a path on this server\");\n" +
  "}\n";
var LINK_TAIL_BUILDER_SOURCE = LINK_PATH_REFUSAL_SOURCE +
  "function _v(value) {\n" +
  "  var tail = _p(value).slice(1);\n" +
  "  var first = tail.charAt(0);\n" +
  "  if (first === \"/\" || first === \"\\\\\" || first === \"\\t\") {\n" +
  "    throw new TypeError(\"not a view field\");\n" +
  "  }\n" +
  "  return tail;\n" +
  "}\n";

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

// The unfinished-work pattern, carried from the authoring rules so the
// gate and the rule cannot drift apart.
//
// One token from that list is held back here, and this is the reason.
// A message a receiving server answered with a temporary failure is a
// DEFERRED message: `outcome.deferred` is the delivery state the
// composer returns, and a comment describing the retry window says the
// same word. In a mail server the bare token cannot separate the domain
// from the marker. Deferred WORK is caught by the qualified pattern
// below instead, which cannot describe a message: work is deferred to a
// later release, a future version, a follow-up patch.
//
// The narrowing is declared in PATTERN_NARROWINGS and printed with the
// other scope exceptions on every run, so it is visible to whoever reads
// the output rather than only to whoever reads this file.
var UNFINISHED_RE = /todo|fixme|xxx\b|hack\b|not[ -]?supported|not[ -]?implemented|unimplemented|out[ -]?of[ -]?scope|placeholder|stub\b|coming[ -]?soon|later patch|follow[ -]?up patch|in[ -]?the[ -]?future/i;
var DEFERRED_WORK_RE = /\bdefer(?:red|ral|s|ring)?\b[^\n]{0,40}?\b(?:later|future|next|follow[ -]?up|subsequent)\s+(?:release|version|patch|milestone|commit|cut)\b/i;

// The lettered label is built from parts, since the forbidden-vocabulary
// gate refuses its noun in every file, this one included.
var NUMBERING_RE  = new RegExp(
  "\\b(?:phase|sweep|batch|slice|group|round)[ -]?\\d+\\b|\\b" + vocabulary.word("ti|er") + "[ -]?[abc]\\b",
  "i");
var TOOLING_RE    = /\b(?:claude|anthropic|chatgpt|openai|copilot|gemini|co[- ]authored[- ]by|ai[- ]generated|llm[- ]generated)\b/i;

// The dash matcher, in two halves.
//
// The unicode half is the obvious one. The ASCII half is the half a
// writer reaches for once the em dash has been taken away, and it is a
// re-punctuation rather than a fix: a spaced hyphen standing in for a
// comma is the same interruption performed by a different character, so
// the rule has to see both or it teaches the substitution it forbids.
//
// The ASCII half requires a word character on each side, which is what
// keeps it off everything in this tree that is notation rather than
// punctuation. A list bullet has no word character before it. A flag
// such as `--dry-run` has no space inside it. A markdown table rule is
// three hyphens rather than two between spaces. A range written `1 - 5`
// does match, and should: it reads as prose and belongs as `1 to 5`.
var DASH_UNICODE_RE = new RegExp("[" + EM_DASH + EN_DASH + "]");
var DASH_ASCII_RE   = /(?<=[\w)"'`])\s--\s(?=[\w("'`])|(?<=[\w)"'`]) - (?=[\w("'`])/;
var DASH_RE         = new RegExp(DASH_UNICODE_RE.source + "|" + DASH_ASCII_RE.source);

// Files where an attribution or tooling token is the machinery rather
// than the violation: a gate cannot refuse a token without naming it.
// Each entry carries the reason, and the reason is what a reviewer
// checks when the entry stops being true.
var TOOLING_TOKEN_EXCEPTIONS = {
  "scripts/check-operator-prose.js":
    "locates the machine-local prose checker and names the working-instruction file it holds outside the gate",
  "scripts/generate-changelog-entry.js":
    "carries the attribution-token pattern the changelog gate refuses",
  "scripts/release.js":
    "names the review connector login the merge gate waits on",
  "test/layer-0-primitives/release-gate-verdicts.test.js":
    "builds the review-thread payload that gate reads, and a thread carries the login of the " +
    "connector that posted it: a fixture spelling some other reviewer would model a situation " +
    "the flow never meets",
};

// The input-validation labels of the authoring rules. The discipline is
// real and the vocabulary is private: an operator reading one of these
// labels is being told which internal classification a reader was
// written under, which answers none of the questions the comment is
// there to answer. Say what the code does with bad input.
//
// The names are the rulebook's own, so the pattern is a frozen contract
// rather than a list somebody keeps in step by hand, and it stays clear
// of the two other senses of the word in this tree: the health-probe
// tiers, which are a framework field, and a listener described as the
// protocol layer it sits at.
//
// The noun every label ends in is built with the vocabulary gate's `word`,
// in lower case and capitalized.
var LABEL_NOUN         = vocabulary.word("ti|er");
var LABEL_NOUN_CAPITAL = vocabulary.word("Ti|er");
var VALIDATION_LABEL_RE = new RegExp(
  "\\bby\\s+" + LABEL_NOUN + "s?\\b" +
  "|\\b(?:the|this|that|a|an)\\s+" +
  "(?:wire(?:[- ]protocol)?|observability|config(?:[- ]time)?|entry[- ]point|defensive|" +
  "hot[- ]path|drop[- ]silent|best[- ]effort|validation)\\s+" + LABEL_NOUN + "\\b",
  "i"
);

// ---------------------------------------------------------------------------
// self-history-in-source: the shapes that describe a past this tree has
// not had
// ---------------------------------------------------------------------------
//
// This repository has one release. A clause naming a previous state of
// the code therefore describes something that has never existed, and it
// costs the reader real time: an operator who reads that a build once
// behaved differently goes looking for which build, and there is no
// answer. Present tense, saying what the software does, is the whole of
// what these sentences can say.
//
// Each shape is named, matched over the prose runs above rather than
// over raw lines, and printed in the run summary so a reader can tell a
// decision from an oversight.

// 1. The past habitual. "used to" is two readings written the same way:
//    the claim about a former behavior, and the participle meaning
//    employed. The participle is what a mail server's comments are full
//    of, so it is excluded by what sits in front of it: a form of `be`,
//    with or without an adverb between; a bare adverb, which is that
//    same form elided; and a comma, which opens the reduced relative
//    clause the participle lives in.
var EMPLOYED_LOOKBEHIND =
  "(?<!\\b(?:is|are|was|were|be|been|being|becomes?|get|gets|got)\\s)" +
  "(?<!\\b(?:is|are|was|were|be|been|being)\\s\\w+\\s)" +
  "(?<!\\b(?:never|ever|only|also|widely|commonly|routinely|rarely)\\s)" +
  "(?<![,;]\\s)";

// 2. A former build of this server, which is the phrase the delivery
//    history reaches for. `release` and `version` are deliberately not
//    here: an operator verifying an older RELEASE against the in-tree
//    key is doing something real, and so is a manifest recording the
//    version before a refresh. What has no referent is a build of this
//    code that behaved differently, so `build` is the noun matched, plus
//    the spelled-out form that names this server directly.
//
// 3. A claim over the whole life of the software. "has always" is false
//    on a tree with one release whichever way it is finished, and where
//    the subject is somebody else's tool the sentence is still about
//    that tool's history rather than about what this code does.
//
// 4. The adverb that puts a behavior in the past without naming when.
//
// 5. A sentence whose subject is the change itself. "That changed
//    nothing" is a verdict on a run and stays out of it, which the
//    lookahead does.
var SELF_HISTORY_SHAPES = [
  {
    name:  "past-habitual",
    what:  "\"used to\" as a claim about a former behavior, excluding the participle meaning " +
           "employed, which is what a form of `be`, a bare adverb or a comma in front of it marks",
    re:    new RegExp(EMPLOYED_LOOKBEHIND + "\\bused\\s+to\\s+\\w+", "g"),
  },
  {
    name:  "former-build",
    what:  "an older, earlier, previous or prior BUILD of this server, and earlier versions of " +
           "this server spelled out. A former release, and a former version of a script or a " +
           "record or somebody else's client, are all things that exist and are not matched",
    re:    new RegExp(
             "\\b(?:older|earlier|previous|prior)\\s+builds?\\b" +
             "|\\b(?:older|earlier|previous|prior)\\s+versions?\\s+of\\s+(?:this|the)\\s+" +
             "(?:server|build|page|repository|package)\\b",
             "gi"
           ),
  },
  {
    name:  "always-claim",
    what:  "\"has always\", which reaches back over a life this tree has not had. Where the " +
           "subject is somebody else's tool the span is real, and naming the tool rather than " +
           "the span says the same thing without the claim",
    re:    /\b(?:has|have|had)\s+always\b/g,
  },
  {
    name:  "former-behavior-adverb",
    what:  "\"previously\", \"formerly\" or \"hitherto\", which put a behavior in a past with no " +
           "build to name",
    re:    /\b(?:previously|formerly|hitherto)\b/gi,
  },
  {
    name:  "the-change-as-subject",
    what:  "a sentence opening on the change itself, which reads as a note to whoever made it. " +
           "A run that changed nothing is a verdict rather than a history and is not matched",
    re:    /(?:^|[.:;!?]\s+)(?:This|That)\s+changed\b(?!\s+nothing\b)/g,
  },
];

// ---------------------------------------------------------------------------
// Shapes the structural detectors below read
// ---------------------------------------------------------------------------

// The one module that may drive the destructive mail-agent verbs. It is
// named as a path rather than as a symbol because the rule is about
// which domain owns the operation, and a path survives every rename
// inside the file it names.
var MAILBOX_ADAPTER = "lib/mail/mailbox.js";

// The one module that reconciles the sealed message bodies on disk
// against the rows naming them, and the only other one that may remove
// one. Named as a path for the same reason the adapter above is.
var BLOB_RECONCILER = "lib/store/blobs.js";

// The one module that screens text somebody else wrote before a person
// reads it, and so the only place the framework's text guard is composed
// for display. Named as a path for the same reason the two above are.
var DISPLAY_SCREEN = "lib/text/index.js";

// A composition of the framework's repairing text guard, and a hand-rolled
// pass over the C1 range. Both are anchored on the framework's own token
// and on the code points themselves rather than on any helper's name,
// because the helper that wrapped them was called four different things
// in four files and a fifth spelling would have gone unread.
var DISPLAY_SCREEN_BY_HAND_RE =
  /\bguardText\s*\.\s*sanitize\s*\(|0x0*80\s*,\s*0x0*9[fF]\b/;

// The one module that reads the documentation blocks, and so the one place
// a matcher for their tags belongs. The gates reach it through
// scripts/source-primitives.js and the wiki reaches it directly. Written as
// a pattern anchored on the tail of the path rather than as an exact
// string, so the exemption is provable on a fixture standing in for that
// file.
var DOCUMENTATION_READER_RE = /(?:^|[/\\])lib[/\\]web[/\\]wiki[/\\]blocks\.js$/;

// A documentation tag OPENING a pattern, which is the shape of a parse: a
// regular expression literal, or a RegExp built from a string, beginning
// with an at sign and then one of three things. The first is a tag the
// reader returns, not followed by a name character or an escaped dot, so
// an address such as `@example\.net` in a pattern is not a tag. The second,
// anchored with `^`, is a capture opening on a letter class, which is a
// reader of any tag name. The third, anchored with `^`, is the end of the
// string followed by `+`, which builds the pattern from a tag name held in a
// variable. Naming a tag in a message or in prose is not this shape and is
// deliberately outside it, because the sentence describing a rule must not
// trip the rule.
var DOCUMENTATION_TAG_MATCHER_RE = new RegExp(
  "(?:\\/|RegExp\\s*\\(\\s*[\"'])(?:" +
    "\\^?@(?:primitive|signature|since|status|spec|deprecated|originated|related|" +
      "module|nav|title|order|slug|featured|intro|card|opts|example|section)" +
      "(?![A-Za-z0-9_$.-]|\\\\{1,2}\\.)" +
    "|\\^@(?:\\((?:\\?:)?(?:\\[A-Za-z|\\[a-z|\\\\w)|[\"']\\s*\\+)" +
  ")");

// The vendored module that decides which audit namespaces need no
// registration. Read rather than copied, so this gate cannot disagree
// with the framework about what it accepts.
var VENDOR_AUDIT_MODULE = "lib/vendor/blamejs/lib/audit.js";

// A filesystem entry point, by the name the platform and the framework
// publish rather than by whatever local name wraps it.
var FS_ENTRY_RE = new RegExp(
  "\\b(?:nodeFs|fs)\\s*\\.\\s*(?:promises\\s*\\.\\s*)?" +
  "(?:rm|rmSync|unlink|unlinkSync|writeFile|writeFileSync|appendFile|appendFileSync|" +
  "readFile|readFileSync|rename|renameSync|open|openSync|mkdir|mkdirSync|copyFile|" +
  "copyFileSync|createReadStream|createWriteStream|existsSync|statSync|lstatSync|" +
  "readdir|readdirSync|chmod|chmodSync|truncate|truncateSync)\\s*\\(" +
  "|\\bb\\s*\\.\\s*atomicFile\\s*\\.\\s*[A-Za-z]+\\s*\\(",
  "g");

// A path assembled where it is used: a join or a resolve, or a string
// glued together with a plus.
var PATH_ASSEMBLED_RE = /\b(?:join|resolve)\s*\(/;

// A filesystem removal, which is the half of FS_ENTRY_RE that destroys
// rather than reads or writes.
var FS_REMOVE_RE = new RegExp(
  "\\b(?:nodeFs|fs)\\s*\\.\\s*(?:promises\\s*\\.\\s*)?" +
  "(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\\s*\\(");

// Where a sealed message body's path can come from. Two frozen
// contracts: the blob directory the mailbox adapter reports out of
// `describe()`, and the one function that turns a digest into the path
// it is filed at. A module that has neither does not know where a
// message body lives and cannot be removing one.
var BLOB_PATH_SOURCE_RE = /\bblobDir\b|\bpathFor\s*\(|\b_blobPath\s*\(/;

// A file's presence read as a POSITIVE condition that ends the call.
// The negated reading is a different question and is not matched: `if
// (!exists(x))` decides that something is ABSENT, which is a fact
// presence really does settle.
//
// Both entry points are named by the API that publishes them rather
// than by any local wrapper, so renaming a helper cannot quiet this.
var EXISTENCE_EARLY_EXIT_RE = new RegExp(
  "\\bif\\s*\\(\\s*(?:[A-Za-z_$][\\w$]*\\s*\\.\\s*)*" +
  "(?:existsSync|exists)\\s*\\([^;{}]*\\)\\s*\\)\\s*\\{?\\s*(?:return|continue)\\b",
  "g");

// A write, by the name the platform and the framework publish. Bare
// `write(` is deliberately absent: a socket, a response and a report all
// carry one, and none of them puts bytes at a path.
var FILE_WRITE_RE =
  /\b(?:writeSync|writeFileSync|writeStream|appendFileSync|copyFileSync)\s*\(/g;

// The blank line RFC 5322 section 2.1 ends a header block at, in every
// spelling this tree writes it: the CRLF pair a conforming wire message
// carries, the bare LF pair a message read off a disk carries, and the
// octet lists either can be built from.
//
// Matched on the SOURCE text rather than on the mask. The mask blanks
// an escape sequence inside a string literal, and the escape is the
// whole of what tells these two values apart from each other and from
// a single line ending.
var BLANK_LINE_SOURCE_RE = new RegExp(
  "\\\\r\\\\n\\\\r\\\\n" +
  "|\\\\n\\\\n" +
  "|0x0[dD]\\s*,\\s*0x0[aA]\\s*,\\s*0x0[dD]\\s*,\\s*0x0[aA]" +
  "|0x0[aA]\\s*,\\s*0x0[aA]");

// Answering "where does the header block end" by looking through a
// whole message for one of those values.
var WHOLE_MESSAGE_SEARCH_RE = /\.\s*(?:indexOf|lastIndexOf|includes|search|split)\s*\(/g;

// Every identifier the file binds to one of those values. The detector
// reads the VALUE rather than the name, so renaming the constant cannot
// quiet it and deleting the value is what makes it go silent.
function _blankLineNames(text) {
  var names = {};
  var re = /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=([^\n]*)/g;
  var m;
  while ((m = re.exec(text)) !== null) {
    if (BLANK_LINE_SOURCE_RE.test(m[2])) names[m[1]] = 1;
  }
  return names;
}

// Whether a call's first argument is one of those values, written where
// it is used or reached through a name the file bound to it.
function _isBlankLineArgument(argSource, names) {
  if (BLANK_LINE_SOURCE_RE.test(argSource)) return true;
  var ident = /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(argSource);
  return ident !== null && names[ident[1]] === 1;
}

// The mail verbs that destroy or relocate a message on the store side
// alone. `move` and `expunge` are the framework's names for them and
// `hardExpunge` is the message store's; all three are contracts rather
// than local symbols, so the matcher survives a rename of whatever
// handle they are reached through.
var DESTRUCTIVE_MAIL_VERB_RE = /\.(?:expunge|move|hardExpunge)\s*\(/;

// The framework's per-row crypto-erase, aimed at the account table. Two
// contracts rather than local symbols: `eraseHard` is the framework
// primitive, and the account table is reached through the schema
// declaration every reader of it resolves the name from, so renaming
// either one is a migration rather than an edit.
var ACCOUNT_ERASE_RE = /\beraseHard\s*\(\s*tables\s*\.\s*ACCOUNTS\b/g;

// The mail erasure that has to accompany it, named as the verb rather
// than as whatever handle it is reached through, so the check survives a
// rename of the handle. Renaming the VERB makes this fire rather than go
// quiet, which is the direction a check has to fail in.
var ACCOUNT_MAIL_ERASE_RE = /\beraseAccountMail\s*\(/g;

// The reason strings the identity layer answers a held mailbox with.
// They are minted as `"account-" + row.status` off the frozen status
// list, so this derives them rather than spelling them: a fifth status
// added to the store arrives here with no second edit, which is the
// whole property the detector below depends on.
//
// `active` is not among them. An active account is never refused, so
// there is no reason string for it to mint, and including it would make
// every correct consumer look incomplete.
var HELD_ACCOUNT_REASONS = tables.ACCOUNT_STATUS
  .filter(function (name) { return name !== "active"; })
  .map(function (name) { return "account-" + name; });

// A DKIM selector row destroyed, in either of the two spellings this
// store has for destroying a row. Both are contracts rather than local
// symbols: `deleteMany` is the framework's bulk delete and `deleteRow`
// is the only single-row write path this identity layer has, and the
// selector table is reached through the schema declaration every reader
// resolves the name from, so renaming any of the three is a migration
// rather than an edit.
//
// The bulk spelling names the table at the head of a chain and the verb
// at the end of it, so the two are matched across a structural boundary
// rather than a distance: a chain is one statement, so the span may not
// cross a semicolon, and the walk has already cut this text to one
// function body. The quantifier is a ReDoS backstop set far above any
// real statement and is never the precision mechanism. A count standing
// in for the boundary stops matching the moment the code grows past it,
// and a matcher that has gone quiet passes green forever.
//
// The statement bound is what keeps a READ of this table from being
// mistaken for a delete of it. Without it the span runs from a
// `.count()` or an `.all()` several statements earlier to the delete
// further down, and the finding is reported against a line that destroys
// nothing.
var SELECTOR_ROW_DELETE_RE = new RegExp(
  "\\bdeleteRow\\s*\\(\\s*tables\\s*\\.\\s*SELECTORS\\b" +
  "|" +
  "\\btables\\s*\\.\\s*SELECTORS\\b(?:(?!\\n\\})[^;]){0,4000}?\\.\\s*deleteMany\\s*\\(",
  "g");

// The erasure of the sealed private key such a row named. One exported
// verb on the module that owns the keys folder, so there is one place
// that knows what a keyRef resolves to on disk, and naming the verb
// rather than the handle keeps this reading through whatever the caller
// bound it to.
var SELECTOR_KEY_ERASE_RE = /\beraseKeyFiles\s*\(/g;

// The decision the eraser is handed, in either spelling a function
// argument takes. What makes an argument the decision is that it is a
// function at all: the eraser runs it with the material already moved
// aside and nothing able to interleave, so whatever it decides is
// decided against the volume the erasure is about to change rather than
// against the one it started on.
var SETTLING_DECISION_RE = /\bfunction\b|=>/;

// A write that puts something on the data volume, through the one
// framework surface every such write in this repository goes through.
// The name is that surface rather than a local helper, so a body that
// renames its own path builder still reads as writing to the volume.
var VOLUME_FILE_WRITE_RE = /\batomicFile\s*\.\s*write[A-Za-z]*\s*\(/g;

// A write taken back off the volume. Node's own removal verbs, which
// are the only ones this repository has, so this reads whatever the
// handle around them is called.
var VOLUME_FILE_REMOVE_RE = /\.\s*(?:rm|rmSync|unlink|unlinkSync)\s*\(/g;

// The columns a unique message identifier is allocated out of. RFC 9051
// section 2.3.1.1 names both, and both are columns of the folder table
// rather than local variables, so neither is a symbol a rename could
// quietly retire: changing either one is a migration, and a client
// addresses a message by the pair.
var UID_ALLOCATION_COUNTER_RE = /\b(?:uidnext|uidvalidity)\b/gi;

// The point at which another caller can run. One synchronous database
// handle in one process means a run of statements carrying none of these
// cannot be cut in half, and a body carrying one can be.
var SUSPENSION_POINT_RE = /\bawait\b/g;

// The verbs that change or destroy a row that already exists.
// `updateOne`, `deleteOne` and `eraseHard` are framework contracts;
// `updateRow` and `deleteRow` are the only write path this identity
// layer has, which its own table declarations say in as many words
// because the sealed columns are bound to the row identity. All five are
// contracts rather than local symbols, so the matcher survives a rename
// of whatever handle they are reached through, and renaming one of them
// is a migration rather than an edit. An insert is deliberately not
// here: it mints its own identity rather than carrying one read earlier,
// so it cannot be the shape below.
var ROW_MUTATION_VERB_RE = /\.\s*(?:updateOne|deleteOne|eraseHard|updateRow|deleteRow)\s*\(/g;

// A row identity as it is written at a call site. `_id` is the
// `rowIdField` every table in this server declares, and the framework
// binds each sealed cell to it, so changing the spelling is a migration
// of the schema rather than a rename of a variable.
var ROW_IDENTITY_RE = /\b([A-Za-z_$][\w$]*)\s*\.\s*_id\b/g;

// The framework's read entry point. Between a suspension and a write
// this is the shape of a row being consulted again, which is the whole
// of what makes the write safe to take.
var DB_READ_ENTRY_RE = /\bb\s*\.\s*db\s*\.\s*from\s*\(/;

// Where a name is bound inside one body. A row read into a local is
// bound with a declaration keyword, and the OFFSET of that declaration
// is what says whether the read happened before a suspension or after
// it. A name with no declaration in this body is a parameter or an outer
// binding, which is a handle rather than a row this body read, so it is
// passed over.
//
// The name is escaped before it becomes a pattern. A JavaScript
// identifier may carry a dollar sign, which is an anchor in a regular
// expression, so a name built in raw would match nothing and the offset
// would read as "never bound here" rather than as "bound before the
// suspension". That failure is silent and in the direction that reports
// nothing, which is the one a matcher must not fail in.
function _bindingOffsetIn(mask, bodies, body, name) {
  var literal = name.replace(/[$]/g, "\\$&");
  var re = new RegExp("(?:^|[^\\w$.])(?:var|let|const)\\s+" + literal + "(?![\\w$])\\s*=", "g");
  var found = _matchesIn(mask, bodies, body, re);
  return found.length === 0 ? -1 : found[found.length - 1].offset;
}

// Whether a row write at `writeOffset` puts back what a read taken
// before a suspension said, with nothing having re-consulted the row in
// between.
//
// Three offsets decide it, and the order between them is the whole
// finding: the binding that read the row, a suspension after it, and the
// write. A suspension that cannot be reached from is not one, so the
// candidates are filtered through the same reachability walk the rest of
// this file uses rather than by their position in the text.
//
// The window that clears it runs from the LAST such suspension to the
// start of the write's own statement, so a write that names the database
// in its own chain does not clear itself.
function _staleRowWrite(mask, bodies, body, writeOffset, awaits) {
  var stmt = _statementAround(mask, writeOffset, body);
  var stmtText = mask.slice(stmt.start, stmt.end);
  var seen = {};
  var names = [];
  var m;
  ROW_IDENTITY_RE.lastIndex = 0;
  while ((m = ROW_IDENTITY_RE.exec(stmtText)) !== null) {
    if (seen[m[1]] === 1) continue;
    seen[m[1]] = 1;
    names.push(m[1]);
  }
  for (var n = 0; n < names.length; n += 1) {
    var bound = _bindingOffsetIn(mask, bodies, body, names[n]);
    if (bound === -1 || bound >= writeOffset) continue;
    var crossing = -1;
    for (var a = 0; a < awaits.length; a += 1) {
      var at = awaits[a].offset;
      if (at <= bound || at >= writeOffset) continue;
      if (!_reachesLater(mask, at, writeOffset)) continue;
      if (at > crossing) crossing = at;
    }
    if (crossing === -1) continue;
    if (crossing < stmt.start &&
        DB_READ_ENTRY_RE.test(mask.slice(crossing, stmt.start))) continue;
    return names[n];
  }
  return null;
}

// The readings a console act about a SET is decided on, by the verbs
// that answer them rather than by whatever handle they are reached
// through. Each is a primitive this server publishes under that exact
// name, so renaming one is a change to a documented surface rather than
// an edit, and deleting the reading takes the matcher with it.
var CONSOLE_SET_READ_SOURCE =
  "\\.\\s*(?:accounts|domains)\\s*\\.\\s*list\\s*\\(" +
  "|\\.\\s*queue\\s*\\.\\s*(?:list|show)\\s*\\(";

// The acts whose correctness is a statement about that set rather than
// about the row or the entry they name: the three that decide who is
// left able to reach the operator interface, and the one that erases a
// message an operator is then told about. Published primitives again,
// for the same reason.
var CONSOLE_SET_ACT_RE =
  /\.\s*accounts\s*\.\s*(?:setAdmin|suspend|delete)\s*\(|\.\s*domains\s*\.\s*setStatus\s*\(|\.\s*queue\s*\.\s*remove\s*\(/g;

// The action the console files when it refuses to leave this server with
// nobody able to sign in. It is a frozen contract rather than a symbol:
// an auditor filters on it, so it survives every rename of the function
// that emits it and disappears only when the refusal itself is deleted.
var CONSOLE_STRANDING_ACTION = "blamepost.web.last_administrator_removal_not_permitted";

// The name of whatever function emits that action, READ from the action
// rather than assumed. A matcher anchored on the spelling the guard
// happens to carry today goes silent the moment somebody renames it, and
// the acts it stopped reading are the ones that take the console away.
function _consoleGuardNames(file, mask) {
  var names = [];
  var at = file.text.indexOf(CONSOLE_STRANDING_ACTION);
  while (at !== -1) {
    var span = _enclosingFunctionSpan(mask, at);
    if (span) {
      var head = file.text.slice(Math.max(0, span.start - 240), span.start);
      var re = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
      var last = null;
      var hit;
      while ((hit = re.exec(head)) !== null) last = hit[1];
      if (last !== null && names.indexOf(last) === -1) names.push(last);
    }
    at = file.text.indexOf(CONSOLE_STRANDING_ACTION, at + 1);
  }
  return names;
}

function _consoleSetReadRe(file, mask) {
  var source = CONSOLE_SET_READ_SOURCE;
  var names  = _consoleGuardNames(file, mask);
  if (names.length > 0) source += "|\\b(?:" + names.join("|") + ")\\s*\\(";
  return new RegExp(source, "g");
}

// The published name of the outbound queue's admission reading. It is
// one of the two methods `blamepost.mail.listeners.create` refuses a
// delivery handle for not carrying, so it is a contract between the
// module that owns the queue and the module that asks it rather than a
// symbol either of them may rename on its own.
var SPOOL_ADMISSION_VERB = "admits";

// Whatever the module that owns the queue calls the function it
// publishes under that name, READ from the binding rather than assumed.
// A matcher anchored on the spelling the admitter happens to carry today
// goes silent the moment somebody renames it, and the calls it stopped
// reading are the ones that decide whether a message is taken at all.
function _spoolAdmissionNames(mask) {
  var out = [];
  var re = new RegExp("\\b" + SPOOL_ADMISSION_VERB + "\\s*:\\s*([A-Za-z_$][\\w$]*)", "g");
  var m;
  while ((m = re.exec(mask)) !== null) {
    if (out.indexOf(m[1]) === -1) out.push(m[1]);
  }
  return out;
}

// Every call of the admission reading in one file, in both spellings: the
// published one a consumer reaches through the handle, and the local one
// the owning module calls it by. The declaration of the admitter is not
// a call of it, and neither is the binding that publishes it, so both are
// passed over — what this reads is the act of asking.
function _spoolAdmissionCalls(mask) {
  var spellings = ["\\.\\s*" + SPOOL_ADMISSION_VERB];
  var names = _spoolAdmissionNames(mask);
  for (var n = 0; n < names.length; n += 1) {
    spellings.push("\\b" + names[n].replace(/[$]/g, "\\$&"));
  }
  var re = new RegExp("(?:" + spellings.join("|") + ")\\s*\\(", "g");
  var out = [];
  var m;
  while ((m = re.exec(mask)) !== null) {
    if (/\bfunction\s*$/.test(mask.slice(Math.max(0, m.index - 40), m.index))) continue;
    out.push(m.index);
  }
  return out;
}

// Where the statement holding `offset` opens, for a statement that
// follows a block.
//
// The shared statement walk balances every bracket it passes, which is
// what an expression needs and what a statement after a closing brace
// does not: an act written under `if (...) { ... }` would have its own
// statement read as starting before that whole block, and the window in
// front of it would then swallow suspensions that belong to a branch
// that already left. A brace at the act's own depth ENDS the statement
// before it, so the walk stops there.
function _statementOpensAt(mask, body, offset) {
  var depth = 0;
  for (var i = offset; i >= body.start; i -= 1) {
    var c = mask[i];
    if (c === ")" || c === "]") depth += 1;
    else if (c === "(" || c === "[") {
      if (depth === 0) return i + 1;
      depth -= 1;
    } else if (depth === 0 && (c === ";" || c === "{" || c === "}")) return i + 1;
  }
  return body.start;
}

// Whether the act at `actOffset` is carried out on a reading that a
// suspension stands after.
//
// Three offsets decide it, the same three the row rule reads, with one
// difference that is the whole of what a SET adds. A per-item act inside
// a loop is taken again on every turn, so the window does not end at the
// act: a suspension sitting AFTER it and still inside the loop is one
// that stands between the reading and the act on the NEXT turn. The
// window is widened to the end of that loop body, and only for a loop
// the reading is outside of, because a reading taken inside the turn is
// re-taken with it.
function _staleConsoleDecision(mask, body, loops, reads, awaits, actOffset) {
  var act = _statementAround(mask, actOffset, body);
  act.start = _statementOpensAt(mask, body, actOffset);
  // The LAST reading in front of the act, and reachability is
  // deliberately not asked of it. A reading answered with a refusal on
  // one branch and carried on from on the other sits in a block that
  // leaves early, and the question here is what the act was decided on
  // rather than whether every path through the block arrives.
  var read = -1;
  for (var r = 0; r < reads.length; r += 1) {
    var got = reads[r].offset;
    if (got >= act.start) continue;
    if (got > read) read = got;
  }
  if (read === -1) return null;

  var from = _statementAround(mask, read, body).end;
  var to   = act.start;
  for (var l = 0; l < loops.length; l += 1) {
    var loop = loops[l];
    if (loop.start > actOffset || loop.end <= actOffset) continue;
    if (loop.header < read) continue;
    if (loop.end > to) to = loop.end;
  }

  for (var w = 0; w < awaits.length; w += 1) {
    var at = awaits[w].offset;
    if (at < from || at >= to) continue;
    // The act's own suspension is the act, not a window in front of it.
    if (at >= act.start && at < act.end) continue;
    // A suspension on a branch that leaves before the act is not one the
    // act is standing on; a suspension after the act inside the loop is
    // reached through the loop's own edge rather than through the text.
    if (at < act.start && !_reachesLater(mask, at, actOffset)) continue;
    return true;
  }
  return null;
}

// An audit emit, by the two entry points the framework publishes plus
// the one this server wraps them in. The receiver and the entry point
// are both captured, because the three differ in ways a detector has to
// act on: `audit.record` returns a promise that rejects at its caller,
// `audit.safeEmit` catches inside the framework and cannot, and the
// store's own writer catches around `audit.record` so its call sites
// cannot either.
//
// The receiver alternatives are `audit`, which covers the framework
// handle however it is reached, and whatever local name a file binds to
// the module that owns the wrapper. That name is READ from the require
// rather than assumed, because a detector anchored on the spelling
// `auditActor` goes silent the moment one file renames its local, and
// the rows it stopped reading are the ones nobody is told about.
var AUDIT_EMIT_VERBS = "record|safeEmit";
var STORE_AUDIT_REQUIRE_RE =
  /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*"[^"]*\bactor"\s*\)/g;

function _auditEmitRe(mask) {
  var names = ["audit"];
  STORE_AUDIT_REQUIRE_RE.lastIndex = 0;
  var m;
  while ((m = STORE_AUDIT_REQUIRE_RE.exec(mask)) !== null) {
    if (names.indexOf(m[1]) === -1) names.push(m[1]);
  }
  // Longest first, so a local whose name begins with `audit` is matched
  // whole rather than truncated to the framework handle and then failing
  // on the dot that is not there.
  names.sort(function (a, c) { return c.length - a.length; });
  return new RegExp("\\b(" + names.join("|") + ")\\s*\\.\\s*(" + AUDIT_EMIT_VERBS + ")\\s*\\(", "g");
}

// The hard-erase call, by the framework verb rather than by whatever
// handle it is reached through, so a rename of the handle does not quiet
// the matcher and a deletion of the call does.
//
// Pairing it with the emit above is a question about two offsets inside
// one function body, which no regular expression answers: the store
// modules build their verbs inside a factory, so every verb's closing
// brace is indented and a `\n\}` boundary walks straight past it into
// the next verb. A character budget standing in for the boundary is
// worse again, because it stops matching as the body grows. The detector
// walks the brace structure instead.
var ERASE_HARD_RE = /\beraseHard\s*\(/g;

// Every call that destroys something this server cannot put back, by the
// verb rather than by the handle it is reached through.
//
// A row and a file are the same class of act here, which is the point of
// one list rather than two. An erasure of an account destroys rows in
// four tables and sealed message bodies under `blobs/`, and a reclaim
// destroys only files; both answer for what they destroyed in a report
// and an audit row that are the only record afterwards, and both are a
// SET of separate acts where any one can be refused. A matcher that read
// only the database half would go quiet over exactly the loop that
// unlinks message bodies.
//
// `force` on a removal is not a guard and reading it as one is the
// mistake this catches: it suppresses a file that is already gone and
// nothing else, so a mount gone read-only, a permission an operator
// changed and a file another process holds open all still raise.
//
// Node's own names, which are a frozen contract: a local alias for the
// module cannot rename them, and a call that is deleted is exactly the
// case where there is nothing left to find.
var DESTRUCTION_RE = /\b(?:eraseHard|rmSync|unlinkSync|rmdirSync)\s*\(/g;

// The same two shapes without the global flag, for the readers that ask
// "is there one of these in this text" rather than walking every match.
// A global regular expression carries its own position between calls, so
// asking it a yes-or-no question inside a loop that is walking it moves
// the walk. Built from the sources above rather than written again, so
// the two spellings of each cannot drift apart.
var DESTRUCTION_ANY_RE  = new RegExp(DESTRUCTION_RE.source);
var ACCOUNT_MAIL_ANY_RE = new RegExp(ACCOUNT_MAIL_ERASE_RE.source);

// The functions a file declares that destroy something and let the
// refusal leave them, by name.
//
// A destruction is often one call frame below the loop that drives the
// set: the loop asks for a message body to be released, and the removal
// is inside the helper that counts the references naming it first. Read
// at the call site alone that loop holds no destruction at all, so the
// matcher goes quiet over exactly the shape it exists to find, and the
// code that abandons the rest of the set passes green.
//
// What makes the reach answerable rather than a guess is the question the
// matchers already ask at a call site, asked of the callee's body
// instead: does a refusal LEAVE it. A helper that catches its own removal
// and answers with a verdict is not a destruction at its call site,
// because nothing arrives there to abandon the loop with. A helper that
// lets the refusal out is one, because the refusal arrives at the call.
// So the set is built from the helpers whose destruction is uncaught, and
// it empties itself the moment one of them starts carrying a verdict.
//
// The reach is ONE frame over functions declared in the same file, and
// that boundary is declared in PATTERN_NARROWINGS with what carries the
// rest. It is deliberately not a call graph: resolving a name across
// files, through a handle or through a value would mean guessing which
// function a call reaches, and a matcher that guesses reports correct
// code, which is what teaches people to route around a detector.
function _destroyingHelpers(mask) {
  var out  = [];
  var decl = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
  var m;
  while ((m = decl.exec(mask)) !== null) {
    var openParen  = m.index + m[0].length - 1;
    var closeParen = _matchingBracket(mask, openParen);
    if (closeParen === -1) continue;
    var open = mask.indexOf("{", closeParen);
    // Nothing but whitespace stands between the parameter list and the
    // body of a function that has one, which is the reading the function
    // walk above takes of the same boundary.
    if (open === -1 || /\S/.test(mask.slice(closeParen + 1, open))) continue;
    var end = _matchingBracket(mask, open);
    if (end === -1) continue;
    // A walk of its own rather than the shared matcher. That one is
    // global and carries its position between calls, so reading it here
    // would move whichever walk is asking.
    var inner = new RegExp(DESTRUCTION_RE.source, "g");
    var body  = mask.slice(open, end);
    var d;
    while ((d = inner.exec(body)) !== null) {
      if (_caughtBeforeLeaving(mask, open + d.index)) continue;
      if (out.indexOf(m[1]) === -1) out.push(m[1]);
      break;
    }
  }
  return out;
}

// The destroying verbs, plus the calls to this file's own helpers that
// let a removal out.
//
// The helper half is anchored on a BARE name, so a method reached through
// a handle is left out: `queue.release(job)` and a local `release()` are
// different functions, and reading the first as the second reports a call
// this file never declared.
function _destructionReach(mask) {
  var helpers = _destroyingHelpers(mask);
  if (helpers.length === 0) return new RegExp(DESTRUCTION_RE.source, "g");
  return new RegExp(DESTRUCTION_RE.source +
    "|(?<![.\\w$])(?:" + helpers.join("|") + ")\\s*\\(", "g");
}

// Whether anything on the path leading to a call has already destroyed
// something, read over the text of the enclosing function up to it.
//
// It is the question that separates a first destruction from a later
// one. A first destruction that refuses has destroyed nothing, so the
// refusal is the whole answer and raising it is right. A later one is
// standing on data that is already gone, so its refusal is one more
// thing to report rather than a reason to discard the report. The mail
// half of an account erasure counts, because it destroys before it
// returns even though it is not itself one of these calls.
function _somethingAlreadyDestroyed(before) {
  return DESTRUCTION_ANY_RE.test(before) || ACCOUNT_MAIL_ANY_RE.test(before);
}

// Actor fields whose presence is itself the answer. `b.permissions`
// reads `scopes` in preference to `roles` whenever it is an array, and
// the submission listener reads `mailboxes` as the set of addresses an
// identity may send as.
var EMPTY_ACTOR_COLLECTION_RE = /\b(?:scopes|roles|mailboxes)\s*:\s*\[\s*\]/;

// A listener option that names the set a peer is measured against, and
// which the framework reads as "measure nobody" when it is absent. The
// shape is the collapse: a collection handed over only while it holds
// something, and dropped when it holds nothing.
var ALLOWLIST_COLLAPSED_WHEN_EMPTY_RE =
  /\b(?:localDomains|relayAllowedFor|allowedSenders|allowedRecipients|allowedOrigins)\s*:[^,;\n]*\.length\s*(?:>\s*0\s*)?\?[^,;\n]*:\s*(?:undefined|null)\b/;

// The question "which addresses reach this mailbox", asked of the alias
// table. Two published tokens make it: the store verb that reads the
// table, and the filter key that narrows it to one destination. Together
// they are the derivation of an account's sending identities, and this
// server has one of those.
//
// The gap is a ReDoS backstop across an options literal rather than a
// precision mechanism, so the key is still found when it is not the
// first entry and when the object is written over several lines.
var SENDING_IDENTITY_REDERIVED_RE =
  /\baliases\s*\.\s*list\s*\(\s*\{[\s\S]{0,240}?\bdestination\s*:/g;

// The module that owns the derivation, which is the one file allowed to
// ask. Matched on the path rather than on the function name, because a
// rename inside that file changes nothing about which module owns the
// question, and a detector anchored on the name would go quiet on one.
var SENDING_IDENTITY_OWNER_RE = /(?:^|[\\/])lib[\\/]mail[\\/]listeners\.js$/;

// The framework call that builds an outbound delivery chain, and the one
// module allowed to make it.
//
// The name is the framework's published surface rather than a local a
// rename could take away, and the dots are spaced because a call written
// across several lines is the same call. The owner is matched by path
// for the reason the derivation above is: which module owns the outbound
// chain is not a fact about any name inside it.
var OUTBOUND_COMPOSER_BUILT_RE =
  /\bb\s*\.\s*mail\s*\.\s*send\s*\.\s*deliver\s*\.\s*create\s*\(/g;
var OUTBOUND_COMPOSER_OWNER_RE = /(?:^|[\\/])lib[\\/]mail[\\/]delivery\.js$/;

// The framework's two answers about a domain name, which are a
// published surface rather than a local name a rename could take away.
//
// They answer different questions and only one of them yields a name.
// `validate` says whether a string MAY be a domain, and the strict
// profile it is asked under admits the DNS root's trailing dot, because
// `example.com.` is the absolute form of RFC 1035 section 2.3.1 and a
// perfectly valid name. `sanitize` says WHICH domain it is, and it is
// the only one of the two that removes that dot and folds the case RFC
// 4343 says is not a difference. So a caller that asks the first
// question and keeps the string it asked about is holding one spelling
// of a name rather than the name, and every store row, file path and
// cache key it goes on to key is keyed on the spelling.
//
// The remaining alternatives are this repository's own derivation,
// which composes both halves in one place, and its non-throwing sibling
// that the readers on the network side compose instead. Any of the
// three counts as deriving.
var DOMAIN_ADMITTED_RE = /\bguardDomain\s*\.\s*validate\s*\(\s*([A-Za-z_$][\w$]*)/g;
var DOMAIN_DERIVED_RE  =
  /\bguardDomain\s*\.\s*sanitize\s*\(|\bcanonicalDomain\s*\(|\bparseDomain\s*\(/;

// The same class through the other door, and the one no admission call
// appears in at all: a domain folded BY HAND.
//
// A case fold is most of the derivation and is not it. RFC 4343 says
// case is not a difference and `toLowerCase` settles that half, which is
// exactly why the shape looks finished; RFC 1035 section 2.3.1 says the
// trailing dot is not a difference either, and nothing here settles
// that half. So a hand fold agrees with the derivation on three of the
// four spellings of every name and disagrees on the fourth, which is
// the disagreement that survives review: it is invisible until a value
// carrying the root dot reaches it, and then it is total.
//
// There is no correct hand fold of a domain in this repository. A caller
// either derives the name, or passes the value it was given to the layer
// that does — and the second is what a surface above the identity layer
// should be doing, because a fold written in two places is two rules
// that have already drifted apart by one dot. So the shape is the
// finding wherever it appears, with no separate test for what the folded
// value goes on to do.
//
// Anchored on `domain`, which is a schema column and the vocabulary this
// project fixes for the concept rather than a symbol somebody may
// rename: the store's `domains` rows carry the name in that property,
// and a fold of one is written over it. The bound is a statement, not a
// layout: `[^\n;]` ends the span at the end of the expression, and the
// count is a ReDoS backstop set far above the longest real one rather
// than the precision mechanism, which is the negative lookahead.
var DOMAIN_HAND_FOLDED_RE =
  /\bdomain\b(?:(?!\.\s*toLowerCase)[^\n;]){0,200}\.\s*toLowerCase\s*\(\s*\)/g;

// What the admitted name doing something afterwards looks like, in the
// six syntactic positions that carry a value out of the function it was
// checked in: returned, given a method, built into a longer string from
// either side, handed on as an option, handed on as an argument.
//
// Syntactic rather than a search for the name, because the mask keeps
// the characters inside a string literal so a matcher can read a value
// out of one, and this repository's refusals are full of sentences with
// the word `domain` in them. A bare search reads those as uses and
// reports the function that refuses correctly.
//
// A name that is admitted and never used again is a GATE, which is a
// legitimate thing to write and the shape a recipient policy takes.
// What makes a finding is the checked value traveling on.
function _domainCarriedOnwardRe(named) {
  var w = named.replace(/[$]/g, "\\$&");
  return new RegExp(
    "\\breturn\\s+" + w + "\\b" +
    "|\\b" + w + "\\s*\\." +
    "|\\b" + w + "\\s*\\+" +
    "|\\+\\s*" + w + "\\b" +
    "|:\\s*" + w + "\\s*[,}]" +
    "|\\(\\s*" + w + "\\s*[,)]");
}

// The framework's address guard, which is a published surface rather
// than a local name a rename could take away.
//
// It is the sibling of the domain pair above and it is NOT symmetrical
// with it, which is the whole reason it needs a rule of its own. The
// domain guard has a `sanitize` half that yields a name; the address
// guard has no such half at all. `validateAddress` reads the RFC 5321
// §4.1.2 addr-spec shape and `validate` reads the same shape as part of
// the wider message guard, and both answer a yes or no about the
// SPELLING they were handed. Neither ever says which mailbox it names.
//
// So there is nothing to compose here, only something to replace: this
// repository's derivation, in `lib/store/address.js`, calls the guard
// under the strict profile and then answers with a name. A caller that
// asks the guard directly is holding a verdict about one spelling out of
// several, and the one it refuses is the one a message may legitimately
// arrive carrying.
var ADDRESS_ADMITTED_RE = /\bguardEmail\s*\.\s*validate(?:Address)?\s*\(/g;

// The module that owns the derivation, matched on the path so a rename
// inside it changes nothing about which side of the boundary it sits on
// and a fixture can exercise the boundary rather than only the pattern.
// It calls the guard because it IS the composition of it, and a detector
// for a rule never fires on the rule.
var ADDRESS_DERIVATION_OWNER_RE = /(?:^|[\\/])lib[\\/]store[\\/]address\.js$/;

// The mail layer, and the one module inside it whose audit rows have a
// principal instead of a peer. Everything else there is driven by
// whoever connected: an inbound delivery, a wire refusal, a queue
// retry. Signing keys are driven by an operator running a command, and
// that operator is the answer an incident is looking for. Both are
// matched on the path, so a rename inside either file changes nothing
// about which side of the boundary it sits on, and a fixture can
// exercise the boundary rather than only the pattern.
var MAIL_LAYER_RE           = /(?:^|[\\/])lib[\\/]mail[\\/]/;
var KEY_LIFECYCLE_OWNER_RE  = /(?:^|[\\/])lib[\\/]mail[\\/]dkim\.js$/;

// A configuration schema field that names a number, and the bounds a
// number needs before anything divides by it or adds it to a moment.
var CONFIG_NUMBER_RE = /\bkind\s*:\s*"(?:integer|number)"/g;
var CONFIG_MIN_RE    = /\bmin\s*:/;
var CONFIG_MAX_RE    = /\bmax\s*:/;

// A configuration schema field that names a list, and the vocabulary an
// author reaches for when the list's order carries meaning.
var CONFIG_ARRAY_RE     = /\bkind\s*:\s*"array"/g;
var CONFIG_ORDER_KEY_RE = /\b(?:ascending|descending)\s*:/;
var ORDER_PROSE_RE      =
  /\bascending\b|\bdescending\b|\bincreasing\b|\bdecreasing\b|\bsorted\b|the one before it|each at least/i;

// The one file entitled to check a credential: the identity layer that
// owns the mailbox failure budget. Written as a path suffix so a fixture
// can exercise the boundary rather than only the pattern.
var IDENTITY_LAYER_RE = /(^|[/\\])lib[/\\]store[/\\]accounts\.js$/;

// The other identity space this server authenticates: a domain-scoped
// sending credential, reached through the documented store path
// `blamepost.store.credentials.verify`. A caller that renames its local
// handle for the registry has moved off that path, and a rename of the
// primitive itself is a breaking change the api-snapshot gate refuses, so
// the dotted tail is a frozen contract rather than a local symbol.
var CREDENTIAL_VERIFY_RE = /\.credentials\.verify\s*\(/g;

// The failure budget being spent. `recordFailure` is `b.auth.lockout`'s
// own verb, so it survives every rename this repository can make and
// disappears only when the budget itself is taken out, which is exactly
// what the detector below exists to notice.
var BUDGET_SPEND_RE = /\brecordFailure\s*\(/;

// The vault's plain seal, which binds a value to the volume and to
// nothing else. `b.vault.seal` is a framework primitive, so the dotted
// tail survives every rename this repository can make; `vault.aad.seal`
// does not match it, because the name before `.seal(` there is `aad`.
var CONTEXTLESS_SEAL_RE = /\bvault\.seal\s*\(/g;

// The plaintext's own digest, computed in the function that seals it.
// A value written under a file name that IS the hash of what it carries
// is bound by that name: the read recomputes the hash and refuses
// anything else, so the seal is not the only thing placing the value.
// `sha3Hash` is the framework's digest verb, so it survives a rename of
// whatever local handle holds it.
var VALUE_NAMED_BY_ITS_DIGEST_RE = /\bsha3Hash\s*\(/;

// A long-lived secret sealed to the volume with no context.
//
// The span is the enclosing function, because the name a value is filed
// under and the seal that carries it are settled in one body: a seal
// whose function also derives the plaintext's digest is a
// content-addressed write, and every other one is a value that opens
// wherever it is put.
function _sealedWithoutItsPurpose(file) {
  var mask = _maskOf(file);
  var out = [];
  CONTEXTLESS_SEAL_RE.lastIndex = 0;
  var m;
  while ((m = CONTEXTLESS_SEAL_RE.exec(mask)) !== null) {
    var span = _enclosingFunctionSpan(mask, m.index);
    var body = span ? mask.slice(span.start, span.end + 1) : mask;
    if (VALUE_NAMED_BY_ITS_DIGEST_RE.test(body)) continue;
    out.push(_atOffset(file, m.index,
      "this secret is sealed to the volume and to nothing else, so any other sealed value " +
      "on the volume opens in its place"));
  }
  return out;
}

// The vault's plain open, which hands a value back exactly as it found
// it when that value carries no seal. `b.vault.unseal` is a framework
// primitive, so the dotted tail survives every rename this repository
// can make; `vault.aad.unseal` does not match it, because the name
// before `.unseal(` there is `aad`.
var CONTEXTLESS_UNSEAL_RE = /\bvault\.unseal\s*\(/g;

// A reader establishing which form the value in front of it is in
// before it opens anything. Two shapes do it, and both are framework
// contracts rather than local names: the authenticated-data test, which
// separates a value bound to a context from one that is not, and a
// prefix test at offset zero, which separates a sealed cell from a file
// holding something else.
var SEAL_FORM_ESTABLISHED_RE = /\bisAadSealed\s*\(|\.indexOf\s*\([^)]*\)\s*===\s*0/;

// A sealed value opened without establishing what it is.
//
// The vault returns an unsealed value unchanged rather than refusing it,
// so a reader that hands it whatever is in the file opens the contents
// of a file nothing here wrote and carries on with them. Binding a value
// to a context is what separates it from every other sealed value on the
// volume, and the reader has to ask which form it holds before it can
// open either one.
//
// The span is the enclosing function, because the question and the open
// are settled in one body.
function _openedWithoutEstablishingItsForm(file) {
  var mask = _maskOf(file);
  var out = [];
  CONTEXTLESS_UNSEAL_RE.lastIndex = 0;
  var m;
  while ((m = CONTEXTLESS_UNSEAL_RE.exec(mask)) !== null) {
    var span = _enclosingFunctionSpan(mask, m.index);
    var body = span ? mask.slice(span.start, span.end + 1) : mask;
    if (SEAL_FORM_ESTABLISHED_RE.test(body)) continue;
    out.push(_atOffset(file, m.index,
      "this value is opened without asking which form it is in, so a file carrying no seal " +
      "at all comes back unchanged and is used as though it had opened"));
  }
  return out;
}

// A sending credential verified where no failure is recorded against it.
//
// The span is the enclosing named function when there is one and the
// whole file otherwise, so a verification mounted as an anonymous route
// handler is measured against the function that mounts it rather than
// against nothing.
function _credentialVerifiedWithoutABudget(file) {
  var mask = _maskOf(file);
  var out = [];
  CREDENTIAL_VERIFY_RE.lastIndex = 0;
  var m;
  while ((m = CREDENTIAL_VERIFY_RE.exec(mask)) !== null) {
    var span = _enclosingFunctionSpan(mask, m.index);
    var body = span ? mask.slice(span.start, span.end + 1) : mask;
    if (BUDGET_SPEND_RE.test(body)) continue;
    out.push(_atOffset(file, m.index,
      "a sending credential is verified here and no failure is recorded against it, so " +
      "guesses aimed at this surface are bounded by nothing"));
  }
  return out;
}

// The value a key carries inside an object literal, read to the next
// separator at the literal's own depth so a conditional or a nested
// call comes back whole rather than truncated at its first comma.
function _valueAfter(text, from) {
  var depth = 0;
  for (var i = from; i < text.length; i += 1) {
    var c = text[i];
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if (c === ")" || c === "]") depth -= 1;
    else if (c === "}") {
      if (depth === 0) return text.slice(from, i);
      depth -= 1;
    } else if (c === "," && depth === 0) return text.slice(from, i);
  }
  return text.slice(from);
}

function _quotedIn(text) {
  return (text.match(/"([A-Za-z0-9_.-]+)"/g) || []).map(function (s) {
    return s.slice(1, -1);
  });
}

// Every audit emit in a file, as the offset of the call, which of the
// two entry points it went through, and the text of the event it was
// handed.
//
// Three detectors ask questions of that event and none can ask them of
// a line: the argument spans several lines, carries nested calls with
// commas of their own, and is reached by bracket depth rather than by
// splitting. Written once here so all three agree about what an event
// is, and so a fourth question asked later starts from the same reading.
function _auditEvents(mask) {
  var out = [];
  var re = _auditEmitRe(mask);
  var m;
  while ((m = re.exec(mask)) !== null) {
    var arg = _firstArgument(mask, m.index + m[0].length - 1);
    if (arg === null) continue;
    out.push({ index: m.index, receiver: m[1], verb: m[2], arg: arg });
  }
  return out;
}

// Whether an emit hands on an event its own function was given, rather
// than building one.
//
// A wrapper that forwards its parameter decides nothing about what is on
// the row: its callers do, and they are scanned in their own right. So a
// question about the row's contents has no answer here and reporting one
// would point a reader at the one site that cannot fix it. An event
// reached any other way is still unreadable and still reported, because
// then there is no scanned site that built it either.
function _forwardsItsParameter(mask, event) {
  var name = /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(event.arg);
  if (!name) return false;
  var span = _enclosingFunctionSpan(mask, event.index);
  if (!span) return false;
  var head = mask.slice(Math.max(0, span.start - 240), span.start);
  var params = /\(([^()]*)\)[^()]*$/.exec(head);
  if (!params) return false;
  return params[1].split(",").some(function (p) { return p.trim() === name[1]; });
}

// The three questions above, asked the same way. A detector supplies
// what it wants to know about one event and gets back findings already
// carrying the file, the line and the enclosing function; the reading of
// the file, of the events in it and of where a finding points is settled
// here rather than in each detector, so the three cannot drift into
// disagreeing about which call is an emit or which line to name.
//
// `ask` answers with the reason text, a list of them when one event is
// wrong in more than one way, or nothing when the event is fine.
function _auditEventFindings(file, ask) {
  var mask = _maskOf(file);
  var out  = [];
  _auditEvents(mask).forEach(function (event) {
    var said = ask(event, mask);
    if (said === null || said === undefined) return;
    var reasons = Array.isArray(said) ? said : [said];
    reasons.forEach(function (reason) {
      if (typeof reason === "string" && reason.length > 0) {
        out.push(_atOffset(file, event.index, reason));
      }
    });
  });
  return out;
}

// The value a key carries at the top level of the object literal that
// opens `arg`, or null when the literal does not carry it there.
//
// Two things make the answer worth having. The depth: a key of the same
// name nested inside another object says nothing about the event's own
// column, because `metadata: { actor: peer }` names an actor in a blob
// nobody can filter on, and reading it as the event's actor would
// report a row as attributed while the column it lands in is empty. And
// the position: a key follows the literal's opening brace or a comma
// and nothing else, which is what keeps the same word appearing inside
// a quoted sentence from answering for a key that is not there.
function _literalKeyValue(arg, name) {
  var open = arg.indexOf("{");
  if (open === -1) return null;
  var head  = new RegExp("^" + name + "\\s*:");
  var depth = 0;
  for (var i = open; i < arg.length; i += 1) {
    var c = arg[i];
    if (c === "{" || c === "(" || c === "[") { depth += 1; continue; }
    if (c === "}" || c === ")" || c === "]") {
      depth -= 1;
      if (depth === 0) return null;
      continue;
    }
    if (depth !== 1 || !/[A-Za-z_$]/.test(c)) continue;
    var back = i - 1;
    while (back > open && /\s/.test(arg[back])) back -= 1;
    if (arg[back] !== "{" && arg[back] !== ",") continue;
    var found = head.exec(arg.slice(i));
    if (found) return _valueAfter(arg, i + found[0].length);
  }
  return null;
}

// The audit namespaces an event may be filed under: the framework's own,
// which need no registration, plus the ones this server registers.
//
// Both halves are read from source rather than restated here. A list
// kept beside the registration goes stale the moment one changes without
// the other, and a gate that has gone stale in that direction reports
// clean while events are being dropped.
var _namespaceCache = null;

function _registeredNamespaces() {
  if (_namespaceCache) return _namespaceCache;
  var out = { known: Object.create(null), repo: Object.create(null), frameworkListRead: false };
  var vendorText;
  try { vendorText = fs.readFileSync(path.join(REPO_ROOT, VENDOR_AUDIT_MODULE), "utf8"); }
  catch (_e) { vendorText = ""; }
  var block = vendorText.match(/FRAMEWORK_NAMESPACES\s*=\s*\[([\s\S]*?)\n\];/);
  if (block) {
    out.frameworkListRead = true;
    (block[1].match(/"[a-z][a-z0-9_-]*"/g) || []).forEach(function (s) {
      out.known[s.slice(1, -1)] = 1;
    });
  }
  _filesUnder(["lib", "bin"]).forEach(function (f) {
    var mask = _maskOf(f);
    var re = /registerNamespace\s*\(/g;
    var m;
    while ((m = re.exec(mask)) !== null) {
      var arg = _firstArgument(mask, m.index + m[0].length - 1);
      if (arg === null) continue;
      var direct = _quotedIn(arg);
      if (direct.length > 0) {
        direct.forEach(function (n) { out.known[n] = 1; out.repo[n] = 1; });
        continue;
      }
      var ident = arg.match(/([A-Za-z_$][\w$]*)/);
      if (!ident) continue;
      var decl = mask.match(new RegExp("\\b(?:var|let|const)\\s+" + ident[1] + "\\s*=([^;]*);"));
      if (!decl) continue;
      _quotedIn(decl[1]).forEach(function (n) { out.known[n] = 1; out.repo[n] = 1; });
    }
  });
  _namespaceCache = out;
  return out;
}

// The vendored tree, named once so a refusal that could not read it can
// say where it looked.
var VENDOR_TREE = "lib/vendor/blamejs";

// Which error-code namespaces the vendored framework files codes under,
// measured from the vendored tree rather than listed here.
//
// A code prefix names a namespace, not an author. This repository is the
// only thing that files a `store/` code, so a test on that prefix answers
// the question it looks like it is asking. `dkim/` is shared with the
// framework, and a test on that prefix admits sentences written for
// whoever composed the framework alongside the ones written for an
// operator. Which prefixes are shared is a property of the vendored tree
// and it changes on a refresh, so it is read on every run: a refresh that
// starts filing codes under a prefix this repository had to itself arms
// the matcher by itself, with no second edit anywhere.
//
// The counts come back with the names because a namespace set built from
// an unreadable tree is empty, and an empty set answers every question
// with "not shared". That is the direction that hides the fault, so the
// caller reports the absence rather than reading the set.
var _vendorNamespaceCache = null;

function _frameworkCodeNamespaces() {
  if (_vendorNamespaceCache) return _vendorNamespaceCache;
  var out = { names: Object.create(null), files: 0, codes: 0 };
  _walk(path.join(REPO_ROOT, VENDOR_TREE), [], JS_EXT_RE).forEach(function (abs) {
    var text;
    try { text = fs.readFileSync(abs, "utf8"); }
    catch (_e) { return; }
    out.files += 1;
    var found = text.match(/"[a-z][a-z0-9]*\/[a-z0-9][a-z0-9-]*"/g);
    if (!found) return;
    found.forEach(function (literal) {
      out.codes += 1;
      out.names[literal.slice(1, literal.indexOf("/"))] = 1;
    });
  });
  _vendorNamespaceCache = out;
  return out;
}

// Which framework tables record where an audit chain was cut, measured
// from the vendored schema rather than listed here.
//
// The chain the audit trail is built on begins at the first row unless a
// purge has moved its origin, and where it moved to is written into a
// table of the framework's own. That table is the one place a counter
// with no row behind it stops being a deletion and becomes a retention
// run, which makes it the highest-value row on the volume to forge: it
// is linked into no chain, is covered by no checkpoint and has no
// append-only trigger over it, so the signature the framework puts on
// the row is the only thing standing between write access to the
// database and a range that reads as archived.
//
// It is identified by the columns that make it a chain origin —
// `lastPurgedCounter` and `lastPurgedRowHash` — rather than by its name,
// so a vendor refresh that renames the table or adds a second one for
// another chain arms the matcher by itself. The name is what this
// repository's code writes, so the names are what the matcher needs; the
// column pair is how they are found.
//
// The count comes back with the names for the reason the namespace
// reader above gives: a set built from an unreadable tree is empty, and
// an empty set answers every question with "nothing to check", which is
// the direction that hides the fault.
var _chainOriginCache = null;

function _chainOriginTables() {
  if (_chainOriginCache) return _chainOriginCache;
  var out = { names: [], filesRead: 0 };
  _walk(path.join(REPO_ROOT, VENDOR_TREE), [], JS_EXT_RE).forEach(function (abs) {
    var text;
    try { text = fs.readFileSync(abs, "utf8"); }
    catch (_e) { return; }
    out.filesRead += 1;
    // Each declaration's span runs from its own `name:` to the next
    // one, which is a structural boundary rather than a count of
    // characters: a table that grows a column still ends where the next
    // table begins.
    var re = /\bname:\s*"([A-Za-z_][A-Za-z0-9_]*)"/g;
    var starts = [];
    var m;
    while ((m = re.exec(text)) !== null) {
      starts.push({ name: m[1], at: m.index });
    }
    for (var i = 0; i < starts.length; i += 1) {
      var end = i + 1 < starts.length ? starts[i + 1].at : text.length;
      var body = text.slice(starts[i].at, end);
      if (!/\blastPurgedCounter\s*:/.test(body)) continue;
      if (!/\blastPurgedRowHash\s*:/.test(body)) continue;
      if (out.names.indexOf(starts[i].name) === -1) out.names.push(starts[i].name);
    }
  });
  _chainOriginCache = out;
  return out;
}

// The names above plus the local constants bound to them in the file
// being scanned. Code here reads the table through a constant, so a
// matcher that only knew the literal would see the declaration line and
// nothing that uses it.
function _chainOriginNames(mask) {
  var derived = _chainOriginTables();
  if (derived.names.length === 0) {
    throw new Error("codebase-patterns: no chain-origin table found under " + VENDOR_TREE +
      " (" + derived.filesRead + " file(s) read). The matcher for a purge record read " +
      "without its signature cannot answer without one, and answering \"nothing to " +
      "check\" over a tree it could not read is the failure this refusal exists to " +
      "prevent.");
  }
  var names = derived.names.slice();
  derived.names.forEach(function (table) {
    var re = new RegExp("\\b([A-Za-z_$][\\w$]*)\\s*=\\s*[\"']" + table + "[\"']", "g");
    var m;
    while ((m = re.exec(mask)) !== null) {
      if (names.indexOf(m[1]) === -1) names.push(m[1]);
    }
  });
  return names;
}

// Site-level exceptions, printed for the same reason the directory ones
// are: an exclusion nobody can see at run time is indistinguishable from
// a matcher that has stopped working.
var SITE_EXCEPTIONS = [{
  detector: "destructive-mail-verb-outside-the-adapter",
  site:     MAILBOX_ADAPTER,
  reason:   "the mailbox adapter owns the folder row, the sequence number and the sealed " +
            "message octets that the store side of a delete or a move leaves behind, so it " +
            "is the module that drives both halves and the only one that may reach the " +
            "store verb directly",
}, {
  detector: "message-body-removed-outside-a-reference-check",
  site:     MAILBOX_ADAPTER,
  reason:   "the adapter removes a body only while deleting the last message row that named " +
            "it, and the count of remaining rows is the line above the removal",
}, {
  detector: "message-body-removed-outside-a-reference-check",
  site:     BLOB_RECONCILER,
  reason:   "the reconciler removes a body only after re-reading the rows immediately before " +
            "the unlink and only once the body has been unreferenced longer than an append " +
            "can take, which is the pair of checks a third site would not carry",
}];

// Directory-level exceptions, printed in the summary so an exclusion is
// visible rather than implicit. Empty is the intended state: a detector
// that skips a directory is a detector with a blind spot, and the entry
// exists so the blind spot is named in the output rather than inferable
// only from the `dirs` list.
var DIR_EXCEPTIONS = [];

// ---------------------------------------------------------------------------
// dash-punctuation-in-prose: the four classes that are not prose
// ---------------------------------------------------------------------------
//
// The detector reads every text file in the tree, so it meets four kinds
// of dash that are not punctuation in a sentence and must not be
// rewritten. Each one is a named regular expression below, a printed line
// in the run summary, and a green fixture that proves it still holds.
// Naming them here rather than leaving them implicit in the matcher is
// the point: a reader can tell a decision from an oversight.

// 1. Gitignored working state. `CLAUDE.md` and everything under
//    `.claude/` are the standing instructions and the session notes.
//    Neither reaches the repository or the tarball, so the house prose
//    rule does not reach them either.
var DASH_GITIGNORED_RE = /(?:^|\/)(?:CLAUDE\.md$|\.claude\/)/;

// 2. A separator the changelog generator owns. `gen-changelog.js` and
//    `generate-changelog-entry.js` emit the entry header and the bullet
//    separator; `check-changelog-extract.js` quotes and matches that
//    header shape so the release workflow's notes extract cannot drift.
//    Rewriting either side makes the gate reject every entry the
//    generator has produced. The exclusion is the shape AND the file:
//    ordinary prose in those same files is still scanned.
var DASH_GENERATOR_FILES_RE = /(?:^|\/)(?:CHANGELOG\.md|gen-changelog\.js|generate-changelog-entry\.js|check-changelog-extract\.js)$/;
var DASH_GENERATOR_SHAPE_RE = new RegExp(
  "##\\s*v[^\\n]{0,32}[" + EM_DASH + "]" +
  "|\\*\\*[^*\\n]{0,160}\\*\\*\\s*[" + EM_DASH + "]"
);

// 3. A citation label naming a document's title. The separator belongs
//    to the title as published, so shortening it misquotes the standard.
var DASH_CITATION_RE = new RegExp(
  "(?:RFC|FIPS|NIST|ETSI|ISO|IETF|BCP|STD)\\s[0-9A-Za-z.:-]+\\s[" + EM_DASH + EN_DASH + "]\\s"
);

// 4. A fenced code block in markdown. Everything inside a fence is
//    literal: a dash there is part of a command, a path or a rendered
//    tree, and editing it breaks the thing the reader pastes.
var DASH_FENCE_RE = /^\s*```/;

// 5. An inline code span, which is a fence one line long and carries the
//    same literal text for the same reason. `git log -- keys/x.json`
//    reads as an interruption to the matcher and is a pathspec
//    separator to git: rewriting it produces a command that does
//    something else. Spans are removed from the line before matching
//    rather than excluded by a whole-line test, so ordinary prose either
//    side of one is still read.
var DASH_INLINE_CODE_RE = /`[^`\n]*`/g;

// The printed form of the four, so the run says which exclusions are in
// force without anyone opening this file.
var DASH_EXCLUSION_CLASSES = [
  { name: "gitignored working state",   what: "CLAUDE.md and .claude/, which never reach the repository or the tarball" },
  { name: "generator-owned separator",  what: "the changelog entry header and bullet separator, in the files that emit or match them" },
  { name: "citation label",             what: "a standards document's title as published, for example an RFC or FIPS label" },
  { name: "fenced code block",          what: "everything between markdown fences, where a dash is part of what the reader pastes" },
  { name: "inline code span",           what: "backticked text on one line, for the same reason as a fence: `git log -- path` is a pathspec, not an aside" },
];

// The dash matcher. JavaScript is read through its comments alone; every
// other format is read whole, so an operator-facing string in a workflow,
// a config file or a document is in scope. The narrowing on JavaScript
// literals is declared in PATTERN_NARROWINGS and printed with the rest.
function _dashScan(file) {
  var out = [];
  var rel = file.rel;
  if (DASH_GITIGNORED_RE.test(rel)) return out;

  var isJs      = /\.(?:js|mjs|cjs)$/.test(rel);
  var isMd      = /\.md$/.test(rel);
  var generated = DASH_GENERATOR_FILES_RE.test(rel);
  var fence     = false;

  for (var i = 0; i < file.lines.length; i++) {
    var line = file.lines[i];
    if (isMd && DASH_FENCE_RE.test(line)) { fence = !fence; continue; }
    if (fence) continue;
    var subject = isJs ? _commentOf(line) : line;
    if (!subject) continue;
    // Inline code goes before the match rather than after, so a line
    // that is only a command cannot report and a line that mixes prose
    // with one still can.
    subject = subject.replace(DASH_INLINE_CODE_RE, " ");
    if (!DASH_RE.test(subject)) continue;
    if (DASH_CITATION_RE.test(subject)) continue;
    if (generated && DASH_GENERATOR_SHAPE_RE.test(subject)) continue;
    out.push({ file: rel, line: i + 1, content: line.trim() });
  }
  return out;
}

// Tokens a detector's pattern deliberately does not carry, printed
// beside the directory exceptions for the same reason. A narrowing that
// lives only inside a regular expression is invisible at run time: the
// gate reports clean and nobody can tell whether the token was
// considered and ruled out or simply never written down. Each entry
// names the detector, the token, and what replaces the coverage.
var PATTERN_NARROWINGS = [{
  detector: "todo-fixme-hack-xxx",
  token:    "defer, deferred",
  reason:   "in a mail server the bare token is delivery state rather than an unfinished-work " +
            "marker, because a temporary failure produces a deferred recipient and the composer " +
            "returns it under that name. The qualified DEFERRED_WORK_RE beside the main pattern " +
            "carries the coverage instead: it matches the token only where it is followed by a " +
            "later release, a future version or a follow-up patch, which is a sentence about " +
            "work and cannot be a sentence about a message",
}, {
  detector: "dash-punctuation-in-prose",
  token:    "string literals in JavaScript",
  reason:   "in a .js file the comment is read and the code is not. Every dash left in a " +
            "JavaScript literal in this tree is an owned value rather than a sentence: the " +
            "release-title separator scripts/release.js builds and then matches HEAD against " +
            "to detect a resumed release, the changelog separators the generators emit, and " +
            "the deliberately broken flag the operator-prose canary writes to prove its own " +
            "gate still fires. Rewriting any of them changes behavior. Prose in every other " +
            "format is read whole, so an operator-facing string in a workflow, a shell script " +
            "or a configuration file is in scope, and .claude/tools/dash-scan.js reports the " +
            "JavaScript literals for review",
}, {
  detector: "dns-read-awaited-without-a-budget",
  token:    "the generic query(name, qtype) reader",
  reason:   "the typed readers are the consumer surface: a module asking one question about " +
            "one name, with something waiting on the answer, which is the shape that needs a " +
            "bound at the call. The generic two-argument reader is the adapter surface, used " +
            "where a resolver is being reshaped into some other reader contract, and there " +
            "the budget belongs on the composed reader rather than on the call inside it, " +
            "because the composition is what a caller awaits. Matching it would report the " +
            "reshaper as unbounded while its own wrapper holds the budget one line away, and " +
            "a detector that fires on the correct shape is one people learn to route around. " +
            "The stalled-resolver vectors in test/layer-2-integration/wire-inbound-resolver " +
            "and test/layer-1-state/inbound-posture carry the coverage instead: each drives a " +
            "consumer path against a handle that accepts a question and never answers it, so " +
            "a reshaper that lost its bound fails there whichever reader it composes",
}, {
  detector: "wall-clock-cutoff-for-in-memory-state",
  token:    "an elapsed subtraction compared against a duration",
  reason:   "the shape `now - startedAt >= SOME_WINDOW_MS` is what the CORRECT code looks like " +
            "too. What separates the two is where `now` came from, and a line reading the " +
            "comparison cannot see that. Matching it would report every window in the tree, " +
            "including the ones already measured on elapsed time, and a detector that fires on " +
            "the correct shape is one people learn to route around. What is matched instead is " +
            "the one spelling that can only be wrong: a cutoff built by subtracting a DURATION " +
            "from the wall clock, which is never how an instant is computed and always how an " +
            "age is. The behavior on both shapes is pinned by the vectors in " +
            "test/layer-1-state/clock-step-windows, which step the wall clock under a live POP3 " +
            "maildrop and a spent report budget and assert that neither decision moves",
}, {
  detector: "row-written-back-across-a-suspension",
  token:    "a write inside a synchronous transaction callback",
  reason:   "the callback handed to `b.db.transaction` is a body of its own that cannot " +
            "suspend, which is exactly what makes it the remedy: a read, a comparison and a " +
            "write inside one are a run nothing can cut in half, so the write is decided " +
            "against the row as it stands rather than as it stood. Reading the callback as " +
            "part of the verb that opened it would report every settled site in the tree, and " +
            "a detector that fires on the correct shape is one people learn to route around. " +
            "What that leaves out of reach is a callback carrying the write and no re-read, " +
            "which is a transaction that buys nothing because a single write was already " +
            "indivisible. Recognizing it means telling a re-read from any other call in the " +
            "callback, and a matcher that guesses at that goes wrong in the direction that " +
            "reports the correct code. The vectors in " +
            "test/layer-1-state/password-reset-durability carry the coverage instead: they " +
            "land a password reset inside a sign in that is suspended in its rehash and " +
            "assert on the wire that the replaced credential opens nothing, which fails for " +
            "any shape that writes the earlier read back however it is spelled",
}, {
  detector: "row-written-back-across-a-suspension",
  token:    "a record destroyed inside a serialized turn on the strength of a reading taken " +
            "outside it",
  reason:   "every matcher here reads the source, and the source of this one is settled: a " +
            "read, no await between, then the write. What separates it is WHEN the write runs. " +
            "A body that hands its write to a per-key chain so concurrent writers cannot " +
            "overwrite each other has moved the write to the back of a queue, and the whole " +
            "queue is the window: whatever was already in it lands first, and the reading the " +
            "write was decided on described the file before any of it. Nothing at the call " +
            "site says so, and a matcher that reported every write handed to a chain would " +
            "report the chain itself, which is the remedy. The vectors in " +
            "test/layer-1-state/tlsrpt-observation-window carry the coverage instead: each " +
            "parks the reporting run at one of its two readings, lands a real transport " +
            "security failure against the same receiver inside that window, and asserts the " +
            "failure is still there to be reported afterwards, which fails for any shape that " +
            "destroys the file on the earlier reading however it is spelled",
}, {
  detector: "outbound-room-measured-rather-than-taken",
  token:    "the recipient routing verdict",
  reason:   "the other answer a message carries across its own delivery is whether each " +
            "recipient still has somewhere to land, and that one is read in the handoff and " +
            "acted on in the verb that files the copy, which are two functions. Every matcher " +
            "here attributes a token to the innermost function holding it, deliberately, " +
            "because joining two siblings into one match reports a function that does neither " +
            "half and nobody can act on the finding. A matcher that reached across the call " +
            "would have to follow the call graph, which is the thing this suite does not " +
            "build. The vectors in test/layer-2-integration/delivery-commit-window carry the " +
            "coverage instead: two of them suspend a mailbox between the recipient being " +
            "accepted and the message being transmitted, on the submission listener and on " +
            "the MX listener, and assert over the wire that the suspended mailbox receives " +
            "nothing, which fails for any shape that files the copy on a verdict read earlier",
}, {
  detector: "material-written-to-the-volume-and-not-taken-back-across-a-suspension",
  token:    "a write that lands on a path another caller is also writing",
  reason:   "this reads whether a body takes its own write back, which is a question about " +
            "one caller. The other way a write goes wrong is two callers arriving at one " +
            "path: a name derived from what an operator asked for rather than minted, so two " +
            "runs derive the same one, and the second write destroys what the first put " +
            "there. Recognizing that means knowing which paths carry material only one " +
            "caller may hold, and the answer is a property of what is under the name rather " +
            "than of any shape at the call: a content-addressed message body written twice " +
            "is written with identical bytes and nothing is lost, while a sealed DKIM " +
            "private key written twice is the only copy of the first one gone. A matcher " +
            "that guessed at the difference would report the blob store, which is correct, " +
            "and a detector that fires on the correct shape is one people learn to route " +
            "around. The one path in this tree where it matters takes its name in a single " +
            "exclusive create and refuses what is already there, and the vectors in " +
            "test/layer-1-state/dkim-key-mint-window carry the coverage: two mints asked for " +
            "one selector at once, and a key file left by a run that stopped, each asserting " +
            "that every record the domain publishes still holds the key it names and that " +
            "the key holds the public half that record carries",
}, {
  detector: "set-destroyed-without-a-verdict-per-item",
  token:    "a destruction more than one call frame below the loop, or reached through a handle",
  reason:   "the matcher reaches ONE frame, over functions this file declares by name, and " +
            "what reaches is decided by whether a refusal leaves the callee rather than by " +
            "what it is called. That covers the shape the adapters are written in, where a " +
            "loop drives a set and the removal sits inside the helper that counts the " +
            "references first. What it cannot answer is a call whose callee it would have to " +
            "guess at: a helper two frames down, a method on a handle, a function passed in " +
            "as a value, or one declared in another file. Answering those means resolving a " +
            "name to a body across the tree, and a matcher that guesses which function a call " +
            "reaches reports correct code, which is what teaches people to route around a " +
            "detector. The vectors in test/layer-2-integration/expunge-body-refusal carry the " +
            "coverage instead: they put one message body out of the volume's reach and drive " +
            "IMAP EXPUNGE and a POP3 commit over a socket, the sessionless destroy verb, and " +
            "an account erasure, asserting that the messages behind the refused one still " +
            "went and that each caller was told which one did not, which fails for any shape " +
            "that lets the removal abandon the set however many frames down it sits",
}, {
  detector: "self-history-in-source",
  token:    "no longer",
  reason:   "the phrase reads as a claim about a former build in a document and as an ordinary " +
            "present-state fact in a mail server, and the second is what this tree carries: a " +
            "mailbox that no longer exists, a body that no longer matches its digest, an " +
            "account that no longer accepts sign in, a domain this server no longer hosts. " +
            "Measured across lib, bin, scripts and test, the phrase appears 166 times and " +
            "almost every one of them is a fact about mail data rather than about the code, so " +
            "matching it would report correct prose by the hundred and a detector that fires " +
            "on the correct shape is one people learn to route around. What separates the two " +
            "readings is whether the subject is the software or something it holds, which no " +
            "matcher here can answer. The one occurrence in this tree that IS a claim about a " +
            "former build says so twice, in `used to accept and no longer does`, and the past " +
            "habitual half of the shape above reports it",
}, {
  detector: "self-history-in-source",
  token:    "the participle in `used to`, meaning employed",
  reason:   "`used to` writes two readings the same way, and the one this tree is full of is " +
            "the participle: a value compared and never used to key anything, a shape checked " +
            "before it is used to narrow a query, a header that cannot be used to write a " +
            "local address. The participle is excluded by what stands in front of it, which is " +
            "a form of `be` with or without an adverb between, a bare adverb where that form " +
            "is elided, or a comma opening the reduced relative clause it sits in. That leaves " +
            "one shape out of reach in each direction: a participle whose auxiliary is further " +
            "back than one word takes an allow marker, and a past habitual written `it never " +
            "used to` is not reported. Both are one line of prose to settle by reading, which " +
            "is the trade a matcher that guessed would take away",
}];

// ---------------------------------------------------------------------------
// Raw control bytes
// ---------------------------------------------------------------------------

// Tab, newline and carriage return are the three control characters a
// text file carries as layout. Every other code point below the space,
// and DEL at 0x7f, is a byte no editor shows and no reviewer sees.
function _isRawControl(code) {
  if (code === 0x09 || code === 0x0a || code === 0x0d) return false;
  return code < 0x20 || code === 0x7f;
}

// Render the offending line for the report WITHOUT the byte in it. The
// summary is printed to stdout and copied into
// `.test-output/codebase-patterns.log`, so passing the raw character
// through would make the log itself the thing grep calls binary, which
// is the failure this detector exists to stop.
function _escapeControls(line) {
  var out = "";
  for (var i = 0; i < line.length; i++) {
    var code = line.charCodeAt(i);
    if (!_isRawControl(code)) { out += line.charAt(i); continue; }
    out += "<0x" + (code < 16 ? "0" : "") + code.toString(16) + ">";
  }
  return out;
}

function _controlByteScan(file) {
  var out = [];
  for (var i = 0; i < file.lines.length; i++) {
    var line = file.lines[i];
    for (var j = 0; j < line.length; j++) {
      if (!_isRawControl(line.charCodeAt(j))) continue;
      out.push({
        file:    file.rel,
        line:    i + 1,
        content: _escapeControls(line).trim(),
      });
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Start tags in shipped templates
// ---------------------------------------------------------------------------

// The types a template may give a script element that carries a body. A
// browser treats a script element with one of these types as a data
// block and does not run its body. The comparison ignores ASCII case,
// ASCII whitespace at either end, and any parameters after a `;`. A type
// that is not listed here counts as script, including a JavaScript
// spelling that appears nowhere in this file.
var TEMPLATE_DATA_BLOCK_TYPES = [
  { type: "application/ld+json", what: "JSON-LD structured data, which search engines read from the page source" },
  { type: "application/json",    what: "a JSON document that an island reads with JSON.parse from the element's text" },
];

// The whitespace the HTML tokenizer separates a tag's parts with: tab,
// line feed, form feed, carriage return and space.
var HTML_TAG_WS_RE = /[\t\n\f\r ]/;

// The end tag that closes a script element's body: `</script` in any
// ASCII case, followed by whitespace, `/`, `>` or the end of the text.
var HTML_SCRIPT_END_RE = /<\/script(?=[\t\n\f\r />]|$)/gi;

// A script source that resolves to this origin: `/` followed by a
// character that cannot begin a host. `//host`, `/\host` and a tab or
// newline between the two slashes all resolve off this origin, and a
// character reference could decode to any of them.
var TEMPLATE_SCRIPT_SRC_RE = /^\/[A-Za-z0-9._~-]/;

// ASCII letters folded to lowercase, every other code point unchanged.
function _asciiLower(s) {
  return s.replace(/[A-Z]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) + 32); });
}

// The start tag opening at `lt`, read the way the HTML tokenizer reads
// one. The tag name ends at whitespace, `/` or `>`. An attribute name is
// folded to lowercase and may open with `=`. A value is double-quoted,
// single-quoted or unquoted, and a `>` inside a quoted value belongs to
// the value. A `value` of null is an attribute written with no `=`. An
// attribute written twice is returned twice, in source order. Character
// references in a value stay encoded. `end` is the offset after the
// closing `>`, or the length of the text when the tag does not close.
function _htmlStartTag(text, lt) {
  var i = lt + 1;
  while (i < text.length && !HTML_TAG_WS_RE.test(text[i]) && text[i] !== "/" && text[i] !== ">") i += 1;
  var tag = { name: _asciiLower(text.slice(lt + 1, i)), attrs: [], end: text.length, closed: false };
  while (i < text.length) {
    var c = text[i];
    if (c === ">") { tag.end = i + 1; tag.closed = true; return tag; }
    if (HTML_TAG_WS_RE.test(c) || c === "/") { i += 1; continue; }
    var at = i;
    i += 1;
    while (i < text.length && !HTML_TAG_WS_RE.test(text[i]) && "/>=".indexOf(text[i]) === -1) i += 1;
    var attr = { name: _asciiLower(text.slice(at, i)), value: null, at: at };
    tag.attrs.push(attr);
    var j = i;
    while (j < text.length && HTML_TAG_WS_RE.test(text[j])) j += 1;
    if (text[j] !== "=") continue;
    i = j + 1;
    while (i < text.length && HTML_TAG_WS_RE.test(text[i])) i += 1;
    var quote = text[i];
    if (quote === "\"" || quote === "'") {
      var close = text.indexOf(quote, i + 1);
      if (close === -1) close = text.length;
      attr.value = text.slice(i + 1, close);
      i = close + 1;
    } else {
      var from = i;
      while (i < text.length && !HTML_TAG_WS_RE.test(text[i]) && text[i] !== ">") i += 1;
      attr.value = text.slice(from, i);
    }
  }
  return tag;
}

// True when an attribute name is an event handler's.
function _isHandlerAttr(attr) {
  return attr.value !== null && /^on[a-z]{3,}$/.test(attr.name);
}

// Null when a script element's attributes make it a data block, or the
// phrase saying why its body counts as script. A data block carries
// exactly one `type` attribute, whose value before any `;`, with ASCII
// whitespace trimmed from both ends, is one of TEMPLATE_DATA_BLOCK_TYPES.
// An event handler on the element is reported by the handler pass.
function _templateScriptBodyVerdict(attrs) {
  var types = attrs.filter(function (a) { return a.name === "type"; });
  if (types.length > 1) {
    return "names its type more than once, so its body counts as script, which this policy refuses to run";
  }
  var essence = types.length
    ? _asciiLower(String(types[0].value || "").split(";")[0].replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, ""))
    : "";
  var listed = TEMPLATE_DATA_BLOCK_TYPES.some(function (x) { return x.type === essence; });
  return listed ? null : "carries its own body, which this policy refuses to run";
}

// How a caught error is turned into text: the message when the value
// carries one, and the value's own text when it does not. Written for any
// binding name, because the name of a catch parameter is the most
// renameable thing in a handler and a matcher anchored on `err` goes
// quiet the first time somebody writes `readErr`.
var CAUGHT_ERROR_TEXT_RE =
  /\(\s*([A-Za-z_$][\w$]*)\s*&&\s*\1\s*\.\s*message\s*\)\s*\|\|\s*String\s*\(\s*\1\s*\)/g;

// The name of the call an expression is written directly inside, or the
// empty string when it is not the first thing inside a call at all.
//
// Read by walking backwards from the expression rather than by searching
// a window in front of it. A wrapper's name sits immediately against its
// own parenthesis, so the question is adjacency, and a window would
// answer a proximity question instead: a screened value earlier in the
// same argument list would read as this one being screened.
function _wrapperCallBefore(mask, at) {
  var i = at - 1;
  while (i >= 0 && /\s/.test(mask.charAt(i))) i -= 1;
  if (mask.charAt(i) !== "(") return "";
  i -= 1;
  while (i >= 0 && /\s/.test(mask.charAt(i))) i -= 1;
  var end = i + 1;
  while (i >= 0 && /[A-Za-z0-9_$.]/.test(mask.charAt(i))) i -= 1;
  return mask.slice(i + 1, end);
}

// Whether that call is the display screen. `forDisplay` is the published
// name of the primitive that owns this question, so a local wrapper
// spelled `_screenForDisplay` is the same answer reached through a bound
// this module adds, and anything else is a different answer.
var DISPLAY_SCREEN_CALL_RE = /(?:^|\.)(?:forDisplay|[A-Za-z0-9_$]*ForDisplay)$/;

// The same question asked of a whole expression rather than of the call
// wrapped directly around one term, for a value that is a property rather
// than an argument.
var DISPLAY_SCREEN_IN_VALUE_RE =
  /(?:^|[^A-Za-z0-9_$.])(?:[A-Za-z0-9_$]+\.)*(?:forDisplay|[A-Za-z0-9_$]*ForDisplay)\s*\(/;

// The fields a refusal reaches a client under, and the field that says
// which refusal it is. RFC 8620 section 5.3 gives a SetError a `type` and
// a `description`; RFC 9457 section 3.1 gives a problem document a `type`
// and a `detail`. Both are wire contracts rather than names this
// repository chose, so neither can be renamed without changing what this
// server answers, and the pair together is what distinguishes a refusal
// somebody's client renders from an internal report row that happens to
// carry a field of the same name.
var REFUSAL_FIELD_RE = /(?:^|[\s{,])["']?(?:description|detail)["']?\s*:/g;
var REFUSAL_TYPE_KEY_RE = /(?:^|[\s{,])["']?type["']?\s*:/;

// Any `message` read out of anything. Written without a holder name,
// because the name of a catch parameter is the most renameable thing in a
// handler and a matcher anchored on `err` goes quiet the first time
// somebody writes `patchErr`.
var MESSAGE_READ_RE = /\.\s*message\b/;

// One property value, from its colon to the comma or the closing bracket
// that ends it at the literal's own depth. A structural boundary rather
// than a count of characters: a value that grows another term is still
// one value, and a detector bounded by length would stop reading the day
// it did.
function _propertyValueSpan(mask, colonIdx) {
  var depth = 0;
  for (var i = colonIdx + 1; i < mask.length; i += 1) {
    var ch = mask.charAt(i);
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return mask.slice(colonIdx + 1, i);
      depth -= 1;
    } else if (ch === "," && depth === 0) {
      return mask.slice(colonIdx + 1, i);
    }
  }
  return mask.slice(colonIdx + 1);
}

var DETECTORS = [
  {
    name: "todo-fixme-hack-xxx",
    description:
      "An unfinished-work marker in the tree. Every primitive ships at a scope its own " +
      "documentation can defend, so a marker here means either the scope was never closed " +
      "or the condition that reopens it was never written down. Close the gap, or write the " +
      "condition and who owns it into the module's comment block. Delivery state is not a " +
      "marker: a deferred message is what a temporary failure produces, so only work deferred " +
      "to a later release reads as unfinished.",
    dirs: ["lib", "bin", "scripts", "test"],
    scan: function (file) {
      var out = [];
      for (var i = 0; i < file.lines.length; i++) {
        var line = file.lines[i];
        if (UNFINISHED_RE.test(line) || DEFERRED_WORK_RE.test(line)) {
          out.push({ file: file.rel, line: i + 1, content: line.trim() });
        }
      }
      return out;
    },
    red: [
      "// TODO: bind the submission listener before this ships\n",
      "function exportMailbox() { return null; }   // not implemented yet\n",
      "// The DSN body is deferred to a later release.\n",
    ],
    green: [
      "// The retention floor refuses the delete and the audit row records the refusal.\n",
      "var waiting = outcome.deferred || [];   // messages held for the next retry window\n",
    ],
  },

  {
    name: "display-screen-rolled-again",
    description:
      "The screen between text somebody else wrote and a person reading it, composed outside " +
      "the module that owns it. Eight files used to answer this question and they answered it " +
      "differently: each composed the framework's balanced profile and took the C1 range off " +
      "afterwards, three folded a tab to a space and five did not, one folded the carriage " +
      "return and line feed run and the rest left it. So a subject that misaligned a console " +
      "table read correctly on the browser page, and a record value that was one line in the " +
      "browser broke a zone diff into three. The screen is one reader now: call " +
      "blamepost.text.forDisplay, which composes the guard, removes the C1 range the balanced " +
      "profile passes, and folds tab, line feed and carriage return to a space. A caller " +
      "holding several lines splits them and screens each one.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      if (file.rel === DISPLAY_SCREEN) return [];
      return _named(file, _lineMatcher(DISPLAY_SCREEN_BY_HAND_RE, "code")(file));
    },
    red: [
      "function _headerText(value) {\n" +
        "  return b.codepointClass.replaceRanges(\n" +
        "    b.guardText.sanitize(value, HEADER_TEXT_GUARD), C1_CONTROL_RANGES, \"\");\n}\n",
      "var C1_CONTROL_RANGES = Object.freeze([[0x0080, 0x009f]]);\n",
      "function _printable(v) {\n  return b.guardText.sanitize(String(v), { profile: \"balanced\" });\n}\n",
    ],
    green: [
      "var text = require(\"../text\");\n" +
        "function _headerText(value) {\n  return text.forDisplay(value);\n}\n",
      "var reason = text.forDisplay((err && err.message) || String(err));\n",
      // The refusal side of the same module, which is a different
      // question and is not this pattern.
      "if (text.hasControlChar(name)) throw err(\"store/bad-argument\", \"a control character\");\n",
      // The guard's other verbs are not the display screen. A write gate
      // that validates rather than repairs is composing the right thing.
      "var verdict = b.guardText.validate(text, { profile: \"strict\" });\n",
    ],
  },

  {
    name: "caught-error-text-into-an-audit-row-unscreened",
    description:
      "A caught error turned into text and written into an audit row with nothing between " +
      "it and the row. An error's message is not this server's prose: a parser answers a " +
      "header line carrying no colon with the line itself, a resolver quotes the record a " +
      "third party published, and a peer's own reply is the text a delivery failure carries. " +
      "So the codepoints in it are a stranger's to choose. `b.audit.safeEmit` redacts " +
      "credential shapes and nothing else, which means a row keeps whatever arrived, and the " +
      "row is read back later in a console table and on the administration page: a value " +
      "carrying the single-byte control sequence introducer at U+009B repaints the row above " +
      "the one it is on, a bidirectional override reverses the sentence an operator is " +
      "deciding on, and a carriage return turns one row into two. The screen is " +
      "blamepost.text.forDisplay, at the site that builds the value, because the row is " +
      "written once and read many times and nothing downstream can recover what arrived. " +
      "Pass the conversion through it, or through a local bound wrapper named for it.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      // The row's own call, which is a framework verb rather than a name
      // this repository chose, and its matching bracket as the boundary.
      // A count of characters would stop reading the moment a row grew
      // another field, and a detector that has gone quiet passes green
      // over the code it was written to read.
      var EMIT = /\bsafeEmit\s*\(/g;
      var m;
      EMIT.lastIndex = 0;
      while ((m = EMIT.exec(mask)) !== null) {
        var open = m.index + m[0].length - 1;
        var end  = _matchingBracket(mask, open);
        if (end === -1) continue;
        var span = mask.slice(open, end);
        var conversion;
        CAUGHT_ERROR_TEXT_RE.lastIndex = 0;
        while ((conversion = CAUGHT_ERROR_TEXT_RE.exec(span)) !== null) {
          var at = open + conversion.index;
          if (DISPLAY_SCREEN_CALL_RE.test(_wrapperCallBefore(mask, at))) continue;
          out.push(_atOffset(file, at,
            "a caught error is turned into text and written into an audit row with no " +
            "display screen in front of it"));
        }
      }
      return out;
    },
    red: [
      "function _drained(name, err) {\n" +
        "  b.audit.safeEmit({\n" +
        "    action:   \"blamepost.mail.listeners.drain_incomplete\",\n" +
        "    outcome:  \"failure\",\n" +
        "    metadata: { listener: name, error: (err && err.message) || String(err) },\n" +
        "  });\n}\n",
      // The same shape under a renamed binding, which is what the matcher
      // reads as a shape rather than as the word `err`.
      "b.audit.safeEmit({ action: \"a.b\", reason: (readErr && readErr.message) || " +
        "String(readErr) });\n",
      // Written into a row that has grown other fields around it, so the
      // boundary is the call rather than a distance from it.
      "b.audit.safeEmit({\n  action: \"a.b\",\n  outcome: \"failure\",\n" +
        "  actor: { userId: null },\n  resource: null,\n  requestId: null,\n" +
        "  metadata: {\n    domain: domain,\n    cause: cause || null,\n" +
        "    reason: (signErr && signErr.message) || String(signErr),\n  },\n});\n",
      // One screened value beside one that is not. A screen anywhere in
      // the literal does not answer for the value next to it, which is
      // why the walk asks about the call a conversion sits directly
      // inside rather than about the row it ends up in.
      "b.audit.safeEmit({ action: \"a.b\", metadata: {\n" +
        "  domain: displayText.forDisplay(domain),\n" +
        "  reason: (err && err.message) || String(err),\n} });\n",
    ],
    green: [
      "b.audit.safeEmit({ action: \"a.b\",\n" +
        "  metadata: { error: text.forDisplay((err && err.message) || String(err)) } });\n",
      "b.audit.safeEmit({ action: \"a.b\",\n" +
        "  metadata: { error: _screenForDisplay((err && err.message) || String(err)) } });\n",
      // A log line is read by an operator too, and it is a different
      // sink with a different lifetime: this pattern is about the row.
      "log.error(\"the push sweep threw: \" + ((err && err.message) || String(err)));\n",
      // A code rather than a message. Nothing a stranger wrote reaches
      // a row through it, so there is nothing here to screen.
      "b.audit.safeEmit({ action: \"a.b\", metadata: { code: (err && err.code) || null } });\n",
      // A row carrying more than one screened value, each screened where
      // it is built. The walk asks about the call a conversion sits
      // directly inside rather than about anything else in the literal,
      // so a row stays silent when every conversion in it is wrapped and
      // reports the one that is not, however many screened values sit
      // beside it.
      "b.audit.safeEmit({ action: \"a.b\", metadata: {\n" +
        "  domain: displayText.forDisplay(domain),\n" +
        "  reason: displayText.forDisplay((err && err.message) || String(err)),\n} });\n",
    ],
  },

  {
    name: "caught-error-text-onto-a-terminal-unscreened",
    description:
      "A caught error turned into text and written straight to one of this process's own " +
      "streams. It is the sibling of the audit-row pattern and the harm arrives sooner: a " +
      "row is read back later, and this is already on the operator's screen. An error's " +
      "message is not this server's prose, so an argument parser quotes the token it could " +
      "not read, a resolver quotes what it was looking up, and a filesystem refusal quotes " +
      "a path. A terminal ACTS on what it is given rather than rendering it inertly, so a " +
      "value carrying the single-byte control sequence introducer at U+009B repaints the " +
      "row above the one it is on, an escape introducer at U+001B clears the line that " +
      "named the fault, a bidirectional override reverses the sentence an operator is " +
      "deciding on, and a carriage return overwrites the first half of a line with the " +
      "second. The screen is blamepost.text.forDisplay, run on each line rather than on " +
      "the whole value, because folding is what makes a single line safe and a stack trace " +
      "is several. Pass the conversion through it, or through a local bound wrapper named " +
      "for it.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      // The write itself, which is the platform's own verb rather than a
      // name this repository chose, so no rename here can quiet this.
      // The matching bracket is the boundary for the same reason the
      // audit-row pattern uses one: a count of characters stops reading
      // the moment a line grows another term, and a detector that has
      // gone quiet passes green over the code it was written to read.
      var WRITE = /\bprocess\s*\.\s*(?:stdout|stderr)\s*\.\s*write\s*\(/g;
      var m;
      WRITE.lastIndex = 0;
      while ((m = WRITE.exec(mask)) !== null) {
        var open = m.index + m[0].length - 1;
        var end  = _matchingBracket(mask, open);
        if (end === -1) continue;
        var span = mask.slice(open, end);
        var conversion;
        CAUGHT_ERROR_TEXT_RE.lastIndex = 0;
        while ((conversion = CAUGHT_ERROR_TEXT_RE.exec(span)) !== null) {
          var at = open + conversion.index;
          if (DISPLAY_SCREEN_CALL_RE.test(_wrapperCallBefore(mask, at))) continue;
          out.push(_atOffset(file, at,
            "a caught error is turned into text and written to a terminal with no " +
            "display screen in front of it"));
        }
      }
      return out;
    },
    red: [
      "process.stderr.write(\"blamepost: \" + ((err && err.message) || String(err)) + \"\\n\");\n",
      // The same shape under a renamed binding and on the other stream,
      // which is what the matcher reads as a shape rather than as the
      // word `err` or as one of the two streams.
      "process.stdout.write(((readErr && readErr.message) || String(readErr)) + \"\\n\");\n",
      // Written into a line that has grown other terms around it, so the
      // boundary is the call rather than a distance from it.
      "process.stderr.write(\"blamepost \" + command + \": \" + prefix + \" \" + label +\n" +
        "  \" \" + ((err && err.message) || String(err)) + \" \" + hint + \"\\n\");\n",
    ],
    green: [
      "process.stderr.write(text.forDisplay((err && err.message) || String(err)) + \"\\n\");\n",
      "process.stderr.write(_linesForDisplay((err && err.message) || String(err)) + \"\\n\");\n",
      // This server's own prose, which carries nothing a stranger chose.
      "process.stderr.write(\"Run `blamepost help` for the list of commands.\\n\");\n",
      // A code rather than a message. Nothing a stranger wrote reaches
      // the terminal through it.
      "process.stderr.write(String((err && err.code) || \"no code\") + \"\\n\");\n",
      // The audit row's own pattern, which is a different exit with a
      // different lifetime and is covered by its own detector.
      "b.audit.safeEmit({ action: \"a.b\",\n" +
        "  metadata: { error: (err && err.message) || String(err) } });\n",
    ],
  },

  {
    name: "caught-error-text-into-a-client-refusal-unscreened",
    description:
      "A caught fault's own message written into the refusal a client is handed back. It is " +
      "the third exit in the same family as the audit row and the terminal, and it is the " +
      "one where the reader is the person who asked. A fault's message is not this server's " +
      "prose: a JMAP client chooses the keyword and the property name a patch names and the " +
      "sentence refusing the patch quotes them, and a receiving peer chooses the reply text " +
      "a delivery failure carries. Markup escaping does not answer it, because none of what " +
      "does the harm is markup: the right-to-left override at U+202E reverses the reading " +
      "order of the rest of the sentence, the single-byte control sequence introducer at " +
      "U+009B opens an escape sequence for anything reading the answer as a stream, and a " +
      "carriage return with no line feed overwrites the first half of the line with the " +
      "second. The screen is blamepost.text.forDisplay, at the site that builds the value, " +
      "because a value built once is read on a page, in a client and in whatever log the " +
      "caller keeps. Pass the read through it, or through a local bound wrapper named for " +
      "it. A refusal carrying a code rather than a message is not this pattern, and neither " +
      "is an internal report row: the field named here is paired with the `type` a SetError " +
      "and a problem document both carry.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      var m;
      REFUSAL_FIELD_RE.lastIndex = 0;
      while ((m = REFUSAL_FIELD_RE.exec(mask)) !== null) {
        var colon = m.index + m[0].length - 1;
        // The literal this field belongs to, which is what says whether
        // the field is a wire refusal or an internal row that happens to
        // use the same word. The brace pair is the boundary for the same
        // reason the audit-row pattern uses the call's bracket: a literal
        // that grows another field is still one literal.
        var literal = _enclosingBraces(mask, colon);
        if (literal === null) continue;
        REFUSAL_TYPE_KEY_RE.lastIndex = 0;
        if (!REFUSAL_TYPE_KEY_RE.test(mask.slice(literal.start, literal.end))) continue;
        var span = _propertyValueSpan(mask, colon);
        if (!MESSAGE_READ_RE.test(span)) continue;
        if (DISPLAY_SCREEN_IN_VALUE_RE.test(span)) continue;
        out.push(_atOffset(file, colon,
          "a caught fault's message is written into a refusal a client renders with no " +
          "display screen in front of it"));
      }
      return out;
    },
    red: [
      "notUpdated[id] = { type: \"invalidProperties\", description: patchErr.message };\n",
      // The other conversion shape, under a renamed binding, in the other
      // field, so what the matcher reads is the shape rather than one
      // spelling or one holder.
      "_sendProblem(res, {\n  status: 502,\n  type:   PROBLEM.undeliverable,\n" +
        "  title:  \"That message was not handed to the outbound path\",\n" +
        "  detail: (sendErr && sendErr.message) || String(sendErr),\n});\n",
      // A refusal that has grown other fields around it, so the boundary
      // is the literal rather than a distance from anything.
      "answer = { problem: {\n  status: 403,\n  instance: here,\n  type: T.author,\n" +
        "  title: \"no\",\n  detail: (e && e.message) || String(e),\n  extra: null,\n} };\n",
    ],
    green: [
      "notUpdated[id] = { type: \"invalidProperties\",\n" +
        "  description: displayText.forDisplay(patchErr.message) };\n",
      "notCreated[key] = { type: \"forbiddenToSend\",\n" +
        "  description: _faultForDisplay(sendErr) };\n",
      // A code rather than a message. Nothing a stranger wrote reaches
      // the client through it.
      "notUpdated[id] = { type: \"invalidProperties\", description: (e && e.code) || \"unknown\" };\n",
      // This server's own prose, which carries nothing anybody else chose.
      "_sendProblem(res, { status: 503, type: T.unreadable, title: \"no\",\n" +
        "  detail: \"The message was not sent. The operator's audit trail names what is " +
        "wrong.\" });\n",
      // An internal report row. It carries no `type`, because nothing
      // reads it as a SetError or as a problem document, and the screen
      // for the surface that eventually prints it belongs there.
      "refused.push({ objectid: id, reason: code, detail: (e && e.message) || String(e) });\n",
    ],
  },

  {
    name: "control-char-offset-spent-as-a-cut",
    description:
      "A control-character offset spent as a place to cut rather than as a reason to refuse. " +
      "The framework's offset answers where the text stops being printable, and a body that " +
      "cuts there keeps everything in front of the first control character and drops the rest. " +
      "That reads as a screen and is not one: the codepoints that change what a line APPEARS " +
      "to say are not control characters at all, so a bidirectional override and a zero-width " +
      "character sit in the kept half untouched, and a value carrying one goes into an audit " +
      "row, a console table and a log line rendering as a different value. The cut also throws " +
      "away the text a reader needed, which is the half of the finding they were looking at. " +
      "Two shapes are correct instead. A field this server stores asks " +
      "blamepost.text.hasControlChar and refuses; a value on its way to somebody's eyes goes " +
      "through blamepost.text.forDisplay, which removes what a reader would act on and keeps " +
      "everything else. Comparing the offset against -1 and refusing on it is the refusal " +
      "shape and is not this pattern.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      var OFFSET = /\bfirstControlCharOffset\s*\(/g;
      // A cut anywhere in the same function body is the second half. The
      // body is the boundary rather than a character count, so a body
      // that grows keeps matching, and the match is attributed to the
      // innermost function so two siblings are never joined into one.
      var CUT = /\.\s*slice\s*\(|\.\s*substring\s*\(|\.\s*substr\s*\(/;
      bodies.forEach(function (body) {
        _matchesIn(mask, bodies, body, OFFSET).forEach(function (m) {
          if (!CUT.test(mask.slice(body.start, body.end))) return;
          out.push(_atOffset(file, m.offset,
            "a control-character offset is spent as a place to cut rather than as a refusal"));
        });
      });
      return out;
    },
    red: [
      "function _field(value, limit) {\n" +
        "  var text = value.trim();\n" +
        "  if (text.length > limit) text = text.slice(0, limit);\n" +
        "  var control = b.codepointClass.firstControlCharOffset(text, { forbidTab: true });\n" +
        "  if (control === 0) return null;\n" +
        "  if (control > 0) text = text.slice(0, control);\n" +
        "  return text;\n}\n",
      "function _recordable(value) {\n" +
        "  var at = b.codepointClass.firstControlCharOffset(value);\n" +
        "  return at === -1 ? value : value.substring(0, at);\n}\n",
    ],
    green: [
      // The refusal shape: the offset is compared and nothing is cut on it.
      "function _wireName(name) {\n" +
        "  if (b.codepointClass.firstControlCharOffset(name, { forbidTab: true }) !== -1) {\n" +
        "    throw err(\"mailbox/bad-mailbox-name\", \"a name carries no control characters.\");\n" +
        "  }\n  return name;\n}\n",
      // The screen, which removes rather than cuts, with a length bound
      // that has nothing to do with the offset.
      "function _field(value, limit) {\n" +
        "  var text = displayText.forDisplay(value).trim();\n" +
        "  if (text.length > limit) text = text.slice(0, limit);\n" +
        "  return text.length > 0 ? text : null;\n}\n",
      // Two siblings, one refusing and one cutting, are two functions and
      // neither is this pattern.
      "function _named(n) {\n" +
        "  if (b.codepointClass.firstControlCharOffset(n) !== -1) throw new TypeError(\"control\");\n" +
        "  return n;\n}\n" +
        "function _short(n) {\n  return n.slice(0, 40);\n}\n",
    ],
  },

  {
    name: "console-direct",
    description:
      "A direct console call in shipped source. Operator output goes through the framework " +
      "logger, which carries the level, the structured fields and the file sink an operator " +
      "configured. A bare console call bypasses all three, so the line is invisible to log " +
      "shipping and unfilterable by level.",
    dirs: ["lib", "bin"],
    scan: _lineMatcher(/\bconsole\s*\.\s*[A-Za-z_$]/, "code"),
    red: [
      "function boot() {\n  console.log(\"mx listener bound\");\n}\n",
    ],
    green: [
      "function boot() {\n  log.info(\"mx listener bound\", { port: 25 });\n}\n",
    ],
  },

  {
    name: "math-random",
    description:
      "Math.random() in shipped source or in a test. It is not a source of unpredictable " +
      "values, so anything an attacker could guess from it (a boundary string, a token, a " +
      "selector suffix, a queue id) is guessable. Use the framework's random primitives, or " +
      "node:crypto. In a test it is worse than useless: it makes the run nondeterministic, " +
      "so the real failure surfaces as a rare flake.",
    dirs: ["lib", "bin", "scripts", "test"],
    scan: _lineMatcher(/\bMath\s*\.\s*random\s*\(/, "code"),
    red: [
      "var boundary = \"----=_Part_\" + Math.random().toString(16);\n",
    ],
    green: [
      "var boundary = \"----=_Part_\" + crypto.randomBytes(16).toString(\"hex\");\n",
    ],
  },

  {
    name: "wall-clock-cutoff-for-in-memory-state",
    description:
      "A cutoff built by subtracting a duration from the wall clock. Date.now() answers what " +
      "time it is, which is a different question from how long something has been open, and it " +
      "moves when an operator corrects a wrong time, when NTP steps a drifted host, and when a " +
      "container that started before it synchronized catches up. An age measured that way is " +
      "wrong by however far the correction went, in whichever direction it went: a step forward " +
      "expires state that is still live, and a step backwards holds it until the clock has " +
      "climbed back to where it was. Neither shows up as an error anywhere. Measure elapsed " +
      "time on b.time.monotonicMs, which counts from a point no clock correction can move and " +
      "advances only at the rate of real time. A reading that has to say WHEN something " +
      "happened is a different thing and stays on the wall clock: an internal date, an audit " +
      "row, a cookie expiry a browser will read, and a retry schedule read back off disk after " +
      "a restart are all correct as they are.",
    dirs: ["lib", "bin"],
    scan: _lineMatcher(
      /\bDate\s*\.\s*now\s*\(\s*\)\s*-\s*(?:[A-Za-z_$][A-Za-z0-9_$]*_MS\b|(?:b\s*\.\s*constants\s*\.\s*)?TIME\s*\.\s*[A-Za-z]+\s*\()/,
      "code"),
    red: [
      "function sweep() {\n  var cutoff = Date.now() - SESSION_TTL_MS;\n}\n",
      "var stale = Date.now() - TIME.minutes(30);\n",
      "var stale = Date.now() - b.constants.TIME.hours(1);\n",
    ],
    green: [
      "function sweep() {\n  var cutoff = _elapsedMs() - SESSION_TTL_MS;\n}\n",
      // A schedule read back off disk names an instant, so comparing the
      // wall clock against it is the only thing that could be meant.
      "if ((entry.nextAttemptAt || 0) > Date.now()) continue;\n",
      // And an expiry handed to a clock this server does not own has to
      // be a date in that clock's terms.
      "var expires = new Date(Date.now() + THEME_TTL_MS).toUTCString();\n",
      // An age against a file's own modification time is measured on the
      // clock that wrote it, which is the wall clock.
      "var ageMs = Date.now() - stat.mtimeMs;\n",
    ],
  },

  {
    name: "rate-limit-declared-without-its-algorithm",
    description:
      "A rate limiter composed without naming the algorithm it wants. The framework offers " +
      "two, and they read DIFFERENT options: the token bucket takes burst and refillPerSecond, " +
      "the fixed window takes max and windowMs. The token bucket is the default, so a limiter " +
      "that names max and windowMs and no algorithm silently runs on the bucket's own defaults " +
      "and the two numbers written at the call site are never read by anything. Nothing " +
      "reports it. Both names are on the primitive's allowed list, so construction succeeds, " +
      "every request is admitted under a ceiling nobody chose, and the only way to find out is " +
      "to count the requests it actually lets through. Name the algorithm at every call, so " +
      "the options beside it are the ones that primitive reads.",
    dirs: ["lib", "bin"],
    scan: _contentMatcher(
      /\.middleware\s*\.\s*rateLimit\s*\(\s*\{(?!(?:(?!\n\})[\s\S]){0,4000}?\balgorithm\s*:)/g),
    red: [
      "var limit = b.middleware.rateLimit({\n  max: 10,\n  windowMs: 300000,\n});\n",
      "function mount(router) {\n  router.use(b.middleware.rateLimit({ max: 60 }));\n}\n",
    ],
    green: [
      "var limit = b.middleware.rateLimit({\n  algorithm: \"fixed-window\",\n" +
        "  max: 10,\n  windowMs: 300000,\n});\n",
      "var limit = b.middleware.rateLimit({\n  algorithm: \"token-bucket\",\n" +
        "  burst: 60,\n  refillPerSecond: 10,\n});\n",
    ],
  },

  {
    name: "session-binding-captured-but-never-asserted",
    description:
      "A session minted with the request that opened it, in a file that never asserts what " +
      "that captures. Handing req to session.create hashes the client address, the user " +
      "agent and the accepted language into the session row, and every later verify that is " +
      "given a request recomputes that hash and compares it. The comparison is a signal and " +
      "nothing more until a verify names a policy for it: requireFingerprintMatch refuses " +
      "the session on any drift, maxAnomalyScore refuses it past a threshold, and a verify " +
      "naming neither hands the session back to a caller that arrived from anywhere at all. " +
      "A cookie copied off the machine it was issued to then goes on working, and the " +
      "binding that was supposed to qualify it is a column nothing reads. Name a policy on " +
      "the verify that guards the surface the binding is for, in the file that captures it. " +
      "A comment saying the policy is set does not satisfy this: the scan reads code only, " +
      "because a sentence is what the binding already had.",
    dirs: ["lib", "bin"],
    // Both halves are framework option names rather than names this
    // repository chooses, so neither a renamed helper nor a moved route
    // quiets this. The capture is found by walking the call's own
    // brackets, so an argument list that grows past any budget is still
    // read whole.
    scan: function (file) {
      var mask = _maskOf(file);
      // The assertion may sit on any verify in the file. The surface a
      // binding guards is not always the route that minted it, and a
      // detector demanding the policy at every verify would forbid a
      // deliberate split between surfaces rather than the silence this
      // is written to catch.
      if (/\brequireFingerprintMatch\s*:/.test(mask)) return [];
      if (/\bmaxAnomalyScore\s*:/.test(mask)) return [];
      var out = [];
      var re  = /\.session\s*\.\s*create\s*\(/g;
      var m;
      while ((m = re.exec(mask)) !== null) {
        var openParen = m.index + m[0].length - 1;
        var first = _firstArgument(mask, openParen);
        if (first === null) continue;
        if (!/\breq\s*:/.test(first)) continue;
        out.push({
          file:    file.rel,
          line:    _lineOfIndex(file.text, m.index),
          content: "session.create binds the request that opened the session, and no verify " +
                   "in this file names a policy for the binding",
        });
      }
      return out;
    },
    red: [
      "var s = await b.session.create({ userId: id, req: req });\n",
      "function mount(router) {\n  router.use(b.middleware.attachUser({\n" +
        "    userLoader: load,\n  }));\n}\n" +
        "async function signIn(req, res) {\n  var s = await b.session.create({\n" +
        "    userId: verdict.accountId,\n    data:   { address: verdict.address },\n" +
        "    ttlMs:  SESSION_TTL_MS,\n    req:    req,\n  });\n}\n",
      // Prose is what the binding already had. A comment naming the
      // option buys no silence.
      "// requireFingerprintMatch: true guards the console.\n" +
        "var s = await b.session.create({ userId: id, req: req });\n",
    ],
    green: [
      // The capture and the assertion, in one file, on the surface the
      // binding is for.
      "async function guard(req, res, next) {\n" +
        "  var ok = await b.session.verify(token, {\n    req: req,\n" +
        "    requireFingerprintMatch: true,\n  });\n  if (!ok) return deny(res);\n  next();\n}\n" +
        "async function signIn(req, res) {\n  var s = await b.session.create({\n" +
        "    userId: id,\n    req:    req,\n  });\n}\n",
      // A threshold is the other policy the primitive reads.
      "async function guard(req, res) {\n  var ok = await b.session.verify(token, {\n" +
        "    req: req,\n    maxAnomalyScore: 0.4,\n    scorer: _score,\n  });\n}\n" +
        "var s = await b.session.create({ userId: id, req: req });\n",
      // Nothing is captured, so there is nothing to assert.
      "var s = await b.session.create({ userId: id, ttlMs: 900000 });\n",
    ],
  },

  {
    name: "failure-budget-left-on-the-wall-clock",
    description:
      "A sign-in failure budget composed without a clock of its own. The budget decays after a " +
      "window and holds for a wait that grows with each run, and both of those are durations. " +
      "The primitive's default clock is Date.now, which answers what time it is rather than " +
      "how long something has been held, and it moves when an operator corrects a wrong time, " +
      "when NTP steps a drifted host, and when a container that started before it synchronized " +
      "catches up. A step forward releases a lockout that is still supposed to be holding and " +
      "hands back a counter that has not decayed; a step backwards holds one past the instant " +
      "it was told to lift. Neither shows up as an error, and the budget is the whole of what " +
      "stands between a guessed password and a mailbox. Pass a clock that advances at the rate " +
      "of real time, and pass the SAME one to the cache underneath it: the cache expires the " +
      "counter on its own clock, so a budget measured on one clock and stored against another " +
      "is given back by whichever of the two moves first.",
    dirs: ["lib"],
    scan: _contentMatcher(
      /\.auth\s*\.\s*lockout\s*\.\s*create\s*\(\s*\{(?!(?:(?!\n\})[\s\S]){0,4000}?\bclock\s*:)/g),
    red: [
      "var budget = b.auth.lockout.create({\n  namespace: \"mailbox\",\n" +
        "  cache: b.cache.create({ namespace: \"n\", backend: \"memory\" }),\n});\n",
    ],
    green: [
      "var budget = b.auth.lockout.create({\n  namespace: \"mailbox\",\n" +
        "  clock: _steadyNow,\n" +
        "  cache: b.cache.create({ namespace: \"n\", backend: \"memory\", clock: _steadyNow }),\n});\n",
    ],
  },

  {
    name: "process-exit-in-lib",
    description:
      "process.exit() inside lib/. A library call that kills the process takes every open " +
      "connection, every in-flight delivery and every queued write with it, and leaves the " +
      "caller no way to shut down cleanly. Throw, and let bin/ decide the exit code.",
    dirs: ["lib"],
    scan: _lineMatcher(/\bprocess\s*\.\s*exit\s*\(/, "code"),
    red: [
      "function start(cfg) {\n  if (!cfg.hostname) process.exit(1);\n}\n",
    ],
    green: [
      "function start(cfg) {\n  if (!cfg.hostname) throw new TypeError(\"hostname required\");\n}\n",
    ],
  },

  {
    name: "empty-catch-swallow",
    description:
      "A catch block with no body and no comment. Dropping an error silently is a legitimate " +
      "choice for an observability sink, where throwing would kill the delivery that produced " +
      "the event, but it has to be the written choice. An empty block cannot be told apart " +
      "from a forgotten one. Handle the error, re-throw it, or record inside the block why it " +
      "is dropped.",
    dirs: ["lib", "bin", "scripts", "test"],
    scan: _contentMatcher(/catch\s*(?:\([^)]{0,120}\))?\s*\{[ \t\r\n]*\}/g),
    red: [
      "try { appendMessage(raw); } catch (e) {}\n",
      "try {\n  appendMessage(raw);\n} catch {\n}\n",
    ],
    green: [
      "try { emitAudit(row); } catch (_e) { /* drop-silent by design: the audit sink must not fail the delivery */ }\n",
    ],
  },

  {
    name: "sealed-read-whose-fault-leaves-untranslated",
    description:
      "A read of sealed material whose failure is allowed to leave the layer as the vault " +
      "raised it. Opening a seal fails for two reasons an operator can act on and cannot tell " +
      "apart from the outside: the bytes were written under a different vault key, or they " +
      "have been damaged where they lie. What the vault raises for either is a plain error " +
      "carrying no code and worded in the vault's own vocabulary, and it is a PERMANENT " +
      "verdict about those bytes. Every consumer of a sealed read is a surface that has to " +
      "act on that: a wire listener with no code to read tells its client to try again at " +
      "something that can never succeed, a relay records the cause as unknown, and a message " +
      "carrying the volume's layout goes to whoever asked. Catch it and refuse in this " +
      "layer's own words, under this layer's code, naming what the operator can act on — the " +
      "domain, the selector, the message — and never the path the fault underneath would " +
      "have handed over. A handler that raises its own refusal, or that answers with a " +
      "worded reason of its own, has done the job; one that hands the caught value straight " +
      "back has not.",
    dirs: ["lib"],
    // The framework's own method name, which is a published contract
    // rather than a symbol this repository can rename: the local handle
    // in front of it is called `vault` in one file and something else in
    // the next, and neither spelling changes the call. The guard is the
    // enclosing try and its catch, walked outward to the function
    // boundary, so a read nested inside a branch or a loop is still
    // covered and a body that grows never falls out of range.
    scan: function (file) {
      var mask   = _maskOf(file);
      var out    = [];
      var re     = /\.unseal\s*\(/g;
      var m;
      while ((m = re.exec(mask)) !== null) {
        if (_caughtBeforeLeaving(mask, m.index, { converted: true })) continue;
        out.push(_atOffset(file, m.index,
          "a seal is opened here and the vault's own fault leaves this layer untranslated"));
      }
      return out;
    },
    red: [
      "function readKey(ref) {\n  var sealed = b.atomicFile.readSync(pathFor(ref));\n" +
        "  return vault.unseal(sealed);\n}\n",
      // Caught and handed straight back, which is the same value leaving
      // by a longer route.
      "function readKey(ref) {\n  try {\n    return vault.unseal(load(ref));\n" +
        "  } catch (e) {\n    log.error(\"key unreadable\");\n    throw e;\n  }\n}\n",
    ],
    green: [
      // Raised as this layer's own coded refusal.
      "function readKey(ref) {\n  try {\n    return vault.unseal(load(ref));\n" +
        "  } catch (_sealError) {\n    throw err(\"dkim/key-seal-unopened\",\n" +
        "      \"the signing key for \" + ref.domain + \" did not open.\");\n  }\n}\n",
      // Answered with a reason this layer worded, for a reader that
      // reports rather than refuses.
      "function digestFault(digest, path) {\n  var raw;\n  try {\n" +
        "    raw = Buffer.from(vault.unseal(read(path)), \"base64\");\n" +
        "  } catch (_e) {\n    return \"the seal did not open\";\n  }\n" +
        "  return sha3(raw) === digest ? null : \"the octets hash to something else\";\n}\n",
      // Nothing sealed is opened here at all.
      "function writeKey(ref, pem) {\n  return atomicFile.write(pathFor(ref), vault.seal(pem));\n}\n",
    ],
  },

  {
    name: "vendor-hand-edit",
    description:
      "A require reaching past the vendored package entry point into its internals. The " +
      "vendored tree is replaced wholesale by the vendor refresh, so a deep import binds this " +
      "repository to a file path upstream never promised to keep, and it reads as a license to " +
      "edit the tree in place. Compose the surface the entry point exports.",
    dirs: ["lib", "bin", "scripts", "test"],
    scan: _lineMatcher(/require\s*\(\s*["'][^"']*vendor[/\\]blamejs[/\\](?!index\.js["'])[^"']+["']/, "any"),
    red: [
      "var store = require(\"../vendor/blamejs/lib/mail-store.js\");\n",
    ],
    green: [
      "var b = require(\"../vendor/blamejs\");\n",
      "var b = require(\"../vendor/blamejs/index.js\");\n",
    ],
  },

  {
    name: "listener-without-operator-limits",
    description:
      "A wire listener built without a rateLimit. Every listener the framework ships resolves " +
      "its own limiter when the caller passes none, so the omission is invisible: the listener " +
      "binds, serves, and holds a per-source ceiling nobody here chose. That ceiling is sized " +
      "for a peer delivering mail rather than for a mailbox client, and two ordinary clients " +
      "behind one home address reach it, so the failure lands on the operator's own users and " +
      "reads to them as the server being down. Pass the limiter built from the operator's " +
      "configuration to every listener, so one answer covers all of them and an operator can " +
      "see what the number is.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      var re   = /\bb\.mail\.server\.(mx|submission|imap|pop3|managesieve)\.create\s*\(/g;
      var out  = [];
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(mask)) !== null) {
        var openParen = m.index + m[0].length - 1;
        var close     = _matchingBracket(mask, openParen);
        if (close === -1) continue;
        if (!/\brateLimit\s*:/.test(mask.slice(openParen, close))) {
          out.push(_atOffset(file, m.index,
            "b.mail.server." + m[1] + ".create() is built with no rateLimit"));
        }
      }
      return out;
    },
    red: [
      "function _buildImap() {\n  return b.mail.server.imap.create({\n" +
      "    tlsContext: opts.tlsContext,\n    mailStore:  mailStore,\n  });\n}\n",
    ],
    green: [
      "function _buildImap() {\n  return b.mail.server.imap.create({\n" +
      "    tlsContext: opts.tlsContext,\n    rateLimit:  limits.rateLimit,\n" +
      "    mailStore:  mailStore,\n  });\n}\n",
    ],
  },

  {
    name: "mailbox-listener-without-the-mailbox-auth-surface",
    description:
      "An IMAP, POP3 or ManageSieve listener built without declaring the mailbox " +
      "authentication surface. This server has two identity spaces and only one listener holds " +
      "both: submission accepts an account or a sending credential, and a credential speaks for " +
      "every local part in a hosted domain. A mailbox protocol handed the submission surface, " +
      "or handed a verifier that names no surface at all, therefore accepts a secret issued to " +
      "SEND mail as an identity that can READ it, and the credential's own refusal list does " +
      "not bound that: it names addresses the credential may not write and says nothing about " +
      "what it may open. What that buys an attacker holding one leaked application secret is " +
      "every message in the domain over IMAP, the maildrop deleted on QUIT over POP3, and the " +
      "filters that decide where mail lands rewritten over ManageSieve. Build each of these " +
      "with the mailbox surface, so the listener refuses a credential as an unknown identity " +
      "and a client cannot tell the refusal from a wrong password. The check reads the absence " +
      "of the good token rather than the presence of the bad one, so a listener added later, a " +
      "verifier that takes no surface, and a renamed constant all fail here rather than going " +
      "quietly green.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      var re   = /\bb\.mail\.server\.(imap|pop3|managesieve)\.create\s*\(/g;
      var out  = [];
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(mask)) !== null) {
        var openParen = m.index + m[0].length - 1;
        var close     = _matchingBracket(mask, openParen);
        if (close === -1) continue;
        if (!/AUTH_SURFACES\s*\.\s*MAILBOX\b/.test(mask.slice(openParen, close))) {
          out.push(_atOffset(file, m.index,
            "b.mail.server." + m[1] + ".create() does not declare AUTH_SURFACES.MAILBOX, so " +
            "a sending credential may be an identity on a mailbox protocol"));
        }
      }
      return out;
    },
    red: [
      "function _buildImap() {\n  return b.mail.server.imap.create({\n" +
      "    auth:      _authConfig(AUTH_SURFACES.SUBMISSION),\n" +
      "    mailStore: mailStore,\n  });\n}\n",
      "function _buildPop3() {\n  return b.mail.server.pop3.create({\n" +
      "    auth:      _authConfig(),\n    mailStore: mailStore,\n  });\n}\n",
      "function _buildManageSieve() {\n  return b.mail.server.managesieve.create({\n" +
      "    auth:      { mechanisms: [\"PLAIN\"], verify: _verify },\n" +
      "    mailStore: mailStore,\n  });\n}\n",
    ],
    green: [
      "function _buildImap() {\n  return b.mail.server.imap.create({\n" +
      "    auth:      _authConfig(AUTH_SURFACES.MAILBOX),\n" +
      "    mailStore: mailStore,\n  });\n}\n",
      "function _buildSubmission() {\n  return b.mail.server.submission.create({\n" +
      "    auth:      _authConfig(AUTH_SURFACES.SUBMISSION),\n" +
      "    mailStore: mailStore,\n  });\n}\n",
    ],
  },

  {
    name: "mx-listener-built-with-a-relay-grant",
    description:
      "An MX listener built with relayAllowedFor. That option tells the listener to accept a " +
      "recipient outside the hosted domains when the connecting peer's address falls inside an " +
      "operator-named range, and this server does not relay for a source address: a range is " +
      "refused at boot, from the configuration and from the listener composition alike. A " +
      "value reaching the framework here goes around both refusals, and what it buys is a 250 " +
      "to a stranger's sender and a 250 to a stranger's recipient, which is the answer an open " +
      "relay gives and the answer a scanner records, followed by a temporary refusal for a " +
      "condition that never clears. Relayed mail also cannot be signed here, because signing " +
      "it would let anything inside the range emit mail aligned under a hosted domain's key, " +
      "so it would leave unsigned under this server's own address and name, and a permanent " +
      "failure would owe a report to a reverse path nobody verified. A device that needs to " +
      "send through this server gets an account and uses the submission listener, which binds " +
      "the identity, signs for the domain, and has a mailbox to report a failure to. Pass no " +
      "relay option at all: an absent value has no spelling for a later reader to widen.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      // Both halves are upstream contracts rather than local names: the
      // framework's constructor and the framework's own option key. A
      // rename here cannot quiet this, and a deletion upstream is what
      // should quiet it.
      var re  = /\bb\.mail\.server\.mx\.create\s*\(/g;
      var out = [];
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(mask)) !== null) {
        var openParen = m.index + m[0].length - 1;
        // The call's own bracket, so the scan covers the whole options
        // object however long it grows and stops at the end of it. A
        // character window would go quiet the moment another option was
        // added above the one it was looking for.
        var close = _matchingBracket(mask, openParen);
        if (close === -1) continue;
        if (/\brelayAllowedFor\s*:/.test(mask.slice(openParen, close))) {
          out.push(_atOffset(file, m.index,
            "b.mail.server.mx.create() is built with a relay grant"));
        }
      }
      return out;
    },
    red: [
      "function _buildMx(localDomains) {\n  return b.mail.server.mx.create({\n" +
      "    tlsContext:      opts.tlsContext,\n    localDomains:    localDomains,\n" +
      "    relayAllowedFor: relayAllowedFor,\n    rateLimit:       limits.rateLimit,\n" +
      "  });\n}\n",
    ],
    green: [
      "function _buildMx(localDomains) {\n  return b.mail.server.mx.create({\n" +
      "    tlsContext:      opts.tlsContext,\n    localDomains:    localDomains,\n" +
      "    rateLimit:       limits.rateLimit,\n  });\n}\n",
    ],
  },

  {
    name: "outbound-delivery-bypass",
    description:
      "A raw SMTP transport reference in lib/. Every outbound path goes through the delivery " +
      "composer, which chains MX lookup, MTA-STS, DANE, REQUIRETLS, retry classification and " +
      "DSN generation. A direct transport send skips all of it, so the message leaves with no " +
      "transport policy applied and fails quietly. That shortcut is tempting for an internal " +
      "notification, which is exactly why it is a finding.",
    dirs: ["lib"],
    scan: _lineMatcher(/\.mail\.transports\.smtp\b/, "code"),
    red: [
      "function notifyOperator(env) {\n  return b.mail.transports.smtp.send(env);\n}\n",
    ],
    green: [
      "function notifyOperator(env) {\n  return outbound.deliver(env);\n}\n",
    ],
  },

  {
    name: "outbound-composer-built-in-a-second-place",
    description:
      "A second outbound delivery chain, built somewhere other than the module that owns " +
      "the one this server sends through. The detector beside this one catches a raw " +
      "transport, which is the loud way past the policy chain; this is the quiet way, " +
      "because a second composer runs a chain of its own and looks entirely correct doing " +
      "it. What it does not share is the settings: the MTA-STS posture, the DANE posture " +
      "and the operator's pinned resolver are arguments, so a second call carries whatever " +
      "its own caller wrote, and a message sent through it leaves under a posture the " +
      "operator never configured. Nothing on the wire says which chain a message took. The " +
      "spool, the retry budget and the report path are not shared either, so a recipient " +
      "the second chain defers waits in nobody's queue and its sender is never told. " +
      "Compose the handle blamepost.mail.delivery.create hands back instead of building " +
      "another one.",
    dirs: ["lib", "bin"],
    // Read off the mask, so the outbound module's own documentation of
    // the call it makes is documentation rather than a second call. The
    // owner is excluded by path for the same reason a detector for a
    // rule never fires on the rule.
    scan: function (file) {
      if (OUTBOUND_COMPOSER_OWNER_RE.test(file.rel)) return [];
      var mask = _maskOf(file);
      var out = [];
      OUTBOUND_COMPOSER_BUILT_RE.lastIndex = 0;
      var hit = OUTBOUND_COMPOSER_BUILT_RE.exec(mask);
      while (hit !== null) {
        out.push(_atOffset(file, hit.index));
        if (hit.index === OUTBOUND_COMPOSER_BUILT_RE.lastIndex) {
          OUTBOUND_COMPOSER_BUILT_RE.lastIndex += 1;
        }
        hit = OUTBOUND_COMPOSER_BUILT_RE.exec(mask);
      }
      return out;
    },
    red: [
      "function _alertTransport(config) {\n" +
        "  return b.mail.send.deliver.create({ hostname: config.hostname });\n}\n",
      // The same call written across several lines, which is the shape a
      // matcher bound to one line goes quiet on.
      "function _reportSender(config) {\n" +
        "  return b.mail\n    .send\n    .deliver\n    .create({\n" +
        "    hostname: config.hostname,\n    policy:   { mtaSts: \"off\" },\n  });\n}\n",
    ],
    green: [
      // The one module that may build it, named by its path.
      {
        as:   "lib/mail/delivery.js",
        text: "function create(opts) {\n" +
          "  var deliver = b.mail.send.deliver.create({ hostname: opts.hostname });\n" +
          "  return deliver;\n}\n",
      },
      // Everywhere else composes the handle that module hands back.
      "function _alertTransport(deliveryHandle) {\n" +
        "  return deliveryHandle.send;\n}\n",
    ],
  },

  {
    name: "bundle-manifest-read-in-a-second-place",
    description:
      "A second reading of a backup bundle's manifest. The manifest is the only thing that " +
      "records which server a bundle was taken on, which data directory it was taken from " +
      "and which id it was written as, and every verb that reports on a bundle has to hold " +
      "those against this server: a restore refuses a bundle whose three fields disagree, so " +
      "a verb that vouches for one without asking sends an operator away believing they hold " +
      "a copy, and a retention sweep that counts one deletes a bundle that would have " +
      "restored in order to keep one that will not. Three verbs read the manifest separately " +
      "and only the restore asked. Route every reading through the one reader that answers " +
      "both questions at once, so a verb added later cannot get the manifest without the " +
      "verdict on where it came from.",
    dirs: ["bin", "lib"],
    // Anchored on the framework's own primitive rather than on the reader
    // around it. `b.restoreBundle.inspect` is a vendored contract this
    // repository cannot rename, so the anchor survives every rename here
    // and disappears only when the manifest stops being read at all. The
    // rule is one reading per file, and the second is the finding: the
    // first is the reader, and anything after it is a caller that went
    // around it.
    scan: function (file) {
      var mask = _maskOf(file);
      var re   = /\bb\.restoreBundle\.inspect\s*\(/g;
      var out  = [];
      var seen = 0;
      var m;
      while ((m = re.exec(mask)) !== null) {
        seen += 1;
        if (seen === 1) continue;
        out.push(_atOffset(file, m.index,
          "the bundle manifest is read here as well, so this reading can report on a bundle " +
          "without holding the origin it records against this server"));
      }
      return out;
    },
    red: [
      "function _stands(dir) {\n  return b.restoreBundle.inspect({ bundleDir: dir });\n}\n" +
        "function _describe(dir) {\n  return b.restoreBundle.inspect({ bundleDir: dir });\n}\n",
    ],
    green: [
      "function _readBundle(dir, bundleId, config) {\n" +
        "  var manifest = b.restoreBundle.inspect({ bundleDir: dir });\n" +
        "  return { manifest: manifest, fault: _originFault(manifest, bundleId, config) };\n}\n" +
        "function _describe(dir, id, config) {\n  return _readBundle(dir, id, config).manifest;\n}\n",
    ],
  },

  {
    name: "give-up-row-that-does-not-say-who-was-told",
    description:
      "The row filed when this server gives up on a queued message, with nothing in it about " +
      "the sender. Giving up destroys a message no receiver refused, so the only thing that " +
      "makes it defensible is that whoever sent it finds out and can send it again. Which " +
      "means the row an operator reads afterwards has to answer whether they did. The " +
      "cancellation rows the browser console and the command line file already carry that " +
      "pair, reported saying whether this server wrote to the sender and withheld saying why " +
      "not when it did not, precisely so a trail is never read as a set of erasures that " +
      "everybody was told about. A give-up row missing the pair reads exactly that way, and " +
      "the operator has no other place to look: the message is off disk and the sender is " +
      "either holding a report or holding nothing. Emit both keys, on the branch that reports " +
      "and on the branch that decides nobody is owed one.",
    dirs: ["lib/mail"],
    // Anchored on the audit action rather than on the function around it.
    // The action is what an operator's filter names, so it survives every
    // rename of the helper and disappears only when the event itself
    // does. The enclosing function is the unit, because the decision
    // about the sender and the row that records it are made together and
    // a branch in between is still the same function.
    scan: function (file) {
      var mask = _maskOf(file);
      var re   = /"blamepost\.mail\.delivery\.spool_abandoned"/g;
      var out  = [];
      var m;
      while ((m = re.exec(mask)) !== null) {
        var span = _enclosingFunctionSpan(mask, m.index);
        if (!span) continue;
        var body = mask.slice(span.start, span.end);
        if (/\breported\s*:/.test(body) && /\bwithheld\s*:/.test(body)) continue;
        out.push(_atOffset(file, m.index,
          "this server files a row saying it gave up on a message and the row does not say " +
          "whether the sender was told"));
      }
      return out;
    },
    red: [
      "async function _abandon(entry, attempt, reason) {\n" +
        "  await _dropSpooledOrRaise(entry.id);\n" +
        "  b.audit.safeEmit({\n" +
        "    action:   \"blamepost.mail.delivery.spool_abandoned\",\n" +
        "    outcome:  \"failure\",\n" +
        "    metadata: { id: entry.id, recipient: entry.recipient, attempt: attempt },\n" +
        "  });\n" +
        "}\n",
      // Half the pair is not the pair: a row that says a report went and
      // never says why one did not is unreadable on the branch that
      // matters.
      "async function _abandon(entry, attempt, reason) {\n" +
        "  await _dropSpooledOrRaise(entry.id);\n" +
        "  b.audit.safeEmit({\n" +
        "    action:   \"blamepost.mail.delivery.spool_abandoned\",\n" +
        "    outcome:  \"failure\",\n" +
        "    metadata: { id: entry.id, reported: true },\n" +
        "  });\n" +
        "}\n",
    ],
    green: [
      "async function _abandon(entry, attempt, reason, notice) {\n" +
        "  await _dropSpooledOrRaise(entry.id);\n" +
        "  var told = false;\n" +
        "  var withheld = notice.withheld || null;\n" +
        "  if (notice.status) told = await _tellTheSender(entry, reason, notice.status);\n" +
        "  b.audit.safeEmit({\n" +
        "    action:   \"blamepost.mail.delivery.spool_abandoned\",\n" +
        "    outcome:  \"failure\",\n" +
        "    metadata: { id: entry.id, reported: told, withheld: withheld },\n" +
        "  });\n" +
        "}\n",
      // A different delivery row is a different rule. This one is about
      // the act that destroys a message nobody refused.
      "function _noteRemovalMidAttempt(entry) {\n" +
        "  b.audit.safeEmit({\n" +
        "    action:   \"blamepost.mail.delivery.spool_removed_mid_attempt\",\n" +
        "    outcome:  \"success\",\n" +
        "    metadata: { id: entry.id, recipient: entry.recipient },\n" +
        "  });\n" +
        "}\n",
    ],
  },

  {
    name: "tls-context-frozen-at-composition",
    description:
      "A certificate handed to a listener as a fixed value. The certificate this server " +
      "presents is not fixed: an operator's certificate client rewrites the two files every " +
      "sixty to ninety days, and the loader watching them rebuilds the context in place when " +
      "it sees the change. A listener composed against the value that accessor held at boot " +
      "keeps presenting the certificate that has since expired, and nothing reports it: the " +
      "reload succeeds, the files on disk are correct, every listener is still bound, and " +
      "every handshake a sending peer offers fails. Read the certificate through the handle " +
      "at the moment of use instead, by installing tlsContext as an accessor on the options " +
      "the listener holds, so each connection is answered with whatever is current. A TLS " +
      "server built from certificate BYTES cannot be given an accessor, so it takes the " +
      "other half of the same rule: it has to be handed the renewed material while it runs, " +
      "which for a node:tls server means setSecureContext on the bound server. A file that " +
      "binds one and never calls it presents the certificate it read at bind until the " +
      "process is restarted, which is the same outage by the other route.",
    dirs: ["lib"],
    // A data property named for the context, which is the one spelling
    // that can only be a snapshot. The accessor form carries the name as
    // a STRING in an Object.defineProperty call, so the correct code
    // never produces this line and a rename of the surrounding helper
    // cannot make the wrong code stop producing it.
    //
    // A key whose value is the identically named identifier is skipped,
    // and the exclusion is structural rather than a carve-out for one
    // file: `tlsContext: tlsContext` is a table restating a name it was
    // given, which is what an export block and a shorthand-expanded
    // literal look like. Wiring a listener means naming something OTHER
    // than the key, so nothing this detector exists to catch can hide
    // behind that shape.
    //
    // The second shape is the same bug where no accessor is available. A
    // node:tls server builds its own context out of PEM bytes and ignores
    // a context passed as an option, so the certificate reaches it as a
    // value by construction and the only supported way to replace it
    // afterwards is setSecureContext on the bound server. Both tokens are
    // upstream contracts, the framework's listen option and Node's server
    // method, so neither a rename here nor a rewritten helper can quiet
    // this, and it goes silent exactly when the file starts installing
    // renewed material. The call is looked for over the mask, so a comment
    // promising one does not count as making one.
    scan: function (file) {
      var out = [];
      var keyed = /^\s*(tlsContext|secureContext)\s*:\s*(.*)$/;
      for (var i = 0; i < file.lines.length; i++) {
        var code = _codeOf(file.lines[i]);
        if (!code) continue;
        var found = keyed.exec(code);
        if (!found) continue;
        var value = found[2].replace(/[\s,]+$/, "");
        if (value === found[1]) continue;
        out.push({ file: file.rel, line: i + 1, content: file.lines[i].trim() });
      }

      var mask = _maskOf(file);
      if (/setSecureContext\s*\(/.test(mask)) return out;
      var bind = /\.listen\s*\(/g;
      var m;
      bind.lastIndex = 0;
      while ((m = bind.exec(mask)) !== null) {
        // The call's own bracket, so the whole options object is read
        // however long it grows. A character window would go quiet the
        // moment another option was added above the one it looks for.
        var openParen = m.index + m[0].length - 1;
        var close = _matchingBracket(mask, openParen);
        if (close === -1) continue;
        if (/(?:^|[\s,{])tls\s*:/.test(mask.slice(openParen, close))) {
          out.push(_atOffset(file, m.index,
            "a TLS listener is bound from certificate material here, and nothing in this " +
            "file hands the running server a renewed one"));
        }
      }
      return out;
    },
    red: [
      "function buildImap() {\n  return b.mail.server.imap.create({\n" +
        "    tlsContext: opts.tlsContext,\n  });\n}\n",
      "function start() {\n  var ctx = handle.secureContext;\n" +
        "  return upgrade({\n    secureContext: ctx,\n  });\n}\n",
      "async function start() {\n" +
        "  var listening = await app.listen({ port: port, host: address, tls: pair(files) });\n" +
        "  servers.https = listening.server;\n}\n",
    ],
    green: [
      "function buildImap() {\n  var o = { greeting: banner };\n" +
        "  Object.defineProperty(o, \"tlsContext\", {\n" +
        "    enumerable: true,\n" +
        "    get: function () { return certificate.secureContext; },\n" +
        "  });\n  return b.mail.server.imap.create(o);\n}\n",
      "function describe() {\n  return { certFile: certificate.certFile };\n}\n",
      // A table restating the name it exports is not a wiring decision.
      "module.exports = {\n  create:     create,\n  tlsContext: tlsContext,\n};\n",
      // A cleartext bind names no certificate and has nothing to renew.
      "async function start() {\n" +
        "  var listening = await app.listen({ port: port, host: address });\n" +
        "  servers.http = listening.server;\n}\n",
      // The same TLS bind, with the renewal followed.
      "async function start() {\n" +
        "  var listening = await app.listen({ port: port, host: address, tls: pair(files) });\n" +
        "  servers.https = listening.server;\n" +
        "  certificate.onReload(function () {\n" +
        "    servers.https.setSecureContext(pair(files));\n" +
        "  });\n}\n",
    ],
  },

  {
    name: "message-kept-or-dropped-on-a-matched-reason",
    description:
      "A yes or no answer about a delivery outcome, reached by matching the words in its " +
      "reason text. Whether an unsent message is kept or dropped is the one decision that " +
      "destroys mail when it is wrong, and a classifier that recognizes a sentence answers " +
      "correctly only for the failures somebody already enumerated. Every other failure, " +
      "which is the whole population of the future ones, falls to whichever side the default " +
      "happens to be, and the default is the one nobody chose. Decide from the outcome's own " +
      "fields instead: mxHost names the receiver that was reached and is absent when none " +
      "was, and reasonCode is the enhanced status, whose RFC 3463 X.4.4 value is written only " +
      "when no reply existed to take a code from. Both are frozen contracts of the composer's " +
      "per recipient outcome, so neither goes quiet when a message is reworded. Match a " +
      "reason's text only where the verdict is not a message's fate, such as classifying what " +
      "a report says about a receiver.",
    dirs: ["lib"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      bodies.forEach(function (body) {
        // A test applied to a delivery outcome's own reason text.
        var matched = _matchesIn(mask, bodies, body,
          /\.(?:test|exec|match|search)\s*\([^)]*\breason\b|\breason\s*\.\s*(?:indexOf|includes|startsWith|endsWith|match|search)\s*\(/g);
        if (matched.length === 0) return;
        // Answering yes or no, rather than classifying into a vocabulary.
        if (_matchesIn(mask, bodies, body, /\breturn\s+(?:true|false)\s*[;)]/g).length === 0) return;
        // About a delivery outcome, rather than about any other text.
        // Both names are fields of the composer's per recipient row.
        if (_matchesIn(mask, bodies, body, /\b(?:reasonCode|mxHost)\b/g).length === 0) return;
        out.push(_atOffset(file, matched[0].offset,
          "a delivery outcome is judged by matching its reason text rather than by its " +
          "recorded verdict"));
      });
      return out;
    },
    red: [
      "function _isStalled(entry) {\n" +
        "  if (String(entry.reasonCode || \"\") !== \"4.4.4\") return false;\n" +
        "  if (typeof entry.mxHost === \"string\" && entry.mxHost.length > 0) return false;\n" +
        "  return TRANSPORT_ABSENT_RE.test(String(entry.reason || \"\"));\n}\n",
      "function keepIt(row) {\n" +
        "  if (!row.mxHost) return row.reason.indexOf(\"is not a function\") !== -1;\n" +
        "  return false;\n" +
        "  var unused = row.reasonCode;\n}\n",
    ],
    green: [
      // The verdict comes from the recorded fields, so no text is read.
      "function _isStalled(entry) {\n" +
        "  var answered = typeof entry.mxHost === \"string\" && entry.mxHost.length > 0;\n" +
        "  if (answered) return false;\n" +
        "  return String(entry.reasonCode || \"\") === \"4.4.4\";\n}\n",
      // Matching a reason is fine where the answer is a classification
      // rather than a message's fate.
      "function _tlsRptResultFor(row) {\n" +
        "  if (row.reasonCode === MX_MISMATCH) return RESULT.STS_INVALID;\n" +
        "  var reason = String(row.reason || \"\");\n" +
        "  if (STARTTLS_RE.test(reason)) return RESULT.STARTTLS_MISSING;\n" +
        "  return null;\n}\n",
      // A yes or no answer about text that is not a delivery outcome.
      "function _isAbsence(err) {\n" +
        "  if (err.code === \"ENODATA\") return true;\n" +
        "  var m = RCODE_RE.exec(String(err.message || \"\"));\n" +
        "  return m !== null && Number(m[1]) === 3;\n}\n",
    ],
  },

  {
    name: "signature-over-a-decoded-message",
    description:
      "A message decoded to a string with a utf8 toString and then handed to a signer as that " +
      "same variable. A message is an octet stream rather than text, and a utf8 decode " +
      "replaces every sequence that is not valid utf8 with the replacement character, which " +
      "no re-encoding recovers: all 128 octet values from 0x80 up are lost when they stand " +
      "alone, and legacy single-byte charsets and 8BITMIME bodies carry them routinely. " +
      "Signing what the decode returned binds the signature to a message the sender never " +
      "wrote, and the re-encoded copy is the one that gets relayed and the one that gets " +
      "stored, so the octets the account submitted survive nowhere and the corruption reads " +
      "as authentic. Hand the signer the octets themselves. A signer that takes a Buffer " +
      "hashes and returns the bytes it was given, so the octets that leave are the octets " +
      "that were signed, and no message has to be refused to keep that true.",
    dirs: ["lib"],
    scan: _contentMatcher(
      /(\b[A-Za-z_$][\w$]*)\s*=[^;]{0,200}?\.toString\s*\(\s*["']utf-?8["']\s*\)(?:(?!\n\})[\s\S]){0,4000}?\.sign\s*\(\s*(?:[^(),]{0,120},\s*)?\1\s*[,)]/g),
    red: [
      "async function sign(domain, rfc822) {\n  var text = rfc822.toString(\"utf8\");\n" +
        "  return signer.sign(text);\n}\n",
      "function signIt(dkim, domain, raw) {\n  var wire = raw.toString(\"utf8\");\n" +
        "  return dkim.sign(domain, wire);\n}\n",
      "async function sign(domain, rfc822) {\n  var text = Buffer.isBuffer(rfc822)\n" +
        "    ? rfc822.toString(\"utf8\") : String(rfc822);\n" +
        "  var signed = signer.sign(text);\n  return signed;\n}\n",
    ],
    green: [
      // The shipped shape: the message reaches the signer as whatever it
      // arrived as, so a Buffer is hashed and returned as octets.
      "async function sign(domain, rfc822) {\n  return signerFor(domain).sign(rfc822);\n}\n",
      "function withHeader(rawBytes, line) {\n  var text = rawBytes.toString(\"utf8\");\n" +
        "  return Buffer.from(text + line, \"utf8\");\n}\n",
      "async function send(dkim, domain, wire) {\n  return dkim.sign(domain, wire);\n}\n",
    ],
  },

  {
    name: "octet-count-describes-a-different-value",
    description:
      "A byte count over a string a utf8 decode produced, emitted without the string it " +
      "counted. A count has one job: to describe the bytes that are actually written or " +
      "actually used. A utf8 decode does not preserve a count, because every sequence it " +
      "cannot read becomes a three byte replacement character, so the decoded copy and the " +
      "octets behind it are two different lengths and a count of one of them is wrong about " +
      "the other. Which one is wrong depends on which one travels. A length written beside " +
      "the decoded string it frames is honest, and the framing holds however lossy the decode " +
      "was. A length written on its own, into a record or an environment describing a message " +
      "the caller holds elsewhere, describes a rendering nobody receives: RFC 5228 sizes a " +
      "message in octets for the `size` test and RFC 9051 answers RFC822.SIZE in them, and " +
      "both are then answered from a number the peer can inflate by choosing a charset. Count " +
      "the value that leaves. Where the bytes are the thing that leaves, their length is the " +
      "answer and no decode belongs in the measurement at all.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      // A name this function decoded out of bytes, and a count taken
      // over a name. Both are read per function, because a count is
      // only suspect beside the decode that produced what it counted.
      var DECODED = /\b([A-Za-z_$][\w$]*)\s*=(?:[^;]){0,300}?\.\s*toString\s*\(\s*["']utf-?8["']\s*\)/g;
      var COUNTED = /Buffer\s*\.\s*byteLength\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]/g;
      bodies.forEach(function (body) {
        var decoded = {};
        _matchesIn(mask, bodies, body, DECODED).forEach(function (d) {
          decoded[d.groups[1]] = 1;
        });
        _matchesIn(mask, bodies, body, COUNTED).forEach(function (c) {
          var name = c.groups[1];
          if (decoded[name] !== 1) return;
          var span = _statementAround(mask, c.offset, body);
          // The count itself is one occurrence. A second one anywhere in
          // the same statement is the counted value traveling out
          // beside its count, which is the honest shape.
          if (_wholeWordCount(mask.slice(span.start, span.end), name) > 1) return;
          out.push(_atOffset(file, c.offset,
            name + " is counted here and is not carried by the statement that emits the count"));
        });
      });
      return out;
    },
    red: [
      "function envOf(inbound) {\n  var text = inbound.body.toString(\"utf8\");\n" +
        "  return { sizeBytes: Buffer.byteLength(text, \"utf8\") };\n}\n",
      // The Sieve environment as it was built before this rule existed.
      // Kept whole, nested callback and all, because the count and the
      // decode sit in the outer function while a loop below them sits in
      // an inner one, and a matcher that read the two as one function
      // would report a shape that is not there.
      "function _sieveEnv(inbound, target) {\n" +
        "  var text = Buffer.isBuffer(inbound.body)\n" +
        "    ? inbound.body.toString(\"utf8\")\n" +
        "    : String(inbound.body || \"\");\n" +
        "  var parsed = b.safeMime.parse(text);\n" +
        "  var raw = (parsed && parsed.headers && parsed.headers.raw) || {};\n" +
        "  var headers = [];\n" +
        "  Object.keys(raw).forEach(function (name) {\n" +
        "    var values = raw[name] || [];\n" +
        "    for (var i = 0; i < values.length; i += 1) {\n" +
        "      headers.push({ name: name, value: values[i] });\n" +
        "    }\n" +
        "  });\n" +
        "  return {\n" +
        "    headers:   headers,\n" +
        "    envelope:  { from: inbound.mailFrom || \"\", to: target.mailbox },\n" +
        "    sizeBytes: Buffer.byteLength(text, \"utf8\"),\n" +
        "  };\n}\n",
    ],
    green: [
      "function envOf(inbound) {\n  var bytes = toBytes(inbound.body);\n" +
        "  return { headers: parse(bytes), sizeBytes: bytes.length };\n}\n",
      // An IMAP literal, which announces the octet count of the payload
      // written immediately after it. The count and the counted string
      // are one value leaving together, so the framing holds however
      // lossy the decode that produced it was. The decode may still be
      // wrong; that is a different rule, about a different thing.
      "function _literal(label, bytes) {\n  var text = bytes.toString(\"utf8\");\n" +
        "  return label + \" {\" + Buffer.byteLength(text, \"utf8\") + \"}\\r\\n\" + text;\n}\n",
      "function envOf(inbound) {\n  var text = inbound.body.toString(\"utf8\");\n" +
        "  return { body: text, sizeBytes: Buffer.byteLength(text, \"utf8\") };\n}\n",
    ],
  },

  {
    name: "header-break-by-whole-message-search",
    description:
      "The end of a message's header block, found by searching the whole message for one " +
      "spelling of the blank line that ends it. RFC 5322 section 2.1 ends the block at the " +
      "FIRST empty line, and this server keeps the octets a peer sent rather than rewriting " +
      "them, so that line arrives as a CRLF pair from a conforming sender and as a bare LF " +
      "from one that read the message off a disk. A search for the CRLF spelling lands on a " +
      "later blank line inside the body of every bare-LF message that quotes a forward or " +
      "carries a MIME preamble, and finds nothing at all in one that does not, so the caller " +
      "either serves body text as headers or serves the whole message as headers. A search " +
      "for the bare spelling fails the same way with the two reversed. Either shape hands the " +
      "sender the choice of which of its own bytes this server calls a header, and leaves the " +
      "surfaces that split correctly disagreeing with the ones that do not about one stored " +
      "message. Scan forward once and stop at the first empty line whichever terminator wrote " +
      "it: blamepost.mail.mailbox.headerBreak is that scan, and every caller composes it " +
      "rather than repeating it.",
    dirs: ["lib", "bin", "scripts"],
    scan: function (file) {
      var mask  = _maskOf(file);
      var names = _blankLineNames(file.text);
      var out   = [];
      // The search runs over the mask, so a call written inside a
      // comment or quoted inside a string literal is not one: both have
      // their parenthesis blanked there. The ARGUMENT is then read back
      // out of the source at the same offsets, because that is where
      // the escape sequence still exists.
      WHOLE_MESSAGE_SEARCH_RE.lastIndex = 0;
      var m;
      while ((m = WHOLE_MESSAGE_SEARCH_RE.exec(mask)) !== null) {
        var open     = m.index + m[0].length - 1;
        var firstArg = _firstArgument(mask, open);
        if (firstArg === null) continue;
        var argSource = file.text.slice(open + 1, open + 1 + firstArg.length);
        if (!_isBlankLineArgument(argSource, names)) continue;
        out.push(_atOffset(file, m.index,
          "the header break is searched for as " + argSource.trim()));
      }
      return out;
    },
    red: [
      // The reported header block, found by looking through the whole
      // message for the CRLF spelling.
      "var HEADER_SEPARATOR = \"\\r\\n\\r\\n\";\n" +
        "function _headerBlock(body) {\n" +
        "  var separator = body.indexOf(HEADER_SEPARATOR);\n" +
        "  return body.subarray(0, separator === -1 ? body.length : separator + 2);\n}\n",
      // The same shape with the value written where it is used.
      "function insertHeader(raw, line) {\n" +
        "  var at = raw.indexOf(\"\\r\\n\\r\\n\");\n  return at;\n}\n",
      // The mirror, which fails the same way with the two spellings
      // reversed.
      "var BREAK = Buffer.from(\"\\n\\n\", \"ascii\");\n" +
        "function split(raw) {\n  return raw.indexOf(BREAK);\n}\n",
      // Built from octets rather than from an escape, so a respelling
      // does not get past the matcher.
      "var BREAK = Buffer.from([0x0D, 0x0A, 0x0D, 0x0A]);\n" +
        "function split(raw) {\n  return raw.indexOf(BREAK);\n}\n",
      // Cut rather than located, which is the same question asked with
      // a different verb.
      "function parts(msg) {\n  return String(msg).split(\"\\r\\n\\r\\n\");\n}\n",
    ],
    green: [
      // The forward scan: one pass, stopping at the first empty line
      // whichever terminator wrote it.
      "function headerBreak(raw) {\n" +
        "  for (var i = 0; i + 1 < raw.length; i += 1) {\n" +
        "    if (raw[i] === 0x0d && raw[i + 1] === 0x0a &&\n" +
        "        raw[i + 2] === 0x0d && raw[i + 3] === 0x0a) return { at: i, terminator: 2 };\n" +
        "    if (raw[i] === 0x0a && raw[i + 1] === 0x0a) return { at: i, terminator: 1 };\n" +
        "  }\n  return null;\n}\n",
      // A caller composing that scan rather than repeating it.
      "function _headerBlock(body) {\n" +
        "  var brk = mailbox.headerBreak(body);\n" +
        "  return body.subarray(0, brk === null ? body.length : brk.at + brk.terminator);\n}\n",
      // A single line ending is not the blank line that ends the block,
      // so a search for one is a different question.
      "var CRLF = Buffer.from(\"\\r\\n\", \"ascii\");\n" +
        "function firstLine(raw) {\n  return raw.indexOf(CRLF);\n}\n",
      // Prose describing the shape is not the shape.
      "// A block found with raw.indexOf(\"\\r\\n\\r\\n\") is found in the wrong place.\n" +
        "function headerBlock(raw) {\n  return raw;\n}\n",
    ],
  },

  {
    name: "byte-cap-that-stops-holding-at-the-decode",
    description:
      "A byte cap taken on octets, decoded to utf8, and never applied again to what the " +
      "decode returned. A cap describes the value it was measured on. This one is measured on " +
      "the octets and then the octets are thrown away: an octet no utf8 decoder can read is " +
      "replaced by a three byte character, so a peer sending nothing else hands back three " +
      "times the cap, and where the capped value goes into a report or onto a wire that is an " +
      "amplification whose factor the peer chooses. Capping the octets first is right and " +
      "bounds the work, so this is not an argument against it: it is an argument that the " +
      "value which actually leaves has to be bounded too, in the encoding it leaves in, and " +
      "cut on a code point boundary so the cut cannot leave half a character behind. A " +
      "function that spends the same budget again on the decoded text has done that and is " +
      "not a finding.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      // Buffer.slice is Buffer.subarray under another name, so both
      // spellings take a byte window and both are read here.
      var WINDOW  = /\.\s*(?:subarray|slice)\s*\(/g;
      var CAP     = /\b([A-Za-z_$][\w$]*_BYTES)\b/;
      // The decode has to be applied to the window itself. Walking the
      // bracket to find where the window ends is what makes that exact,
      // rather than a character budget standing in for the answer and
      // quietly ceasing to match as the call grows.
      var DECODE  = /^\s*\.\s*toString\s*\(\s*["']utf-?8["']\s*\)/;
      bodies.forEach(function (body) {
        _matchesIn(mask, bodies, body, WINDOW).forEach(function (m) {
          var open = mask.indexOf("(", m.offset);
          if (open === -1) return;
          var close = _matchingBracket(mask, open);
          if (close === -1 || close >= body.end) return;
          var cap = CAP.exec(mask.slice(open + 1, close));
          if (!cap) return;
          var tail = mask.slice(close + 1, body.end);
          if (!DECODE.test(tail)) return;
          var afterDecode = tail.replace(DECODE, "");
          // The same budget spent again, on the text this time.
          if (new RegExp("\\b" + cap[1] + "\\b").test(afterDecode)) return;
          out.push(_atOffset(file, m.offset,
            cap[1] + " bounds the octets and nothing bounds the text they decode to"));
        });
      });
      return out;
    },
    red: [
      // The reported header block as it was built before this rule
      // existed, whole rather than as its last line.
      "function _headerBlock(body) {\n" +
        "  var bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body), \"utf8\");\n" +
        "  var separator = bytes.indexOf(HEADER_SEPARATOR);\n" +
        "  var end = separator === -1 ? bytes.length : separator + 2;\n" +
        "  return bytes.subarray(0, Math.min(end, MAX_REPORTED_HEADER_BYTES)).toString(\"utf8\");\n}\n",
      "function shown(bytes) {\n  return bytes.slice(0, MAX_SHOWN_BYTES).toString(\"utf8\");\n}\n",
    ],
    green: [
      // The budget is spent a second time, on the text that leaves.
      "function headerBlock(bytes, end) {\n" +
        "  var window = bytes.subarray(0, Math.min(end, MAX_REPORTED_HEADER_BYTES)).toString(\"utf8\");\n" +
        "  return boundText(window, MAX_REPORTED_HEADER_BYTES);\n}\n",
      "function headerBlock(bytes, end) {\n" +
        "  return boundText(bytes.subarray(0, end).toString(\"utf8\"), MAX_REPORTED_HEADER_BYTES);\n}\n",
      // Octets in and octets out: nothing was decoded, so the cap still
      // describes what is carried.
      "function headerBlock(bytes, end) {\n" +
        "  return bytes.subarray(0, Math.min(end, MAX_REPORTED_HEADER_BYTES));\n}\n",
    ],
  },

  {
    name: "byte-budget-spent-on-text",
    description:
      "A budget named in bytes spent by slicing a value that is then joined to a string, " +
      "which is what makes the sliced value text rather than octets. Slicing a buffer to a " +
      "byte budget is exact and is not a finding; slicing a string to one is not, because a " +
      "JavaScript string is indexed in UTF-16 code units and a character is one unit at three " +
      "bytes across most of the world's scripts and two units at four bytes beyond them, so a " +
      "budget of N bytes spent this way lets several times N through. The cut is the second " +
      "half of it: a slice landing between the two units of one character leaves an unpaired " +
      "half, which is a string no encoder can write out, so the record an operator opened to " +
      "diagnose one failure becomes the next one. Spend the budget over code points, charging " +
      "each one what it actually costs to store.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      var SLICE = /\.\s*slice\s*\(/g;
      var CAP   = /\b([A-Za-z_$][\w$]*_BYTES)\b/;
      // Concatenation is the proof the sliced value is text. A buffer
      // joined to a string with a plus is not code anybody writes, so
      // this separates the case the reason is about from an honest byte
      // window, without having to guess at a variable's type.
      var JOINED = /^\s*\+/;
      bodies.forEach(function (body) {
        _matchesIn(mask, bodies, body, SLICE).forEach(function (m) {
          var open = mask.indexOf("(", m.offset);
          if (open === -1) return;
          var close = _matchingBracket(mask, open);
          if (close === -1 || close >= body.end) return;
          var cap = CAP.exec(mask.slice(open + 1, close));
          if (!cap) return;
          if (!JOINED.test(mask.slice(close + 1, body.end))) return;
          out.push(_atOffset(file, m.offset,
            cap[1] + " is a byte budget and it is being spent in the units a string is indexed by"));
        });
      });
      return out;
    },
    red: [
      // The screening a delivery record went through before this rule
      // existed: a budget named in bytes, both tests spent on the units
      // the string is indexed by.
      "function _screenForDisplay(value) {\n" +
        "  var safe = sanitize(foldHeaderText(_text(value), \" \"));\n" +
        "  if (safe.length <= MAX_RECORDED_REASON_BYTES) return safe;\n" +
        "  return safe.slice(0, MAX_RECORDED_REASON_BYTES - TRUNCATION_MARK.length) + TRUNCATION_MARK;\n}\n",
      "function shorten(answer) {\n  return answer.slice(0, MAX_SHOWN_BYTES) + \"...\";\n}\n",
    ],
    green: [
      "function shorten(safe) {\n" +
        "  return boundByCost(safe, MAX_RECORDED_REASON_BYTES, utf8Cost) + MARK;\n}\n",
      // A byte window taken out of a buffer, which is what the budget
      // actually names.
      "function head(buf) {\n  return buf.slice(0, MAX_HEADER_BYTES);\n}\n",
      "function shorten(flat) {\n  return flat.slice(0, MAX_SHOWN_CHARS) + \"...\";\n}\n",
      "function named(refused) {\n  return refused.slice(0, MAX_REPORTED_RECIPIENTS);\n}\n",
    ],
  },

  {
    name: "mail-agent-without-role-gate",
    description:
      "A b.mail.agent.create in shipped source whose options carry no permissions key. The " +
      "agent checks a scope on every verb it routes and checks nothing at all when it holds " +
      "no permission table, so the two are indistinguishable from every caller below it: one " +
      "is a gate that allows everything, the other is no gate. An agent composed this way " +
      "runs the wire protocols with no role check beside a browser surface that has one, and " +
      "nothing says so until somebody uses it. Build it through the mailbox module's agent " +
      "factory, which composes the table this server issues, so there is one construction " +
      "site rather than one per consumer.",
    dirs: ["lib", "bin"],
    scan: _contentMatcher(
      /\.mail\.agent\.create\s*\(\s*\{(?:(?!permissions\s*:)(?!\n\})[\s\S]){0,4000}?\}\s*\)/g),
    red: [
      "function build(store) {\n  return b.mail.agent.create({\n    store:    store,\n" +
        "    posture:  null,\n    dispatch: { mode: \"local\" },\n  });\n}\n",
      "var agent = b.mail.agent.create({ store: store, dispatch: { mode: \"local\" } });\n",
    ],
    green: [
      "function build(store) {\n  return b.mail.agent.create({\n    store:       store,\n" +
        "    posture:     null,\n    permissions: roleTable(),\n" +
        "    dispatch:    { mode: \"local\" },\n  });\n}\n",
    ],
  },

  {
    name: "octet-count-over-indexed-text",
    description:
      "One function measures a value in octets with Buffer.byteLength and indexes that same " +
      "value with String.slice. The two count different things. A JavaScript string is " +
      "counted in UTF-16 code units; every offset and length the mail protocols carry is " +
      "counted in octets, from the IMAP partial fetch BODY[]<start.count> to the literal that " +
      "announces how many octets follow it to the POP3 message size. On any message that is " +
      "not entirely ASCII the two diverge, so a window a client addressed in octets is served " +
      "from somewhere else and a count the client is about to trust describes a different " +
      "number of bytes than arrive. Hold the octets in a Buffer, take the window with " +
      "subarray, and convert once at the point the bytes leave.",
    dirs: ["lib"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      var INDEXED = /([A-Za-z_$][\w$]*)\s*\.\s*slice\s*\(/g;
      var MEASURED = /Buffer\s*\.\s*byteLength\s*\(\s*([A-Za-z_$][\w$]*)\s*,/g;
      bodies.forEach(function (body) {
        var indexed  = _matchesIn(mask, bodies, body, INDEXED);
        var measured = _matchesIn(mask, bodies, body, MEASURED);
        if (indexed.length === 0 || measured.length === 0) return;
        var seen = {};
        measured.forEach(function (mm) {
          indexed.forEach(function (ii) {
            var name = ii.groups[1];
            if (name !== mm.groups[1] || seen[name]) return;
            seen[name] = 1;
            out.push(_atOffset(file, ii.offset,
              name + " is measured in octets and indexed as text in the same function"));
          });
        });
      });
      return out;
    },
    red: [
      "function render(bytes, start, count) {\n  var text = bytes.toString(\"utf8\");\n" +
        "  text = text.slice(start, start + count);\n" +
        "  return \"{\" + Buffer.byteLength(text, \"utf8\") + \"}\\r\\n\" + text;\n}\n",
      "function frame(body) {\n  var size = Buffer.byteLength(body, \"utf8\");\n" +
        "  var head = body.slice(0, 80);\n  return size + head;\n}\n",
    ],
    green: [
      "function render(bytes, start, count) {\n  var window = bytes.subarray(start, start + count);\n" +
        "  var text = window.toString(\"utf8\");\n" +
        "  return \"{\" + Buffer.byteLength(text, \"utf8\") + \"}\\r\\n\" + text;\n}\n",
      "function frame(body) {\n  return Buffer.byteLength(body, \"utf8\");\n}\n" +
        "function preview(other) {\n  return other.slice(0, 80);\n}\n",
    ],
  },

  {
    name: "message-octets-round-tripped-through-text",
    description:
      "A function decodes bytes with toString(\"utf8\") and then indexes the result or encodes " +
      "it back to bytes. That round trip is not the identity: any octet sequence the decoder " +
      "does not recognize becomes U+FFFD, which is three octets where there was one, so what " +
      "comes out is neither what went in nor the size recorded for it, and nothing reports " +
      "the substitution. Mail carries those octets routinely — an 8BITMIME body in a legacy " +
      "charset, an unencoded 8-bit header field — so a message, a header block or a body " +
      "stays in a Buffer end to end. Decode only what a specification defines as UTF-8, and " +
      "only after isUtf8 has confirmed the bytes are; refuse the ones that are not, loudly, " +
      "rather than substituting characters into somebody's mail.",
    dirs: ["lib"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      var DECODE  = /\.\s*toString\s*\(\s*["']utf-?8["']\s*\)/g;
      // Indexing the decoded text, or encoding it back. Either one means
      // the bytes were needed after all.
      var REUSE   = /\.\s*slice\s*\(|Buffer\s*\.\s*(?:from|concat)\s*\(/g;
      // A function that has established the bytes are valid UTF-8
      // before decoding them is not a finding: the round trip it then
      // performs really is the identity. Both shapes that establish it
      // count, the predicate and the decoder that refuses instead of
      // substituting.
      var GATED   = /\bisUtf8\s*\(|\bfatal\s*:\s*true\b/;
      bodies.forEach(function (body) {
        // The gate has to be this function's own. A check inside a
        // function nested below it says nothing about the bytes this one
        // is decoding.
        if (GATED.test(_ownText(mask, bodies, body))) return;
        var decodes = _matchesIn(mask, bodies, body, DECODE);
        if (decodes.length === 0) return;
        var reuses = _matchesIn(mask, bodies, body, REUSE);
        for (var i = 0; i < reuses.length; i += 1) {
          if (reuses[i].offset <= decodes[0].offset) continue;
          out.push(_atOffset(file, decodes[0].offset,
            "bytes are decoded to text here and needed as bytes again below"));
          return;
        }
      });
      return out;
    },
    red: [
      "function withHeader(rawBytes, line) {\n  var text = rawBytes.toString(\"utf8\");\n" +
        "  var at = text.indexOf(\"\\r\\n\\r\\n\");\n" +
        "  return Buffer.from(text.slice(0, at) + line + text.slice(at), \"utf8\");\n}\n",
      "async function sign(domain, rfc822) {\n  var text = rfc822.toString(\"utf8\");\n" +
        "  return Buffer.from(signer.sign(text), \"utf8\");\n}\n",
    ],
    green: [
      "function withHeader(rawBytes, line) {\n  var at = rawBytes.indexOf(SEPARATOR);\n" +
        "  return Buffer.concat([rawBytes.subarray(0, at), line, rawBytes.subarray(at)]);\n}\n",
      "async function sign(domain, rfc822) {\n  if (!isUtf8(rfc822)) throw new Error(\"refused\");\n" +
        "  var text = rfc822.toString(\"utf8\");\n" +
        "  return Buffer.from(signer.sign(text), \"utf8\");\n}\n",
      "function decodeSasl(response) {\n  var raw = Buffer.from(response, \"base64\");\n" +
        "  return raw.toString(\"utf8\").split(SEPARATOR);\n}\n",
    ],
  },

  {
    name: "test-check-discards-third-argument",
    description:
      "An assertion calling check() with a third argument. check(label, condition) takes two, " +
      "so the third is evaluated and thrown away and the failure prints the label alone. The " +
      "value that decided the verdict is what a reader needs: a wire transcript, a rendered " +
      "page, a spawned process or a config object says which of the many ways the condition " +
      "could be false actually happened, and without it the next move is another run with a " +
      "print statement added. count(label, condition, detail) is the same assertion with that " +
      "value quoted in the message, bounded and collapsed onto one line, and it increments the " +
      "same counter, so converting a call changes what a failure says and not what a run " +
      "totals. Pass the value to count rather than dropping it into check.",
    dirs: ["test"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      // Two spellings reach the shared assertion: the bound local every
      // file declares, and the qualified form through the helpers
      // module. Nothing else does, so a `.check(` on some other object
      // is excluded by the same lookbehind that keeps `recheck(` and
      // `_precheck(` out, and the arity of a DNS posture checker or a
      // permission table is not read against this rule.
      var re = /(?<![A-Za-z0-9_$.])(?:helpers\s*\.\s*)?check\s*\(/g;
      var m;
      while ((m = re.exec(mask)) !== null) {
        // The declaration is not a call. Its parameter list is the
        // contract calls are read against, so counting it would report
        // the statement of the rule as a breach of it.
        if (/\bfunction\s+$/.test(mask.slice(Math.max(0, m.index - 24), m.index))) continue;
        // Arguments are cut at the commas sitting at the call's own
        // bracket depth, so a nested call, an array, an object literal
        // and a comma inside a label all stay inside the one argument
        // that holds them. A character budget would answer this wrong
        // the first time an argument grew.
        var argc = _argumentCount(file.text, mask, m.index + m[0].length - 1);
        if (argc < 3) continue;
        out.push(_atOffset(file, m.index,
          "check() called with " + argc + " arguments; everything after the second is " +
          "discarded, so the failure prints the label with no value beside it"));
      }
      return out;
    },
    red: [
      "check(\"the page carries the account\", body.indexOf(\"alice\") !== -1, body);\n",
      "helpers.check(\"the queue drained\", q.length === 0, JSON.stringify(q));\n",
      // The third argument arrives through a nested call carrying commas
      // of its own, which is the shape a character-counting matcher and
      // a comma-splitting one both get wrong.
      "check(\"headers\", has(h, \"from\", \"to\"), render(h, { limit: 2 }));\n",
    ],
    green: [
      "check(\"the page carries the account\", body.indexOf(\"alice\") !== -1);\n",
      "count(\"the page carries the account\", body.indexOf(\"alice\") !== -1, body);\n",
      "count(\"the transcript ends on the refusal\", ok, transcript, { limit: 2000 });\n",
      // Commas belonging to a nested call, an array literal, an object
      // literal and a string do not separate arguments.
      "check(\"headers\", has(h, \"from\", \"to\"));\n",
      "check(\"rows\", eq(rows, [\"a\", \"b\", \"c\"]));\n",
      "check(\"opts\", same(o, { a: 1, b: 2 }));\n",
      "check(\"the label is literal\", text === \"a, b, c\");\n",
      // Neither an identifier ending in the word nor another object's
      // method of the same name is this assertion.
      "recheck(\"label\", cond, detail);\n",
      "state._precheck(\"label\", cond, detail);\n",
      "check(\"the role table answers\", table.check(actor, \"mail:expunge\") === true);\n",
      "var report = await posture.check({ domains: [\"example.com\"] }, opts, extra);\n",
      // The declaration states the contract rather than breaching it.
      "function check(label, condition) {\n  if (!condition) throw new Error(label);\n}\n",
    ],
  },

  {
    name: "test-promise-settimeout-sleep",
    description:
      "A fixed-budget sleep in a test. Every \"passes alone, fails under load\" flake is a " +
      "budget tuned on an idle machine: too short and it flakes on a contended runner, too " +
      "long and it wastes the whole suite's time. Poll instead, with helpers.waitUntil, which " +
      "returns the moment the condition holds and names the condition when it times out. To " +
      "assert that nothing happens across a window, helpers.passiveObserve is the one shape " +
      "that legitimately burns its budget.",
    dirs: ["test"],
    scan: _contentMatcher(/new\s+Promise\s*\((?:(?!\n\})[\s\S]){0,200}?setTimeout\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*\d+\s*\)/g),
    red: [
      "await new Promise(function (r) { setTimeout(r, 250); });\n",
      "await new Promise((resolve) => setTimeout(resolve, 1500));\n",
    ],
    green: [
      "await helpers.waitUntil(function () { return queue.drained; }, { timeoutMs: 5000, label: \"queue drained\" });\n",
      "await new Promise(function (r) { setTimeout(r, intervalMs); });\n",
    ],
  },

  {
    name: "hand-rolled-promise-sleep",
    description:
      "A sleep written by hand in shipped source: a Promise whose executor passes its resolve " +
      "function straight to setTimeout. The framework ships b.safeAsync.sleep, which refuses a " +
      "delay that is not a finite number, accepts an abort signal, and keeps the timer " +
      "referenced unless the caller passes unref. A local copy does none of that, and each " +
      "copy is another place the same wait can be written differently. Call " +
      "b.safeAsync.sleep instead.",
    dirs: ["lib", "bin"],
    scan: _contentMatcher(/new\s+Promise\s*\((?:(?!\n\})[\s\S]){0,200}?setTimeout\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*[\w$.]+\s*\)/g),
    red: [
      "function _sleep(ms) {\n  return new Promise(function (resolve) { setTimeout(resolve, ms); });\n}\n",
      "var pause = function (ms) { return new Promise((r) => setTimeout(r, ms)); };\n",
    ],
    green: [
      "async function pause(ms) {\n  await b.safeAsync.sleep(ms);\n}\n",
      "return new Promise(function (resolve, reject) {\n" +
        "  var timer = setTimeout(function () { reject(new Error(\"timed out\")); }, budgetMs);\n" +
        "  work.then(resolve, reject);\n});\n",
    ],
  },

  {
    name: "test-fixture-mode-masked-by-umask",
    description:
      "A directory-creation mode in a test that the fixture umask narrows to something " +
      "stricter, so the fixture does not create what it says it creates. test/helpers sets a " +
      "0077 umask, because the server refuses to start against a data directory looser than " +
      "0750 and a fixture that creates its own decides whether the server under test can boot. " +
      "mkdir applies the umask to its mode argument, so a fixture written as " +
      "mkdirSync(dir, { mode: 0o755 }) to prove that a loose directory is REFUSED gets a 0700 " +
      "directory, the server starts, and the case passes having asserted nothing. chmod is not " +
      "masked, so a fixture that has to be loose sets the mode with chmodSync after creating " +
      "the directory. Only group and other bits are flagged, since those are the ones this " +
      "umask clears. The scan reads one line at a time, so a call split across lines is not " +
      "matched.",
    dirs: ["test"],
    scan: function (file) {
      var out = [];
      var re  = /mkdirSync\s*\([^;]{0,200}?mode\s*:\s*(0o[0-7]{3,4})/;
      for (var i = 0; i < file.lines.length; i++) {
        var m = re.exec(file.lines[i]);
        if (!m) continue;
        if ((parseInt(m[1].slice(2), 8) & 0o077) !== 0) {
          out.push({ file: file.rel, line: i + 1, content: file.lines[i].trim() });
        }
      }
      return out;
    },
    red: [
      "nodeFs.mkdirSync(dir, { recursive: true, mode: 0o755 });\n",
      "fs.mkdirSync(dataDir, { mode: 0o770 });\n",
    ],
    green: [
      // Group and other bits already clear, so the umask changes nothing.
      "nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });\n",
      // No mode at all is the ordinary case the umask exists to handle.
      "nodeFs.mkdirSync(dir, { recursive: true });\n",
      // The supported way to fixture a deliberately loose directory.
      "nodeFs.chmodSync(ctx.cfg.paths.dataDir, 0o777);\n",
    ],
  },

  {
    name: "test-statement-commented-out",
    description:
      "A statement disabled by commenting it out in a test. The assertions are the whole of " +
      "what a test file does, so a commented-out one costs the file its verdict while leaving " +
      "every outward sign of health: the run proceeds, the remaining checks report, and the " +
      "process exits zero. Nothing downstream can tell the difference, because the CHECKS " +
      "total a passing run prints counts what still ran, so a file that lost half its " +
      "assertions reads exactly like one that never had them, and the behavior those " +
      "assertions pinned goes unmeasured until it breaks in production. A statement that has " +
      "to stop running is deleted rather than commented, and a check that cannot run in this " +
      "environment goes through helpers.skip, which lands in the skip counter and is named in " +
      "the run instead of vanishing from it. Restore the statement, or delete it and record " +
      "in the file what is no longer covered.",
    dirs: ["test"],
    scan: function (file) {
      // A callee written hard against its parenthesis, which is how a
      // call is written and how prose naming one is not. `Copyright (c)`
      // and `the revision (a push that moves the head)` are a word and a
      // parenthetical, and both carry the space that this rejects. The
      // optional lead covers the statement keywords a call is reached
      // through; those are language, so a rename cannot retire them.
      var opensCall =
        /^(?:(?:var|let|const)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*|return\s+|throw\s+)?(?:await\s+)?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\(/;
      // A statement ends where the call closes. Prose that happens to
      // name a function reads `reconcile() compares the two tables` and
      // ends in a word, so the terminator is what separates a sentence
      // about a call from the call itself.
      var terminates = /\)\s*;$/;
      var out = [];
      for (var i = 0; i < file.lines.length; i += 1) {
        var body = _lineCommentBody(file.lines[i]);
        if (!body || !opensCall.test(body)) continue;
        // Either the statement closes here, or its parenthesis is still
        // open and the rest of it is on the commented lines below. The
        // second half is what reads a call spanning several lines, whose
        // first line ends on a callback's brace rather than on the
        // terminator.
        if (!terminates.test(body) && !_leavesParenOpen(body)) continue;
        out.push({ file: file.rel, line: i + 1, content: file.lines[i].trim() });
      }
      return _named(file, out);
    },
    red: [
      "async function refuses(session) {\n" +
      "  // await imapExpungeIsRefused(session, ctx.audit, ctx.identity, forImap);\n" +
      "  session.send(session.tag() + \" LOGOUT\");\n" +
      "}\n",
      "// check(\"the floor refuses the message inside the window\", refused === true);\n",
      "// session.send(session.tag() + \" LOGOUT\");\n",
      // Spanning several lines: the first line ends on the callback's
      // brace rather than on the terminator, and the parenthesis it
      // opened is what says the statement continues.
      "// await helpers.waitUntil(function () {\n" +
      "//   return collector.received >= 1;\n" +
      "// }, { timeoutMs: 5000, label: \"the bounce arrived\" });\n",
      // The same, broken at the argument list.
      "// count(\n" +
      "//   \"the row is held\", held === true, row);\n",
      // The value a later assertion reads, disabled with it.
      "// var rows = ctx.audit.forAction(\"mail.expunge\");\n",
      "// return helpers.waitUntil(predicate, opts);\n",
    ],
    green: [
      // The statement running, which is the whole point.
      "await imapExpungeIsRefused(session, ctx.audit, ctx.identity, forImap);\n",
      // Prose naming a function opens no statement and closes none.
      "// reconcile() compares the table against the checker's report in both\n" +
      "// directions.\n",
      // A parenthetical wrapping onto the next line leaves a parenthesis
      // open across two comment lines and is still a sentence.
      "// revision (a push after the review moves the head and this goes false\n" +
      "// until the next one).\n",
      "// Copyright (c) blamejs contributors\n",
      // A call quoted inside a sentence is not at the head of the line.
      "// The assertion is `check(label, condition)`, which takes two arguments.\n",
      // A usage example belongs in the block above the primitive, where
      // whole statements are the documented form, declarations included.
      "/**\n" +
      " * count(label, condition, detail) quotes the value in the failure.\n" +
      " *\n" +
      " *   var helpers = require(\"../helpers\");\n" +
      " *   count(\"the queue drained\", queue.length === 0, queue.length);\n" +
      " */\n",
      // A note on the end of a line whose statement still runs.
      "await helpers.waitUntil(pred, opts); // count(\"drained\", ok, n);\n",
      // The skip is the supported way to record a check that could not
      // run, and it is a live call rather than a commented one.
      "helpers.skip(\"no container engine on this host\");\n",
    ],
  },

  {
    name: "internal-rulebook-vocabulary-in-source",
    description:
      "Internal authoring vocabulary or an assistant-tooling name in the source. Numbered " +
      "phases, sweeps, batches, slices and lettered groupings are a private index into work " +
      "that a reader of this repository has no access to, so they describe nothing. The " +
      "validation " + LABEL_NOUN + "s are the same vocabulary one level down: the discipline " +
      "decides how a reader treats bad input and the label names the classification instead " +
      "of the behavior, so \"defensive by " + LABEL_NOUN + "\" and \"the observability " +
      LABEL_NOUN + "\" leave the reader knowing which bucket somebody filed the code under and " +
      "not what it does with a truncated record. Attribution and tooling names never belong " +
      "in an artifact at all. Say what the code does.",
    dirs: ["lib", "bin", "scripts", "test"],
    scan: function (file) {
      var toolingExempt = Object.prototype.hasOwnProperty.call(TOOLING_TOKEN_EXCEPTIONS, file.rel);
      var out = [];
      for (var i = 0; i < file.lines.length; i++) {
        var line = file.lines[i];
        var hit = NUMBERING_RE.test(line) || VALIDATION_LABEL_RE.test(line) ||
          (!toolingExempt && TOOLING_RE.test(line));
        if (hit) out.push({ file: file.rel, line: i + 1, content: line.trim() });
      }
      return out;
    },
    red: [
      "// Rewritten during the phase 3 sweep over the listener glue.\n",
      "// Co-Authored-By: an assistant\n",
      "// " + LABEL_NOUN_CAPITAL + "-B accounts keep the shorter retention window.\n",
      "// Defensive by " + LABEL_NOUN + ": a missing, truncated or unparseable lock reads as absent.\n",
      "// Best effort by " + LABEL_NOUN + ", and the direction of the compromise matters.\n",
      "  // Drop-silent by design, in the observability " + LABEL_NOUN +
        ": a report is not a delivery.\n",
      " * refuses at the point of parse. That is the wire " + LABEL_NOUN + " doing its job.\n",
    ],
    green: [
      "// The MX listener refuses to bind until the operator acknowledges DNS posture.\n",
      // Drop-silent on its own is the authoring rule's sanctioned marking:
      // it says what happens to the failure rather than which bucket the
      // reader was filed under.
      "// Drop-silent by design: a failed audit emit must not kill the delivery that made it.\n",
      // The health-probe tiers, which are a framework field and a real
      // distinction an operator configures.
      "  }, { tier: [\"liveness\", \"readiness\"], critical: true });\n",
      "  // Registered per " + LABEL_NOUN +
        " rather than across both, because the verdict is not the same.\n",
      "  // The same reading on the other " + LABEL_NOUN + ". A restart re-reads the same spool.\n",
    ],
  },

  {
    name: "self-history-in-source",
    description:
      "A sentence describing this software's own past. There is one release, so a clause " +
      "naming a former behavior points at a build that has never existed: an operator who " +
      "reads that an entry was held by an earlier build goes looking for which build, and " +
      "there is no answer to find. The rule is not about tense but about referent, so the " +
      "present moment is untouched: what is running now, what the queue holds now and what a " +
      "record says now are all facts about this build. Rewrite the sentence to say what the " +
      "software does. Five shapes are matched, over the comments and the string literals " +
      "rather than over raw lines, so a wrapped sentence is read whole and an identifier is " +
      "not read at all: the past habitual, a former build, a claim over the whole life of the " +
      "code, the adverb that puts a behavior in an unnamed past, and a sentence whose subject " +
      "is the change. Where a test asserts on a message this reaches, the message and the " +
      "assertion move together. Scoped to what `package.json` packs, which is what the rule " +
      "it enforces is scoped to: the rule names every comment in every source file that " +
      "ships in the tarball, and `test` and `scripts` are in neither the tarball nor the " +
      "reach of an operator. Held against them it reported 45 sites, and reading them says " +
      "why that is the wrong set rather than merely a larger one: a test comment naming the " +
      "shape a test was written against is the record of why the test exists, which is the " +
      "one piece of maintainer prose worth keeping, and a detector that asks for 45 correct " +
      "sentences to be flattened is one a maintainer learns to route around. The same " +
      "judgment the `no longer` narrowing above records, applied to the file set instead of " +
      "the phrase.",
    dirs: ["lib", "bin"],
    scan: _proseShapeMatcher(SELF_HISTORY_SHAPES),
    red: [
      "// A primitive that used to sit here, and the record of why it does not.\n",
      "// verb, so both take the button; the page used to render it for a single account.\n",
      // The wrapped sentence, which is the shape a line matcher cannot
      // read: the subject is on the line above the phrase.
      "  // Its answer holds the rows against a blob directory that keeps moving, so\n" +
      "  // frozen rows used to make every message delivered since read as unreferenced.\n",
      "// what a descriptor written against an older build carries, and it is\n",
      "  // upgrade is whatever an earlier build left held.\n",
      // The string literal, which is where an operator meets the sentence.
      "  var why = \"This message was held by an earlier build: \" + reason;\n",
      "// which is what earlier versions of this server did. Its bytes are not\n",
      " * for the release being cut, with the same fields it has always had.\n",
      "// This check previously asked whether the surface exported the callable.\n",
      "// The count contract came later. This changed what a clean run means.\n",
    ],
    green: [
      // The participle meaning employed, wrapped exactly as the tree
      // wraps it, which is the pair the run joining exists to tell apart.
      "// A domain given as a scoping argument, checked for shape before it is\n" +
      "// used to narrow anything. A mistyped name refused here is an argument.\n",
      "// layer; names a zone SAYS, folded here and only ever compared, never\n" +
      "// used to key anything.\n",
      "  // that timing cannot be used to ask which addresses exist.\n",
      "// Every dotted path in a captured snapshot whose descriptor is an array,\n" +
      "// used to hold the declarations against the surface they name.\n",
      // The present moment, which is a fact about this build.
      "// The rows now carry the moment they were frozen, so what it reports is bounded.\n",
      "// A verdict on a run: one that changed nothing and said nothing is not a failure.\n",
      // A release and a version are things that exist. A build is not.
      " * operator verifying an older release against the in-tree public key then\n",
      "  // still records the previous version. Either alone would pass on a tree\n",
      // Present-state facts about mail data, which is what "no longer"
      // carries in this tree and why it is not a shape here.
      "  // A POP3 session holding the maildrop of an account that no longer exists.\n",
      "// bodies that no longer match their digest are repaired on the next write\n",
    ],
  },

  {
    name: "dash-punctuation-in-prose",
    description:
      "Dash punctuation in prose. This repository's prose uses a colon, a comma or a second " +
      "sentence instead, in documents, workflow files, configuration and source comments " +
      "alike, and the rule holds in code because a dash pasted into a command or a flag " +
      "breaks it. Both the unicode dashes and the ASCII stand-ins are matched, because a " +
      "spaced hyphen doing a comma's job is the same interruption with a different character " +
      "rather than a fix, and so are a semicolon and a pair of parentheses. Restructure the " +
      "sentence: split it, promote the aside, or demote it into the clause it modifies. The " +
      "ASCII half needs a word character on each side, so a list bullet, a flag, a table rule " +
      "and arithmetic are all left alone. Four classes are not prose and are excluded by " +
      "name: gitignored working state, the changelog generator's separator, a citation label " +
      "naming a document's title, a fenced code block, and an inline code span.",
    dirs: ["lib", "bin", "scripts", "test", "docs", "docker", "release-notes", ".github"],
    exts: PROSE_EXT_RE,
    includeRepoRoot: true,
    scan: _dashScan,
    red: [
      "// one clause " + EM_DASH + " and the next\n",
      "// a range of 1 " + EN_DASH + " 5 messages\n",
      // The ASCII forms. Each is the same interruption as the em dash
      // above, written with the character a writer reaches for when the
      // em dash is refused, which is why the rule has to catch it here
      // rather than accept it as a fix.
      "// one clause - and the next\n",
      "// one clause -- and the next\n",
      { as: "operator.md", text: "The queue drains - usually within a minute.\n" },
      { as: "workflow.yml", text: "          # the tarball is packed once - every job reuses it\n" },
      { as: "workflow.yml",  text: "      - name: Trivy scan " + EM_DASH + " release gate\n" },
      { as: "workflow.yml",  text: "          # the tarball is packed once " + EM_DASH + " every job reuses it\n" },
      { as: "operator.md",   text: "The queue drains " + EM_DASH + " usually within a minute.\n" },
      { as: ".dockerignore", text: "# Per-app runtime state " + EM_DASH + " never bake into an image\n" },
      // The generator exclusion is the shape, not a license over the
      // file: ordinary prose in the gate that quotes the header still
      // has to fire, or excluding the shape would blind the whole file.
      { as: "check-changelog-extract.js", text: "// the gate refuses " + EM_DASH + " loudly\n" },
    ],
    green: [
      "// one clause, and the next\n",
      "var label = \"a range of 1 " + EN_DASH + " 5 messages\";\n",
      // Notation the ASCII half must not touch. A bullet has no word
      // character before it, a flag has no space inside it, a table rule
      // is three hyphens rather than two, and arithmetic lives in code
      // rather than in a comment.
      { as: "operator.md",  text: "- the first item\n- the second item\n" },
      { as: "operator.md",  text: "Run `blamepost queue flush --force` to retry everything.\n" },
      { as: "operator.md",  text: "| port | protocol |\n|------|----------|\n" },
      { as: "SECURITY.md",  text: "Verify with `git log -- keys/release-pqc-pub.json` before trusting it.\n" },
      { as: "workflow.yml", text: "      - name: Trivy scan\n" },
      "var waitMs = backoffMs[Math.min(attempt - 1, backoffMs.length - 1)];\n",
      "// grep with -iE for the case-insensitive form\n",
      { as: "CLAUDE.md",
        text: "The rule " + EM_DASH + " and every exception to it.\n" },
      { as: "check-changelog-extract.js",
        text: "// the canonical `## vX.Y.Z " + EM_DASH + " YYYY-MM-DD` header\n" },
      { as: "CHANGELOG.md",
        text: "- **Zero runtime dependencies** " + EM_DASH + " the framework is vendored in-tree.\n" },
      { as: "release-notes/v0.1.0.json",
        text: "{ \"label\": \"RFC 5321 " + EM_DASH + " Simple Mail Transfer Protocol\" }\n" },
      { as: "ARCHITECTURE.md",
        text: "```\nblamepost.db  SQLite " + EM_DASH + " accounts, domains, folders\n```\n" },
    ],
  },

  {
    name: "raw-control-byte-in-text",
    description:
      "A raw control character in a text file. Tab, newline and carriage return are layout; " +
      "every other code point below the space and DEL at 0x7f is a byte that no editor renders " +
      "and no reviewer sees in a diff. A program that needs one BUILDS it, the way " +
      "`String.fromCharCode(0)` names a SASL separator, so the character the code depends on is " +
      "written where a reader can see it. Embedding the byte instead costs the tree its own " +
      "search: grep answers `Binary file <path> matches` and prints no line and no content, so " +
      "every pattern the pre-ship audit runs with -n reports a file that matched and nothing " +
      "about what matched, which is a hit that reads like a summary line and gets skimmed. A " +
      "fixture that has to CARRY a control character is the same rule rather than an exception " +
      "to it: build the character and concatenate it, and the test keeps testing the byte while " +
      "the file stays readable. Binary assets are out of reach by construction, because this " +
      "scans only the text extensions and the named text files.",
    dirs: ["lib", "bin", "scripts", "test", "docs", "docker", "release-notes", ".github"],
    exts: PROSE_EXT_RE,
    includeRepoRoot: true,
    scan: _controlByteScan,
    red: [
      // The shape both live sites had: a separator embedded in the
      // expression that uses it.
      "if (seen.has(i + \"" + NUL + "\" + target)) continue;\n",
      // A fixture value, which is the case where the byte is the point
      // of the line and still does not have to be typed.
      "  \"a name with a control character in it\": \"a" + NUL + "b.sealed\",\n",
      // The rest of the range, so the matcher is proved on more than the
      // one code point that happened to drift in.
      "var sep = \"" + VTAB + "\";\n",
      "var reset = \"" + ESCAPE + "[0m\";\n",
      "var rub = \"" + DELETE_CH + "\";\n",
      // Prose formats carry the byte just as invisibly as source does,
      // and the operator-facing documents are where a skimmed grep hit
      // costs the most.
      { as: "operator.md", text: "The queue drains" + NUL + " within a minute.\n" },
      { as: "workflow.yml", text: "      - name: scan" + NUL + "\n" },
      { as: "release-notes/v0.1.0.json",
        text: "{ \"headline\": \"a" + NUL + "b\" }\n" },
    ],
    green: [
      // The convention itself. The call names the code point in source a
      // reviewer reads, and the file holds no control character.
      "var SASL_PLAIN_SEPARATOR = String.fromCharCode(0);\n",
      "var SEP = String.fromCharCode(0);\n",
      "if (seen.has(i + SEP + target)) continue;\n",
      // The escape sequence is two ordinary characters, a backslash and
      // a letter, so source and JSON that describe a control character
      // are left alone.
      "var sep = \"\\u0000\";\n",
      "var nl = \"\\n\";\n",
      { as: "release-notes/v0.1.0.json", text: "{ \"sep\": \"\\u0000\" }\n" },
      // The three layout characters, which every file in the tree has.
      "function f() {\n\tvar indented = 1;\n\treturn indented;\n}\n",
      { as: "operator.md", text: "| port | protocol |\n|------|----------|\n" },
    ],
  },

  {
    name: "loop-that-acts-before-it-has-refused",
    description:
      "A loop that both awaits work and refuses part way through. Whatever the earlier turns " +
      "of the loop already did stays done, and the caller is told the whole operation failed, " +
      "so the record it reads back and the state on disk disagree with no way to tell how far " +
      "the loop got. A key pair with one half written, a domain with one selector retired and " +
      "the other still signing, and a message filed into a folder the client is told it never " +
      "reached are all this one shape. Settle every element first, in a pass that touches " +
      "nothing and may refuse freely, then act in a second pass that no longer needs to " +
      "refuse. Where acting can still fail, wrap the action so the failure is caught and the " +
      "earlier turns are unwound, and name whatever could not be unwound in the error.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out = [];
      _loopBodies(mask).forEach(function (loop) {
        var body = mask.slice(loop.start, loop.end);
        if (!/\bawait\b/.test(body)) return;
        if (!/\bthrow\b/.test(body)) return;
        if (/\bcatch\b/.test(body)) return;
        out.push(_atOffset(file, loop.header));
      });
      return out;
    },
    red: [
      "async function retire(names) {\n" +
        "  for (var i = 0; i < names.length; i += 1) {\n" +
        "    var row = find(names[i]);\n" +
        "    if (!row) throw new Error(\"no selector is named \" + names[i]);\n" +
        "    await store.retireSelector(row);\n" +
        "  }\n}\n",
      "async function drain(entries) {\n" +
        "  while (entries.length > 0) {\n" +
        "    var entry = entries.shift();\n" +
        "    if (!entry.id) throw new TypeError(\"every spooled entry carries an id\");\n" +
        "    await spool.write(entry);\n" +
        "  }\n}\n",
    ],
    green: [
      "async function retire(names) {\n" +
        "  var rows = [];\n" +
        "  for (var i = 0; i < names.length; i += 1) {\n" +
        "    var row = find(names[i]);\n" +
        "    if (!row) throw new Error(\"no selector is named \" + names[i]);\n" +
        "    rows.push(row);\n" +
        "  }\n" +
        "  for (var j = 0; j < rows.length; j += 1) {\n" +
        "    await store.retireSelector(rows[j]);\n" +
        "  }\n}\n",
      "async function eraseAll(refs) {\n" +
        "  var left = [];\n" +
        "  for (var i = 0; i < refs.length; i += 1) {\n" +
        "    try { await erase(refs[i]); }\n" +
        "    catch (_e) { left.push(refs[i]); }\n" +
        "  }\n" +
        "  if (left.length > 0) throw new Error(\"still on disk: \" + left.join(\", \"));\n}\n",
      "function checkAll(names) {\n" +
        "  for (var i = 0; i < names.length; i += 1) {\n" +
        "    if (!LABEL_RE.test(names[i])) throw new TypeError(names[i] + \" is not a label\");\n" +
        "  }\n}\n",
    ],
  },

  {
    name: "filesystem-path-built-at-the-call-site",
    description:
      "A filesystem call whose path is assembled in its own argument list. An identifier that " +
      "reaches a path decides which bytes the call reads, overwrites or removes, so it has to " +
      "be checked against the shape this server mints before it becomes one, and a check is " +
      "only reliable when there is one place to put it. Every directory under the data volume " +
      "therefore derives its paths in one small function per directory, and the check sits in " +
      "front of that function. A join written at the point of use is a second door with no " +
      "check behind it: an identifier from a command line or a form field then addresses any " +
      "file on the volume whose name ends the way that directory's names end.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out = [];
      FS_ENTRY_RE.lastIndex = 0;
      var m;
      while ((m = FS_ENTRY_RE.exec(mask)) !== null) {
        var arg = _firstArgument(mask, m.index + m[0].length - 1);
        if (arg === null) continue;
        if (!PATH_ASSEMBLED_RE.test(arg) && arg.indexOf("+") === -1) continue;
        out.push(_atOffset(file, m.index));
      }
      return out;
    },
    red: [
      "function drop(id) {\n" +
        "  return nodeFs.promises.rm(nodePath.join(spoolDir, id + \".json\"), { force: true });\n}\n",
      "function readBody(id) {\n" +
        "  return b.atomicFile.read(spoolDir + \"/\" + id + \".eml\", { maxBytes: 64 });\n}\n",
    ],
    green: [
      "function _bodyPath(id) { return nodePath.join(spoolDir, id + \".eml\"); }\n",
      "function drop(id) {\n" +
        "  _assertSpoolId(id, \"remove\");\n" +
        "  return nodeFs.promises.rm(_bodyPath(id), { force: true });\n}\n",
      "b.atomicFile.ensureDir(keyDir, 0o700);\n",
    ],
  },

  {
    name: "destructive-mail-verb-outside-the-adapter",
    description:
      "A destructive mail-agent or message-store verb driven from outside the mailbox adapter. " +
      "Those verbs own one half of a delete and one half of a move: they decide whether the " +
      "message may go and they destroy the message store's row. The other half is the folder " +
      "row, the sequence number and the vault-sealed original octets, and the adapter owns " +
      "that half. A caller that reaches the verb directly performs half an operation: a delete " +
      "reports the message destroyed and leaves its body sealed and readable on the volume, " +
      "and a move leaves the message in neither folder on the mail protocols while the browser " +
      "still lists it. The adapter's own verbs carry both halves, and nothing should reach " +
      "past them.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      if (file.rel === MAILBOX_ADAPTER) return [];
      return _named(file, _lineMatcher(DESTRUCTIVE_MAIL_VERB_RE, "code")(file));
    },
    red: [
      "var verdict = await agent.expunge({ actor: actor, folder: folder, objectIds: ids });\n",
      "await agent.move({ actor: actor, from: from.storeName, to: to.storeName });\n",
      "store.hardExpunge(objectIds);\n",
    ],
    green: [
      "var outcome = await mailbox.expungeObjects(actor, folder.name, objectIds);\n",
      "var filed = await mailbox.moveObjects(actor, from.name, to.name, objectIds);\n",
      "if (typeof store.hardExpunge !== \"function\") throw new TypeError(\"store is wrong shape\");\n",
    ],
  },

  {
    name: "allocation-counter-read-in-a-body-that-suspends",
    description:
      "A folder's message identifier counter read inside a function body that also suspends. " +
      "RFC 9051 section 2.3.1.1 makes a message identifier unique within its mailbox and never " +
      "reused, so the counter it comes out of has to be read and spent without anything else " +
      "getting between the two. The database handle is one synchronous handle in one process, " +
      "which means a run of statements carrying no await cannot be cut in half and a body " +
      "carrying one can be: two callers suspended on the same await both resume holding the " +
      "value they read before it, both file a message under it, and the second one fails on " +
      "the unique index after its other half has already been committed. What is left is a " +
      "message the store holds in one folder and this layer holds in another, which no " +
      "protocol lists and no delete verb can name, because every one of them resolves an " +
      "identifier against the intersection of the two. Allocate in a synchronous function that " +
      "reads the counter and records the value it took in one run, and call that function from " +
      "the verb that suspends.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out = [];
      for (var i = 0; i < bodies.length; i += 1) {
        // Attribution is to the innermost body, so a synchronous
        // allocator declared beside a suspending verb is read as its own
        // function rather than as part of whatever encloses both.
        var reads = _matchesIn(mask, bodies, bodies[i], UID_ALLOCATION_COUNTER_RE);
        if (reads.length === 0) continue;
        if (_matchesIn(mask, bodies, bodies[i], SUSPENSION_POINT_RE).length === 0) continue;
        for (var r = 0; r < reads.length; r += 1) {
          out.push(_atOffset(file, reads[r].offset,
            "a message identifier counter is read in a body that suspends, so the value " +
            "can be spent by another caller before this one writes it"));
        }
      }
      return out;
    },
    red: [
      // The counter read after the suspension, which is where the value
      // another caller has already taken gets written a second time.
      "async function moveObjects(actor, from, to, ids) {\n" +
        "  var destination = _requireFolder(to);\n" +
        "  await agent.move({ fromFolder: from, toFolder: destination.folder, objectIds: ids });\n" +
        "  var nextUid = destination.uidnext;\n" +
        "  for (var i = 0; i < ids.length; i += 1) {\n" +
        "    rows.update(ids[i], { folder: destination.folder, uid: nextUid });\n" +
        "    nextUid += 1;\n" +
        "  }\n" +
        "  _touchFolder(destination, { uidnext: nextUid });\n" +
        "}\n",
      // The same crossing written the other way round, with the read
      // hoisted above the suspension and the counter recorded below it.
      "async function fileInto(actor, source, destination, ids) {\n" +
        "  var first = destination.uidnext;\n" +
        "  await agent.move({ fromFolder: source, toFolder: destination.folder, objectIds: ids });\n" +
        "  _touchFolder(destination, { uidnext: first + ids.length });\n" +
        "}\n",
      // The layout the adapter is actually written in: the verb is built
      // inside a factory, so its closing brace is indented and the read
      // sits one level further in again.
      "function create(opts) {\n" +
        "  async function filed(actor, to, ids) {\n" +
        "    var row = _requireFolder(to);\n" +
        "    await agent.move({ toFolder: row.folder, objectIds: ids });\n" +
        "    rows.update(ids[0], { uid: row.uidnext, uidvalidity: row.uidvalidity });\n" +
        "  }\n" +
        "  return { filed: filed };\n" +
        "}\n",
    ],
    green: [
      // The settled shape: one synchronous function reads the counter and
      // records what it took, and the verb that suspends calls it.
      "function _takeUids(folderId, howMany) {\n" +
        "  var folder = b.db.from(FOLDERS).where({ _id: folderId }).first();\n" +
        "  var first = folder.uidnext;\n" +
        "  _touchFolder(folder, { uidnext: first + howMany });\n" +
        "  return { folder: folder.folder, first: first };\n" +
        "}\n" +
        "\n" +
        "async function moveObjects(actor, from, to, ids) {\n" +
        "  var destination = _requireFolder(to);\n" +
        "  await agent.move({ fromFolder: from, toFolder: destination.folder, objectIds: ids });\n" +
        "  var taken = _takeUids(destination._id, ids.length);\n" +
        "  for (var i = 0; i < ids.length; i += 1) {\n" +
        "    rows.update(ids[i], { folder: taken.folder, uid: taken.first + i });\n" +
        "  }\n" +
        "}\n",
      // The arrival path, which allocates and writes without suspending
      // at all and is therefore already indivisible.
      "function appendMessage(name, rawBytes, appendOpts) {\n" +
        "  var row = _requireFolder(name);\n" +
        "  var uid = row.uidnext;\n" +
        "  b.db.from(MESSAGES).insertOne({ folder: row.folder, uid: uid });\n" +
        "  _touchFolder(row, { uidnext: uid + 1 });\n" +
        "  return { uid: uid, uidvalidity: row.uidvalidity };\n" +
        "}\n",
      // A synchronous reader of the counter declared beside a suspending
      // sibling inside one factory. A boundary that read the factory
      // whole would join these two into a match and name a verb that
      // does neither half, which is what the structural walk replaces.
      "function create(opts) {\n" +
        "  function selectFolder(actor, name) {\n" +
        "    var row = _requireFolder(name);\n" +
        "    return { uidnext: row.uidnext, uidvalidity: row.uidvalidity };\n" +
        "  }\n" +
        "  async function expungeFolder(actor, name) {\n" +
        "    var row = _requireFolder(name);\n" +
        "    return await agent.expunge({ folder: row.folder });\n" +
        "  }\n" +
        "  return { selectFolder: selectFolder, expungeFolder: expungeFolder };\n" +
        "}\n",
    ],
  },

  {
    name: "row-written-back-across-a-suspension",
    description:
      "A row changed or destroyed on the strength of a read taken before the body suspended, " +
      "with nothing having looked at the row again in between. The database handle is one " +
      "synchronous handle in one process, so a run of statements carrying no await cannot be " +
      "cut in half and a body carrying one can be: whatever the read said is a description of " +
      "the row as it stood before the suspension, and by the time the write lands another " +
      "caller has had the whole suspension to change it. The write then puts the earlier " +
      "state back, and the change that landed in the window is gone with no error anywhere " +
      "and no audit row saying it was undone. The password path is where this costs the most, " +
      "because the suspension is an Argon2id hash and Argon2id is slow on purpose: an " +
      "operator replacing a credential that has been taken can have their reset overwritten " +
      "by a sign in that was already in flight with the old one, and the reset reports " +
      "success. This is the sibling of the allocation-counter rule and it takes the opposite " +
      "remedy, because collapsing the read and the write into one synchronous run is only " +
      "available where the work between them is synchronous. Here it is the suspension, so " +
      "the row has to be consulted AGAIN after it: re-read inside the write and compare what " +
      "the row holds now against what the decision was made on, then write only if it still " +
      "matches. When the row has moved, abandon the write rather than failing the call, " +
      "wherever the write was an optimization the caller does not depend on.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out = [];
      for (var i = 0; i < bodies.length; i += 1) {
        var awaits = _matchesIn(mask, bodies, bodies[i], SUSPENSION_POINT_RE);
        if (awaits.length === 0) continue;
        var writes = _matchesIn(mask, bodies, bodies[i], ROW_MUTATION_VERB_RE);
        for (var w = 0; w < writes.length; w += 1) {
          var stale = _staleRowWrite(mask, bodies, bodies[i], writes[w].offset, awaits);
          if (stale === null) continue;
          out.push(_atOffset(file, writes[w].offset,
            "a row is written from " + stale + ", which was read before this body suspended " +
            "and is not read again after it, so the write puts back what another caller has " +
            "already changed"));
        }
      }
      return out;
    },
    red: [
      // The rehash on a successful sign in: the row is read at the top,
      // the hash is awaited, and the write goes out against the identity
      // the earlier read carried.
      "async function authenticate(opts) {\n" +
        "  var row = accountFor(opts.address);\n" +
        "  if (!await password.verify(row.passwordHash, opts.password)) return denied();\n" +
        "  if (password.needsRehash(row.passwordHash)) {\n" +
        "    var refreshed = await password.hash(opts.password);\n" +
        "    tables.updateRow(tables.ACCOUNTS, row._id, { passwordHash: refreshed });\n" +
        "  }\n" +
        "  return { ok: true };\n" +
        "}\n",
      // The same crossing written through the framework's own chain
      // rather than through this layer's writer.
      "async function retire(id, reason) {\n" +
        "  var row = b.db.from(SELECTORS).where({ _id: id }).first();\n" +
        "  await announce(row.selector);\n" +
        "  b.db.from(SELECTORS).where({ _id: row._id }).updateOne({ _id: row._id, status: \"retired\" });\n" +
        "}\n",
      // The destroying form, and the layout this tree is actually
      // written in: the verb is built inside a factory, so its closing
      // brace is indented and the write sits one level further in again.
      "function create(ctx) {\n" +
        "  async function forget(opts) {\n" +
        "    var row = _requireRow(opts.id);\n" +
        "    await mail.eraseAccountMail(row.address);\n" +
        "    b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: opts.reason });\n" +
        "  }\n" +
        "  return { forget: forget };\n" +
        "}\n",
    ],
    green: [
      // The settled shape for a write the caller depends on: the read is
      // repeated inside the transaction that writes, so the row the
      // decision was made about is the row that is written.
      "async function setPassword(opts) {\n" +
        "  var row = _requireRow(opts.id);\n" +
        "  var hashed = await password.hash(opts.password);\n" +
        "  return b.db.transaction(function () {\n" +
        "    _requireRow(row._id);\n" +
        "    tables.updateRow(tables.ACCOUNTS, row._id, { passwordHash: hashed });\n" +
        "    return b.db.from(tables.ACCOUNTS).where({ _id: row._id }).first();\n" +
        "  });\n" +
        "}\n",
      // The settled shape for a write the caller does NOT depend on: the
      // row is read again after the suspension and the write is taken
      // only while it still says what the decision was made on.
      "async function authenticate(opts) {\n" +
        "  var row = accountFor(opts.address);\n" +
        "  if (!await password.verify(row.passwordHash, opts.password)) return denied();\n" +
        "  if (password.needsRehash(row.passwordHash)) {\n" +
        "    var refreshed = await password.hash(opts.password);\n" +
        "    var current = b.db.from(tables.ACCOUNTS).where({ _id: row._id }).first();\n" +
        "    if (current && current.passwordHash === row.passwordHash) {\n" +
        "      tables.updateRow(tables.ACCOUNTS, row._id, { passwordHash: refreshed });\n" +
        "    }\n" +
        "  }\n" +
        "  return { ok: true };\n" +
        "}\n",
      // The read and the write with nothing between them. The verb
      // suspends afterwards to record what it did, which is a suspension
      // the write has already crossed rather than one it is exposed to.
      "async function suspendAccount(opts) {\n" +
        "  var row = _requireRow(opts.id);\n" +
        "  tables.updateRow(tables.ACCOUNTS, row._id, { status: \"suspended\" });\n" +
        "  await audit.record({ action: \"account.suspended\", id: row._id });\n" +
        "  return _present(row);\n" +
        "}\n",
      // The row bound AFTER the suspension, which is what a re-read looks
      // like when the write needs the fresh row rather than only the
      // fresh verdict.
      "async function moveObjects(actor, from, to, ids) {\n" +
        "  var destination = _requireFolder(to);\n" +
        "  await agent.move({ fromFolder: from, toFolder: destination.folder, objectIds: ids });\n" +
        "  for (var i = 0; i < ids.length; i += 1) {\n" +
        "    var row = b.db.from(MESSAGES).where({ folder: from, objectid: ids[i] }).first();\n" +
        "    if (!row) continue;\n" +
        "    b.db.from(MESSAGES).where({ _id: row._id }).updateOne({ _id: row._id, folder: to });\n" +
        "  }\n" +
        "}\n",
      // A synchronous writer declared beside a suspending sibling inside
      // one factory. A boundary that read the factory whole would join
      // these two into a match and name a verb that does neither half.
      "function create(opts) {\n" +
        "  function touch(row, changes) {\n" +
        "    b.db.from(FOLDERS).where({ _id: row._id }).updateOne(changes);\n" +
        "  }\n" +
        "  async function refresh(name) {\n" +
        "    var row = _requireFolder(name);\n" +
        "    return await agent.expunge({ folder: row.folder });\n" +
        "  }\n" +
        "  return { touch: touch, refresh: refresh };\n" +
        "}\n",
    ],
  },

  {
    name: "message-body-removed-outside-a-reference-check",
    description:
      "A module that can name a sealed message body's path and also removes files. A body is " +
      "the only copy of what a message said: nothing else on the volume holds the octets, and " +
      "the row that pointed at it says only where it was. Two places may remove one, and each " +
      "carries a check that the other could not. The mailbox adapter removes a body while " +
      "deleting the last row that named it, so the count of remaining rows is what says it is " +
      "safe. The reconciler removes a body nothing names at all, so re-reading the rows at the " +
      "unlink and refusing anything newer than an append can take is what says it is safe. A " +
      "third site has neither, and deletes a body that a row still points at or one whose row " +
      "is still being written, and in both cases the message is gone and the operator finds " +
      "out when somebody opens it. Route the removal through the module that owns the check " +
      "rather than reaching for the path.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      if (file.rel === MAILBOX_ADAPTER || file.rel === BLOB_RECONCILER) return [];
      if (!BLOB_PATH_SOURCE_RE.test(_maskOf(file))) return [];
      return _named(file, _lineMatcher(FS_REMOVE_RE, "code")(file));
    },
    red: [
      "function purge(digest) {\n" +
        "  var target = blobs.pathFor(blobDir, digest);\n" +
        "  nodeFs.rmSync(target, { force: true });\n}\n",
      "async function tidy(digests) {\n" +
        "  var dir = store.mailbox.describe().blobDir;\n" +
        "  for (var i = 0; i < digests.length; i += 1) {\n" +
        "    await nodeFs.promises.unlink(nodePath.join(dir, digests[i]));\n" +
        "  }\n}\n",
    ],
    green: [
      // Reading a body needs the path and destroys nothing.
      "function body(digest) {\n" +
        "  return b.atomicFile.readSync(blobs.pathFor(blobDir, digest), { maxBytes: 64 });\n}\n",
      // Removing a scratch directory is not removing a message body, and
      // this file has no way to name one.
      "function dropScratch(dir) {\n" +
        "  try { nodeFs.rmSync(dir, { recursive: true, force: true }); }\n" +
        "  catch (_e) { /* drop-silent by design */ }\n}\n",
      // Reporting what the reconciler answered is not reaching for a path.
      "function lines(report) {\n" +
        "  return [report.blobsOnDisk + \" on disk\", report.orphanBytes + \" bytes\"];\n}\n",
    ],
  },

  {
    name: "write-skipped-on-existence-alone",
    description:
      "A write skipped because a file is already at the path, in a body that goes on to " +
      "write that same file. Presence answers whether something is there and answers nothing " +
      "about whether it is what it should be, so a skip taken on presence alone hands the " +
      "caller whatever is at that path: a file cut short by a restore that copied a prefix, " +
      "by a write that stopped part way, or by a volume that gave back less than it was " +
      "given. The caller is holding the bytes at that moment, which is the one point where " +
      "putting it right costs the write that was about to happen anyway, and skipping is what " +
      "throws that away. Worse, it is silent: the caller is told the same thing it is told on " +
      "success, so the fault surfaces later at whoever reads the file and looks like their " +
      "problem. Check something about the CONTENT before deciding the file is already " +
      "correct, and write when it is not. A length is nearly free and separates a file cut " +
      "short from a whole one; a digest is the whole answer and costs a read of the file, so " +
      "which one belongs here is a decision to make out loud rather than to skip. The " +
      "negated reading is not this pattern and is not reported: `if (!exists(x))` decides " +
      "that something is absent, which is exactly what presence settles.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out = [];
      for (var i = 0; i < bodies.length; i += 1) {
        // The skip and the write have to be the same function's, so
        // attribution is to the innermost body. A guard in one function
        // and a write in a sibling are two functions, and reporting them
        // as one names code that does not exist.
        var skips = _matchesIn(mask, bodies, bodies[i], EXISTENCE_EARLY_EXIT_RE);
        if (skips.length === 0) continue;
        if (_matchesIn(mask, bodies, bodies[i], FILE_WRITE_RE).length === 0) continue;
        for (var s = 0; s < skips.length; s += 1) {
          out.push(_atOffset(file, skips[s].offset,
            "a write is skipped because a file is at the path, which says nothing about " +
            "whether it holds what the caller was about to put there"));
        }
      }
      return out;
    },
    red: [
      // The shape itself: presence taken as correctness, and the write
      // the skip discards sitting right below it.
      "function _writeBlob(digest, raw) {\n" +
        "  var target = _blobPath(digest);\n" +
        "  if (nodeFs.existsSync(target)) return;\n" +
        "  b.atomicFile.ensureDir(nodePath.dirname(target), 0o700);\n" +
        "  b.atomicFile.writeSync(target, vault.seal(raw.toString(\"base64\")));\n" +
        "}\n",
      // The framework's own existence reader rather than the platform's,
      // so the exemption cannot be had by changing which one is called.
      "function store(id, bytes) {\n" +
        "  if (b.atomicFile.exists(_bodyPath(id))) return;\n" +
        "  b.atomicFile.writeFileSync(_bodyPath(id), bytes);\n" +
        "}\n",
      // Built inside a factory, so the body's closing brace is indented
      // and a boundary that assumed column zero would walk past it. The
      // skip is a continue inside a loop rather than a return.
      "function create(opts) {\n" +
        "  function seed(entries) {\n" +
        "    for (var i = 0; i < entries.length; i += 1) {\n" +
        "      if (nodeFs.existsSync(entries[i].path)) continue;\n" +
        "      nodeFs.writeFileSync(entries[i].path, entries[i].bytes);\n" +
        "    }\n" +
        "  }\n" +
        "  return { seed: seed };\n" +
        "}\n",
    ],
    green: [
      // The content decides, so a file that is there and wrong is
      // written rather than trusted.
      "function _writeBlob(raw) {\n" +
        "  var digest = b.crypto.sha3Hash(raw);\n" +
        "  var target = _blobPath(digest);\n" +
        "  var onDisk = _statOrNull(target);\n" +
        "  if (onDisk !== null && onDisk.size >= _floorFor(raw.length)) return digest;\n" +
        "  b.atomicFile.writeSync(target, vault.seal(raw.toString(\"base64\")));\n" +
        "  return digest;\n" +
        "}\n",
      // Absence is what presence really settles, so the negated reading
      // is not this pattern however close it looks.
      "function spool(entry) {\n" +
        "  if (!b.atomicFile.exists(_bodyPath(entry.id))) return _abandon(entry);\n" +
        "  b.atomicFile.writeFileSync(_descriptorPath(entry.id), _render(entry));\n" +
        "}\n",
      // A presence check that ends a call which writes nothing. Reading
      // the answer off the filesystem is the whole of the question.
      //
      // Green for THIS detector and not an endorsement of the shape. The
      // real `_workingCopyRoot` no longer asks whether the path is there,
      // because a directory named /dev/shm exists on Windows too and is
      // an ordinary one on disk, so the answer was yes in the one case it
      // had to be no. It asks the kernel which filesystem is mounted
      // there instead. What this fixture pins is narrower: presence
      // deciding a return value, with no write anywhere in the function,
      // is not the thing this detector hunts.
      "function _workingCopyRoot() {\n" +
        "  if (nodeFs.existsSync(\"/dev/shm\")) return \"/dev/shm\";\n" +
        "  throw err(\"store/no-working-copy-mount\", \"no memory backed directory\");\n" +
        "}\n",
      // The guard in one function and the write in a sibling, which is
      // two functions rather than one doing both.
      "function create(ctx) {\n" +
        "  function held(path) { if (nodeFs.existsSync(path)) return true; return false; }\n" +
        "  function put(path, bytes) { b.atomicFile.writeSync(path, bytes); }\n" +
        "  return { held: held, put: put };\n" +
        "}\n",
      // A socket write is not a file write, so a presence check beside
      // one is not this pattern.
      "function answer(socket, path) {\n" +
        "  if (nodeFs.existsSync(path)) return socket.write(\"+OK already here\\r\\n\");\n" +
        "  socket.write(\"-ERR nothing there\\r\\n\");\n" +
        "}\n",
    ],
  },

  {
    name: "account-refusal-reason-partly-read",
    description:
      "A consumer that reads some of the reasons a held mailbox is refused under and not " +
      "the rest. The identity layer mints one per status it refuses for, so they are a " +
      "closed set: reading two of three means a mailbox in the third state falls through " +
      "to whatever the last branch says, which is written for a case that is not this one. " +
      "The failures are quiet and they are not the same failure twice. At the browser door " +
      "the omitted state is told its password does not match, so its owner resets a " +
      "credential that was already right. On the wire it takes the answer for the states " +
      "that lift, so a sending server retries for its whole window against a mailbox that " +
      "will never take the message. Answer the set rather than its members: test the " +
      "`account-` prefix when one sentence covers every state, or give the missing state a " +
      "branch of its own when it does not. Deriving the list from the frozen status " +
      "declaration is what keeps a status added later from arriving as a fourth omission.",
    dirs: ["lib", "bin"],
    // Anchored on the reason strings themselves, which are a frozen
    // contract rather than a symbol anybody may rename: an operator's
    // audit filter names them, and the identity layer builds them off
    // the status column. A detector anchored on the function reading
    // them would go silently green the first time somebody renamed a
    // handler, which is the failure mode a dead detector has.
    //
    // The whole quoted literal is matched, so the error codes this
    // server throws under `store/account-<status>` are a different
    // string and are left alone. Their members legitimately differ per
    // verb: `suspend` refuses an archived account and one part way
    // through an erasure and has nothing to say about a suspended one,
    // which is correct and is not this bug.
    //
    // One reason alone is not a chain. A single call site naming the
    // state it is reporting has no other branch to be inconsistent
    // with, and reporting it would fire on every correct caller in the
    // tree.
    scan: function (file) {
      if (!/\.js$/.test(file.rel)) return [];
      var seen = Object.create(null);
      var first = { line: 0 };
      for (var i = 0; i < HELD_ACCOUNT_REASONS.length; i += 1) {
        var re = new RegExp("([\"'])" + HELD_ACCOUNT_REASONS[i] + "\\1", "g");
        var hit = re.exec(file.text);
        if (hit === null) continue;
        seen[HELD_ACCOUNT_REASONS[i]] = true;
        var line = _lineOfIndex(file.text, hit.index);
        if (first.line === 0 || line < first.line) first = { line: line };
      }
      var read = Object.keys(seen);
      if (read.length < 2) return [];
      if (read.length === HELD_ACCOUNT_REASONS.length) return [];
      var missing = HELD_ACCOUNT_REASONS.filter(function (name) { return !seen[name]; });
      return [{
        file:    file.rel,
        line:    first.line,
        content: "reads " + read.sort().join(" and ") + " but not " + missing.join(" or "),
      }];
    },
    red: [
      // The chain of branches, which is the shape the browser door and
      // every report table are written in. The state nobody listed
      // reaches the last branch and is answered as something else.
      "var problem = verdict.reason === \"account-suspended\"\n" +
        "  ? \"That account is suspended.\"\n" +
        "  : verdict.reason === \"account-archived\"\n" +
        "    ? \"That account is archived.\"\n" +
        "    : \"That address and password do not match an account here.\";\n",
      // The same omission written as a table, which is how a wire
      // verdict is spelled. Which member is left out does not matter.
      "var RETRYABLE = { \"account-suspended\": true, \"account-erasing\": true };\n",
    ],
    green: [
      // Every state answered.
      "var problem = verdict.reason === \"account-suspended\"\n" +
        "  ? \"That account is suspended.\"\n" +
        "  : verdict.reason === \"account-archived\"\n" +
        "    ? \"That account is archived.\"\n" +
        "    : verdict.reason === \"account-erasing\"\n" +
        "      ? \"That account is being erased.\"\n" +
        "      : \"That address and password do not match an account here.\";\n",
      // The categorical read, which is what a consumer with one sentence
      // for the whole set should write and which cannot fall out of step
      // at all.
      "if (String(reason).indexOf(\"account-\") === 0) return \"4.2.1\";\n",
      // One reason on its own is not a chain.
      "return _denied(address, \"account-suspended\", source);\n",
      // The error codes this layer throws are a different namespace, and
      // their members differ per verb on purpose.
      "throw err(\"store/account-archived\", \"reinstate it first.\");\n" +
        "throw err(\"store/account-erasing\", \"finish the erasure instead.\");\n",
    ],
  },

  {
    name: "account-erased-out-from-under-its-mail",
    description:
      "An account row crypto-erased in a body that never reaches the account's mail, or " +
      "reaches it only after the row is already gone. The framework's erase is one row in one " +
      "table and cascades nothing, so the mailbox rows, the message rows, the message store's " +
      "rows and the sealed bodies under the blob store all survive it. Nothing else removes " +
      "them either: the body release is reference counted and the references are exactly the " +
      "rows that stayed, so the count can never reach zero and the octets are pinned for the " +
      "life of the volume. Worse, they were never sealed under anything the erase destroyed. " +
      "Every body is sealed under the volume's key, so one left behind opens exactly as it " +
      "did before, here and on every backup taken afterwards, which turns a right-to-erasure " +
      "request into a row deletion that reports success. Erase the mail through the mailbox " +
      "adapter's own verb in the same call, so the delete path, the retention floor and the " +
      "preservation-order gate all run and the caller is told which messages were held back. " +
      "Order is half of that. The delete path refuses per message, so a sweep can finish with " +
      "mail still on the volume by design, and an identity erased before the sweep leaves " +
      "exactly that mail owned by a row nothing resolves: no lookup finds it, no listing " +
      "attributes it, the reconciliation reports it as mail no account holds, and the verb an " +
      "operator is told to run again answers that there is no such account. Settle the " +
      "dependents first and erase the identity last, once nothing still names it.",
    dirs: ["lib", "bin"],
    // Attribution stays on the innermost body here, so an erasure
    // written in one function and a mail erasure written in a sibling
    // are read as two functions rather than as one doing both. The
    // account row is erased directly by the verb that owns the erasure
    // rather than from inside a callback, so nothing on this pair needs
    // to be reached from an enclosing body.
    scan: function (file) {
      return _rowAheadOfItsMaterial(file, {
        row:      ACCOUNT_ERASE_RE,
        material: ACCOUNT_MAIL_ERASE_RE,
        missing:
          "an account row is erased in a body that never reaches the account's mail, so " +
          "the mailboxes, the message rows and the sealed bodies stay on the volume",
        late:
          "an account row is erased before the sweep of the account's mail, so whatever " +
          "the delete path holds back is left owned by an identity that no longer resolves",
      });
    },
    red: [
      // The erase on its own, which is what the framework primitive does
      // and all it does.
      "async function remove(opts) {\n" +
        "  var row = _requireRow(opts.id);\n" +
        "  var result = b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: opts.reason });\n" +
        "  return { id: row._id, rowsErased: result.rowsDeleted };\n" +
        "}\n",
      // The two halves written in sibling functions, so nothing calls the
      // second one on the path that runs the first.
      "function create(ctx) {\n" +
        "  async function sweep(id) { return ctx.mail().eraseAccountMail(actor, id, {}); }\n" +
        "  async function remove(opts) {\n" +
        "    var row = _requireRow(opts.id);\n" +
        "    return b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: opts.reason });\n" +
        "  }\n" +
        "  return { remove: remove, sweep: sweep };\n" +
        "}\n",
      // Both halves on one path, and the identity destroyed first. The
      // sweep refuses per message, so the mail it keeps ends up owned by
      // a row that went one line earlier.
      "async function remove(opts) {\n" +
        "  var row = _requireRow(opts.id);\n" +
        "  var result = b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: opts.reason });\n" +
        "  var swept = await mail().eraseAccountMail(actor, row._id, { reason: opts.reason });\n" +
        "  return { rowsErased: result.rowsDeleted, mailErased: swept.destroyed.length };\n" +
        "}\n",
    ],
    green: [
      // The sweep first and the identity last, which is the order that
      // leaves anything held back still owned by something that resolves.
      "async function remove(opts) {\n" +
        "  var row = _requireRow(opts.id);\n" +
        "  var swept = await mail().eraseAccountMail(actor, row._id, { reason: opts.reason });\n" +
        "  if (swept.refused.length > 0) return { held: swept.refused };\n" +
        "  var result = b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: opts.reason });\n" +
        "  return { rowsErased: result.rowsDeleted, mailErased: swept.destroyed.length };\n" +
        "}\n",
      // An alias is a leaf: nothing in the schema points at one, so there
      // is nothing for its erasure to cascade to.
      "function dropAlias(row, reason) {\n" +
        "  return b.db.eraseHard(tables.ALIASES, row._id, { reason: reason });\n" +
        "}\n",
      // Reporting what an erasure answered is not performing one.
      "function lines(result) {\n" +
        "  return [result.rowsErased + \" row\", result.mailErased + \" message\"];\n" +
        "}\n",
    ],
  },

  {
    name: "account-verdict-built-from-the-status-column-alone",
    description:
      "A recipient or sign-in verdict about an account, built from the row's status column " +
      "without the erasure marker beside it. An erasure records itself on the account row " +
      "twice, and the identity layer's declaration of the marker column says why: the status " +
      "transition is ONE write, a records-retention posture puts a trigger on a status column " +
      "and refuses the transition itself, and the erasure then writes the marker in a change " +
      "set of its own. So a row whose mail an erasure has already destroyed can carry the " +
      "marker while its status column still reads active, and a reader that asks the column " +
      "alone answers that the mailbox is in service. The two readers then disagree about one " +
      "account: the account layer refuses the sign in and every listing shows the outstanding " +
      "erasure, while the recipient lookup hands the MX listener a deliverable verdict and the " +
      "sender is told 250 for mail whose owner cannot open it and whose mailbox is part-way " +
      "through being destroyed. Read the two columns together through " +
      "blamepost.store.tables.accountStatus, which is the one derivation of what an account " +
      "row's state is, and build the verdict off what it answers.",
    dirs: ["lib", "bin"],
    // Anchored on two frozen contracts and on no symbol a rename could
    // move. The `account-` reason prefix is wire-visible: the MX listener
    // maps `account-erasing` onto a 550 with the enhanced code 5.1.1, and
    // an operator's audit filter names the same strings. The column is a
    // SQLite column, so renaming it is a migration rather than an edit.
    //
    // The error codes this layer throws under `store/account-<status>`
    // are a different string and are left alone, because the quote has to
    // sit immediately in front of the prefix for the shape to match.
    //
    // The body carrying the reason is the boundary, walked as brackets
    // rather than counted in characters, so every read of the column in
    // the function that builds the verdict is named and a body that grows
    // keeps being read. A body that reads the shared derivation instead
    // stops matching on its own, so nothing here depends on a good token
    // keeping its name.
    //
    // Which reads are named comes out of the source rather than out of a
    // list written here: the reason shape carries the name the row is
    // held under in that body, and only reads of THAT row are reported.
    // A domain row read in the same function carries no marker beside its
    // status and is answered by the column alone, so naming it would be
    // reporting correct code.
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      var REASON = /"account-"\s*\+\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*status\b/g;
      bodies.forEach(function (body) {
        var text = mask.slice(body.start, body.end);
        var held = Object.create(null);
        var found;
        REASON.lastIndex = 0;
        while ((found = REASON.exec(text)) !== null) held[found[1]] = true;
        Object.keys(held).forEach(function (name) {
          var column = new RegExp("\\b" + name + "\\s*\\.\\s*status\\b", "g");
          _matchesIn(mask, bodies, body, column).forEach(function (m) {
            out.push(_atOffset(file, m.offset,
              "an account verdict is built from the status column without the erasure " +
              "marker beside it, so a row carrying the marker alone reads as in service"));
          });
        });
      });
      return out;
    },
    red: [
      // The recipient lookup, deciding deliverability off the column it
      // read and naming the state in the reason it hands the listener.
      "function resolve(recipient) {\n" +
        "  var account = b.db.from(tables.ACCOUNTS).where({ address: recipient }).first();\n" +
        "  var deliverable = account.status === \"active\";\n" +
        "  return { deliverable: deliverable,\n" +
        "    reason: deliverable ? null : \"account-\" + account.status };\n" +
        "}\n",
      // The same shape where an alias is followed to the mailbox behind
      // it, which is the second place a lookup reads an account row.
      "function _expand(rows, targets) {\n" +
        "  var live = target.status === \"active\";\n" +
        "  targets.push({ deliverable: live, reason: live ? null : \"account-\" + target.status });\n" +
        "}\n",
    ],
    green: [
      // The shared derivation, which answers for both columns.
      "function resolve(recipient) {\n" +
        "  var account = b.db.from(tables.ACCOUNTS).where({ address: recipient }).first();\n" +
        "  var status = tables.accountStatus(account);\n" +
        "  var deliverable = status === \"active\";\n" +
        "  return { deliverable: deliverable,\n" +
        "    reason: deliverable ? null : \"account-\" + status };\n" +
        "}\n",
      // The error codes this layer throws are a different namespace, and
      // the verbs that throw them have already read the derivation.
      "function _bounceMailbox(value) {\n" +
        "  var account = accounts.get(value);\n" +
        "  if (account.status !== \"active\") {\n" +
        "    throw err(\"store/account-\" + account.status, \"name a mailbox in service.\");\n" +
        "  }\n" +
        "}\n",
      // A reason naming what was attempted rather than what state a row
      // is in. It carries the same prefix and reads no column.
      "function _refused(action) {\n" +
        "  return { attempted: \"account-\" + action, outcome: \"denied\" };\n" +
        "}\n",
      // A domain row, which carries no marker beside its status and is
      // answered by the column alone.
      "function resolve(recipient) {\n" +
        "  var domainRow = _hostedDomain(recipient.domain);\n" +
        "  if (domainRow.status !== \"active\") return _verdict({ reason: \"domain-disabled\" });\n" +
        "  return _verdict({ deliverable: true });\n" +
        "}\n",
    ],
  },

  {
    name: "set-destroyed-without-a-verdict-per-item",
    description:
      "A loop that destroys a set of things, rows or sealed message bodies, and lets one " +
      "item's refusal leave the turn it was raised on. Neither destruction is a bulk " +
      "operation and neither answers like one: the framework's erase consults the " +
      "preservation-order registry and the dual-control gate for EACH row, and a file " +
      "removal is refused per file by a mount that has gone read-only, a permission an " +
      "operator changed or another process holding it open. So a set is a set of separate " +
      "verdicts and any one of them can be no. A loop that carries none of them stops at " +
      "the first refusal, abandons every item behind it, and takes with it the verdict for " +
      "the items it has already destroyed. On a destruction path that verdict is the whole " +
      "of the record: the data is gone, no audit row was written because the write comes " +
      "after the loop, the caller is handed an exception where it expected a report, and " +
      "nothing anywhere says which items went. The subject whose erasure this was cannot be " +
      "told what happened and neither can a regulator. The `force` flag on a removal is not " +
      "a guard: it covers a file that is already gone and nothing else. Catch the refusal " +
      "around the destruction ITSELF, fold it into what the verb returns marked with " +
      "whether something is deliberately keeping the item or something went wrong with it, " +
      "and carry on through the rest of the set. A guard wrapped around the whole loop is " +
      "not that: it settles the fault and still abandons everything after the item that " +
      "raised it.",
    dirs: ["lib", "bin"],
    // The anchor is the framework primitive's and Node's own names, which
    // are frozen contracts rather than local symbols: a rename of the
    // helper holding the loop cannot hide it, an alias for the filesystem
    // module cannot either, and a deletion of the destruction is exactly
    // the case where there is nothing left to find. The boundary is the
    // loop body, walked as brackets, so a body that grows keeps being
    // read.
    //
    // It reaches one call frame past the loop, over the file's own
    // helpers, because a loop that hands the destruction to a helper
    // abandons its set exactly as one that writes the call inline does.
    // What reaches is decided by whether a refusal LEAVES the helper
    // rather than by its name, so a helper that starts carrying a verdict
    // drops out of the reach on its own.
    scan: function (file) {
      var mask  = _maskOf(file);
      var loops = _loopBodies(mask);
      var out   = [];
      // The destroying verbs and, one frame down, the calls to this
      // file's own helpers that let a removal out. A loop that hands the
      // destruction to a helper is the same abandonment as one that
      // writes it inline, and the call site is where the refusal arrives.
      var reach = _destructionReach(mask);
      var m;
      while ((m = reach.exec(mask)) !== null) {
        var turn = null;
        for (var i = 0; i < loops.length; i += 1) {
          if (m.index < loops[i].start || m.index >= loops[i].end) continue;
          // The innermost loop, which is the one whose turn is abandoned.
          if (turn === null || loops[i].start > turn.start) turn = loops[i];
        }
        if (turn === null) continue;
        if (_caughtBeforeLeaving(mask, m.index, { floor: turn.start })) continue;
        out.push(_atOffset(file, m.index,
          "a set is destroyed one item at a time with no verdict carried per item, so the " +
          "first refusal leaves the loop and takes the record of what already went"));
      }
      return out;
    },
    red: [
      // The bare loop: every row erased, no row answered for.
      "function eraseRows(table, where, reason) {\n" +
        "  var rows = b.db.from(table).where(where).all();\n" +
        "  for (var i = 0; i < rows.length; i += 1) {\n" +
        "    b.db.eraseHard(table, rows[i]._id, { reason: reason });\n" +
        "  }\n" +
        "  return rows.length;\n" +
        "}\n",
      // A guard around the WHOLE loop. The fault is settled and every row
      // behind the one that raised it is still abandoned, unerased and
      // unreported, which is the half a function-wide reading misses.
      "function eraseRows(table, rows, reason, refused) {\n" +
        "  try {\n" +
        "    for (var i = 0; i < rows.length; i += 1) {\n" +
        "      b.db.eraseHard(table, rows[i]._id, { reason: reason });\n" +
        "    }\n" +
        "  } catch (e) {\n" +
        "    refused.push({ table: table, reason: e.code });\n" +
        "  }\n" +
        "}\n",
      // A per-row handler that hands the refusal straight back out. The
      // value still leaves, so the rest of the set is still abandoned.
      "function eraseRows(table, rows, reason) {\n" +
        "  for (var i = 0; i < rows.length; i += 1) {\n" +
        "    try {\n" +
        "      b.db.eraseHard(table, rows[i]._id, { reason: reason });\n" +
        "    } catch (e) {\n" +
        "      throw e;\n" +
        "    }\n" +
        "  }\n" +
        "}\n",
      // The shape the adapters are written in: the verb is built inside a
      // factory, so the loop sits two levels in and the closing brace of
      // the function it belongs to is indented.
      "function create(opts) {\n" +
        "  function sweep(table, rows, reason) {\n" +
        "    for (var i = 0; i < rows.length; i += 1) {\n" +
        "      b.db.eraseHard(table, rows[i]._id, { reason: reason });\n" +
        "    }\n" +
        "  }\n" +
        "  return { sweep: sweep };\n" +
        "}\n",
      // The file half of the same class. `force` reads like a guard and
      // is not one: it covers a file that is already gone, and every
      // other reason a removal fails still leaves here, abandoning every
      // body behind this one and the audit row that is the only record
      // the bodies that went were ever on the volume.
      "async function reclaim(candidates, reason) {\n" +
        "  var freed = [];\n" +
        "  for (var i = 0; i < candidates.length; i += 1) {\n" +
        "    nodeFs.rmSync(candidates[i].path, { force: true });\n" +
        "    freed.push(candidates[i].digest);\n" +
        "  }\n" +
        "  await auditActor.record({ action: \"blobs.reclaimed\", outcome: \"success\" });\n" +
        "  return freed;\n" +
        "}\n",
      // The destruction one call frame down. The loop holds no removal of
      // its own, and the refusal still arrives at the call inside it and
      // abandons every message behind this one.
      "function create(opts) {\n" +
        "  function _releaseBlob(digest) {\n" +
        "    if (b.db.from(MESSAGES).where({ blobDigest: digest }).count() > 0) return;\n" +
        "    nodeFs.rmSync(_blobPath(digest), { force: true });\n" +
        "  }\n" +
        "  function expunge(rows) {\n" +
        "    var gone = [];\n" +
        "    for (var i = 0; i < rows.length; i += 1) {\n" +
        "      _releaseBlob(rows[i].digest);\n" +
        "      gone.push(rows[i].objectid);\n" +
        "    }\n" +
        "    return gone;\n" +
        "  }\n" +
        "  return { expunge: expunge };\n" +
        "}\n",
    ],
    green: [
      // The verdict carried per row, which is what the set needs.
      "function eraseRows(table, rows, reason, refused) {\n" +
        "  var erased = 0;\n" +
        "  for (var i = 0; i < rows.length; i += 1) {\n" +
        "    try {\n" +
        "      b.db.eraseHard(table, rows[i]._id, { reason: reason });\n" +
        "      erased += 1;\n" +
        "    } catch (e) {\n" +
        "      refused.push({ record: rows[i]._id, reason: e.code, preserved: false });\n" +
        "    }\n" +
        "  }\n" +
        "  return erased;\n" +
        "}\n",
      // The handler nested inside a branch of the same turn. It still
      // settles before the turn ends, which is the question being asked.
      "function eraseRows(table, rows, reason, refused) {\n" +
        "  for (var i = 0; i < rows.length; i += 1) {\n" +
        "    if (rows[i].keep !== true) {\n" +
        "      try {\n" +
        "        b.db.eraseHard(table, rows[i]._id, { reason: reason });\n" +
        "      } catch (e) {\n" +
        "        refused.push({ record: rows[i]._id, reason: e.code });\n" +
        "      }\n" +
        "    }\n" +
        "  }\n" +
        "}\n",
      // One row erased on its own is not a set, so there is no per-row
      // verdict for it to carry. What that erase owes its caller is a
      // different question and a different class.
      "function dropAlias(row, reason) {\n" +
        "  return b.db.eraseHard(tables.ALIASES, row._id, { reason: reason });\n" +
        "}\n",
      // A loop over rows that destroys nothing.
      "function describe(rows) {\n" +
        "  var out = [];\n" +
        "  for (var i = 0; i < rows.length; i += 1) out.push(rows[i]._id);\n" +
        "  return out;\n" +
        "}\n",
      // The file half with its verdict carried, which is the same answer
      // the row half gives: this file could not go, here is what the
      // volume said, and the rest of the set still went.
      "async function reclaim(candidates, reason) {\n" +
        "  var freed = [];\n" +
        "  var failed = [];\n" +
        "  for (var i = 0; i < candidates.length; i += 1) {\n" +
        "    try {\n" +
        "      nodeFs.rmSync(candidates[i].path, { force: true });\n" +
        "      freed.push(candidates[i].digest);\n" +
        "    } catch (e) {\n" +
        "      failed.push({ digest: candidates[i].digest, detail: e.message });\n" +
        "    }\n" +
        "  }\n" +
        "  return { freed: freed, failed: failed };\n" +
        "}\n",
      // The same call one frame down, once the helper carries its own
      // verdict. The loop is reading an answer rather than standing in
      // front of a refusal, so there is nothing for it to abandon the set
      // with, and the helper drops out of the reach on its own.
      "function create(opts) {\n" +
        "  function _releaseBlob(digest) {\n" +
        "    if (b.db.from(MESSAGES).where({ blobDigest: digest }).count() > 0) return null;\n" +
        "    try {\n" +
        "      nodeFs.rmSync(_blobPath(digest), { force: true });\n" +
        "    } catch (e) {\n" +
        "      return { detail: (e && e.message) || String(e) };\n" +
        "    }\n" +
        "    return null;\n" +
        "  }\n" +
        "  function expunge(rows) {\n" +
        "    var gone = [];\n" +
        "    var kept = [];\n" +
        "    for (var i = 0; i < rows.length; i += 1) {\n" +
        "      var held = _releaseBlob(rows[i].digest);\n" +
        "      if (held !== null) { kept.push(rows[i].objectid); continue; }\n" +
        "      gone.push(rows[i].objectid);\n" +
        "    }\n" +
        "    return { gone: gone, kept: kept };\n" +
        "  }\n" +
        "  return { expunge: expunge };\n" +
        "}\n",
      // A method reached through a handle is not this file's helper,
      // whatever it is named. Reading the two as one reports a call the
      // file never declared.
      "function create(opts) {\n" +
        "  function release(digest) {\n" +
        "    nodeFs.rmSync(_blobPath(digest), { force: true });\n" +
        "  }\n" +
        "  function drain(queue, jobs) {\n" +
        "    for (var i = 0; i < jobs.length; i += 1) queue.release(jobs[i]);\n" +
        "  }\n" +
        "  return { release: release, drain: drain };\n" +
        "}\n",
    ],
  },

  {
    name: "destruction-past-the-first-without-a-verdict",
    description:
      "A step that destroys something on a path where something has ALREADY been destroyed, " +
      "and whose refusal can leave the function it is in. The loop case is its sibling; " +
      "this is the one that is not a set, and the account erasure is where it lives: the " +
      "mail goes first, the aliases go next, and the account row goes last. By the time " +
      "that last erase runs there is nothing to undo and nothing to read back, so a refusal " +
      "allowed to leave hands the caller an exception in place of the report, skips the " +
      "audit row written after it because that write is never reached, and leaves the " +
      "subject's mail destroyed with nothing anywhere saying so. The operator answering an " +
      "erasure request is told the call failed, and the account is still in service. The " +
      "first destruction on a path is not this: it has destroyed nothing, so its refusal IS " +
      "the whole answer and raising it is right. What changes at the second is that the " +
      "report becomes the only record. Catch the refusal around the destruction itself, " +
      "carry it into what the verb returns marked with whether something is deliberately " +
      "keeping the thing or something went wrong with it, and let the call answer. Every " +
      "write after a destruction owes the same, including the one that records the state " +
      "the subject was left in.",
    dirs: ["lib", "bin"],
    // Anchored on the destroying verbs, which are framework and Node
    // contracts rather than local names, and bounded by the enclosing
    // function walked as brackets. The ordering question is answered on
    // the text in front of the call rather than on a line count, so a
    // function that grows keeps being read.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      var at   = [];
      DESTRUCTION_RE.lastIndex = 0;
      var m;
      // Collected first and walked afterwards, so the yes-or-no reading
      // below cannot move the walk that produced it.
      while ((m = DESTRUCTION_RE.exec(mask)) !== null) at.push(m.index);
      for (var i = 0; i < at.length; i += 1) {
        var span = _enclosingFunctionSpan(mask, at[i]);
        if (!span) continue;
        if (!_somethingAlreadyDestroyed(mask.slice(span.start, at[i]))) continue;
        if (_caughtBeforeLeaving(mask, at[i])) continue;
        out.push(_atOffset(file, at[i],
          "something on this path is already destroyed, and this destruction can still " +
          "raise past the report and the audit row that are the only record of it"));
      }
      return out;
    },
    red: [
      // The account erasure: the mail is swept, the aliases are answered
      // for per row, and the identity erase raises past both.
      "async function remove(opts) {\n" +
        "  var row = _requireRow(opts.id);\n" +
        "  var swept = await mail().eraseAccountMail(actor, row._id, { reason: opts.reason });\n" +
        "  for (var i = 0; i < aliasRows.length; i += 1) {\n" +
        "    try {\n" +
        "      b.db.eraseHard(tables.ALIASES, aliasRows[i]._id, { reason: opts.reason });\n" +
        "    } catch (e) {\n" +
        "      refused.push({ address: aliasRows[i].address, reason: e.code });\n" +
        "    }\n" +
        "  }\n" +
        "  var result = b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: opts.reason });\n" +
        "  await auditActor.record({ action: \"account.destroyed\", outcome: \"success\" });\n" +
        "  return { rowsErased: result.rowsDeleted, mailErased: swept.destroyed.length };\n" +
        "}\n",
      // Two destructions of files, the second uncaught. The first has
      // already run by the time it raises.
      "function purge(paths, reason) {\n" +
        "  nodeFs.unlinkSync(paths.body);\n" +
        "  nodeFs.rmSync(paths.descriptor, { force: true });\n" +
        "  return { removed: 2 };\n" +
        "}\n",
      // The shape the store modules are written in: the verb is built
      // inside a factory, so its closing brace is indented.
      "function create(ctx) {\n" +
        "  async function remove(row, reason) {\n" +
        "    await ctx.mail().eraseAccountMail(actor, row._id, { reason: reason });\n" +
        "    return b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: reason });\n" +
        "  }\n" +
        "  return { remove: remove };\n" +
        "}\n",
    ],
    green: [
      // The verdict carried, which is what makes the call able to answer.
      "async function remove(opts) {\n" +
        "  var row = _requireRow(opts.id);\n" +
        "  var swept = await mail().eraseAccountMail(actor, row._id, { reason: opts.reason });\n" +
        "  var refused = [];\n" +
        "  var result = { rowsDeleted: 0 };\n" +
        "  try {\n" +
        "    result = b.db.eraseHard(tables.ACCOUNTS, row._id, { reason: opts.reason });\n" +
        "  } catch (e) {\n" +
        "    refused.push({ record: \"the account row\", reason: e.code });\n" +
        "  }\n" +
        "  await auditActor.record({ action: \"account.destroyed\", outcome: \"success\" });\n" +
        "  return { rowsErased: result.rowsDeleted, refused: refused };\n" +
        "}\n",
      // The first destruction on a path, which has destroyed nothing yet.
      // Its refusal is the whole answer and belongs to its caller.
      "function dropAlias(row, reason) {\n" +
        "  return b.db.eraseHard(tables.ALIASES, row._id, { reason: reason });\n" +
        "}\n",
      // Two erases in two separate verbs. Neither is standing on the
      // other's destruction, so neither owes the other's report.
      "function create(ctx) {\n" +
        "  function dropAlias(row, reason) {\n" +
        "    return b.db.eraseHard(tables.ALIASES, row._id, { reason: reason });\n" +
        "  }\n" +
        "  function dropSelector(row, reason) {\n" +
        "    return b.db.eraseHard(tables.SELECTORS, row._id, { reason: reason });\n" +
        "  }\n" +
        "  return { dropAlias: dropAlias, dropSelector: dropSelector };\n" +
        "}\n",
      // Reporting what a destruction answered is not performing one.
      "function lines(result) {\n" +
        "  return [result.rowsErased + \" row\", result.mailErased + \" message\"];\n" +
        "}\n",
    ],
  },

  {
    name: "selector-row-deleted-out-from-under-its-key",
    description:
      "A DKIM selector row deleted in a body that never erases the sealed private key the " +
      "row named, or erases it only after the row is already gone. The selector row is the " +
      "ONLY handle on that file. Nothing walks the keys folder: the blob reconciliation reads " +
      "the message blob directory and no other, and the one code path that erases a key finds " +
      "its subject through a selector row's keyRef column. So a deletion that takes the row " +
      "and leaves the file leaves a signing key for the domain on the volume permanently, in " +
      "every backup bundle taken afterwards, with no verb able to name it and no report able " +
      "to count it. Whoever holds that key signs mail as the domain, which is the whole of " +
      "what DKIM asserts, and it stays true if the domain is later re-hosted by somebody " +
      "else. Erase the key file through the DKIM module's own eraser in the same call, so " +
      "one place knows where a keyRef resolves to. Order is half of it: erase the file " +
      "first and delete the row second, so a file that could not be erased still has the " +
      "row that names it and the operator can run the verb again.",
    dirs: ["lib", "bin"],
    // The enclosing bodies count here, and they have to. The selector
    // rows for a whole domain are deleted inside a transaction callback,
    // because the rows and the domain row have to go together or not at
    // all, and a filesystem erase cannot be written inside a database
    // transaction. So the erase belongs above the callback, in the body
    // that holds it, which is still the same path.
    scan: function (file) {
      return _rowAheadOfItsMaterial(file, {
        row:       SELECTOR_ROW_DELETE_RE,
        material:  SELECTOR_KEY_ERASE_RE,
        enclosing: true,
        missing:
          "a DKIM selector row is deleted in a body that never erases the sealed private " +
          "key it named, so the key stays on the volume with nothing left that can find it",
        late:
          "a DKIM selector row is deleted before the sealed private key it named is " +
          "erased, so an erase that does not complete leaves the key with no row to name it",
      });
    },
    red: [
      // The bulk form: every selector a domain published, dropped in one
      // statement, with the key files never mentioned.
      "async function remove(opts) {\n" +
        "  b.db.from(tables.SELECTORS).where({ domain: name }).deleteMany();\n" +
        "  tables.deleteRow(tables.DOMAINS, row._id);\n" +
        "}\n",
      // The single-row form, which reads the row and so has the keyRef
      // in its hand while it drops it.
      "async function removeSelector(opts) {\n" +
        "  var row = _requireSelector(opts, \"removeSelector\");\n" +
        "  tables.deleteRow(tables.SELECTORS, row._id);\n" +
        "  return { domain: row.domain, outcome: \"removed\" };\n" +
        "}\n",
      // Both halves on one path and the row first, written the way the
      // real verb is: the deletion inside a transaction callback, the
      // erase after it. The body's closing brace is indented, so a
      // boundary that assumed column zero would walk straight past it.
      "function create(ctx) {\n" +
        "  async function remove(opts) {\n" +
        "    b.db.transaction(function () {\n" +
        "      b.db.from(tables.SELECTORS).where({ domain: name }).deleteMany();\n" +
        "    });\n" +
        "    await dkim.eraseKeyFiles(ctx.dataDir, refs);\n" +
        "  }\n" +
        "  return { remove: remove };\n" +
        "}\n",
      // The erase written in a sibling, so nothing calls it on the path
      // that deletes the row.
      "function create(ctx) {\n" +
        "  async function sweepKeys(refs) { return dkim.eraseKeyFiles(ctx.dataDir, refs); }\n" +
        "  async function removeSelector(opts) {\n" +
        "    tables.deleteRow(tables.SELECTORS, row._id);\n" +
        "  }\n" +
        "  return { removeSelector: removeSelector, sweepKeys: sweepKeys };\n" +
        "}\n",
    ],
    green: [
      // The key first, the row second, in one body.
      "async function removeSelector(opts) {\n" +
        "  var row = _requireSelector(opts, \"removeSelector\");\n" +
        "  await dkim.eraseKeyFiles(dataDir, [row.keyRef]);\n" +
        "  tables.deleteRow(tables.SELECTORS, row._id);\n" +
        "}\n",
      // The shape the bulk removal actually takes: the erase above the
      // transaction, the rows inside it.
      "function create(ctx) {\n" +
        "  async function remove(opts) {\n" +
        "    await dkim.eraseKeyFiles(ctx.dataDir, refs);\n" +
        "    b.db.transaction(function () {\n" +
        "      b.db.from(tables.SELECTORS).where({ domain: name }).deleteMany();\n" +
        "      tables.deleteRow(tables.DOMAINS, row._id);\n" +
        "    });\n" +
        "  }\n" +
        "  return { remove: remove };\n" +
        "}\n",
      // Reading the selector rows is not deleting any of them.
      "function listSelectors(opts) {\n" +
        "  return b.db.from(tables.SELECTORS).orderBy(\"domain\", \"asc\").all().map(_present);\n" +
        "}\n",
      // Moving a selector out of signing keeps the row, and the key with
      // it, which is the whole point of the overlap.
      "function retireSelector(row, retiresAt) {\n" +
        "  tables.updateRow(tables.SELECTORS, row._id, { status: \"retiring\", retiresAt: retiresAt });\n" +
        "}\n",
      // A delete aimed at another table names no key file, so it is not
      // this pattern however close the shape looks.
      "function dropDomain(row) {\n" +
        "  return tables.deleteRow(tables.DOMAINS, row._id);\n" +
        "}\n",
    ],
  },

  {
    name: "selector-key-erasure-without-the-row-decision",
    description:
      "A sealed DKIM private key erased on one side of a suspension while the selector rows " +
      "naming it are settled on the other. Erasing a key is the only suspension either " +
      "destructive selector verb has, so every reading taken before it describes the volume " +
      "as it stood rather than as it stands, and both ways that goes wrong destroy signing " +
      "material an operator cannot get back. A refusal raised AFTER the erasure leaves the " +
      "rows published and the keys gone: the domain signs nothing, every message it sends " +
      "fails DMARC alignment, and running the verb again reaches the same refusal for as " +
      "long as whatever changed stays changed, while minting a replacement is refused for " +
      "the rows that are still there. And a refusal that is about the SET rather than about " +
      "one row cannot be re-taken by re-reading that row: a domain's last active selector is " +
      "a statement about every selector it signs with, and the one row being withdrawn is " +
      "unchanged in each of two concurrent withdrawals, so both read two active selectors and " +
      "both proceed. Hand the eraser the decision instead. It moves the material aside, runs " +
      "the decision with nothing able to interleave, and destroys or restores by its answer, " +
      "so every refusal is decided against the volume as it stands and sits beside the row " +
      "deletion it authorizes. A body that erases key material and deletes no selector row is " +
      "not this shape: retirement erases the private halves deliberately and leaves the rows " +
      "published through their overlap, because nothing signs with a retiring selector.",
    dirs: ["lib", "bin"],
    // The enclosing bodies count, for the reason the sibling detector
    // above gives: the rows are deleted inside a transaction callback,
    // which is a body of its own, and the erasure that has to carry the
    // decision sits in the body holding it.
    //
    // Both halves are anchored on frozen contracts. `eraseKeyFiles` is
    // the exported verb of the module that owns the keys folder, so
    // renaming it is a change to a published surface rather than an
    // edit, and the row spellings are the framework's bulk delete and
    // this layer's only single-row write path against a table name every
    // reader resolves from the schema declaration. Whether the decision
    // is there is read off the call's own argument list, walked by
    // bracket depth to the parenthesis that closes it, so a decision
    // written across ten lines counts exactly as one written across one.
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out  = [];
      var seen = {};
      for (var i = 0; i < bodies.length; i += 1) {
        if (_matchesIn(mask, bodies, bodies[i], SELECTOR_ROW_DELETE_RE).length === 0) continue;
        var around = _bodiesAround(bodies, bodies[i].start);
        for (var a = 0; a < around.length; a += 1) {
          var erasures = _matchesIn(mask, bodies, around[a], SELECTOR_KEY_ERASE_RE);
          for (var e = 0; e < erasures.length; e += 1) {
            var offset = erasures[e].offset;
            if (seen[offset] === 1) continue;
            var open = mask.indexOf("(", offset);
            if (open === -1) continue;
            var args = _callArguments(mask, open);
            if (args !== null && args.length > 2 && args.slice(2).some(function (arg) {
              return SETTLING_DECISION_RE.test(arg);
            })) continue;
            seen[offset] = 1;
            out.push(_atOffset(file, offset,
              "sealed DKIM private keys are erased here and the selector rows naming them are " +
              "settled somewhere else, so every refusal on the far side of the erasure leaves " +
              "a published record for a key that is gone; hand the eraser the decision that " +
              "deletes the rows"));
          }
        }
      }
      return out;
    },
    red: [
      // The bulk form: the keys for a whole domain erased, then the rows
      // decided in a transaction the erasure knows nothing about. The
      // verb is built inside a factory, so its closing brace is indented
      // and the deletion sits two levels further in again.
      "function create(ctx) {\n" +
        "  async function remove(opts) {\n" +
        "    var swept = await dkim.eraseKeyFiles(ctx.dataDir, refs);\n" +
        "    if (swept.stranded.length > 0) throw err(\"store/domain-keys-stranded\", name);\n" +
        "    b.db.transaction(function () {\n" +
        "      _refuseWhileInUse(name);\n" +
        "      b.db.from(tables.SELECTORS).where({ domain: name }).deleteMany();\n" +
        "    });\n" +
        "  }\n" +
        "  return { remove: remove };\n" +
        "}\n",
      // The single-row form, with the re-read that answers about the row
      // and not about the set the refusal was made on.
      "async function removeSelector(opts) {\n" +
        "  var row = _requireSelector(opts, \"removeSelector\");\n" +
        "  await dkim.eraseKeyFiles(dataDir, [row.keyRef]);\n" +
        "  b.db.transaction(function () {\n" +
        "    var current = b.db.from(tables.SELECTORS).where({ _id: row._id }).first();\n" +
        "    if (current.status !== row.status) return false;\n" +
        "    tables.deleteRow(tables.SELECTORS, row._id);\n" +
        "  });\n" +
        "}\n",
      // The eraser reached through a differently named handle, which is
      // the spelling a matcher bound to the receiver goes quiet on. The
      // verb is the contract; whatever it is reached through is not.
      "async function withdraw(opts) {\n" +
        "  await keyStore.eraseKeyFiles(dataDir, [row.keyRef]);\n" +
        "  tables.deleteRow(tables.SELECTORS, row._id);\n" +
        "}\n",
    ],
    green: [
      // The settled shape: the decision travels with the erasure, so the
      // refusals and the deletion they authorize are one run.
      "async function removeSelector(opts) {\n" +
        "  var row = _requireSelector(opts, \"removeSelector\");\n" +
        "  var swept = await dkim.eraseKeyFiles(dataDir, [row.keyRef], function () {\n" +
        "    var active = _activeKeyOf(row.domain);\n" +
        "    if (active.length <= 1) return { refusal: \"store/last-selector\" };\n" +
        "    tables.deleteRow(tables.SELECTORS, row._id);\n" +
        "    return null;\n" +
        "  });\n" +
        "  if (!swept.committed) throw err(swept.verdict.refusal, row.domain);\n" +
        "}\n",
      // The same thing written with an arrow, which is a decision by the
      // same test.
      "async function remove(opts) {\n" +
        "  var swept = await dkim.eraseKeyFiles(dataDir, refs, () => {\n" +
        "    b.db.from(tables.SELECTORS).where({ domain: name }).deleteMany();\n" +
        "    return true;\n" +
        "  });\n" +
        "  return swept.erased.length;\n" +
        "}\n",
      // Retirement: the private halves go and the rows stay published
      // through their overlap on purpose, because nothing signs with a
      // retiring selector. No selector row is deleted here at all.
      "async function retire(domain, matches) {\n" +
        "  for (var j = 0; j < matches.length; j += 1) {\n" +
        "    await store.domains.retireSelector({ domain: domain, selector: matches[j].selector });\n" +
        "  }\n" +
        "  await eraseKeyFiles(opts.dataDir, matches.map(function (m) { return m.keyRef; }));\n" +
        "}\n",
      // The eraser's own body, which unlinks files and settles no rows.
      "async function eraseKeyFiles(dataDir, keyRefs, decide) {\n" +
        "  var targets = keyRefs.map(function (ref) { return _keyPathOf(dataDir, ref); });\n" +
        "  await nodeFs.promises.rm(targets[0]);\n" +
        "  return { erased: targets };\n" +
        "}\n",
    ],
  },

  {
    name: "set-membership-decision-acted-on-across-a-suspension",
    description:
      "A console act whose correctness is a statement about a SET, carried out on the strength " +
      "of a reading of that set taken before the body suspended. Three of these decide who is " +
      "left able to reach the operator interface — taking the role away, suspending or " +
      "archiving the account that holds it, and withdrawing the domain its address belongs to " +
      "— and one erases a message off the outbound spool and then tells its sender so. What " +
      "makes the set different from the row is that re-reading the row answers a different " +
      "question: the account being demoted is unchanged in each of two concurrent demotions, " +
      "so both read two administrators, both conclude they are not taking the last, and the " +
      "server they leave has no console. Nothing in the browser grants the role back once " +
      "nobody can reach the browser, and the command line verbs that would open the data " +
      "volume the running server is holding, so the way back begins with stopping every " +
      "listener. The spool case is not irreversible and is worse in a different direction: a " +
      "message that leaves while the cancellation is working through the selection gets a row " +
      "saying it was erased and its sender gets a report saying an operator stopped mail that " +
      "in fact arrived, sent to a reverse path that on forwarded mail is a value whoever sent " +
      "the message chose. Ask the question at the instant of the act instead: take the reading " +
      "with nothing suspending between it and the write, and where the act is per-item inside " +
      "a loop, take it inside the turn that acts rather than once for the whole selection. A " +
      "reading taken earlier is worth keeping as a courtesy, so an operator is not asked to " +
      "confirm a change that was going to be refused anyway, but it is not the authority.",
    // The long-running server's own surfaces, where two callers are in
    // flight at once by construction: the console serves whatever
    // arrives, and the spool is swept on a schedule of its own. The
    // command line is read for the same reason and reaches the shape
    // through a window of its own: the data volume opening between the
    // reading and the act, which is the longest suspension any verb
    // there has.
    dirs: ["lib", "bin"],
    // The acts are published primitives, matched by their own namespace
    // and verb rather than by the handle they are reached through, so a
    // caller that renames its local still reads as making the act. The
    // readings are the same. The one symbol that cannot be frozen is the
    // guard the console calls instead of reading the set inline, so its
    // name is read out of the audit action it emits, which is the frozen
    // contract an auditor filters on.
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var loops  = _loopBodies(mask);
      var readRe = _consoleSetReadRe(file, mask);
      var out = [];
      for (var i = 0; i < bodies.length; i += 1) {
        var acts = _matchesIn(mask, bodies, bodies[i], CONSOLE_SET_ACT_RE);
        if (acts.length === 0) continue;
        var reads = _matchesIn(mask, bodies, bodies[i], readRe);
        if (reads.length === 0) continue;
        var awaits = _matchesIn(mask, bodies, bodies[i], SUSPENSION_POINT_RE);
        for (var a = 0; a < acts.length; a += 1) {
          if (_staleConsoleDecision(mask, bodies[i], loops, reads, awaits, acts[a].offset) === null) {
            continue;
          }
          out.push(_atOffset(file, acts[a].offset,
            "this act is decided by a reading of the set taken before the body suspended and " +
            "not taken again after it, so another caller has had the whole suspension to " +
            "change what the decision was made on"));
        }
      }
      return out;
    },
    red: [
      // The demotion: the set is measured, the row is resolved across a
      // suspension, and the role is taken on the strength of the earlier
      // measurement.
      "function mount(router) {\n" +
        "  router.post(\"/admin/accounts\", async function (req, res) {\n" +
        "    var standing = await _strandingRefusal({ excludeId: id });\n" +
        "    if (standing !== null) { await _render(req, res, standing); return; }\n" +
        "    var subject = await store.accounts.get(id);\n" +
        "    await store.accounts.setAdmin({ id: subject.id, isAdmin: false, reason: why });\n" +
        "  });\n" +
        "}\n" +
        "function _strandingRefusal(opts) {\n" +
        "  b.audit.safeEmit({\n" +
        "    action: \"blamepost.web.last_administrator_removal_not_permitted\",\n" +
        "    outcome: \"denied\",\n" +
        "  });\n" +
        "  return null;\n" +
        "}\n",
      // The withdrawal, measured through the set readings themselves
      // rather than through a guard, so the file carries no action name
      // to read a guard's name out of.
      "async function disableDomain(req, res, name) {\n" +
        "  var live = await store.accounts.list({ status: \"active\" });\n" +
        "  if (live.length === 0) return;\n" +
        "  var counted = await _accountCounts();\n" +
        "  await store.domains.setStatus({ domain: name, status: \"disabled\", reason: counted });\n" +
        "}\n",
      // The per-item form, and the one a straight-line reading misses:
      // the selection is read once, and the suspension standing between
      // the reading and the act is the report written on the turn before.
      "async function cancelSelection(ids, reason) {\n" +
        "  var waiting = await delivery.queue.list();\n" +
        "  for (var i = 0; i < waiting.length; i += 1) {\n" +
        "    await delivery.queue.remove(waiting[i].id, { reason: reason });\n" +
        "    await delivery.bounce({ to: waiting[i].from, reason: reason });\n" +
        "  }\n" +
        "}\n",
    ],
    green: [
      // The settled shape: the courtesy reading stays where a refusal
      // still costs nothing, and the reading the act is decided on sits
      // beside the act with nothing suspending in between.
      "function mount(router) {\n" +
        "  router.post(\"/admin/accounts\", async function (req, res) {\n" +
        "    var early = _strandingRefusal({ excludeId: id });\n" +
        "    if (early !== null) { await _render(req, res, early); return; }\n" +
        "    var subject = await store.accounts.get(id);\n" +
        "    if (_stillAsking(req, res, body, ask)) return;\n" +
        "    var standing = _strandingRefusal({ excludeId: subject.id });\n" +
        "    if (standing !== null) { await _render(req, res, standing); return; }\n" +
        "    await store.accounts.setAdmin({ id: subject.id, isAdmin: false, reason: why });\n" +
        "  });\n" +
        "}\n" +
        "function _strandingRefusal(opts) {\n" +
        "  b.audit.safeEmit({\n" +
        "    action: \"blamepost.web.last_administrator_removal_not_permitted\",\n" +
        "    outcome: \"denied\",\n" +
        "  });\n" +
        "  return null;\n" +
        "}\n",
      // The per-item form with the reading taken inside the turn that
      // acts, so the report written on the turn before stands between
      // two readings rather than between one reading and every act.
      "async function cancelSelection(ids, reason) {\n" +
        "  var waiting = await delivery.queue.list();\n" +
        "  for (var i = 0; i < waiting.length; i += 1) {\n" +
        "    var current = await delivery.queue.show(waiting[i].id);\n" +
        "    if (current === null) { missed += 1; continue; }\n" +
        "    await delivery.queue.remove(waiting[i].id, { reason: reason });\n" +
        "    await delivery.bounce({ to: waiting[i].from, reason: reason });\n" +
        "  }\n" +
        "}\n",
      // A body that acts without having read the set at all is deciding
      // nothing about it, so there is no reading for a suspension to
      // stand after. The command line resolves one name and moves it.
      "async function suspendAccount(address, reason) {\n" +
        "  var row = await store.accounts.get(address);\n" +
        "  await store.accounts.suspend({ id: row.id, reason: reason });\n" +
        "}\n",
      // The reading and the act in one run. Nothing suspends between
      // them, so the volume the decision is about is the volume the act
      // lands on.
      "async function withdraw(name, reason) {\n" +
        "  var counted = await _accountCounts();\n" +
        "  var live = store.accounts.list({ status: \"active\" });\n" +
        "  if (live.length === 0) return counted;\n" +
        "  return store.domains.setStatus({ domain: name, status: \"disabled\", reason: reason });\n" +
        "}\n",
    ],
  },

  {
    name: "material-written-to-the-volume-and-not-taken-back-across-a-suspension",
    description:
      "A body that writes material onto the data volume and then keeps going, with nothing " +
      "that takes the write back when the work after it does not complete. This is the " +
      "create-path form of the fault the deletion detectors above read: material and the " +
      "record naming it are separate writes, nothing spans them, and whichever one is left " +
      "alone is left with nothing able to find it. Material without its record is the worse " +
      "half, because every listing this server offers enumerates records, so the material is " +
      "in no listing, carries no identifier an operator can read and is reached by no verb, " +
      "while the ceilings deciding whether the volume can take more are measured off the " +
      "volume and weigh it. Enough of it and the server refuses new work over room that " +
      "nothing on screen accounts for. What makes a body the shape rather than an ordinary " +
      "write is the suspension after it: that is the point where something else can fail and " +
      "unwind past this frame, leaving what was already on disk. A single write that ends its " +
      "body is not this, because nothing follows it that can throw. Write the material first, " +
      "so the half-written state is something nobody has to act on yet, and remove it when the " +
      "work after it throws. A process that dies mid-way runs no cleanup at all, so the write " +
      "also owes a reconciliation that walks the directory and holds the material against the " +
      "records, which is where the operator learns the identifier to clear.",
    dirs: ["lib", "bin"],
    // Both halves are frozen contracts rather than local symbols. The
    // write is the one framework surface every volume write in this
    // repository goes through, and the removals are Node's own verbs, so
    // renaming a path builder or the helper around either one leaves
    // this reading the same shape.
    //
    // Order is read off the offsets this walk already found, never off
    // the distance between them, so a body that grows or is reindented
    // moves every offset together and changes nothing. A removal only
    // counts when it stands after the write: one written before it runs
    // on the way in rather than on the way out.
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out = [];
      for (var i = 0; i < bodies.length; i += 1) {
        var writes = _matchesIn(mask, bodies, bodies[i], VOLUME_FILE_WRITE_RE);
        if (writes.length === 0) continue;
        writes.sort(function (left, right) { return left.offset - right.offset; });
        var first = writes[0].offset;

        var suspends = _matchesIn(mask, bodies, bodies[i], SUSPENSION_POINT_RE);
        var keepsGoing = false;
        for (var s = 0; s < suspends.length; s += 1) {
          if (suspends[s].offset > first) { keepsGoing = true; break; }
        }
        if (!keepsGoing) continue;

        var removals = _matchesIn(mask, bodies, bodies[i], VOLUME_FILE_REMOVE_RE);
        var takenBack = false;
        for (var r = 0; r < removals.length; r += 1) {
          if (removals[r].offset > first) { takenBack = true; break; }
        }
        if (takenBack) continue;

        out.push(_atOffset(file, first,
          "material is written onto the volume and the body keeps going, with nothing that " +
          "removes it when the work after the write does not complete"));
      }
      return out;
    },
    red: [
      // The shape the spool had: the message, then the descriptor, and
      // nothing between them or after them.
      "async function spool(entry, rfc822) {\n" +
        "  var id = mintId();\n" +
        "  await b.atomicFile.write(bodyPath(id), rfc822, { fileMode: 0o600 });\n" +
        "  await writeDescriptor({ id: id, recipient: entry.recipient });\n" +
        "  return id;\n" +
        "}\n",
      // Guarded, and the guard does not take the material back, which is
      // what a bare try/catch produces.
      "async function spool(entry, rfc822) {\n" +
        "  await b.atomicFile.write(bodyPath(id), rfc822, { fileMode: 0o600 });\n" +
        "  try {\n" +
        "    await writeDescriptor(entry);\n" +
        "  } catch (e) {\n" +
        "    log.error(\"could not write the descriptor: \" + e.message);\n" +
        "    throw e;\n" +
        "  }\n" +
        "}\n",
      // The removal is there and it runs on the way IN, before the
      // write, so nothing undoes the material that landed.
      "async function spool(entry, rfc822) {\n" +
        "  await nodeFs.promises.rm(claimPath(id), { force: true });\n" +
        "  await b.atomicFile.write(bodyPath(id), rfc822, { fileMode: 0o600 });\n" +
        "  await writeDescriptor(entry);\n" +
        "}\n",
      // The record is a database row rather than a second file, and the
      // material is stranded the same way when the row does not land.
      "async function store(digest, octets) {\n" +
        "  await b.atomicFile.write(blobPath(digest), vault.seal(octets), { fileMode: 0o600 });\n" +
        "  await appendMessageRow({ digest: digest });\n" +
        "}\n",
    ],
    green: [
      // The material taken back when the work after it throws.
      "async function spool(entry, rfc822) {\n" +
        "  await b.atomicFile.write(bodyPath(id), rfc822, { fileMode: 0o600 });\n" +
        "  try {\n" +
        "    await writeDescriptor(entry);\n" +
        "  } catch (e) {\n" +
        "    try { await nodeFs.promises.rm(bodyPath(id), { force: true }); }\n" +
        "    catch (_rmErr) { log.error(\"stranded: \" + id); }\n" +
        "    throw e;\n" +
        "  }\n" +
        "}\n",
      // The write ends the body, so nothing follows it that can throw.
      "async function writeKey(keyRef, privateKeyPem) {\n" +
        "  await b.atomicFile.write(keyPath(keyRef), vault.seal(privateKeyPem), { fileMode: 0o600 });\n" +
        "}\n",
      // Handing the write back to the caller is the same: this frame has
      // nothing left to do after it.
      "function writeDescriptor(entry) {\n" +
        "  return b.atomicFile.writeJson(descriptorPath(entry.id), entry, { fileMode: 0o600 });\n" +
        "}\n",
      // Removing both halves of a pair writes nothing at all.
      "async function dropSpooled(id) {\n" +
        "  await nodeFs.promises.rm(bodyPath(id), { force: true });\n" +
        "  await nodeFs.promises.rm(descriptorPath(id), { force: true });\n" +
        "}\n",
      // Reading both halves is not writing either of them.
      "async function readEntry(id) {\n" +
        "  var body = await b.atomicFile.read(bodyPath(id));\n" +
        "  var entry = await b.atomicFile.readJson(descriptorPath(id));\n" +
        "  return { body: body, entry: entry };\n" +
        "}\n",
    ],
  },

  {
    name: "outbound-room-measured-rather-than-taken",
    description:
      "The outbound queue asked whether it has room, by a caller that then goes on to use " +
      "that answer. The answer describes one directory at one instant, and the directory is " +
      "shared by every connection this server is serving and by the retry sweep, so it is " +
      "spent the moment anybody else asks. Nothing at all stands between the question and " +
      "the write in the same turn, and everything stands between them in practice: a copy " +
      "filed into every mailbox the envelope names here, an MX lookup, a policy chain and a " +
      "whole SMTP conversation with a receiver that answers at its own pace. Two senders " +
      "crossing the last slot together both read room, both proceed, and the one that loses " +
      "is refused at its own write with mailboxes on this server already holding the " +
      "message. SMTP gives the whole message one reply, so that refusal is the sender being " +
      "told to send everything again, and everyone who already received it receives it " +
      "twice. The queue is also past its ceiling, which is the bound that was supposed to " +
      "keep the volume the mailboxes live on from filling. Take the room instead of " +
      "measuring it: the reserving verb answers the same question and HOLDS what it admits " +
      "until the caller gives it back, so the answer cannot be spent by somebody else and " +
      "the refusal lands where refusing is still free — before the first copy is written. " +
      "Hold it across everything the message does and release it once, on every path out. " +
      "Publishing the reading is not using it: what this reads is the act of asking.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      var offsets = _spoolAdmissionCalls(mask);
      var out = [];
      for (var i = 0; i < offsets.length; i += 1) {
        out.push(_atOffset(file, offsets[i],
          "the outbound queue is asked whether it has room and the answer is acted on, but " +
          "nothing holds the room it described, so another connection takes it before the " +
          "write this authorized"));
      }
      return out;
    },
    red: [
      // The consumer side, reached through the published handle.
      "function _refuseIfQueueIsFull(leaving, body, origin) {\n" +
        "  var refusal = delivery.queue.admits({ entries: leaving, bytes: leaving * size });\n" +
        "  if (refusal === null) return;\n" +
        "  throw refusal;\n" +
        "}\n",
      // The owning module, which calls its admitter by its local name.
      // The name is read out of the binding that publishes it, so this
      // is found without the matcher being told what it is called.
      "function create(opts) {\n" +
        "  function _admitToSpool(request) { return null; }\n" +
        "  async function send(envelope) {\n" +
        "    var refusal = _admitToSpool({ entries: 1, bytes: wire.length });\n" +
        "    if (refusal !== null) throw refusal;\n" +
        "    await deliver(envelope);\n" +
        "    await _spool(envelope, wire);\n" +
        "  }\n" +
        "  return { send: send, queue: { admits: _admitToSpool } };\n" +
        "}\n",
      // The same thing with the admitter renamed, which is the spelling a
      // matcher bound to today's name goes quiet on.
      "function create(opts) {\n" +
        "  function roomFor(request) { return null; }\n" +
        "  async function send(envelope) {\n" +
        "    if (roomFor({ entries: 1, bytes: 1 }) !== null) throw new Error(\"full\");\n" +
        "    await deliver(envelope);\n" +
        "  }\n" +
        "  return { queue: { admits: roomFor } };\n" +
        "}\n",
    ],
    green: [
      // The settled shape: the room is taken rather than measured, and
      // given back on every path out.
      "async function relay(leaving, body, origin) {\n" +
        "  var held = delivery.queue.reserve({ entries: leaving, bytes: leaving * size });\n" +
        "  if (held.taken !== true) throw held.refusal;\n" +
        "  try {\n" +
        "    await deliver({ to: leaving, hold: held });\n" +
        "  } finally {\n" +
        "    held.release();\n" +
        "  }\n" +
        "}\n",
      // Publishing the reading is not using it. The arithmetic lives in
      // one place and both verbs go through it, so the reading and the
      // hold cannot answer differently.
      "function create(opts) {\n" +
        "  function _admitToSpool(request) { return _spoolVerdict(request, false); }\n" +
        "  function _holdSpool(request) { return _spoolVerdict(request, true); }\n" +
        "  return { queue: { admits: _admitToSpool, reserve: _holdSpool } };\n" +
        "}\n",
      // Reporting how full the queue is asks nothing about admission.
      "function describe() {\n" +
        "  return { spool: queueCapacity(), waiting: queueCount() };\n" +
        "}\n",
    ],
  },

  {
    name: "audit-action-under-an-unregistered-namespace",
    description:
      "An audit action whose first segment is a namespace nothing registers. The framework " +
      "refuses an action name under an unknown namespace, and the emitter that the hot paths " +
      "use drops what it cannot file, by design, because throwing there would kill the " +
      "delivery that produced the event. The two together are silent: the refusal happens, " +
      "the row is discarded, and the call returns the same value it returns on success. Every " +
      "path that refuses something is exactly the path whose record an operator goes looking " +
      "for afterwards. Register the namespace at boot, before the first event, or file the " +
      "event under one that is already registered. An action name a reader cannot resolve to " +
      "a literal is the same problem one step further away, so it is reported too.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var registry = _registeredNamespaces();
      if (!registry.frameworkListRead) {
        return [{
          file:    file.rel,
          line:    1,
          content: "the framework namespace list could not be read from " + VENDOR_AUDIT_MODULE +
                   ", so no action name in this file can be checked",
        }];
      }
      return _auditEventFindings(file, function (event) {
        var key = /\baction\s*:/.exec(event.arg);
        if (!key) return null;
        var names = _quotedIn(_valueAfter(event.arg, key.index + key[0].length));
        if (names.length === 0) {
          return "audit action name is not a literal, so the namespace behind it cannot " +
            "be checked";
        }
        return names.map(function (name) {
          var ns = name.split(".")[0];
          return registry.known[ns] === 1
            ? null
            : "audit namespace '" + ns + "' is registered nowhere";
        });
      });
    },
    red: [
      "b.audit.safeEmit({ action: \"mailserver.delivery.failed\", outcome: \"failure\" });\n",
      "await b.audit.record({ action: actionName, outcome: \"success\" });\n",
    ],
    green: [
      "b.audit.safeEmit({ action: \"blamepost.mail.delivery.report_unsent\", outcome: \"failure\" });\n",
      "await b.audit.record({\n" +
        "  action:  wide ? \"alias.catch_all_added\" : \"alias.added\",\n" +
        "  outcome: \"success\",\n});\n",
      "b.audit.safeEmit({ action: \"auth.login\", outcome: \"success\" });\n",
    ],
  },

  {
    name: "chain-origin-read-without-verifying-its-signature",
    description:
      "A function that reads the framework table recording where an audit chain was cut, and " +
      "hands the answer on without asking the framework whether the row's signature holds. " +
      "That row is the one statement in a trail that says rows are ALLOWED to be missing: it " +
      "discards every audit row at or below the counter it names from the walk, so it is the " +
      "one row somebody erasing a trail has to write. It carries a signature over that " +
      "counter, over the hash the row at it held and over the archive it names, and the key " +
      "that signature is made with is sealed under the same passphrase as the database. A " +
      "reader that skips the check is wrong in one of two directions and an operator acts on " +
      "both: it reads a boundary somebody wrote as a retention run, or it reports a boundary " +
      "this server signed as a row worth nothing. Call `verifyPurgeAnchor` inside the " +
      "function that reads the row, and let the caller decide from the status it returns " +
      "rather than from the shape of the columns. A comment does not count and neither does " +
      "a check the caller makes afterwards: the place that touched the row is the place that " +
      "knows what was read.",
    dirs: ["lib", "bin"],
    // The anchor is the framework's own table, found in the vendored
    // schema by the column pair that makes it a chain origin rather than
    // by a name this repository could rename, plus whatever local
    // constant this file binds it to. The good token is the framework's
    // own verifier, which is a published primitive rather than a local
    // symbol, so it survives a rename here and disappears only when the
    // call itself goes. The enclosing function is the shared outward
    // walk, so a read wrapped in a branch or a try block is still read
    // as the same function.
    scan: function (file) {
      var mask  = _maskOf(file);
      var names = _chainOriginNames(mask);
      var out   = [];
      var seen  = Object.create(null);
      names.forEach(function (name) {
        var re = new RegExp("(?:\\b|\")" + name + "(?:\\b|\")", "g");
        var m;
        while ((m = re.exec(mask)) !== null) {
          var span = _enclosingFunctionSpan(mask, m.index);
          if (!span) continue;
          if (seen[span.start]) continue;
          var body = mask.slice(span.start, span.end);
          if (/\bverifyPurgeAnchor\s*\(/.test(body)) continue;
          seen[span.start] = 1;
          out.push(_atOffset(file, m.index,
            "the record that turns a missing counter into a purge is read here and nothing " +
            "in this function asks whether its signature holds"));
        }
      });
      return out;
    },
    red: [
      // The shape this replaced: the counter read, compared, and handed
      // back as a verdict that says the reading was made.
      "var PURGE_ANCHOR_TABLE = \"_blamejs_audit_purge_anchor\";\n" +
        "function readAnchor(anchor) {\n" +
        "  var row = b.db.from(PURGE_ANCHOR_TABLE).where({ scope: \"audit\" }).first();\n" +
        "  if (row && anchor.counter <= Number(row.lastPurgedCounter)) {\n" +
        "    return { checked: true, counter: anchor.counter, purged: true };\n" +
        "  }\n" +
        "  return null;\n" +
        "}\n",
      // The table named as a literal at the read, which is the same
      // reading written without the constant.
      "function purgedThrough() {\n" +
        "  var row = b.db.from(\"_blamejs_audit_purge_anchor\").first();\n" +
        "  return row ? Number(row.lastPurgedCounter) : null;\n" +
        "}\n",
      // The shape that replaced the first one and is wrong the other
      // way: the row is read, the word an operator receives is fixed at
      // the read, and nothing established which of the two records this
      // volume carries.
      "var PURGE_ANCHOR_TABLE = \"_blamejs_audit_purge_anchor\";\n" +
        "function purgeRecord() {\n" +
        "  var row = b.db.from(PURGE_ANCHOR_TABLE).where({ scope: \"audit\" }).first();\n" +
        "  if (!row) return null;\n" +
        "  return {\n" +
        "    through:  Number(row.lastPurgedCounter),\n" +
        "    unsigned: \"an unsigned purge record says every row up to counter \" +\n" +
        "      row.lastPurgedCounter + \" was archived and deleted, and that table \" +\n" +
        "      \"carries no signature over it\",\n" +
        "  };\n" +
        "}\n",
    ],
    green: [
      // The reader asks the framework about the row it just read and
      // hands the status on, so a caller can tell a signed boundary from
      // an older record and both from one that was edited.
      "var PURGE_ANCHOR_TABLE = \"_blamejs_audit_purge_anchor\";\n" +
        "function purgeRecord() {\n" +
        "  var row = b.db.from(PURGE_ANCHOR_TABLE).where({ scope: \"audit\" }).first();\n" +
        "  if (!row) return null;\n" +
        "  var verdict = b.auditChain.verifyPurgeAnchor(row);\n" +
        "  return {\n" +
        "    through: Number(row.lastPurgedCounter),\n" +
        "    status:  verdict.status,\n" +
        "  };\n" +
        "}\n",
      // The binding on its own. Naming the table at module level is how
      // a file's readers reach it and is not itself a reading, so a
      // declaration with nothing in the tree using it yet is silent.
      "var PURGE_ANCHOR_TABLE = \"_blamejs_audit_purge_anchor\";\n" +
        "var PURGE_ANCHOR_SCOPE = \"audit\";\n",
      // A different framework table read the ordinary way: the rule is
      // about the one row that discards a range from the walk, not about
      // every read in the tree.
      "function ticksFor(name) {\n" +
        "  return b.db.from(\"_blamejs_scheduler_ticks\").where({ name: name }).all();\n" +
        "}\n",
    ],
  },

  {
    name: "audit-row-that-names-no-actor",
    description:
      "An audit row written from a surface that knows who is acting, with no actor on the " +
      "event. The chain writer fills the actor columns from the event's own actor and " +
      "null-fills whatever it is not given, so an event that leaves the key out produces a " +
      "row recording what happened and nobody who did it. A hash-linked sequence of " +
      "anonymous rows is a log rather than an audit trail: it proves the record was not " +
      "altered and answers none of the questions an incident asks of a suspension, an " +
      "erasure or a newly hosted domain. Each surface scanned here holds a principal at the " +
      "moment it emits. The identity layer runs under whoever reached it, the browser " +
      "surface has an authenticated session, and the command line has an invoking operator, " +
      "so name the actor: the one the surface established, or one the site builds itself " +
      "where the principal is not that one. An empty object is not an answer, because it " +
      "records nobody as deliberately as leaving the key out, and an event assembled out of " +
      "sight cannot be read at all. What decides whether a module is scanned is whose act the " +
      "row describes. The listeners, the delivery chain and the mailbox adapter are outside " +
      "it, because an inbound delivery and a wire refusal are performed by a peer rather than " +
      "a principal and their rows carry that peer in fields of their own. The signing-key " +
      "module is inside it, because minting, rotating, retiring and withdrawing a selector are " +
      "performed by an operator running a command, and which operator is the first question an " +
      "incident asks of a key that could sign as the domain.",
    dirs: ["lib/store", "lib/web", "bin", "lib/mail"],
    scan: function (file) {
      // The mail layer is scanned for one module. A blanket entry would
      // report every delivery and listener event, all of which describe
      // what a peer did and none of which have a principal to name.
      if (MAIL_LAYER_RE.test(file.rel) && !KEY_LIFECYCLE_OWNER_RE.test(file.rel)) return [];
      return _auditEventFindings(file, function (event, mask) {
        if (event.arg.indexOf("{") === -1) {
          if (_forwardsItsParameter(mask, event)) return null;
          return "the audit event is assembled somewhere else, so whether the row names " +
            "an actor cannot be read here";
        }
        var named = _literalKeyValue(event.arg, "actor");
        if (named === null) {
          return "an audit row is written with no actor, so it records what happened and " +
            "nobody who did it";
        }
        if (/^\s*\{\s*\}\s*$/.test(named)) {
          return "an audit row's actor is an empty object, which records nobody as " +
            "deliberately as leaving the key out";
        }
        return null;
      });
    },
    red: [
      "await b.audit.record({\n" +
        "  action:   \"account.suspended\",\n" +
        "  outcome:  \"success\",\n" +
        "  resource: { kind: \"account\", id: row._id },\n});\n",
      // An actor named inside the metadata blob rather than in the
      // column an auditor filters on.
      "b.audit.safeEmit({\n" +
        "  action:   \"blamepost.jmap.websocket.refused\",\n" +
        "  outcome:  \"denied\",\n" +
        "  metadata: { reason: \"origin-not-served\", actor: peer },\n});\n",
      "await b.audit.record({ action: \"domain.added\", outcome: \"success\", actor: {} });\n",
      "await b.audit.record(event);\n",
      // The store's own writer is an emit entry point too, so a row
      // written through it is read on the same terms. A detector that
      // saw only the framework handle would have stopped reading every
      // site the moment the wrapper landed.
      "var auditActor = require(\"./actor\");\n" +
        "async function add(name, row) {\n" +
        "  await auditActor.record({\n" +
        "    action:   \"domain.added\",\n" +
        "    outcome:  \"success\",\n" +
        "    resource: { kind: \"domain\", id: row._id },\n" +
        "  });\n" +
        "}\n",
      // And through a local named something else, which is the case a
      // matcher anchored on the spelling would go quiet on.
      "var trail = require(\"../store/actor\");\n" +
        "async function suspend(id) {\n" +
        "  await trail.record({ action: \"account.suspended\", outcome: \"success\" });\n" +
        "}\n",
      // The signing-key module is inside the scan, so an anonymous row
      // written there is a finding rather than an exclusion.
      { as:   "lib/mail/dkim.js",
        text: "await b.audit.record({\n" +
              "  action:   \"blamepost.mail.dkim.keys_rotated\",\n" +
              "  outcome:  \"success\",\n" +
              "  metadata: { domain: domain, incoming: minted },\n});\n" },
    ],
    green: [
      "await b.audit.record({\n" +
        "  action:   \"account.suspended\",\n" +
        "  outcome:  \"success\",\n" +
        "  actor:    auditActor.current(),\n" +
        "  resource: { kind: \"account\", id: row._id },\n});\n",
      "b.audit.safeEmit({\n" +
        "  action:   \"blamepost.jmap.websocket.refused\",\n" +
        "  outcome:  \"denied\",\n" +
        "  actor:    auditActor.forRequest(req),\n" +
        "  metadata: { reason: \"origin-not-served\" },\n});\n",
      // A site whose principal is not the ambient one builds its own.
      "b.audit.safeEmit({\n" +
        "  action:  \"account.authentication_refused\",\n" +
        "  outcome: \"denied\",\n" +
        "  actor:   { ip: sourceKey === \"\" ? null : sourceKey },\n});\n",
      // A key of the same name inside a nested object does not answer
      // for the event, and a sentence carrying the word does not either.
      "await b.audit.record({\n" +
        "  action:   \"account.lockout_released\",\n" +
        "  outcome:  \"success\",\n" +
        "  actor:    auditActor.current(),\n" +
        "  reason:   \"the actor: whoever asked for it\",\n" +
        "  metadata: { actor: null },\n});\n",
      // The boundary inside the mail layer, proven rather than assumed.
      // A wire refusal names the peer it came from in fields of its own
      // and has no principal to name, so it is not a finding.
      { as:   "lib/mail/listeners.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.listeners.body_read_as_two_messages\",\n" +
              "  outcome:  \"denied\",\n" +
              "  metadata: { direction: direction, mailFrom: envelope.mailFrom || \"\" },\n});\n" },
      { as:   "lib/mail/delivery.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.delivery.report_unsent\",\n" +
              "  outcome:  \"failure\",\n" +
              "  metadata: { domain: domain, reason: cause },\n});\n" },
      // And the key module inside that same layer, named, so the
      // exclusion above cannot quietly widen back over it.
      { as:   "lib/mail/dkim.js",
        text: "await b.audit.record({\n" +
              "  action:   \"blamepost.mail.dkim.keys_rotated\",\n" +
              "  outcome:  \"success\",\n" +
              "  actor:    auditActor.current(),\n" +
              "  metadata: { domain: domain, incoming: minted },\n});\n" },
      // A row written through the store's own writer, naming its actor.
      "var auditActor = require(\"./actor\");\n" +
        "async function add(name, row) {\n" +
        "  await auditActor.record({\n" +
        "    action:   \"domain.added\",\n" +
        "    outcome:  \"success\",\n" +
        "    actor:    auditActor.current(),\n" +
        "    resource: { kind: \"domain\", id: row._id },\n" +
        "  });\n" +
        "}\n",
      // The writer itself, handing on the event it was given. It decides
      // nothing about the row, and the sites that do are read on their
      // own. An event reached any other way is still a finding, which
      // the bare `record(event)` fixture above holds.
      "async function record(event) {\n" +
        "  try {\n" +
        "    await b.audit.record(event);\n" +
        "  } catch (_e) {\n" +
        "    /* drop-silent by design */\n" +
        "  }\n" +
        "}\n",
    ],
  },

  {
    name: "audit-actor-assembled-at-the-emit",
    description:
      "An audit row whose actor is an object literal written beside the event. One module owns " +
      "the shape the actor columns are filled from: it trims and bounds each field, removes the " +
      "codepoints a terminal acts on rather than prints, freezes the result and marks it so a " +
      "scope can tell an actor it built from one it did not. A literal written at the emit " +
      "skips all of that and carries the fields whoever wrote it remembered, which on the mail " +
      "surface is the identity and not the address the command arrived from. A session row that " +
      "names the account and not the peer cannot answer what else that address did while it " +
      "held a credential, and on a refusal from a stranger the address is the whole of what the " +
      "row can stand behind. Two of the four fields come off the wire, so an actor assembled " +
      "here is also an unbounded field a peer chose the size of. Hand the fields to the actor " +
      "module instead. Naming no identity is still done there: a peer and no principal is the " +
      "truthful answer for a connection that proved nothing, and it is the answer a refused " +
      "credential is given on purpose, because the name a refused attempt claimed is a name " +
      "whoever is guessing chose.",
    // The mail layer, where a row describes what arrived on a socket.
    // The browser surface builds its actor from the request and the
    // command line from the process, and each has its own constructor in
    // the same module; what is particular here is that one listener
    // serves both kinds of principal on one port, so the choice between
    // them is made per row rather than per surface.
    dirs: ["lib/mail"],
    scan: function (file) {
      var mask  = _maskOf(file);
      var found = [];
      // The CONSTRUCTION, wherever it is written. Anchoring on the emit
      // alone reads the sites that inline the literal and goes quiet the
      // moment one is lifted into a helper, which is the same row with
      // one more hop in front of it. The four names are the columns the
      // chain writer fills from, so a literal opening with one of them
      // is an actor whatever it is called and wherever it sits, and the
      // only place one belongs is inside the call that shapes it.
      var opens = /\{\s*(?:userId|ip|userAgent|sessionId)\s*:/g;
      var at;
      while ((at = opens.exec(mask)) !== null) {
        if (/build\(\s*$/.test(mask.slice(Math.max(0, at.index - 40), at.index))) continue;
        found.push(_atOffset(file, at.index,
          "an actor for an audit row is assembled as an object literal rather than built by " +
          "the module that owns the shape, so it carries only the fields written here and is " +
          "neither screened nor bounded"));
      }
      // The other way an inline actor is wrong, which the pass above
      // cannot see because it carries none of the names it looks for: a
      // literal whose fields are not the ones the chain writer reads.
      // The row then names nobody while looking, at the call site, like
      // it names somebody.
      return found.concat(_auditEventFindings(file, function (event) {
        var named = _literalKeyValue(event.arg, "actor");
        if (named === null || !/^\s*\{/.test(named)) return null;
        if (/\b(?:userId|ip|userAgent|sessionId)\s*:/.test(named)) return null;
        return "an audit row's actor is an object literal carrying none of the fields the " +
          "chain writer fills the actor columns from, so every one of them is null-filled";
      }));
    },
    red: [
      { as:   "lib/mail/listeners.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.listeners.imap_create_refused\",\n" +
              "  outcome:  \"denied\",\n" +
              "  actor:    { userId: (state.actor && state.actor.id) || null },\n" +
              "  metadata: { mailbox: request.mailbox },\n});\n" },
      // A credential's row is the same shape with a different id on it.
      { as:   "lib/mail/listeners.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.listeners.sending_credential_stopped\",\n" +
              "  outcome:  \"denied\",\n" +
              "  actor:    { userId: scope.id },\n});\n" },
      // And a peer-only literal, which is the right CONTENT assembled in
      // the wrong place: still unscreened, still unbounded.
      { as:   "lib/mail/mailbox.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.mailbox.expunge_denied\",\n" +
              "  outcome:  \"denied\",\n" +
              "  actor:    { ip: ctx.remoteAddress },\n});\n" },
      // The same literal lifted into a helper, which is the shape an
      // emit-anchored matcher goes quiet on while every row it feeds is
      // still missing the peer.
      { as:   "lib/mail/listeners.js",
        text: "function _imapVerbActor(state) {\n" +
              "  return { userId: (state.actor && state.actor.id) || null };\n" +
              "}\n" },
      // A literal naming a field the chain writer does not read. It
      // looks attributed at the call site and lands as a row naming
      // nobody.
      { as:   "lib/mail/listeners.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.listeners.imap_close\",\n" +
              "  outcome:  \"failure\",\n" +
              "  actor:    { id: state.actor.id },\n});\n" },
    ],
    green: [
      { as:   "lib/mail/listeners.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.listeners.imap_create_refused\",\n" +
              "  outcome:  \"denied\",\n" +
              "  actor:    _wireActor(state.actor, state.remoteAddress, state.id),\n" +
              "  metadata: { mailbox: request.mailbox },\n});\n" },
      { as:   "lib/mail/dkim.js",
        text: "await b.audit.record({\n" +
              "  action:   \"blamepost.mail.dkim.keys_rotated\",\n" +
              "  outcome:  \"success\",\n" +
              "  actor:    auditActor.current(),\n});\n" },
      // The fields handed over rather than shaped here. The call is what
      // makes it the module's answer, whatever the fields are.
      { as:   "lib/mail/listeners.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.listeners.mx_recipient_domain_not_hosted\",\n" +
              "  outcome:  \"denied\",\n" +
              "  actor:    auditActor.build({ ip: ctx.remoteAddress }),\n});\n" },
      // A row naming no actor at all is a different question, asked by
      // the detector above. Reporting it here would put two names on one
      // line and send a reader to fix the wrong half.
      { as:   "lib/mail/listeners.js",
        text: "b.audit.safeEmit({\n" +
              "  action:   \"blamepost.mail.listeners.boot_failed\",\n" +
              "  outcome:  \"failure\",\n" +
              "  metadata: { line: line },\n});\n" },
      // The fields spread over several lines, which is how the longer
      // ones are written and the form a bound counted in characters
      // would stop reading.
      { as:   "lib/mail/listeners.js",
        text: "function _wireActor(principal, peer, connectionId) {\n" +
              "  return auditActor.build({\n" +
              "    userId:    (principal && principal.id) || null,\n" +
              "    ip:        peer || null,\n" +
              "    sessionId: connectionId || null,\n" +
              "  });\n" +
              "}\n" },
    ],
  },

  {
    name: "audit-emit-whose-failure-reaches-the-caller",
    description:
      "An audit row written on the awaiting entry point with nothing to catch it, so a sink " +
      "that cannot write decides what the caller is told. A verb changes something and then " +
      "records it, and those are two writes: by the time the second one runs the change is on " +
      "disk and no later write can take it back, so the only question a failure leaves is what " +
      "the caller hears. Letting the sink's error out answers it in the one way that cannot be " +
      "recovered from, because 'the domain was not added' and 'the domain was added and the " +
      "row was not written' arrive as the same error while needing opposite responses. The " +
      "damage spreads past the verb that emits: a caller that unwinds on the throw undoes half " +
      "of a completed operation, which is how a key mint erases the private half it just wrote " +
      "and leaves the selector row pointing at it. Wrap the emit and drop what cannot be " +
      "filed, or route it through a helper that already does. A catch that rethrows is not a " +
      "wrap, since the value still leaves. The fire-and-forget entry point is not reported: " +
      "the framework catches inside it, so it cannot throw at its caller in the first place. " +
      "The two ways an emit can be wrong in the source rather than in the field, an " +
      "unregistered namespace and a row naming no actor, are the other detectors in this " +
      "family, and they are what keeps dropping a row from hiding a coding mistake.",
    // The command line is scanned for the same reason the library is, and
    // the two other detectors in this family already scan it. Its verbs
    // perform a change and then record it exactly as the store's do, and
    // one of them has further to fall: a restore opens the volume it just
    // put in place and records what it found, so an emit that threw read
    // as a volume that would not open and the restore was rolled back.
    dirs: ["lib", "bin"],
    scan: function (file) {
      return _auditEventFindings(file, function (event, mask) {
        // Only the framework's awaiting entry point can reject at its
        // caller. The fire-and-forget one catches inside the framework,
        // and the store's own writer catches around this same call, so a
        // site that goes through either is already answered.
        if (event.receiver !== "audit" || event.verb !== "record") return null;
        if (_caughtBeforeLeaving(mask, event.index)) return null;
        return "an audit sink failure escapes into the caller, which cannot then tell an " +
          "operation that did not happen from one that happened and went unrecorded";
      });
    },
    red: [
      "async function add(opts) {\n" +
        "  var row = tables.insertRow(DOMAINS, { domain: name });\n" +
        "  await b.audit.record({\n" +
        "    action: \"domain.added\", outcome: \"success\", actor: auditActor.current(),\n" +
        "  });\n" +
        "  return row;\n" +
        "}\n",
      // The shape the store modules are written in: the verb is built
      // inside a factory, so its closing brace is indented and a
      // boundary that assumed column zero would walk straight past it.
      "function create(opts) {\n" +
        "  async function suspend(id, reason) {\n" +
        "    tables.updateRow(ACCOUNTS, id, { status: \"suspended\" });\n" +
        "    await b.audit.record({ action: \"account.suspended\", outcome: \"success\" });\n" +
        "    return _present(id);\n" +
        "  }\n" +
        "  return { suspend: suspend };\n" +
        "}\n",
      // A catch that rethrows is not a wrap: the sink's error still
      // reaches the caller, by a longer route.
      "async function remove(row, reason) {\n" +
        "  tables.deleteRow(ALIASES, row._id);\n" +
        "  try {\n" +
        "    await b.audit.record({ action: \"alias.removed\", outcome: \"success\" });\n" +
        "  } catch (e) {\n" +
        "    throw e;\n" +
        "  }\n" +
        "}\n",
      // A try whose block closed before the emit covers nothing, however
      // close to it the handler sits in the text.
      "async function reclaim(reason) {\n" +
        "  try { sweep(); }\n" +
        "  catch (_e) { /* drop-silent by design */ }\n" +
        "  await b.audit.record({ action: \"blobs.reclaimed\", outcome: \"success\" });\n" +
        "}\n",
      // Returned rather than awaited, from a callback. The rejection
      // still settles in whatever awaited the callback.
      "function applied(config, found) {\n" +
        "  return b.audit.record({\n" +
        "    action: \"blamepost.restore.applied\", outcome: \"success\",\n" +
        "  });\n" +
        "}\n",
    ],
    green: [
      // The wrap, with the emit doing the recording after the change.
      "async function add(opts) {\n" +
        "  var row = tables.insertRow(DOMAINS, { domain: name });\n" +
        "  try {\n" +
        "    await b.audit.record({ action: \"domain.added\", outcome: \"success\" });\n" +
        "  } catch (_e) {\n" +
        "    /* drop-silent by design: the domain is added either way */\n" +
        "  }\n" +
        "  return row;\n" +
        "}\n",
      // The fire-and-forget entry point cannot throw at its caller, so
      // it is not a finding however it is written.
      "function refused(peer) {\n" +
        "  b.audit.safeEmit({\n" +
        "    action: \"account.authentication_refused\", outcome: \"denied\",\n" +
        "  });\n" +
        "}\n",
      // Nested inside a branch and a loop that are themselves inside the
      // try. The walk goes outward through the blocks, so this is
      // covered where a layout match would have missed it.
      "async function sweep(rows, reason) {\n" +
        "  try {\n" +
        "    for (var i = 0; i < rows.length; i += 1) {\n" +
        "      if (rows[i].stale) {\n" +
        "        await b.audit.record({ action: \"alias.removed\", outcome: \"success\" });\n" +
        "      }\n" +
        "    }\n" +
        "  } catch (_e) {\n" +
        "    /* drop-silent by design: the sweep already happened */\n" +
        "  }\n" +
        "}\n",
      // The helper that owns the wrap. Its own emit is inside the catch
      // it provides, which is what lets every call site stop writing one.
      "async function record(event) {\n" +
        "  try {\n" +
        "    await b.audit.record(event);\n" +
        "  } catch (_e) {\n" +
        "    /* drop-silent by design */\n" +
        "  }\n" +
        "}\n",
      // A handler that reports what it caught and does not rethrow is
      // still a wrap. Swallowing is the property, not silence.
      "async function purge(reason) {\n" +
        "  try {\n" +
        "    await b.audit.record({ action: \"blamepost.audit.purged\", outcome: \"success\" });\n" +
        "  } catch (e) {\n" +
        "    report.warn(\"the row could not be written: \" + e.message);\n" +
        "  }\n" +
        "}\n",
      // A call site going through the store's writer needs no wrap of
      // its own: the wrap is inside what it called.
      "var auditActor = require(\"./actor\");\n" +
        "async function add(name, row) {\n" +
        "  await auditActor.record({ action: \"domain.added\", outcome: \"success\" });\n" +
        "  return row;\n" +
        "}\n",
      // The same through a differently named local, so the exemption
      // rests on which module was required rather than on a spelling.
      "var trail = require(\"../store/actor\");\n" +
        "async function suspend(id) {\n" +
        "  await trail.record({ action: \"account.suspended\", outcome: \"success\" });\n" +
        "}\n",
    ],
  },

  {
    name: "audit-outcome-asserted-against-what-happened",
    description:
      "An audit row filed as a success from inside a catch handler. The handler runs BECAUSE " +
      "the work failed, so the outcome is already known there and it is not this one. An " +
      "outcome is the field `b.audit.query` filters on and the first thing an operator asks a " +
      "trail for, so a row carrying a verdict nothing derived does not merely omit the fault: " +
      "it answers the question with the opposite of the answer, and it does so at the moment " +
      "somebody is consulting the trail precisely because something has gone wrong. The rule " +
      "is that the outcome is read off the result. Work that failed and was absorbed is a " +
      "failure; work that was refused is a denial; a verb that can end either way carries the " +
      "verdict in a variable settled on the path that produced it. Record the cause beside " +
      "it, in a field of its own rather than only inside a sentence, so the two failures that " +
      "share one handler stay separable by a query.",
    dirs: ["lib", "bin"],
    // Anchored on the audit row's own frozen shape, which is a pair of
    // field names the framework reads rather than symbols this
    // repository can rename: a literal `outcome` of `success` inside an
    // object that also names an `action`. The nesting question is the
    // shared outward walk, so a handler that grows a branch or a loop
    // around the emit is still read as the handler.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      var re   = /\boutcome\s*:\s*["']success["']/g;
      var m;
      while ((m = re.exec(mask)) !== null) {
        var row = _enclosingBraces(mask, m.index);
        if (!row) continue;
        if (!/\baction\s*:/.test(mask.slice(row.start, row.end))) continue;
        if (!_insideCatchHandler(mask, m.index)) continue;
        out.push(_atOffset(file, m.index,
          "an audit row is filed as a success from inside the handler that ran " +
          "because the work failed"));
      }
      return out;
    },
    red: [
      "async function send(message) {\n" +
        "  try {\n" +
        "    wire = await dkim.sign(domain, wire);\n" +
        "  } catch (err) {\n" +
        "    b.audit.safeEmit({\n" +
        "      action:   \"blamepost.mail.compose.unsigned\",\n" +
        "      outcome:  \"success\",\n" +
        "      metadata: { domain: domain },\n" +
        "    });\n" +
        "  }\n" +
        "}\n",
      // Nested a branch deep inside the handler, which a character
      // budget or a layout match would walk past.
      "async function file(copy) {\n" +
        "  try {\n" +
        "    return mailStore.appendMessage(sentFolder, copy);\n" +
        "  } catch (err) {\n" +
        "    if (err && err.code === \"store/quota-exceeded\") {\n" +
        "      await auditActor.record({\n" +
        "        action:  \"blamepost.mail.compose.unfiled\",\n" +
        "        outcome: \"success\",\n" +
        "      });\n" +
        "    }\n" +
        "    return null;\n" +
        "  }\n" +
        "}\n",
      // The promise spelling of a handler, which runs for the same
      // reason and is the same claim about what happened.
      "function search(state, tag) {\n" +
        "  return scan(state)\n" +
        "    .then(function (rows) { return answer(rows); })\n" +
        "    .catch(function (failure) {\n" +
        "      b.audit.safeEmit({\n" +
        "        action:  \"blamepost.mail.listeners.imap_search\",\n" +
        "        outcome: \"success\",\n" +
        "      });\n" +
        "    });\n" +
        "}\n",
    ],
    green: [
      // The success arm of the same promise chain, which is the half
      // that did run because the work happened.
      "function search(state, tag) {\n" +
        "  return scan(state)\n" +
        "    .then(function (rows) {\n" +
        "      b.audit.safeEmit({\n" +
        "        action:  \"blamepost.mail.listeners.imap_search\",\n" +
        "        outcome: \"success\",\n" +
        "      });\n" +
        "      return answer(rows);\n" +
        "    });\n" +
        "}\n",
      // The same handler, filing what actually happened and naming the
      // cause in a field a query can reach.
      "async function send(message) {\n" +
        "  try {\n" +
        "    wire = await dkim.sign(domain, wire);\n" +
        "  } catch (err) {\n" +
        "    b.audit.safeEmit({\n" +
        "      action:   \"blamepost.mail.compose.unsigned\",\n" +
        "      outcome:  \"failure\",\n" +
        "      metadata: { domain: domain, cause: (err && err.code) || null },\n" +
        "    });\n" +
        "  }\n" +
        "}\n",
      // A refusal absorbed by a handler is a denial, which is a verdict
      // the handler did derive.
      "function refuse(command, err) {\n" +
        "  try {\n" +
        "    socket.write(reply(err));\n" +
        "  } catch (_e) {\n" +
        "    b.audit.safeEmit({\n" +
        "      action:  \"blamepost.mail.listeners.imap_search_refused\",\n" +
        "      outcome: \"denied\",\n" +
        "    });\n" +
        "  }\n" +
        "}\n",
      // The emit is inside the GUARDED block, not the handler: the row
      // is about work that succeeded, and the catch beside it exists so
      // a trail that cannot be written does not fail the work.
      "async function purge(reason) {\n" +
        "  var swept = await engine.purgeOlder({ keep: 3 });\n" +
        "  try {\n" +
        "    await b.audit.record({\n" +
        "      action:  \"blamepost.backup.purged\",\n" +
        "      outcome: \"success\",\n" +
        "      reason:  reason,\n" +
        "    });\n" +
        "  } catch (e) {\n" +
        "    report.warn(\"the row could not be written: \" + e.message);\n" +
        "  }\n" +
        "  return swept;\n" +
        "}\n",
      // A verb that can end either way carries the verdict in a variable
      // settled on the path that produced it.
      "async function rotate(domain) {\n" +
        "  var outcome = \"failure\";\n" +
        "  try {\n" +
        "    await mintPair(domain);\n" +
        "    outcome = \"success\";\n" +
        "  } catch (err) {\n" +
        "    log.error(err.message);\n" +
        "  }\n" +
        "  b.audit.safeEmit({ action: \"blamepost.mail.dkim.keys_rotated\", outcome: outcome });\n" +
        "}\n",
      // Not an audit row: an object carrying a verdict of its own, which
      // the caller reads rather than an auditor.
      "function verdictOf(entry) {\n" +
        "  try {\n" +
        "    return { id: entry.id, outcome: probe(entry) };\n" +
        "  } catch (_e) {\n" +
        "    return { id: entry.id, outcome: \"success\", note: \"nothing was queued\" };\n" +
        "  }\n" +
        "}\n",
    ],
  },

  {
    name: "destruction-reported-from-an-answer-nothing-read",
    description:
      "A body that hands back a destruction as done, written as a literal, while the answer of " +
      "the call that was supposed to do the destroying is thrown away. The two halves are the " +
      "whole finding: a verdict a caller reads, and nothing in the body that could have " +
      "derived it. Removing a file is not a question with one answer. It was there and it is " +
      "gone; it was never there, so nothing was cancelled and whoever asked has to be told the " +
      "message is past cancelling; or the volume would not give it up, which is the one that " +
      "costs the most, because the caller files a row saying the thing is gone and writes to " +
      "somebody to say so while it is still on disk being retried. A removal made with the " +
      "flag that ignores an absent path cannot tell the first two apart and a caller that " +
      "discards the result cannot see the third, so the constant is not a summary of what " +
      "happened but a replacement for it. Read the verdict off the act: return what the act " +
      "answered, one part at a time where the act has parts, and name the part that refused, " +
      "because which one refused decides what is left behind.",
    dirs: ["lib", "bin"],
    // Two shapes in one body, and neither is a renameable symbol. The
    // verdict is matched by the field names a CALLER reads, which are a
    // contract between the two rather than a local spelling. The missing
    // derivation is matched as a pure shape: an awaited call standing
    // alone as a statement, which is an answer arriving and being
    // dropped. A verdict computed from anything the body settled carries
    // no literal and never matches, which is the whole of the remedy.
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      var verdictRe = /\b(?:removed|erased|destroyed|expunged|deleted|cancelled)\s*:\s*true\b/g;
      var discardedRe = /(?:^|[;{}])\s*await\s+[A-Za-z_$]/g;
      for (var i = 0; i < bodies.length; i += 1) {
        var verdicts = _matchesIn(mask, bodies, bodies[i], verdictRe);
        if (verdicts.length === 0) continue;
        if (_matchesIn(mask, bodies, bodies[i], discardedRe).length === 0) continue;
        for (var v = 0; v < verdicts.length; v += 1) {
          out.push(_atOffset(file, verdicts[v].offset,
            "this body reports a destruction as done with a literal while the answer of the " +
            "call that was to do it is discarded, so the verdict a caller reads is a constant " +
            "rather than a reading of what happened"));
        }
      }
      return out;
    },
    red: [
      // The spool cancellation: the unlink is awaited as a statement of
      // its own and the verdict is written underneath it.
      "async function queueRemove(id) {\n" +
        "  _assertSpoolId(id, \"remove\");\n" +
        "  await _dropSpooled(id);\n" +
        "  return { id: id, removed: true };\n" +
        "}\n",
      // The same claim about signing material, and the layout this tree
      // is written in: the verb is built inside a factory, so its closing
      // brace is indented and the verdict sits one level further in.
      "function create(ctx) {\n" +
        "  async function withdraw(ref) {\n" +
        "    await eraseKeyFiles(ctx.dataDir, [ref]);\n" +
        "    return { keyRef: ref, erased: true };\n" +
        "  }\n" +
        "  return { withdraw: withdraw };\n" +
        "}\n",
      // Nested a branch deep, which a layout match or a character budget
      // would walk past.
      "async function forget(id, reason) {\n" +
        "  if (reason) {\n" +
        "    await blobs.eraseHard(id);\n" +
        "    return { id: id, destroyed: true };\n" +
        "  }\n" +
        "  return { id: id, destroyed: false };\n" +
        "}\n",
    ],
    green: [
      // The settled shape: the act answers, the answer is bound, and the
      // verdict is that answer rather than a constant beside it.
      "async function queueRemove(id) {\n" +
        "  _assertSpoolId(id, \"remove\");\n" +
        "  var account = await _dropSpooled(id);\n" +
        "  return { id: id, removed: account.removed, outcome: account.outcome };\n" +
        "}\n",
      // A verdict derived from the act in the line above it, with no
      // suspension anywhere: the entry was resolved or the body raised,
      // and the flag it reports is the one it just set.
      "function markDelete(actor, dropId, msgNum) {\n" +
        "  var entry = _messageIn(_dropFor(actor, dropId), msgNum);\n" +
        "  if (!entry) throw err(\"mailbox/no-message\", \"DELE: no message with that number.\");\n" +
        "  entry.deleted = true;\n" +
        "  return { msgNum: entry.msgNum, deleted: true };\n" +
        "}\n",
      // An awaited call whose answer is read, beside a verdict about
      // something the body did settle.
      "async function retire(domain, ref) {\n" +
        "  var swept = await eraseKeyFiles(domain, [ref]);\n" +
        "  return { keyRef: ref, erased: swept.erased.length === 1 };\n" +
        "}\n",
      // A request rather than a verdict: the literal is an instruction
      // this body is sending, and the body reports whatever came back.
      "async function forget(id, reason) {\n" +
        "  return store.accounts.delete({ id: id, reason: reason, destroy: true });\n" +
        "}\n",
    ],
  },

  {
    name: "refusal-code-raised-outside-a-published-code-set",
    description:
      "A refusal code written as a literal at the throw site, in a module that publishes its " +
      "code vocabulary as an exported frozen set. A published set is read by callers deciding " +
      "what a code means and by operator-facing surfaces deciding whether a message was worded " +
      "for a reader at all, and a prefix cannot stand in for either question once two authors " +
      "share the prefix. Both readings are only worth anything if the set is COMPLETE, and a " +
      "code raised from a literal is one the set does not hold: the caller's branch misses it " +
      "and the surface treats a refusal written for an operator as one that was not. Name the " +
      "code once as a constant, raise it by that name, and list the constant in the set, so " +
      "the vocabulary and the throws cannot come apart. A module that publishes no set is not " +
      "making the promise and is left alone.",
    dirs: ["lib"],
    // Two structural facts, no renameable symbol between them: the file
    // publishes a frozen CODES member, and a code-shaped literal sits in
    // the leading argument position of a call somewhere inside a
    // function body. The constant declarations the set is built from are
    // at module scope, so they are outside every function span and the
    // matcher passes over them without needing to recognize them.
    scan: function (file) {
      var mask = _maskOf(file);
      if (!/\bCODES\s*:\s*Object\.freeze\s*\(/.test(mask)) return [];
      var out = [];
      var re  = /\(\s*"[a-z][a-z0-9]*\/[a-z0-9-]+"\s*,/g;
      var m;
      while ((m = re.exec(mask)) !== null) {
        if (_enclosingFunctionSpan(mask, m.index) === null) continue;
        out.push(_atOffset(file, m.index,
          "a refusal code is raised from a literal in a module that publishes its code set"));
      }
      return out;
    },
    red: [
      "function readKey(entry) {\n" +
        "  throw err(\"dkim/key-unreadable\", \"the signing key is not on this volume\");\n" +
        "}\n" +
        "module.exports = { CODES: Object.freeze({ noActiveSelector: NO_ACTIVE_SELECTOR }) };\n",
    ],
    green: [
      // Raised by the name the set is built from.
      "var KEY_UNREADABLE = \"dkim/key-unreadable\";\n" +
        "function readKey(entry) {\n" +
        "  throw err(KEY_UNREADABLE, \"the signing key is not on this volume\");\n" +
        "}\n" +
        "module.exports = { CODES: Object.freeze({ keyUnreadable: KEY_UNREADABLE }) };\n",
      // A module publishing no set makes no promise about its codes, so
      // a literal there is a style question rather than a broken one.
      "function load(path) {\n" +
        "  throw _err(\"config/file-missing\", \"no configuration file at that path\");\n" +
        "}\n" +
        "module.exports = { load: load };\n",
      // A slash-carrying literal that is not a code, in a module that
      // does publish a set: it is not in the leading argument position.
      "var CANONICALIZATION = \"relaxed/relaxed\";\n" +
        "function create(opts) {\n" +
        "  var canonicalization = opts.canonicalization || \"relaxed/relaxed\";\n" +
        "  return { canonicalization: canonicalization };\n" +
        "}\n" +
        "module.exports = { create: create, CODES: Object.freeze({ a: A }) };\n",
    ],
  },

  {
    name: "refusal-selected-by-a-shared-code-prefix",
    description:
      "A refusal sorted by the namespace its code starts with, where the vendored framework " +
      "files codes under that namespace too. A prefix names a namespace, not an author, and " +
      "the question a surface asking it usually means to ask is whether anybody wrote the " +
      "sentence for a reader. Two layers file under `dkim/`: this server's signer, whose " +
      "refusals name a domain, a selector and the verb to run next, and the framework, whose " +
      "refusals name a primitive and the option path it holds an argument against. A prefix " +
      "test admits both, so an operator is shown an argument they cannot pass and the log " +
      "line the fallback would have written is lost with it. Read membership in the frozen " +
      "code set the composing module publishes instead, which is decided by what that module " +
      "throws and can never hold a code the framework invented. A prefix this repository is " +
      "the only author of answers the question it looks like it is asking and is left alone; " +
      "the vendored tree is measured on every run rather than listed here, so a refresh that " +
      "begins using one of those prefixes arms this without a second edit. Both spellings " +
      "are read, the string method and the anchored regular expression, because which one a " +
      "line happens to use says nothing about what it does. A test asserting that a recorded " +
      "cause carries the prefix is the same defect wearing the other hat, and worse, because " +
      "it makes the production reader look checked, so the suites are read as well. What the " +
      "match cannot see is whether a namespace-shaped literal is a code namespace or the " +
      "first segment of a path, and the framework's vocabulary is wide enough to hold names " +
      "like `queue` and `text`. Nothing in this tree collides today, and the report names the " +
      "namespace so a collision reads as one at a glance; a path prefix that lands on one of " +
      "those names is the case for an allow marker on the line.",
    dirs: ["lib", "bin", "test", "scripts"],
    scan: function (file) {
      var vendor = _frameworkCodeNamespaces();
      if (vendor.codes === 0) {
        return [{
          file:    file.rel,
          line:    1,
          content: "no error codes could be read from " + VENDOR_TREE + ", so no code prefix " +
                   "in this file can be told apart from the framework's own",
        }];
      }
      var out = [];
      function _take(offset, namespace) {
        if (vendor.names[namespace] !== 1) return;
        out.push(_atOffset(file, offset,
          "a refusal is sorted by the '" + namespace + "/' prefix, which the vendored " +
          "framework files codes under too"));
      }
      var mask = _maskOf(file);
      var call = /(?:indexOf|lastIndexOf|startsWith|includes)\s*\(\s*"([a-z][a-z0-9]*)\/"/g;
      var m;
      while ((m = call.exec(mask)) !== null) _take(m.index, m[1]);
      // The regular expression spelling, read off the raw text: the mask
      // blanks a regex literal, so there is nothing there to match. It is
      // anchored and followed by the call that runs it, which is a shape
      // that appears in code and not in a sentence about code.
      var literal = /\/\^([a-z][a-z0-9]*)\\\/\/\s*\.\s*(?:test|exec)\s*\(/g;
      while ((m = literal.exec(file.text)) !== null) _take(m.index, m[1]);
      return out;
    },
    red: [
      "function refusalText(err, fallback) {\n" +
        "  if (err && typeof err.code === \"string\" && err.code.indexOf(\"dkim/\") === 0) {\n" +
        "    return err.message;\n  }\n  return fallback;\n}\n",
      // The same decision written as an anchored regular expression.
      "function mayShow(err) {\n" +
        "  return /^dkim\\//.test(err.code);\n}\n",
      // A namespace the framework files under, reached by a different
      // string method: the shape is the prefix test, not the call.
      "function isVaultFault(err) {\n" +
        "  return String(err.code).startsWith(\"vault/\");\n}\n",
    ],
    green: [
      // Membership in the set the composing module publishes.
      "var DKIM_CODES = require(\"../mail/dkim\").CODES;\n" +
        "function refusalText(err, fallback) {\n" +
        "  if (err && DKIM_CODES.indexOf(err.code) !== -1) return err.message;\n" +
        "  return fallback;\n}\n",
      // A prefix this repository is the only author of.
      "function refusalText(err, fallback) {\n" +
        "  if (err && typeof err.code === \"string\" && err.code.indexOf(\"store/\") === 0) {\n" +
        "    return err.message;\n  }\n  return fallback;\n}\n",
      // A path prefix, which is not a code namespace and never was.
      "function isSealed(keyPem) {\n" +
        "  return keyPem.indexOf(SEALED_PEM_PREFIX) === 0;\n}\n",
      // One whole code compared for equality, which names an author as
      // well as a namespace.
      "function relayedUnsigned(err) {\n" +
        "  return err.code === DKIM_CODES.noActiveSelector;\n}\n",
    ],
  },

  {
    name: "empty-actor-collection-as-a-grant",
    description:
      "An actor field set to an empty list. These fields answer a question by being present, " +
      "not by what they hold: the permission gate reads the scope list in preference to the " +
      "role list whenever it is an array, and the submission listener reads the mailbox list " +
      "as the set of addresses that identity may send as. An empty list is therefore an " +
      "explicit grant of nothing rather than a request to decide from something else, so an " +
      "actor built this way is refused every verb its role allows and every address it owns. " +
      "Leave the field out when there is nothing to say, and fill it when there is.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      return _named(file, _lineMatcher(EMPTY_ACTOR_COLLECTION_RE, "code")(file));
    },
    red: [
      "var actor = { id: id, roles: [\"account\"], scopes: [] };\n",
      "return { id: verdict.accountId, roles: [], mailboxes: [address] };\n",
    ],
    green: [
      "var actor = { id: id, roles: [\"account\"], mailboxes: [address] };\n",
      "var actor = { id: id, scopes: [\"mail.read\", \"mail.write\"] };\n",
    ],
  },

  {
    name: "allowlist-collapsed-to-absent-when-empty",
    description:
      "A listener option naming the set a peer is measured against, handed over only while it " +
      "holds something and dropped when it holds nothing. These options answer by being " +
      "present: the framework applies the check against whatever the set holds, an empty set " +
      "included, and skips the check entirely when the option is absent. So the empty spelling " +
      "means 'match nobody' and the absent spelling means 'ask nobody', and collapsing the " +
      "first into the second turns a list that refuses everyone into no list at all. It is a " +
      "firewall rule set that opens when the last rule is deleted. The MX listener's relay " +
      "verdict is the case that bites first: what comes out is a server that answers a " +
      "stranger's sender and a stranger's recipient with the same acceptance an open relay " +
      "gives, which is what a scanner records whatever happens to the message afterwards. " +
      "Hand the set over as it is, and where an empty one means there is nothing this " +
      "listener could serve, refuse before constructing it rather than constructing one with " +
      "the check switched off.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      return _named(file, _lineMatcher(ALLOWLIST_COLLAPSED_WHEN_EMPTY_RE, "code")(file));
    },
    red: [
      "    localDomains: localDomains.length > 0 ? localDomains : undefined,\n",
      "  relayAllowedFor: allowed.length ? allowed : null,\n",
    ],
    green: [
      "    localDomains: localDomains,\n",
      "      inReplyTo: draft.inReplyTo.length > 0 ? draft.inReplyTo : undefined,\n",
    ],
  },

  {
    name: "config-number-without-bounds",
    description:
      "A configuration schema field naming a number with no floor and no ceiling. Every " +
      "number an operator sets here ends up in arithmetic that decides a moment, a budget or " +
      "a size, and the arithmetic cannot tell a value it was never meant to receive from one " +
      "it was. A retry budget of zero destroys mail on the first send, a wait of zero spends " +
      "the whole budget in a second, and a lifetime beyond the specification's ceiling is a " +
      "policy no receiver honors. The schema is where an operator finds out, at boot, rather " +
      "than at the moment a message is lost, so every numeric field carries both bounds.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out = [];
      CONFIG_NUMBER_RE.lastIndex = 0;
      var m;
      while ((m = CONFIG_NUMBER_RE.exec(mask)) !== null) {
        var obj = _enclosingBraces(mask, m.index);
        if (!obj) continue;
        var text = mask.slice(obj.start, obj.end + 1);
        if (CONFIG_MIN_RE.test(text) && CONFIG_MAX_RE.test(text)) continue;
        out.push(_atOffset(file, m.index));
      }
      return out;
    },
    red: [
      "var setting = { key: \"queueSweepMs\", kind: \"integer\", fallback: 60000 };\n",
      "var setting = { key: \"maxAttempts\", kind: \"integer\", min: 1, fallback: 5 };\n",
    ],
    green: [
      "var setting = { key: \"mtaStsMaxAge\", kind: \"integer\", min: 86400, max: 31557600 };\n",
      "var field = { maxAttempts: { kind: \"integer\", min: 1, max: 100 } };\n",
    ],
  },

  {
    name: "config-ordered-list-with-unenforced-order",
    description:
      "A configuration schema field whose prose describes an order the schema does not " +
      "enforce. A list whose order carries meaning is read by index somewhere, and the reader " +
      "has no way to notice that the operator wrote it the other way round: a retry schedule " +
      "indexed by attempt hands back the shortest wait where it names the longest, and " +
      "nothing anywhere reports a setting that was accepted and then read backwards. Prose in " +
      "the schema tells the operator what to write and enforces nothing. Declare the order on " +
      "the field so a list in the wrong order is refused at boot, where the operator can fix " +
      "it, rather than obeyed at three in the morning.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out = [];
      CONFIG_ARRAY_RE.lastIndex = 0;
      var m;
      while ((m = CONFIG_ARRAY_RE.exec(mask)) !== null) {
        var obj = _enclosingBraces(mask, m.index);
        if (!obj) continue;
        var text = mask.slice(obj.start, obj.end + 1);
        if (!ORDER_PROSE_RE.test(text)) continue;
        if (CONFIG_ORDER_KEY_RE.test(text)) continue;
        out.push(_atOffset(file, m.index));
      }
      return out;
    },
    red: [
      "var field = {\n" +
        "  kind:    \"array\",\n" +
        "  element: { kind: \"integer\", min: 1, max: 9 },\n" +
        "  expects: \"waits in milliseconds, each at least as long as the one before it\",\n};\n",
    ],
    green: [
      "var field = {\n" +
        "  kind:      \"array\",\n" +
        "  element:   { kind: \"integer\", min: 1, max: 9 },\n" +
        "  ascending: true,\n" +
        "  expects:   \"waits in milliseconds, each at least as long as the one before it\",\n};\n",
      "var field = {\n" +
        "  kind:    \"array\",\n" +
        "  element: { kind: \"uri\" },\n" +
        "  expects: \"a JSON array of contact URIs\",\n};\n",
    ],
  },

  {
    name: "credential-check-outside-the-identity-layer",
    description:
      "A presented secret verified where the failure budget for it is not spent. This " +
      "server authenticates two identity spaces and each has one entry point that owns its " +
      "budget: an account password reaches store.accounts.authenticate, and a domain-scoped " +
      "sending credential reaches the mail layer's credential entry point, which reads the " +
      "budget before the verify and records the outcome after it. A second place that " +
      "checks the same secret answers the same question with none of that: the guesses it " +
      "takes cost the attacker nothing, and the budget the other surfaces enforce is a " +
      "bound the attacker walks around by picking the surface that does not have it. The " +
      "two arms are the two spaces. A password verification outside the identity layer is " +
      "one; a credential verified in a function that records no failure against it is the " +
      "other, and the second is the one a new transport reintroduces, because reaching the " +
      "registry directly looks like composition rather than like a second front door. " +
      "Route the check through the entry point instead, so there is one budget rather than " +
      "one per caller.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var out = IDENTITY_LAYER_RE.test(file.rel)
        ? []
        : _lineMatcher(/\.auth\.password\.verify\s*\(/, "code")(file);
      return out.concat(_credentialVerifiedWithoutABudget(file));
    },
    red: [
      { as:   "lib/web/index.js",
        text: "async function reauth(row, supplied) {\n" +
              "  return b.auth.password.verify(row.passwordHash, supplied);\n}\n" },
      { as:   "bin/blamepost.js",
        text: "var ok = await b.auth.password.verify(stored, typed);\n" },
      { as:   "lib/web/index.js",
        text: "async function sendRoute(req, res) {\n" +
              "  var presented = readBearer(req);\n" +
              "  var verdict = await store.credentials.verify(presented);\n" +
              "  if (!verdict || verdict.ok !== true) { refuse(res, 401); return; }\n" +
              "  await relay(res, verdict);\n}\n" },
    ],
    green: [
      { as:   "lib/store/accounts.js",
        text: "var matched = await b.auth.password.verify(row.passwordHash, password);\n" },
      { as:   "lib/web/index.js",
        text: "var verdict = await store.accounts.authenticate({\n" +
              "  address: address, password: password, source: peer });\n" },
      { as:   "lib/mail/listeners.js",
        text: "async function checkCredential(registry, secret) {\n" +
              "  var standing = await budget.check(id);\n" +
              "  if (standing.locked === true) return { ok: false };\n" +
              "  var verdict = await registry.credentials.verify(secret);\n" +
              "  if (!verdict || verdict.ok !== true) {\n" +
              "    await budget.recordFailure(id);\n" +
              "    return { ok: false };\n  }\n" +
              "  await budget.recordSuccess(id);\n" +
              "  return { ok: true };\n}\n" },
      { as:   "lib/web/index.js",
        text: "async function sendRoute(req, res) {\n" +
              "  var checked = await checkCredential(store.credentials, {\n" +
              "    secret: readBearer(req), source: peer });\n" +
              "  if (checked.ok !== true) { refuse(res, 401); return; }\n}\n" },
    ],
  },

  {
    name: "secret-sealed-without-a-purpose",
    description:
      "A long-lived secret written to the data volume through the vault's plain seal. That " +
      "seal binds a value to the volume and to nothing else, so every sealed value on one " +
      "volume opens in place of every other: a provider token dropped into the signing-key " +
      "folder opens as a signing key, and a key belonging to one selector opens as another " +
      "selector's. The reader learns only that a server holding this volume's vault key " +
      "wrote the value, which is not the question it is asking. Seal through b.vault.aad " +
      "with a context naming the purpose and the thing the value belongs to, and open it " +
      "under the same context, so a value sealed as anything else does not open at all. A " +
      "seal whose own function derives the plaintext's digest is a content-addressed write " +
      "and is not this: the file name is the hash of what it carries and the read recomputes " +
      "it, so the name places the value and the seal is not asked to.",
    dirs: ["lib", "bin"],
    scan: _sealedWithoutItsPurpose,
    red: [
      { as:   "lib/mail/dkim.js",
        text: "async function _writeKey(target, privateKeyPem) {\n" +
              "  await b.atomicFile.write(target, vault.seal(privateKeyPem), " +
              "{ fileMode: 0o600 });\n}\n" },
      { as:   "lib/store/credentials.js",
        text: "var stored = vault.seal(token);\n" },
    ],
    green: [
      { as:   "lib/mail/dkim.js",
        text: "async function _writeKey(target, privateKeyPem, context) {\n" +
              "  await b.atomicFile.write(target, vault.aad.seal(privateKeyPem, context), " +
              "{ fileMode: 0o600 });\n}\n" },
      { as:   "lib/mail/mailbox.js",
        text: "function _writeBlob(raw) {\n" +
              "  var digest = b.crypto.sha3Hash(raw);\n" +
              "  b.atomicFile.writeSync(_blobPath(digest), " +
              "vault.seal(raw.toString(\"base64\")), { fileMode: 0o600 });\n" +
              "  return digest;\n}\n" },
      { as:   "lib/mail/dkim.js",
        text: "if (typeof vault.seal !== \"function\") throw new TypeError(\"no vault\");\n" },
    ],
  },

  {
    name: "sealed-value-opened-without-establishing-its-form",
    description:
      "A stored value handed to the vault's plain open by a reader that never asked which " +
      "form it is in. The vault returns a value carrying no seal exactly as it found it " +
      "rather than refusing it, so the contents of a file nothing here wrote come back from " +
      "the open and are used as though they had been unsealed. A value bound to a context " +
      "through b.vault.aad does not open this way at all, and it is the binding that " +
      "separates one sealed value on a volume from every other. Ask first: branch on " +
      "b.vault.aad.isAadSealed and open the bound form under its own context, or test the " +
      "seal prefix at offset zero when the value was sealed by a framework tool outside " +
      "this server and carries no context of ours. Either way the reader knows what it is " +
      "holding before it opens it.",
    dirs: ["lib", "bin"],
    scan: _openedWithoutEstablishingItsForm,
    red: [
      { as:   "lib/mail/mailbox.js",
        text: "function _readBlob(digest) {\n" +
              "  var sealed = b.atomicFile.readSync(_blobPath(digest), { encoding: \"utf8\" });\n" +
              "  var opened = vault.unseal(sealed);\n" +
              "  return Buffer.from(opened, \"base64\");\n}\n" },
      { as:   "lib/store/blobs.js",
        text: "function _digestFault(digest, path) {\n" +
              "  var sealed = b.atomicFile.readSync(path, { encoding: \"utf8\" });\n" +
              "  var raw = Buffer.from(vault.unseal(sealed), \"base64\");\n" +
              "  return b.crypto.sha3Hash(raw) === digest ? null : \"mismatch\";\n}\n" },
    ],
    green: [
      { as:   "lib/mail/mailbox.js",
        text: "function _readBlob(digest) {\n" +
              "  var sealed = b.atomicFile.readSync(_blobPath(digest), { encoding: \"utf8\" });\n" +
              "  var opened = vault.aad.isAadSealed(sealed)\n" +
              "    ? vault.aad.unseal(sealed, _bodySealContext(digest))\n" +
              "    : vault.unseal(sealed);\n" +
              "  return Buffer.from(opened, \"base64\");\n}\n" },
      { as:   "lib/index.js",
        text: "function _keyMaterial(keyFile) {\n" +
              "  var keyPem = _readPem(keyFile);\n" +
              "  if (keyPem.indexOf(SEALED_PEM_PREFIX) === 0) {\n" +
              "    keyPem = vault.unseal(keyPem).toString(\"utf8\");\n  }\n" +
              "  return keyPem;\n}\n" },
      { as:   "lib/dns/index.js",
        text: "function _readToken(sealedToken) {\n" +
              "  return vault.aad.unseal(sealedToken, TOKEN_SEAL_CONTEXT);\n}\n" },
    ],
  },

  {
    name: "audit-written-before-the-erasure-it-describes",
    description:
      "An audit row emitted before the hard erase it reports on, in the same function. The " +
      "outcome is not known yet at that point: eraseHard refuses a subject under a " +
      "preservation order and refuses a table behind a dual-control gate, so the row can " +
      "describe a destruction that never happens. The audit chain is hash-linked and " +
      "append-only, which makes that claim one no later row can retract, and an auditor " +
      "reading it is told a mailbox was erased on a date it was not. It is also the ordering " +
      "that hides a partial erasure: a call that records first and then destroys several rows " +
      "reports one settled outcome for a sequence that can stop halfway. Erase first, then " +
      "record what actually went, counting the rows the erase reported.",
    dirs: ["lib", "bin"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out = [];
      // One emit covering several erases in the same body is one defect,
      // so the emit offset is what is reported and what is deduplicated.
      var reported = Object.create(null);
      ERASE_HARD_RE.lastIndex = 0;
      var m;
      while ((m = ERASE_HARD_RE.exec(mask)) !== null) {
        var span = _enclosingFunctionSpan(mask, m.index);
        if (!span) continue;
        // Only the part of the body that runs before this erase. An emit
        // after it is the settled order and is what the fix looks like.
        var before = mask.slice(span.start, m.index);
        // The nearest emit above the erase, not the first one in the
        // body: a verb with an early-returning branch emits there too,
        // and pointing at that line sends the reader to the wrong half
        // of the function.
        // Built from the whole file rather than from the slice, so the
        // emit names this file binds to the store's writer are in it
        // even when the require sits above the function being read.
        var emitRe = _auditEmitRe(mask);
        var emit = null;
        var seen;
        while ((seen = emitRe.exec(before)) !== null) {
          if (_reachesLater(mask, span.start + seen.index, m.index)) emit = seen;
        }
        if (!emit) continue;
        var at = span.start + emit.index;
        if (reported[at] === 1) continue;
        reported[at] = 1;
        out.push(_atOffset(file, at,
          "an audit row is written before the eraseHard it describes, so it records an " +
          "outcome that is not settled yet"));
      }
      return out;
    },
    red: [
      "async function remove(row, reason) {\n" +
        "  await b.audit.record({\n" +
        "    action: \"account.destroyed\", outcome: \"success\", reason: reason,\n" +
        "  });\n" +
        "  return b.db.eraseHard(ACCOUNTS, row._id, { reason: reason, subjectId: row.address });\n" +
        "}\n",
      "function purge(row, reason) {\n" +
        "  b.audit.safeEmit({ action: \"alias.destroyed\", outcome: \"success\" });\n" +
        "  b.db.eraseHard(ALIASES, row._id, { reason: reason });\n" +
        "}\n",
      // The shape the store modules are actually written in: the verb is
      // built inside a factory, so its closing brace is indented and the
      // erase sits inside a loop nested one level further in again.
      "function create(opts) {\n" +
        "  async function remove(row, reason) {\n" +
        "    await b.audit.record({ action: \"account.destroyed\", outcome: \"success\" });\n" +
        "    var rows = b.db.from(ALIASES).where({ destinationMailbox: row.address }).all();\n" +
        "    for (var i = 0; i < rows.length; i += 1) {\n" +
        "      b.db.eraseHard(ALIASES, rows[i]._id, { reason: reason });\n" +
        "    }\n" +
        "  }\n" +
        "  return { remove: remove };\n" +
        "}\n",
    ],
    green: [
      // The settled order: destroy, then report what the destruction returned.
      "async function remove(row, reason) {\n" +
        "  var result = b.db.eraseHard(ACCOUNTS, row._id, { reason: reason, subjectId: row.address });\n" +
        "  await b.audit.record({\n" +
        "    action: \"account.destroyed\", outcome: \"success\", reason: reason,\n" +
        "    metadata: { rowsErased: result.rowsDeleted },\n" +
        "  });\n" +
        "  return result;\n" +
        "}\n",
      // Two separate top-level functions.
      "async function archive(row, reason) {\n" +
        "  await b.audit.record({ action: \"account.archived\", outcome: \"success\" });\n" +
        "}\n" +
        "\n" +
        "function erase(row, reason) {\n" +
        "  return b.db.eraseHard(ACCOUNTS, row._id, { reason: reason });\n" +
        "}\n",
      // The same two, as indented siblings inside a factory. A boundary
      // that assumed a closing brace at column zero joined these into a
      // match and named the wrong verb, which is what the structural walk
      // replaces, so this fixture is the proof that it stays apart.
      "function create(opts) {\n" +
        "  async function setPassword(row, hash) {\n" +
        "    await b.audit.record({ action: \"account.password_changed\", outcome: \"success\" });\n" +
        "    return row;\n" +
        "  }\n" +
        "  async function remove(row, reason) {\n" +
        "    var result = b.db.eraseHard(ACCOUNTS, row._id, { reason: reason });\n" +
        "    await b.audit.record({ action: \"account.destroyed\", outcome: \"success\" });\n" +
        "    return result;\n" +
        "  }\n" +
        "  return { setPassword: setPassword, remove: remove };\n" +
        "}\n",
      // A verb whose reversible branch records and returns, above a
      // destructive branch that erases first. The record is earlier in
      // the text and on no path that reaches the erase.
      "async function remove(row, opts, reason) {\n" +
        "  if (opts.destroy !== true) {\n" +
        "    tables.updateRow(ACCOUNTS, row._id, { status: \"archived\" });\n" +
        "    await b.audit.record({ action: \"account.archived\", outcome: \"success\" });\n" +
        "    return { id: row._id, outcome: \"archived\" };\n" +
        "  }\n" +
        "  var result = b.db.eraseHard(ACCOUNTS, row._id, { reason: reason });\n" +
        "  await b.audit.record({ action: \"account.destroyed\", outcome: \"success\" });\n" +
        "  return result;\n" +
        "}\n",
      "async function suspend(row, reason) {\n" +
        "  await b.audit.record({ action: \"account.suspended\", outcome: \"success\" });\n" +
        "}\n",
    ],
  },

  {
    name: "submission-relay-without-a-header-identity-binding",
    description:
      "A file that composes the authenticated submission listener without also carrying the " +
      "refusal that binds the header identity. The envelope sender and the From header are " +
      "different addresses and only one of them is bound by the listener: the framework " +
      "compares MAIL FROM against the authenticated account's mailbox set and never reads the " +
      "message. So an account that passes the envelope binding can still write any address it " +
      "likes into From, and From is the address a person actually reads. Worse, the relay " +
      "signs on the way out, so the forged header leaves under the hosting domain's own key, " +
      "arrives aligned and passes DMARC on this server's authority rather than in spite of " +
      "it. Between two accounts on one server that is impersonation with a valid password in " +
      "front of it. Compute the addresses the authenticated account may write from the store " +
      "that already answers who an address belongs to, and refuse the message before it is " +
      "signed or relayed.",
    dirs: ["lib"],
    // The anchor is the framework primitive, which is a frozen contract:
    // renaming it is an upstream break and deleting it removes the
    // hazard entirely. The good token is the refusal's stable error
    // code rather than the name of whatever function raises it, so
    // renaming the binding leaves the detector silent and deleting the
    // binding makes it fire. Both are read out of code rather than out
    // of prose, so a comment quoting either can neither silence it nor
    // trip it.
    scan: function (file) {
      var composesSubmission = null;
      var carriesBinding     = false;
      for (var i = 0; i < file.lines.length; i++) {
        var code = _codeOf(file.lines[i]);
        if (!code) continue;
        if (/listeners\/from-header-not-owned/.test(code)) carriesBinding = true;
        if (composesSubmission === null &&
            /\bb\s*\.\s*mail\s*\.\s*server\s*\.\s*submission\s*\.\s*create\s*\(/.test(code)) {
          composesSubmission = { file: file.rel, line: i + 1, content: file.lines[i].trim() };
        }
      }
      if (composesSubmission === null || carriesBinding) return [];
      return [composesSubmission];
    },
    red: [
      "function _buildSubmission(implicitTls) {\n" +
        "  return b.mail.server.submission.create({\n" +
        "    identityBinding: \"strict\",\n" +
        "    agent: _submissionAgent(),\n" +
        "  });\n" +
        "}\n",
      // The binding named only in prose. A comment describing the rule
      // is not the rule, and this is the shape a half-finished revert
      // leaves behind.
      "// refuses a From the account does not own with listeners/from-header-not-owned\n" +
        "function _buildSubmission() {\n" +
        "  return b.mail.server.submission.create({ identityBinding: \"strict\" });\n" +
        "}\n",
    ],
    green: [
      "function _refuseUnownedFrom(actor, body) {\n" +
        "  var err = new Error(\"this account may not write that From header\");\n" +
        "  err.code = \"listeners/from-header-not-owned\";\n" +
        "  throw err;\n" +
        "}\n" +
        "function _buildSubmission(implicitTls) {\n" +
        "  return b.mail.server.submission.create({ agent: _submissionAgent() });\n" +
        "}\n",
      // A file that never composes the submission listener is not this
      // detector's business, whatever else it does with a message.
      "function relay(body) {\n  return delivery.send({ rfc822: body });\n}\n",
    ],
  },

  {
    name: "db-open-without-the-single-opener-lock",
    description:
      "A file that opens the database without also carrying the refusal that keeps a second " +
      "WRITER out of the volume. Opening for writing is not a read. The database is " +
      "encrypted at rest, so the framework decrypts the whole file into a working copy of " +
      "its own and writes that copy back on a timer and at shutdown. Two writers cannot see " +
      "each other's copy, so both write the whole volume back and whichever writes last " +
      "replaces the other's entirely: every message the loser accepted since it started is " +
      "gone, the window is bounded by neither process's lifetime, and what is left on disk " +
      "is internally consistent and simply missing that mail, so nothing downstream " +
      "notices. Open the volume in one place, take the lock before anything decrypts, and " +
      "refuse the second writer by name. A read-only open is not a second writer and takes " +
      "no lock, but it belongs in that same one place, because the file that opens the " +
      "database is the file that has to hold both rules.",
    dirs: ["lib", "bin"],
    // The anchor is the framework primitive, which is a frozen contract:
    // renaming it is an upstream break and deleting it removes the
    // hazard. The good token is the refusal's stable error code rather
    // than the name of whatever function raises it, so renaming the
    // lock leaves the detector working and deleting the lock makes it
    // fire. Both are read out of code rather than out of prose, so a
    // comment quoting either cannot silence it or trip it.
    scan: function (file) {
      var opensDatabase = null;
      var carriesRefusal = false;
      for (var i = 0; i < file.lines.length; i++) {
        var code = _codeOf(file.lines[i]);
        if (!code) continue;
        if (/store\/volume-in-use/.test(code)) carriesRefusal = true;
        if (opensDatabase === null && /\bb\s*\.\s*db\s*\.\s*init\s*\(/.test(code)) {
          opensDatabase = { file: file.rel, line: i + 1, content: file.lines[i].trim() };
        }
      }
      if (opensDatabase === null || carriesRefusal) return [];
      return [opensDatabase];
    },
    red: [
      "async function open(cfg) {\n" +
        "  await b.db.init({ dataDir: cfg.dataDir, atRest: \"encrypted\", schema: TABLES });\n" +
        "  return handle;\n" +
        "}\n",
      // The lock named only in prose. A comment describing the rule is
      // not the rule, and this is the shape a half-finished revert
      // leaves behind.
      "// takes the volume lock first, refusing with store/volume-in-use\n" +
        "async function open(cfg) {\n" +
        "  await b.db.init({ dataDir: cfg.dataDir, schema: TABLES });\n" +
        "}\n",
    ],
    green: [
      "function _holdVolume(dataDir) {\n" +
        "  throw err(\"store/volume-in-use\", \"another process holds \" + dataDir);\n" +
        "}\n" +
        "async function open(cfg) {\n" +
        "  _holdVolume(cfg.paths.dataDir);\n" +
        "  await b.db.init({ dataDir: cfg.paths.dataDir, schema: TABLES });\n" +
        "}\n",
      // A file that never opens the database is not this detector's
      // business, whatever else it does with the volume.
      "function close() {\n  b.db.close();\n}\n",
    ],
  },

  {
    name: "shutdown-that-closes-the-volume-without-anchoring-the-trail",
    description:
      "An ordered shutdown that closes the store without first flushing the audit trail and " +
      "anchoring it. Two things are lost, and neither reports itself. Buffered rows live in " +
      "memory until a flush, so a stop takes with it the last events before it and every " +
      "event the stop itself produces, which are the rows an incident asks about first. And " +
      "the record beside the volume, which is what a rewritten chain has to get past, " +
      "advances only when a checkpoint is written: the one the framework writes at boot " +
      "anchors the trail as it stood when the server STARTED, and nothing advances it while " +
      "the server runs. A server up for a month and then stopped leaves a month of rows past " +
      "the last anchored one, every one of them rewritable on the stopped volume while the " +
      "record beside it still agrees. The framework's own close launches a final checkpoint " +
      "without waiting for it and tears the database handle down on the same tick, so that " +
      "one almost never lands. Flush, checkpoint, flush again, as a phase of its own before " +
      "the store closes: the second flush is not a duplicate, because writing the checkpoint " +
      "is itself an audited act and produces the last event of the process.",
    dirs: ["lib", "bin"],
    // Anchored on two frozen contracts rather than on any name in this
    // repository. The hazard is the framework's shutdown composer, and
    // the remedy is the framework's checkpoint call; renaming either is
    // an upstream break and deleting the composer removes the hazard.
    // The phase names, the function that closes the store and the
    // variable holding it can all be renamed freely without silencing
    // this. Both tokens are read out of code rather than prose, so a
    // comment quoting either cannot trip it or quiet it.
    scan: function (file) {
      var mask = _maskOf(file);
      var re   = /\bb\s*\.\s*appShutdown\s*\.\s*create\s*\(/g;
      var out  = [];
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(mask)) !== null) {
        var openParen = m.index + m[0].length - 1;
        var close     = _matchingBracket(mask, openParen);
        if (close === -1) continue;
        var body = mask.slice(openParen, close);
        // A shutdown with no store to close is not this detector's
        // business. What makes one the hazard is a phase that closes
        // something, because that is the phase the trail has to be
        // written down before.
        if (!/\.\s*close\s*\(/.test(body)) continue;
        if (/\bb\s*\.\s*audit\s*\.\s*checkpoint\s*\(/.test(body)) continue;
        out.push(_atOffset(file, m.index,
          "b.appShutdown.create() closes the volume with no phase that anchors the trail"));
      }
      return out;
    },
    red: [
      "b.appShutdown.create({\n" +
        "  phases: [\n" +
        "    { name: \"listeners\", run: function () { return server.stop(); } },\n" +
        "    { name: \"store\",     run: function () { return store.close(); } },\n" +
        "  ],\n" +
        "});\n",
      // The flush without the anchor. Rows reach disk and the record
      // beside the volume still names the counter the boot left it at,
      // so everything written since the server started stays outside
      // what the record can answer for.
      "b.appShutdown.create({\n" +
        "  phases: [\n" +
        "    { name: \"audit\", run: function () { return b.audit.flush(); } },\n" +
        "    { name: \"store\", run: function () { return store.close(); } },\n" +
        "  ],\n" +
        "});\n",
    ],
    green: [
      "b.appShutdown.create({\n" +
        "  phases: [\n" +
        "    { name: \"listeners\", run: function () { return server.stop(); } },\n" +
        "    { name: \"audit\",     run: async function () {\n" +
        "      await b.audit.flush();\n" +
        "      await b.audit.checkpoint({ skipIfUnchanged: true });\n" +
        "      await b.audit.flush();\n" +
        "    } },\n" +
        "    { name: \"store\",     run: function () { return store.close(); } },\n" +
        "  ],\n" +
        "});\n",
      // A shutdown that closes nothing on the volume has no trail to
      // anchor, whatever else it drains.
      "b.appShutdown.create({\n" +
        "  phases: [{ name: \"listeners\", run: function () { return server.stop(); } }],\n" +
        "});\n",
    ],
  },

  {
    name: "repeating-timer-armed-with-no-way-to-disarm-it",
    description:
      "A repeating timer whose handle is discarded, or kept in a variable nothing ever stops. " +
      "The framework's repeating timer is fire-and-forget and unreferenced, so neither the " +
      "process nor any test notices one that was never disarmed: it simply keeps firing. What " +
      "it fires into is the problem. Every timer in this server runs beside a store, and an " +
      "ordered shutdown drains the listeners, writes the trail down and then CLOSES that " +
      "store, so a tick arriving after the close reads a database that is gone and a tick " +
      "arriving during it races the phase it overlaps. A sweep that outlives its server " +
      "retries deliveries against a closed spool, and an anchor that outlives one writes a " +
      "checkpoint over a volume another process may already hold. Hold the handle in a " +
      "variable and stop it on the way down, in the same module that armed it, or return it " +
      "so the caller that will stop it owns the lifecycle.",
    dirs: ["lib"],
    // Anchored on the framework's own verb rather than on any name here.
    // Renaming it is an upstream break and deleting the call removes the
    // hazard, so the anchor cannot go silently green. The receiver is
    // optional so a file that binds the framework's async helper to a
    // local reads the same as one reaching it through the handle, and the
    // variable holding the timer is READ from the assignment rather than
    // assumed, because a matcher spelling `sweepTimer` stops seeing the
    // fifth timer the moment somebody names it something else.
    scan: function (file) {
      var mask = _maskOf(file);
      var re   = /(?:\b[A-Za-z_$][\w$]*\s*\.\s*)?safeAsync\s*\.\s*repeating\s*\(/g;
      var out  = [];
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(mask)) !== null) {
        var before = mask.slice(Math.max(0, m.index - 160), m.index);
        // Handed straight back to the caller. The lifecycle belongs to
        // whoever receives it, and that caller is scanned in its own
        // right, so there is nothing this site could do differently.
        if (/\breturn\s*$/.test(before)) continue;
        var target = /([A-Za-z_$][\w$]*)\s*=\s*$/.exec(before);
        if (target === null) {
          out.push(_atOffset(file, m.index,
            "a repeating timer whose handle is discarded, so nothing can ever stop it"));
          continue;
        }
        var stops = new RegExp("\\b" + target[1] + "\\s*\\.\\s*stop\\s*\\(");
        if (stops.test(mask)) continue;
        out.push(_atOffset(file, m.index,
          "the repeating timer held in " + target[1] + " is never stopped, so it outlives " +
          "the server that armed it and fires into a store that has closed"));
      }
      return out;
    },
    red: [
      // The handle discarded outright.
      "function start() {\n" +
        "  b.safeAsync.repeating(sweep, SWEEP_MS, { name: \"outbound-sweep\" });\n" +
        "}\n",
      // Held, and stopped nowhere.
      "var sweepTimer = null;\n" +
        "function start() {\n" +
        "  sweepTimer = b.safeAsync.repeating(sweep, SWEEP_MS, { unref: true });\n" +
        "}\n" +
        "function stop() {\n" +
        "  sweepTimer = null;\n" +
        "}\n",
      // Reached through a local binding of the framework's async helper,
      // so the finding does not rest on the receiver being spelled `b`.
      "var safeAsync = b.safeAsync;\n" +
        "var anchorTimer = null;\n" +
        "function start() {\n" +
        "  anchorTimer = safeAsync.repeating(anchor, ANCHOR_MS, { unref: true });\n" +
        "}\n",
    ],
    green: [
      "var sweepTimer = null;\n" +
        "function start() {\n" +
        "  sweepTimer = b.safeAsync.repeating(sweep, SWEEP_MS, { unref: true });\n" +
        "}\n" +
        "function stop() {\n" +
        "  if (sweepTimer === null) return;\n" +
        "  sweepTimer.stop();\n" +
        "  sweepTimer = null;\n" +
        "}\n",
      // Handed to the caller, which is where the lifecycle then lives.
      "function armSweep() {\n" +
        "  return b.safeAsync.repeating(sweep, SWEEP_MS, { unref: true });\n" +
        "}\n",
      // A file with no repeating timer in it is not this detector's
      // business, whatever else it schedules.
      "function later(fn) {\n  return setTimeout(fn, 10);\n}\n",
    ],
  },

  {
    name: "wire-refusal-answered-as-a-success",
    description:
      "A catch block that answers the peer with its protocol's SUCCESS reply and does not " +
      "re-raise. Every wire protocol here separates the two verdicts and clients act on the " +
      "difference: a refusal is a command that failed and the person reading the client sees " +
      "one, while a success is the server saying it did the work. Turning an error into a " +
      "success reports work that did not happen, and the reply carries whatever the handler " +
      "had built by then, which is usually nothing: an IMAP SEARCH that could not read the " +
      "folder answers `* SEARCH` with no numbers and a tagged OK, a LIST that could not read " +
      "the folder table answers an empty mailbox list, a POP3 commit that removed none of the " +
      "messages answers +OK. A client cannot tell any of those from an empty mailbox, so it " +
      "renders one, and nothing anywhere records that the question was never answered. Write " +
      "the refusal the protocol defines for the condition, or re-raise and let the caller " +
      "write it.",
    dirs: ["lib", "bin"],
    // The anchor is a frozen contract rather than a name: `OK`, `+OK`
    // and `250` are the success words RFC 9051, RFC 1939, RFC 5804 and
    // RFC 5321 define, so they survive every rename and disappear only
    // when the reply itself does. The good token is a re-raise, which is
    // the one thing that makes a catch block not this shape whatever
    // else it writes. Comments are masked out before the match, so a
    // comment quoting a reply line can neither trip it nor silence it.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      var re   = /\bcatch\s*(?:\([^)]{0,120}\))?\s*\{/g;
      // A protocol success word, at the front of a string literal. The
      // quote is part of the match so a bare identifier spelled `ok` is
      // not one, and the leading space is optional because a tagged
      // IMAP reply is written as the tag plus " OK ...". The mask keeps
      // string CONTENT while blanking the brackets inside it, so this
      // reads the reply the handler would write.
      var SUCCESS = /"[ \t]*(?:\+OK\b|OK[ "]|250[ -])/;
      var m;
      re.lastIndex = 0;
      while ((m = re.exec(mask)) !== null) {
        var open  = m.index + m[0].length - 1;
        var close = _matchingBracket(mask, open);
        if (close === -1) continue;
        var body = mask.slice(open, close);
        // Re-raising ends the operation as a failure however the caller
        // spells the reply, so the block is not answering anything.
        if (/\bthrow\b/.test(body)) continue;
        if (!SUCCESS.test(body)) continue;
        out.push(_atOffset(file, m.index,
          "an error is caught here and answered with a protocol success"));
      }
      return out;
    },
    red: [
      "function search(tag) {\n" +
        "  try { return scan(); }\n" +
        "  catch (e) {\n" +
        "    write(\"* SEARCH\");\n" +
        "    write(tag + \" OK SEARCH completed\");\n" +
        "  }\n}\n",
      "async function commit(drop) {\n" +
        "  try { await expunge(drop); }\n" +
        "  catch (_e) { socket.write(\"+OK maildrop emptied\\r\\n\"); }\n}\n",
      "async function handoff(inbound) {\n" +
        "  try { await deliver(inbound); }\n" +
        "  catch (e) { reply(\"250 2.0.0 accepted\"); }\n}\n",
    ],
    green: [
      // The refusal the protocol defines for the condition.
      "function search(tag) {\n" +
        "  try { return scan(); }\n" +
        "  catch (e) { write(tag + \" NO SEARCH could not read the mailbox\"); }\n}\n",
      // Re-raised, so whatever writes the reply writes a failure.
      "function search(tag) {\n" +
        "  try { return scan(); }\n" +
        "  catch (e) { record(e); throw e; }\n}\n",
      // The success written on the path where the work actually
      // happened, which is not inside a catch.
      "function search(tag) {\n" +
        "  var hits = scan();\n" +
        "  write(\"* SEARCH \" + hits.join(\" \"));\n" +
        "  write(tag + \" OK SEARCH completed\");\n}\n",
      // An observability sink that drops by design writes nothing to
      // the peer at all.
      "function note(row) {\n" +
        "  try { audit.emit(row); }\n" +
        "  catch (_e) { /* drop-silent by design: the audit sink must not fail the delivery */ }\n}\n",
    ],
  },

  {
    name: "spool-attempt-without-exclusive-claim",
    description:
      "A module that reads a stored message back off the volume and hands it to the delivery " +
      "composer, without anywhere in it taking the framework's exclusive-create lock. Draining " +
      "the outbound spool is the one mutating operation that does not open the database, which " +
      "is deliberate: it has to keep working on a server whose volume will not open. The price " +
      "is that the single-opener lock never sees it, so two processes can walk the same entries " +
      "at once and attempt one message twice, or move it out from under an attempt already in " +
      "flight. The guard is a claim on the individual entry, and it has to be a fact the kernel " +
      "decided rather than a value somebody wrote into a file: a gate that reads a recorded " +
      "claim fails open on exactly the occasion the record is wrong, which is a crash. " +
      "b.appShutdown.pidLock is that fact, because it creates the claim exclusively and probes " +
      "the recorded holder for liveness before reaping it. Anchored on the framework export and " +
      "on the composer's raw-bytes envelope key, so neither a renamed helper nor a reworded " +
      "comment can quietly retire it.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      // The claim, taken anywhere in the module that owns the spool.
      // Module scope rather than function scope because the claim is
      // taken by a helper and spent by the loop, which are two bodies.
      if (/\bappShutdown\s*\.\s*pidLock\b/.test(mask)) return [];
      var bodies = _functionBodies(mask);
      var out    = [];
      bodies.forEach(function (body) {
        // A message read back off the volume.
        var read = _matchesIn(mask, bodies, body,
          /\batomicFile\s*\.\s*read(?:Json)?\s*\(/g);
        if (read.length === 0) return;
        // Handed to the delivery composer. `rfc822` is the key the
        // composer's envelope carries raw message bytes under, which is
        // a frozen contract of that surface rather than a local name.
        if (_matchesIn(mask, bodies, body, /\brfc822\s*:/g).length === 0) return;
        out.push(_atOffset(file, read[0].offset,
          "a spooled message is read off disk and re-sent with no exclusive claim on the entry"));
      });
      return out;
    },
    red: [
      "async function runDue(now) {\n" +
        "  var entries = await listSpool();\n" +
        "  for (var i = 0; i < entries.length; i += 1) {\n" +
        "    var body = await b.atomicFile.read(bodyPath(entries[i].id), { maxBytes: CAP });\n" +
        "    await deliver({ from: entries[i].from, to: [entries[i].recipient], rfc822: body });\n" +
        "  }\n}\n",
      // The advisory form: a claim read out of the descriptor rather
      // than taken from the kernel. It fails open on a crash, which is
      // the occasion it exists for.
      "async function retryOne(id) {\n" +
        "  var entry = await b.atomicFile.readJson(descriptorPath(id));\n" +
        "  if (entry.claimedBy) return null;\n" +
        "  return await deliver({ from: entry.from, to: [entry.recipient], rfc822: entry.body });\n}\n",
    ],
    green: [
      // The claim taken from the framework's exclusive-create lock, in
      // a helper the loop calls.
      "function claim(id) {\n" +
        "  var lock = b.appShutdown.pidLock(claimPath(id));\n" +
        "  try { lock.acquire(); } catch (_e) { return null; }\n" +
        "  return lock;\n}\n" +
        "async function runDue(now) {\n" +
        "  var entries = await listSpool();\n" +
        "  for (var i = 0; i < entries.length; i += 1) {\n" +
        "    var held = claim(entries[i].id);\n" +
        "    if (held === null) continue;\n" +
        "    var body = await b.atomicFile.read(bodyPath(entries[i].id), { maxBytes: CAP });\n" +
        "    await deliver({ from: entries[i].from, to: [entries[i].recipient], rfc822: body });\n" +
        "    held.release();\n" +
        "  }\n}\n",
      // A module that composes an envelope without ever reading one
      // back off the volume has no entry to claim.
      "async function relay(body) {\n" +
        "  return await deliver({ from: sender, to: recipients, rfc822: body });\n}\n",
      // And one that reads the volume without re-sending anything.
      "async function describeOne(id) {\n" +
        "  return await b.atomicFile.readJson(descriptorPath(id), { maxBytes: CAP });\n}\n",
    ],
  },

  {
    name: "dns-absence-read-from-a-code-the-resolver-does-not-send",
    description:
      "A DNS error classified against `resolver/nxdomain-or-error`, which the vendored resolver " +
      "does not raise. It reports a name that does not exist under `resolver/nxdomain` and every " +
      "other non-zero RCODE under `resolver/query-failed`, and the two are separate on purpose: " +
      "a name nobody published is the ordinary answer for a policy record, while a query nobody " +
      "answered is not an answer at all. A comparison against the retired code matches neither, " +
      "so absence stops being recognized and the commonest state of a zone reads as a broken " +
      "resolver: the posture report sends an operator to look at a resolver that is working, and " +
      "an SPF mechanism naming a host that does not exist defers inbound mail instead of " +
      "evaluating. A test fixture that raises the retired code is the same defect wearing the " +
      "other hat, and worse, because it makes the production reader look correct. Classify " +
      "against the codes the resolver actually sends, and never fold `resolver/query-failed` " +
      "into absence: a policy that disappears when its lookup breaks is a policy an attacker " +
      "removes by breaking the lookup. Anchored on the retired code in a `.code` comparison or " +
      "assignment, so a line asserting the code is GONE is not itself a finding.",
    dirs: ["lib", "bin", "test", "scripts"],
    scan: _lineMatcher(
      /\.code\s*(?:={2,3}|!={1,2}|=)\s*["']resolver\/nxdomain-or-error["']/, "code"),
    red: [
      "function isAbsence(err) {\n" +
        "  if (err.code === \"resolver/nxdomain-or-error\") return true;\n" +
        "  return false;\n}\n",
      // The fixture half: a mock raising a code nothing produces.
      "function nxdomain(name) {\n" +
        "  var err = new Error(\"query: upstream RCODE=3 for \" + name);\n" +
        "  err.code = \"resolver/nxdomain-or-error\";\n" +
        "  return err;\n}\n",
    ],
    green: [
      "function isAbsence(err) {\n" +
        "  if (err.code === \"resolver/nxdomain\") return true;\n" +
        "  return false;\n}\n",
      "function nxdomain(name) {\n" +
        "  var err = new Error(\"query: upstream RCODE=3 for \" + name);\n" +
        "  err.code = \"resolver/nxdomain\";\n" +
        "  return err;\n}\n",
      // A gate that reads the vendored source to check the code is gone
      // names it without classifying anything against it.
      "function theCodeIsRetired(source) {\n" +
        "  return source.indexOf(\"resolver/nxdomain-or-error\") === -1;\n}\n",
    ],
  },
  {
    name: "dns-read-awaited-without-a-budget",
    description:
      "A DNS record read awaited straight off a resolver handle. The handle is not this " +
      "server's to reason about: an operator pins one, and what it does when a question " +
      "cannot be answered is its own business. A handle that REJECTS is harmless, because " +
      "every reader in this tree already has a verdict for a lookup that failed. A handle " +
      "that ACCEPTS the question and never answers it is the one shape with no verdict at " +
      "all, and it is ordinary rather than exotic: a nameserver that takes the query and " +
      "drops the response, a firewall that blackholes the reply, and a handle written " +
      "around an internal service that has stopped answering all present exactly that way. " +
      "Awaited with no bound, the wait ends only when something else gives up. On a mail " +
      "session that is an idle timeout that cuts the socket with nothing said, and a " +
      "handful of such connections from one source occupy the server without sending a " +
      "byte of mail. On a posture report there is nothing else at all, so the command and " +
      "the browser request that asked for it stay open for as long as the resolver stays " +
      "silent. Hold a budget over the read instead: compose " +
      "blamepost.mail.posture.withinDnsBudget around the call rather than awaiting the " +
      "call itself. A lookup that runs out of budget is a lookup that FAILED and is never " +
      "folded into 'this name publishes nothing': a policy that disappears when its query " +
      "stalls is a policy an attacker removes by stalling the query.",
    dirs: ["lib", "bin"],
    // Anchored on the resolver's own typed reader names, which are a
    // frozen contract rather than a symbol somebody may rename, and on
    // the shape that hides the wait: `await` applied to the read itself.
    // The bounded spelling hands the read to the budget and awaits that,
    // so it never writes `await <handle>.query<Type>(` and needs no
    // negative lookahead to stay silent.
    scan: _lineMatcher(
      new RegExp("await\\s+[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*" +
        "\\.query(?:Dnskey|Cname|Https|Aaaa|Tlsa|Svcb|Srv|Txt|Ptr|Mx|Ns|Ds|A)\\s*\\("),
      "code"),
    red: [
      "async function _txtRecords(resolver, name) {\n" +
        "  var answer = await resolver.queryTxt(name);\n" +
        "  return (answer && answer.rrs) || [];\n}\n",
      // A second record type through a second reader. The TXT reader is
      // composed from one place and the others are not, so a bound
      // proven on TXT proves nothing about them.
      "async function _checkTlsa(resolver, qname) {\n" +
        "  var answer = await resolver.queryTlsa(qname);\n" +
        "  return ((answer && answer.rrs) || []).length;\n}\n",
      // The handle reached through a property rather than through a
      // local, which is the spelling a matcher bound to a bare
      // identifier goes quiet on.
      "async function _reverseName(deps, arpa) {\n" +
        "  var answer = await deps.dns.resolver.queryPtr(arpa);\n" +
        "  return (answer && answer.rrs) || [];\n}\n",
    ],
    green: [
      // The budget held over the call, which is what ends the wait.
      "async function _txtRecords(resolver, name, budgetMs) {\n" +
        "  var answer = await withinDnsBudget(resolver.queryTxt(name), budgetMs, \"txt\");\n" +
        "  return (answer && answer.rrs) || [];\n}\n",
      // The budget held over a composed reader rather than over the call
      // inside it. The read is handed to the wrapper, so the function
      // that makes it never awaits the handle directly.
      "function _readerOver(resolver, budgetMs) {\n" +
        "  return function (qname) {\n" +
        "    return withinDnsBudget(resolver.queryTxt(qname), budgetMs, \"txt \" + qname);\n" +
        "  };\n}\n",
      // A database read is not a DNS read. The generic two-argument
      // `query` form is deliberately outside this pattern, which is
      // declared in PATTERN_NARROWINGS with what carries the coverage.
      "async function _rows(db, sql) {\n" +
        "  return await db.query(sql);\n}\n",
      // A documentation example is prose about the surface rather than a
      // read this server makes.
      "/**\n * @example\n *   var answer = await resolver.queryTxt(\"_dmarc.example.com\");\n */\n",
    ],
  },
  {
    name: "framework-method-back-filled-by-a-stand-in",
    description:
      "A handle the vendored framework built, probed for a method with `typeof`, copied with " +
      "`Object.create`, and given that same method by this repository. The shape is a stand-in " +
      "for framework surface, and it is written for a release where the surface was missing. " +
      "Two things happen when the next release ships it. The stand-in becomes dead code that " +
      "still runs, so the framework's own implementation is never the one composed. And, worse, " +
      "the framework's check that REFUSES a handle lacking the method can no longer fire, " +
      "because the probe fills the gap before anything downstream looks: a genuinely broken " +
      "handle then reaches the call as a working one, and the refusal that existed to say so is " +
      "silently unreachable. `b.mail.helo` is the case that made this a rule. It refuses a " +
      "resolver with no `queryPtr` rather than reporting a clean pass it cannot support, and a " +
      "facade supplying `queryPtr` turns that refusal back into the every-address pass it was " +
      "written to end. Compose the framework handle directly and let it refuse. A method this " +
      "APPLICATION owns is a different thing and is not matched: the shape here is a probe for " +
      "the member, then a copy, then that member supplied, all on one handle, which is a " +
      "substitution and not an extension. When a vendored release genuinely lacks something, " +
      "file it upstream and compose what does exist, so the workaround has an owner and an end.",
    dirs: ["lib", "bin"],
    scan: _contentMatcher(
      new RegExp(
        "typeof\\s+([A-Za-z_$][\\w$]*)\\.([A-Za-z_$][\\w$]*)\\s*[=!]==?\\s*[\"']function[\"']" +
        "(?:(?!\\n\\})[\\s\\S]){0,2000}?" +
        "Object\\.create\\(\\s*\\1\\s*\\)" +
        "(?:(?!\\n\\})[\\s\\S]){0,2000}?" +
        "\\.\\2\\s*=",
        "g")),
    red: [
      "function _fcrdnsResolver(resolver) {\n" +
        "  if (!resolver || typeof resolver.queryPtr === \"function\") return resolver;\n" +
        "  var facade = Object.create(resolver);\n" +
        "  facade.queryPtr = function (qname) { return resolver.query(qname, \"PTR\"); };\n" +
        "  return facade;\n}\n",
      // The negated spelling of the same probe, which is the shape a
      // second author reaches for.
      "function _withReader(handle) {\n" +
        "  if (typeof handle.readRow !== \"function\") {\n" +
        "    var shim = Object.create(handle);\n" +
        "    shim.readRow = function (id) { return handle.read(id); };\n" +
        "    return shim;\n  }\n  return handle;\n}\n",
    ],
    green: [
      // The framework handle, composed as it is.
      "function _heloGate(localDomains) {\n" +
        "  return { evaluate: function (ctx) {\n" +
        "    return b.mail.helo.evaluate(Object.assign({}, ctx, { resolver: resolver }));\n" +
        "  } };\n}\n",
      // A facade adding a verb this application owns. Nothing probes the
      // handle for it, because the framework was never going to have it.
      "function _mount(mailStore) {\n" +
        "  var jmapStore = Object.create(mailStore);\n" +
        "  jmapStore.subscribePush = function (actor) { return _push(actor); };\n" +
        "  return jmapStore;\n}\n",
      // Probing a handle and refusing on the answer, which is the
      // opposite of substituting for it.
      "function _requireReader(handle) {\n" +
        "  if (typeof handle.queryPtr !== \"function\") {\n" +
        "    throw new TypeError(\"this resolver cannot answer PTR, so no pass can be claimed\");\n" +
        "  }\n  return handle;\n}\n",
    ],
  },
  {
    name: "operator-route-without-the-operator-gate",
    description:
      "A route under /admin registered without the middleware that establishes the caller " +
      "administers this server. Everything on that path reads or changes the whole server " +
      "rather than one mailbox: every account, every hosted domain, the outbound spool, the " +
      "signing keys, somebody else's audit trail, and the release of a sign-in budget, which " +
      "takes a defense away from a mailbox its owner did not consent for. A signed-in mailbox " +
      "owner is a signed-in caller, so the session check alone admits every account on the " +
      "server to all of it. Register the gate on the route beside the session check rather " +
      "than testing the role inside the handler: a check inside the body is one an early " +
      "return, a new branch or a second handler on the same path can be added around, and " +
      "the whole point of the middleware is that there is nowhere for the request to go if " +
      "it does not pass. Renaming the gate does not hide anything from this: the token stops " +
      "appearing on every administration route at once, so the report is every one of them " +
      "rather than silence.",
    dirs: ["lib", "bin"],
    scan: _contentMatcher(
      new RegExp(
        "router\\.(?:get|post|put|patch|delete)\\(\\s*[\"']/admin" +
        "(?:(?!requireAdmin)[^\\n]){0,240}?" +
        "(?:function\\s*\\(|\\)\\s*;)",
        "g")),
    red: [
      "function mount(router) {\n" +
        "  router.get(\"/admin/lockouts\", requireAccount, async function (req, res) {\n" +
        "    await _renderLockouts(req, res, null, 0);\n  });\n}\n",
      // The role read inside the body instead, which is the shape that
      // reads as a gate and is not one.
      "function mount(router) {\n" +
        "  router.post(\"/admin/accounts\", requireAccount, async function (req, res) {\n" +
        "    if (!req.user.isAdmin) return;\n    await _save(req);\n  });\n}\n",
      // A named handler, registered with no gate at all.
      "function mount(router) {\n" +
        "  router.get(\"/admin/queue\", requireAccount, renderQueue);\n}\n",
    ],
    green: [
      "function mount(router) {\n" +
        "  router.get(\"/admin/lockouts\", requireAccount, requireAdmin, async function (req, res) {\n" +
        "    await _renderLockouts(req, res, null, 0);\n  });\n}\n",
      "function mount(router) {\n" +
        "  router.get(\"/admin/queue\", requireAccount, requireAdmin, renderQueue);\n}\n",
      // A route that is not under /admin and is scoped to the caller's
      // own mailbox by the handle it reads through.
      "function mount(router) {\n" +
        "  router.get(\"/mail/:folder\", requireAccount, async function (req, res) {\n" +
        "    await _renderFolder(req, res);\n  });\n}\n",
    ],
  },
  {
    name: "sending-identity-derived-outside-the-one-place",
    description:
      "A second computation of which addresses an account may write as the author of a " +
      "message. The question is asked of the alias table by naming the mailbox an alias " +
      "points at, and it has exactly one answer in this server, in the module the " +
      "submission listener refuses a message from. Three surfaces read that answer: the " +
      "listener measures a message's From and Sender against it before anything signs or " +
      "relays the message, the browser compose form offers it as a choice, and JMAP " +
      "Identity/get publishes it to a client. A second derivation is how those stop " +
      "agreeing, and the disagreement is silent in both directions: a surface that " +
      "computes a wider set offers an address the wire then refuses, and one that " +
      "computes a narrower set hides an address the account holds. The catch-all rule is " +
      "where it goes wrong first, because an alias that claims every name at a domain is " +
      "not an identity and a fresh derivation has to remember that on its own. Compose " +
      "blamepost.mail.listeners.permittedAuthors instead of asking the store again.",
    dirs: ["lib", "bin"],
    // Two frozen contracts, neither of them a renameable local: the
    // store verb that reads the alias table, and the documented filter
    // key that turns it into the question about one mailbox. A rename of
    // either is a change to the identity layer's published surface
    // rather than a refactor, and a deletion removes the hazard. The
    // quantifier is a ReDoS backstop set far above any options literal
    // and is not the precision mechanism: the negative half of this
    // detector is the file scope, and the positive half is the pair of
    // tokens. The module that owns the derivation is excluded by path
    // for the same reason a detector for a rule never fires on the rule.
    //
    // Read off the mask rather than the source, so the worked example in
    // the store primitive's own documentation is the documentation it is
    // and not a second derivation. A comment quoting the shape can then
    // neither trip this nor silence it.
    scan: function (file) {
      if (SENDING_IDENTITY_OWNER_RE.test(file.rel)) return [];
      var mask = _maskOf(file);
      var out = [];
      SENDING_IDENTITY_REDERIVED_RE.lastIndex = 0;
      var hit = SENDING_IDENTITY_REDERIVED_RE.exec(mask);
      while (hit !== null) {
        out.push(_atOffset(file, hit.index));
        if (hit.index === SENDING_IDENTITY_REDERIVED_RE.lastIndex) {
          SENDING_IDENTITY_REDERIVED_RE.lastIndex += 1;
        }
        hit = SENDING_IDENTITY_REDERIVED_RE.exec(mask);
      }
      return out;
    },
    red: [
      "function _authorsFor(account) {\n" +
        "  return store.aliases.list({ destination: account.address })\n" +
        "    .map(function (row) { return row.address; });\n" +
        "}\n",
      // The same question spread over an options object, which is the
      // shape a matcher bound to one line goes quiet on.
      "function _sendingAddresses(store, account) {\n" +
        "  var rows = store.aliases.list({\n" +
        "    includeDisabled: false,\n" +
        "    destination:     account.address,\n" +
        "  });\n" +
        "  return rows.map(function (row) { return row.address; });\n" +
        "}\n",
    ],
    green: [
      // The one place that may ask, named by its path.
      {
        as:   "lib/mail/listeners.js",
        text: "function permittedAuthors(store, actor) {\n" +
          "  var rows = store.aliases.list({ destination: own.address });\n" +
          "  return rows;\n}\n",
      },
      // Every other surface composes the answer rather than recomputing it.
      "function _identitiesFor(account) {\n" +
        "  return permittedAuthors(store, { id: account.id, address: account.address });\n" +
        "}\n",
      // The administration page lists the alias table itself, which is a
      // different question and carries no destination filter.
      "async function _renderAliases(req, res) {\n" +
        "  var aliases = _asArray(await store.aliases.list({ includeDisabled: true }));\n" +
        "  return aliases;\n}\n",
    ],
  },

  {
    name: "domain-admitted-without-being-derived",
    description:
      "A domain name admitted by the framework's domain guard and then carried onward in the " +
      "spelling it arrived in. The guard answers two questions and only one of them yields a " +
      "name: `validate` says the string may be a domain, and `sanitize` says which domain it " +
      "is. The strict profile deliberately admits the DNS root's trailing dot, because the " +
      "absolute form is a valid name, and `sanitize` is the only half that removes it and " +
      "folds the case. A caller that asks `validate` and keeps its own argument therefore " +
      "holds one spelling out of several for a single domain, and every consumer downstream " +
      "that does derive the name now disagrees with it: a lookup misses the row in front of " +
      "it, a derived file name gains an empty label, and a cache answers about a domain that " +
      "is not the one asked for. The disagreement is silent, because both strings are valid " +
      "names and neither side has any way to notice the other folded differently. Derive the " +
      "name once — `guardDomain.sanitize` under the same profile, or the identity layer's " +
      "`canonicalDomain` and `parseDomain`, which compose both halves — and carry what that " +
      "returns. The same class arrives through a second door with no guard call in it at " +
      "all: a domain folded by hand with `toLowerCase`. That settles the case half RFC 4343 " +
      "describes and leaves the trailing dot untouched, so it agrees with the derivation on " +
      "three of the four spellings of every name and disagrees on the fourth. There is no " +
      "correct hand fold of a domain here. Either derive the name, or pass the value " +
      "untouched to the layer that does — which is what a surface above the identity layer " +
      "should do, because a fold written twice is two rules that have already drifted.",
    dirs: ["lib", "bin"],
    // Anchored on the framework's published guard rather than on any
    // local name, so a rename anywhere in this repository changes
    // nothing about what is found, and a deletion removes the hazard
    // along with the match. The positive half is the admission call and
    // the identifier it was handed; the negative half is the derivation
    // being absent from the same function. There is no character budget
    // anywhere in it: the function body is the bound, so a body that
    // grows keeps being read whole.
    //
    // The identifier has to be used AFTER the admission for this to be
    // a finding. A guard that admits a name and derives nothing from it
    // is a gate, which is a legitimate thing to write and the shape a
    // recipient policy takes; what makes it a finding is the checked
    // value traveling on.
    //
    // The hand fold is matched beside it, in the same pass over the same
    // bodies and under the same exemption, because it is one class and a
    // second entry would be a second reason to keep in step. It carries
    // no traveling test of its own: the fold IS the value, so a fold
    // that happened is a spelling that was written down.
    //
    // Read off the mask, so a worked example in a primitive's own
    // documentation block is the documentation it is rather than a
    // second derivation, and a comment quoting the shape can neither
    // trip this nor silence it.
    scan: function (file) {
      var mask   = _maskOf(file);
      var bodies = _functionBodies(mask);
      var out    = [];
      for (var i = 0; i < bodies.length; i += 1) {
        var body = bodies[i];
        if (DOMAIN_DERIVED_RE.test(_ownText(mask, bodies, body))) continue;
        var hits = _matchesIn(mask, bodies, body, DOMAIN_ADMITTED_RE);
        for (var h = 0; h < hits.length; h += 1) {
          var named = hits[h].groups[1];
          var openParen = mask.indexOf("(", hits[h].offset);
          if (openParen === -1) continue;
          var closeParen = _matchingBracket(mask, openParen);
          if (closeParen === -1) continue;
          if (!_domainCarriedOnwardRe(named).test(mask.slice(closeParen + 1, body.end))) continue;
          out.push(_atOffset(file, hits[h].offset));
        }
        var folded = _matchesIn(mask, bodies, body, DOMAIN_HAND_FOLDED_RE);
        for (var f = 0; f < folded.length; f += 1) {
          out.push(_atOffset(file, folded[f].offset));
        }
      }
      return out;
    },
    red: [
      // The admission used as a fold, which it is not.
      "function _assertDomain(domain, label) {\n" +
        "  var verdict = b.guardDomain.validate(domain, { profile: \"strict\" });\n" +
        "  if (!verdict.ok) throw new TypeError(label + \": refused\");\n" +
        "  return domain.toLowerCase();\n" +
        "}\n",
      // The same shape with the admitted name traveling into a path
      // rather than out of a return, which is the form that reaches the
      // volume.
      "function _keyFileFor(name, selector) {\n" +
        "  var ok = b.guardDomain.validate(name, { profile: \"strict\" });\n" +
        "  if (!ok.ok) return null;\n" +
        "  return nodePath.join(keyDir, name + \".\" + selector + \".sealed\");\n" +
        "}\n",
      // A stored row folded by hand on its way into the set a listener
      // measures every recipient against. No guard call appears at all,
      // which is what the shape above cannot see.
      "function _activeDomains(rows) {\n" +
        "  return rows.map(function (row) {\n" +
        "    return { domain: String(row.domain || row).toLowerCase() };\n" +
        "  });\n" +
        "}\n",
      // The same fold on a request field, on its way into a layer that
      // would have derived it. Redundant today and a second rule about
      // one name whichever way it is read.
      "async function _postDkim(req, res) {\n" +
        "  var body = _bodyOf(req);\n" +
        "  var domain = _str(body.domain, \"\").toLowerCase();\n" +
        "  await dkim.generate({ domain: domain });\n" +
        "}\n",
      // And the fold feeding a membership test, which is where the
      // disagreement becomes an answer an operator acts on.
      "async function cmdDoctor(flags) {\n" +
        "  var hosted = active.map(function (d) { return String(d.domain).toLowerCase(); });\n" +
        "  return hosted.indexOf(wanted) === -1 ? 1 : 0;\n" +
        "}\n",
    ],
    green: [
      // Both halves asked, which is what yields a name.
      "function canonicalDomain(text, label) {\n" +
        "  var verdict = b.guardDomain.validate(text, GUARD_OPTS);\n" +
        "  if (!verdict.ok) throw err(\"store/bad-domain\", label + \" is not usable\");\n" +
        "  return b.guardDomain.sanitize(text, GUARD_OPTS);\n" +
        "}\n",
      // The derivation composed from the one place that owns it.
      "function _assertDomain(domain, label) {\n" +
        "  return address.canonicalDomain(domain, label);\n" +
        "}\n",
      // A gate. The name is admitted and nothing is derived from it, so
      // there is no second spelling to disagree with anybody about.
      "function _recipientPolicy(ctx) {\n" +
        "  var domain = _domainOf(ctx.rcptTo);\n" +
        "  var verdict = b.guardDomain.validate(domain, { profile: profile });\n" +
        "  if (!verdict.ok) return { ok: false, reason: \"Recipient domain refused\" };\n" +
        "  return { ok: true };\n" +
        "}\n",
      // The stored row read through the derivation instead, which is
      // what the hand fold above is replaced by.
      "function _activeDomains(rows) {\n" +
        "  return rows.map(function (row) {\n" +
        "    var name = storeAddress.parseDomain(row.domain);\n" +
        "    return { domain: name.domain };\n" +
        "  });\n" +
        "}\n",
      // The request field handed on untouched. The layer below derives,
      // and a surface above it that folds anyway is the second rule.
      "async function _postDkim(req, res) {\n" +
        "  var body = _bodyOf(req);\n" +
        "  await dkim.generate({ domain: _str(body.domain, \"\") });\n" +
        "}\n",
      // A fold of something that is not a domain. The anchor is the
      // concept, so a header name, a selector, a flag and an algorithm
      // label go on being folded wherever folding them is right.
      "function _headerName(value) {\n" +
        "  return String(value).trim().toLowerCase();\n" +
        "}\n",
      // The comparison fold the posture checker keeps, which is
      // deliberately NOT the derivation and must not be replaced by it:
      // every value it folds arrived from DNS or from a policy document,
      // where refusing a hostile name would throw away the finding the
      // operator has to see. It folds both halves and keys nothing.
      "function _normalizeName(name) {\n" +
        "  var value = String(name || \"\").trim().toLowerCase();\n" +
        "  return value.charAt(value.length - 1) === \".\" ? value.slice(0, -1) : value;\n" +
        "}\n",
    ],
  },

  {
    name: "address-admitted-without-being-derived",
    description:
      "The framework's address guard, asked outside the module that composes it. It is the " +
      "sibling of the domain rule and it is not shaped like it: the domain guard answers in " +
      "two halves and one of them yields a name, while the address guard has no such half. " +
      "`validateAddress` and `validate` both answer whether a string matches the RFC 5321 " +
      "section 4.1.2 addr-spec shape, about the spelling they were handed, and neither ever " +
      "says which mailbox it names. So asking one is never half of a derivation, it is a " +
      "different question, and the caller is left holding one spelling out of several for a " +
      "single mailbox. The spelling that guard refuses is the one this matters for: RFC 1035 " +
      "section 2.3.1 makes `example.com.` the absolute form of the same name, no wire reader " +
      "checks a MESSAGE HEADER against the envelope grammar, and a message carrying that form " +
      "in From or To is delivered and filed like any other. A surface that then answers such " +
      "a message — a reply, a forward, a submission built from its headers — refuses the " +
      "account holder's own draft, naming address syntax, which points them at what they " +
      "wrote rather than at the header they are answering. The other direction is the same " +
      "rule read backwards: what leaves has to be a form the NEXT server accepts under the " +
      "grammar this one refuses the other for, so admitting the spelling instead of folding " +
      "it would send an empty label onward. Compose `lib/store/address.js` instead, and carry " +
      "what it returns: `parse` where a refusal is a verdict to answer with, `canonical` " +
      "where it is an operator's mistake to throw on. It runs the same guard under the same " +
      "profile, " +
      "so a homograph label, an IP literal and a second at sign are refused exactly as before, " +
      "and it hands back a name with the root dot removed, the domain folded and the RFC 5233 " +
      "tag still attached.",
    dirs: ["lib", "bin"],
    // Anchored on the framework's published guard rather than on any
    // local name, so a rename anywhere in this repository changes
    // nothing about what is found and a deletion removes the hazard
    // along with the match. There is no second token to bound and so no
    // walk to bound it with: unlike the domain rule, where admitting a
    // name and deriving nothing from it is a legitimate gate, there is
    // no use for this guard here at all. A caller that wants a gate gets
    // one from the derivation, which refuses everything the guard
    // refuses; a caller that wants a name can only get one there. The
    // rule is therefore absolute, and the file scope is the whole of the
    // negative half.
    //
    // Read off the mask, so a worked example in a primitive's own
    // documentation block is the documentation it is rather than a
    // second derivation, and a comment quoting the shape can neither
    // trip this nor silence it.
    scan: function (file) {
      if (ADDRESS_DERIVATION_OWNER_RE.test(file.rel)) return [];
      var mask = _maskOf(file);
      var out  = [];
      ADDRESS_ADMITTED_RE.lastIndex = 0;
      var hit = ADDRESS_ADMITTED_RE.exec(mask);
      while (hit !== null) {
        out.push(_atOffset(file, hit.index));
        if (hit.index === ADDRESS_ADMITTED_RE.lastIndex) ADDRESS_ADMITTED_RE.lastIndex += 1;
        hit = ADDRESS_ADMITTED_RE.exec(mask);
      }
      return out;
    },
    red: [
      // The admission used as a fold, which it is not: what comes back
      // is the caller's own argument, spelling and all.
      "function _assertAddress(addr, label) {\n" +
        "  var verdict = b.guardEmail.validateAddress(addr.address, { profile: \"strict\" });\n" +
        "  if (!verdict.ok) throw new TypeError(label + \": refused\");\n" +
        "  return addr;\n" +
        "}\n",
      // The same question through the wider guard, which reads the same
      // addr-spec shape and is the door a screening call reaches for.
      "function _firstUnacceptable(addresses) {\n" +
        "  for (var i = 0; i < addresses.length; i += 1) {\n" +
        "    if (!b.guardEmail.validate(addresses[i]).ok) return addresses[i];\n" +
        "  }\n  return null;\n}\n",
      // A gate, which is legitimate for a domain and is not one here,
      // because the derivation refuses everything this refuses and is
      // the only thing that also answers with a name.
      "function _reportDestination(published) {\n" +
        "  var verdict = b.guardEmail.validate(published, { profile: \"strict\" });\n" +
        "  if (!verdict.ok) throw new TypeError(\"the published destination is unusable\");\n" +
        "  return published;\n}\n",
    ],
    green: [
      // The one place that may ask, named by its path.
      {
        as:   "lib/store/address.js",
        text: "function parse(input) {\n" +
          "  var shape = b.guardEmail.validateAddress(text, GUARD_OPTS);\n" +
          "  if (!shape.ok) return _refuse(\"address-refused\", shape.issues);\n" +
          "  return { ok: true, address: localPart + \"@\" + domain };\n}\n",
      },
      // Every other surface composes the derivation and carries what it
      // returns.
      "function _assertAddress(addr, label) {\n" +
        "  var derived = storeAddress.parse(addr.address);\n" +
        "  if (!derived.ok) throw new TypeError(label + \": not an address\");\n" +
        "  return { name: addr.name, address: derived.written };\n}\n",
      // The throwing sibling, for the paths where a bad address is an
      // operator's mistake rather than a verdict to answer with.
      "function _adminContact(value) {\n" +
        "  return address.canonical(value, \"admin contact\").written;\n}\n",
      // A gate written the same way. The derivation refuses everything
      // the guard refuses, so nothing is given up by asking it instead.
      "function _firstUnacceptable(addresses) {\n" +
        "  for (var i = 0; i < addresses.length; i += 1) {\n" +
        "    if (!address.parse(addresses[i]).ok) return addresses[i];\n" +
        "  }\n  return null;\n}\n",
      // A different guard on a different concept. The anchor is this one
      // guard, so every other one goes on being composed where it
      // belongs.
      "function _validateAttachment(att, index) {\n" +
        "  var verdict = b.guardFilename.validate(att.filename, { profile: \"balanced\" });\n" +
        "  if (!verdict.ok) throw new TypeError(\"attachment refused\");\n" +
        "  return att;\n}\n",
      // The message half of the same guard, which reads octets rather
      // than an address and is not what this is about.
      "function _screenBody(bytes) {\n" +
        "  return b.guardEmail.sanitize(bytes, { profile: \"strict\" });\n}\n",
    ],
  },

  {
    name: "dns-reader-list-without-ptr",
    description:
      "A list of DNS record types that a resolver handle derives its typed readers from, with " +
      "no PTR among them. The handle it builds cannot answer a reverse question, and the HELO " +
      "identity gate REFUSES such a handle rather than reading the missing reader as an " +
      "address that has no reverse name, so every session against a listener holding one ends " +
      "at EHLO with a server error for a reason that belongs to the handle rather than to the " +
      "peer. The omission is invisible from reading the list. PTR is the only type on it that " +
      "no policy lookup asks for, so a list assembled for the TXT, MX and address questions a " +
      "sender check makes looks complete while leaving out the one the connection itself " +
      "needs, and the reader list is exactly the kind of thing that gets copied into a second " +
      "file and then only half maintained. Put PTR on the list, or compose the shared handle " +
      "in test/helpers/dns-zone.js, which derives every reader from one list.",
    dirs: ["lib", "bin", "test"],
    scan: _contentMatcher(
      // Anchored on the shape rather than on any name: an array literal
      // opening with the two address types every such list opens with,
      // carrying at least a third type after them, and closing without
      // PTR appearing inside it. The third entry is what separates a
      // reader list from the pair of address types a caller keeps to ask
      // which questions are address questions. The bound is a ReDoS
      // backstop set far above any real list; the closing bracket and
      // the lookahead are what decide.
      new RegExp("\\[\\s*\"A\",\\s*\"AAAA\",\\s*\"(?:(?!PTR)[\\s\\S]){0,600}?\\]", "g")),
    red: [
      "var TYPED_READERS = Object.freeze([\n" +
        "  \"A\", \"AAAA\", \"CNAME\", \"MX\", \"NS\", \"TXT\", \"SRV\", \"TLSA\", \"DS\", \"DNSKEY\",\n" +
        "]);\n",
      // The same omission written inline, which is the spelling a second
      // copy of the fixture reaches for.
      "function pinned(zone) {\n" +
        "  var handle = { query: query };\n" +
        "  [\"A\", \"AAAA\", \"MX\", \"TXT\"].forEach(function (qtype) {\n" +
        "    handle[\"query\" + qtype] = function (name) { return query(name, qtype); };\n" +
        "  });\n  return handle;\n}\n",
    ],
    green: [
      "var TYPED_READERS = Object.freeze([\n" +
        "  \"A\", \"AAAA\", \"CNAME\", \"MX\", \"NS\", \"PTR\", \"TXT\", \"SRV\", \"TLSA\", \"DS\",\n" +
        "  \"DNSKEY\", \"SVCB\", \"HTTPS\",\n" +
        "]);\n",
      "function pinned(zone) {\n" +
        "  var handle = { query: query };\n" +
        "  [\"A\", \"AAAA\", \"PTR\", \"MX\", \"TXT\"].forEach(function (qtype) {\n" +
        "    handle[\"query\" + qtype] = function (name) { return query(name, qtype); };\n" +
        "  });\n  return handle;\n}\n",
      // A list of address types that builds no readers at all is a
      // different thing and is not what this is about.
      "var ADDRESS_TYPES = [\"A\", \"AAAA\"];\n" +
        "function isAddressQuestion(qtype) { return ADDRESS_TYPES.indexOf(qtype) !== -1; }\n",
    ],
  },
  {
    name: "subprocess-verdict-discarded",
    description:
      "A subprocess run with failure tolerated, whose status is then never read. Tolerating a " +
      "failure and discarding the answer are two different decisions, and only the first one " +
      "is written down here. Tolerating it is often right: it is how one command reports a " +
      "failing build AND the findings that arrived with it out of a single pass, instead of " +
      "stopping at the first and making the operator run a second round to learn the rest. " +
      "Dropping the status is never right, because the phase that follows then reads a failure " +
      "as a pass. Bind the result and let it decide the exit code, with a message naming what " +
      "failed. A run whose status looks like it cannot matter still has one worth reading: it " +
      "is what tells the operator whether the cleanup the refusal message promises actually " +
      "happened.",
    dirs: ["lib", "bin", "scripts", "test"],
    // Anchored on the OPTION KEY rather than on the helper that reads it.
    // `allowFail` is the contract between that helper and every caller, so
    // renaming the helper cannot quiet this, and the only thing that
    // silences it is the tolerance genuinely going away.
    //
    // The precision is structural, not a character budget. `[^;]` cannot
    // cross a statement boundary, which is what keeps a bare call from
    // reaching a later, correctly-bound one further down the same
    // function; the `\n}` guard cannot cross a function boundary; and the
    // leading keyword lookahead is what stops `if (`, `while (` and
    // `return (` from reading as calls at statement position. The
    // `{0,600}` is purely a runaway backstop, set far above any call this
    // shape is written in.
    scan: _contentMatcher(new RegExp(
      "^[ \\t]*(?:await\\s+)?" +
      "(?!(?:if|for|while|switch|catch|do|else|return|typeof|delete|void|function)\\b)" +
      "[A-Za-z_$][\\w$]*\\s*\\(" +
      "(?:(?!\\n\\})[^;]){0,600}?" +
      "\\ballowFail\\s*:",
      "gm")),
    red: [
      "function cmdWatch(prNum) {\n" +
        "  _run(\"gh\", [\"pr\", \"checks\", prNum, \"--watch\"], { allowFail: true });\n" +
        "  _ok(\"checks watched\");\n}\n",
      // A differently named runner, which is the spelling a matcher bound
      // to one helper's name goes quiet on.
      "function cmdGates() {\n" +
        "  _spawnGate(\"node\", [\"scripts/check-something.js\"], { allowFail: true });\n" +
        "  return true;\n}\n",
      // The same discard with the call wrapped over several lines.
      "function cmdPublish(runId) {\n" +
        "  _run(\"gh\", [\n    \"run\", \"watch\", runId, \"--exit-status\",\n  ], { allowFail: true });\n}\n",
    ],
    green: [
      // The status bound and turned into a verdict.
      "function cmdInterop() {\n" +
        "  var rv = _run(\"node\", [\"scripts/test-integration.js\"], { allowFail: true });\n" +
        "  if (rv.status !== 0) throw new Error(\"a failing interop run is a hard stop\");\n" +
        "  return rv;\n}\n",
      // A bare call with no tolerance at all, followed further down the
      // same function by one that reads its status. This is the pair a
      // character-counted matcher joins into a false report.
      "function cmdPush(branch, prNum, text) {\n" +
        "  _run(\"git\", [\"push\", \"-u\", \"origin\", branch]);\n" +
        "  _ok(\"pushed \" + branch);\n" +
        "  var rv = _run(\"gh\", [\"pr\", \"comment\", prNum, \"--body\", text], { allowFail: true });\n" +
        "  if (rv.status !== 0) console.log(\"the push landed; the comment did not\");\n}\n",
      // A guarded call whose status IS read, where the guard is what
      // opens the line.
      "function cmdVerify(npmRunId) {\n" +
        "  if (npmRunId) {\n" +
        "    var rv = _run(\"gh\", [\"run\", \"watch\", npmRunId, \"--exit-status\"], { allowFail: true });\n" +
        "    if (rv.status !== 0) throw new Error(\"nothing reached the registry\");\n  }\n}\n",
      // The helper that READS the option, which names it without passing
      // it.
      "function _run(cmd, args, opts) {\n" +
        "  if (rv.status !== 0 && !opts.allowFail) throw new Error(cmd + \" failed\");\n" +
        "  return rv;\n}\n",
      // Prose describing the shape the rule refuses.
      "// _run(\"gh\", [\"pr\", \"checks\"], { allowFail: true }) would discard the verdict\n" +
        " * and _run(\"git\", [\"tag\"], { allowFail: true }) would discard it too\n",
    ],
  },

  {
    name: "template-url-attribute-interpolation",
    description:
      "A template interpolation in a markup attribute a browser resolves as a URL, written " +
      "where the value it is handed decides the scheme or the host. The engine escapes a " +
      "two-brace interpolation, and escaping leaves a scheme intact, so `href=\"{{ target }}\"` " +
      "renders `javascript:` or `https://elsewhere` as readily as a path: the page is then safe " +
      "only while every producer of that value stays correct. The template holds the position " +
      "itself when the text ahead of the interpolation is a literal slash, a literal fragment " +
      "mark, or a literal scheme with the whole authority after it. Refused here: an " +
      "interpolation or a tag at the start of the value, a literal second slash or backslash " +
      "after the first, a literal that is none of those three, a scheme that runs what follows " +
      "it, an interpolation inside an authority, and the un-escaped three-brace form anywhere " +
      "in the value, which lets the value close the attribute and open another. Write the " +
      "slash in the template and interpolate a value built without it. The three-brace form " +
      "stays correct where it belongs, which is element CONTENT carrying already-sanitized " +
      "markup.",
    dirs: ["lib"],
    exts: /\.html$/,
    // Anchored on the engine's delimiter syntax and the HTML attribute
    // names, both of which are frozen contracts rather than anything this
    // repository can rename. Read over the whole file rather than line by
    // line, so an attribute written across two lines is still seen, and in
    // all three quoting styles, because an unquoted value is a value too.
    //
    // A literal slash cannot stop a value that begins with a second slash
    // or a backslash, because the pair names another host. That half is
    // held where the value is built: the view field detector below refuses
    // a value no view field builder produced, and
    // test/layer-0-primitives/web-link-origin.test.js renders every view
    // with hostile values and walks each value back to its builder. This
    // is the wide net over every template under lib/, so a template added
    // in a directory that read has never heard of is still held to the
    // shape.
    scan: function (file) {
      var out = [];
      if (!/\.html$/.test(file.rel)) return out;
      var re = new RegExp("\\b(href|src|srcset|action|formaction|cite|poster|background|ping|" +
        "manifest|longdesc|usemap|codebase|profile|data|xlink:href)\\s*=\\s*" +
        "(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))", "gi");
      var m;
      while ((m = re.exec(file.text)) !== null) {
        var value = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : m[4]);
        var tag = /\{\{|\{%/.exec(value);
        if (tag === null) continue;
        var prefix = value.slice(0, tag.index);
        var second = prefix.charAt(1);
        var scheme = /^([A-Za-z][A-Za-z0-9+.-]*):(\/\/)?/.exec(prefix);
        var why = null;
        if (value.indexOf("{{{") !== -1) {
          why = "an un-escaped interpolation, which lets the value close the attribute";
        } else if (prefix.length === 0) {
          why = "an interpolation at the start of the value, so the value chooses the scheme";
        } else if (prefix.charAt(0) === "/") {
          if (second === "/" || second === "\\" || second === "\t" || second === "\n" || second === "\r") {
            why = "a second slash ahead of the interpolation, so the value names the host";
          }
        } else if (prefix.charAt(0) !== "#") {
          if (scheme === null) {
            why = "a literal that is not a path, a fragment or a scheme ahead of the interpolation";
          } else if (/^(?:javascript|vbscript|livescript|data)$/i.test(scheme[1])) {
            why = "a scheme that runs what follows it";
          } else if (scheme[2] !== undefined && prefix.slice(scheme[0].length).indexOf("/") === -1) {
            why = "an interpolation inside the authority, so the value names the host";
          }
        }
        if (why === null) continue;
        out.push({
          file:    file.rel,
          line:    file.text.slice(0, m.index).split(/\r?\n/).length,
          content: m[0].trim() + ": " + why,
        });
      }
      return out;
    },
    red: [
      // The value decides the scheme.
      { as: "page.html", text: "<a class=\"btn\" href=\"{{ target }}\">Open</a>\n" },
      { as: "page.html", text: "<form action=\"{{ postHref }}\" method=\"post\">\n" },
      { as: "page.html", text: "<button formaction=\"{{ target }}\">Send</button>\n" },
      { as: "page.html", text: "<img src=\"{{ m.remoteImage }}\" alt=\"\">\n" },
      // Written across two lines, which a line-at-a-time reader misses.
      { as: "page.html", text: "<a\n  href=\"{{ target }}\"\n  class=\"btn\">Open</a>\n" },
      // The other two quoting styles.
      { as: "page.html", text: "<a href='{{ target }}'>Open</a>\n" },
      { as: "page.html", text: "<a href={{ target }}>Open</a>\n" },
      // A tag at the start decides the scheme just as well.
      { as: "page.html", text: "<a href=\"{% if a %}{{ a }}{% endif %}\">Open</a>\n" },
      // The un-escaped form, with and without a slash ahead of it.
      { as: "page.html", text: "<a class=\"btn\" href=\"{{{ target }}}\">Open</a>\n" },
      { as: "page.html", text: "<a href=\"/{{{ target }}}\">Open</a>\n" },
      // A slash written ahead of the value that is the first of two.
      { as: "page.html", text: "<a href=\"//{{ host }}/x\">Open</a>\n" },
      { as: "page.html", text: "<a href=\"/\\{{ host }}\">Open</a>\n" },
      // A scheme with the host left to the value, and a scheme that runs.
      { as: "page.html", text: "<a href=\"https://{{ host }}/x\">Open</a>\n" },
      { as: "page.html", text: "<a href=\"javascript:{{ code }}\">Open</a>\n" },
      // A relative literal, which resolves against whatever page renders it.
      { as: "page.html", text: "<a href=\"mail/{{ folder }}\">Open</a>\n" },
    ],
    green: [
      { as: "page.html", text: "<a class=\"btn\" href=\"/{{ target }}\">Open</a>\n" },
      { as: "page.html", text: "<form action=\"/{{ postHref }}\" method=\"post\">\n" },
      { as: "page.html", text: "<a\n  href=\"/{{ target }}\"\n  class=\"btn\">Open</a>\n" },
      { as: "page.html", text: "<a href=\"/{{ a }}?b={{ b }}\">Open</a>\n" },
      { as: "page.html", text: "<a href=\"/sign-in\">Sign in</a>\n" },
      // A fragment, a mail address and a citation, each with its scheme or
      // mark written in the template and only the tail interpolated.
      { as: "page.html", text: "<a href=\"#{{ anchor }}\">Jump</a>\n" },
      { as: "page.html", text: "<a href=\"mailto:{{ address }}\">Write</a>\n" },
      { as: "page.html", text: "<a href=\"https://www.rfc-editor.org/rfc/rfc{{ number }}\">RFC</a>\n" },
      // The raw form where it is correct: element content carrying markup
      // the sanitizer has already screened.
      { as: "page.html", text: "<div class=\"letter-body\">{{{ m.bodyHtml }}}</div>\n" },
      // An interpolation in an ordinary attribute is a different question
      // and not this one, including one whose value is the word action.
      { as: "page.html", text: "<span title=\"{{{ label }}}\">x</span>\n" },
      { as: "page.html", text: "<input type=\"hidden\" name=\"action\" value=\"{{ pending.action }}\">\n" },
      { as: "page.html", text: "<meta name=\"description\" content=\"{{ pageDescription }}\">\n" },
    ],
  },

  {
    name: "web-url-handed-to-the-browser-not-built",
    description:
      "A URL this application hands the browser that was not built into the form the place it " +
      "lands on takes. The browser surface turns a value into a URL in two places. A redirect " +
      "is an absolute path on this server, passed through the helper that refuses anything " +
      "else. A view field, the property a template reads a link under, is that same path " +
      "without its leading slash, because the template writes the slash itself, and it is " +
      "built by the view field helper: the one that composes the path refusal, removes the " +
      "slash, and refuses a remainder that begins with a slash or a backslash. Escaping holds " +
      "neither form, because the engine escapes an interpolation and leaves the scheme intact. " +
      "The two forms are not interchangeable: a path handed to a template renders as two " +
      "slashes and a host, carrying the reader off this origin still holding the session, and " +
      "a view field handed to a redirect is a target relative to the page. Refused for a view " +
      "field is anything other than an empty value or exactly one call to a view field " +
      "builder: a literal, a concatenation, a template literal, a bare name, a value read off " +
      "the request, a path built for a redirect, or a builder's value with more written after " +
      "it. A builder is one with the shape in this file, one with the shape in a module this " +
      "file requires, or a local name for either, which is a function whose every return is " +
      "one call to a builder. Refused for a redirect is a value neither produced by a call " +
      "nor written as an absolute path on this server, and one produced by a view field " +
      "builder. Build a view field through the view field helper and a redirect through the " +
      "path helper.",
    dirs: ["lib", "bin"],
    // Anchored on two frozen contracts and one naming convention, none of
    // which this repository can rename out from under the matcher. The
    // attribute names are the browser's: a property called `href` or
    // `src` is resolved as a URL wherever it is rendered. The `Href`
    // suffix is the key the templates read a link target under, a form
    // target included. The redirect is the response method the framework
    // exposes, matched without its receiver so that naming the parameter
    // something other than `res` changes no verdict. A view field is read
    // both where it is assigned onto an object and where it is written as
    // a key of an object literal, which is how nearly every page builds
    // one.
    //
    // Nothing here names either helper. A redirect target counts as built
    // when it BEGINS with a call. A view field counts as built when it is
    // one call to a builder `_linkTailBuilders` names, which is a body
    // with the view field builder's shape wherever it sits and the local
    // names that reach it, so a rename leaves this silent exactly where it
    // was silent before and firing exactly where it fired. The price of a
    // shape anchor is that a call
    // reaching no refusal reads like one that does; the deep read of this
    // surface walks each builder to what it returns and answers that,
    // while this answers whether the value was built at all and into
    // which form.
    //
    // Browser code under lib/web/public assigns a link onto a live element
    // rather than into a template, so an assignment there is a whole URL
    // and is read the way a redirect target is.
    //
    // A view field exists only where a view is built, which is under
    // lib/web. Everywhere else the attribute names are ordinary words: a
    // backup bundle has a `manifest`, a record has a `src`. So assignments
    // and object keys are read only in files under lib/web, and the
    // redirect is read in every file this detector walks.
    //
    // `action` is deliberately not in the attribute set. The form targets
    // these templates render read keys ending in `Href`, so nothing is
    // lost, and a bare `action` in this tree is the audit verb a query
    // filters on rather than anything a browser resolves. Matching it
    // would report that filter on every read.
    //
    // Depth is counted rather than measured, so there is no bound on how
    // long an expression may be and no layout a growing one can outgrow.
    scan: function (file) {
      var out = [];
      if (!/\.js$/.test(file.rel)) return out;
      var mask = _maskOf(file);
      var browser = /(?:^|\/)lib\/web\/public\//.test(file.rel);
      var webSurface = /(?:^|\/)lib\/web\//.test(file.rel);
      var keys = "href|src|srcset|formaction|cite|poster|ping|manifest|[A-Za-z_$][\\w$]*Href";

      var assign = new RegExp("\\.\\s*(" + keys + ")\\s*=(?!=)", "g");
      var m;
      while (webSurface && (m = assign.exec(mask)) !== null) {
        var value = _linkExpressionAt(file.text, m.index + m[0].length);
        var why = browser
          ? _linkTargetNotBuilt(value)
          : _linkViewFieldNotBuilt(value, _linkTailBuilders(file));
        if (why === null) continue;
        out.push(_atOffset(file, m.index,
          "'" + m[1] + "' is assigned " + why));
      }

      var property = new RegExp("[{,]\\s*(" + keys + ")\\s*:(?!:)", "g");
      var p;
      while (webSurface && !browser && (p = property.exec(mask)) !== null) {
        var at = p.index + p[0].length;
        var whyKey = _linkViewFieldNotBuilt(_linkExpressionAt(file.text, at, true),
          _linkTailBuilders(file));
        if (whyKey === null) continue;
        out.push(_atOffset(file, at, "'" + p[1] + "' is set to " + whyKey));
      }

      var redirect = /\.\s*redirect\s*\(/g;
      var r;
      while ((r = redirect.exec(mask)) !== null) {
        var arg = _linkFirstArgument(file.text, r.index + r[0].length - 1);
        var reason = _linkRedirectNotBuilt(arg, _linkTailBuilders(file));
        if (reason === null) continue;
        out.push(_atOffset(file, r.index,
          "a redirect is answered with " + reason));
      }
      return out;
    },
    red: [
      // A link target concatenated in place, which is the shape the guard
      // exists to screen.
      { as: "lib/web/index.js",
        text: "function _cards(rows) {\n  rows.forEach(function (row) {\n" +
          "    row.href = \"/admin/dmarc?domain=\" + row.domain;\n  });\n}\n" },
      // The same value read straight off the request.
      { as: "lib/web/index.js",
        text: "function _page(req, view) {\n  view.nextHref = req.query.next;\n}\n" },
      // A bare name, where what reaches the attribute is whatever bound it.
      { as: "lib/web/index.js",
        text: "function _row(item, target) {\n  item.href = target;\n}\n" },
      // A literal that leaves this origin behind a second slash.
      { as: "lib/web/index.js",
        text: "function _row(item) {\n  item.href = \"//evil.example/x\";\n}\n" },
      // A literal carrying a scheme the browser executes.
      { as: "lib/web/index.js",
        text: "function _row(item) {\n  item.href = \"javascript:alert(1)\";\n}\n" },
      // A template literal assembled in place.
      { as: "lib/web/index.js",
        text: "function _row(item, n) {\n  item.olderHref = " + LINK_TICK + "/mail/${n}" +
          LINK_TICK + ";\n}\n" },
      // The same mistake in an image source, which no template in this
      // tree carries today and which nobody would think to look at when
      // the first one lands.
      { as: "lib/web/index.js",
        text: "function _row(item, u) {\n  item.src = u;\n}\n" },
      // One good branch and one that was never built. A conditional does
      // not stop being a link target because half of it is fine.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _row(item, ok, n) {\n" +
          "  item.backHref = ok ? _v(\"/a\") : \"/mail/\" + n;\n}\n" },
      // A root-relative literal, which the template's own slash turns
      // into two.
      { as: "lib/web/index.js",
        text: "function _nav(item) {\n  item.href = \"/admin/queue\";\n}\n" },
      // A path built for a redirect and handed to a template, with the
      // path refusal defined beside it. It renders `//admin/queue`.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _nav(item) {\n" +
          "  item.href = _p(\"/admin/queue\");\n}\n" },
      // The same two mistakes as keys of an object literal, which is how
      // nearly every page builds its view.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _page(offset) {\n" +
          "  return { nextHref: _p(\"/admin/accounts?offset=\" + offset), label: \"Next\" };\n}\n" },
      { as: "lib/web/index.js",
        text: "function _nav(active) {\n  return [\n" +
          "    { href: \"/admin\", label: \"Overview\", current: active === \"overview\" },\n  ];\n}\n" },
      // A builder's value with more written after it. The builder hands
      // back an empty value for the root, and what follows it would then
      // begin the value with a slash.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _row(item, f) {\n" +
          "  item.href = _v(\"/\") + \"/\" + f;\n}\n" },
      // A builder that removes the slash and refuses a second one, but not
      // a backslash, so it does not have the view field builder's shape.
      { as: "lib/web/index.js",
        text: LINK_PATH_REFUSAL_SOURCE +
          "function _v(value) {\n  var tail = _p(value).slice(1);\n" +
          "  if (tail.charAt(0) === \"/\") { throw new TypeError(\"x\"); }\n  return tail;\n}\n" +
          "function _row(item) {\n  item.href = _v(\"/a\");\n}\n" },
      // A builder this file does not define, reached as a method.
      { as: "lib/web/wiki/index.js",
        text: "function _link(text, path) {\n" +
          "  return { text: text, wikiHref: links.build(path) };\n}\n" },
      // A call through a module this repository does not hold. A require
      // that resolves to nothing leaves the call unbuilt, which is the
      // verdict a typo in the path deserves.
      { as: "lib/web/index.js",
        text: "var links = require(\"./nothing-is-here\");\n" +
          "function _row(item) {\n  item.href = links.href(\"/a\");\n}\n" },
      // A call through a module that resolves and defines no function
      // under that name.
      { as: "lib/web/index.js",
        text: "var links = require(\"./links\");\n" +
          "function _row(item) {\n  item.href = links.nothing(\"/a\");\n}\n" },
      // A local name for a builder is a name for ONE builder. A second
      // return that nothing built is a branch reaching the template
      // unscreened, however built the first branch is.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _href(value, ok) {\n" +
          "  if (ok) { return _v(value); }\n  return value;\n}\n" +
          "function _row(item) {\n  item.href = _href(\"/a\", true);\n}\n" },
      // A local name whose target is not a builder at all.
      { as: "lib/web/index.js",
        text: "function _href(value) {\n  return links.href(value);\n}\n" +
          "function _row(item) {\n  item.href = _href(\"/a\");\n}\n" },
      // A redirect answering with wherever the request asked to go.
      { as: "lib/web/index.js",
        text: "function _signIn(req, res) {\n  res.redirect(req.query.next);\n}\n" },
      // A redirect concatenating its own target.
      { as: "lib/web/index.js",
        text: "function _after(res, folder) {\n  res.redirect(\"/mail/\" + folder);\n}\n" },
      // A redirect under a receiver named anything at all, which is why
      // the method is matched without one.
      { as: "lib/web/index.js",
        text: "function _out(reply, body) {\n  reply.redirect(body.back);\n}\n" },
      // A redirect answered with a view field, which the browser resolves
      // against the page it was on.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _after(res) {\n" +
          "  res.redirect(_v(\"/mail/INBOX\"));\n}\n" },
    ],
    green: [
      // Outside the browser surface the attribute names are ordinary words:
      // a backup bundle has a manifest, and a record says where it came from.
      // Nothing there is rendered by a template or resolved by a browser.
      { as: "bin/blamepost.js",
        text: "function _bundleSummary(opened) {\n" +
          "  var summary = { manifest: opened.manifest, src: opened.dir };\n" +
          "  summary.manifest = opened.manifest;\n  return summary;\n}\n" },
      { as: "lib/store/index.js",
        text: "function _describe(bundle) {\n  return { manifest: bundle.manifestPath };\n}\n" },
      // Built by the view field builder.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _row(item, f) {\n" +
          "  item.href = _v(\"/admin/dmarc?domain=\" + f);\n}\n" },
      // Built by a builder under a different name, which is the rename
      // this detector must survive.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE.replace(/_v\(/g, "_asViewLink(") +
          "function _row(item, f) {\n" +
          "  item.href = _asViewLink(\"/admin/dmarc?domain=\" + f);\n}\n" },
      // Built by the builder in the module this file requires, which is
      // where the rule lives so that both surfaces read one copy of it.
      { as: "lib/web/index.js",
        text: "var links = require(\"./links\");\n" +
          "function _row(item, f) {\n  item.href = links.href(\"/mail/\" + f);\n}\n" },
      // A local name for that builder, which is what keeps the call sites
      // in a surface reading as the surface's own.
      { as: "lib/web/index.js",
        text: "var links = require(\"./links\");\n" +
          "function _href(value) {\n  return links.href(value);\n}\n" +
          "function _row(item, f) {\n  item.href = _href(\"/mail/\" + f);\n}\n" },
      // A name for a name, which resolves because the names are taken to
      // a fixed point rather than one hop.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE +
          "function _one(value) {\n  return _v(value);\n}\n" +
          "function _two(value) {\n  return _one(value);\n}\n" +
          "function _row(item) {\n  item.href = _two(\"/a\");\n}\n" },
      // The wiki's shape: its own rule asked at home, the shared one
      // asked through the module both surfaces require.
      { as: "lib/web/wiki/index.js",
        text: "var links = require(\"../links\");\n" +
          "function _wikiPath(value) {\n  return links.path(value);\n}\n" +
          "function _wikiHref(value) {\n  return links.href(_wikiPath(value));\n}\n" +
          "function _link(text, target) {\n" +
          "  return { text: text, wikiHref: _wikiHref(target) };\n}\n" },
      // The empty fallback, which renders no link and is how a page says
      // there is no next one.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _page(view, more) {\n" +
          "  view.nextHref = more ? _v(\"/admin/accounts?offset=25\") : \"\";\n}\n" },
      { as: "lib/web/index.js",
        text: "function _page(view) {\n  view.inboxHref = \"\";\n}\n" },
      // A nested conditional of built targets, written in parentheses.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _row(item, a, bq) {\n" +
          "  item.href = a ? _v(\"/x\") : (bq ? _v(\"/y\") : \"\");\n}\n" },
      // Keys of an object literal, built, beside keys that are not links.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _nav(active, offset) {\n  return [\n" +
          "    { href: _v(\"/admin\"), label: \"Overview\", current: active === \"overview\" },\n" +
          "    { nextHref: offset > 0\n      ? _v(\"/admin/accounts?offset=\" + offset) : \"\",\n" +
          "      label: \"Next\" },\n  ];\n}\n" },
      // A key name read on the right of a conditional is not a key.
      { as: "lib/web/index.js",
        text: "function _pick(more, nextHref, prevHref) {\n" +
          "  return f(more, more ? nextHref : prevHref);\n}\n" },
      // Browser code assigning a whole path onto a live element.
      { as: "lib/web/public/islands/mailbox.js",
        text: "function _open(link) {\n  link.href = \"/mail/INBOX\";\n}\n" },
      // A comparison is not an assignment.
      { as: "lib/web/index.js",
        text: "function _row(item, target) {\n" +
          "  if (item.href === target) { return true; }\n  return false;\n}\n" },
      // Prose describing the shape the rule refuses.
      { as: "lib/web/index.js",
        text: "// Never write row.href = \"//evil.example/x\" here, and never\n" +
          "// res.redirect(req.query.next) either.\n" },
      // A property named after a verb rather than an attribute. An audit
      // query filters on `action`, and reporting it on every read is how
      // a gate teaches people to skim past it.
      { as: "lib/web/index.js",
        text: "function _query(criteria, action) {\n" +
          "  if (action.length > 0) { criteria.action = action; }\n}\n" },
      // A redirect built by the helper.
      { as: "lib/web/index.js",
        text: "function _signIn(res, user) {\n  res.redirect(_inboxPath(user));\n}\n" },
      // A redirect resolved with a fallback, which cannot hand back a
      // target off this origin.
      { as: "lib/web/index.js",
        text: "function _back(res, body) {\n" +
          "  res.redirect(b.safeRedirect.resolve(_str(body.back, \"/\"), { fallback: \"/\" }));\n}\n" },
      // A redirect to a path written out in full.
      { as: "lib/web/index.js",
        text: "function _out(res) {\n  res.redirect(\"/sign-in\");\n}\n" },
      // A built value written across two lines, with a second call nested
      // inside the one that builds it. Depth is counted rather than
      // measured, so neither the line break nor the inner call ends the
      // read before the value is whole.
      { as: "lib/web/index.js",
        text: LINK_TAIL_BUILDER_SOURCE + "function _cards(finished, days) {\n" +
          "  finished.href = _v(\"/admin/dmarc?domain=\" +\n" +
          "    encodeURIComponent(finished.domain) + \"&days=\" + days);\n}\n" },
      // A conditional written inside the call that builds the value. One
      // question mark belongs to the condition, one to a string literal,
      // and a nested conditional sits behind parentheses of its own.
      // None of the three splits a value that is one call.
      { as: "lib/web/index.js",
        text: "function _back(res, path, notice) {\n" +
          "  res.redirect(_path(notice\n" +
          "    ? path + (path.indexOf(\"?\") === -1 ? \"?\" : \"&\") + \"notice=\" + notice\n" +
          "    : path));\n}\n" },
      // A redirect built by a call on a line that returns straight after
      // it, with a property read as the argument.
      { as: "lib/web/index.js",
        text: "function _signIn(req, res) {\n" +
          "  if (req.user) { res.redirect(_inboxPath(req.user)); return; }\n}\n" },
      // An object literal as the argument to the builder. Its braces are
      // depth like any other, and the colon inside them opens no
      // conditional.
      { as: "lib/web/index.js",
        text: "function _in(res, verdict) {\n" +
          "  res.redirect(_inboxPath({ id: verdict.accountId }));\n}\n" },
    ],
  },

  {
    name: "island-dom-sink-refused-by-trusted-types",
    description:
      "A DOM sink in shipped browser code that Trusted Types refuses. Every page this server " +
      "renders carries require-trusted-types-for 'script', and a browser enforcing it throws a " +
      "TypeError when a plain string reaches one of these sinks instead of a typed value. The " +
      "island stops on that line, so whatever it was part way through building never appears " +
      "and the reader loses the behavior with nothing on screen to say why. Nothing on this " +
      "surface needs one: build elements with createElement, set their text with textContent, " +
      "and set their attributes with setAttribute. A page that has to show markup it did not " +
      "build is asking for the sanitizer, which runs on the server before the value is sent.",
    dirs: ["lib/web/public"],
    // Anchored on the sink names, which are frozen browser API contracts
    // rather than anything this repository can rename, and read over the
    // masked whole file so an assignment split across two lines is still
    // seen. A sink reached through a computed property name is not
    // matched; what carries that case is the policy itself, which refuses
    // the write in the reader's browser at the moment it happens.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      [
        [/\.\s*(?:innerHTML|outerHTML|srcdoc)\s*=(?!=)/g,
          "markup assigned to a sink that requires a typed value"],
        [/\.\s*(?:insertAdjacentHTML|setHTMLUnsafe|createContextualFragment)\s*\(/g,
          "markup parsed into the document through a sink that requires a typed value"],
        [/\bdocument\s*\.\s*write(?:ln)?\s*\(/g,
          "markup written into the document through a sink that requires a typed value"],
        [/\bnew\s+Function\s*\(|\beval\s*\(/g,
          "source compiled at run time, which this policy refuses twice over"],
        [/\b(?:setTimeout|setInterval)\s*\(\s*["'`]/g,
          "a timer handed source as a string rather than a function"],
      ].forEach(function (pair) {
        var re = pair[0];
        var m;
        re.lastIndex = 0;
        while ((m = re.exec(mask)) !== null) out.push(_atOffset(file, m.index, pair[1]));
      });
      return out;
    },
    red: [
      "function paint(row) {\n  row.innerHTML = \"<b>\" + row.dataset.subject + \"</b>\";\n}\n",
      "function paint(bar) {\n  bar.insertAdjacentHTML(\"beforeend\", \"<span>All</span>\");\n}\n",
      "function boot() {\n  document.write(\"<p>loading</p>\");\n}\n",
      "function later() {\n  setTimeout(\"refresh()\", 500);\n}\n",
      "function build(src) {\n  return new Function(\"return \" + src);\n}\n",
    ],
    green: [
      "function paint(bar) {\n  var label = document.createElement(\"label\");\n" +
        "  label.textContent = \"All\";\n  bar.appendChild(label);\n}\n",
      "function later() {\n  setTimeout(function () { refresh(); }, 500);\n}\n",
      "function mark(el) {\n  el.setAttribute(\"aria-pressed\", \"true\");\n}\n",
    ],
  },

  {
    name: "template-inline-script-or-event-handler",
    description:
      "Script in a shipped template that the policy will not run: an event-handler attribute, " +
      "a script element carrying its own body, or a script element sourced off this origin. " +
      "Every page this server renders carries script-src 'self' with no unsafe-inline source, " +
      "so a browser runs none of the three. The handler never fires on the element it is " +
      "written on, the body of the script element is dropped, and the off-origin source is " +
      "never fetched. All three fail quietly, which leaves a control that reads as wired and " +
      "does nothing. Put the code in a file under lib/web/public/islands, load it with a src " +
      "that is an absolute path on this server, and reach the element with addEventListener " +
      "there. A script element whose one type attribute is " +
      TEMPLATE_DATA_BLOCK_TYPES.map(function (x) { return x.type; }).join(" or ") +
      ", with no event handler on it, is a data block the browser does not run, and it may " +
      "carry a body.",
    dirs: ["lib"],
    exts: /\.html$/,
    // Anchored on the HTML attribute prefix and the script element, both
    // frozen contracts. Every `<` followed by a letter is read as a start
    // tag with the tokenizer's attribute rules, including one inside a
    // quoted value or inside another script element's body, so a data
    // block's body is read as markup as well. The quoted-handler pattern
    // also runs over the whole text and finds a handler after a template
    // expression whose `>` ends the tag early. A handler both passes
    // find is reported once.
    scan: function (file) {
      var out = [];
      if (!/\.html$/.test(file.rel)) return out;
      var text = file.text;
      function _at(index, content) {
        return {
          file:    file.rel,
          line:    text.slice(0, index).split(/\r?\n/).length,
          content: content,
        };
      }
      var handlerAt = {};
      function _handler(index, name) {
        if (handlerAt[index]) return;
        handlerAt[index] = 1;
        out.push(_at(index, name + "= is an event handler this policy refuses to run"));
      }
      var m;
      var quoted = /\s(on[a-z]{3,})\s*=\s*["']/g;
      while ((m = quoted.exec(text)) !== null) _handler(m.index + 1, m[1]);

      var open = /<[A-Za-z]/g;
      while ((m = open.exec(text)) !== null) {
        var tag = _htmlStartTag(text, m.index);
        tag.attrs.forEach(function (a) { if (_isHandlerAttr(a)) _handler(a.at, a.name); });
        if (!/^script(?![a-z0-9_])/.test(tag.name)) continue;

        var head = text.slice(m.index, tag.end).replace(/\s+/g, " ");
        var bodyEnd = text.length;
        if (tag.closed) {
          HTML_SCRIPT_END_RE.lastIndex = tag.end;
          var endTag = HTML_SCRIPT_END_RE.exec(text);
          if (endTag !== null) bodyEnd = endTag.index;
        }
        var body = tag.closed ? text.slice(tag.end, bodyEnd) : "";
        if (body.trim().length > 0) {
          var verdict = _templateScriptBodyVerdict(tag.attrs);
          if (verdict !== null) out.push(_at(m.index, head + " " + verdict));
        }
        // The other half of the same rule. A source off this origin is
        // refused by the same directive that refuses an inline body, and
        // it fails the same quiet way. Every `src` on the element is read.
        tag.attrs.forEach(function (a) {
          if (a.name !== "src") return;
          var value = a.value === null ? "" : a.value;
          if (TEMPLATE_SCRIPT_SRC_RE.test(value)) return;
          out.push(_at(m.index,
            "<script src=\"" + value + "\"> is not an absolute path on this server, " +
            "which this policy refuses to load"));
        });
      }
      return out;
    },
    red: [
      { as: "page.html", text: "<button onclick=\"send()\">Send</button>\n" },
      { as: "page.html", text: "<img src=\"/x.png\" onerror=\"boom()\">\n" },
      { as: "page.html", text: "<script>window.ready = true;</script>\n" },
      { as: "page.html", text: "<script defer>\n  boot();\n</script>\n" },
      { as: "page.html", text: "<script src=\"https://cdn.example.net/x.js\"></script>\n" },
      { as: "page.html", text: "<script src=\"//cdn.example.net/x.js\"></script>\n" },
      // A type that a browser runs, or that this file does not list.
      { as: "page.html", text: "<script type=\"\">boot();</script>\n" },
      { as: "page.html", text: "<script type>boot();</script>\n" },
      { as: "page.html", text: "<script type=\"module\">import \"/static/islands/x.js\";</script>\n" },
      { as: "page.html", text: "<script type=\"text/javascript\">boot();</script>\n" },
      { as: "page.html", text: "<script type=\" Text/JavaScript \">boot();</script>\n" },
      { as: "page.html", text: "<script type=module>boot();</script>\n" },
      { as: "page.html", text: "<script type=\"text/jscript\">boot();</script>\n" },
      { as: "page.html", text: "<script type=\"importmap\">{\"imports\":{}}</script>\n" },
      // A listed type with an event handler on the element.
      { as: "page.html", text: "<script type=\"application/ld+json\" onload=\"boot()\">{}</script>\n" },
      { as: "page.html", text: "<script type=\"application/ld+json\" onload=boot()>{}</script>\n" },
      { as: "page.html", text: "<script type=\"application/ld+json\"ONLOAD=boot()>{}</script>\n" },
      // Two type attributes, in either order, in any case, and with a `>`
      // inside a quoted value between them.
      { as: "page.html", text: "<script type=\"application/ld+json\" type=\"module\">boot();</script>\n" },
      { as: "page.html", text: "<script type=\"module\" type=\"application/ld+json\">boot();</script>\n" },
      { as: "page.html", text: "<script TYPE=\"application/ld+json\" Type=\"text/javascript\">boot();</script>\n" },
      { as: "page.html", text: "<script type=\"application/ld+json\" data-note=\">\" type=\"module\">boot();</script>\n" },
      // Script after a data block, where the data block's end tag carries
      // an attribute or the executable element opens inside its body.
      { as: "page.html", text: "<script type=\"application/ld+json\">{}</script foo><script>boot();</script>\n" },
      { as: "page.html", text: "<svg><script type=\"application/ld+json\"><p><script>boot();</script></script></svg>\n" },
      // A script element whose end tag never arrives.
      { as: "page.html", text: "<script>\n  boot();\n" },
      // Handlers the quoted pattern alone does not reach.
      { as: "page.html", text: "<button onclick=send()>Send</button>\n" },
      { as: "page.html", text: "<button ONCLICK=\"send()\">Send</button>\n" },
      { as: "page.html", text: "<img src=\"/x.png\"/onerror=\"boom()\">\n" },
      // Sources that resolve off this origin.
      { as: "page.html", text: "<script src=https://cdn.example.net/x.js></script>\n" },
      { as: "page.html", text: "<script src=\"/\\cdn.example.net/x.js\"></script>\n" },
      { as: "page.html", text: "<script src=\"/&#47;cdn.example.net/x.js\"></script>\n" },
    ],
    green: [
      { as: "page.html", text: "<script src=\"/static/islands/mailbox.js\" defer></script>\n" },
      { as: "page.html", text: "<button type=\"submit\" name=\"theme\" value=\"dark\">Dark</button>\n" },
      { as: "page.html", text: "<form method=\"post\" action=\"/compose\" data-island=\"compose\">\n" },
      // Data blocks, with the type quoted three ways, in mixed case, with
      // a parameter, padded, and on a tag split across lines.
      { as: "page.html", text: "<script type=\"application/ld+json\">{\"@type\":\"SoftwareApplication\"}</script>\n" },
      { as: "page.html", text: "<script type='application/ld+json'>{\"@type\":\"SoftwareApplication\"}</script>\n" },
      { as: "page.html", text: "<script type=application/ld+json>{\"@type\":\"SoftwareApplication\"}</script>\n" },
      { as: "page.html", text: "<script type=\"Application/LD+JSON\">{\"@type\":\"SoftwareApplication\"}</script>\n" },
      { as: "page.html", text: "<script type=\"application/ld+json; charset=utf-8\">{\"@type\":\"SoftwareApplication\"}</script>\n" },
      { as: "page.html", text: "<script type=\" application/json \" id=\"compose-limits\">{\"recipients\":100}</script>\n" },
      { as: "page.html", text: "<script\n  type=\"application/ld+json\"\n>\n{\"@type\":\"SoftwareApplication\"}\n</script>\n" },
      // A data block beside a loaded island, and one whose body a template
      // writes raw from a value serialized for a script element.
      { as: "page.html", text: "<script type=\"application/ld+json\">{}</script>\n" +
        "<script src=\"/static/islands/theme.js\" defer></script>\n" },
      { as: "page.html", text: "  {% if structuredData %}<script type=\"application/ld+json\">" +
        "{{{ structuredData }}}</script>{% endif %}\n" },
      // Prose naming a word that opens with "on", outside any tag.
      { as: "page.html", text: "<p>Set online = true in the config.</p>\n" },
    ],
  },

  {
    name: "listener-state-carried-as-a-boolean",
    description:
      "A listener's place in the inventory written or read as a boolean. Two values can " +
      "say that a port is held and that it is not, and there the vocabulary runs out: a " +
      "listener this server deliberately left shut lands on the same side as one that was " +
      "supposed to bind and did not, and every reader downstream treats the pair as one " +
      "fact. It is not one fact. Port 25 stays closed while no domain is hosted, which is " +
      "the state every first boot passes through, because the documented sequence starts " +
      "the server and only then creates the first domain. Read as a failure, that window " +
      "is a working mail server reporting itself down to every readiness gate, load " +
      "balancer and dependent service for as long as the setup takes, while submission, " +
      "IMAP, ManageSieve and the browser surface are all serving. Read as fine, it is a " +
      "server whose MX port is shut and whose monitoring says mail is arriving. Carry the " +
      "state word from blamepost.mail.listeners.LISTENER_STATES instead, and carry the " +
      "reason beside it, so a reader can tell a refusal this server can explain from a " +
      "port that should be open and is not.",
    dirs: ["lib", "bin"],
    // Anchored on the field name rather than on any function around it,
    // because the shape is a data contract and not a control flow: a
    // boolean cannot carry three states however the code reading it is
    // arranged, so there is no second condition that would make one of
    // these acceptable. `bound` survives every rename of the functions
    // that build and read the inventory, and stops matching only when
    // the field itself is gone, which is the fix. Comments are masked
    // out before the match, so prose describing the shape neither trips
    // it nor silences it.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      // The read: a row's membership tested against a boolean.
      var READ = /\.bound\s*(?:===|!==)\s*(?:true|false)\b/g;
      // The write: the field built as a boolean, whether from a literal,
      // a `typeof` probe, a cast or a double negation.
      var WRITE = /\bbound\s*:\s*(?:true\b|false\b|typeof\b|Boolean\(|!!)/g;
      [
        [READ,  "a listener's state is read here as a boolean"],
        [WRITE, "a listener's state is written here as a boolean"],
      ].forEach(function (pair) {
        var re = pair[0];
        var m;
        re.lastIndex = 0;
        while ((m = re.exec(mask)) !== null) {
          out.push(_atOffset(file, m.index, pair[1]));
        }
      });
      return out;
    },
    red: [
      // The read that turns a deliberate refusal into a failure.
      "function verdict(table) {\n" +
        "  var down = table.filter(function (row) { return row.bound !== true; });\n" +
        "  return { ok: down.length === 0, unbound: down.map(nameOf) };\n}\n",
      // The write that leaves the reader above nothing else to go on.
      "function inventory(shape) {\n" +
        "  return names.map(function (name) {\n" +
        "    return { name: name, bound: typeof shape.bound[name] === \"number\" };\n" +
        "  });\n}\n",
      // The same collapse spelled as a cast.
      "function row(name, port) {\n  return { name: name, bound: Boolean(port) };\n}\n",
      // And as a literal, which is how a fixture teaches the shape back
      // into the tree it was written for.
      "function row(name) {\n  return { name: name, bound: false };\n}\n",
    ],
    green: [
      // The state word and the reason, which is what a reader needs in
      // order to tell the two absent ports apart.
      "function inventory(shape, held) {\n" +
        "  return names.map(function (name) {\n" +
        "    if (typeof shape.bound[name] === \"number\") {\n" +
        "      return { name: name, state: \"bound\", reason: null };\n    }\n" +
        "    if (typeof held[name] === \"string\") {\n" +
        "      return { name: name, state: \"withheld\", reason: held[name] };\n    }\n" +
        "    return { name: name, state: \"unbound\", reason: \"it holds no port\" };\n" +
        "  });\n}\n",
      // The reader that sorts by state and keeps the third case apart
      // from the failing one.
      "function verdict(table) {\n" +
        "  var sorted = { bound: [], withheld: [], unbound: [], disabled: [] };\n" +
        "  table.forEach(function (row) { sorted[row.state].push(row); });\n" +
        "  return { ok: sorted.unbound.length === 0, held: sorted.withheld };\n}\n",
      // The ports a listener handle actually took, which is a map of
      // numbers and not a row of the inventory at all.
      "function bound() {\n  return Object.assign({}, boundPorts);\n}\n",
      // Reading a port out of that map, which names the field without
      // reducing it to a yes or a no.
      "function portOf(shape, name) {\n" +
        "  return typeof shape.bound[name] === \"number\" ? shape.bound[name] : null;\n}\n",
      // Prose describing the shape the rule refuses, in both comment
      // forms, because a rule stated in the tree must not trip the
      // detector that enforces it.
      "// a row written as { name: name, bound: true } cannot carry the third state\n" +
        "// and a reader testing entry.bound !== true collapses it back again\n",
      "/**\n" +
        " * A row of { name: name, bound: false } holds two states where three\n" +
        " * are needed, and entry.bound === true reads only one of them.\n" +
        " */\n",
    ],
  },
  {
    name: "security-gate-waived-on-an-unvalidated-header",
    description:
      "A security middleware composed with an option that stands the gate down on a request " +
      "header the application never validates. The waiver reads the header's presence and " +
      "nothing else, so any caller writes the value that buys it: a header naming a scheme " +
      "with no credential behind it satisfies the skip exactly as a real one does. Presence " +
      "is not authenticity, and an attacker composing a cross-site request writes their own " +
      "headers, so a gate keyed on one is a gate keyed on something the attacker controls. " +
      "It is sound only where presence really does prove that no ambient credential is in " +
      "play, and it stops being sound the moment the same request can carry one as well. " +
      "Validating the header's value does not repair it either: that would be an " +
      "authentication check, and the request would still be one the ambient credential " +
      "authenticated. Key the waiver on the ABSENCE of the ambient credential — the cookie a " +
      "browser attaches by itself — rather than on the presence of a header, and never let it " +
      "waive an origin cross-check, which answers a different question than a token compare " +
      "does.",
    dirs: ["lib", "bin"],
    // Anchored on the option key rather than on the mount around it. The
    // key is a published name on the framework surface this repository
    // composes against, so it does not go quiet when something here is
    // renamed, and it stops matching only when the composition stops
    // asking for the waiver, which is the fix. Comments are masked before
    // the match, so prose stating the rule neither trips it nor silences
    // it.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      [
        // The key names the header that waives the gate, so spelling it at
        // all is the waiver: there is no off value to write.
        //
        // `csrfProtect`'s `skipStateless` used to be the other member of
        // this family and was matched here beside it. It is not one any
        // more. That option now keys on the absence of a Cookie header and
        // nothing else, and it sits below the origin cross-check rather
        // than above it, so composing it waives a token compare for a
        // caller that has no ambient credential to forge and waives
        // nothing else. That is the rule this detector is written to
        // enforce rather than a violation of it, so matching the key would
        // report the correct composition as the bug — which is the failure
        // mode a detector cannot recover from, because the fix for it is
        // to reintroduce the hole.
        [/\bskipHeader\s*:/g,
          "a gate is waived here on a request header any caller can write"],
      ].forEach(function (pair) {
        var re = pair[0];
        var m;
        re.lastIndex = 0;
        while ((m = re.exec(mask)) !== null) {
          out.push(_atOffset(file, m.index, pair[1]));
          if (m.index === re.lastIndex) re.lastIndex += 1;
        }
      });
      return out;
    },
    red: [
      // The shape that shipped: the waiver taken from the option, on the
      // one chain the browser surface routes every request through.
      "function _mountNotice(router) {\n" +
        "  router.use(b.middleware.aiActDisclosure({ skipHeader: \"x-skip-notice\" }));\n}\n",
      // The same trade spread over an object literal, which is where a
      // budgeted matcher would stop reading.
      "function _mountNotice(router) {\n" +
        "  router.use(b.middleware.aiActDisclosure({\n" +
        "    audience:   \"operator\",\n" +
        "    skipHeader: \"x-skip-notice\",\n" +
        "  }));\n}\n",
      // The header handed in from configuration, so no literal names it.
      "function _mountNotice(router, cfg) {\n" +
        "  router.use(b.middleware.aiActDisclosure({ skipHeader: cfg.bypassHeader }));\n}\n",
    ],
    green: [
      // The waiver keyed on the absence of the ambient credential, which
      // is the shape that is sound: a caller carrying no cookie has
      // nothing a cross-site page could spend, and the origin cross-check
      // still runs underneath it.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.csrfProtect({\n" +
        "    cookie:        true,\n" +
        "    checkOrigin:   true,\n" +
        "    skipStateless: true,\n" +
        "  }));\n}\n",
      // The same on one line, because the composition is written both
      // ways across the tree.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.csrfProtect({ cookie: true, skipStateless: true, " +
        "checkOrigin: true }));\n}\n",
      // A route exemption, which is a different decision: it names paths
      // the operator chose, not a header the caller writes.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.csrfProtect({ cookie: true, skipPaths: [\"/.well-known/\"] }));\n}\n",
      // Prose stating the rule, in both comment forms, because a rule
      // written into the tree must not trip the detector enforcing it.
      "// composing skipHeader: \"x-skip-notice\" waives a gate on a header nothing validates\n" +
        "// and any caller can write the value that buys the skip\n",
      "/**\n" +
        " * Never compose skipHeader here: the waiver reads the header's\n" +
        " * presence, and an attacker composing a cross-site request writes\n" +
        " * their own headers.\n" +
        " */\n",
    ],
  },

  {
    name: "transport-reading-middleware-left-on-the-framework-default",
    description:
      "A framework middleware that decides from the transport, mounted without being handed " +
      "this surface's own reading of it. `securityHeaders` decides whether HSTS is sent, and " +
      "`csrfProtect` decides whether the double-submit cookie carries `Secure` and the " +
      "`__Host-` prefix and which scheme the origin cross-check builds this server's own " +
      "origin from. Left on the framework's default resolver, each of them answers from the " +
      "socket this process holds. Behind a terminator that socket is cleartext while the " +
      "browser's connection is TLS, so the cookie loses the attributes that keep it off the " +
      "cleartext port and the cross-check compares against a scheme no browser used. Both of " +
      "these are mounted twice on this surface, once on the request lifecycle the application " +
      "factory builds and once on the chain the routes mount, and the two run at different " +
      "points: the earlier mount decides the first refusal and the later one writes the last " +
      "header. One mount left on the default therefore reads this process's socket while its " +
      "twin reads the proxy, a request measures one of each pair and says nothing about the " +
      "other, and the split surfaces only as a deployment behind a terminator answering " +
      "differently from the same request arriving directly. Build one reading with " +
      "`b.requestHelpers.trustedProtocol`, which takes `X-Forwarded-Proto` from a peer the " +
      "configuration names and from nobody else, and pass it as `protocolResolver` at every " +
      "mount. The application factory mounts both of these unless told otherwise, so a call " +
      "that configures neither is two mounts on the default rather than none.",
    dirs: ["lib", "bin"],
    // Anchored on the framework's own names in both mounting shapes: the
    // two middleware constructors, and the two keys the application
    // factory reads its middleware configuration by. Those are the
    // surface this repository composes against rather than symbols it
    // can rename, so nothing renamed here goes quiet, and a deletion
    // takes the mount away along with the match.
    //
    // What is required is the KEY and never the value. The reading is
    // built once and handed around under whatever local name the file
    // gives it, so a matcher spelling that name would go quiet the first
    // time somebody renamed a variable.
    //
    // Both extents are bracket pairs, the call's own and the
    // configuration literal's, so a mount that grows is still read
    // whole. Nothing here is bounded by a character count for a body to
    // outgrow.
    //
    // Read off the mask, so the same names written in a comment or
    // inside a message the reader is shown are prose rather than a
    // mount, and a sentence stating the rule can neither trip this nor
    // silence it.
    //
    // Two shapes are reported that are not a missing key. A factory call
    // configured from a value rather than from a literal is reported
    // because the transport its middleware answer from cannot be read at
    // the mount, which is the whole of what this rule asks for. And
    // switching one of the pair off is not accommodated: the security
    // middleware on this surface are not behind a switch, so a
    // configuration that removed one would be the larger finding rather
    // than a way past this one.
    scan: function (file) {
      var mask     = _maskOf(file);
      var out      = [];
      var resolver = /\bprotocolResolver\s*:/;
      var hit;

      var mounted = /\bb\s*\.\s*middleware\s*\.\s*(securityHeaders|csrfProtect)\s*\(/g;
      while ((hit = mounted.exec(mask)) !== null) {
        var openParen  = hit.index + hit[0].length - 1;
        var closeParen = _matchingBracket(mask, openParen);
        if (closeParen !== -1 && resolver.test(mask.slice(openParen, closeParen))) continue;
        out.push(_atOffset(file, hit.index,
          "b.middleware." + hit[1] + " is mounted with no protocolResolver, so it decides " +
          "from this process's own socket"));
      }

      var factory = /\bb\s*\.\s*createApp\s*\(/g;
      var keys    = ["securityHeaders", "csrf"];
      while ((hit = factory.exec(mask)) !== null) {
        var open  = hit.index + hit[0].length - 1;
        var close = _matchingBracket(mask, open);
        if (close === -1) continue;
        var at = open + 1;
        while (at < close && /\s/.test(mask[at])) at += 1;
        if (mask[at] !== "{") {
          out.push(_atOffset(file, hit.index,
            "b.createApp is configured from a value rather than from a literal, so the " +
            "transport its middleware decide from cannot be read at the mount"));
          continue;
        }
        var appEnd = _matchingBracket(mask, at);
        if (appEnd === -1) continue;
        var mw = _objectValueBraces(mask, { start: at, end: appEnd }, "middleware");
        for (var k = 0; k < keys.length; k += 1) {
          var cfg = mw === null ? null : _objectValueBraces(mask, mw, keys[k]);
          if (cfg !== null && resolver.test(mask.slice(cfg.start, cfg.end))) continue;
          out.push(_atOffset(file, hit.index,
            "b.createApp mounts " + keys[k] + " with no protocolResolver, so it decides " +
            "from this process's own socket"));
        }
      }
      return out;
    },
    red: [
      // The mount taking every default there is, which is the shape a
      // second chain gets added with.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.securityHeaders());\n}\n",
      // Options named, and not this one, which is the shape a mount
      // drifts into as other settings are added around it.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.csrfProtect({\n" +
        "    cookie:        true,\n" +
        "    checkOrigin:   true,\n" +
        "    skipStateless: true,\n" +
        "  }));\n}\n",
      // The options assembled out of sight and handed in, which leaves a
      // reader of the mount unable to say which transport it answers
      // from.
      "function _mountSecurity(router, opts) {\n" +
        "  router.use(b.middleware.securityHeaders(opts));\n}\n",
      // One of the pair wired through the application factory and its
      // twin left on the default, which is the split this rule exists
      // for: the two run at different points and answer from different
      // connections.
      "async function start() {\n" +
        "  app = await b.createApp({\n" +
        "    routes:     handle.routes,\n" +
        "    middleware: {\n" +
        "      securityHeaders: { protocolResolver: handle.resolveProtocol },\n" +
        "      csrf:            { cookie: true },\n" +
        "    },\n" +
        "  });\n}\n",
      // The factory configuring neither, which mounts both on the
      // default rather than mounting neither.
      "async function start() {\n" +
        "  app = await b.createApp({ dataDir: dataDir, routes: handle.routes });\n}\n",
      // The whole configuration built elsewhere.
      "async function start() {\n  app = await b.createApp(appOptions);\n}\n",
    ],
    green: [
      // Both mounts on the routed chain handed the one reading, written
      // across an object literal.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.securityHeaders({\n" +
        "    referrerPolicy:   REFERRER_POLICY,\n" +
        "    protocolResolver: transport.resolve,\n" +
        "  }));\n" +
        "  router.use(b.middleware.csrfProtect({\n" +
        "    cookie:           true,\n" +
        "    checkOrigin:      true,\n" +
        "    skipStateless:    true,\n" +
        "    protocolResolver: transport.resolve,\n" +
        "  }));\n}\n",
      // The same on one line, because the composition is written both
      // ways across the tree.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.csrfProtect({ cookie: true, " +
        "protocolResolver: transport.resolve }));\n}\n",
      // The factory with both configured, each under the name the
      // factory reads it by.
      "async function start() {\n" +
        "  app = await b.createApp({\n" +
        "    dataDir:    dataDir,\n" +
        "    routes:     handle.routes,\n" +
        "    middleware: {\n" +
        "      securityHeaders: {\n" +
        "        referrerPolicy:   REFERRER_POLICY,\n" +
        "        protocolResolver: handle.resolveProtocol,\n" +
        "      },\n" +
        "      csrf: { protocolResolver: handle.resolveProtocol },\n" +
        "    },\n" +
        "  });\n}\n",
      // A middleware that decides nothing from the transport, mounted
      // the way the rest of the chain is.
      "function _mountSecurity(router) {\n" +
        "  router.use(b.middleware.botGuard());\n" +
        "  router.use(b.middleware.fetchMetadata());\n}\n",
      // The names inside a message the reader is shown, which describes
      // the factory rather than calling it.
      "function _refuse() {\n" +
        "  throw new TypeError(\"mountJmapWebSocket(server) needs the bound HTTP server, \" +\n" +
        "    \"the one b.createApp().listen resolves with.\");\n}\n",
      // Prose stating the rule, in both comment forms, because a rule
      // written into the tree must not trip the detector enforcing it.
      "// b.createApp mounts securityHeaders and csrfProtect unless told\n" +
        "// otherwise, so a middleware block naming neither leaves both of\n" +
        "// them reading this process's own socket.\n",
      "/**\n" +
        " * Pass protocolResolver to b.middleware.securityHeaders() and to\n" +
        " * b.middleware.csrfProtect() at every mount, so the HSTS decision\n" +
        " * and the cookie and origin decisions come from one reading.\n" +
        " */\n",
    ],
  },

  {
    name: "build-context-exclusion-that-stops-at-the-root",
    description:
      "A .dockerignore exclusion with no `**/` in front of it. The syntax reads like " +
      ".gitignore's and is not: a .gitignore pattern carrying no slash matches at every " +
      "depth, while a .dockerignore pattern is matched against the whole relative path with " +
      "Go's filepath.Match, whose `*` never crosses a separator. So a bare name there covers " +
      "the context root and nothing under it, and the patterns written that way are the ones " +
      "naming credential material and developer scratch, which is the half that must not be " +
      "the half doing nothing. The failure is silent in the direction that costs: the file " +
      "reads as though it excludes the thing, the build succeeds, and the environment file " +
      "holding a vault passphrase is uploaded to the daemon from one directory in. Write " +
      "`**/name`, which covers the root as well as every depth below it. A negation is exempt " +
      "by shape rather than by exception: it puts a path back, and a re-include that reached " +
      "every depth would be the dangerous direction of the same mistake.",
    dirs: ["docker"],
    exts: PROSE_EXT_RE,
    includeRepoRoot: true,
    scan: function (file) {
      if (!/(?:^|\/)\.dockerignore$/.test(file.rel)) return [];
      var out = [];
      for (var i = 0; i < file.lines.length; i++) {
        var line = file.lines[i].trim();
        if (line === "" || line.charAt(0) === "#" || line.charAt(0) === "!") continue;
        if (line.indexOf("**/") === 0) continue;
        out.push({ file: file.rel, line: i + 1, content: line });
      }
      return out;
    },
    red: [
      { as: ".dockerignore", text: ".env\n.env.*\n" },
      { as: ".dockerignore", text: "# Runtime state.\n**/data\n.npmrc\n" },
      { as: ".dockerignore", text: "**/*.pem\nid_rsa*\n" },
    ],
    green: [
      { as: ".dockerignore",
        text: "# Credential material, excluded at every depth.\n\n" +
              "**/.env\n**/.env.*\n**/*.pem\n**/id_rsa*\n!lib/vendor/**\n" },
      // The rule is about the file docker reads, not about the shape of a
      // line. A bare name in prose or in a gitignore is not an exclusion
      // that silently covers one directory.
      { as: "notes.md", text: ".env\n.env.*\n" },
      { as: ".gitignore", text: ".env\n.env.*\n" },
    ],
  },

  {
    name: "documentation-tag-matched-outside-its-reader",
    description:
      "A pattern that matches a documentation block tag, outside the module that owns the parse. " +
      "The documentation gates and the reference wiki read the same blocks, and each governs " +
      "exactly the set it read, so a second matcher is a second answer to what a block says. " +
      "The failure is silent in both directions. A primitive a gate's own pattern does not " +
      "reach is one that gate reports nothing about, so its verdict still reads clean. A block " +
      "a gate reads one way and the wiki reads another passes the gate and then fails the wiki " +
      "build that runs when the server is created. Take the records from " +
      "scripts/source-primitives.js, which is lib/web/wiki/blocks.js bound to this repository " +
      "and carries every tag any gate or page needs. The tag spelling is the anchor because it " +
      "is the contract: a matcher can be renamed freely and still has to spell the tag, or " +
      "capture a tag name, to find anything, so no rename can quietly retire this rule. What " +
      "is matched is a tag opening a pattern, which is what a parse looks like; naming a tag " +
      "in a message or in prose describes one and is left alone.",
    dirs: ["lib", "bin", "scripts", "test"],
    scan: function (file) {
      if (DOCUMENTATION_READER_RE.test(file.rel)) return [];
      return _lineMatcher(DOCUMENTATION_TAG_MATCHER_RE, "code")(file);
    },
    red: [
      "var prim = /@primitive\\s+(\\S+)/.exec(block);\n",
      "var mp = line.match(/@primitive\\s+(\\S+)/);\n",
      "var re = new RegExp(\"@primitive\\\\s+(\\\\S+)\");\n",
      "var anchored = /^@primitive\\b/.test(line.trim());\n",
      // A second reader of another tag the reader returns. This line was
      // the comment block gate's own reading of `@signature`.
      "var SIGNATURE_LINE_RE  = /^@signature\\s+(.+)$/;\n",
      "var nav = /^@nav\\s+(.+)$/.exec(line);\n",
      // A reader of any tag, built from the name held in a variable. This
      // line was scripts/source-primitives.js reading every tag itself.
      "  var re = new RegExp(\"^@\" + name + \"\\\\s+(.+)$\");\n",
      "var TAG = /^@([A-Za-z][A-Za-z0-9]*)(?:\\s+(\\S.*))?$/;\n",
      // The script the gates read through composes the reader, so a
      // matcher written there is a second parse like any other.
      { as:   "scripts/source-primitives.js",
        text: "var m = /@primitive\\s+(\\S+)/.exec(blockText);\n" },
    ],
    green: [
      // The shared reader, asked for the tag by name. Nothing here spells
      // the tag, so a rename of the helper cannot make this shape drift
      // back into a second parse.
      "var token = _tag(lines, \"primitive\");\n",
      "var since = sourcePrimitives.tagMap(primitives, \"since\");\n",
      "var text = typeof record.signature === \"string\" ? record.signature : null;\n",
      // The tag named inside a message the reader is shown. It describes
      // the parse rather than performing one, and rewording a correct
      // sentence to get past a detector removes the evidence without
      // changing anything real.
      "finding(\"unresolved-related\", p, \"@related \" + t + \" is not a declared @primitive.\");\n",
      // A documentation block declaring one. This is the thing being
      // parsed, not a parse of it, and it appears in lib/ and test/ by
      // the hundred.
      " * @primitive blamepost.store.openSnapshot\n * @since 0.1.0\n",
      " * @module blamepost.web.wiki\n * @nav    Reference wiki\n",
      "// Reads each @primitive block's @status and @since from the shared records.\n",
      // Patterns opening on an at sign that read no documentation tag: an
      // address, a package scope and an image digest.
      "var recipient = /@example\\.net$/.test(address);\n",
      "var re = new RegExp(\"@example\\\\.net$\");\n",
      "var bare = String(name).replace(/^@[^/]+\\//, \"\");\n",
      "var DIGEST_RE = /@(sha256:[0-9a-f]{64})\\b/;\n",
      // The line-scoped declaration readers the gates keep for themselves.
      // Neither is a documentation block tag.
      { as:   "scripts/source-primitives.js",
        text: "var REMOVAL_RE = /^(?:\\/\\/+|\\*|\\/\\*\\*)?\\s*@removed\\s+(.+?)\\s*$/;\n" },
      // The owner is where the matcher belongs, so it is the one file the
      // rule cannot apply to.
      { as:   "lib/web/wiki/blocks.js",
        text: "var TAG_LINE_RE = /^@([A-Za-z][A-Za-z0-9]*)(?:\\s+(\\S.*))?$/;\n" },
    ],
  },

  {
    name: "request-verb-chosen-by-a-default",
    description:
      "A handler that picks which verb to run from a request field, supplying a verb of its " +
      "own when the field is absent. Every administration page in this server posts one form " +
      "field naming what the operator pressed, and every one of those pages carries a verb " +
      "that erases something: a queue flush, a key rotation, a domain added, an account " +
      "created, an alias written. A default turns the two ways that field can fail to arrive " +
      "into that verb. A request naming nothing runs it, and so does a request naming " +
      "anything the handler does not recognize, because a value that matches no branch falls " +
      "to the same place an absent one does. Neither is a request for the verb, and the " +
      "operator sees the result of an act nobody asked for. Read the field with an empty " +
      "default, dispatch on equality, and let a value that matches no branch fall through to " +
      "the page: an unrecognized verb is a request that named nothing this server does, and " +
      "doing nothing is the only answer that cannot be wrong. Both defaulting spellings are " +
      "matched, the reader's fallback argument and the `||` after it, because which one a " +
      "handler uses says nothing about what it does.",
    dirs: ["lib", "bin"],
    // Anchored on the field name and on the shape of a supplied default,
    // neither of which any rename inside this repository reaches. The
    // field name is the contract between a rendered form and the route
    // that reads it: renaming it means renaming the `name=` attribute on
    // every button in lib/web/views in the same change, and the pair
    // still has to be spelled somewhere for a handler to dispatch at all.
    // A deletion removes the hazard along with the match.
    //
    // There is no character budget: the match is a field read and the
    // literal immediately beside it, so nothing about how long the
    // handler grows changes what is found.
    //
    // Read off the mask, so a comment quoting the shape is the prose it
    // is rather than a dispatch, and a sentence describing the rule can
    // neither trip this nor silence it.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      var re   = /\.action\s*(?:,\s*|\|\|\s*)"[^"\n]+"/g;
      var hit;
      while ((hit = re.exec(mask)) !== null) {
        out.push(_atOffset(file, hit.index));
        if (hit.index === re.lastIndex) re.lastIndex += 1;
      }
      return out;
    },
    red: [
      "router.post(\"/admin/queue\", requireAdmin, async function (req, res) {\n" +
        "  if (_str(body.action, \"run\") === \"run\") { await queue.runDue(); return; }\n" +
        "});\n",
      // The other spelling, which a second author reaches for.
      "async function _save(req) {\n" +
        "  var action = req.body.action || \"add\";\n" +
        "  if (action === \"remove\") return _remove(req);\n" +
        "  return _add(req);\n}\n",
      // A default written across the argument list, which a matcher bound
      // to one spelling of the whitespace misses.
      "function _dispatch(body) {\n" +
        "  var action = _str(body.action,\n    \"rotate\");\n" +
        "  return action;\n}\n",
    ],
    green: [
      // The empty default, with every verb named and nothing at the end
      // but the page.
      "router.post(\"/admin/queue\", requireAdmin, async function (req, res) {\n" +
        "  var action = _str(body.action, \"\");\n" +
        "  if (action === \"run\")    { await _run(req, res);    return; }\n" +
        "  if (action === \"cancel\") { await _cancel(req, res); return; }\n" +
        "  await _renderQueue(req, res, null, 0);\n});\n",
      // A field that is not the dispatch field, defaulted, which is
      // ordinary in a browser surface where a missing parameter is not an
      // event.
      "function _read(query) {\n  return _str(query.folder, \"Inbox\");\n}\n",
      // The same field read with no default at all.
      "function _read(body) {\n  return typeof body.action === \"string\" ? body.action : \"\";\n}\n",
      // A sentence describing the rule, which is prose and not a dispatch.
      "// A handler that read body.action, \"run\" would run the queue for a\n" +
        "// request that named nothing.\n",
    ],
  },

  {
    name: "audited-reason-supplied-by-the-page",
    description:
      "A rendered form that fills in the reason an audit row records. The identity layer keeps " +
      "`reason` as a column of its own precisely so an incident review can read why a mailbox " +
      "was suspended, why a domain stopped accepting mail, or why a message was cancelled off " +
      "the spool, and it refuses several of those verbs without one. A hidden field, or a " +
      "prefilled value on a visible one, satisfies that refusal with a sentence nobody chose: " +
      "every row then carries the same words whatever happened, which is worse than carrying " +
      "none, because a column that is present and always identical reads like somebody wrote " +
      "it and an absent one is visibly absent. Ask the operator, and let the layer underneath " +
      "refuse when they decline to answer. A verb that genuinely warrants no typed reason " +
      "records what the layer performing it knows rather than a sentence collected by a form " +
      "and thrown away.",
    dirs: ["lib"],
    exts: /\.html$/,
    // Anchored on the field name and on the two markup shapes that supply
    // a value for it. The name is the contract between the template and
    // the route that reads it, and the route reads it to fill an audit
    // column of the same name, so a rename is a change to both ends at
    // once rather than a refactor that could leave this quiet. A control
    // asking the operator for the value carries no `value` attribute and
    // is not matched, which is the whole distinction being drawn.
    scan: function (file) {
      if (!/\.html$/.test(file.rel)) return [];
      var out = [];
      var re  = /<input\b[^>]*>/gi;
      var tag;
      while ((tag = re.exec(file.text)) !== null) {
        var text = tag[0];
        if (!/\bname\s*=\s*"reason"/i.test(text)) continue;
        var hidden = /\btype\s*=\s*"hidden"/i.test(text);
        var filled = /\bvalue\s*=\s*"[^"]+"/i.test(text);
        if (!hidden && !filled) continue;
        out.push({
          file:    file.rel,
          line:    file.text.slice(0, tag.index).split(/\r?\n/).length,
          content: text.replace(/\s+/g, " ").trim(),
        });
      }
      return out;
    },
    red: [
      { as: "accounts.html",
        text: "<input type=\"hidden\" name=\"reason\" value=\"operator request\">\n" },
      // A visible control the page has already answered for, which is the
      // same sentence on every row with an edit box drawn around it.
      { as: "domains.html",
        text: "<input id=\"reason\" name=\"reason\" type=\"text\" value=\"operator request\">\n" },
      // Attribute order is the author's choice and says nothing about
      // what the field does.
      { as: "queue.html",
        text: "<input name=\"reason\" value=\"routine maintenance\" type=\"hidden\">\n" },
    ],
    green: [
      // The operator is asked, and the layer underneath refuses an empty
      // answer.
      { as: "accounts.html",
        text: "<label for=\"reason\">Why</label>\n" +
          "<input id=\"reason\" name=\"reason\" type=\"text\" autocomplete=\"off\" required>\n" },
      // An empty value attribute supplies nothing, which is what a form
      // redrawn after a refusal carries.
      { as: "queue.html",
        text: "<input id=\"reason\" name=\"reason\" type=\"text\" value=\"\">\n" },
      // A hidden field carrying something that is not a reason. The row
      // has to know WHICH account, and the page is the only thing that
      // knows which row the button was on.
      { as: "accounts.html",
        text: "<input type=\"hidden\" name=\"id\" value=\"{{ a.id }}\">\n" },
      // The word in prose, describing what the field is for.
      { as: "queue.html",
        text: "<p class=\"hint\">Recorded as the reason against each cancelled message.</p>\n" },
    ],
  },

  {
    name: "imap-selection-without-permanentflags",
    description:
      "An IMAP selection answered with UIDVALIDITY and no PERMANENTFLAGS. RFC 9051 section " +
      "6.3.2 makes both required OK untagged responses to SELECT and to EXAMINE, and a " +
      "client that is not sent PERMANENTFLAGS is entitled to assume every flag it sends is " +
      "kept. It then offers the account holder tags the mailbox will not hold, and offers no " +
      "way to invent one where the mailbox would have held it, because the same response is " +
      "what carries the \\* that says new keywords are allowed. The missing response looks " +
      "like nothing at all on the wire: the selection completes, the mailbox opens, and what " +
      "the client believes about it is wrong. Write the response beside the UIDVALIDITY one, " +
      "naming the flags the selection keeps, and an empty list where it keeps none.",
    dirs: ["lib"],
    // Anchored on the response code as RFC 9051 section 7.1 spells it,
    // which is a wire contract rather than a name any refactor here can
    // change, and bounded by the enclosing function walked as brackets
    // rather than by a line count. The bracket form is what separates the
    // response from the word in a sentence, so the anchor is read off the
    // source; the mask then says whether that offset is code, because a
    // comment describing the response is not one.
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      var re   = /\[UIDVALIDITY\s/g;
      var m;
      while ((m = re.exec(file.text)) !== null) {
        var letter = m.index + 1;
        if (mask[letter] === " ") continue;
        var span = _enclosingFunctionSpan(mask, m.index);
        if (!span) continue;
        if (mask.slice(span.start, span.end).indexOf("PERMANENTFLAGS") !== -1) continue;
        out.push(_atOffset(file, m.index,
          "this selection sends UIDVALIDITY and no PERMANENTFLAGS, so the client is never " +
          "told which flags the mailbox keeps"));
      }
      return out;
    },
    red: [
      "function _select(state, socket, info, tag) {\n" +
        "  _untagged(socket, info.exists + \" EXISTS\");\n" +
        "  _untagged(socket, \"FLAGS (\" + info.flags.join(\" \") + \")\");\n" +
        "  _untagged(socket, \"OK [UIDVALIDITY \" + info.uidvalidity + \"] UIDs valid\");\n" +
        "  _untagged(socket, \"OK [UIDNEXT \" + info.uidnext + \"] Predicted next UID\");\n" +
        "  _tagged(socket, tag, \"OK [READ-WRITE] SELECT completed\");\n" +
        "}\n",
      // The shape the listeners are written in: the handler is built
      // inside a factory and returns a closure, so its closing brace is
      // indented and a matcher anchored at column zero reads past it.
      "function handlerFor(examine) {\n" +
        "  return function (state, socket, parsed) {\n" +
        "    return open(state).then(function (info) {\n" +
        "      _untagged(socket, \"OK [UIDVALIDITY \" + info.uidvalidity + \"] UIDs valid\");\n" +
        "      _tagged(socket, parsed.tag, \"OK SELECT completed\");\n" +
        "    });\n" +
        "  };\n" +
        "}\n",
    ],
    green: [
      "function _select(state, socket, info, tag, examine) {\n" +
        "  _untagged(socket, info.exists + \" EXISTS\");\n" +
        "  _untagged(socket, \"FLAGS (\" + info.flags.join(\" \") + \")\");\n" +
        "  _untagged(socket, \"OK [PERMANENTFLAGS (\" +\n" +
        "    (examine ? [] : info.permanentFlags).join(\" \") + \")] Flags kept\");\n" +
        "  _untagged(socket, \"OK [UIDVALIDITY \" + info.uidvalidity + \"] UIDs valid\");\n" +
        "  _tagged(socket, tag, \"OK SELECT completed\");\n" +
        "}\n",
      // The word in a sentence, describing what the field holds. A
      // comment is not a response.
      "function _next(now) {\n" +
        "  // The value a client caches against, read back as [UIDVALIDITY n].\n" +
        "  return Math.floor(now / 1000);\n" +
        "}\n",
      // The same word as a key of the STATUS answer, which RFC 9051
      // section 6.3.11 asks a different question with.
      "function statusFolder(actor, name) {\n" +
        "  return { MESSAGES: 2, UIDNEXT: 3, UIDVALIDITY: 17 };\n" +
        "}\n",
    ],
  },

  {
    name: "jmap-method-served-without-its-argument-refusal",
    description:
      "A JMAP method handler whose body does not open by taking a refusal from its arguments " +
      "and returning it. Every handler runs behind one dispatcher, and that dispatcher skips " +
      "its cross-account check for a call whose accountId is absent or null: it reads the " +
      "value, finds nothing, and continues to the handler rather than refusing. What closes " +
      "that hole is the handler itself, which refuses a call naming no account before it " +
      "resolves one, so a call that omitted the argument never reaches a store read. A " +
      "handler added without the opening refusal reopens it, and nothing else in the tree is " +
      "positioned to notice: no behavioral test can cover a method that does not exist yet, " +
      "and the dispatcher is vendored and cannot be changed here. Open every handler with " +
      "the two statements the others open with, a refusal taken from args and an immediate " +
      "return of it when it is not null, and put any further argument checking after them. " +
      "The shape is what is required rather than a particular helper, so renaming the " +
      "helpers changes nothing.",
    dirs: ["lib"],
    scan: function (file) {
      var mask = _maskOf(file);
      var out  = [];
      // The key is an RFC 8620 section 5 method name, `Type/verb`, which
      // is wire vocabulary rather than a name this repository chooses:
      // it survives every rename a handler or a helper can undergo, and
      // it disappears only when the method itself is withdrawn.
      var re = /"([A-Z][A-Za-z0-9]*\/[a-z][A-Za-z0-9]*)"\s*:\s*(?:async\s+)?function\s*\([^)]*\)\s*\{(?!\s*var\s+([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\s*\(\s*args\s*\)\s*;\s*if\s*\(\s*\2\s*!==\s*null\s*\)\s*return\s+\2\s*;)/g;
      var m;
      while ((m = re.exec(mask)) !== null) {
        out.push(_atOffset(file, m.index,
          "the " + m[1] + " handler does not open by returning a refusal read from its " +
          "arguments, so a call naming no account reaches it"));
        if (m.index === re.lastIndex) re.lastIndex += 1;
      }
      return out;
    },
    red: [
      // A handler that resolves an account before refusing anything.
      "var methods = {\n" +
        "  \"Email/get\": async function (actor, args) {\n" +
        "    var account = await _account(actor);\n" +
        "    return { accountId: args.accountId, list: [], state: \"1\" };\n" +
        "  },\n};\n",
      // A handler that takes the refusal and then does not act on it.
      "var methods = {\n" +
        "  \"Mailbox/set\": async function (actor, args) {\n" +
        "    var refused = _setRefusal(args);\n" +
        "    var account = await _account(actor);\n" +
        "    if (refused !== null) return refused;\n" +
        "    return { accountId: args.accountId };\n" +
        "  },\n};\n",
      // A handler refusing on the wrong condition, which lets a null
      // answer through exactly where the dispatcher already stopped.
      "var methods = {\n" +
        "  \"EmailSubmission/set\": async function (actor, args) {\n" +
        "    var refused = _setRefusal(args);\n" +
        "    if (refused === null) return refused;\n" +
        "    return { accountId: args.accountId };\n" +
        "  },\n};\n",
      // A handler reading its refusal from something other than the
      // arguments, so the call's own accountId is never examined.
      "var methods = {\n" +
        "  \"Thread/get\": async function (actor, args) {\n" +
        "    var refused = _getRefusal(actor);\n" +
        "    if (refused !== null) return refused;\n" +
        "    return { accountId: args.accountId, list: [] };\n" +
        "  },\n};\n",
    ],
    green: [
      // The shape every handler in the tree opens with. The helper name
      // is read by nothing here, which is the point: rename it and this
      // stays silent.
      "var methods = {\n" +
        "  \"Email/get\": async function (actor, args) {\n" +
        "    var refused = _jmapGetRefusal(args);\n" +
        "    if (refused !== null) return refused;\n" +
        "    var account = await _jmapAccount(actor);\n" +
        "    return { accountId: args.accountId, list: [], state: \"1\" };\n" +
        "  },\n" +
        "  \"Mailbox/query\": async function (actor, args) {\n" +
        "    var stopped = somethingElseEntirely(args);\n" +
        "    if (stopped !== null) return stopped;\n" +
        "    return { accountId: args.accountId, ids: [] };\n" +
        "  },\n};\n",
      // A synchronous handler, which is the same shape without `async`.
      "var methods = {\n" +
        "  \"Identity/get\": function (actor, args) {\n" +
        "    var refused = _getRefusal(args);\n" +
        "    if (refused !== null) return refused;\n" +
        "    return { accountId: args.accountId, list: [] };\n" +
        "  },\n};\n",
      // A key that looks like a method name and holds no handler. A
      // mapping table is not a dispatch table.
      "var LABELS = {\n" +
        "  \"Email/get\": \"read one message\",\n" +
        "  \"Email/set\": \"change one message\",\n};\n",
      // The same words in a comment and in a sentence, which are not
      // keys of anything.
      "// The Email/get handler answers a list. See also Mailbox/query.\n" +
        "function describe() {\n" +
        "  return \"Email/get: function (actor, args) { ... }\";\n" +
        "}\n",
    ],
  },
];

// Allow-class registry. Every detector name is a valid class, plus the
// classes other gates in this repository enforce, so a marker for one
// of those is not reported here as unregistered.
var EXTERNAL_ALLOW_CLASSES = {
  "swallow-unverified": "enforced by scripts/check-swallow-coverage.js",
  "slsa-framework-action-not-sha-pinned":
    "enforced by .pinact.yaml, which names the same reusable workflow: the SLSA generator's " +
    "internal builder fetch refuses a non-tag ref, so it is tag-pinned rather than SHA-pinned",
};

function _validAllowClasses() {
  var out = {};
  DETECTORS.forEach(function (d) { out[d.name] = 1; });
  Object.keys(EXTERNAL_ALLOW_CLASSES).forEach(function (k) { out[k] = 1; });
  return out;
}

// ---------------------------------------------------------------------------
// Allow-marker filtering
// ---------------------------------------------------------------------------

function _filterMarkers(matches, name) {
  var fileAllow = {};
  function _hasFileAllow(rel) {
    if (Object.prototype.hasOwnProperty.call(fileAllow, rel)) return fileAllow[rel];
    var rec = _fileCache[rel];
    var head = rec ? rec.lines.slice(0, 50) : [];
    var re = new RegExp("codebase-patterns:allow-file\\s+" + name + "\\b");
    var found = head.some(function (l) { return re.test(l); });
    fileAllow[rel] = found;
    return found;
  }
  function _hasLineAllow(rel, lineNum) {
    var rec = _fileCache[rel];
    if (!rec) return false;
    var re = new RegExp("allow:" + name + "\\b");
    return re.test(rec.lines[lineNum - 1] || "") ||
           re.test(rec.lines[lineNum - 2] || "") ||
           re.test(rec.lines[lineNum - 3] || "");
  }
  return matches.filter(function (m) {
    if (_hasFileAllow(m.file)) return false;
    if (_hasLineAllow(m.file, m.line)) return false;
    return true;
  });
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

var _allViolations = [];

function _report(name, matches, scanned) {
  if (matches.length > 0) {
    var preview = matches.map(function (m) {
      return "      " + m.file + ":" + m.line + ": " + String(m.content).slice(0, 120);
    }).join("\n");
    console.log("  FAIL  " + name + ": " + matches.length + " violation(s)\n" + preview);
    _allViolations.push({ name: name, count: matches.length });
  } else {
    console.log("  ok    " + name + ": clean over " + scanned + " file(s)");
  }
}

// ---------------------------------------------------------------------------
// Detector self-proof
// ---------------------------------------------------------------------------

// A fixture is either a bare string, which stands for a JavaScript
// source snippet, or `{ as: "<name>", text: "..." }` when the matcher
// reads the file's name. A detector that treats a workflow, a markdown
// document and a source comment differently has to be provable on all
// three, and the name is how the matcher tells them apart.
function _fixtureRecord(name, fixture, index) {
  var text = typeof fixture === "string" ? fixture : fixture.text;
  var as   = typeof fixture === "string" ? "sample.js" : fixture.as;
  return {
    rel:   "fixture:" + name + "#" + index + "/" + as,
    abs:   null,
    text:  text,
    lines: text.split(/\r?\n/),
  };
}

// Every detector proves itself on this run rather than on the day it
// was written: each red fixture must produce at least one match, and
// each green fixture must produce none. A matcher that has gone quiet
// through a rename or a rewritten regex fails here instead of passing
// green over a tree it no longer reads.
function _proveDetector(d) {
  check(d.name + ": has a description", typeof d.description === "string" && d.description.length > 40);
  check(d.name + ": declares at least one directory", Array.isArray(d.dirs) && d.dirs.length > 0);
  check(d.name + ": has a matcher", typeof d.scan === "function");
  check(d.name + ": ships at least one red fixture", Array.isArray(d.red) && d.red.length > 0);

  d.red.forEach(function (fixture, i) {
    var hits = d.scan(_fixtureRecord(d.name, fixture, i));
    check(d.name + ": fires on red fixture " + i, hits.length > 0);
  });
  (d.green || []).forEach(function (fixture, i) {
    var hits = d.scan(_fixtureRecord(d.name, fixture, i));
    check(d.name + ": stays silent on green fixture " + i, hits.length === 0);
  });
}

// ---------------------------------------------------------------------------
// Live scan
// ---------------------------------------------------------------------------

function _runDetector(d) {
  var files = _filesUnder(d.dirs, { exts: d.exts, includeRepoRoot: d.includeRepoRoot });
  var matches = [];
  files.forEach(function (f) { matches = matches.concat(d.scan(f)); });
  _report(d.name, _filterMarkers(matches, d.name), files.length);
}

// A marker naming a detector that does not exist suppresses nothing, so
// the code it was written to cover ships unflagged. Every marker in the
// tree has to name a registered class.
// `.github/` is audited under the prose file filter rather than the
// JavaScript one, because the dash detector now reaches workflow files
// and a marker written there has to name a registered class too.
function _auditAllowMarkers() {
  var valid = _validAllowClasses();
  var files = _filesUnder(["lib", "bin", "scripts", "test"])
    .concat(_filesUnder([".github"], { exts: PROSE_EXT_RE }));
  var bad = [];
  files.forEach(function (f) {
    for (var i = 0; i < f.lines.length; i++) {
      var line = f.lines[i];
      var re = /(?:codebase-patterns:allow-file\s+|allow:)([a-z][a-z0-9-]*)/g;
      var m;
      while ((m = re.exec(line)) !== null) {
        if (!valid[m[1]]) {
          bad.push({ file: f.rel, line: i + 1, content: line.trim() });
        }
      }
    }
  });
  _report("allow-markers-are-registered", bad, files.length);
}

// ---------------------------------------------------------------------------

function run() {
  _allViolations = [];

  // A file the walk found and the reader could not open must stop the run.
  // Answering with empty text instead hands every detector a file with
  // nothing in it, so all 100 report it clean while it still counts toward
  // the total each one publishes: the count and the verdict agree, and both
  // are wrong. This tree is held in a synchronizing folder that has taken a
  // lock on a file mid-run before, so the read fault is reachable here
  // rather than theoretical.
  var unreadable = null;
  try { _readRecord(path.join(REPO_ROOT, "lib", "no-such-file-for-the-read-proof.js")); }
  catch (e) { unreadable = e; }
  check("a file the reader cannot open stops the run rather than reading as empty",
    unreadable !== null);
  check("and the refusal names the file it could not read",
    unreadable !== null && String(unreadable.message).indexOf(
      "no-such-file-for-the-read-proof.js") !== -1);

  var names = {};
  DETECTORS.forEach(function (d) {
    check("detector name is unique: " + d.name, !names[d.name]);
    names[d.name] = 1;
  });

  // A declared narrowing that names a detector nobody registered
  // describes coverage that does not exist, which is worse than an
  // undeclared one: it reads as a decision somebody made.
  PATTERN_NARROWINGS.forEach(function (x) {
    check("pattern narrowing names a registered detector: " + x.detector, names[x.detector] === 1);
  });

  console.log("detector self-proof (" + DETECTORS.length + " detectors):");
  DETECTORS.forEach(_proveDetector);

  console.log("\nlive scan:");
  DETECTORS.forEach(_runDetector);
  _auditAllowMarkers();

  if (DIR_EXCEPTIONS.length || PATTERN_NARROWINGS.length || SITE_EXCEPTIONS.length) {
    console.log("\nscope exceptions in force:");
    if (!DIR_EXCEPTIONS.length) {
      console.log("  no directory is excluded from any detector");
    }
    DIR_EXCEPTIONS.forEach(function (x) {
      console.log("  " + x.detector + " does not scan " + x.dir + ": " + x.reason);
    });
    SITE_EXCEPTIONS.forEach(function (x) {
      console.log("  " + x.detector + " does not scan " + x.site + ": " + x.reason);
    });
    PATTERN_NARROWINGS.forEach(function (x) {
      console.log("  " + x.detector + " does not match " + x.token + ": " + x.reason);
    });
  }

  // The registered set the audit detector measured against, printed so a
  // namespace that quietly stopped being registered is visible in the
  // run rather than only in the source that used to register it.
  var registry = _registeredNamespaces();
  var registered = Object.keys(registry.repo).sort();
  console.log("\naudit namespaces this server registers, beyond the framework's own:");
  console.log("  " + (registered.length ? registered.join(", ") : "none"));

  console.log("\ndash-punctuation-in-prose, classes that are not prose punctuation:");
  DASH_EXCLUSION_CLASSES.forEach(function (x) {
    console.log("  " + x.name + ": " + x.what);
  });

  console.log("\nself-history-in-source, the shapes read out of comments and string literals:");
  SELF_HISTORY_SHAPES.forEach(function (x) {
    console.log("  " + x.name + ": " + x.what);
  });

  console.log("\ntemplate-inline-script-or-event-handler, the script types a template body may carry:");
  TEMPLATE_DATA_BLOCK_TYPES.forEach(function (x) {
    console.log("  " + x.type + ": " + x.what);
  });

  var exempt = Object.keys(TOOLING_TOKEN_EXCEPTIONS);
  if (exempt.length) {
    console.log("\ntooling-token exceptions in force:");
    exempt.forEach(function (rel) {
      console.log("  " + rel + ": " + TOOLING_TOKEN_EXCEPTIONS[rel]);
    });
  }

  if (_allViolations.length) {
    console.log("\n" + _allViolations.length + " detector(s) reporting:");
    _allViolations.forEach(function (v) {
      console.log("  " + v.name + ": " + v.count + " violation(s)");
    });
  }

  // One cumulative gate: every detector runs to completion first, so a
  // failing run shows the whole report rather than the first finding.
  check("zero codebase-pattern violations across all detectors", _allViolations.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  // Persistent output through synchronous fd writes, mirroring
  // test/smoke.js, so a failing run's detail is on disk even if the
  // process dies mid-run. Read the log rather than re-running.
  var OUT = path.join(REPO_ROOT, ".test-output");
  try { fs.mkdirSync(OUT, { recursive: true }); }
  catch (_e) { /* drop-silent by design: a missing log must not fail the gate */ }
  var LOG_PATH = path.join(OUT, "codebase-patterns.log");
  try { fs.unlinkSync(LOG_PATH); }
  catch (_e) { /* drop-silent by design: no previous log to clear */ }
  var _logFd = fs.openSync(LOG_PATH, "w");
  var _logWrite = function (chunk) {
    try {
      var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      fs.writeSync(_logFd, buf, 0, buf.length, null);
    } catch (_e) { /* drop-silent by design: the console still carries the line */ }
  };
  var origStdout = process.stdout.write.bind(process.stdout);
  var origStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = function (c, e, cb) { _logWrite(c); return origStdout(c, e, cb); };
  process.stderr.write = function (c, e, cb) { _logWrite(c); return origStderr(c, e, cb); };
  process.on("exit", function () {
    try { fs.closeSync(_logFd); }
    catch (_e) { /* drop-silent by design: the fd goes with the process */ }
  });
  console.log("output: " + LOG_PATH);
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
