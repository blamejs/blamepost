#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * check-forbidden-vocabulary: refuses the commercial product vocabulary this
 * repository does not use, in every file git tracks and every untracked file
 * that git does not ignore.
 *
 * WHAT IS MATCHED. Every run of letters is split into words at camelCase
 * boundaries, so `readTimeoutMs` yields `read`, `Timeout` and `Ms`. Each word
 * is compared, ignoring case, against the entries in REFUSED below. A
 * two-word entry matches two consecutive words separated by nothing, by
 * whitespace, or by a hyphen, underscore or comment leader, and it still
 * matches when the second word starts the next line.
 *
 * WHAT IS NOT SCANNED. The vendored packages under `lib/vendor/<package>/`,
 * binary files, and every file git ignores, which includes the maintainer's
 * local instruction file. The run prints the path rule and names every file
 * it skipped as binary or unreadable.
 *
 * EXEMPTIONS. Each exemption lists exact forms of one documented sense. A
 * form matches the text immediately before and after one word, and never a
 * whole line or a whole file. The self-proof checks on every run that each
 * form passes its own text and that the same word used in a product sense
 * right after it is still refused.
 *
 * WHAT THE RUN EXAMINED is published as its last lines, pass or fail:
 *
 *   EXAMINED <n> files-scanned
 *   EXAMINED <n> refused-forms-proven
 *
 * `files-scanned` counts files read and tokenized. `refused-forms-proven`
 * counts entries in REFUSED that the self-proof found refused in prose and in
 * an identifier. A broken file listing takes the first to zero, and a broken
 * tokenizer or an emptied table takes the second to zero. A zero in either
 * unit fails the run.
 *
 * Run:
 *   node scripts/check-forbidden-vocabulary.js
 *   node scripts/check-forbidden-vocabulary.js --root <dir>
 *
 * Exit codes:
 *   0  no refused word outside an exemption, and both units are non-zero
 *   1  a refused word was found, the self-proof failed, or a unit was zero
 *   2  the run could not be performed
 */

var fs   = require("node:fs");
var path = require("node:path");
var cp   = require("node:child_process");

var counts = require("./examined-counts.js");

var ROOT_DEFAULT = path.resolve(__dirname, "..");
var LABEL = "[forbidden-vocabulary] ";

// ---------------------------------------------------------------------------
// The refused vocabulary
// ---------------------------------------------------------------------------

// Each entry carries a `|` that `word` removes before matching, so the words
// do not appear in this file. An entry with a space is two or three words in
// sequence. Inflected forms are listed one by one.
var REFUSED = [
  "st|ripe",
  "bil|ling",
  "in|voice", "in|voices", "in|voiced", "in|voicing",
  "sub|scription", "sub|scriptions",
  "pay|ment", "pay|ments",
  "pa|id",
  "pl|an", "pl|ans", "pl|anned", "pl|anning", "pl|anner", "pl|anners",
  "pri|cing",
  "ti|er", "ti|ers", "ti|ered",
  "pre|mium", "pre|miums",
  "enter|prise ed|ition",
  "cus|tomer", "cus|tomers",
  "sign|up fun|nel", "sign up fun|nel",
  "mone|tize", "mone|tizes", "mone|tized", "mone|tizing", "mone|tization",
  "reve|nue", "reve|nues",
  "tri|al", "tri|als",
  "se|at", "se|ats",
  "up|sell", "up|sells", "up|selling",
];

function word(encoded) {
  return String(encoded).split("|").join("");
}

// The table decoded into lowercase word sequences.
var FORMS = REFUSED.map(function (entry) {
  return { entry: entry, words: word(entry).toLowerCase().split(" ") };
});

// ---------------------------------------------------------------------------
// Exemptions
// ---------------------------------------------------------------------------

// A form is written as the text around one word, with the word in braces and
// encoded like a REFUSED entry: `health-probe {ti|ers}`. A space in a form
// matches whitespace, or a line break followed by a comment leader, so a form
// still matches a sentence wrapped across two comment lines. Forms compare
// case exactly.
var EXEMPTIONS = [
  {
    id:     "health-probe-field",
    reason: "a health-probe tier is the framework option that selects the liveness or readiness probe",
    forms:  [
      "{ti|er}: [",
      "{ti|er}: \"liveness\"",
      "{ti|er}: \"readiness\"",
      "health-probe {ti|er}",
      "health-probe {ti|ers}",
      "health-probe-{ti|ers}",
    ],
  },
  {
    id:     "jmap-push",
    reason: "a push subscription is the JMAP object of RFC 8620 section 7.2 that a client registers to receive state changes",
    forms:  [
      "Push{Sub|scription}",
      "push {sub|scription}",
    ],
  },
  {
    id:     "rlo-filename-example",
    reason: "a filename disguised with a right-to-left override is the example the header screening documents and tests",
    forms:  [
      "{In|voice} <RLO>gpj.exe",
      "{In|voice} exe.jpg",
      "\"{In|voice} \" + RLO + \"gpj.exe\"",
    ],
  },
  {
    id:     "release-notes-refused-list",
    reason: "the release-notes schema descriptions list the internal words the release-notes checks reject",
    forms:  [
      "phase / sweep / {ti|er} / batch / group / slice",
    ],
  },
];

var FORM_GAP = "(?:[ \\t]*\\r?\\n[ \\t]*(?:\\/\\/+|\\*|#)?[ \\t]*|[ \\t]+)";
var WORD_CHAR_RE = /[A-Za-z0-9_]/;

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function gapped(s) {
  return s.split(" ").map(escapeRe).join(FORM_GAP);
}

// The plain text a form stands for, with the braces and the `|` removed.
function formText(form) {
  return word(form.replace("{", "").replace("}", ""));
}

function compileForm(form) {
  var open  = form.indexOf("{");
  var close = form.indexOf("}", open);
  if (open === -1 || close === -1) {
    throw new TypeError("exemption form " + JSON.stringify(form) + " marks no word in braces");
  }
  var before = form.slice(0, open);
  var after  = form.slice(close + 1);
  var leading  = before.length > 0 && WORD_CHAR_RE.test(before.charAt(0)) ? "(?<![A-Za-z0-9_])" : "";
  var trailing = after.length > 0 && WORD_CHAR_RE.test(after.charAt(after.length - 1)) ? "(?![A-Za-z0-9_])" : "";
  return {
    form:   form,
    word:   word(form.slice(open + 1, close)),
    before: new RegExp(leading + gapped(before) + "$"),
    after:  new RegExp("^" + gapped(after) + trailing),
  };
}

EXEMPTIONS.forEach(function (ex) {
  ex.compiled = ex.forms.map(compileForm);
});

// How far either side of a word a form may reach.
var FORM_REACH = 400;

function exemptionFor(text, token) {
  var before = text.slice(Math.max(0, token.start - FORM_REACH), token.start);
  var after  = text.slice(token.end, token.end + FORM_REACH);
  for (var i = 0; i < EXEMPTIONS.length; i += 1) {
    var forms = EXEMPTIONS[i].compiled;
    for (var j = 0; j < forms.length; j += 1) {
      var f = forms[j];
      if (token.text === f.word && f.before.test(before) && f.after.test(after)) return EXEMPTIONS[i];
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

var PATH_EXCLUSIONS = [
  {
    match:  /^lib\/vendor\/[^/]+\//,
    reason: "a vendored package is refreshed wholesale by scripts/vendor-update.sh and is read-only in this tree",
  },
];

var SKIP_EXT = /\.(png|jpe?g|gif|ico|pem|der|p12|pfx|crt|cer|key|woff2?|ttf|eot|zip|gz|tgz|pdf|bin)$/i;

// A file this project WROTE, whatever bytes it holds. The NUL test below is a
// backstop for a binary whose extension is not on the list above, and a source
// file is never that. Four `fuzz/*.fuzz.js` files hold a NUL in their OWN
// SOURCE, in a literal they hand a wire reader as input, and for as long as the
// backstop judged by bytes alone those four went unread while the run still
// reported a whole tree. The seed corpora on disk are a separate set and carry
// no NUL; it is the harness sources that do. A NUL cannot
// hide a refused word, so a source file is read with each NUL standing in for
// a line break, and only a file whose name claims no source format can still
// be dropped as binary.
var SOURCE_EXT = /\.(js|mjs|cjs|json|md|ya?ml|sh|html?|css|txt|dict)$/i;

var NUL = String.fromCharCode(0);

function excluded(rel) {
  return PATH_EXCLUSIONS.some(function (x) { return x.match.test(rel); }) || SKIP_EXT.test(rel);
}

// The files git tracks under `root`, plus untracked files git does not
// ignore. Throws when git cannot list them.
function listFiles(root) {
  var out = cp.execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    cwd:       root,
    encoding:  "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio:     ["ignore", "pipe", "pipe"],
  });
  var seen = Object.create(null);
  return out.split(NUL).filter(function (rel) {
    if (!rel || seen[rel]) return false;
    seen[rel] = true;
    return true;
  });
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

var RUN_RE  = /[A-Za-z]+/g;
var PART_RE = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+/g;

// What may separate two words of one entry: nothing, or whitespace, hyphens,
// underscores and comment leaders spanning at most one line break.
var PHRASE_GAP_RE = /^[\s\-_*/#>]*$/;

// The letters a backslash escape begins with in a regular expression or a
// string literal: `\b`, `\s`, `\w`, `\d`, `\n`, `\t`, `\u` and the rest.
var ESCAPE_LETTER_RE = /^[bBdDfknprsStuvwWxcP]$/;

// Every word in `text`, in order, with its offsets.
//
// A run that follows a backslash is also read without its first letter
// when that letter can begin an escape, so the word in `\bword` is read as
// well as `bword`. Words are keyed by offset, so a word both readings find
// is listed once.
function tokenize(text) {
  var tokens = [];
  var seen = Object.create(null);
  function add(from, letters) {
    var part;
    PART_RE.lastIndex = 0;
    while ((part = PART_RE.exec(letters)) !== null) {
      var start = from + part.index;
      var key = start + ":" + part[0].length;
      if (seen[key] === 1) continue;
      seen[key] = 1;
      tokens.push({
        text:  part[0],
        lower: part[0].toLowerCase(),
        start: start,
        end:   start + part[0].length,
      });
    }
  }
  var run;
  RUN_RE.lastIndex = 0;
  while ((run = RUN_RE.exec(text)) !== null) {
    add(run.index, run[0]);
    if (run.index > 0 && text.charAt(run.index - 1) === "\\" && run[0].length > 1 &&
        ESCAPE_LETTER_RE.test(run[0].charAt(0))) {
      add(run.index + 1, run[0].slice(1));
    }
  }
  tokens.sort(function (a, b) { return a.start - b.start || a.end - b.end; });
  return tokens;
}

function lineAt(text, offset) {
  var n = 1;
  for (var i = text.indexOf("\n"); i !== -1 && i < offset; i = text.indexOf("\n", i + 1)) n += 1;
  return n;
}

function gapAllowed(text, from, to) {
  var gap = text.slice(from, to);
  return PHRASE_GAP_RE.test(gap) && gap.split("\n").length <= 2;
}

// The refused words in `text` outside an exemption, and the exempted ones.
function scanText(text, rel) {
  var tokens   = tokenize(text);
  var findings = [];
  var exempted = [];
  for (var i = 0; i < tokens.length; i += 1) {
    for (var f = 0; f < FORMS.length; f += 1) {
      var words = FORMS[f].words;
      if (tokens[i].lower !== words[0]) continue;
      var matched = true;
      for (var k = 1; k < words.length && matched; k += 1) {
        var next = tokens[i + k];
        matched = Boolean(next) && next.lower === words[k] &&
          gapAllowed(text, tokens[i + k - 1].end, next.start);
      }
      if (!matched) continue;
      var last = tokens[i + words.length - 1];
      var hit = {
        file:  rel,
        line:  lineAt(text, tokens[i].start),
        found: text.slice(tokens[i].start, last.end),
      };
      var exemption = words.length === 1 ? exemptionFor(text, tokens[i]) : null;
      if (exemption) {
        hit.exemption = exemption.id;
        exempted.push(hit);
      } else {
        findings.push(hit);
      }
    }
  }
  return { findings: findings, exempted: exempted };
}

// Reads one file under `root` and scans it. A file that cannot be read, or
// that holds a NUL byte, is added to `tally.skipped` and not counted.
function scanFile(root, rel, tally) {
  var src;
  try { src = fs.readFileSync(path.join(root, rel), "utf8"); }
  catch (_e) {
    tally.skipped.push(rel + " (unreadable)");
    return { findings: [], exempted: [] };
  }
  if (src.indexOf(NUL) !== -1) {
    if (!SOURCE_EXT.test(rel)) {
      tally.skipped.push(rel + " (control byte, read as binary)");
      return { findings: [], exempted: [] };
    }
    src = src.split(NUL).join("\n");
  }
  tally.scanned += 1;
  return scanText(src, rel);
}

// ---------------------------------------------------------------------------
// Self-proof
// ---------------------------------------------------------------------------

function capitalized(w) {
  return w.charAt(0).toUpperCase() + w.slice(1);
}

// Each REFUSED entry is proven when it is refused exactly once in a prose
// line and exactly once inside a camelCase identifier. Each exemption form
// must pass its own text, and the same word placed after that text in a
// product sense must be refused. Returns { proven, problems }.
function selfProof() {
  var problems = [];
  var proven = 0;
  FORMS.forEach(function (form) {
    var prose = scanText("The page names " + form.words.join(" ") + " here.\n", "self-proof");
    var ident = scanText("var the" + form.words.map(capitalized).join("") + "Id = 1;\n", "self-proof");
    if (prose.findings.length === 1 && ident.findings.length === 1) {
      proven += 1;
      return;
    }
    problems.push("self-proof: the entry " + JSON.stringify(form.entry) + " was refused " +
      prose.findings.length + " time(s) in prose and " + ident.findings.length +
      " time(s) in an identifier, and each should be once");
  });
  EXEMPTIONS.forEach(function (ex) {
    ex.compiled.forEach(function (c) {
      var own = formText(c.form);
      var passes = scanText(own + "\n", "self-proof");
      if (passes.findings.length !== 0 || passes.exempted.length === 0) {
        problems.push("self-proof: the exemption " + ex.id + " does not pass its own form " +
          JSON.stringify(own));
      }
      var beside = scanText(own + " and then a " + c.word + " sold to each account.\n", "self-proof");
      if (beside.findings.length !== 1) {
        problems.push("self-proof: beside the form " + JSON.stringify(own) + " of " + ex.id +
          ", a product-sense " + JSON.stringify(c.word) + " was refused " + beside.findings.length +
          " time(s) rather than once");
      }
    });
  });
  return { proven: proven, problems: problems };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  var opts = { root: ROOT_DEFAULT };
  for (var i = 0; i < argv.length; i += 1) {
    var a = argv[i];
    if (a === "--root") {
      i += 1;
      if (i >= argv.length) throw new TypeError("--root requires a directory path");
      opts.root = path.resolve(argv[i]);
      continue;
    }
    throw new TypeError("unrecognized argument: " + a);
  }
  var stat;
  try { stat = fs.statSync(opts.root); }
  catch (_e) { throw new TypeError("--root is not a readable directory: " + opts.root); }
  if (!stat.isDirectory()) throw new TypeError("--root is not a directory: " + opts.root);
  return opts;
}

function main(argv) {
  var opts;
  try { opts = parseArgs(argv); }
  catch (e) {
    process.stderr.write(LABEL + ((e && e.message) || String(e)) + "\n");
    return 2;
  }

  var files;
  try { files = listFiles(opts.root); }
  catch (e) {
    process.stderr.write(LABEL + "git could not list the files under " + opts.root + ": " +
      String((e && e.message) || e).split("\n")[0] + "\n");
    return 2;
  }

  PATH_EXCLUSIONS.forEach(function (x) {
    process.stdout.write(LABEL + "not scanned: " + String(x.match) + ", because " + x.reason + ".\n");
  });

  var proof = selfProof();

  var tally = { scanned: 0, skipped: [] };
  var findings = [];
  var exempted = [];
  files.forEach(function (rel) {
    if (excluded(rel)) return;
    var res = scanFile(opts.root, rel, tally);
    findings = findings.concat(res.findings);
    exempted = exempted.concat(res.exempted);
  });

  EXEMPTIONS.forEach(function (ex) {
    var n = exempted.filter(function (h) { return h.exemption === ex.id; }).length;
    process.stdout.write(LABEL + "exemption " + ex.id + ": " + n + " occurrence(s), because " +
      ex.reason + ".\n");
  });

  if (tally.skipped.length > 0) {
    process.stdout.write(LABEL + tally.skipped.length + " file(s) were not scanned and are not counted:\n");
    tally.skipped.forEach(function (s) { process.stdout.write("  " + s + "\n"); });
  }

  proof.problems.forEach(function (p) { process.stderr.write(LABEL + p + "\n"); });
  findings.forEach(function (h) {
    process.stderr.write(LABEL + h.file + ":" + h.line + "  " + h.found + "\n");
  });

  var bad = findings.length + proof.problems.length;
  if (bad === 0 && tally.scanned > 0) {
    process.stdout.write(LABEL + "OK, no refused word outside an exemption in " + tally.scanned +
      " file(s).\n");
  } else if (bad > 0) {
    process.stderr.write(LABEL + findings.length + " finding(s) and " + proof.problems.length +
      " self-proof problem(s). Write operator, account, domain or admin, or describe the " +
      "behavior, instead of a commercial product term.\n");
  }

  var published = counts.publish([
    { unit: "files-scanned",        n: tally.scanned },
    { unit: "refused-forms-proven", n: proof.proven },
  ], { tag: LABEL.trim() });

  return (bad === 0 && published === 0) ? 0 : 1;
}

module.exports = {
  REFUSED:         REFUSED,
  EXEMPTIONS:      EXEMPTIONS,
  PATH_EXCLUSIONS: PATH_EXCLUSIONS,
  word:            word,
  formText:        formText,
  tokenize:        tokenize,
  scanText:        scanText,
  selfProof:       selfProof,
};

if (require.main === module) process.exit(main(process.argv.slice(2)));
