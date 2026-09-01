#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/check-operator-prose: the static gate that runs the technical-writing
// skill's offline prose checker over every operator-facing document in this
// repository.
//
// Why: README.md, SECURITY.md, docs/operator-guide.md and their siblings are the
// surface an operator reads before pointing DNS at a machine. The checker catches
// the mechanical
// defects a human reviewer skims past. What is ENFORCED here is the set that can
// mislead someone acting on the document: a dash inside a flag that turns a
// copy-pasteable command into a broken one, a malformed RFC or CVE reference, a
// credential-shaped token, a regional spelling mix. The rest of the checker's
// families are advisory in this repository and run under `check:prose:all`; the
// CHECKS constant below carries the evidence for each exclusion.
//
// The checker is a machine-local tool, NOT a dependency of this repository.
// Hard rule #1 is zero npm runtime dependencies, and dev tooling never ships in
// the tarball, so this gate LOCATES the checker at run time and never installs,
// vendors, or postinstalls it.
//
// That is why this is `npm run check:prose` and NOT part of `npm run gates`.
// The absence rule below is right for this gate and wrong for a shared default:
// a clone, a clean CI runner and a release environment have no checker, so a
// `gates` that ran this would fail for everyone who has not installed an
// external skill. It joins `gates` when the checker is something the repository
// itself provisions; until then the reviewed-exception table and both controls
// still do their work on every `check:prose` run.
//
// ABSENCE FAILS. A gate that silently skips when its tool is missing stops
// gating at exactly the moment nobody is told, and the skip bucket is where the
// defect it hunts ends up. The only way past this gate without the checker is a
// declaration that costs something visible: BLAMEPOST_PROSE_CHECK=off, which
// someone has to write down and can be read back later. A missing file is not
// that declaration, so a missing file is an error.
//
// Availability is decided by PROBING FOR THE FILE, never by reading the
// checker's own output or exit code. "The tool errored, so it must not be
// installed" is precisely how a genuine regression in the tool reads as absence
// and the gate quietly stops gating.
//
// AN INERT CHECKER FAILS TOO. Absence is one failure mode. The other is a
// checker that still runs and has regressed into reporting nothing, and that
// one reads as a clean bill of health on every document it is handed. So a
// positive control runs first: the gate writes a document carrying a defect the
// checker is required to catch, runs the checker on it under the same
// invocation the real documents get, and requires a finding back. A control
// that comes back clean stops the gate there, because a checker that reports
// nothing about a known-bad document reports nothing about the real ones
// either.
//
// The control is an untagged fenced code block. That rule is structural,
// decided by the checker's own fence parser rather than by a data file it
// loads, so it survives a data refresh and a retuning of the style heuristics.
// The control asserts only that SOMETHING was reported. It reads no finding
// id, no message, and no count above one, so the checker stays free to reword
// and renumber its output.
//
// A CRASHED CHECKER IS NOT A PROSE DEFECT. A tool that throws on load and a
// tool that found twenty real findings both exit non-zero. Telling an operator
// to fix their writing when the tool fell over sends them hunting for a defect
// that is not there, and hides the one that is. A non-zero exit is therefore
// classified before it is reported: the gate asks the checker for a
// machine-readable report of the same run and reads its SHAPE, its finding
// COUNT, and each finding's location and flagged token. The finding MESSAGE is
// never read to decide a verdict. Reading it would make this script an opinion
// about the checker's wording, which is the thing the inherited stdio below
// exists to prevent.
//
// AN ADDRESS RFC 2606 RESERVES IS NOT A POSSIBLY-REAL ADDRESS. The checker's
// real-address rule excludes `example.com`, `example.net` and `example.org`
// and stops there, so `partner@othercorp.example` at one of the top-level
// names the same RFC reserves comes back as a finding. Left standing, that
// asks an author to replace the thing the reservation exists for, and the way
// around it is a domain that looks real. The gate sets those aside instead,
// bounded two ways: only the family that asks the real-address question, and
// only when every address-shaped token in the same document is also reserved,
// because the checker collapses a rule's occurrences in one document into one
// finding and a real address could otherwise leave behind a reserved one.
// Anything set aside is named on stdout, so a finding printed in the report
// above and absent from the verdict is accounted for rather than silently
// gone.
//
// A FINDING THAT WAS READ AND FOUND CORRECT IS DECLARED IN WRITING, WITH ITS
// CONTEXT. Some documents carry findings that are right as they stand: a
// standard's published title spelled the way its publisher spells it, a
// reporting address a reporter is genuinely meant to use, a destructive command
// whose operands are literal paths the surrounding step created. Each of those
// is recorded in REVIEWED below and reconciled against what the checker reports,
// in both directions, so an acceptance bounds exactly what its author read and
// nothing that arrives later.
//
// Coverage is DISCOVERED from disk rather than enumerated, so a document added
// anywhere in the repository is gated the day it lands. There is no list to go
// stale: the gate walks the tree for *.md at every depth, and everything it
// finds is in scope unless the file appears in EXCLUDED or its directory
// appears in SKIPPED_DIRS, each with a written reason that prints on every run.
// Depth is not a scope boundary. `.github/ISSUE_TEMPLATE`, `docker` and
// `test/integration` all reach anyone who clones the repository, which is this
// project's test for operator-facing.
//
// Environment:
//   BLAMEPOST_PROSE_CHECKER   path to check_technical_text.mjs, overriding the
//                       default location. Keeps the gate portable to a machine
//                       that installs the skill somewhere else.
//   BLAMEPOST_PROSE_CHECK     "off", and only "off", declares a deliberate
//                       skip. Any other value is refused rather than guessed
//                       at, because a misspelt opt-out that silently gates (or
//                       silently does not) is the ambiguity this gate exists
//                       to remove.
//
// Exit codes:
//   0   the checker reported no findings, or every finding it reported is
//       recorded in REVIEWED and still describes what was read there, or a skip
//       was explicitly declared
//   1   a finding nobody has read, an acceptance that describes nothing, or the
//       checker could not be found
//   2   the gate itself could not run (bad configuration, spawn failure)
//   3   a control came back the wrong way: the checker did not flag a known-bad
//       document, or the reconciler raised no objection to a known-bad finding
//       set. Something that should have reported did not, so its verdict cannot
//       be trusted
//   4   the checker did not complete a run, so it returned no verdict at all
//
// Codes 3 and 4 are failures of the TOOLING. They say nothing about the prose in
// this repository, and the message on each says so.

var fs    = require("node:fs");
var os    = require("node:os");
var path  = require("node:path");
var proc  = require("node:child_process");

var examinedCounts = require("./examined-counts.js");

var TAG  = "[check-operator-prose]";
var ROOT = path.resolve(__dirname, "..");

// The default install location of the technical-writing skill. It is not the
// only option, since BLAMEPOST_PROSE_CHECKER overrides it, but it is the one
// this machine uses.
var DEFAULT_CHECKER = path.join(
  os.homedir(), ".claude", "skills", "technical-writing",
  "scripts", "check_technical_text.mjs"
);

// Markdown that is NOT operator-facing, by repository-relative path. Every
// entry carries the reason it is exempt, so an exclusion has to be argued
// for in writing rather than added quietly. Anything not listed here is gated.
var EXCLUDED = [
  { file: "CLAUDE.md", reason: "gitignored working instructions - never reaches the repository or the tarball" }
];

// Directories the walk does not enter, by name, at any depth. Same discipline
// as EXCLUDED: a reason per entry, printed on every run. A directory that is
// not listed here is walked, so the only way a document goes unchecked is by
// somebody writing down why.
var SKIPPED_DIRS = [
  { dir: "node_modules", reason: "installed dependencies - another project's prose, and a clone of this one does not carry them" },
  { dir: "vendor",       reason: "the vendored upstream tree - upstream's prose, refreshed wholesale by scripts/vendor-update.sh and read-only here, so a finding in it names text nobody in this repository may edit" },
  { dir: ".git",         reason: "the object store - no documents, and walking it is slow" },
  { dir: ".claude",      reason: "local agent settings and worktree checkouts - a worktree is a second copy of this repository and would gate every document twice" },
  { dir: ".references",  reason: "internal research and build plans - gitignored, never in a clone or the tarball" },
  { dir: ".scratch",     reason: "internal working notes - gitignored, never in a clone or the tarball" },
  { dir: "memory",       reason: "cross-session working notes - gitignored, never in a clone or the tarball" },
  { dir: "coverage",     reason: "generated coverage report - build output, gitignored" },
  { dir: ".test-output", reason: "gate logs - build output, gitignored" }
];

// Findings that were read and found correct as they stand. This is the only way
// past the gate with a finding present, and using it is meant to cost something:
// an entry names the document, the check family, the token the checker flagged,
// and one context string per accepted occurrence, which is a fragment that has
// to still be on the flagged line for that occurrence to count as covered.
//
// The context is what makes an entry bound anything. `rm -rf data data-e2e`
// names two literal directories and is the shape the check's own advice asks
// for; `rm -rf $BUILD_DIR/` two lines later is the shape the check exists to
// catch, and an entry keyed on the token alone would wave the second one through
// on the first one's reasoning. Ordering follows the document: contexts are
// matched against the occurrences in line order.
//
// reconcile() compares the table against the checker's report in both
// directions, so each of these fails the gate:
//
//   an entry that matches nothing         the prose moved on and the acceptance
//                                         describes something no longer there
//   an occurrence with no entry           nobody has read it
//   more occurrences than contexts        a new one arrived behind an accepted one
//   a context missing from its line       the line was rewritten after it was read
//
// The table starts empty. Every finding the checker reports is a finding to fix,
// until somebody reads one, decides it is right as it stands, and writes down
// which occurrence they read and why. An entry added without a context string
// covers nothing and fails the reconciler, which is the point.
//
// Entry shape:
//   { file: "<repo-relative path>", check: "<check family>",
//     match: "<the token the checker flagged>",
//     contexts: [ "<fragment still on the flagged line>", ... ],
//     reason: "<why this occurrence is correct as written>" }
var REVIEWED = [
  {
    file: "docs/operator-guide.md",
    check: "secrets",
    match: "10.100.51.198",
    contexts: ["in-addr.arpa"],
    reason: "Not a private address. `in-addr.arpa` names an address backwards, so " +
      "10.100.51.198.in-addr.arpa is the reverse zone for 198.51.100.10, which RFC 5737 " +
      "reserves for documentation and which matches the A record shown above it. Rewriting " +
      "this to look like documentation space would produce a PTR record for a different " +
      "address than the example resolves to, so the fix the checker suggests would break " +
      "the recipe it is reading."
  },
  {
    file: "CODE_OF_CONDUCT.md",
    check: "secrets",
    match: "security@blamejs.com",
    contexts: ["**`security@blamejs.com`**"],
    reason: "Intentional. This is the project's published reporting address, which is the " +
      "point of the document: a conduct report has to reach somebody, and a reserved " +
      "example.com address would mean it reached nobody."
  },
  {
    file: "GOVERNANCE.md",
    check: "secrets",
    match: "security@blamejs.com",
    contexts: ["**Contact:**"],
    reason: "Intentional, and the same address the code of conduct names, which this line " +
      "says explicitly so the two cannot drift apart unnoticed."
  },
  {
    file: "SECURITY.md",
    check: "secrets",
    match: "security@blamejs.com",
    contexts: ["advisory form is not available"],
    reason: "Intentional. This is the reporting address the document exists to publish, and a " +
      "reserved example.com address here would mean a vulnerability report reaching nobody. The " +
      "same address appears twice more in this file, in the expected output of the tag " +
      "verification recipe and in the signing-key row, and neither is reported because both sit " +
      "in inline code spans, which is correct: an operator comparing their terminal against those " +
      "two needs the literal string."
  },
  {
    file: "SUPPORT.md",
    check: "secrets",
    match: "security@blamejs.com",
    contexts: ["Report conduct"],
    reason: "Intentional. The support table routes each kind of request somewhere, and this " +
      "row points at the address the code of conduct already publishes."
  }
];

// The gated documents sit a few directories down at most. The cap
// is a stop for a pathological tree, not a scope decision, so hitting it fails
// the gate rather than silently truncating what gets checked.
var MAX_DEPTH = 8;

function fail(code, lines) {
  lines.forEach(function (l) { console.error(TAG + " " + l); });
  process.exit(code);
}

/**
 * finish(code) publishes the document count and exits.
 *
 * Called on the paths that end CLEAN having assessed the documents, which
 * are the ones where a verdict over an empty set is possible and therefore
 * the ones the count has to speak for. Everything that ends non-zero goes
 * through `fail`, which already has a finding to report; a refusal added
 * there would bury it under the accounting.
 *
 * The declared skip is the one clean exit that does NOT come through here,
 * and that is deliberate rather than missed. That path assessed nothing on
 * purpose, said so in a banner, and is the only sanctioned way to run
 * without the checker present; a count beside it would describe a document
 * set nobody read, and a refusal would make the declaration impossible to
 * act on. What it leaves on the record is the banner, which is the point of
 * requiring the declaration in the first place.
 *
 * The number is the document set, because that is what has to move for this
 * gate to be answering anything. Findings are not a unit and never could
 * be: zero findings is the healthy answer here, so a count of them cannot
 * tell a clean tree from a checker that read none of it. That distinction
 * is the whole reason a count sits beside a canary rather than instead of
 * one. The canary proves the checker still FIRES, and this proves it
 * REACHED the tree.
 */
function finish(code) {
  var published = examinedCounts.publish([
    { unit: "operator-documents", n: docs.length },
  ], { tag: TAG });
  process.exit(code !== 0 ? code : published);
}

function msg(e) { return (e && e.message) || String(e); }

// The first lines of a captured run, for a diagnostic. Only ever used to show
// an operator why the checker failed to produce a verdict, never to decide one.
function captured(run) {
  var out = [];
  ["stderr", "stdout"].forEach(function (stream) {
    var text = String(run[stream] || "").replace(/\s+$/, "");
    if (!text) return;
    out.push("", "  --- checker " + stream + " ---");
    text.split(/\r?\n/).slice(0, 20).forEach(function (l) { out.push("  " + l); });
  });
  return out;
}

// ---------------------------------------------------------------------------
// Reconcile what the checker reported against what somebody wrote down having
// read it. Returns the list of things that do not line up; an empty list is the
// only clean answer.
//
// `lineOf(file, line)` hands back the source line the checker flagged, or null
// when it cannot be read. It is a parameter so the control below can drive this
// over synthetic input without touching the tree.
// ---------------------------------------------------------------------------
function reconcile(findings, lineOf, reviewed) {
  // The key is the encoded triple rather than a joined string: a token like
  // "rm -rf" carries a space, and joining on one would let two different
  // triples collide into a single key and share an acceptance.
  function keyOf(o) { return JSON.stringify([o.file, o.check, o.match]); }
  function name(o)  { return o.file + " / " + o.check + " / \"" + o.match + "\""; }

  var byKey = Object.create(null);
  findings.forEach(function (f) {
    var k = keyOf(f);
    if (!byKey[k]) byKey[k] = [];
    byKey[k].push(f);
  });
  Object.keys(byKey).forEach(function (k) {
    byKey[k].sort(function (a, b) { return a.line - b.line; });
  });

  var declared = Object.create(null);
  var problems = [];

  reviewed.forEach(function (r) {
    var k = keyOf(r);
    if (declared[k]) {
      problems.push(
        "two reviewed entries cover " + name(r) + ". Merge them into one: the number of " +
        "accepted occurrences has to be readable off a single entry, or neither entry " +
        "bounds how many there are."
      );
      return;
    }
    declared[k] = true;
    var group = byKey[k] || [];
    if (group.length === 0) {
      problems.push(
        "the reviewed exception for " + name(r) + " matches nothing the checker reported. " +
        "The prose moved on and the acceptance now describes something that is not there - " +
        "delete the entry."
      );
      return;
    }
    if (group.length !== r.contexts.length) {
      problems.push(
        "the reviewed exception for " + name(r) + " accepts " + r.contexts.length +
        " occurrence(s) and the checker reported " + group.length + " (line" +
        (group.length === 1 ? " " : "s ") +
        group.map(function (f) { return f.line; }).join(", ") + "). An occurrence is being " +
        "covered by reasoning written for a different one. Read the new line: fix it, or " +
        "add its context to the entry."
      );
      return;
    }
    group.forEach(function (f, i) {
      var text = lineOf(f.file, f.line);
      if (text === null) {
        problems.push(
          "the checker reported " + name(r) + " at " + f.file + ":" + f.line +
          ", and that line could not be read back to confirm the reviewed context."
        );
        return;
      }
      if (text.indexOf(r.contexts[i]) === -1) {
        problems.push(
          "the reviewed context for " + name(r) + " is no longer on " + f.file + ":" + f.line +
          ".\n    reviewed: " + r.contexts[i] +
          "\n    line now: " + text.trim() +
          "\n    The line was rewritten after it was read, so the acceptance no longer " +
          "covers what is on it. Read it again, then update or remove the entry."
        );
      }
    });
  });

  Object.keys(byKey).forEach(function (k) {
    if (declared[k]) return;
    byKey[k].forEach(function (f) {
      problems.push(
        "unreviewed finding: " + f.file + ":" + f.line + " [" + f.check + "] \"" + f.match + "\""
      );
    });
  });

  return problems;
}

// Reads a document back off disk, caching per file, in the two shapes the
// verdicts below need: the whole document, and one flagged line of it. A file
// that cannot be read and a line number past the end both answer null, which
// every caller treats as a failure rather than a pass.
function documentCache() {
  var cache = Object.create(null);
  function linesOf(file) {
    if (cache[file] === undefined) {
      try {
        cache[file] = fs.readFileSync(path.join(ROOT, file), "utf8").split(/\r?\n/);
      } catch (_e) {
        // A document that cannot be read back answers null, which reconcile() treats as a failure
        // rather than a pass: an acceptance whose line cannot be confirmed is not confirmed.
        cache[file] = null;
      }
    }
    return cache[file];
  }
  return {
    linesOf: linesOf,
    lineAt:  function (file, line) {
      var lines = linesOf(file);
      if (lines === null || !(line >= 1 && line <= lines.length)) return null;
      return lines[line - 1];
    },
  };
}

// The positive control on the reconciler. A table that accepts whatever it is
// handed reads as a clean tree on every run, which is the same failure mode as a
// checker that reports nothing. So the four objections the table exists to
// raise are exercised against synthetic input before the real report is judged,
// along with the one case that has to stay silent.
//
// The synthetic entry is built here rather than borrowed from REVIEWED, so
// editing the real table cannot quietly change what the control proves.
function reconcilerControl() {
  var TABLE = [{
    file: "doc.md", check: "region", match: "widgetise",
    contexts: ["the widgetise step"], reason: "control"
  }];
  var hit  = { file: "doc.md", check: "region", match: "widgetise", line: 7 };
  var more = { file: "doc.md", check: "region", match: "widgetise", line: 9 };
  function line(f, n) { return f === "doc.md" && n === 7 ? "  the widgetise step is set" : null; }

  var cases = [
    { want: 0, why: "an occurrence whose declared context is still on its line",
      run: function () { return reconcile([hit], line, TABLE); } },
    { want: 1, why: "an occurrence with no entry at all",
      run: function () { return reconcile([hit], line, []); } },
    { want: 1, why: "a second occurrence hiding behind one accepted context",
      run: function () { return reconcile([hit, more], line, TABLE); } },
    { want: 1, why: "a declared context the line no longer carries",
      run: function () { return reconcile([hit], function () { return "rewritten"; }, TABLE); } },
    { want: 1, why: "an entry matching nothing the checker reported",
      run: function () { return reconcile([], line, TABLE); } }
  ];

  for (var i = 0; i < cases.length; i++) {
    var got;
    try {
      got = cases[i].run();
    } catch (e) {
      return ["the reviewed-exception control threw on " + cases[i].why + ": " + msg(e)];
    }
    if (!Array.isArray(got)) {
      return ["the reviewed-exception control gave a non-list answer for " + cases[i].why + "."];
    }
    if (cases[i].want === 0 && got.length !== 0) {
      return [
        "the reviewed-exception control objected to " + cases[i].why + ".",
        "It reported: " + got[0],
        "",
        "A table that rejects what it was written to accept fails every run. This is a",
        "defect in the GATE, and nothing here is a verdict on the prose."
      ];
    }
    if (cases[i].want !== 0 && got.length === 0) {
      return [
        "the reviewed-exception control stayed silent about " + cases[i].why + ".",
        "",
        "A table that raises no objection accepts every finding in this repository, so a",
        "clean run would mean nothing. This is a defect in the GATE, and nothing here is a",
        "verdict on the prose."
      ];
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// An address RFC 2606 reserves is not a possibly-real address
//
// The checker's real-address rule excludes `example.com`, `example.net` and
// `example.org` and stops there, so an address at one of the top-level names
// the same RFC reserves, `partner@othercorp.example`, comes back as a
// possibly-real address. That is the wrong incentive to put in front of a doc
// author: they wrote the thing the reservation exists for, the gate asked them
// to change it, and the way around it is a domain that looks real.
//
// Reserved here means what RFC 2606 reserves and nothing else. Section 2 sets
// aside the top-level names `.test`, `.example`, `.invalid` and `.localhost`;
// section 3 sets aside `example.com`, `example.net` and `example.org`. A
// subdomain of any of them is inside the same reservation. No mail reaches any
// of these, which is the property being relied on, and every other domain
// keeps drawing exactly the finding it draws today.
//
// The BOUND is the part that matters, because of how the checker reports.
// Every occurrence of one rule in one document collapses into a SINGLE finding
// whose `match` is the first of them; the rest are named only in the message,
// which this gate does not read and must not start reading. So setting a
// finding aside on its own token alone would set aside the occurrences behind
// it, and a genuinely real address further down the same document would leave
// with them. Nothing is set aside unless EVERY address-shaped token in the
// document is reserved. That re-scan is deliberately wider than the checker's
// rule: it carries none of the exclusions and it does not skip code spans, so
// it over-reports, and over-reporting here keeps a finding rather than
// dropping one.
// ---------------------------------------------------------------------------
var RESERVED_EMAIL_DOMAIN_RE =
  /^(?:[a-z0-9-]+\.)*(?:test|example|invalid|localhost|example\.(?:com|net|org))$/i;

// An address-shaped token, with none of the checker's exclusions, so a
// superset of what its rule can flag. Held as a source string because the scan
// below needs its own global instance per document rather than a shared one
// carrying a `lastIndex` between them.
var ADDRESS_SHAPE = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}";

function reservedAddress(text) {
  var at = String(text).lastIndexOf("@");
  return at !== -1 && RESERVED_EMAIL_DOMAIN_RE.test(String(text).slice(at + 1));
}

// Which findings are reserved addresses that nothing in their own document
// contradicts. Returns the ones to set aside; every other finding is judged
// exactly as it was before.
//
// `linesOf(file)` hands back a document's lines, or null when it cannot be
// read. It is a parameter so the control below can drive this over synthetic
// input without touching the tree.
function reservedExampleFindings(findings, linesOf) {
  var verdicts = Object.create(null);

  function everyAddressIsReserved(file) {
    if (verdicts[file] === undefined) {
      var lines = linesOf(file);
      if (lines === null) {
        // A document that cannot be re-read has confirmed nothing, and an
        // unconfirmed finding stays a finding.
        verdicts[file] = false;
      } else {
        var seen = lines.join("\n").match(new RegExp(ADDRESS_SHAPE, "g")) || [];
        // A document the scan finds no address in cannot be the document this
        // finding's address came from, so the disagreement keeps the finding.
        verdicts[file] = seen.length > 0 && seen.every(reservedAddress);
      }
    }
    return verdicts[file];
  }

  return findings.filter(function (f) {
    // Scoped to the family that asks the real-address question. A finding from
    // another family that happens to quote an address is asking something else
    // and is none of this rule's business.
    if (f.check !== "secrets") return false;
    if (!reservedAddress(f.match)) return false;
    return everyAddressIsReserved(f.file);
  });
}

// The positive control on the rule above. A filter that turns findings into
// silence is a filter that can turn a real one into a pass, so the five
// answers it has to give are exercised against synthetic input before it is
// pointed at the real report.
function reservedExampleControl() {
  var documents = {
    "reserved.md": ["Write to partner@othercorp.example.", "Or to alice@example.com."],
    "mixed.md":    ["Write to partner@othercorp.example.", "Or to real@blamejs.com."],
  };
  function linesOf(file) {
    return Object.prototype.hasOwnProperty.call(documents, file) ? documents[file] : null;
  }
  function at(file, check, match) {
    return { file: file, check: check, match: match, line: 1 };
  }

  var cases = [
    { want: 1, why: "an address at a reserved top-level name, in a document carrying no other",
      findings: [at("reserved.md", "secrets", "partner@othercorp.example")] },
    { want: 0, why: "that same address in a document that also carries a real one",
      findings: [at("mixed.md", "secrets", "partner@othercorp.example")] },
    { want: 0, why: "an address at a domain the reservation does not cover",
      findings: [at("reserved.md", "secrets", "real@blamejs.com")] },
    { want: 0, why: "a reserved address reported by a check family other than secrets",
      findings: [at("reserved.md", "notation", "partner@othercorp.example")] },
    { want: 0, why: "a finding whose document cannot be read back",
      findings: [at("absent.md", "secrets", "partner@othercorp.example")] }
  ];

  for (var i = 0; i < cases.length; i += 1) {
    var got;
    try {
      got = reservedExampleFindings(cases[i].findings, linesOf);
    } catch (e) {
      return ["the RFC 2606 control threw on " + cases[i].why + ": " + msg(e)];
    }
    if (!Array.isArray(got)) {
      return ["the RFC 2606 control gave a non-list answer for " + cases[i].why + "."];
    }
    if (got.length !== cases[i].want) {
      return [
        "the RFC 2606 control set aside " + got.length + " finding(s) for " + cases[i].why +
          ", and " + cases[i].want + " is correct.",
        "",
        "Setting aside too many hides findings nobody has read. Setting aside too few leaves",
        "the reserved names drawing findings, which is what teaches an author to write a real",
        "domain instead. Either way this is a defect in the GATE, and nothing here is a",
        "verdict on the prose."
      ];
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// The declared skip. Checked first: it is the one sanctioned way past the gate,
// and it must not depend on the tool it is declaring the absence of.
// ---------------------------------------------------------------------------
var declared = process.env.BLAMEPOST_PROSE_CHECK;
if (declared !== undefined && String(declared).trim() !== "") {
  var value = String(declared).trim().toLowerCase();
  if (value !== "off") {
    fail(2, [
      "BLAMEPOST_PROSE_CHECK is set to \"" + declared + "\", which is not a value this gate knows.",
      "The only recognized value is \"off\". An unrecognized value is refused rather than",
      "guessed at, because guessing turns a typo into a silently disabled gate."
    ]);
  }
  console.log(TAG + " ==================================================================");
  console.log(TAG + " SKIPPED BY DECLARATION - BLAMEPOST_PROSE_CHECK=off");
  console.log(TAG + " Operator-facing prose was NOT checked on this run.");
  console.log(TAG + " This is a declared exemption, not a clean result. Unset");
  console.log(TAG + " BLAMEPOST_PROSE_CHECK to restore the gate.");
  console.log(TAG + " ==================================================================");
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Resolve the checker, and say which one was used. Order: the environment
// override, then the default location.
// ---------------------------------------------------------------------------
var override = process.env.BLAMEPOST_PROSE_CHECKER;
var fromEnv  = override !== undefined && String(override).trim() !== "";
var checker  = fromEnv ? path.resolve(String(override).trim()) : DEFAULT_CHECKER;

console.log(TAG + " checker: " + checker);
console.log(TAG + " source:  " + (fromEnv ? "BLAMEPOST_PROSE_CHECKER" : "default location"));

// Probe for the FILE. Never infer availability from the checker's behavior: a
// tool that has regressed into erroring on every run must fail this gate, not
// be mistaken for a tool that was never installed.
if (!fs.existsSync(checker)) {
  fail(1, [
    "the prose checker was not found.",
    "",
    "  looked for: " + checker,
    "  source:     " + (fromEnv ? "BLAMEPOST_PROSE_CHECKER environment variable" : "default location"),
    "",
    "This gate fails closed. A missing checker is not a pass - operator-facing prose",
    "went unchecked, and reporting that as success is how the defect it hunts ships.",
    "",
    "To proceed, do one of:",
    "  1. Install the technical-writing skill so the path above resolves.",
    "  2. Point BLAMEPOST_PROSE_CHECKER at check_technical_text.mjs where it does live.",
    "  3. Declare the skip: BLAMEPOST_PROSE_CHECK=off. It prints loudly and is a deliberate,",
    "     written act - which is the difference between it and a missing file."
  ]);
}

// ---------------------------------------------------------------------------
// Ask the checker whether it COMPLETED, by re-running it over the same inputs
// for its machine-readable envelope. A crash and a report full of findings both
// exit non-zero, and the two call for opposite actions from the operator.
//
// The envelope is read for its shape, meaning whether it parses, whether it
// carries a findings array and whether it says it examined anything, and for
// the LENGTH of that array.
// Finding text is never read. A gate that decided its verdict by grepping the
// checker's messages would be filtering the tool it is running, which is the
// defect the inherited stdio on the real run exists to prevent.
// ---------------------------------------------------------------------------
var MAX_REPORT = 32 * 1024 * 1024;

// The scope the gate enforces. Declared here because BOTH the completion probe and the real
// run must use it: scoping only the run would make the probe count a different population,
// and the summary line would then report a number the gate never acted on.
// BLAMEPOST_PROSE_CHECKS=all widens this to every family the checker implements, which is what
// `npm run check:prose:all` sets. The advisory families are then read by a human rather than
// enforced; the narrow set below is what a machine gets to decide.
var CHECKS = String(process.env.BLAMEPOST_PROSE_CHECKS || "").trim() === "all"
  ? null
  : "notation,identifiers,secrets,region";
function withChecks(argv) { return CHECKS === null ? argv : argv.concat(["--checks=" + CHECKS]); }

function completionOf(fileArgs) {
  var probe = proc.spawnSync(
    process.execPath,
    withChecks([checker].concat(fileArgs, ["--fail-on-findings", "--json"])),
    { cwd: ROOT, encoding: "utf8", maxBuffer: MAX_REPORT }
  );
  if (probe.error)  return { completed: false, why: "it could not be started (" + msg(probe.error) + ")" };
  if (probe.signal) return { completed: false, why: "it was killed by signal " + probe.signal };
  var env;
  try {
    env = JSON.parse(String(probe.stdout || ""));
  } catch (e) {
    return {
      completed: false,
      why: "it wrote no parseable report to stdout (" + msg(e).split(/\r?\n/)[0].slice(0, 120) + ")"
    };
  }
  if (!env || typeof env !== "object" || !Array.isArray(env.findings)) {
    return { completed: false, why: "its report carries no findings array" };
  }
  if (env.ok !== true) {
    return { completed: false, why: "its own report says it examined nothing (ok=" + JSON.stringify(env.ok) + ")" };
  }
  // Every finding is checked for the four fields the reconciliation reads, because the checker is
  // externally versioned and a renamed or missing one is a TOOLING incompatibility. Left unchecked
  // it would arrive as a prose defect: a finding with no `file` reconciles against nothing and
  // reports as unreviewed, and one with a `line` that is not a number reads a line this repository
  // never wrote. The whole point of the classification above is that those two call for opposite
  // actions from an operator, and that holds one level down as well.
  for (var f = 0; f < env.findings.length; f++) {
    var rec = env.findings[f];
    if (!rec || typeof rec !== "object") {
      return { completed: false, why: "finding " + f + " of its report is not an object" };
    }
    var missing = ["file", "check", "match"].filter(function (name) {
      return typeof rec[name] !== "string" || rec[name] === "";
    });
    if (!Number.isInteger(rec.line) || rec.line < 1) missing.push("line");
    if (missing.length) {
      return {
        completed: false,
        why: "finding " + f + " of its report is missing or has retyped " + missing.join(", ") +
          " (this gate reads those four to reconcile a finding against what has been read)"
      };
    }
  }
  return { completed: true, findings: env.findings.length, list: env.findings };
}

// ---------------------------------------------------------------------------
// The positive control. Everything above proves the checker is THERE; this
// proves it still CHECKS. The fixture goes in the OS temp directory, because
// writing a deliberately defective document inside the repository would put it
// in the very tree being gated, and a throw partway would leave it there.
// ---------------------------------------------------------------------------
// The known-bad input must be a defect the gate ENFORCES, not merely one the checker can
// find. An earlier canary used a bare code fence, which is a `convention` finding; once the
// gate was scoped to notation/identifiers/secrets/region that fence stopped tripping, and
// the control correctly reported that its own verdict had become worthless. The defect below
// is a `notation` one: an em dash where a command's double hyphen belongs,
// which turns a copy-pasteable flag into a broken one. The control therefore
// fails whenever the enforced scope stops working. Change CHECKS and this must
// change with it.
var CANARY_DOC = [
  "# canary",
  "",
  "A control document the prose gate writes, checks, and deletes on every run.",
  "",
  "```bash",
  "npm run build " + "—" + "dry-run",
  "```",
  ""
].join("\n");

function runCanary() {
  var dir;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamepost-prose-canary-"));
  } catch (e) {
    return { code: 2, lines: ["cannot create a canary fixture under " + os.tmpdir() + ": " + msg(e)] };
  }
  var doc = path.join(dir, "canary.md");
  try {
    fs.writeFileSync(doc, CANARY_DOC, "utf8");

    // The same argv the real documents get, INCLUDING the check scope. A control run
    // under a wider scope proves the checker works in a mode nothing else uses: if
    // `notation` regressed but any advisory family still flagged the fixture, the run
    // would exit nonzero and the canary would report OK while the enforced set was dead.
    // All three invocations here, the probe, the control and the real run, go
    // through withChecks for that reason.
    var run = proc.spawnSync(
      process.execPath, withChecks([checker, doc, "--fail-on-findings"]),
      { cwd: ROOT, encoding: "utf8", maxBuffer: MAX_REPORT }
    );
    if (run.error) {
      return { code: 2, lines: ["could not run the checker on the control document: " + msg(run.error)] };
    }
    if (run.signal) {
      return {
        code: 4,
        lines: ["the checker was killed by signal " + run.signal + " on the control document."].concat(captured(run))
      };
    }
    if (run.status === 0) {
      return {
        code: 3,
        lines: [
          "the checker did not flag a known-bad input.",
          "",
          "  checker: " + checker,
          "  control: a markdown document whose fenced command writes a flag with an em dash",
          "           where the double hyphen belongs, which is a `notation` defect and so",
          "           sits inside the enforced set above",
          "  result:  exit 0 under --fail-on-findings, which means it found nothing",
          "",
          "A checker that reports nothing about a document written to be reported on will",
          "report nothing about the real documents either, so its verdict on them cannot be",
          "trusted. This is a regression in the TOOL. The prose in this repository has not",
          "been assessed on this run.",
          "",
          "To proceed, do one of:",
          "  1. Repair or reinstall the technical-writing skill so its checker reports again.",
          "  2. Point BLAMEPOST_PROSE_CHECKER at a check_technical_text.mjs that works.",
          "  3. Declare the skip: BLAMEPOST_PROSE_CHECK=off. It prints loudly and is on the record."
        ].concat(captured(run))
      };
    }
    var done = completionOf([doc]);
    if (!done.completed) {
      return {
        code: 4,
        lines: [
          "the checker did not complete a run on the control document: " + done.why + ".",
          "It exited " + run.status + " without producing a report.",
          "",
          "  checker: " + checker,
          "",
          "This is a failure of the TOOL. Nothing here is a verdict on the prose in this",
          "repository - no document was assessed on this run."
        ].concat(captured(run))
      };
    }
    if (done.findings < 1) {
      return {
        code: 3,
        lines: [
          "the checker exited " + run.status + " on the control document and then reported zero",
          "findings when asked for the same run again. The two answers disagree, so neither is",
          "a result this gate can act on.",
          "",
          "  checker: " + checker,
          "",
          "This is a failure of the TOOL, and says nothing about the prose in this repository."
        ].concat(captured(run))
      };
    }
    return { ok: true, findings: done.findings };
  } catch (e) {
    return { code: 2, lines: ["the control document could not be prepared: " + msg(e)] };
  } finally {
    // A throw or a failed control must not leave the fixture behind, and
    // process.exit does not run a finally, so every arm above RETURNS and the
    // gate exits after this function, never inside it.
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      console.error(TAG + " warning: the canary fixture " + dir + " could not be removed: " + msg(e));
    }
  }
}

var canary = runCanary();
if (!canary.ok) fail(canary.code, canary.lines);
console.log(TAG + " canary:  OK, the checker flagged the known-bad control document (" +
  canary.findings + " finding(s)), so its verdict below is a real one");

var reconcilerFault = reconcilerControl();
if (reconcilerFault) fail(3, reconcilerFault);
console.log(TAG + " control: OK, the reviewed-exception table objects to an unread finding, a " +
  "count that grew, a context that moved and an entry matching nothing");

var reservedFault = reservedExampleControl();
if (reservedFault) fail(3, reservedFault);
console.log(TAG + " control: OK, the RFC 2606 rule sets aside a reserved address and keeps a " +
  "real one, a reserved one sharing a document with a real one, another family's finding " +
  "and one whose document cannot be read");

// ---------------------------------------------------------------------------
// Discover the document set. Nothing is hardcoded, so a new document cannot
// join the repository ungated, at any depth.
// ---------------------------------------------------------------------------
var excludedNames = EXCLUDED.map(function (e) { return e.file; });
var skipped = {};
SKIPPED_DIRS.forEach(function (s) { skipped[s.dir] = true; });

var found     = [];
var walkError = null;
var tooDeep   = null;

function walk(dir, rel, depth) {
  if (walkError || tooDeep) return;
  if (depth > MAX_DEPTH) { tooDeep = rel || "."; return; }
  var entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    walkError = (rel || ".") + " - " + msg(e);
    return;
  }
  entries.forEach(function (d) {
    // A symlink is never followed. It is the only way this walk can loop, and a
    // link pointing out of the tree would pull in documents the repository does
    // not carry. Windows junctions report as symlinks here too.
    if (d.isSymbolicLink()) return;
    var child = rel ? rel + "/" + d.name : d.name;
    if (d.isDirectory()) {
      if (skipped[d.name]) return;
      walk(path.join(dir, d.name), child, depth + 1);
      return;
    }
    if (d.isFile() && /\.md$/i.test(d.name)) found.push(child);
  });
}

walk(ROOT, "", 0);

if (walkError) {
  fail(2, [
    "cannot read " + walkError,
    "Discovery stopped there, so the scope of this run is unknown and no part of it",
    "can be reported as clean."
  ]);
}
if (tooDeep) {
  fail(2, [
    "the walk hit its depth cap of " + MAX_DEPTH + " at " + tooDeep + ".",
    "Anything below that directory would go unchecked, and a truncated scope reported",
    "as a pass is the failure this gate exists to prevent. Raise MAX_DEPTH deliberately,",
    "or add the directory to SKIPPED_DIRS with a reason."
  ]);
}

var docs = found
  .filter(function (n) { return excludedNames.indexOf(n) === -1; })
  .sort();

if (docs.length === 0) {
  fail(2, [
    "no operator-facing document was found under " + ROOT + ".",
    "Nothing was checked, which is not a clean result."
  ]);
}

console.log(TAG + " documents (" + docs.length + ", discovered from disk): " + docs.join(", "));
SKIPPED_DIRS.forEach(function (s) {
  console.log(TAG + " skipped:  " + s.dir + "/ - " + s.reason);
});
EXCLUDED.forEach(function (e) {
  console.log(TAG + " excluded: " + e.file + " - " + e.reason);
});
// Printed on every run, in full. An acceptance nobody sees is one nobody revisits, and the
// reason is the part that has to be re-read: it is what a future reader checks the finding
// against when deciding whether it still holds.
REVIEWED.forEach(function (r) {
  console.log(TAG + " reviewed: " + r.file + " [" + r.check + "] \"" + r.match + "\" x" +
    r.contexts.length + " - " + r.reason);
});
console.log("");

// ---------------------------------------------------------------------------
// Run it. --fail-on-findings is what turns a report into a gate; the checker
// exits 0 with findings otherwise, because its findings are a review by default.
// stdio is inherited so the checker's own output reaches the operator verbatim -
// a summary written here would be this script's opinion of the findings, and
// filtering them would be the exact defect the gate exists to prevent.
// ---------------------------------------------------------------------------
// The gate is SCOPED to the check families that decide something here, because a gate that
// fires on correct prose is one an operator learns to ignore, and then it protects nothing.
//
//   notation     a dash inside --dry-run, a smart quote inside a command, a mangled version
//                constraint. This is the damage the whole checker exists to prevent, and the
//                one class where a false negative ships a broken copy-pasteable command.
//   identifiers  a malformed RFC / CVE / CWE / GHSA / SPDX / package reference.
//   secrets      a credential-shaped token committed into a document.
//   region       a regional-spelling MIX, which is a real inconsistency rather than a taste.
//
// The families left out are advisory here, not silent. `npm run check:prose:all` runs the
// full set for a human read. Each is excluded for a structural reason, not for being noisy:
//   acronyms      the mail vocabulary is acronyms: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT,
//                 IMAP, JMAP, SASL. The checker's own text says to leave an acronym where
//                 context disambiguates it, and a mail server's documentation is that
//                 context; expanding each one on every use makes the document harder to read,
//                 not easier.
//   productnames  fires inside identifiers and URLs its own rule text calls protected
//                 (`application/json`, `https://`), and on single letters the rule says never
//                 to fire on.
//   spelling      fires on punctuation inside badge and code spans.
//   markup        duplicate "Added" / "Fixed" headings, which Keep a Changelog requires once
//                 per release, in a file this repository generates.
//   claims,       flag-only by design: they route to a human owner rather than to a verdict,
//   sources,      so failing a build on them would assert a judgement the checker is
//   style,        explicitly not making.
//   comments
var args = withChecks([checker].concat(docs, ["--fail-on-findings"]));
var run  = proc.spawnSync(process.execPath, args, { cwd: ROOT, stdio: "inherit" });

if (run.error) {
  fail(2, ["could not run the checker: " + msg(run.error)]);
}
if (run.signal) {
  fail(4, ["the checker was killed by signal " + run.signal + " - treat as not run, not as clean."]);
}

var code = run.status;
if (code === 0) {
  // A clean run is where a stale acceptance hides. The table is reconciled in BOTH directions, so
  // an entry matching nothing has to fail here as much as it does beside a finding. Otherwise the
  // last prose fix quietly leaves an exception behind, and it sits there ready to cover a finding
  // with the same key and context when one is reintroduced. Reconciled against an empty report,
  // which is exactly what the checker just said.
  var cleanProblems = CHECKS === null ? [] : reconcile([], documentCache().lineAt, REVIEWED);
  if (cleanProblems.length) {
    fail(1, [
      "the checker reported no findings, and " + cleanProblems.length + " reviewed exception(s) " +
        "no longer describe anything:",
      ""
    ].concat(cleanProblems.map(function (p, i) { return "  " + (i + 1) + ". " + p; })).concat([
      "",
      "The prose was fixed and the acceptance outlived it. Delete the entry: left in place it " +
      "would cover the same finding silently if it ever came back."
    ]));
  }
  console.log("");
  console.log(TAG + " OK, no findings in " + docs.length + " operator-facing document(s)");
  finish(0);
}

// A non-zero exit carries two different results, and they ask opposite things of
// the operator: rewrite a sentence, or repair a tool. Classify before reporting.
console.error("");
var outcome = completionOf(docs);

if (!outcome.completed) {
  fail(4, [
    "the checker did not complete a run: " + outcome.why + ".",
    "It exited " + code + " without producing a report.",
    "",
    "  checker:   " + checker,
    "  documents: " + docs.length + ", none of them assessed",
    "",
    "This is a failure of the TOOL. Whatever it printed above is not a verdict on the",
    "prose in this repository - there is no defect here to go and fix. Repair or",
    "reinstall the checker and run the gate again."
  ]);
}
if (outcome.findings === 0) {
  fail(4, [
    "the checker exited " + code + " and then reported zero findings when asked for the same",
    "run again. The two answers disagree, so neither is a result this gate can act on.",
    "",
    "  checker:   " + checker,
    "  documents: " + docs.length,
    "",
    "This is a failure of the TOOL, and says nothing about the prose in this repository."
  ]);
}
// The two modes answer different questions, so they exit differently.
//
// The SCOPED default runs notation, identifiers, secrets and region: a broken
// command flag, a malformed identifier, a leaked credential, a spelling a reader
// cannot search for. A caller reading the exit status of that run is asking
// whether the tree is clean, and the answer must be able to be no. It stays
// strict.
//
// `all` additionally runs the families that are flag-only by design, meaning
// claims, sources, style and comments, where a finding routes to a human
// rather than to a verdict. That run is a reading list, and exiting non-zero for it made the
// documented review step look like a failing build every time anyone ran it.
//
// A tool failure above still exits non-zero in BOTH modes; that classification is
// the whole point of the branch it sits in. BLAMEPOST_PROSE_STRICT=1 forces the strict
// status even in `all` mode, for whoever wires that run into a pipeline.
var strict = String(process.env.BLAMEPOST_PROSE_STRICT || "").trim() === "1" || CHECKS !== null;

// The enforced scope reconciles against REVIEWED. `all` mode does not: it runs families the
// table was never written for, so every flag-only finding would read as unreviewed and the
// answer would be noise. That run stays a reading list.
if (CHECKS !== null) {
  var docCache = documentCache();
  // The RFC 2606 rule runs before the reconciliation, so a reserved address
  // needs no written acceptance and nobody is taught to write a real domain to
  // get past the gate. Each one it sets aside is named here, because the
  // checker's own report is printed above in full and a finding that appears
  // there and then does not appear in the verdict has to be accounted for.
  var reserved = reservedExampleFindings(outcome.list, docCache.linesOf);
  reserved.forEach(function (f) {
    console.log(TAG + " reserved: " + f.file + ":" + f.line + " [" + f.check + "] \"" + f.match +
      "\" - RFC 2606 reserves this name for documentation and no address in this document " +
      "sits outside that reservation, so the finding above is not one to act on");
  });
  var judged   = outcome.list.filter(function (f) { return reserved.indexOf(f) === -1; });
  var problems = reconcile(judged, docCache.lineAt, REVIEWED);
  if (problems.length === 0) {
    console.log("");
    console.log(TAG + " OK, " + docs.length + " document(s); of the " + outcome.findings +
      " finding(s) above, " + reserved.length + " name" + (reserved.length === 1 ? "s" : "") +
      " a domain RFC 2606 reserves and the other " + judged.length + " " +
      (judged.length === 1 ? "is" : "are") + " recorded in REVIEWED and still");
    console.log(TAG + " describe" + (judged.length === 1 ? "s" : "") + " the line " +
      (judged.length === 1 ? "it was" : "they were") + " read on. The checker's own report is " +
      "printed in full above, so nothing here is hidden. What these lines add is that " +
      "somebody read it.");
    finish(0);
  }
  fail(1, [
    "the checker reported " + outcome.findings + " finding(s) across " + docs.length +
      " document(s), and " + problems.length + " of them do not reconcile with what has been read:",
    ""
  ].concat(problems.map(function (p, i) { return "  " + (i + 1) + ". " + p; })).concat([
    "",
    "Fix the prose, or read the finding and record it in REVIEWED in this file with the",
    "context it was read on and the reason it is correct as it stands. An acceptance costs a",
    "written reason on purpose: it is what the next reader checks the finding against."
  ]));
}

var report = [
  "the checker completed and reported " + outcome.findings + " finding(s) across " +
    docs.length + " document(s).",
  "This run includes the families that are flag-only by design, which the reviewed-exception",
  "table above was never written for, so its findings are a reading list rather than a",
  "verdict. Read them and fix what is a defect.",
  "",
  strict
    ? "Exit status is non-zero: BLAMEPOST_PROSE_STRICT=1 was set."
    : "Exit status is 0. Set BLAMEPOST_PROSE_STRICT=1 to fail on them instead."
];
if (strict) fail(1, report);
report.forEach(function (l) { console.error(TAG + " " + l); });
finish(0);
