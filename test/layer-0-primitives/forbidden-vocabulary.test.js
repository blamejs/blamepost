// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * forbidden-vocabulary: scripts/check-forbidden-vocabulary.js driven over
 * fixture trees, with its exit code, its findings and its published counts
 * as the verdict.
 *
 * Every fixture tree is a fresh `git init` under a temporary directory. Its
 * files are untracked, so the gate lists them through `git ls-files --others`.
 * Git runs with no global or system configuration, so the machine's own
 * ignore rules do not change which fixture files are scanned.
 *
 * The words the gate refuses are built here with `gate.word`, so this file
 * does not contain them and passes the gate itself.
 *
 * The cases: the tokenizer and the self-proof called directly; a clean tree;
 * every refused entry in prose, in an identifier and in capitals; every
 * exemption passing its documented sense; a product-sense use beside each
 * exemption refused; an empty tree refused; a directory git cannot list and a
 * bad argument refused; and the counts published over this repository.
 *
 * No sockets and no database. It spawns git and node, and writes fixture
 * trees under the temporary directory.
 *
 * Run standalone: node test/layer-0-primitives/forbidden-vocabulary.test.js
 */

var fs    = require("node:fs");
var path  = require("node:path");
var cp    = require("node:child_process");
var spawn = cp.spawn;

var helpers        = require("../helpers");
var examinedCounts = require("../../scripts/examined-counts.js");
var gate           = require("../../scripts/check-forbidden-vocabulary.js");

var check = helpers.check;
var count = helpers.count;
var w     = gate.word;

var REPO_ROOT = helpers.REPO_ROOT;
var GATE      = path.join(REPO_ROOT, "scripts", "check-forbidden-vocabulary.js");

var RUN_CEILING_MS = 60000;

// ---------------------------------------------------------------------------
// Fixture trees
// ---------------------------------------------------------------------------

var _emptyConfig = null;

// The environment every git call and every gate run in a fixture tree gets:
// an empty global configuration, no system configuration, and a ceiling one
// level above the tree so git does not search the directories above it.
function gitEnv(root) {
  if (_emptyConfig === null) {
    var dir = helpers.tempDir("vocab-gitconfig");
    _emptyConfig = path.join(dir, "empty.gitconfig");
    fs.writeFileSync(_emptyConfig, "");
  }
  return Object.assign({}, process.env, {
    GIT_CONFIG_GLOBAL:       _emptyConfig,
    GIT_CONFIG_NOSYSTEM:     "1",
    GIT_CEILING_DIRECTORIES: path.dirname(root),
  });
}

function writeFiles(root, files) {
  Object.keys(files).forEach(function (rel) {
    var abs = path.join(root, rel.split("/").join(path.sep));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, files[rel]);
  });
}

function gitTree(label, files) {
  var root = helpers.tempDir("vocab-" + label);
  cp.execFileSync("git", ["init", "-q"], {
    cwd:   root,
    env:   gitEnv(root),
    stdio: ["ignore", "pipe", "pipe"],
  });
  writeFiles(root, files || {});
  return root;
}

// Runs the gate and resolves with its exit code, its stdout alone, and
// stdout and stderr together. The child is killed at the ceiling.
function runGate(args, env) {
  return new Promise(function (resolve) {
    var child = spawn(process.execPath, [GATE].concat(args), {
      cwd:   REPO_ROOT,
      env:   env || process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    var out = "";
    var stdout = "";
    var timer = setTimeout(function () {
      try { child.kill("SIGKILL"); }
      catch (_e) { /* drop-silent by design: the ceiling result below is the verdict */ }
      resolve({ code: null, out: out + "\n(ceiling hit)", stdout: stdout });
    }, RUN_CEILING_MS);
    child.stdout.on("data", function (d) { out += d.toString(); stdout += d.toString(); });
    child.stderr.on("data", function (d) { out += d.toString(); });
    child.on("error", function (e) {
      clearTimeout(timer);
      resolve({ code: -1, out: "spawn failed: " + e.message, stdout: "" });
    });
    child.on("close", function (code) {
      clearTimeout(timer);
      resolve({ code: code, out: out, stdout: stdout });
    });
  });
}

function runOver(root) {
  return runGate(["--root", root], gitEnv(root));
}

function flat(text) {
  return String(text).replace(/\s+/g, " ").trim().slice(0, 600);
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// How many findings the gate printed for one file.
function findingsFor(out, rel) {
  var re = new RegExp("\\] " + escapeRe(rel) + ":\\d+ ", "g");
  return (String(out).match(re) || []).length;
}

function publishedUnit(stdout, unit) {
  var hit = examinedCounts.publishedCounts(stdout).filter(function (c) { return c.unit === unit; });
  return hit.length === 1 ? hit[0].n : null;
}

function camel(phrase) {
  return phrase.split(" ").map(function (p) {
    return p.charAt(0).toUpperCase() + p.slice(1);
  }).join("");
}

// ---------------------------------------------------------------------------
// The words used in fixtures
// ---------------------------------------------------------------------------

var T  = w("ti|er");
var TS = w("ti|ers");
var S  = w("sub|scription");
var I  = w("In|voice");

// ---------------------------------------------------------------------------
// In process
// ---------------------------------------------------------------------------

function theTokenizerSplitsIdentifiersIntoWords() {
  var parts = gate.tokenize("readTimeoutMs HTTPServer snake_case").map(function (t) { return t.text; });
  count("camelCase, an acronym and snake_case each split into their words",
    parts.join(",") === "read,Timeout,Ms,HTTP,Server,snake,case", parts.join(","));

  var inside = gate.scanText("The explanation planted a plane beside the plant.\n", "probe");
  count("a word that merely contains a refused word is not a finding",
    inside.findings.length === 0, JSON.stringify(inside.findings));

  // A regular expression puts an escape letter directly in front of a word:
  // `\b` in a literal, `\\b` in a string handed to RegExp. Read as one run
  // of letters, the word becomes `b` plus the word and slips past.
  var escaped = [
    "var re = /\\b" + T + "[ -]?[abc]\\b/i;\n",
    "var re = new RegExp(\"\\\\b" + T + "\\\\b\");\n",
    "var re = /\\s" + w("pl|an") + "s?\\s/;\n",
  ];
  escaped.forEach(function (source, i) {
    var found = gate.scanText(source, "probe-escape-" + i);
    count("a refused word behind a regex escape letter is a finding (" + i + ")",
      found.findings.length === 1, JSON.stringify(found.findings) + " in " + JSON.stringify(source));
  });
  var harmless = gate.scanText("var re = /\\bexplanation\\b|\\splanted\\s/;\n", "probe-escape-clean");
  count("a regex escape in front of an ordinary word is not a finding",
    harmless.findings.length === 0, JSON.stringify(harmless.findings));
}

function theSelfProofPassesAndCountsEveryEntry() {
  var proof = gate.selfProof();
  count("the self-proof reports no problem", proof.problems.length === 0,
    proof.problems.join(" | "));
  count("the self-proof proves every refused entry",
    proof.proven === gate.REFUSED.length, proof.proven + " of " + gate.REFUSED.length);
}

// ---------------------------------------------------------------------------
// A clean tree
// ---------------------------------------------------------------------------

async function aCleanTreePassesAndPublishesWhatItRead() {
  var files = {
    "README.md":                    "An operator runs this server for each hosted domain and account.\n",
    "lib/index.js":                 "var readTimeoutMs = 1000;\nmodule.exports = { readTimeoutMs: readTimeoutMs };\n",
    "docs/wording.md":              "The explanation planted a plane, and an " + w("enter|prise") +
                                    " grade " + w("ed|ition") + " stays two separate words.\n",
    "lib/vendor/upstream/notes.md": "Upstream prose names " + w("pri|cing") + " and is not scanned.\n",
    "assets/blob.dat":              "binary " + String.fromCharCode(0) + " " + w("pa|id") + "\n",
    "ignored.md":                   "A file git ignores names " + w("se|ats") + ".\n",
    ".gitignore":                   "ignored.md\n",
  };
  var root = gitTree("clean", files);
  var run = await runOver(root);

  count("clean tree: the gate exits 0", run.code === 0, "exit " + run.code + ": " + flat(run.out));
  count("clean tree: it says it found nothing, over the files it read",
    /OK, no refused word outside an exemption in 4 file\(s\)/.test(run.out), flat(run.out));
  count("clean tree: files-scanned counts the four text files git lists outside the vendor path",
    publishedUnit(run.stdout, "files-scanned") === 4, flat(run.stdout));
  count("clean tree: refused-forms-proven counts every refused entry",
    publishedUnit(run.stdout, "refused-forms-proven") === gate.REFUSED.length, flat(run.stdout));
  count("clean tree: the binary file is named as not scanned",
    run.out.indexOf("assets/blob.dat (control byte, read as binary)") !== -1, flat(run.out));
  count("clean tree: the vendor path rule is printed",
    run.out.indexOf("not scanned: /^lib\\/vendor\\/[^/]+\\//") !== -1, flat(run.out));
  helpers.removeTempDir(root);
}

// ---------------------------------------------------------------------------
// Every refused entry
// ---------------------------------------------------------------------------

async function everyRefusedEntryIsFound() {
  var files = {};
  gate.REFUSED.forEach(function (entry, i) {
    var phrase = w(entry);
    files["prose/entry-" + i + ".md"]  = "The page names " + phrase + " here.\n";
    files["ident/entry-" + i + ".js"]  = "var some" + camel(phrase) + "Value = 1;\n";
    files["upper/entry-" + i + ".txt"] = "THE PAGE NAMES " + phrase.toUpperCase() + " HERE.\n";
  });
  files["wrapped/phrase.md"] = "// The " + w("enter|prise") + "\n// " + w("ed|ition") + " page.\n";
  files["lib/vendor/MANIFEST.json"] = "{ \"note\": \"" + w("bil|ling") + "\" }\n";
  var root = gitTree("words", files);
  var run = await runOver(root);

  count("every entry: the gate exits 1", run.code === 1, "exit " + run.code);
  gate.REFUSED.forEach(function (entry, i) {
    var prose = findingsFor(run.out, "prose/entry-" + i + ".md");
    var ident = findingsFor(run.out, "ident/entry-" + i + ".js");
    var upper = findingsFor(run.out, "upper/entry-" + i + ".txt");
    count("refused entry " + i + " is found once in prose, once in an identifier and once in capitals",
      prose === 1 && ident === 1 && upper === 1,
      "prose " + prose + ", identifier " + ident + ", capitals " + upper);
  });
  count("a two-word entry wrapped across two comment lines is found",
    findingsFor(run.out, "wrapped/phrase.md") === 1, flat(run.out.slice(-600)));
  count("the vendor manifest one level above the vendored packages is scanned",
    findingsFor(run.out, "lib/vendor/MANIFEST.json") === 1, flat(run.out.slice(-600)));
  count("every file in the tree was scanned",
    publishedUnit(run.stdout, "files-scanned") === gate.REFUSED.length * 3 + 2,
    flat(run.stdout.slice(-200)));
  helpers.removeTempDir(root);
}

// ---------------------------------------------------------------------------
// Exemptions, and the product-sense use beside each one
// ---------------------------------------------------------------------------

// Each exemption id maps to a fixture holding only its documented sense, the
// number of exempted occurrences in it, and a fixture that adds a
// product-sense use of the same word beside that sense.
var EXEMPTION_CASES = {
  "health-probe-field": {
    exempt: [
      "  }, { " + T + ": [\"liveness\", \"readiness\"], critical: true });",
      "    { " + T + ": \"readiness\", critical: true });",
      "    { " + T + ": \"liveness\", critical: false });",
      "// the health-probe " + TS + ", which are a framework field",
      "// the two senses in this tree: the health-probe",
      "// " + TS + ", which are a framework field",
      " * Run standalone: node test/layer-2-integration/health-probe-" + TS + ".test.js",
      "// and each health-probe " + T + " reports on its own",
    ].join("\n") + "\n",
    occurrences: 7,
    red: "  }, { " + T + ": [\"liveness\"] }); // and the " + T + " an account buys\n",
  },
  "jmap-push": {
    exempt: [
      "there is no `Push" + w("Sub|scription") + "/set`, so a client has nothing to register",
      "a push " + S + " needs an authenticated actor",
      "  // cross account gate is one gate. A push",
      "  //   " + S + " reads its account off the actor",
    ].join("\n") + "\n",
    occurrences: 3,
    red: "a push " + S + " is free, and a monthly " + S + " is not\n",
  },
  "rlo-filename-example": {
    exempt: [
      "// decoding to `" + I + " <RLO>gpj.exe` is shown as `" + I + " exe.jpg`",
      "        encodedWord(\"" + I + " \" + RLO + \"gpj.exe\")],",
    ].join("\n") + "\n",
    occurrences: 3,
    red: "// `" + I + " exe.jpg` is not the " + I.toLowerCase() + " an account was sent\n",
  },
  "release-notes-refused-list": {
    exempt: "\"description\": \"the sweep rejects phase / sweep / " + T +
      " / batch / group / slice numbering and tool names.\"\n",
    occurrences: 1,
    red: "\"description\": \"the sweep rejects phase / sweep / " + T +
      " / batch / group / slice numbering, and the top " + T + " is extra.\"\n",
  },
};

async function everyExemptionPassesItsDocumentedSense() {
  var ids = gate.EXEMPTIONS.map(function (ex) { return ex.id; });
  count("the test carries a fixture for exactly the exemptions the gate declares",
    JSON.stringify(ids.slice().sort()) === JSON.stringify(Object.keys(EXEMPTION_CASES).sort()),
    ids.join(", "));

  var files = {};
  Object.keys(EXEMPTION_CASES).forEach(function (id) {
    files["exempt/" + id + ".txt"] = EXEMPTION_CASES[id].exempt;
  });
  var root = gitTree("exempt", files);
  var run = await runOver(root);

  count("exemptions: a tree holding only the documented senses exits 0",
    run.code === 0, "exit " + run.code + ": " + flat(run.out));
  Object.keys(EXEMPTION_CASES).forEach(function (id) {
    var want = EXEMPTION_CASES[id].occurrences;
    count("exemption " + id + " passes all " + want + " occurrence(s) in its fixture",
      run.out.indexOf("exemption " + id + ": " + want + " occurrence(s)") !== -1,
      flat(run.out));
  });
  helpers.removeTempDir(root);
}

async function aProductSenseUseBesideEachExemptionIsRefused() {
  var files = {};
  Object.keys(EXEMPTION_CASES).forEach(function (id) {
    files["red/" + id + ".txt"] = EXEMPTION_CASES[id].red;
  });
  var root = gitTree("red", files);
  var run = await runOver(root);

  count("product sense: the gate exits 1", run.code === 1, "exit " + run.code + ": " + flat(run.out));
  Object.keys(EXEMPTION_CASES).forEach(function (id) {
    var n = findingsFor(run.out, "red/" + id + ".txt");
    count("beside exemption " + id + ", the product-sense use is refused exactly once",
      n === 1, n + " finding(s): " + flat(run.out));
  });
  helpers.removeTempDir(root);
}

// ---------------------------------------------------------------------------
// Input-validation labels in operator documentation
// ---------------------------------------------------------------------------

// The labels the internal-rulebook-vocabulary-in-source detector refuses in
// lib/, bin/, scripts/ and test/, each written in a Markdown file under a
// fixture docs/ directory, which that detector does not read.
var LABELS_IN_DOCS = {
  "docs/observability.md": "A failed report is dropped, as the observability " + T + " requires.\n",
  "docs/wire.md":          "A malformed command is refused. That is the wire " + T + " at work.\n",
  "docs/defensive.md":     "Defensive by " + T + ": a truncated lock file reads as absent.\n",
  "docs/best-effort.md":   "Best effort by " + T + ", so a slow resolver is skipped.\n",
  "docs/validation.md":    "The validation " + TS + " decide how each reader treats bad input.\n",
};

async function aValidationLabelInOperatorDocsIsRefused() {
  var root = gitTree("labels-docs", LABELS_IN_DOCS);
  var run = await runOver(root);

  var perFile = Object.keys(LABELS_IN_DOCS).map(function (rel) {
    return { rel: rel, n: findingsFor(run.out, rel) };
  });
  count("labels in docs: \"the observability " + T + "\" in docs/observability.md is refused once",
    perFile[0].n === 1, perFile[0].n + " finding(s): " + flat(run.out));
  count("labels in docs: every label is refused exactly once in its Markdown file",
    perFile.every(function (f) { return f.n === 1; }),
    perFile.map(function (f) { return f.rel + " " + f.n; }).join(", "));
  count("labels in docs: the gate exits 1", run.code === 1, "exit " + run.code + ": " + flat(run.out));
  helpers.removeTempDir(root);
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

async function anEmptyTreeIsRefused() {
  var root = gitTree("empty", {});
  var run = await runOver(root);

  count("empty tree: the gate exits 1", run.code === 1, "exit " + run.code + ": " + flat(run.out));
  count("empty tree: it refuses the empty unit by name",
    /REFUSED: 0 files-scanned/.test(run.out), flat(run.out));
  count("empty tree: files-scanned is not published as a count",
    publishedUnit(run.stdout, "files-scanned") === null, flat(run.stdout));
  count("empty tree: it does not report the tree as clean",
    run.out.indexOf("OK, no refused word") === -1, flat(run.out));
  helpers.removeTempDir(root);
}

async function aRunThatCannotListFilesIsRefused() {
  var plain = helpers.tempDir("vocab-nogit");
  fs.writeFileSync(path.join(plain, "README.md"), "An operator reads this.\n");
  var run = await runOver(plain);
  count("a directory git cannot list exits 2", run.code === 2, "exit " + run.code + ": " + flat(run.out));
  count("and it says git could not list the files",
    run.out.indexOf("git could not list the files") !== -1, flat(run.out));
  helpers.removeTempDir(plain);

  var missing = await runGate(["--root", path.join(plain, "absent")]);
  check("a --root that does not exist exits 2", missing.code === 2);
  var noValue = await runGate(["--root"]);
  check("--root with no value exits 2", noValue.code === 2);
  var unknown = await runGate(["--everything"]);
  check("an unrecognized argument exits 2", unknown.code === 2);
}

// ---------------------------------------------------------------------------
// This repository
// ---------------------------------------------------------------------------

async function theGatePublishesBothCountsOverThisRepository() {
  var run = await runGate([], process.env);
  var scanned = publishedUnit(run.stdout, "files-scanned");
  count("over this repository the gate publishes a non-zero files-scanned",
    typeof scanned === "number" && scanned > 0, flat(run.stdout.slice(-300)));
  count("over this repository it proves every refused entry",
    publishedUnit(run.stdout, "refused-forms-proven") === gate.REFUSED.length,
    flat(run.stdout.slice(-300)));
}

// The gate is only a gate if the chain runs it. `scripts.gates` is the one
// list `npm run gates`, CI and the release battery all read.
function theChainRunsTheGate() {
  var pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));
  var chain = pkg.scripts && pkg.scripts.gates;
  count("the gates script runs check-forbidden-vocabulary",
    typeof chain === "string" && chain.indexOf("scripts/check-forbidden-vocabulary.js") !== -1,
    String(chain));
}

// ---------------------------------------------------------------------------

async function run() {
  theTokenizerSplitsIdentifiersIntoWords();
  theSelfProofPassesAndCountsEveryEntry();
  await aCleanTreePassesAndPublishesWhatItRead();
  await everyRefusedEntryIsFound();
  await everyExemptionPassesItsDocumentedSense();
  await aProductSenseUseBesideEachExemptionIsRefused();
  await aValidationLabelInOperatorDocsIsRefused();
  await anEmptyTreeIsRefused();
  await aRunThatCannotListFilesIsRefused();
  await theGatePublishesBothCountsOverThisRepository();
  theChainRunsTheGate();
  return helpers.getChecks();
}

module.exports = { name: "forbidden-vocabulary", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
