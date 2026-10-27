// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * fuzz-seed-corpus: every fuzz harness loads, reads every seed in its own
 * corpus without reporting a finding, and arrives at the reader it is
 * written for.
 *
 * The harnesses under `fuzz/` run under a fuzzing budget in the
 * ClusterFuzzLite workflows and nowhere else. A harness that stops
 * loading, or one that reports a well-formed seed as a finding, is
 * otherwise found the next time a pull request touches `lib/` and the
 * fuzzing job fails for a reason that has nothing to do with that pull
 * request.
 *
 * Reading the seeds without a finding is the weaker half of the question,
 * and on its own it is answered the same way by a harness that drives a
 * reader and by a harness that returns before it calls anything. So each
 * harness names the entry points it drives, `fuzz/reach.js` counts the
 * seeds that arrive at each one, and an entry point no seed reached fails
 * this file. The count published below is of arrivals rather than of
 * files, because a count of files is what a harness that reaches nothing
 * still publishes.
 *
 * WHAT IS DRIVEN. `fuzz/reach.js` and `fuzz/run-once.js`, required rather
 * than copied. `measureAll` discovers the harnesses, loads each one, reads
 * its declaration, and runs it over every file in its `<name>_seed_corpus`
 * directory with each declared entry point counted. Both functions also
 * run over fixture harnesses written to a temporary directory, which is
 * how each refusal is shown to fire: a harness that throws on one seed, a
 * harness whose returned promise rejects, a harness that returns a promise
 * without declaring it, a harness with no corpus or an empty one, a
 * directory with no harness in it, a harness that names no entry point, a
 * harness naming one that is not there, and a harness that names one and
 * never calls it.
 *
 * WHAT IS PUBLISHED. `EXAMINED <n> fuzz-harnesses`,
 * `EXAMINED <n> seed-inputs`, `EXAMINED <n> harness-entry-points` and
 * `EXAMINED <n> entry-point-reaches`, ahead of the `CHECKS` line. Any
 * number at zero fails the run. The last two fail apart: a tree that stops
 * declaring entry points drops the third, and a tree that stops arriving
 * at them drops the fourth while the third stands still.
 *
 * The build script and both fuzzing workflows ask `run-once.js --mode`
 * whether to pass `--sync`. Each one is read here for that call, so a
 * script that goes back to passing `--sync` to every harness fails this
 * file instead of dropping the rejections of the asynchronous ones.
 *
 * No sockets and no database. It loads the harnesses in this process and
 * writes fixture files under a temporary directory.
 *
 * Run standalone: node test/layer-0-primitives/fuzz-seed-corpus.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var spawnRun = require("../helpers/spawn");
var runOnce  = require("../../fuzz/run-once.js");
var reach    = require("../../fuzz/reach.js");

var count = helpers.count;
var tail  = spawnRun.lastLines;

var REPO_ROOT   = helpers.REPO_ROOT;
var FUZZ_DIR    = nodePath.join(REPO_ROOT, "fuzz");
var RUN_ONCE_JS = nodePath.join(FUZZ_DIR, "run-once.js");

// The three places a harness is handed to jazzer. Each one has to ask the
// runner which mode a harness declares.
var MODE_READERS = [
  ".clusterfuzzlite/build.sh",
  ".github/workflows/cflite_pr.yml",
  ".github/workflows/cflite_batch.yml",
];

// A line that hands a harness to jazzer with `--sync` on it, other than
// the `sync)` branch of the case on the mode.
var UNCONDITIONAL_SYNC_RE =
  /^(?![ \t]*sync\))[^\n]*(?:jazzer|compile_javascript_fuzzer)[^\n]*--sync\b[^\n]*$/m;

var RUN_CEILING_MS = 60000;

function _findingLabels(summary) {
  var out = [];
  summary.harnesses.forEach(function (h) {
    h.findings.forEach(function (f) { out.push(h.name + "/" + f.label); });
  });
  return out;
}

function _describe(summary) {
  return JSON.stringify({
    harnesses: summary.harnessCount,
    seeds:     summary.seedCount,
    targets:   summary.targetCount,
    reaches:   summary.reachCount,
    findings:  _findingLabels(summary),
    refusals:  summary.refusals.map(function (r) { return r.split("\n")[0]; }),
  });
}

function _unreached(entry) {
  return (entry.targets || []).filter(function (t) { return t.seeds === 0; })
    .map(function (t) { return t.name; });
}

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

async function everyHarnessReadsItsOwnSeedsClean() {
  var summary = await reach.measureAll(FUZZ_DIR);

  // Discovery, read a second way. A matcher in run-once.js that stopped
  // matching would publish a smaller set and agree with itself.
  var onDisk = nodeFs.readdirSync(FUZZ_DIR).filter(function (f) {
    return f.endsWith(runOnce.HARNESS_SUFFIX);
  });
  count("tree: the runner discovers every *.fuzz.js file in fuzz/",
    summary.harnesses.length === onDisk.length && onDisk.length > 0,
    summary.harnesses.length + " discovered, " + onDisk.length + " on disk");

  summary.harnesses.forEach(function (h) {
    count("tree: " + h.name + " loads and has a seed corpus with a seed in it",
      h.problem === null && h.seeds > 0, h.problem === null ? h.seeds + " seeds" : h.problem);
    count("tree: " + h.name + " reads every seed in its corpus without a finding",
      h.findings.length === 0,
      h.findings.map(function (f) {
        return f.label + ": " + ((f.error && f.error.message) || String(f.error));
      }).join(" | "), { limit: 2000 });
    // The half a clean read cannot answer. A harness that names no entry
    // point, and a harness that names one it no longer calls, both read
    // every seed without a finding.
    count("reach: " + h.name + " names the entry points it drives, and each one is there",
      h.problem === null && h.targets.length > 0,
      h.problem === null ? h.targets.length + " entry points" : h.problem);
    count("reach: " + h.name + " arrives at every entry point it names, from its own corpus",
      h.problem === null && _unreached(h).length === 0,
      h.problem === null
        ? h.targets.map(function (t) { return t.name + " " + t.seeds + "/" + h.seeds; }).join(" | ")
        : h.problem,
      { limit: 2000 });
  });

  count("tree: at least one harness ran", summary.harnessCount > 0, _describe(summary));
  count("tree: at least one seed was read", summary.seedCount > 0, _describe(summary));
  count("reach: the tree declares at least one entry point", summary.targetCount > 0,
    _describe(summary));
  count("reach: at least one seed arrived at one of them", summary.reachCount > 0,
    _describe(summary));
  count("tree: the run carries no refusal", summary.refusals.length === 0,
    summary.refusals.join(" | "), { limit: 2000 });

  console.log("EXAMINED " + summary.harnessCount + " fuzz-harnesses");
  console.log("EXAMINED " + summary.seedCount + " seed-inputs");
  console.log("EXAMINED " + summary.targetCount + " harness-entry-points");
  console.log("EXAMINED " + summary.reachCount + " entry-point-reaches");
}

// The declaration the shell scripts read, read here the same way and then
// held against a spawn of the command they actually run. A disagreement
// would hand jazzer the wrong flag for that harness.
async function theModeTheScriptsReadIsTheModeTheHarnessLoadsWith() {
  var names = runOnce.harnessNames(FUZZ_DIR);
  var seen = {};
  for (var i = 0; i < names.length; i += 1) {
    var mode = runOnce.declaredMode(runOnce.harnessFile(FUZZ_DIR, names[i]));
    if (seen[mode]) continue;
    seen[mode] = true;
    var rv = await spawnRun.runNodeScript([RUN_ONCE_JS, "--mode", names[i]], {
      cwd: REPO_ROOT, ceilingMs: RUN_CEILING_MS,
    });
    count("mode: `run-once.js --mode " + names[i] + "` prints the declared " + mode,
      rv.code === 0 && rv.out.trim() === mode, "exit " + rv.code + ": " + tail(rv.out, 3));
  }
  count("mode: the tree carries a harness of each mode, so both answers were asked for",
    seen[runOnce.SYNC] === true && seen[runOnce.ASYNC] === true, JSON.stringify(seen));

  MODE_READERS.forEach(function (rel) {
    var text = nodeFs.readFileSync(nodePath.join(REPO_ROOT, rel), "utf8");
    count("mode: " + rel + " asks run-once.js for each harness's mode",
      text.indexOf("run-once.js --mode") !== -1, rel);
    // `--sync` written straight onto the jazzer command line passes it to
    // every harness whatever the harness declares. The one line allowed to
    // carry it is the `sync)` branch of the case on the mode.
    var unconditional = UNCONDITIONAL_SYNC_RE.exec(text);
    count("mode: " + rel + " does not pass --sync to every harness unconditionally",
      unconditional === null, unconditional === null ? rel : unconditional[0]);
  });
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Each fixture is a directory holding harness files and corpus
// directories, written at run time. A harness that fails on purpose
// committed under fuzz/ would be fuzzed by the workflows.
function _fixtureDir(root, name, files) {
  var dir = nodePath.join(root, name);
  nodeFs.mkdirSync(dir, { recursive: true });
  Object.keys(files).forEach(function (rel) {
    var abs = nodePath.join(dir, rel);
    nodeFs.mkdirSync(nodePath.dirname(abs), { recursive: true });
    if (files[rel] === null) return;
    nodeFs.writeFileSync(abs, files[rel]);
  });
  return dir;
}

var BREAKING_SEED = "the seed this harness breaks on";

var THROWS_ON_ONE_SEED =
  '"use strict";\n' +
  "module.exports.fuzz = function (data) {\n" +
  "  if (data.toString(\"utf8\") === " + JSON.stringify(BREAKING_SEED) + ") {\n" +
  "    throw new Error(\"fixture: a planted finding\");\n" +
  "  }\n" +
  "};\n";

var READS_EVERYTHING =
  '"use strict";\n' +
  "module.exports.fuzz = function (data) { return data.length; };\n";

var REJECTS_ON_ONE_SEED =
  '"use strict";\n' +
  "module.exports.fuzz = async function (data) {\n" +
  "  await Promise.resolve();\n" +
  "  if (data.toString(\"utf8\") === " + JSON.stringify(BREAKING_SEED) + ") {\n" +
  "    throw new Error(\"fixture: a planted rejection\");\n" +
  "  }\n" +
  "};\n" +
  "module.exports.async = true;\n";

var RETURNS_A_PROMISE_UNDECLARED =
  '"use strict";\n' +
  "module.exports.fuzz = function (data) { return Promise.resolve(data.length); };\n";

var DECLARES_IN_ANOTHER_FORM =
  '"use strict";\n' +
  "module.exports.fuzz = async function (data) { return data.length; };\n" +
  "module.exports[\"async\"] = true;\n";

// A stand-in reader, declared and driven the way a harness declares and
// drives the framework guard it is written for.
var FIXTURE_READER =
  '"use strict";\n' +
  "var reader = { read: function (data) { return data.length; } };\n";

var FIXTURE_DECLARATION =
  "module.exports.targets = function () {\n" +
  "  return [{ name: \"fixture.reader.read\", of: reader, call: \"read\" }];\n" +
  "};\n";

var DRIVES_WHAT_IT_NAMES = FIXTURE_READER +
  "module.exports.fuzz = function (data) { return reader.read(data); };\n" +
  FIXTURE_DECLARATION;

// The shape a clean read cannot see: every seed is read without a
// finding and the reader the harness is written for is never called.
var NAMES_A_READER_IT_NEVER_CALLS = FIXTURE_READER +
  "module.exports.fuzz = function (data) { return data.length; };\n" +
  FIXTURE_DECLARATION;

// The shape a renamed or removed reader leaves behind.
var NAMES_A_READER_THAT_IS_NOT_THERE =
  '"use strict";\n' +
  "var reader = {};\n" +
  "module.exports.fuzz = function (data) { return data.length; };\n" +
  FIXTURE_DECLARATION;

var NAMES_THE_SAME_READER_TWICE = FIXTURE_READER +
  "module.exports.fuzz = function (data) { return reader.read(data); };\n" +
  "module.exports.targets = function () {\n" +
  "  return [{ name: \"fixture.reader.read\", of: reader, call: \"read\" },\n" +
  "          { name: \"fixture.reader.read\", of: reader, call: \"read\" }];\n" +
  "};\n";

// ---------------------------------------------------------------------------
// The refusals, each shown to fire
// ---------------------------------------------------------------------------

async function aHarnessThatThrowsOnOneSeedFailsTheCheck(root) {
  var dir = _fixtureDir(root, "throws", {
    "planted.fuzz.js":                  THROWS_ON_ONE_SEED,
    "planted_seed_corpus/fine.txt":     "an ordinary seed",
    "planted_seed_corpus/breaks.txt":   BREAKING_SEED,
  });
  var summary = await runOnce.corpusSmoke(dir);

  count("canary: the planted harness is reported with exactly one finding",
    summary.findingCount === 1 &&
    JSON.stringify(_findingLabels(summary)) === JSON.stringify(["planted/breaks.txt"]),
    _describe(summary));
  count("canary: the check fails on it, so a finding cannot pass as a clean corpus",
    summary.refusals.length === 1 && summary.refusals[0].indexOf("breaks.txt") !== -1 &&
    summary.refusals[0].indexOf("a planted finding") !== -1, _describe(summary));
  count("canary: the seed beside it was still read and counted",
    summary.seedCount === 2 && summary.harnessCount === 1, _describe(summary));

  // The same fixture through the command line, which is what a person
  // reproducing the failure runs.
  var rv = await spawnRun.runNodeScript([RUN_ONCE_JS, "--all", dir], {
    cwd: REPO_ROOT, ceilingMs: RUN_CEILING_MS,
  });
  count("canary: `run-once.js --all` over the fixture exits 1 and names the seed",
    rv.code === 1 && /REFUSED: planted reported a finding on the seed breaks\.txt/.test(rv.out),
    "exit " + rv.code + ": " + tail(rv.out, 5));
}

async function aRejectionFromAnAsyncHarnessIsAFinding(root) {
  var dir = _fixtureDir(root, "rejects", {
    "rejects.fuzz.js":                  REJECTS_ON_ONE_SEED,
    "rejects_seed_corpus/fine.txt":     "an ordinary seed",
    "rejects_seed_corpus/breaks.txt":   BREAKING_SEED,
  });
  var summary = await runOnce.corpusSmoke(dir);
  count("async: a harness declaring async is loaded as one",
    summary.harnesses[0].mode === runOnce.ASYNC, _describe(summary));
  count("async: its rejected promise is the finding, on the seed that produced it",
    JSON.stringify(_findingLabels(summary)) === JSON.stringify(["rejects/breaks.txt"]),
    _describe(summary));
}

async function aPromiseFromAnUndeclaredHarnessIsAFinding(root) {
  var dir = _fixtureDir(root, "undeclared", {
    "undeclared.fuzz.js":               RETURNS_A_PROMISE_UNDECLARED,
    "undeclared_seed_corpus/fine.txt":  "an ordinary seed",
  });
  var summary = await runOnce.corpusSmoke(dir);
  count("undeclared: a promise from a harness that declares nothing is a finding",
    summary.findingCount === 1 &&
    /does not declare `module\.exports\.async = true;`/.test(summary.refusals.join(" ")),
    _describe(summary));
}

async function aDeclarationTheScriptsCannotReadIsRefused(root) {
  var dir = _fixtureDir(root, "otherform", {
    "otherform.fuzz.js":                DECLARES_IN_ANOTHER_FORM,
    "otherform_seed_corpus/fine.txt":   "an ordinary seed",
  });
  var summary = await runOnce.corpusSmoke(dir);
  count("declaration: an async export the source line does not match refuses the load",
    summary.harnessCount === 0 && /did not load/.test(summary.refusals.join(" ")) &&
    /source declares sync/.test(summary.refusals.join(" ")), _describe(summary));
}

async function aHarnessWithoutSeedsIsRefused(root) {
  var noCorpus = _fixtureDir(root, "nocorpus", {
    "lonely.fuzz.js":                   READS_EVERYTHING,
  });
  var none = await runOnce.corpusSmoke(noCorpus);
  count("no corpus: a harness with no seed corpus directory is refused by name",
    /lonely has no seed corpus at lonely_seed_corpus/.test(none.refusals.join(" | ")),
    _describe(none));
  count("no corpus: and a run that read no seed is refused as well",
    none.seedCount === 0 && /no seed input was read/.test(none.refusals.join(" | ")),
    _describe(none));

  var emptyCorpus = _fixtureDir(root, "emptycorpus", {
    "hollow.fuzz.js":                   READS_EVERYTHING,
    "hollow_seed_corpus/.keep-dir":     null,
  });
  var hollow = await runOnce.corpusSmoke(emptyCorpus);
  count("empty corpus: a harness whose corpus directory holds no file is refused by name",
    /hollow has an empty seed corpus/.test(hollow.refusals.join(" | ")), _describe(hollow));
}

async function aDirectoryWithNoHarnessIsRefused(root) {
  var dir = _fixtureDir(root, "noharness", {});
  var summary = await runOnce.corpusSmoke(dir);
  count("no harness: a directory with nothing to run is refused rather than reported clean",
    summary.harnessCount === 0 && summary.seedCount === 0 &&
    /no \*\.fuzz\.js harness was found/.test(summary.refusals.join(" | ")),
    _describe(summary));
}

// ---------------------------------------------------------------------------
// The reach refusals, each shown to fire
// ---------------------------------------------------------------------------

async function aHarnessThatNamesAReaderItNeverCallsIsRefused(root) {
  var dir = _fixtureDir(root, "unreached", {
    "quiet.fuzz.js":                    NAMES_A_READER_IT_NEVER_CALLS,
    "quiet_seed_corpus/one.txt":        "one",
    "quiet_seed_corpus/two.txt":        "two",
  });

  // The weaker question first, on the same fixture. It answers clean,
  // which is what makes the reach question worth asking.
  var clean = await runOnce.corpusSmoke(dir);
  count("reach: a harness that calls nothing still reads every seed without a finding",
    clean.refusals.length === 0 && clean.seedCount === 2, _describe(clean));

  var summary = await reach.measureAll(dir);
  count("reach: and the reach measurement refuses it, naming the harness and the reader",
    summary.refusals.some(function (r) {
      return r.indexOf("quiet declares fixture.reader.read") !== -1 &&
        r.indexOf("no seed in its corpus arrived there") !== -1;
    }), _describe(summary));
  count("reach: the seeds were still read and counted, so the refusal is about arrival",
    summary.seedCount === 2 && summary.targetCount === 1 && summary.reachCount === 0,
    _describe(summary));
}

async function aHarnessThatNamesNoReaderIsRefused(root) {
  var dir = _fixtureDir(root, "undeclared-target", {
    "silent.fuzz.js":                   READS_EVERYTHING,
    "silent_seed_corpus/one.txt":       "one",
  });
  var summary = await reach.measureAll(dir);
  count("reach: a harness exporting no targets function is refused by name",
    /silent .*exports no targets function/.test(summary.refusals.join(" | ")), _describe(summary));
  count("reach: and it counts toward nothing, so no number stands in for it",
    summary.harnessCount === 0 && summary.targetCount === 0 && summary.reachCount === 0,
    _describe(summary));
}

async function aHarnessNamingAReaderThatMovedIsRefused(root) {
  var gone = _fixtureDir(root, "reader-gone", {
    "moved.fuzz.js":                    NAMES_A_READER_THAT_IS_NOT_THERE,
    "moved_seed_corpus/one.txt":        "one",
  });
  var summary = await reach.measureAll(gone);
  count("reach: a named reader that is not a function is refused, naming it",
    /fixture\.reader\.read is declared as read and that is undefined/
      .test(summary.refusals.join(" | ")), _describe(summary));

  var twice = _fixtureDir(root, "reader-twice", {
    "twice.fuzz.js":                    NAMES_THE_SAME_READER_TWICE,
    "twice_seed_corpus/one.txt":        "one",
  });
  var repeated = await reach.measureAll(twice);
  count("reach: two entries under one name are refused, so neither answers for the other",
    /repeats the name fixture\.reader\.read/.test(repeated.refusals.join(" | ")),
    _describe(repeated));
}

// The control for the reach half. Every vector above would pass against a
// measurement that refused everything.
async function aHarnessThatDrivesWhatItNamesIsAccepted(root) {
  var dir = _fixtureDir(root, "reaches", {
    "driven.fuzz.js":                   DRIVES_WHAT_IT_NAMES,
    "driven_seed_corpus/one.txt":       "one",
    "driven_seed_corpus/two.txt":       "two",
  });
  var summary = await reach.measureAll(dir);
  count("control: a harness that drives the reader it names carries no refusal",
    summary.refusals.length === 0 && summary.targetCount === 1 && summary.reachCount === 2,
    _describe(summary));
  // Required here rather than at the top of the file: the fixture is
  // written during the run, so there is nothing at this path until now.
  var fixture = require(nodePath.join(dir, "driven.fuzz.js"));
  var reader = fixture.targets()[0].of.read;
  count("control: and the reader it names is put back once the measurement is over",
    typeof reader === "function" && String(reader).indexOf("return data.length") !== -1,
    String(reader));
}

// The control. Every vector above would pass against a runner that
// refused everything.
async function aHarnessThatReadsEverySeedCleanIsAccepted(root) {
  var dir = _fixtureDir(root, "clean", {
    "clean.fuzz.js":                    READS_EVERYTHING,
    "clean_seed_corpus/one.txt":        "one",
    "clean_seed_corpus/two.txt":        BREAKING_SEED,
    "asyncclean.fuzz.js":               REJECTS_ON_ONE_SEED.replace(BREAKING_SEED, "never sent"),
    "asyncclean_seed_corpus/one.txt":   "one",
  });
  var summary = await runOnce.corpusSmoke(dir);
  count("control: harnesses that read every seed clean carry no refusal",
    summary.refusals.length === 0 && summary.harnessCount === 2 && summary.seedCount === 3,
    _describe(summary));
}

// ---------------------------------------------------------------------------

async function run() {
  var root = helpers.tempDir("fuzzcorpus");
  try {
    await aHarnessThatReadsEverySeedCleanIsAccepted(root);
    await aHarnessThatThrowsOnOneSeedFailsTheCheck(root);
    await aRejectionFromAnAsyncHarnessIsAFinding(root);
    await aPromiseFromAnUndeclaredHarnessIsAFinding(root);
    await aDeclarationTheScriptsCannotReadIsRefused(root);
    await aHarnessWithoutSeedsIsRefused(root);
    await aDirectoryWithNoHarnessIsRefused(root);

    await aHarnessThatDrivesWhatItNamesIsAccepted(root);
    await aHarnessThatNamesAReaderItNeverCallsIsRefused(root);
    await aHarnessThatNamesNoReaderIsRefused(root);
    await aHarnessNamingAReaderThatMovedIsRefused(root);

    await theModeTheScriptsReadIsTheModeTheHarnessLoadsWith();
    await everyHarnessReadsItsOwnSeedsClean();
  } finally {
    helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "fuzz-seed-corpus", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
