// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Run one harness over one input, over a directory of inputs, or run
 * every harness over its own seed corpus, under plain Node.
 *
 * Three jobs. It reproduces a finding from the artifact libFuzzer wrote,
 * which is a stack trace rather than a fuzzer log. It runs the seed
 * corpus as a smoke check, so a harness that no longer loads or that
 * reports a well-formed input as a finding is caught without waiting for
 * a fuzzing budget. And it answers whether a harness is synchronous,
 * which is the one flag the build scripts pass per harness.
 *
 * Usage:
 *   node fuzz/run-once.js <target> <text>
 *   node fuzz/run-once.js <target> @<path>
 *   node fuzz/run-once.js <target> --corpus [dir]
 *   node fuzz/run-once.js --all [dir]
 *   node fuzz/run-once.js --mode <target>
 *
 * `<target>` is the harness basename, so `smtp-command` runs
 * `fuzz/smtp-command.fuzz.js`. `--corpus` defaults to that target's
 * `<target>_seed_corpus` directory. `--all` runs every harness in `dir`,
 * default this directory, over its own seed corpus. `--mode` prints
 * `sync` or `async` and runs nothing.
 *
 * Exit codes: 0 when every input was read without a finding, 1 when one
 * of them produced a finding or `--all` refused the run, and 2 when the
 * arguments named something that is not there.
 *
 * `test/layer-0-primitives/fuzz-seed-corpus.test.js` requires this file
 * and runs `corpusSmoke` over the tree, so the seed corpora run with the
 * suite rather than only when a fuzzing budget does.
 */

var fs   = require("node:fs");
var path = require("node:path");

var HERE = __dirname;

var HARNESS_SUFFIX = ".fuzz.js";
var CORPUS_SUFFIX  = "_seed_corpus";

var SYNC  = "sync";
var ASYNC = "async";

// How a harness says it returns a promise. jazzer runs a harness under
// `--sync` unless told otherwise, and under `--sync` it does not wait for
// a returned promise: a rejection from one is never reported as a
// finding. The build script and both fuzzing workflows ask `--mode`
// which flag to pass, and `--mode` reads the source for this exact line
// rather than loading the harness, so the answer costs no framework load
// and has no side effects. `loadHarness` holds the loaded module to the
// same answer, so a declaration written in any other form is refused
// rather than read as synchronous.
var ASYNC_DECLARATION_RE = /^module\.exports\.async = true;$/m;

// A refusal about the arguments or the tree, as opposed to a finding in
// a harness. The command line answers the first with exit code 2.
function _usage(message) {
  var err = new Error(message);
  err.code = "run-once/usage";
  return err;
}

function _isPromiseLike(value) {
  return value !== null && (typeof value === "object" || typeof value === "function") &&
    typeof value.then === "function";
}

/**
 * The harness names in `dir`, sorted: every regular file ending in
 * `.fuzz.js`, with the suffix removed.
 */
function harnessNames(dir) {
  if (!fs.existsSync(dir)) throw _usage("there is no harness directory at " + dir + ".");
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter(function (e) { return e.isFile() && e.name.endsWith(HARNESS_SUFFIX); })
    .map(function (e) { return e.name.slice(0, -HARNESS_SUFFIX.length); })
    .sort();
}

function harnessFile(dir, name) {
  return path.join(dir, name + HARNESS_SUFFIX);
}

function corpusDir(dir, name) {
  return path.join(dir, name + CORPUS_SUFFIX);
}

/**
 * `sync` or `async`, read from the harness source without loading it.
 */
function declaredMode(file) {
  if (!fs.existsSync(file)) throw _usage("there is no harness at " + file + ".");
  return ASYNC_DECLARATION_RE.test(fs.readFileSync(file, "utf8")) ? ASYNC : SYNC;
}

/**
 * Load one harness. Returns `{ name, file, mode, fuzz }`.
 *
 * Throws when the file is missing, exports no `fuzz` function, or
 * exports an `async` flag that the source declaration does not match.
 */
function loadHarness(dir, name) {
  var file = harnessFile(dir, name);
  var mode = declaredMode(file);
  var mod = require(file);
  if (typeof mod.fuzz !== "function") {
    throw _usage(name + HARNESS_SUFFIX + " exports no fuzz function, so jazzer has nothing to call.");
  }
  var exported = mod.async === true ? ASYNC : SYNC;
  if (exported !== mode) {
    throw _usage(name + HARNESS_SUFFIX + " exports async as " + String(mod.async) +
      " and its source declares " + mode + ". The build scripts read the source line " +
      "`module.exports.async = true;` and nothing else, so the two have to agree.");
  }
  return { name: name, file: file, mode: mode, fuzz: mod.fuzz };
}

/**
 * Every regular file in a corpus directory, sorted by name, as
 * `{ label, bytes }`.
 */
function corpusInputs(dir) {
  if (!fs.existsSync(dir)) throw _usage("there is no corpus directory at " + dir + ".");
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter(function (e) { return e.isFile(); })
    .map(function (e) { return e.name; })
    .sort()
    .map(function (name) {
      return { label: name, bytes: fs.readFileSync(path.join(dir, name)) };
    });
}

/**
 * Run a loaded harness over one input. Resolves to `null` when the
 * input was read without a finding, or to the error that is the finding.
 *
 * A synchronous harness that returns a promise is a finding of its own:
 * jazzer would run it under `--sync` and never see that promise settle.
 */
async function runInput(harness, bytes) {
  try {
    var returned = harness.fuzz(bytes);
    if (!_isPromiseLike(returned)) return null;
    if (harness.mode === ASYNC) {
      await returned;
      return null;
    }
    try { await returned; }
    catch (_e) { /* the contract finding below is the one reported */ }
    return new Error(harness.name + HARNESS_SUFFIX + " returned a promise and does not " +
      "declare `module.exports.async = true;`, so under --sync jazzer does not wait for it " +
      "and a rejection is never reported.");
  } catch (err) {
    return err || new Error("the harness threw " + String(err));
  }
}

/**
 * Run every harness in `dir` over its own seed corpus.
 *
 * Resolves to `{ dir, harnesses, harnessCount, seedCount, findingCount,
 * refusals }`. Each entry in `harnesses` is `{ name, mode, seeds,
 * findings, problem }`, and each finding is `{ label, error }`.
 * `refusals` lists every reason the run cannot be called clean: no
 * harness at all, no seed read at all, a harness with no seed corpus or
 * an empty one, a harness that did not load, and every finding.
 */
async function corpusSmoke(dir) {
  var summary = {
    dir:          dir,
    harnesses:    [],
    harnessCount: 0,
    seedCount:    0,
    findingCount: 0,
    refusals:     [],
  };
  var names = harnessNames(dir);
  for (var i = 0; i < names.length; i += 1) {
    var entry = { name: names[i], mode: null, seeds: 0, findings: [], problem: null };
    summary.harnesses.push(entry);

    var harness;
    try {
      harness = loadHarness(dir, names[i]);
    } catch (err) {
      entry.problem = "did not load: " + ((err && err.stack) || String(err));
      continue;
    }
    entry.mode = harness.mode;
    summary.harnessCount += 1;

    var corpus = corpusDir(dir, names[i]);
    if (!fs.existsSync(corpus)) {
      entry.problem = "has no seed corpus at " + path.basename(corpus);
      continue;
    }
    var inputs = corpusInputs(corpus);
    if (inputs.length === 0) {
      entry.problem = "has an empty seed corpus at " + path.basename(corpus);
      continue;
    }
    for (var s = 0; s < inputs.length; s += 1) {
      var error = await runInput(harness, inputs[s].bytes);
      entry.seeds += 1;
      summary.seedCount += 1;
      if (error !== null) {
        entry.findings.push({ label: inputs[s].label, error: error });
        summary.findingCount += 1;
      }
    }
  }

  if (names.length === 0) summary.refusals.push("no *" + HARNESS_SUFFIX + " harness was found in " + dir);
  if (summary.harnessCount === 0) summary.refusals.push("no harness loaded");
  if (summary.seedCount === 0) summary.refusals.push("no seed input was read");
  summary.harnesses.forEach(function (h) {
    if (h.problem !== null) summary.refusals.push(h.name + " " + h.problem);
    h.findings.forEach(function (f) {
      summary.refusals.push(h.name + " reported a finding on the seed " + f.label + ": " +
        ((f.error && f.error.message) || String(f.error)));
    });
  });
  return summary;
}

// ---- command line ----------------------------------------------------------

function _inputsFrom(target, args) {
  if (args[0] === "--corpus") return corpusInputs(args[1] || corpusDir(HERE, target));
  if (args.length === 0) throw _usage("name an input: some text, @<path>, or --corpus.");
  var literal = args.join(" ");
  if (literal.charAt(0) === "@") {
    var file = literal.slice(1);
    if (!fs.existsSync(file)) throw _usage("there is no file at " + file + ".");
    return [{ label: file, bytes: fs.readFileSync(file) }];
  }
  return [{ label: "<argument>", bytes: Buffer.from(literal, "utf8") }];
}

async function _runTarget(target, args) {
  var harness = loadHarness(HERE, target);
  var inputs  = _inputsFrom(target, args);
  var findings = 0;
  for (var i = 0; i < inputs.length; i += 1) {
    var error = await runInput(harness, inputs[i].bytes);
    if (error === null) {
      process.stdout.write("read  " + target + "  " + inputs[i].label +
        "  (" + inputs[i].bytes.length + " bytes)\n");
      continue;
    }
    findings += 1;
    process.stdout.write("FIND  " + target + "  " + inputs[i].label + "\n");
    process.stdout.write(((error && error.stack) || String(error)) + "\n");
  }
  process.stdout.write("EXAMINED " + inputs.length + " inputs\n");
  process.stdout.write("EXAMINED " + findings + " findings\n");
  return findings === 0 ? 0 : 1;
}

async function _runAll(dir) {
  var summary = await corpusSmoke(dir || HERE);
  summary.harnesses.forEach(function (h) {
    process.stdout.write((h.problem === null && h.findings.length === 0 ? "ok    " : "FAIL  ") +
      h.name + "  (" + (h.mode || "not loaded") + ", " + h.seeds + " seeds)\n");
  });
  summary.refusals.forEach(function (r) { process.stdout.write("REFUSED: " + r + "\n"); });
  process.stdout.write("EXAMINED " + summary.harnessCount + " harnesses\n");
  process.stdout.write("EXAMINED " + summary.seedCount + " seed-inputs\n");
  return summary.refusals.length === 0 ? 0 : 1;
}

async function main() {
  var argv = process.argv.slice(2);
  if (argv.length === 0) throw _usage("name a harness, for example smtp-command.");
  if (argv[0] === "--all") return _runAll(argv[1]);
  if (argv[0] === "--mode") {
    if (!argv[1]) throw _usage("--mode needs a harness name.");
    process.stdout.write(declaredMode(harnessFile(HERE, argv[1])) + "\n");
    return 0;
  }
  return _runTarget(argv[0], argv.slice(1));
}

module.exports = {
  HARNESS_SUFFIX:       HARNESS_SUFFIX,
  CORPUS_SUFFIX:        CORPUS_SUFFIX,
  SYNC:                 SYNC,
  ASYNC:                ASYNC,
  ASYNC_DECLARATION_RE: ASYNC_DECLARATION_RE,
  harnessNames:         harnessNames,
  harnessFile:          harnessFile,
  corpusDir:            corpusDir,
  declaredMode:         declaredMode,
  loadHarness:          loadHarness,
  corpusInputs:         corpusInputs,
  runInput:             runInput,
  corpusSmoke:          corpusSmoke,
};

if (require.main === module) {
  main().then(function (code) {
    process.exitCode = code;
  }, function (err) {
    if (err && err.code === "run-once/usage") {
      process.stderr.write("run-once: " + err.message + "\n");
      process.exitCode = 2;
      return;
    }
    process.stderr.write("run-once: " + ((err && err.stack) || String(err)) + "\n");
    process.exitCode = 1;
  });
}
