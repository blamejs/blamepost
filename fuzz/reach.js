// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether a harness arrives at the reader it is written for, measured on
 * the harness's own seed corpus.
 *
 * `run-once.js` answers whether a harness loads and reads its seeds
 * without reporting a finding. That is a different question. A harness
 * whose body returns before it calls anything, and a harness whose reader
 * moved out from under it, both read every seed without a finding and
 * both answer for no part of the server. The count such a run publishes
 * is a count of files.
 *
 * So each harness names the entry points it drives, as an exported
 * `targets` function returning one entry per reader:
 *
 *   module.exports.targets = function () {
 *     return [
 *       { name: "b.guardImapCommand.validate",
 *         of: b.guardImapCommand, call: "validate" },
 *     ];
 *   };
 *
 * `of` is the object the harness itself calls through and `call` is the
 * property on it, so the declaration and the call site are the same
 * lookup. A reader that is renamed or removed leaves `of[call]` absent
 * and the declaration is refused; a harness that stops calling a reader
 * it still declares reaches it on no seed and is refused for that.
 * `name` is the label a refusal prints, so it is the text somebody greps
 * for.
 *
 * `measure` replaces each declared entry point with a counting wrapper,
 * runs every seed through the harness, and records which seeds arrived at
 * which entry point. The originals go back afterwards, on a finding as
 * well, because the harnesses of one run share the modules they read.
 *
 * WHAT IS PUBLISHED. `targetCount` is the entry points the tree declares
 * and `reachCount` is the arrivals measured, one per entry point per seed
 * that got there. The two fail apart: a harness that stops declaring
 * anything drops the first, and a harness that stops arriving anywhere
 * drops the second while the first stands still.
 *
 * `test/layer-0-primitives/fuzz-seed-corpus.test.js` drives this over
 * `fuzz/` and over fixture harnesses of its own.
 */

var nodePath = require("node:path");

var runOnce = require("./run-once.js");

// A refusal about a declaration or the tree, rather than a finding inside
// a reader.
function _refusal(message) {
  var err = new Error(message);
  err.code = "reach/declaration";
  return err;
}

/**
 * The entry points one loaded harness declares, each checked to be a
 * function that is there now.
 */
function declaredTargets(mod, name) {
  if (typeof mod.targets !== "function") {
    throw _refusal(name + runOnce.HARNESS_SUFFIX + " exports no targets function, so nothing " +
      "says which reader it is written for and a run over it answers for no part of the server.");
  }
  var declared = mod.targets();
  if (!Array.isArray(declared) || declared.length === 0) {
    throw _refusal(name + runOnce.HARNESS_SUFFIX + " declares no entry point.");
  }
  var seen = Object.create(null);
  return declared.map(function (entry, i) {
    var at = name + runOnce.HARNESS_SUFFIX + " target " + i;
    if (entry === null || typeof entry !== "object") {
      throw _refusal(at + " is not an object.");
    }
    if (typeof entry.name !== "string" || entry.name.length === 0) {
      throw _refusal(at + " carries no name, so a refusal about it would name nothing.");
    }
    if (seen[entry.name]) {
      throw _refusal(at + " repeats the name " + entry.name + ", so one of the two would be " +
        "answered for by the other.");
    }
    seen[entry.name] = true;
    if (entry.of === null || (typeof entry.of !== "object" && typeof entry.of !== "function")) {
      throw _refusal(entry.name + " names no object to read the entry point off.");
    }
    if (typeof entry.call !== "string" || entry.call.length === 0) {
      throw _refusal(entry.name + " names no property to read off that object.");
    }
    if (typeof entry.of[entry.call] !== "function") {
      throw _refusal(entry.name + " is declared as " + entry.call + " and that is " +
        typeof entry.of[entry.call] + " rather than a function, so the harness drives nothing " +
        "by that name.");
    }
    return { name: entry.name, of: entry.of, call: entry.call, seeds: 0, calls: 0 };
  });
}

// Put every stand-in back, newest first. Two declarations may name the
// same property under two names, and the second stand-in then wraps the
// first, so unwinding in the order they went on would leave one of them
// installed for the harnesses measured after this one.
function _restoreAll(restores) {
  for (var i = restores.length - 1; i >= 0; i -= 1) restores[i]();
}

// A counting stand-in for one entry point, put back by `restore`.
function _instrument(target) {
  var original = target.of[target.call];
  function counted() {
    target.calls += 1;
    return original.apply(this, arguments);
  }
  Object.defineProperty(counted, "name", { value: original.name, configurable: true });
  Object.defineProperty(counted, "length", { value: original.length, configurable: true });
  Object.keys(original).forEach(function (k) { counted[k] = original[k]; });

  try { target.of[target.call] = counted; }
  catch (err) {
    throw _refusal(target.name + " cannot be measured: writing to " + target.call +
      " was refused (" + ((err && err.message) || String(err)) + ").");
  }
  if (target.of[target.call] !== counted) {
    throw _refusal(target.name + " cannot be measured: " + target.call + " kept its old value " +
      "after the write, so an arrival at it would go uncounted.");
  }
  return function () { target.of[target.call] = original; };
}

/**
 * Run one harness over its own seed corpus with its declared entry points
 * counted.
 *
 * Returns `{ name, mode, seeds, findings, targets, problem }`. `targets`
 * carries one entry per declaration with `seeds`, the number of seeds
 * that arrived at it, and `calls`, the arrivals. `problem` is set instead
 * when the harness did not load or its declaration was refused, and the
 * caller reports that rather than a reach.
 */
async function measure(dir, name) {
  // Rooted first, because `require` reads a path that is not rooted as a
  // package name rather than as a file on disk.
  dir = nodePath.resolve(dir);
  var entry = { name: name, mode: null, seeds: 0, findings: [], targets: [], problem: null };

  var harness;
  var mod;
  try {
    harness = runOnce.loadHarness(dir, name);
    mod = require(runOnce.harnessFile(dir, name));
  } catch (err) {
    entry.problem = "did not load: " + ((err && err.stack) || String(err));
    return entry;
  }
  entry.mode = harness.mode;

  var corpus = runOnce.corpusDir(dir, name);
  var inputs;
  try { inputs = runOnce.corpusInputs(corpus); }
  catch (_e) { entry.problem = "has no seed corpus at " + name + runOnce.CORPUS_SUFFIX; return entry; }
  if (inputs.length === 0) {
    entry.problem = "has an empty seed corpus at " + name + runOnce.CORPUS_SUFFIX;
    return entry;
  }

  var targets;
  try { targets = declaredTargets(mod, name); }
  catch (err) { entry.problem = (err && err.message) || String(err); return entry; }
  entry.targets = targets;

  var restores = [];
  try {
    for (var t = 0; t < targets.length; t += 1) restores.push(_instrument(targets[t]));
  } catch (err) {
    _restoreAll(restores);
    entry.problem = (err && err.message) || String(err);
    entry.targets = [];
    return entry;
  }

  try {
    for (var s = 0; s < inputs.length; s += 1) {
      for (var r = 0; r < targets.length; r += 1) targets[r].calls = 0;
      var error = await runOnce.runInput(harness, inputs[s].bytes);
      entry.seeds += 1;
      if (error !== null) entry.findings.push({ label: inputs[s].label, error: error });
      for (var k = 0; k < targets.length; k += 1) {
        if (targets[k].calls > 0) targets[k].seeds += 1;
      }
    }
  } finally {
    _restoreAll(restores);
  }
  return entry;
}

/**
 * Every harness in `dir`, run over its own seed corpus with its declared
 * entry points counted.
 *
 * Resolves to `{ dir, harnesses, harnessCount, seedCount, findingCount,
 * targetCount, reachCount, refusals }`. `refusals` lists every reason the
 * run cannot be called clean: an empty tree, a harness that did not load
 * or declared nothing readable, a seed that produced a finding, and an
 * entry point no seed arrived at.
 */
async function measureAll(dir) {
  dir = nodePath.resolve(dir);
  var summary = {
    dir:          dir,
    harnesses:    [],
    harnessCount: 0,
    seedCount:    0,
    findingCount: 0,
    targetCount:  0,
    reachCount:   0,
    refusals:     [],
  };

  var names = runOnce.harnessNames(dir);
  for (var i = 0; i < names.length; i += 1) {
    var entry = await measure(dir, names[i]);
    summary.harnesses.push(entry);
    if (entry.problem !== null) continue;
    summary.harnessCount += 1;
    summary.seedCount += entry.seeds;
    summary.findingCount += entry.findings.length;
    summary.targetCount += entry.targets.length;
    entry.targets.forEach(function (target) { summary.reachCount += target.seeds; });
  }

  if (names.length === 0) {
    summary.refusals.push("no *" + runOnce.HARNESS_SUFFIX + " harness was found in " + dir);
  }
  if (summary.harnessCount === 0) summary.refusals.push("no harness was measured");
  if (summary.seedCount === 0) summary.refusals.push("no seed input was read");
  if (summary.targetCount === 0) summary.refusals.push("no harness declared an entry point");
  if (summary.reachCount === 0) summary.refusals.push("no seed arrived at any entry point");

  summary.harnesses.forEach(function (h) {
    if (h.problem !== null) { summary.refusals.push(h.name + " " + h.problem); return; }
    h.findings.forEach(function (f) {
      summary.refusals.push(h.name + " reported a finding on the seed " + f.label + ": " +
        ((f.error && f.error.message) || String(f.error)));
    });
    h.targets.forEach(function (target) {
      if (target.seeds > 0) return;
      summary.refusals.push(h.name + " declares " + target.name + " and no seed in its corpus " +
        "arrived there, so the corpus answers for nothing that reader does");
    });
  });
  return summary;
}

module.exports = {
  declaredTargets: declaredTargets,
  measure:         measure,
  measureAll:      measureAll,
};
