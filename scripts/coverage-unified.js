// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Unified cross-layer branch coverage. `npm run coverage` measures c8 over the smoke
// suite ONLY; it misses the lib branches only a real client on a real socket reaches,
// such as the SMTP conversation that ends in a refusal, the IMAP command a client
// pipelines, and the delivery attempt a receiving MTA rejects. Those live in the
// integration layer. This runner accumulates both under one shared V8-coverage
// directory and emits a single merged report and lcov, so the coverage floor reflects
// EVERY test layer. That is the honest number to rank the least-covered modules
// against and drive up. It writes
// coverage/lcov.info, so `check-swallow-coverage` runs against the merged report too.
//
//   node scripts/coverage-unified.js            merged text-summary + lcov
//   node scripts/coverage-unified.js --detail   also the per-file table
//
// The smoke layer is required (a failing layer fails the run); the integration layer is
// best-effort, because it needs listeners bound and a service stack up. A run without
// them warns and is skipped rather than failing the coverage number for the layer that
// did run, and its coverage is DISCARDED rather than merged, so a partial run can never
// inflate the floor.
//
// Each layer runs its entrypoint DIRECTLY under node with NODE_V8_COVERAGE pointed at
// the shared directory (child test processes inherit it), so raw V8 coverage from every
// layer accumulates; `c8 report --temp-directory` then merges it. This avoids wrapping
// each command through the c8 CLI (whose argument parsing differs per layer cwd).
//
// WHAT THE RUN MERGED, published as the last lines of stdout:
//
//   EXAMINED <n> declared-coverage-layers
//   EXAMINED <n> merged-coverage-layers
//   EXAMINED <n> merged-coverage-files
//
// Three, because they fail independently and the report reads the same however
// they came apart. `declared-coverage-layers` is the list this runner was built
// to accumulate; a layer removed from it shrinks the floor with nothing else
// moving. `merged-coverage-layers` is how many of them actually contributed,
// which is the number that drops when the best-effort layer exits non-zero and
// has its coverage discarded, and it used to be a boolean nothing read. And
// `merged-coverage-files` is the raw V8 output that reached the merge
// directory: two layers can both run and exit clean having written none of it,
// which leaves the layer counts healthy and the merged report built over
// nothing.
//
// The number matters beyond this script because `check-swallow-coverage` reads
// the lcov this run writes. A floor measured on one layer of two, reported
// under a cross-layer heading, is a weaker verdict wearing a stronger name.

var spawnSync = require("node:child_process").spawnSync;
var path = require("node:path");
var fs = require("node:fs");

var examinedCounts = require("./examined-counts.js");

var ROOT = path.resolve(__dirname, "..");
var COV = path.join(ROOT, "coverage");
var MERGE = path.join(COV, "tmp-merged");
var C8 = path.join(ROOT, "node_modules", "c8", "bin", "c8.js");
// The vendored framework is excluded: it is upstream's code, covered by upstream's own
// suite, and folding it in would bury this project's real number under a tree nobody
// here writes tests for.
var INCLUDE = ["--include=bin/**", "--include=lib/**", "--exclude=lib/vendor/**"];
var detail = process.argv.indexOf("--detail") >= 0;

fs.rmSync(COV, { recursive: true, force: true });
fs.mkdirSync(MERGE, { recursive: true });

// One coverage layer: run its entrypoint under node with NODE_V8_COVERAGE pointed at a PER-LAYER directory,
// and fold that directory into the shared MERGE set ONLY on success. A required layer that exits non-zero
// fails the whole run; a best-effort layer that exits non-zero has its coverage DISCARDED (the per-layer dir
// is removed, never merged), so partial execution from a suite that loaded lib and then failed can never
// inflate the merged floor or satisfy check-swallow-coverage with a failed run's hits.
// What each layer contributed, so the run can say it rather than leaving the
// answer in a boolean nothing reads. `merged` counts the layers whose raw
// coverage reached MERGE; `files` counts the raw coverage files themselves,
// because a layer can run, exit clean and write none.
var merged = { layers: 0, files: 0, missing: [] };

function layer(opts) {
  process.stdout.write("\n[coverage-unified] === " + opts.label + " ===\n");
  var layerDir = path.join(COV, "tmp-" + opts.slug);
  fs.rmSync(layerDir, { recursive: true, force: true });
  fs.mkdirSync(layerDir, { recursive: true });
  var env = Object.assign({}, process.env, { NODE_V8_COVERAGE: layerDir });
  var r = spawnSync(process.execPath, opts.cmd, { cwd: opts.cwd || ROOT, stdio: "inherit", env: env });
  if (r.status !== 0) {
    fs.rmSync(layerDir, { recursive: true, force: true });   // discard a failed layer's coverage rather than merging it
    if (opts.required) { process.stderr.write("[coverage-unified] " + opts.label + " FAILED (exit " + r.status + "): required layer\n"); process.exit(r.status || 1); }
    process.stderr.write("[coverage-unified] " + opts.label + " skipped (exit " + r.status + "): coverage discarded, continuing\n");
    merged.missing.push(opts.label + " (exit " + r.status + ")");
    return false;
  }
  var written = fs.readdirSync(layerDir);
  written.forEach(function (fn) { fs.renameSync(path.join(layerDir, fn), path.join(MERGE, fn)); });
  fs.rmSync(layerDir, { recursive: true, force: true });
  merged.layers += 1;
  merged.files  += written.length;
  return true;
}

// The layers this runner accumulates. Declared as a list so the count it
// publishes is the list it actually walked rather than a number written beside
// it, which is the same distinction every gate here is held to.
var LAYERS = [
  { slug: "smoke", label: "smoke", cmd: [path.join("test", "smoke.js")], required: true },
  { slug: "integration", label: "integration (live listeners)", cmd: [path.join("scripts", "test-integration.js")], required: false },
];

LAYERS.forEach(layer);

process.stdout.write("\n[coverage-unified] === merged cross-layer report ===\n");
var reporters = ["--reporter=text-summary", "--reporter=lcov"];
if (detail) reporters.push("--reporter=text");
var report = spawnSync(
  process.execPath,
  [C8, "report", "--temp-directory=" + MERGE, "--reports-dir=" + COV].concat(INCLUDE, reporters),
  { cwd: ROOT, stdio: "inherit", env: process.env }
);
// spawnSync reports a SIGNAL kill (or a failure to spawn) as a NULL status, so `status || 0` would exit 0 after
// an OOM-killed or never-started reporter and hand a downstream gate a missing/partial lcov. Anything other than
// a clean exit 0 fails the run.
if (report.error) {
  process.stderr.write("[coverage-unified] merged report could not run: " + report.error.message + "\n");
  process.exit(1);
}
if (report.status !== 0) {
  process.stderr.write("[coverage-unified] merged report FAILED (" + (report.signal ? "signal " + report.signal : "exit " + report.status) + ") -- the report is missing or partial\n");
  process.exit(report.status || 1);
}

// A layer that did not contribute is named on stdout rather than left to a
// stderr line the caller's `&&` chain scrolls past. The heading on the report
// above says cross-layer, and a reader has to be able to see which layers that
// covered.
merged.missing.forEach(function (label) {
  process.stdout.write("[coverage-unified] " + label + " did not contribute coverage, so the " +
    "merged floor above does not answer for the branches only that layer reaches\n");
});

process.exit(examinedCounts.publish([
  { unit: "declared-coverage-layers", n: LAYERS.length },
  { unit: "merged-coverage-layers",   n: merged.layers },
  { unit: "merged-coverage-files",    n: merged.files },
], { tag: "[coverage-unified]" }));
