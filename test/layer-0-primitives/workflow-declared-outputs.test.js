// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * workflow-declared-outputs: a value a workflow computes and publishes has
 * to be read by something.
 *
 * A step that writes `key=value` to `$GITHUB_OUTPUT`, or a job that lists a
 * name under `outputs:`, is making a value available to the rest of the
 * run. Nothing checks that anything takes it. The expression that would
 * read it, `steps.<id>.outputs.<key>` or `needs.<job>.outputs.<key>`, is
 * ordinary text: writing it wrong, renaming the step, or deleting the only
 * reader leaves the producer in place, still running, still costing the
 * time it costs, and answering nobody. The workflow stays green, because
 * an unread output is not an error to GitHub.
 *
 * The live case was the container release. It pulled the published image,
 * streamed it through `docker save` into a digest and published the result
 * as a step output that no expression anywhere in the tree named. The work
 * ran on every tag.
 *
 * WHAT IS ASSERTED. Every declaration is paired with a reader, in both
 * directions of the pairing:
 *
 *   - every `$GITHUB_OUTPUT` key a step writes is named by a
 *     `steps.<id>.outputs.<key>` expression;
 *   - every name a job lists under `outputs:` is named by a
 *     `needs.<job>.outputs.<name>` expression;
 *   - every step that writes an output has an `id`, because a step without
 *     one cannot be named by any expression at all.
 *
 * WHY THE PARSER IS HELD TO A COUNT. This file reads YAML with line
 * matching, so the way it fails is by reading less than is there: a write
 * spelled in a shape the matcher does not know is a declaration nobody
 * checks, and the file goes on reporting clean. So every line in a workflow
 * that mentions `$GITHUB_OUTPUT` has to be attributed to a key this reader
 * extracted. A new spelling then fails here rather than quietly leaving the
 * rule covering less of the tree than it did yesterday.
 *
 * No sockets, no database and no child process. It reads the workflow
 * files.
 *
 * Run standalone:
 * node test/layer-0-primitives/workflow-declared-outputs.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");

var count = helpers.count;

var WORKFLOW_DIR = nodePath.join(helpers.REPO_ROOT, ".github", "workflows");

// The shell variable a step writes an output through. Matched as text
// because that is how it appears in a `run:` block.
var OUTPUT_FILE_TOKEN = "$GITHUB_OUTPUT";

// One `key=value` or `key<<DELIMITER` write, as a step spells it. The
// second form is the multi-line one, and it declares the same key: a
// reader that knew only the first would treat every captured lint
// transcript in this tree as an unread output.
var OUTPUT_KEY = /^\s*(?:echo|printf)\s+["']?([A-Za-z_][A-Za-z0-9_-]*)(?:=|<<)/;

// ---------------------------------------------------------------------------
// Reading the workflows
// ---------------------------------------------------------------------------

function workflowFiles() {
  return nodeFs.readdirSync(WORKFLOW_DIR)
    .filter(function (f) { return /\.ya?ml$/.test(f); })
    .sort()
    .map(function (f) { return { name: f, text: nodeFs.readFileSync(nodePath.join(WORKFLOW_DIR, f), "utf8") }; });
}

// Every step output a file declares, with the step that owns it.
//
// The step is identified by the nearest `id:` above the write, which is
// what GitHub itself resolves the expression against. A write with no `id`
// above it inside the same step is reported with an empty owner rather than
// attributed to the previous step, because attributing it would invent a
// reader for it.
function declaredStepOutputs(text) {
  var lines      = text.split(/\r?\n/);
  var found      = [];
  var attributed = [];
  var stepId     = null;
  var blockKeys  = null;

  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];

    // A new step begins at a `- name:` or `- uses:` item, which is where
    // the previous step's id stops applying.
    if (/^\s*-\s+(?:name|uses):/.test(line)) stepId = null;
    var idAt = /^\s*id:\s*([A-Za-z0-9_-]+)\s*$/.exec(line);
    if (idAt) stepId = idAt[1];

    // A braced group collecting several writes, closed by one redirect.
    if (/^\s*\{\s*$/.test(line)) { blockKeys = []; continue; }
    if (blockKeys !== null) {
      if (line.indexOf(OUTPUT_FILE_TOKEN) !== -1 && /^\s*\}/.test(line)) {
        blockKeys.forEach(function (k) {
          found.push({ key: k.key, stepId: stepId, line: k.line });
        });
        attributed.push(i + 1);
        blockKeys = null;
        continue;
      }
      if (/^\s*\}/.test(line)) { blockKeys = null; continue; }
      var inBlock = OUTPUT_KEY.exec(line);
      if (inBlock) blockKeys.push({ key: inBlock[1], line: i + 1 });
      continue;
    }

    if (line.indexOf(OUTPUT_FILE_TOKEN) === -1) continue;
    var single = OUTPUT_KEY.exec(line);
    if (single) {
      found.push({ key: single[1], stepId: stepId, line: i + 1 });
      attributed.push(i + 1);
    }
  }
  return { outputs: found, attributedLines: attributed };
}

// Every line that writes to the output file, whether or not this reader
// understood it. The difference between this and the list above is the
// reader's blind spot, and the case below refuses to let one exist.
function outputWriteLines(text) {
  var lines = text.split(/\r?\n/);
  var at    = [];
  lines.forEach(function (line, i) {
    if (line.indexOf(OUTPUT_FILE_TOKEN) !== -1) at.push(i + 1);
  });
  return at;
}

// Every name a job publishes under `outputs:`, with the job that owns it.
// Job keys sit two levels under `jobs:`, and a job's `outputs:` block is
// four spaces in with its names six, which is the shape every workflow here
// is written in.
function declaredJobOutputs(text) {
  var lines  = text.split(/\r?\n/);
  var found  = [];
  var jobId  = null;
  var inJobs = false;
  var inOuts = false;

  lines.forEach(function (line, i) {
    if (/^jobs:\s*$/.test(line)) { inJobs = true; return; }
    if (!inJobs) return;
    if (/^\S/.test(line)) { inJobs = false; jobId = null; inOuts = false; return; }

    var jobAt = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (jobAt) { jobId = jobAt[1]; inOuts = false; return; }
    if (/^ {4}outputs:\s*$/.test(line)) { inOuts = true; return; }
    if (inOuts) {
      var nameAt = /^ {6}([A-Za-z0-9_-]+):/.exec(line);
      if (nameAt) { found.push({ key: nameAt[1], jobId: jobId, line: i + 1 }); return; }
      if (/^ {0,5}\S/.test(line)) inOuts = false;
    }
  });
  return found;
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

// The canary. Every claim below is a filter over what the reader found, so
// a reader that found nothing would satisfy all of them at once.
function theSweepFoundDeclarationsToCheck(files) {
  var steps = 0;
  var jobs  = 0;
  files.forEach(function (file) {
    steps += declaredStepOutputs(file.text).outputs.length;
    jobs  += declaredJobOutputs(file.text).length;
  });
  count("the workflow directory still holds files to read",
    files.length > 0, files.length + " file(s)");
  count("the sweep found step outputs, so what follows answers for them rather than " +
    "for an empty list",
  steps > 0, steps + " step output(s)");
  count("the sweep found job outputs too",
    jobs > 0, jobs + " job output(s)");
}

// The reader's own blind spot, refused. A write spelled in a shape the
// matcher above does not know is a declaration this file does not check,
// and nothing else in the tree checks it either.
function everyWriteLineWasRead(files) {
  var unread = [];
  files.forEach(function (file) {
    var read = declaredStepOutputs(file.text).attributedLines;
    outputWriteLines(file.text).forEach(function (at) {
      if (read.indexOf(at) === -1) unread.push(file.name + ":" + at);
    });
  });
  count("every line that writes a workflow output was read back as a named key, so this " +
    "file's coverage cannot shrink by someone spelling a write a new way",
  unread.length === 0, unread.join(" "));
}

// A step with no `id` cannot be named by any expression, so whatever it
// publishes is unreachable from the moment it is written.
function everyPublishingStepCanBeNamed(files) {
  var anonymous = [];
  files.forEach(function (file) {
    declaredStepOutputs(file.text).outputs.forEach(function (out) {
      if (!out.stepId) anonymous.push(file.name + ":" + out.line + " (" + out.key + ")");
    });
  });
  count("every step that publishes an output carries an id, so an expression can name it",
    anonymous.length === 0, anonymous.join(" "));
}

// The finding this file exists for, on the step side.
function everyStepOutputIsRead(files) {
  var unread = [];
  files.forEach(function (file) {
    declaredStepOutputs(file.text).outputs.forEach(function (out) {
      if (!out.stepId) return;   // reported by its own case above
      var reader = "steps." + out.stepId + ".outputs." + out.key;
      if (file.text.indexOf(reader) === -1) {
        unread.push(file.name + ":" + out.line + " " + reader);
      }
    });
  });
  count("every value a step publishes is read by an expression that names it, so no step " +
    "spends a run computing something nothing consumes",
  unread.length === 0, unread.join(" "));
}

// The same rule one level up. A job output is read from another job, so the
// whole directory is searched rather than the one file.
function everyJobOutputIsRead(files) {
  var everything = files.map(function (f) { return f.text; }).join("\n");
  var unread = [];
  files.forEach(function (file) {
    declaredJobOutputs(file.text).forEach(function (out) {
      var reader = "needs." + out.jobId + ".outputs." + out.key;
      if (everything.indexOf(reader) === -1) {
        unread.push(file.name + ":" + out.line + " " + reader);
      }
    });
  });
  count("every value a job publishes is read by a job that declares it in needs",
    unread.length === 0, unread.join(" "));
}

// The readers themselves, driven against sources written here, because
// every case above would pass on a reader that returned an empty list and
// on one that returned everything.
function theReadersFindAndMissTheRightLines() {
  var singleLine = [
    "    steps:",
    "      - name: Compute tags",
    "        id: tags",
    "        run: |",
    '          echo "semver=$REF" >> "$GITHUB_OUTPUT"',
    "",
  ].join("\n");
  var single = declaredStepOutputs(singleLine).outputs;
  count("a single-line write is read as one key owned by the step id above it",
    single.length === 1 && single[0].key === "semver" && single[0].stepId === "tags",
    JSON.stringify(single));

  var braced = [
    "      - name: Compute tags",
    "        id: tags",
    "        run: |",
    "          {",
    '            echo "semver=$REF"',
    '            echo "is_tag=true"',
    '          } >> "$GITHUB_OUTPUT"',
    "",
  ].join("\n");
  var block = declaredStepOutputs(braced).outputs;
  count("a braced group closed by one redirect is read as every key inside it",
    block.length === 2 && block[0].key === "semver" && block[1].key === "is_tag" &&
    block.every(function (b) { return b.stepId === "tags"; }),
    JSON.stringify(block));

  var multiline = [
    "      - name: Run ESLint",
    "        id: eslint",
    "        run: |",
    "          {",
    '            echo "output<<ESLINT_EOF"',
    '            echo "$OUTPUT"',
    '            echo "ESLINT_EOF"',
    '          } >> "$GITHUB_OUTPUT"',
    "",
  ].join("\n");
  var heredoc = declaredStepOutputs(multiline).outputs;
  count("a multi-line write declares its key once, and the content lines are not keys",
    heredoc.length === 1 && heredoc[0].key === "output", JSON.stringify(heredoc));

  var orphan = [
    "      - name: Detect shell scripts",
    "        run: |",
    '          echo "found=$count" >> "$GITHUB_OUTPUT"',
    "",
  ].join("\n");
  var noId = declaredStepOutputs(orphan).outputs;
  count("a write with no step id is reported with no owner rather than attributed upward",
    noId.length === 1 && noId[0].stepId === null, JSON.stringify(noId));

  var carried = [
    "      - name: Earlier step",
    "        id: earlier",
    "        run: echo hello",
    "      - name: Later step",
    "        run: |",
    '          echo "found=1" >> "$GITHUB_OUTPUT"',
    "",
  ].join("\n");
  count("an id belonging to an earlier step does not reach a later one",
    declaredStepOutputs(carried).outputs[0].stepId === null,
    JSON.stringify(declaredStepOutputs(carried).outputs));

  var jobsSource = [
    "jobs:",
    "  publish:",
    "    name: Build, scan, publish",
    "    outputs:",
    "      digest:  ${{ steps.push.outputs.digest }}",
    "      version: ${{ steps.tags.outputs.semver }}",
    "    steps:",
    "      - name: Checkout",
    "  smoke-test:",
    "    needs: publish",
    "",
  ].join("\n");
  var jobOuts = declaredJobOutputs(jobsSource);
  count("a job's published names are read with the job that owns them",
    jobOuts.length === 2 && jobOuts[0].jobId === "publish" && jobOuts[0].key === "digest" &&
    jobOuts[1].key === "version", JSON.stringify(jobOuts));
  count("a step key inside the job's outputs block is not read as a second job output",
    jobOuts.every(function (o) { return o.jobId === "publish"; }), JSON.stringify(jobOuts));

  count("a file that publishes nothing reads as no declarations rather than as one",
    declaredStepOutputs("jobs:\n  a:\n    steps:\n      - run: echo hi\n").outputs.length === 0 &&
    declaredJobOutputs("jobs:\n  a:\n    steps:\n      - run: echo hi\n").length === 0);
}

// ---------------------------------------------------------------------------

function run() {
  var files = workflowFiles();

  theSweepFoundDeclarationsToCheck(files);
  theReadersFindAndMissTheRightLines();

  everyWriteLineWasRead(files);
  everyPublishingStepCanBeNamed(files);
  everyStepOutputIsRead(files);
  everyJobOutputIsRead(files);

  return helpers.getChecks();
}

module.exports = { name: "workflow-declared-outputs", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
