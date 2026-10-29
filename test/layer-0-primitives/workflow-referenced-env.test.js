// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * Every environment variable a workflow step reads is one something sets.
 *
 * A shell reading an unset variable does not fail. It substitutes the
 * empty string, and where the read is guarded the guard takes the branch
 * written for "nothing here". So a step that reads a name nobody sets
 * runs green forever and answers with nothing, which is the shape that
 * survives longest: no error, no log line, and a value downstream that
 * is always empty.
 *
 * This is not hypothetical here. `ci.yml` captured the Dockerfile
 * linter's findings out of `HADOLINT_RESULTS`, a name set nowhere in the
 * repository. The guard on it always took the empty branch, the `else`
 * that formats the findings was unreachable, and the job output feeding
 * the pull-request lint comment was always the empty string. The linter
 * itself worked the whole time and failed the job correctly on a
 * finding, so nothing was red and the comment simply never carried what
 * it was written to carry.
 *
 * A behavioral test cannot ask this question: these steps only run on a
 * GitHub runner, and the failure is an empty string rather than an
 * error, so even there it would take an assertion on the rendered
 * comment to see it. That is what §3 reserves a structural detector for.
 *
 * WHAT IT READS. Inside every `run:` block, every `$NAME` and
 * `${NAME}` and `${NAME:-default}` whose name is env-var shaped. A name
 * counts as set when the same `run:` block assigned it earlier, when the
 * step, job or workflow declares it under `env:`, or when the runner
 * provides it.
 *
 * WHAT IT DOES NOT READ. Lower-case names, because a shell script's own
 * locals are ordinarily spelled that way here and are assigned before
 * use in the same block. Positional parameters and `$?`, `$!`, `$$`.
 * Anything inside a `${{ }}` expression, which GitHub substitutes before
 * the shell ever sees it.
 *
 * Run standalone: node test/layer-0-primitives/workflow-referenced-env.test.js
 */

"use strict";

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");

var count = helpers.count;
var check = helpers.check;

var WORKFLOW_DIR = nodePath.join(helpers.REPO_ROOT, ".github", "workflows");

// What a runner puts in the environment of every step, so a read of one
// is answered whether or not the workflow mentions it. GitHub documents
// the first group; the rest are ordinary POSIX and container names.
var PROVIDED = Object.freeze([
  "CI", "HOME", "PATH", "PWD", "SHELL", "TERM", "USER", "LANG", "LC_ALL", "TMPDIR",
  "GITHUB_ACTION", "GITHUB_ACTIONS", "GITHUB_ACTOR", "GITHUB_API_URL", "GITHUB_BASE_REF",
  "GITHUB_ENV", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_HEAD_REF",
  "GITHUB_JOB", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_REF", "GITHUB_REF_NAME",
  "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_ID",
  "GITHUB_RUN_NUMBER", "GITHUB_SERVER_URL", "GITHUB_SHA", "GITHUB_STEP_SUMMARY",
  "GITHUB_TOKEN", "GITHUB_WORKFLOW", "GITHUB_WORKSPACE",
  "RUNNER_ARCH", "RUNNER_DEBUG", "RUNNER_NAME", "RUNNER_OS", "RUNNER_TEMP",
  "RUNNER_TOOL_CACHE",
]);

// An env-var shaped name: upper case, digits and underscores, not
// starting with a digit. A shell local spelled in lower case is left
// alone, because those are assigned in the same block by convention here
// and a reader that flagged them would report the whole file.
var REFERENCE = /\$\{?([A-Z][A-Z0-9_]*)(?::-[^}]*)?\}?/g;

// `NAME=value` and `export NAME=value` and `read NAME`, which is how a
// block sets a name for its own later lines.
var ASSIGNMENT = /(?:^|\s|;|&&|\|\||\()\s*(?:export\s+|declare\s+-\w+\s+)?([A-Z][A-Z0-9_]*)=/;
var READ_INTO = /^\s*(?:read|mapfile|readarray)\s+(?:-\w+\s+)*([A-Z][A-Z0-9_]*)/;

var FILES_EXAMINED = 0;
var REFERENCES_EXAMINED = 0;

function workflowFiles() {
  return nodeFs.readdirSync(WORKFLOW_DIR)
    .filter(function (f) { return f.endsWith(".yml") || f.endsWith(".yaml"); })
    .sort()
    .map(function (f) {
      return { name: f, text: nodeFs.readFileSync(nodePath.join(WORKFLOW_DIR, f), "utf8") };
    });
}

function indentOf(line) {
  var m = /^(\s*)/.exec(line);
  return m[1].length;
}

// Every name any `env:` block in the file declares, with the line it sits
// on. Scope is not tracked: a name declared for one step and read by
// another is a different fault from the one this file is about, and
// treating the file's declarations as one set keeps this from reporting
// it as this one.
function declaredEnvNames(text) {
  var lines = text.split("\n");
  var names = Object.create(null);
  var inEnv = false;
  var envIndent = -1;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (/^\s*#/.test(line)) continue;
    if (/^\s*env:\s*$/.test(line)) {
      inEnv = true;
      envIndent = indentOf(line);
      continue;
    }
    if (!inEnv) continue;
    if (line.trim().length === 0) continue;
    if (indentOf(line) <= envIndent) { inEnv = false; continue; }
    var m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:/.exec(line);
    if (m) names[m[1]] = i + 1;
  }
  return names;
}

// Each `run:` block as its own lines, with the file line each began on.
function runBlocks(text) {
  var lines = text.split("\n");
  var blocks = [];
  for (var i = 0; i < lines.length; i += 1) {
    var m = /^(\s*)run:\s*\|?/.exec(lines[i]);
    if (!m) continue;
    var runIndent = m[1].length;
    var body = [];
    var j = i + 1;
    for (; j < lines.length; j += 1) {
      if (lines[j].trim().length === 0) { body.push({ text: "", line: j + 1 }); continue; }
      if (indentOf(lines[j]) <= runIndent) break;
      body.push({ text: lines[j], line: j + 1 });
    }
    blocks.push({ start: i + 1, body: body });
    i = j - 1;
  }
  return blocks;
}

// A GitHub expression is substituted before the shell runs, so a `$NAME`
// inside one is not a shell read.
function withoutExpressions(line) {
  return line.replace(/\$\{\{[\s\S]*?\}\}/g, " ");
}

function unsetReferences(files) {
  var findings = [];
  files.forEach(function (file) {
    FILES_EXAMINED += 1;
    var declared = declaredEnvNames(file.text);
    runBlocks(file.text).forEach(function (block) {
      var assigned = Object.create(null);
      block.body.forEach(function (entry) {
        var line = withoutExpressions(entry.text);
        if (/^\s*#/.test(line)) return;

        var a = ASSIGNMENT.exec(line);
        if (a) assigned[a[1]] = true;
        var r = READ_INTO.exec(line);
        if (r) assigned[r[1]] = true;
        // `for NAME in ...` binds the name for the rest of the block.
        var f = /^\s*for\s+([A-Z][A-Z0-9_]*)\s+in\s/.exec(line);
        if (f) assigned[f[1]] = true;

        REFERENCE.lastIndex = 0;
        var m;
        while ((m = REFERENCE.exec(line)) !== null) {
          var name = m[1];
          REFERENCES_EXAMINED += 1;
          if (assigned[name]) continue;
          if (declared[name] !== undefined) continue;
          if (PROVIDED.indexOf(name) !== -1) continue;
          findings.push(file.name + ":" + entry.line + " reads $" + name +
            ", which nothing in this workflow sets");
        }
      });
    });
  });
  return findings;
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

function theSweepReachedSomething(files) {
  count("the sweep found workflow files to read", files.length > 0, String(files.length));
  var blocks = files.reduce(function (n, f) { return n + runBlocks(f.text).length; }, 0);
  count("and run blocks inside them", blocks > 0, String(blocks));
}

function noStepReadsANameNothingSets(files) {
  var findings = unsetReferences(files);
  count("no workflow step reads an environment variable nothing sets, because a shell " +
    "answers one with the empty string and takes the branch written for nothing",
    findings.length === 0, findings.join("; ").slice(0, 600));
}

// The reader has to find the fault and leave the ordinary shapes alone,
// proven on written-out text rather than on the tree, so the proof holds
// when the tree changes.
function theReaderFindsAndMissesTheRightLines() {
  var bad = {
    name: "fixture-bad.yml",
    text: [
      "jobs:",
      "  a:",
      "    steps:",
      "      - name: Capture",
      "        run: |",
      "          if [ -z \"${NEVER_SET_ANYWHERE:-}\" ]; then",
      "            echo empty",
      "          fi",
      "",
    ].join("\n"),
  };
  var found = unsetReferences([bad]);
  count("the reader reports a name nothing sets", found.length === 1, found.join("; "));
  check("and names the line it sits on", found.length === 1 && found[0].indexOf(":6 ") !== -1);

  var good = [
    { label: "a name the step declares under env",
      text: ["jobs:", "  a:", "    steps:", "      - name: S", "        env:",
        "          MY_VALUE: x", "        run: |", "          echo \"$MY_VALUE\"", ""].join("\n") },
    { label: "a name the block assigns first",
      text: ["jobs:", "  a:", "    steps:", "      - name: S", "        run: |",
        "          MY_VALUE=$(date)", "          echo \"$MY_VALUE\"", ""].join("\n") },
    { label: "a name the runner provides",
      text: ["jobs:", "  a:", "    steps:", "      - name: S", "        run: |",
        "          echo x >> \"$GITHUB_OUTPUT\"", ""].join("\n") },
    { label: "a name inside a GitHub expression",
      text: ["jobs:", "  a:", "    steps:", "      - name: S", "        run: |",
        "          echo \"${{ steps.x.outputs.$NOT_A_SHELL_READ }}\"", ""].join("\n") },
    { label: "a loop variable",
      text: ["jobs:", "  a:", "    steps:", "      - name: S", "        run: |",
        "          for F in a b; do echo \"$F\"; done", ""].join("\n") },
    { label: "an exported name",
      text: ["jobs:", "  a:", "    steps:", "      - name: S", "        run: |",
        "          export MY_VALUE=1", "          echo \"$MY_VALUE\"", ""].join("\n") },
  ];
  good.forEach(function (g) {
    var out = unsetReferences([{ name: "fixture-good.yml", text: g.text }]);
    count("the reader leaves " + g.label + " alone", out.length === 0, out.join("; "));
  });
}

// ---------------------------------------------------------------------------

function run() {
  var files = workflowFiles();
  theSweepReachedSomething(files);
  noStepReadsANameNothingSets(files);
  theReaderFindsAndMissesTheRightLines();

  console.log("EXAMINED " + FILES_EXAMINED + " workflow-files");
  console.log("EXAMINED " + REFERENCES_EXAMINED + " env-references");
  return helpers.getChecks();
}

module.exports = {
  name:      "workflow-referenced-env",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
