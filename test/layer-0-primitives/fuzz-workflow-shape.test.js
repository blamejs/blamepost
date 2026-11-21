// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * The fuzz workflows keep every input libFuzzer writes when it stops a run,
 * and set a memory ceiling the instrumented harnesses fit under.
 *
 * libFuzzer names the input that stopped a run by why it stopped:
 * `crash-<hash>`, `leak-<hash>`, `timeout-<hash>` or `oom-<hash>`. The
 * upload step keeps only the prefixes it lists, so a prefix it leaves out
 * is a stop whose input is discarded and cannot be replayed.
 *
 * jazzer instruments every module a harness loads, including the vendored
 * framework, and a harness that composes it is already near 2.5 GB resident
 * before the first input runs. libFuzzer's default ceiling is 2048 MB, so
 * the run is refused as out of memory on its baseline rather than on any
 * input. Each jazzer invocation therefore passes `-rss_limit_mb`, set at or
 * above 4096.
 *
 * These steps run only on a GitHub runner, so this reads the workflow text.
 *
 * Run standalone: node test/layer-0-primitives/fuzz-workflow-shape.test.js
 */

"use strict";

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");

var check = helpers.check;

var WORKFLOWS = ["cflite_batch.yml", "cflite_pr.yml"];
var ARTIFACT_PREFIXES = ["crash-", "leak-", "timeout-", "oom-"];
var MIN_RSS_LIMIT_MB = 4096;

function read(name) {
  return nodeFs.readFileSync(nodePath.join(helpers.REPO_ROOT, ".github", "workflows", name), "utf8")
    .replace(/\r\n/g, "\n");
}

// The `path:` list of each upload-artifact step, as the entries it names.
function uploadPathLists(text) {
  var lists = [];
  var re = /^(\s*)path:\s*\|\s*\n((?:\1\s+\S.*\n?)+)/gm;
  var m;
  while ((m = re.exec(text)) !== null) {
    lists.push(m[2].split("\n").map(function (l) { return l.trim(); }).filter(Boolean));
  }
  return lists;
}

function run() {
  WORKFLOWS.forEach(function (name) {
    var text = read(name);

    var invocations = text.match(/npx --prefix fuzz jazzer\b/g) || [];
    check(name + " invokes jazzer at least once", invocations.length > 0);

    var crashLists = uploadPathLists(text).filter(function (l) {
      return l.some(function (e) { return e.indexOf("crash-") === 0; });
    });
    check(name + " has an upload step for the inputs libFuzzer writes", crashLists.length > 0);
    crashLists.forEach(function (list) {
      ARTIFACT_PREFIXES.forEach(function (p) {
        check(name + ": the artifact upload keeps " + p + "* inputs (lists: " + list.join(", ") + ")",
          list.some(function (e) { return e.indexOf(p) === 0; }));
      });
    });

    var args = /libfuzzer_args=\(([^)]*)\)/.exec(text);
    check(name + " builds a libfuzzer_args list", args !== null);
    var rss = args ? /-rss_limit_mb=(\d+)/.exec(args[1]) : null;
    check(name + ": libfuzzer_args sets -rss_limit_mb to at least " + MIN_RSS_LIMIT_MB +
      " (found " + (rss ? rss[1] : "none") + ")", rss !== null && Number(rss[1]) >= MIN_RSS_LIMIT_MB);
  });

  console.log("EXAMINED " + WORKFLOWS.length + " fuzz-workflows");
  return helpers.getChecks();
}

module.exports = {
  name:      "fuzz-workflow-shape",
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
