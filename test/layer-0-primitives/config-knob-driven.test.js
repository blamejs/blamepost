// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * config-knob-driven: a setting the loader declares is a setting some
 * test writes.
 *
 * test/layer-0-primitives/config-knob-reach.test.js asks whether a
 * declared setting is READ by a module that acts on it. This file asks
 * the other half: whether any test ever WRITES the variable an operator
 * writes. Neither question implies the other. A setting can be read on
 * every request and still have no test that sets it, and a value read
 * into a binding can be read in the one position where both answers
 * agree.
 *
 * The shape this refuses is a branch that exists for one position of a
 * setting and is driven only in the other. `publicSiteEnabled` is the
 * worked example. The root of the browser port lays the environment's
 * value under the operator's stored answer, so with no stored row the
 * environment decides whether the public page is served. Every file that
 * published the page did it by writing the stored row, and none named
 * the variable, so the branch reading the environment was exercised in
 * its off position only. Writing that branch to answer off outright
 * would have left every one of those runs green while a fresh volume
 * that asked for the page met the sign-in redirect instead.
 *
 * That is not a bug a behavioral test can report about itself. Each file
 * involved passed, and what was missing was a vector none of them owed.
 * The question is a property of the test directory rather than of any
 * one file in it, which is why it is asked here.
 *
 * WHAT COUNTS AS DRIVING IT. The setting's environment variable name,
 * appearing on a line of code in a file under `test/`. The name is the
 * string an operator types into their container, so it is a frozen
 * contract rather than a symbol anybody may rename: it survives every
 * refactor of the loader and disappears only when the setting does.
 *
 * Comment text is not code. A full-line comment is dropped and a
 * trailing comment is cut off the end of a code line, so a variable
 * named in the sentence above a fixture does not count as a fixture
 * driving it. That reader is imported from config-knob-reach rather than
 * copied, because two gates with their own idea of what a comment is
 * would disagree about the same line.
 *
 * WHERE THE TABLE COMES FROM. `config.SETTINGS`, which is what the
 * loader publishes. A reader that recovered the names by matching the
 * loader's source text instead would answer for the rows whose spelling
 * it happened to match: that reading of the same table missed
 * `BLAMEPOST_LISTENERS`, and a gate built on it would have reported a
 * covered tree while leaving one row unasked.
 *
 * COUNTS. Three, because they fail independently. `declared-settings` is
 * what the loader publishes, `test-files-read` is what the directory
 * walk found, and `driving-mentions-found` is what the reader matched. A
 * reader that stopped matching takes the third to zero while the first
 * two stay healthy; a walk resolved against a wrong directory takes the
 * second to zero while the reader still returns a clean verdict over
 * nothing. Zero in any of the three is refused.
 *
 * No sockets, no database, no network. It reads source text, and the
 * reader's own vectors are source strings rather than files.
 *
 * Run standalone:
 * node test/layer-0-primitives/config-knob-driven.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;
var count   = helpers.count;
var config  = require("../../lib/config");

// One reader for what a line of source says, shared with the gate that
// asks the other half of this question.
var codeOn = require("./config-knob-reach.test.js").codeOn;

var REPO_ROOT = helpers.REPO_ROOT;

// The tree a fixture lives in.
var TEST_ROOT = "test";

// This file's own source, which is read by nothing here.
//
// The vectors below drive the reader over strings that spell real
// variable names, and those lines are under `test/` like any other. A
// walk that read them would find every name it was looking for in the
// gate that was looking, and report a covered tree on the strength of
// its own text: the setting this gate was written for is one of the
// names quoted below, so the first run would have passed while nothing
// outside this file drove it. The exclusion is refuted by
// `theExclusionIsLiveAndStillEarned` rather than trusted.
var NOT_A_FIXTURE = TEST_ROOT + "/layer-0-primitives/config-knob-driven.test.js";

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

// Every file under `dir`, as a repository-relative path plus its text.
// Every extension is read rather than `.js` alone, because a fixture may
// state a variable in a compose file or a shell script beside the test
// that runs it, and a reader that skipped those would report a covered
// setting as uncovered.
function testFiles(dir, rel, out) {
  nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    var full = nodePath.join(dir, entry.name);
    var here = rel === "" ? entry.name : rel + "/" + entry.name;
    if (entry.isDirectory()) { testFiles(full, here, out); return; }
    if (!entry.isFile()) return;
    out.push({ path: here, text: nodeFs.readFileSync(full, "utf8") });
  });
  return out;
}

// Where each environment variable is written, as `path:line`. Exported
// so the vectors below can drive it over source strings rather than over
// files.
function mentionsIn(files, names) {
  var found = {};
  names.forEach(function (name) { found[name] = []; });
  files.forEach(function (file) {
    var lines = file.text.split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      var code = codeOn(lines[i]);
      if (code === "") continue;
      for (var n = 0; n < names.length; n += 1) {
        if (code.indexOf(names[n]) !== -1) found[names[n]].push(file.path + ":" + (i + 1));
      }
    }
  });
  return found;
}

function drivenSettings(opts) {
  var dir = nodePath.join(opts.root, TEST_ROOT);
  var walked = nodeFs.existsSync(dir) ? testFiles(dir, TEST_ROOT, []) : [];
  var files = walked.filter(function (file) { return file.path !== NOT_A_FIXTURE; });
  var names = config.SETTINGS.map(function (s) { return s.env; });
  var mentions = mentionsIn(files, names);
  var total = 0;
  names.forEach(function (name) { total += mentions[name].length; });
  return { files: files, walked: walked, names: names, mentions: mentions, total: total };
}

// ---------------------------------------------------------------------------
// The reader, driven over source strings
// ---------------------------------------------------------------------------

function theReaderReadsCodeAndNotProse() {
  var found = mentionsIn([{
    path: "test/vector.js",
    text: [
      "// BLAMEPOST_HOSTNAME is the public MX name.",
      " * BLAMEPOST_DATA_DIR names the volume.",
      "var env = { BLAMEPOST_HTTP_PORT: \"8080\" };",
      "var other = 1; // BLAMEPOST_LOG_LEVEL is set elsewhere",
    ].join("\n"),
  }], ["BLAMEPOST_HOSTNAME", "BLAMEPOST_DATA_DIR", "BLAMEPOST_HTTP_PORT", "BLAMEPOST_LOG_LEVEL"]);

  count("a variable named in a full-line comment is not a fixture driving it",
    found.BLAMEPOST_HOSTNAME.length === 0, found.BLAMEPOST_HOSTNAME.join(", "));
  count("and neither is one named in a block comment",
    found.BLAMEPOST_DATA_DIR.length === 0, found.BLAMEPOST_DATA_DIR.join(", "));
  count("a variable written into an environment map is found, with the line it is on",
    found.BLAMEPOST_HTTP_PORT.length === 1 &&
    found.BLAMEPOST_HTTP_PORT[0] === "test/vector.js:3",
    found.BLAMEPOST_HTTP_PORT.join(", "));
  count("and a trailing comment on a line of code is cut off rather than read",
    found.BLAMEPOST_LOG_LEVEL.length === 0, found.BLAMEPOST_LOG_LEVEL.join(", "));
}

function aSettingNoTestDrivesIsNamed() {
  var found = mentionsIn([{
    path: "test/vector.js",
    text: "var env = { BLAMEPOST_HOSTNAME: \"mx.example.com\" };",
  }], ["BLAMEPOST_HOSTNAME", "BLAMEPOST_PUBLIC_SITE_ENABLED"]);

  count("the reader reports a variable no line of the tree writes",
    found.BLAMEPOST_PUBLIC_SITE_ENABLED.length === 0,
    found.BLAMEPOST_PUBLIC_SITE_ENABLED.join(", "));
  count("while the one on the line beside it is still found",
    found.BLAMEPOST_HOSTNAME.length === 1, found.BLAMEPOST_HOSTNAME.join(", "));
}

// The walk reads the whole tree, including the directories a wire test
// keeps its fixtures in. A walk that stopped at the top would answer for
// the runner and nothing under it.
function theWalkReachesEveryLayer(report) {
  var layers = ["test/layer-0-primitives", "test/layer-1-state", "test/layer-2-integration",
    "test/helpers"];
  layers.forEach(function (layer) {
    var reached = report.files.filter(function (file) {
      return file.path.indexOf(layer + "/") === 0;
    }).length;
    count("the walk read the files under " + layer, reached > 0, reached);
  });
}

function aWalkThatReadNothingIsRefused(report) {
  count("the loader still publishes settings to ask about",
    report.names.length > 0, report.names.length);
  count("the walk still found test files to read",
    report.files.length > 0, report.files.length);
  count("and the reader still matched variables, rather than answering clean over nothing",
    report.total > 0, report.total);
}

function everySettingIsDrivenByATest(report) {
  var undriven = [];
  config.SETTINGS.forEach(function (setting) {
    if (report.mentions[setting.env].length === 0) {
      undriven.push(setting.key + " (" + setting.env + ")");
    }
  });

  count("every setting the loader declares is written by at least one test, so both " +
    "positions of the value are reachable from a fixture. A setting named here is one " +
    "no run ever sets: the code that reads it may be correct, and a run that changed it " +
    "to answer one way always would report exactly the same verdict it reports now",
    undriven.length === 0, undriven.join(", "), { limit: 2000 });

  // The sites are published per setting on a passing run as well, so a
  // reviewer can see WHERE each one is driven rather than only that it is.
  config.SETTINGS.forEach(function (setting) {
    var sites = report.mentions[setting.env];
    if (sites.length === 0) return;
    count(setting.env + " is written at " + sites.slice(0, 2).join(", ") +
      (sites.length > 2 ? " and " + (sites.length - 2) + " more" : ""),
      sites.length > 0, sites.length);
  });
}

// The exclusion above is held to both edges. A path that no longer names
// a file leaves the walk reading everything while a line here says
// otherwise, and an excluded file that stopped quoting variable names is
// an exclusion standing over nothing.
function theExclusionIsLiveAndStillEarned(report) {
  var excluded = report.walked.filter(function (file) { return file.path === NOT_A_FIXTURE; });
  count("the excluded path names a file the walk actually found",
    excluded.length === 1, excluded.length + " matches for " + NOT_A_FIXTURE);
  count("and the reader was handed the tree with that file taken out of it",
    report.files.length === report.walked.length - excluded.length,
    report.files.length + " of " + report.walked.length);
  if (excluded.length !== 1) return;

  var quoted = mentionsIn(excluded, report.names);
  var spelled = report.names.filter(function (name) { return quoted[name].length > 0; });
  count("the excluded file still spells declared variable names in its own vectors, which " +
    "is what it is excluded for",
    spelled.length > 0, spelled.join(", "));
}

// The table is taken from the loader rather than recovered from its text,
// so a row whose spelling a reader did not anticipate is still asked
// about. Refuted here rather than asserted in the header.
function theTableComesFromTheLoader(report) {
  check("every declared setting carries an environment variable name",
    config.SETTINGS.every(function (s) { return typeof s.env === "string" && s.env.length > 0; }));
  count("the names asked about are the loader's own rows, one for one",
    report.names.length === config.SETTINGS.length,
    report.names.length + " against " + config.SETTINGS.length);

  var unique = {};
  report.names.forEach(function (name) { unique[name] = true; });
  count("and no two settings share one variable, which would hide the second behind the first",
    Object.keys(unique).length === report.names.length,
    Object.keys(unique).length + " against " + report.names.length);

  // The reader matches a name anywhere on the line, so a name contained
  // in a longer one would be credited to every line writing the longer
  // one. Nothing outside this file would say so: the shorter setting
  // would read as driven on the strength of a fixture that never
  // mentions it.
  var contained = [];
  report.names.forEach(function (outer) {
    report.names.forEach(function (inner) {
      if (inner !== outer && outer.indexOf(inner) !== -1) {
        contained.push(inner + " inside " + outer);
      }
    });
  });
  count("and no variable name is contained in another, which the reader would credit to " +
    "the wrong setting. Two names in that relation need a reader matching a whole token " +
    "rather than a substring",
    contained.length === 0, contained.join(", "));
}

// ---------------------------------------------------------------------------

function run() {
  var report = drivenSettings({ root: REPO_ROOT });

  // Published first, so the run says what it looked at whether the
  // assertions below pass or fail.
  console.log("EXAMINED " + report.names.length + " declared-settings");
  console.log("EXAMINED " + report.files.length + " test-files-read");
  console.log("EXAMINED " + report.total + " driving-mentions-found");

  theReaderReadsCodeAndNotProse();
  aSettingNoTestDrivesIsNamed();

  aWalkThatReadNothingIsRefused(report);
  theWalkReachesEveryLayer(report);
  theExclusionIsLiveAndStillEarned(report);
  theTableComesFromTheLoader(report);
  everySettingIsDrivenByATest(report);

  return helpers.getChecks();
}

module.exports = {
  name:           "config-knob-driven",
  run:            run,
  getChecks:      helpers.getChecks,
  drivenSettings: drivenSettings,
  mentionsIn:     mentionsIn,
};

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
