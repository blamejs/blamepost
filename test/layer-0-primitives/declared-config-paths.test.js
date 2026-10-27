// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * declared-config-paths: every directory a configuration file points a tool
 * at has to exist in the repository the tool will read.
 *
 * The failure is silent on this side and loud on the other. `.github/
 * dependabot.yml` names a package ecosystem and a directory; Dependabot
 * clones the repository, looks for the manifest that ecosystem requires,
 * and aborts the run when it is not there. Nothing local says anything,
 * because every file involved is well formed. The only symptom is a job
 * that fails on its own schedule, in a place nobody watches between
 * releases.
 *
 * That is not hypothetical. The published commit declared an npm ecosystem
 * at `/fuzz` and carried no `fuzz/` directory, so the weekly job failed
 * with `dependency_file_not_found` every time it ran.
 *
 * TRACKED, NOT PRESENT ON DISK. This gate asks git what the repository
 * holds rather than asking the filesystem what this working tree holds.
 * The two answers differ for exactly the case that matters: a manifest
 * written but never added is on disk and invisible to every tool that
 * clones. Reading the filesystem here would report clean on the one tree
 * where the defect lives, which is the shape of gate this repository has
 * been bitten by before.
 *
 * `paths-ignore` in the CodeQL config is deliberately NOT checked. An
 * exclusion naming a directory that does not exist yet still excludes it
 * correctly on the day it appears, so absence there is a forward-looking
 * entry rather than a defect. `paths` is checked, because an analyzed path
 * that does not exist means the scanner reads less than the config claims.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/declared-config-paths.test.js`.
 */

var fs      = require("node:fs");
var path    = require("node:path");
var { execFileSync } = require("node:child_process");
var helpers = require("../helpers");
var check   = helpers.check;

var REPO_ROOT  = helpers.REPO_ROOT;
var DEPENDABOT = path.join(REPO_ROOT, ".github", "dependabot.yml");
var CODEQL     = path.join(REPO_ROOT, ".github", "codeql", "codeql-config.yml");

// The manifest each ecosystem requires at the directory it names. An
// ecosystem absent from this table is reported rather than skipped, so a
// new ecosystem in the config arrives as a finding here instead of passing
// unexamined.
var MANIFEST = {
  npm:               ["package.json"],
  docker:            ["Dockerfile"],
  "github-actions":  [".github/workflows"],
};

// Ask git, not the filesystem. `git ls-files` lists what is tracked in the
// index, which is what a clone receives.
// A git that cannot answer raises rather than reporting an empty list. An
// empty list here reads as "the manifest is not tracked", which would be a
// true failure carrying a false cause, and a gate that names the wrong
// cause costs more than one that does not run.
function trackedUnder(relPath) {
  var out;
  try {
    out = execFileSync("git", ["ls-files", "--", relPath],
      { cwd: REPO_ROOT, encoding: "utf8" });
  } catch (err) {
    throw new Error("declared-config-paths: `git ls-files` failed for " +
      relPath + ", so this gate cannot tell tracked from untracked: " +
      (err && err.message ? err.message : String(err)));
  }
  return out.split("\n").filter(function (line) { return line.trim() !== ""; });
}

// A narrow reader for the two shapes this file needs. Hand-reading a
// configuration format is fragile, so the count it produces is compared
// against a raw scan of the same file below: a format change that defeats
// the reader shows up as a disagreement rather than as an empty result.
function readEcosystems(text) {
  var entries = [];
  var current = null;
  text.split("\n").forEach(function (raw) {
    var line = raw.replace(/#.*$/, "");
    var eco = /^\s*-\s*package-ecosystem:\s*"?([^"\s]+)"?/.exec(line);
    if (eco) {
      if (current) entries.push(current);
      current = { ecosystem: eco[1], directory: null };
      return;
    }
    var dir = /^\s*directory:\s*"?([^"\s]+)"?/.exec(line);
    if (dir && current && current.directory === null) current.directory = dir[1];
  });
  if (current) entries.push(current);
  return entries;
}

function readCodeqlPaths(text) {
  var out = [];
  var inPaths = false;
  text.split("\n").forEach(function (raw) {
    var line = raw.replace(/#.*$/, "");
    if (/^paths:\s*$/.test(line)) { inPaths = true; return; }
    // Any other top-level key ends the block, `paths-ignore` included.
    if (/^\S/.test(line) && !/^paths:\s*$/.test(line)) { inPaths = false; return; }
    if (!inPaths) return;
    var item = /^\s*-\s*"?([^"\s]+)"?/.exec(line);
    if (item) out.push(item[1]);
  });
  return out;
}

async function run() {
  var depText = fs.readFileSync(DEPENDABOT, "utf8");
  var entries = readEcosystems(depText);

  // The reader is measured against the file before its output is trusted.
  var rawCount = (depText.match(/^\s*-\s*package-ecosystem:/gm) || []).length;
  check("dependabot: the reader found every declared ecosystem, read " +
    entries.length + " of " + rawCount,
    entries.length === rawCount);

  // Empty set refusal. A gate that examines nothing answers for nothing.
  check("dependabot: the config still declares at least one ecosystem to check",
    entries.length > 0);

  entries.forEach(function (entry) {
    var label = entry.ecosystem + " at " + entry.directory;

    check("dependabot: " + label + " names a directory",
      typeof entry.directory === "string" && entry.directory !== "");
    if (!entry.directory) return;

    var wanted = MANIFEST[entry.ecosystem];
    check("dependabot: " + label + " uses an ecosystem this gate knows the manifest for",
      Array.isArray(wanted));
    if (!Array.isArray(wanted)) return;

    var dir = entry.directory.replace(/^\/+/, "").replace(/\/+$/, "");
    wanted.forEach(function (manifest) {
      var target = dir === "" ? manifest : dir + "/" + manifest;
      var found  = trackedUnder(target);
      check("dependabot: " + label + " has " + target +
        " tracked in git, so a clone can find it (tracked files: " + found.length + ")",
        found.length > 0);
    });
  });

  var qlText  = fs.readFileSync(CODEQL, "utf8");
  var qlPaths = readCodeqlPaths(qlText);

  check("codeql: the config still declares at least one analyzed path",
    qlPaths.length > 0);

  qlPaths.forEach(function (p) {
    var found = trackedUnder(p);
    check("codeql: the analyzed path " + p +
      " is tracked in git, so the scanner reads it (tracked files: " + found.length + ")",
      found.length > 0);
  });

  // The readers themselves, driven over synthetic text carrying one defect
  // each. These are what prove the checks above can fail, without touching
  // the tree to do it.
  var missingManifest = readEcosystems([
    'version: 2',
    'updates:',
    '  - package-ecosystem: "npm"',
    '    directory: "/nowhere-at-all"',
    '    schedule:',
    '      interval: "weekly"',
  ].join("\n"));
  check("reader: a declared ecosystem is read back with its directory",
    missingManifest.length === 1 &&
    missingManifest[0].ecosystem === "npm" &&
    missingManifest[0].directory === "/nowhere-at-all");
  check("reader: the directory that ecosystem names is not tracked, " +
    "which is the shape this gate exists to refuse",
    trackedUnder("nowhere-at-all/package.json").length === 0);

  var twoEntries = readEcosystems([
    '  - package-ecosystem: "npm"',
    '    directory: "/"',
    '  - package-ecosystem: "docker"',
    '    directory: "/sub"',
  ].join("\n"));
  check("reader: two ecosystems are read as two entries, not merged",
    twoEntries.length === 2 &&
    twoEntries[1].ecosystem === "docker" &&
    twoEntries[1].directory === "/sub");

  var commented = readEcosystems([
    '  # - package-ecosystem: "npm"',
    '  - package-ecosystem: "docker"',
    '    directory: "/"',
  ].join("\n"));
  check("reader: a commented-out ecosystem is not counted as declared",
    commented.length === 1 && commented[0].ecosystem === "docker");

  var qlSample = readCodeqlPaths([
    'queries:',
    '  - uses: security-extended',
    '',
    'paths:',
    '  - lib',
    '  - bin',
    '',
    'paths-ignore:',
    '  - lib/vendor',
  ].join("\n"));
  check("reader: the analyzed paths are read without absorbing paths-ignore, read " +
    JSON.stringify(qlSample),
    qlSample.length === 2 && qlSample[0] === "lib" && qlSample[1] === "bin");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
