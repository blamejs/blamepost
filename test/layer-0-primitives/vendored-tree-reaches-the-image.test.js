// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Every file the vendored manifest hashes still reaches the build context.
 *
 * `lib/vendor/MANIFEST.json` records a hash over the vendored tree and
 * `scripts/check-vendor-integrity.js` re-hashes the tree on disk against
 * it. Both run on the host. Neither answers the question the image asks,
 * which is whether the tree that ships is the tree that was hashed.
 *
 * `.dockerignore` is what can separate them. Its patterns are written for
 * a source tree, and several of them name shapes that appear in ordinary
 * library code: a `test` directory, a `.crt` fixture, a `.key` sample, a
 * `.log` example. A refresh that brings one of those in would leave the
 * image holding a tree the manifest does not describe, and the integrity
 * gate would keep passing, because it reads the host.
 *
 * There is one exclusion the tree already trips, and the repository
 * already handles it: `**` slash `*.pem` would take the vendored trust
 * anchors, and the last line of `.dockerignore` puts them back. That
 * negation is why this file parses the patterns rather than listing
 * them: a check carrying its own copy of the rules would have to be kept
 * in step with the file it is checking, and the copy that drifts is the
 * one nobody reads.
 *
 * This is the static half of the question. The other half, re-hashing
 * inside a built image, needs a container engine, and a check that can be
 * skipped is not the one to rest a supply-chain claim on.
 *
 * Run standalone: node test/layer-0-primitives/vendored-tree-reaches-the-image.test.js
 */

var helpers = require("../helpers");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var ROOT          = helpers.REPO_ROOT;
var DOCKERIGNORE  = path.join(ROOT, ".dockerignore");
var VENDOR_DIR    = path.join(ROOT, "lib", "vendor");

// The two units this file examines, published so a run that read an empty
// tree cannot report the same clean verdict as one that read the whole of
// it.
var _filesScanned    = 0;
var _patternsApplied = 0;

/**
 * Read `.dockerignore` into exclusions and re-inclusions.
 *
 * Only the forms this repository actually uses are interpreted, and any
 * line that is not one of them is reported rather than ignored: a pattern
 * this cannot read is a pattern this cannot check, and passing over it
 * silently is how a gate comes to answer for less than it claims.
 */
function readDockerignore() {
  var text = fs.readFileSync(DOCKERIGNORE, "utf8");
  var exclude = [];
  var include = [];
  var unreadable = [];

  text.split("\n").forEach(function (raw) {
    var line = raw.trim();
    if (line === "" || line.indexOf("#") === 0) return;
    var negated = line.indexOf("!") === 0;
    var body = negated ? line.slice(1) : line;

    var rule = null;
    if (body.indexOf("**/") === 0) {
      var rest = body.slice(3);
      if (rest.indexOf("*.") === 0) rule = { kind: "suffix", value: rest.slice(1) };
      else if (rest.indexOf("*") === -1) rule = { kind: "basename", value: rest };
      else if (/^[A-Za-z0-9_.-]+\*$/.test(rest)) {
        rule = { kind: "prefix", value: rest.slice(0, -1) };
      }
    } else if (/^lib\/vendor\/\*\*\/\*\.[A-Za-z0-9]+$/.test(body)) {
      rule = { kind: "vendorSuffix", value: body.slice(body.lastIndexOf(".")) };
    }

    if (rule === null) { unreadable.push(line); return; }
    (negated ? include : exclude).push(rule);
  });

  return { exclude: exclude, include: include, unreadable: unreadable };
}

// Does one rule take this path? `relative` is repository-relative with
// forward slashes; `base` is the file or directory name on its own.
function rulesTake(rule, relative, base) {
  if (rule.kind === "suffix")       return base.length > rule.value.length && base.endsWith(rule.value);
  if (rule.kind === "basename")     return base === rule.value;
  if (rule.kind === "prefix")       return base.indexOf(rule.value) === 0;
  if (rule.kind === "vendorSuffix") {
    return relative.indexOf("lib/vendor/") === 0 && base.endsWith(rule.value);
  }
  return false;
}

// Every path under the vendored tree that an exclusion takes and no
// re-inclusion puts back.
function strippedFromContext(rules) {
  var stripped = [];

  function walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_e) { return; }
    entries.forEach(function (entry) {
      var full     = path.join(dir, entry.name);
      var relative = path.relative(ROOT, full).split(path.sep).join("/");

      var taken = rules.exclude.filter(function (rule) {
        return rulesTake(rule, relative, entry.name);
      })[0];
      var putBack = taken !== undefined && rules.include.some(function (rule) {
        return rulesTake(rule, relative, entry.name);
      });

      if (taken !== undefined && !putBack) {
        stripped.push(relative + (entry.isDirectory() ? "/" : "") +
          "  (" + taken.kind + " " + taken.value + ")");
      }

      if (entry.isDirectory()) { walk(full); return; }
      _filesScanned += 1;
    });
  }

  walk(VENDOR_DIR);
  return stripped;
}

// ---------------------------------------------------------------------------

async function run() {
  count("the build context's exclusion list is readable at all",
    fs.existsSync(DOCKERIGNORE), DOCKERIGNORE);

  var rules = readDockerignore();
  _patternsApplied = rules.exclude.length + rules.include.length;

  // A pattern shape this file cannot interpret is reported rather than
  // passed over, because an unread pattern is coverage this claims and
  // does not have.
  count("every pattern in the exclusion list is one this check can apply",
    rules.unreadable.length === 0, rules.unreadable.join(" ; "));

  count("the exclusion list was actually parsed, rather than read as empty",
    rules.exclude.length >= 10,
    rules.exclude.length + " exclusion(s), " + rules.include.length + " re-inclusion(s)");

  var stripped = strippedFromContext(rules);

  count("the vendored tree was walked, rather than reported clean unread",
    _filesScanned >= 100, _filesScanned + " file(s) under lib/vendor/");

  // The verdict. A hit here means the image ships a vendored tree the
  // manifest does not describe, while the integrity gate keeps passing
  // because it reads the host.
  count("no file the vendored manifest hashes is stripped from the build context",
    stripped.length === 0, stripped.join(" ; "));

  // The re-inclusion is load-bearing, so it is asserted rather than
  // assumed: if it were dropped, the check above would fail, but this
  // says which line is holding it up.
  count("and the one exclusion the tree does trip is put back by a re-inclusion",
    rules.include.length >= 1,
    JSON.stringify(rules.include));

  return helpers.getChecks();
}

module.exports = {
  name:      "vendored-tree-reaches-the-image",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>`. The lines beside it name what was
// examined: a run that read no patterns and a run that read all of them
// otherwise report the same total.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + _filesScanned + " vendored-files");
    console.log("EXAMINED " + _patternsApplied + " build-context-patterns");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
