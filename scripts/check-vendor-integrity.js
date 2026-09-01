#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Vendored-tree integrity gate.
 *
 * Re-hashes every tree and file `lib/vendor/MANIFEST.json` declares and
 * compares the result against the hash the manifest recorded. A difference
 * means the vendored framework was changed outside
 * `scripts/vendor-update.sh`, and the next refresh will replace the tree and
 * take the change with it without saying so.
 *
 * That is the failure this exists for, and it is quiet. A patch applied
 * straight into `lib/vendor/blamejs/` works. It passes the behavioral
 * suite, it survives review, and it disappears on the day somebody vendors
 * the next upstream release. Nothing announces the loss, and the symptom
 * arrives later as a capability that has gone missing. Comparing the
 * recorded hash against the bytes on disk turns that into a failing check
 * on the commit that introduces it.
 *
 * Run locally:
 *   node scripts/check-vendor-integrity.js
 *   node scripts/check-vendor-integrity.js --json               // structured output
 *   node scripts/check-vendor-integrity.js --warn               // exit 0, print only
 *   node scripts/check-vendor-integrity.js --manifest <path>    // measure another tree
 *
 * This is a STATIC gate, in the `npm run gates` chain, and deliberately not
 * a boot check. Two reasons. Hashing tens of megabytes on every start buys
 * an operator nothing at the moment they most want the server listening.
 * And a tree that has already been tampered with is a tree that can rewrite
 * the boot check that measures it, so the measurement belongs somewhere the
 * tampered tree does not run.
 *
 * Failure policy, in one sentence: a tree this gate could not measure is
 * reported as UNKNOWN and never as verified. A changed tree fails. So does
 * an unmeasured one, under its own summary line, because a check that did
 * not happen reading as intact is the one answer an integrity gate must
 * never give. Absence is the case that matters and it is the case a naive
 * implementation gets wrong: a missing manifest, a package that declares no
 * files, a slot with no recorded hash and a tree that cannot be read all
 * leave a per-slot loop with nothing to compare, and a loop with nothing to
 * compare finds nothing wrong.
 *
 * The hashing comes from `scripts/refresh-vendor-manifest.js`, which is
 * also what writes the values this reads. One implementation measures and
 * records, so the comparison cannot drift into two algorithms that agree
 * until the day they do not. Requiring that file runs nothing.
 *
 * What this gate does NOT establish: that the recorded hash describes the
 * bytes the publisher shipped. The manifest and the tree can be rewritten
 * together by anyone who can write to the working tree. The publisher's own
 * claim is the `integrity` value the refresh verifies before extraction,
 * and the record of it is the signed commit that introduced the manifest.
 *
 * Exit codes:
 *   0  every declared tree matches its recorded hash
 *   1  a mismatch, or something that could not be measured
 *   2  the invocation itself was wrong
 */

var fs   = require("node:fs");
var path = require("node:path");

var refresh = require("./refresh-vendor-manifest.js");

var DEFAULT_MANIFEST_PATH = refresh.MANIFEST_PATH;

var WARN_ONLY = process.argv.indexOf("--warn") !== -1;
var JSON_OUT  = process.argv.indexOf("--json") !== -1;

// The refresh tool writes this string into a hash slot whose declared path
// was not on disk when it ran. It is a record that nothing was measured,
// and reading it as a hash would compare a tree against the literal text.
var MISSING_MARKER = "MISSING";

// Every status that means "this slot was not measured". They share one
// bucket because they leave the same hole: the gate reached the end with
// nothing compared, and a per-slot loop over nothing reports no findings.
var UNMEASURED_STATUSES = [
  "missing-manifest",
  "unreadable-manifest",
  "no-packages",
  "no-file-slots",
  "no-recorded-hash",
  "orphan-hash-slot",
  "missing-tree",
  "unreadable-tree",
];

function _isUnmeasured(result) {
  return UNMEASURED_STATUSES.indexOf(result && result.status) !== -1;
}

/**
 * _manifestPathFrom(argv) reads the `--manifest` override. This is an
 * entry point rather than a request, so a flag with no value is refused:
 * silently falling back to the repository manifest would measure a tree
 * the caller did not ask about and report the answer as though it had.
 */
function _manifestPathFrom(argv) {
  var at = argv.indexOf("--manifest");
  if (at === -1) return DEFAULT_MANIFEST_PATH;
  var value = argv[at + 1];
  if (typeof value !== "string" || value.length === 0 || value.charAt(0) === "-") {
    throw new TypeError("--manifest needs a path");
  }
  return path.resolve(value);
}

/**
 * _rootFor(manifestPath) resolves the repository root the manifest's
 * file paths are relative to. The manifest lives at
 * `<root>/lib/vendor/MANIFEST.json`, so the root is two directories above
 * it. Deriving it from the manifest rather than from this script's own
 * location is what lets the gate measure a tree somewhere else.
 */
function _rootFor(manifestPath) {
  return path.resolve(path.dirname(manifestPath), "..", "..");
}

/**
 * _readManifest(manifestPath) returns the parsed manifest, or a result
 * describing why there is none. Absence and unreadability are verdicts
 * here, not exceptions, because both are answers this gate has to report
 * rather than reasons to stop having an opinion.
 */
function _readManifest(manifestPath) {
  var raw;
  try {
    raw = fs.readFileSync(manifestPath, "utf8");
  } catch (e) {
    var missing = e && e.code === "ENOENT";
    return {
      manifest: null,
      failure: {
        slot:   "(manifest)",
        path:   manifestPath,
        status: missing ? "missing-manifest" : "unreadable-manifest",
        detail: missing
          ? "no manifest at " + manifestPath + ", so there is no recorded hash to " +
            "measure the vendored tree against"
          : "cannot read " + manifestPath + ": " + ((e && e.message) || String(e)),
      },
    };
  }
  try {
    return { manifest: JSON.parse(raw), failure: null };
  } catch (e2) {
    return {
      manifest: null,
      failure: {
        slot:   "(manifest)",
        path:   manifestPath,
        status: "unreadable-manifest",
        detail: "cannot parse " + manifestPath + ": " + ((e2 && e2.message) || String(e2)),
      },
    };
  }
}

/**
 * _measureSlot(root, pkgKey, slot, declared, recorded) hashes one declared
 * path and compares it against the recorded value. A declared path ending
 * in a separator is hashed as a directory tree and anything else as a
 * single file, which is the same choice the refresh tool makes when it
 * records the value. Reading the shape off the declaration rather than off
 * the disk is deliberate: a directory that a regular file is now standing
 * in for is a finding, not a file to hash.
 */
function _measureSlot(root, pkgKey, slot, declared, recorded) {
  var base = {
    package:  pkgKey,
    slot:     slot,
    declared: declared,
    recorded: recorded,
  };
  if (typeof recorded !== "string" || recorded.length === 0 || recorded === MISSING_MARKER) {
    base.status = "no-recorded-hash";
    base.detail = "slot '" + slot + "' declares " + declared + " and records " +
      (recorded === MISSING_MARKER
        ? "the missing-file marker, so the refresh that wrote it measured nothing"
        : "no hash, so nothing compares the bytes on disk against anything");
    return base;
  }

  var abs = path.resolve(root, declared);
  base.path = abs;
  if (!fs.existsSync(abs)) {
    base.status = "missing-tree";
    base.detail = "the manifest declares " + declared + " and nothing is on disk there";
    return base;
  }

  var computed;
  try {
    computed = /[/\\]$/.test(declared) ? refresh.hashTree(abs) : refresh.hashFile(abs);
  } catch (e) {
    base.status = "unreadable-tree";
    base.detail = "cannot hash " + declared + ": " + ((e && e.message) || String(e));
    return base;
  }

  base.computed = computed;
  base.status   = recorded === computed ? "verified" : "mismatch";
  if (base.status === "mismatch") {
    base.detail = "recorded " + recorded + " and the bytes on disk hash to " + computed;
  }
  return base;
}

/**
 * verify(opts) walks the manifest and returns one result per declared
 * slot, plus a result standing in for any level that had nothing to walk.
 * Pure apart from reading the filesystem, and exported so the failure
 * paths are provable against a temporary directory.
 */
function verify(opts) {
  opts = opts || {};
  var manifestPath = opts.manifestPath || DEFAULT_MANIFEST_PATH;
  var root         = opts.root || _rootFor(manifestPath);

  var read = _readManifest(manifestPath);
  if (read.failure) {
    return { manifestPath: manifestPath, root: root, results: [read.failure] };
  }

  var packages = (read.manifest && read.manifest.packages) || {};
  var keys = Object.keys(packages);
  if (keys.length === 0) {
    return {
      manifestPath: manifestPath,
      root:         root,
      results:      [{
        slot:   "(packages)",
        path:   manifestPath,
        status: "no-packages",
        detail: "the manifest declares no packages, so it records the integrity of nothing",
      }],
    };
  }

  var results = [];
  keys.forEach(function (pkgKey) {
    var entry  = packages[pkgKey] || {};
    var files  = entry.files  || {};
    var hashes = entry.hashes || {};
    var slots  = Object.keys(files);
    if (slots.length === 0) {
      results.push({
        package: pkgKey,
        slot:    "(files)",
        status:  "no-file-slots",
        detail:  "package '" + pkgKey + "' declares no file slots, so nothing about it is measured",
      });
      return;
    }
    slots.forEach(function (slot) {
      var declared = files[slot];
      if (typeof declared !== "string" || declared.length === 0) {
        results.push({
          package: pkgKey,
          slot:    slot,
          status:  "no-file-slots",
          detail:  "slot '" + slot + "' names no path",
        });
        return;
      }
      results.push(_measureSlot(root, pkgKey, slot, declared, hashes[slot]));
    });
    // A recorded hash naming no declared file is a value nothing compares.
    // The refresh tool rebuilds the hash map from the file map, so one can
    // only appear when the manifest was edited by something else.
    Object.keys(hashes).forEach(function (slot) {
      if (Object.prototype.hasOwnProperty.call(files, slot)) return;
      results.push({
        package: pkgKey,
        slot:    slot,
        status:  "orphan-hash-slot",
        detail:  "slot '" + slot + "' records a hash and declares no file, so the value is " +
                 "compared against nothing",
      });
    });
  });

  return { manifestPath: manifestPath, root: root, results: results };
}

/**
 * _verdict(results) turns the per-slot results into the one line this gate
 * answers with and the exit code that goes with it.
 *
 * The rule it encodes: a slot that could not be measured is UNKNOWN, and
 * UNKNOWN is not a pass. Measuring nothing is not the same as finding
 * nothing wrong, so an empty result set fails too.
 *
 * Pure, and exported, so the failure paths are provable without a
 * filesystem.
 */
function _verdict(results) {
  results = results || [];
  var changed = results.filter(function (r) { return r.status === "mismatch"; });
  var unknown = results.filter(_isUnmeasured);

  if (changed.length > 0) {
    return {
      code: 1,
      summary: "FAIL: " + changed.length + " vendored path(s) changed outside the vendor " +
        "refresh and no longer match the hash the manifest recorded" +
        (unknown.length > 0 ? ", and " + unknown.length + " that could not be measured" : ""),
      advice: "The vendored tree is replaced wholesale by the next refresh, so a change made " +
        "here is a change that disappears. Revert it and compose the framework surface " +
        "instead, or vendor a release that carries it with: bash scripts/vendor-update.sh blamejs <version>",
    };
  }
  if (unknown.length > 0) {
    return {
      code: 1,
      summary: "UNKNOWN: " + unknown.length + " vendored path(s) could not be measured. " +
        "Integrity is unknown, not intact.",
      advice: "Repair the manifest with: node scripts/refresh-vendor-manifest.js",
    };
  }
  if (results.length === 0) {
    return {
      code: 1,
      summary: "UNKNOWN: nothing was measured. Integrity is unknown, not intact.",
      advice: "Repair the manifest with: node scripts/refresh-vendor-manifest.js",
    };
  }
  return {
    code: 0,
    summary: "OK, every vendored tree matches the hash recorded for it (" +
      results.length + " path(s))",
    advice: "",
  };
}

var LABELS = {
  verified: "OK",
  mismatch: "CHANGED",
};

function _label(status) {
  if (LABELS[status]) return LABELS[status];
  return UNMEASURED_STATUSES.indexOf(status) !== -1 ? "UNKNOWN" : status;
}

function _writeHuman(walk, verdict) {
  var out = "[vendor-integrity] " + walk.results.length +
    " declared vendored path(s) measured against " + walk.manifestPath + ":\n";
  walk.results.forEach(function (r) {
    var line = "  [" + _label(r.status) + "] " +
      (r.package ? r.package + " " : "") + r.slot;
    if (r.declared) line += "  " + r.declared;
    out += line + "\n";
    if (r.detail) out += "        " + r.detail + "\n";
  });
  out += "[vendor-integrity] " + verdict.summary + "\n";
  if (verdict.advice) out += "[vendor-integrity] " + verdict.advice + "\n";
  process.stdout.write(out);
}

// WHAT THE RUN EXAMINED, published as the last lines of stdout on every path
// that reaches a verdict:
//
//   EXAMINED <n> manifest-packages
//   EXAMINED <n> verified-slots
//
// Both, because they fail independently and the second is the one a healthy
// first number hides. `manifest-packages` is the manifest as it was read: a
// manifest that lost its packages takes it to zero and there is nothing left
// below to measure. `verified-slots` is how many declared files were actually
// hashed and COMPARED, which comes apart from the first number the moment
// every slot resolves to something unmeasurable: a missing tree, a slot with
// no recorded hash, an orphan hash naming no file. A manifest holding one
// package none of whose files could be measured prints a healthy package
// count and has measured nothing.
// In --json mode the same two numbers ride INSIDE the document instead. The
// structured stdout carries the document alone so a caller can parse it
// without stripping trailing lines off the end, and appending count lines
// there would break exactly the contract that mode exists for.
function _examinedCounts(results) {
  var packages = {};
  var verified = 0;
  (results || []).forEach(function (r) {
    if (r && r.package) packages[r.package] = true;
    if (r && r.status === "verified") verified += 1;
  });
  return { manifestPackages: Object.keys(packages).length, verifiedSlots: verified };
}

function _publishExamined(results) {
  var c = _examinedCounts(results);
  process.stdout.write("EXAMINED " + c.manifestPackages + " manifest-packages\n");
  process.stdout.write("EXAMINED " + c.verifiedSlots + " verified-slots\n");
}

function main() {
  var manifestPath;
  try {
    manifestPath = _manifestPathFrom(process.argv);
  } catch (e) {
    process.stderr.write("[vendor-integrity] " + ((e && e.message) || String(e)) + "\n");
    process.exit(2);
    return;
  }

  var walk    = verify({ manifestPath: manifestPath });
  var verdict = _verdict(walk.results);

  if (JSON_OUT) {
    // stdout carries the document alone so a caller can parse it without
    // stripping a trailing summary line off the end of it.
    process.stdout.write(JSON.stringify({
      manifestPath: walk.manifestPath,
      results:      walk.results,
      verdict:      verdict,
      examined:     _examinedCounts(walk.results),
    }, null, 2) + "\n");
    process.stderr.write("[vendor-integrity] " + verdict.summary + "\n");
  } else {
    _writeHuman(walk, verdict);
  }

  if (WARN_ONLY) {
    // The advisory local run still printed the verdict above. What --warn
    // changes is the exit code, never the claim.
    if (verdict.code !== 0) {
      process.stdout.write("[vendor-integrity] --warn: exiting 0 anyway\n");
    }
    if (!JSON_OUT) _publishExamined(walk.results);
    process.exit(0);
    return;
  }
  // Published on a failing run as well as a passing one, so the number sits
  // beside the findings rather than only beside a pass.
  if (!JSON_OUT) _publishExamined(walk.results);
  process.exit(verdict.code);
}

module.exports = {
  MANIFEST_PATH:       DEFAULT_MANIFEST_PATH,
  UNMEASURED_STATUSES: UNMEASURED_STATUSES,
  verify:              verify,
  _verdict:            _verdict,
  _isUnmeasured:       _isUnmeasured,
  _manifestPathFrom:   _manifestPathFrom,
  _rootFor:            _rootFor,
};

if (require.main === module) {
  main();
}
