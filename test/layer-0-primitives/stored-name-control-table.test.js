// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One control-character table for every value this server stores and
 * later prints.
 *
 * The framework's table is the C0 block plus the delete code point.
 * `b.codepointClass.C0_CTRL_RANGES` covers U+0000 to U+001F with tab,
 * line feed and carriage return exempted, `isForbiddenControlChar` adds
 * U+007F, and `firstControlCharOffset` answers over exactly that set. The
 * C1 range at U+0080 to U+009F is outside it, and U+009B is the control
 * sequence introducer: one code point that opens an escape sequence, so a
 * value carrying it colors or moves whatever reads it as a stream.
 *
 * This server's table is `blamepost.text.hasControlChar`, which covers
 * C0, the delete code point and C1. It is the write side, and its own
 * documentation says so: a field this server stores and will later print
 * in a header, a table and a page is refused there once rather than
 * repaired at each of the places it is read.
 *
 * The gate below is that the two do not get mixed up. A refusal in
 * shipped source written on the framework's table admits every C1 code
 * point, and the value then reaches an operator's terminal, a client's
 * terminal, a log line and an audit row. It reads as a control-character
 * refusal at the call site, which is why nothing about the source says
 * it is the narrower one.
 *
 * No sockets, no disk beyond reading the tree.
 *
 * Run standalone: node test/layer-0-primitives/stored-name-control-table.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers     = require("../helpers");
var b           = require("../../lib/vendor/blamejs");
var displayText = require("../../lib/text");

var count = helpers.count;

var REPO_ROOT = helpers.REPO_ROOT;

// Where shipped source lives. The vendored tree is read-only and holds
// the framework's own table, so it is not scanned.
var SCANNED_DIRS = ["lib", "bin"];
var VENDOR_REL   = nodePath.join("lib", "vendor");

// A call to the framework's control-character reader. The parenthesis is
// what separates a call from a mention of the name in a comment, and the
// comment in `lib/text/index.js` that explains why this server carries
// its own table is exactly such a mention.
var FRAMEWORK_TABLE_CALL = /\bfirstControlCharOffset\s*\(/;

// The C1 range, built from its code points because a raw C1 octet does
// not survive an editor or a file read intact.
var C1_FIRST = 0x0080;
var C1_LAST  = 0x009f;

function _sourceFiles() {
  var out = [];
  SCANNED_DIRS.forEach(function (dir) {
    var root = nodePath.join(REPO_ROOT, dir);
    if (!nodeFs.existsSync(root)) return;
    (function walk(at) {
      nodeFs.readdirSync(at, { withFileTypes: true }).forEach(function (entry) {
        var full = nodePath.join(at, entry.name);
        if (entry.isDirectory()) {
          if (nodePath.relative(REPO_ROOT, full) === VENDOR_REL) return;
          walk(full);
          return;
        }
        if (entry.isFile() && entry.name.endsWith(".js")) out.push(full);
      });
    }(root));
  });
  return out;
}

// ---------------------------------------------------------------------------
// The two tables, measured rather than assumed
// ---------------------------------------------------------------------------

// The claim the gate rests on is about what each table answers, and a
// gate written around a remembered answer stops being about anything the
// moment the answer moves. So the answer is read here.
function theRepositoryTableCoversTheC1Range() {
  var missed = [];
  for (var code = C1_FIRST; code <= C1_LAST; code += 1) {
    if (!displayText.hasControlChar("a" + String.fromCharCode(code) + "b")) {
      missed.push("0x" + code.toString(16));
    }
  }
  count("this server's table for a stored field refuses every code point in the C1 range",
    missed.length === 0, missed.join(", "));

  // And it is at least as wide as the framework's, in both directions,
  // so a value refused by the framework's is never admitted by this one.
  // Written as a comparison rather than as a second remembered list, so a
  // vendor refresh that widens the framework's table leaves this true.
  var narrower = [];
  for (var c = 0; c <= 0x00ff; c += 1) {
    var sample = "a" + String.fromCharCode(c) + "b";
    if (b.codepointClass.firstControlCharOffset(sample, { forbidTab: true }) !== -1 &&
        !displayText.hasControlChar(sample)) {
      narrower.push("0x" + c.toString(16));
    }
  }
  count("and it refuses everything the framework's table refuses, so moving a gate onto it " +
    "admits nothing that was refused before",
    narrower.length === 0, narrower.join(", "));

  // The detail is the reason this file exists, printed whether or not it
  // is still true, so a vendor refresh that closes the gap says so.
  var frameworkMisses = [];
  for (var d = C1_FIRST; d <= C1_LAST; d += 1) {
    if (b.codepointClass.firstControlCharOffset("a" + String.fromCharCode(d) + "b",
      { forbidTab: true }) === -1) {
      frameworkMisses.push(d);
    }
  }
  count("and the two tables are measured against the vendored framework rather than against " +
    "a remembered answer",
    true, "the framework's table passes " + frameworkMisses.length + " of the " +
      (C1_LAST - C1_FIRST + 1) + " C1 code points");
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

function noShippedRefusalIsWrittenOnTheNarrowerTable() {
  var files = _sourceFiles();

  // The canary. A walk that read nothing satisfies the refusal below
  // while answering for no part of the tree, which is the failure mode a
  // clean verdict over an empty set has.
  count("the scan read the shipped source tree",
    files.length > 0, files.length + " file(s)");

  var hits = [];
  files.forEach(function (file) {
    var lines = nodeFs.readFileSync(file, "utf8").split(/\r?\n/);
    for (var i = 0; i < lines.length; i += 1) {
      if (!FRAMEWORK_TABLE_CALL.test(lines[i])) continue;
      hits.push(nodePath.relative(REPO_ROOT, file).replace(/\\/g, "/") + ":" + (i + 1));
    }
  });

  count("no shipped source calls the framework's control-character reader, because the value " +
    "it is asked about is one this server stores and later prints, and the answer it gives " +
    "passes the C1 range",
    hits.length === 0, hits.join(", "));
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function run() {
  theRepositoryTableCoversTheC1Range();
  noShippedRefusalIsWrittenOnTheNarrowerTable();
  return helpers.getChecks();
}

module.exports = {
  name:      "stored-name-control-table",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
