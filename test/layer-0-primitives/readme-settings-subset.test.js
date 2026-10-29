// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * readme-settings-subset: the README's settings table is shorter than the
 * operator guide's by a shape, not by whatever anybody left out.
 *
 * Two documents carry a settings table. The guide's is the reference and
 * has to hold a row per setting, which
 * test/layer-1-state/docs-surface.test.js requires. The README's is
 * deliberately shorter, and that file says so where it compares printed
 * defaults: a setting with no README row is passed over, so the shorter
 * table stays shorter.
 *
 * That decision is right and stays. What it left open is that "shorter"
 * was never given a shape, so the README's table could be short by
 * anything at all and nothing would say which. It was short by an
 * outbound setting for a while, and the omission read exactly like the
 * five deliberate ones.
 *
 * So the exemption is kept and the shortness is measured instead. Three
 * questions, none of which needs the README to carry a row it does not
 * want:
 *
 *   - Every row the README carries has a row in the guide. A row here for
 *     a name the reference does not hold is a variable an operator reads
 *     about in one document and cannot look up in the other, and the
 *     likeliest cause is a name the server stopped reading.
 *   - The rows the README omits are the per-listener port variables and
 *     nothing else. That set is read off the listener table rather than
 *     written here, so a listener added next week is inside the shape the
 *     day it lands. The README covers those six through the listeners
 *     setting instead, and it names all six in the paragraph above its
 *     table.
 *   - A setting the schema marks as required has a row in both. An
 *     operator reading only the README has to be able to see everything
 *     the server refuses to start without.
 *
 * The rows are read as ROWS rather than as mentions. A variable named
 * inside a paragraph about something else is not a place an operator can
 * look a default up, which is the same distinction the reference table's
 * own check makes.
 *
 * No sockets, no database. It reads two documents and the schema.
 *
 * Run standalone: node test/layer-0-primitives/readme-settings-subset.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var parity  = require("../helpers/parity");
var config  = require("../../lib/config");

var check = helpers.check;
var count = helpers.count;

var REPO_ROOT = helpers.REPO_ROOT;

var REFERENCE = "docs/operator-guide.md";
var SHORTER   = "README.md";

function _read(relative) {
  return nodeFs.readFileSync(nodePath.join(REPO_ROOT, relative), "utf8");
}

// The variables one document gives a table row of their own. The row
// shape is the same in both: the variable in the first cell, then cells
// that differ between the two documents and are not read here.
function rowVariables(relative) {
  var names = [];
  _read(relative).split("\n").forEach(function (line) {
    var m = /^\|\s*`(BLAMEPOST_[A-Z0-9_]+)`\s*\|/.exec(line);
    if (m !== null && names.indexOf(m[1]) === -1) names.push(m[1]);
  });
  return names;
}

// The per-listener port variables, off the listener table. Each one moves
// one listener's port and touches nothing else, which is the form that
// fits a `docker run` line; the README covers the whole set through the
// listeners setting and names them in a sentence rather than giving each
// a row.
function listenerPortVariables() {
  return config.LISTENER_NAMES.map(function (listener) {
    return config.LISTENER_DEFAULTS[listener].portVar;
  });
}

function bothTablesAreReadable() {
  var reference = rowVariables(REFERENCE);
  var shorter   = rowVariables(SHORTER);

  count("the reference table carries rows to compare against",
    reference.length >= 30, reference.length + " row(s) in " + REFERENCE);

  count("and the shorter table carries rows of its own, so a table that stopped being a table " +
    "is a failure rather than a subset of everything",
    shorter.length >= 25, shorter.length + " row(s) in " + SHORTER);

  count("the shorter table really is shorter, which is the arrangement this file measures " +
    "rather than the one it is trying to change",
    shorter.length < reference.length,
    shorter.length + " of " + reference.length + " row(s)");

  return { reference: reference, shorter: shorter };
}

// The subset relation, both ways at once. The set the README is held
// against is the reference minus the ports, so a row it omits for any
// other reason comes back as a name on one side of the difference and a
// row it invents comes back on the other.
function theShorterTableIsTheReferenceMinusThePorts(tables) {
  var ports = listenerPortVariables();
  count("the rows the shorter table may omit are read off the listener table rather than " +
    "listed here", ports.length >= 5, ports.join(", "));

  var carried = tables.reference.filter(function (name) {
    return ports.indexOf(name) === -1;
  });
  count("so the set it is held against is the reference without them",
    carried.length > 0 && carried.length < tables.reference.length,
    carried.length + " of " + tables.reference.length + " reference row(s)");

  parity.report(count, {
    have:      tables.shorter,
    want:      carried,
    haveLabel: SHORTER,
    wantLabel: REFERENCE + " without the per-listener port rows",
    missingHint: "the shorter table is short by something other than a port variable, which " +
      "is either a row to add or a shape to widen on purpose",
    extraHint: "a row here that the reference does not carry is a variable an operator " +
      "cannot look up, and is usually one the server stopped reading",
  });

  // The other half of the arrangement. The README omits those six rows
  // because it covers them in a sentence, so a port variable it neither
  // gives a row nor names is one an operator reading that document alone
  // never learns about.
  var readme  = _read(SHORTER);
  var unnamed = ports.filter(function (name) { return readme.indexOf(name) === -1; });
  check("and every port variable it leaves out of its table is named in its prose instead, " +
    "which is what makes leaving the row out a shape rather than an omission" +
    (unnamed.length ? ", and these are not: " + unnamed.join(", ") : ""),
    unnamed.length === 0);
}

// A setting with no fallback stops the start when it is unset, so it is
// the one class of row a reader of the shorter document cannot be left to
// find in the longer one.
function everyRequiredSettingIsInBothTables(tables) {
  var required = config.SETTINGS.filter(function (setting) {
    return setting.required === true;
  }).map(function (setting) { return setting.env; });

  count("the settings the server refuses to start without are read off the schema rather " +
    "than off either document",
    required.length >= 2, required.join(", "));

  var missing = required.filter(function (name) {
    return tables.shorter.indexOf(name) === -1 || tables.reference.indexOf(name) === -1;
  });
  check("and each of them has a row in both tables, so an operator reading either document " +
    "sees everything that has to be set before the first start" +
    (missing.length ? ", and these do not: " + missing.join(", ") : ""),
    missing.length === 0);
}

// ---- runner ----------------------------------------------------------------

function run() {
  var tables = bothTablesAreReadable();
  theShorterTableIsTheReferenceMinusThePorts(tables);
  everyRequiredSettingIsInBothTables(tables);
  return helpers.getChecks();
}

module.exports = { name: "readme-settings-subset", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
