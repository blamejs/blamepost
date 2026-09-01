// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * published-count-floor: a gate joins the count contract by existing, not
 * by somebody remembering to opt it in.
 *
 * The contract itself is settled. A gate publishes `EXAMINED <n> <unit>`
 * for every unit it answers for, a zero in any unit is refused, and
 * scripts/examined-counts.js is the one place that reads and writes those
 * lines. What was never settled is who has to keep it. Every gate that
 * holds the contract today holds it because a person went and added the
 * lines, one gate at a time, and nothing at all happens when the next gate
 * is written without them. It passes its own review, it passes CI, and the
 * first thing that would notice is a release battery it may never be in.
 *
 * That is the same defect the contract exists to refuse, one level up. A
 * gate exiting clean over an empty set answers for no part of the tree; a
 * FLOOR that covers only the gates somebody remembered answers for no part
 * of the gate directory. Both are silent, and both look exactly like the
 * healthy case from outside.
 *
 * So this is the sibling of static-gate-invocation.test.js. That file asks
 * whether every gate is REACHED before a merge. This one asks whether every
 * gate that is reached SAYS WHAT IT LOOKED AT. Neither question implies the
 * other: a gate can run on every pull request and still report a clean
 * verdict over nothing, and a gate can publish a perfect count and be
 * invoked by nothing.
 *
 * WHAT COUNTS AS A GATE is not decided here. It is `gateScripts()` in
 * static-gate-invocation.test.js, imported rather than restated, because a
 * second definition of "gate-shaped" is a second thing to keep in step and
 * the one that drifts is the one that stops covering a newly added script.
 * The shape is derived from the directory, by a `check-` or `validate-`
 * prefix or a `--check` flag, so a script written next week is inside the
 * floor the moment it lands, which is the whole point.
 *
 * WHAT COUNTS AS PUBLISHING is two shapes, both anchored on a frozen
 * contract rather than on a symbol anybody may rename:
 *
 *   - the gate routes its counts through the shared publisher, which is a
 *     require of scripts/examined-counts.js and a call to `publish`; or
 *   - the gate writes a count line itself, which means forming the frozen
 *     count word followed by a space as a string literal. Only a writer
 *     forms that prefix. A reader of the contract names the bare words
 *     instead: scripts/run-gates.js holds them in a list and
 *     scripts/release.js parses them, and neither builds the prefix, which
 *     is the distinction that has to hold: a gate that can READ a count is not a
 *     gate that PUBLISHES one, and a recognizer that confused the two would
 *     wave through the orchestrator and every gate that merely mentions the
 *     word.
 *
 * WHAT AN EXEMPTION IS, and why it lives in the script. A gate with
 * genuinely nothing to count declares that in its own file header, as
 *
 *     PUBLISHES-NO-COUNT: <the reason, in a sentence>
 *
 * and not as an entry in a table over here. Two reasons, and the second is
 * the one that decided it. A table in the test is a hand-maintained list of
 * scripts, which is the shape this repository has been bitten by three
 * times; it goes stale silently and it is read by nobody who is not already
 * looking at it. And an exemption is an argument, so it belongs where the
 * argument will actually be met: at the top of the file somebody opens when
 * they wonder why this gate says nothing. The reason has to be long enough
 * to be a sentence rather than a label, and it has to sit in the header
 * block rather than buried at the bottom, because an argument nobody reads
 * excuses nothing.
 *
 * The exemption is held to BOTH edges, the way the invocation exemptions
 * are. A marker on a script that does publish is a note in the tree
 * asserting something untrue about it, so it fails here and is deleted
 * rather than left to describe the file it stopped describing.
 *
 * No sockets, no database, no network, and nothing is spawned. It reads the
 * script directory.
 *
 * Run standalone:
 * node test/layer-0-primitives/published-count-floor.test.js
 */

var fs   = require("node:fs");
var path = require("node:path");

var helpers = require("../helpers");
var count   = helpers.count;

// The one definition of what a gate is, from the file that owns it.
var invocation = require("./static-gate-invocation.test.js");

var REPO_ROOT   = helpers.REPO_ROOT;
var SCRIPTS_DIR = path.join(REPO_ROOT, "scripts");

// ---------------------------------------------------------------------------
// Recognizing a publisher
// ---------------------------------------------------------------------------

// The shared publisher, by the module path that IS the contract. Renaming
// the file would move the reader and the writer together, which is the
// property that makes the path a safe anchor and a function name an unsafe
// one.
var SHARED_PUBLISHER_RE = /require\(\s*["'][^"']*examined-counts(?:\.js)?["']\s*\)/;
var PUBLISH_CALL_RE     = /\.publish\s*\(/;

// A count line's own prefix: the frozen word and the space that follows it,
// inside a string literal. `EXAMINED` is what every gate answers in and
// `CHECKS` is the detector suite's spelling, frozen because test/smoke.js
// reads it. The trailing space is load-bearing and is the whole reason this
// pattern can tell a writer from a reader.
var COUNT_LITERAL_RE = /["'`](?:EXAMINED|CHECKS) /;

// A comment-only line, in the two forms this repository writes: the `//`
// note and the interior of a block header.
var COMMENT_ONLY_RE = /^\s*(?:\/\/|\*|\/\*)/;

/**
 * _code(source) is the script with its comment lines dropped.
 *
 * Prose is not output, and every file here explains itself at length: the
 * release orchestrator quotes the count line it PARSES, in backticks, in a
 * paragraph about which gate publishes one. Read as source that would make
 * a reader of the contract look like a writer of it, which is the one
 * distinction this recognizer has to keep.
 *
 * Line-based rather than a real comment stripper, and deliberately so. The
 * failure it can still have is dropping a line it should have kept, which
 * turns a publishing gate into a loud finding somebody goes and looks at.
 * The failure it cannot have is keeping a paragraph and reading it as a
 * publish, which is the silent direction and the one that would put a gate
 * inside the floor without it holding the contract.
 */
function _code(source) {
  return String(source).split(/\r?\n/)
    .filter(function (l) { return !COMMENT_ONLY_RE.test(l); })
    .join("\n");
}

/**
 * _publishes(source) answers whether this script emits a count of its own.
 */
function _publishes(source) {
  var text = _code(source);
  if (SHARED_PUBLISHER_RE.test(text) && PUBLISH_CALL_RE.test(text)) return true;
  return COUNT_LITERAL_RE.test(text);
}

// ---------------------------------------------------------------------------
// Reading an exemption out of the script that carries it
// ---------------------------------------------------------------------------

// The marker, in a comment. Line comments and both interior forms of a
// block comment are accepted, because this repository writes its file
// headers as one long block and its inline notes as `//`.
var MARKER_RE = /^\s*(?:\/\/+|\*|\/\*+)\s*PUBLISHES-NO-COUNT:\s*(.*)$/;

// A comment line that continues the sentence above it. Kept separate from
// the marker so a second marker cannot be absorbed into the first one's
// reason.
var COMMENT_LINE_RE = /^\s*(?:\/\/+|\*)\s?(.*?)\s*$/;

// How far into the file the marker may sit and still be met by a reader who
// opened it. Every script here writes its purpose as a header block in the
// first page or so; an exemption below that is one nobody encounters.
var HEADER_LINES = 60;

// A reason has to be an argument rather than a label. The invocation
// exemptions are held to forty characters, which is enough to stop a bare
// entry; this one is held higher because it has no surrounding table to
// give it context and has to carry the whole case on its own.
var MIN_REASON = 80;

/**
 * _exemption(source) -> { found, line, reason } for the first marker, or
 * { found: false } when the script carries none.
 *
 * The reason is the marker line's own tail plus the comment lines that
 * continue it, so a sentence wrapped at the column width this repository
 * writes to is read whole. It ends at the first line that is not a comment,
 * at an empty comment line, and at a second marker.
 */
function _exemption(source) {
  var lines = String(source).split(/\r?\n/);
  for (var i = 0; i < lines.length; i += 1) {
    var m = MARKER_RE.exec(lines[i]);
    if (m === null) continue;

    var parts = [];
    if (m[1].trim().length > 0) parts.push(m[1].trim());

    for (var j = i + 1; j < lines.length; j += 1) {
      if (MARKER_RE.test(lines[j])) break;
      var c = COMMENT_LINE_RE.exec(lines[j]);
      if (c === null) break;
      if (c[1].length === 0) break;
      parts.push(c[1]);
    }

    return { found: true, line: i + 1, reason: parts.join(" ").trim() };
  }
  return { found: false, line: 0, reason: "" };
}

// ---------------------------------------------------------------------------
// Cases: the recognizers themselves
// ---------------------------------------------------------------------------

// The publisher recognizer decides which half of the problem every script
// is in, so it is asserted directly. A recognizer that said yes to
// everything would report a perfect floor over a directory of silent gates,
// and one that said no to everything would demand an exemption from every
// gate that already holds the contract.
function _publisherRecognizerCases() {
  count("publisher: a gate routing its counts through the shared publisher is one",
    _publishes('var c = require("./examined-counts.js");\nvar code = c.publish([{ unit: "x", n: 1 }]);\n'));

  count("publisher: a gate writing the count line itself is one",
    _publishes('console.log("EXAMINED " + n + " lib-source-files");\n'));

  count("publisher: so is one writing it through the stream rather than the console",
    _publishes('process.stdout.write("EXAMINED " + n + " floor-references\\n");\n'));

  count("publisher: the detector suite's own spelling counts",
    _publishes('console.log("CHECKS " + n);\n'));

  count("publisher: a gate that only READS the contract is not publishing it",
    _publishes('var ACCEPTED = ["EXAMINED", "CHECKS"];\n' +
      'var found = counts.publishedCounts(stdout, ACCEPTED);\n') === false);

  count("publisher: naming the shared module without calling publish is not publishing",
    _publishes('var c = require("./examined-counts.js");\n' +
      "var empty = c.emptyUnits(c.publishedCounts(out));\n") === false);

  count("publisher: prose about what a gate examined is not a count line",
    _publishes("// Every gate in the release battery publishes what it EXAMINED, one\n" +
      "// line per unit, and a zero is refused.\n") === false);

  // The shape that was actually there. The release orchestrator quotes the
  // count line it parses, in backticks, in a paragraph explaining which gate
  // publishes one; read as source it looked like a publisher.
  count("publisher: a comment quoting the count line is the reader describing it, not one",
    _publishes("// know which gate publishes a liveness signal. Its last line is `CHECKS <n>`,\n" +
      "// and the release battery reads it back off stdout.\n") === false);

  count("publisher: the same words inside a block header are prose too",
    _publishes("/**\n * The gate publishes `EXAMINED <n> <unit>` for every unit it answers\n" +
      ' * for, spelled "EXAMINED " with the unit after it.\n */\n') === false);

  count("publisher: a commented-out publish is not a publish",
    _publishes('// var c = require("./examined-counts.js");\n' +
      '// var code = c.publish([{ unit: "x", n: 1 }]);\n') === false);

  count("publisher: a silent gate is recognized as silent",
    _publishes('function main() {\n  console.log("[thing] OK, nothing to report");\n}\n') === false);
}

// The exemption reader decides whether a silent gate argued for itself. A
// reader that accepted a bare marker would turn the one way past this floor
// into a token somebody types to make the test stop talking.
function _exemptionReaderCases() {
  var none = _exemption('console.log("hello");\n');
  count("exemption: a script carrying no marker has none", none.found === false);

  var wrapped = _exemption([
    "/**",
    " * A gate.",
    " *",
    " * PUBLISHES-NO-COUNT: its stdout is the artifact a later job signs, so a count",
    " * line written there would corrupt the document rather than describe it.",
    " */",
    "",
  ].join("\n"));
  count("exemption: a reason wrapped across comment lines is read whole",
    wrapped.found === true &&
    /count\s+line written there would corrupt the document/.test(wrapped.reason),
    JSON.stringify(wrapped));

  var stops = _exemption([
    "// PUBLISHES-NO-COUNT: the first reason, which runs on",
    "// to a second line.",
    "",
    "// An unrelated note that is not part of the reason.",
    "",
  ].join("\n"));
  count("exemption: the reason stops at the blank line rather than eating the file",
    stops.found === true && stops.reason.indexOf("unrelated note") === -1,
    JSON.stringify(stops));

  var bare = _exemption("// PUBLISHES-NO-COUNT:\nvar x = 1;\n");
  count("exemption: a marker with nothing after it carries no reason",
    bare.found === true && bare.reason.length === 0, JSON.stringify(bare));

  var line = _exemption("var x = 1;\nvar y = 2;\n// PUBLISHES-NO-COUNT: a reason.\n");
  count("exemption: the line it was found on is reported, so the header rule can be applied",
    line.found === true && line.line === 3, JSON.stringify(line));
}

// ---------------------------------------------------------------------------
// Cases: the floor over the real directory
// ---------------------------------------------------------------------------

function _floorCases() {
  var gates = invocation.gateScripts();

  // Canary. An empty discovery would report a perfect floor over no gates,
  // which is the verdict this whole file exists to refuse.
  count("the gate scan still finds the gate scripts", gates.length > 1,
    gates.length + " script(s): " + gates.join(", "));

  var sources = {};
  gates.forEach(function (name) {
    sources[name] = fs.readFileSync(path.join(SCRIPTS_DIR, name), "utf8");
  });

  var publishing = gates.filter(function (n) { return _publishes(sources[n]); });

  // Canary, the other way. Every case below is also satisfied by a
  // recognizer that stopped matching and a directory that then answered
  // with exemptions, so the recognizer has to be shown still finding the
  // gates that do hold the contract.
  count("the publisher recognizer still finds gates that hold the contract",
    publishing.length > 1,
    publishing.length + " of " + gates.length + ": " + publishing.join(", "));

  var silent          = [];
  var unexplained     = [];
  var buried          = [];
  var staleExemptions = [];

  gates.forEach(function (name) {
    var exempt = _exemption(sources[name]);

    if (_publishes(sources[name])) {
      if (exempt.found) staleExemptions.push(name + " (line " + exempt.line + ")");
      return;
    }
    if (!exempt.found) {
      silent.push(name);
      return;
    }
    if (exempt.reason.length < MIN_REASON) {
      unexplained.push(name + " (" + exempt.reason.length + " characters)");
    }
    if (exempt.line > HEADER_LINES) {
      buried.push(name + " (line " + exempt.line + ")");
    }
  });

  count("every gate-shaped script publishes what it examined, or declares in its own " +
    "header why it has nothing to count",
  silent.length === 0,
  silent.length === 0 ? "" : "silent: " + silent.join(", "));

  count("every declaration argues its case rather than naming itself",
    unexplained.length === 0,
    unexplained.length === 0 ? "" : "shorter than " + MIN_REASON + " characters: " +
      unexplained.join(", "));

  count("every declaration sits in the header, where a reader opening the file meets it",
    buried.length === 0,
    buried.length === 0 ? "" : "below line " + HEADER_LINES + ": " + buried.join(", "));

  count("no declaration is written on a gate that publishes anyway",
    staleExemptions.length === 0,
    staleExemptions.length === 0 ? "" : "stale: " + staleExemptions.join(", "));
}

// ---------------------------------------------------------------------------

function run() {
  _publisherRecognizerCases();
  _exemptionReaderCases();
  _floorCases();

  return helpers.getChecks();
}

module.exports = { name: "published-count-floor", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
