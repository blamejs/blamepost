// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The swallow gate's two readers, held to known shapes.
 *
 * `scripts/check-swallow-coverage.js` decides, for every `catch` in this
 * project's own sources, whether the fault propagates, whether a test
 * drove the catch, and whether the author wrote down why it fails closed.
 * The first and third of those are pure functions over source text, and
 * the script exports them saying they are held by a hermetic test. They
 * were exported and nothing imported them, so the two readers the whole
 * verdict rests on were checked only by the tree they happened to be run
 * over.
 *
 * Both readers fail in a way the gate's own output cannot show:
 *
 *   - `findSwallows` reaching zero is the finder having stopped matching,
 *     and the gate then reports every file read beside a verdict about no
 *     catch at all. The empty-set refusal catches the total at zero; it
 *     cannot catch a finder that still recognizes one shape and has
 *     stopped recognizing another.
 *   - `isMarked` deciding a marker belongs to a catch by counting lines
 *     rather than by reading the comment the marker is written in. A
 *     reason long enough to wrap puts the marker outside the count, and
 *     the swallow is then reported unmarked with its own explanation
 *     sitting in the file directly above it.
 *
 * Every fixture here is a string. No report is read, no source tree is
 * walked, nothing is spawned.
 *
 * Run standalone: node test/layer-0-primitives/swallow-gate.test.js
 */

var helpers = require("../helpers");
var gate    = require("../../scripts/check-swallow-coverage.js");

var count = helpers.count;

// The marker, spelled once. A second spelling here would be a second
// answer to what the gate reads.
var MARKER = "allow:swallow-unverified";

function swallowsIn(src) {
  return gate.findSwallows("lib/probe.js", src);
}

function markedIn(src) {
  var lines = src.split("\n");
  var found = swallowsIn(src);
  if (found.length !== 1) {
    throw new Error("fixture must hold exactly one swallow, found " + found.length);
  }
  return gate.isMarked(lines, found[0].startLine, found[0].endLine);
}

// ---- findSwallows ---------------------------------------------------------

// A catch that propagates is fail-closed by construction, in each of the
// three forms the gate recognizes. If any of these starts counting as a
// swallow the gate turns into noise; if the plain one stops counting, the
// gate goes quiet while proving nothing.
function theFinderSeparatesPropagationFromSwallowing() {
  var cases = [
    { what: "a catch that returns a value is a swallow",
      src: "function f() {\n  try { g(); }\n  catch (e) {\n    return null;\n  }\n}\n",
      swallow: true },
    { what: "a catch that re-throws is not",
      src: "function f() {\n  try { g(); }\n  catch (e) {\n    throw e;\n  }\n}\n",
      swallow: false },
    { what: "a catch that returns a rejected promise is not",
      src: "function f() {\n  try { g(); }\n  catch (e) {\n    return Promise.reject(e);\n  }\n}\n",
      swallow: false },
    { what: "a catch that throws through the schema helper is not",
      src: "function f() {\n  try { g(); }\n  catch (e) {\n    fail(\"bad\", e);\n  }\n}\n",
      swallow: false },
    { what: "a catch with an empty body is a swallow",
      src: "function f() {\n  try { g(); }\n  catch (e) {\n  }\n}\n",
      swallow: true },
    { what: "a catch that throws and also returns a value is a swallow, because the " +
        "return is a path out that carries no fault",
      src: "function f() {\n  try { g(); }\n  catch (e) {\n    if (e.code) throw e;\n" +
        "    return null;\n  }\n}\n",
      swallow: true },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var n = swallowsIn(cases[i].src).length;
    count("findSwallows: " + cases[i].what, n === (cases[i].swallow ? 1 : 0),
      "found " + n);
  }
}

// A `throw` that is only mentioned in a comment or a string must not read
// as propagation, or a swallow hides behind the word.
function theFinderDoesNotReadThrowOutOfProseOrStrings() {
  var commented = "function f() {\n  try { g(); }\n  catch (e) {\n" +
    "    // we do not throw here\n    return null;\n  }\n}\n";
  count("findSwallows: the word throw in a comment does not make a catch propagate",
    swallowsIn(commented).length === 1, "found " + swallowsIn(commented).length);

  var stringed = "function f() {\n  try { g(); }\n  catch (e) {\n" +
    "    log(\"throw\");\n    return null;\n  }\n}\n";
  count("findSwallows: the word throw inside a string does not either",
    swallowsIn(stringed).length === 1, "found " + swallowsIn(stringed).length);
}

// The line numbers are what the coverage lookup and the marker reader both
// key on, so a finder that reports the right count at the wrong lines
// answers about some other code.
function theFinderReportsTheCatchsOwnLines() {
  var src = "function f() {\n" +          // 1
    "  try { g(); }\n" +                  // 2
    "  catch (e) {\n" +                   // 3
    "    return null;\n" +                // 4
    "  }\n" +                             // 5
    "}\n";                                // 6
  var sw = swallowsIn(src)[0];
  count("findSwallows: the swallow starts on the line the catch keyword is on",
    sw.startLine === 3, "startLine " + sw.startLine);
  count("findSwallows: and ends on the line its body closes",
    sw.endLine === 5, "endLine " + sw.endLine);
  count("findSwallows: and it carries the caught name, which the finding prints",
    sw.param === "e", sw.param);
}

// ---- isMarked -------------------------------------------------------------

// The shapes the marker is actually written in. The last two are the ones
// that failed: the gate read a fixed two lines above the catch, so a
// reason that wrapped onto a third line put the marker out of reach, and a
// single-line `try { ... }` between the block and the catch put it out of
// reach whatever its length.
function theMarkerIsReadInEveryShapeItIsWrittenIn() {
  var cases = [
    { what: "on the catch line itself",
      src: "function f() {\n  try { g(); }\n" +
        "  catch (e) { return null; }   // " + MARKER + " reason\n}\n" },
    { what: "inside the catch body",
      src: "function f() {\n  try { g(); }\n  catch (e) {\n" +
        "    // " + MARKER + " reason\n    return null;\n  }\n}\n" },
    { what: "on the single line directly above the catch",
      src: "function f() {\n  try { g(); }\n" +
        "  // " + MARKER + " reason\n  catch (e) { return null; }\n}\n" },
    { what: "as the first line of a comment block that wraps onto a third line, which " +
        "is how a reason worth writing down is usually the wrong length",
      src: "function f() {\n" +
        "  // " + MARKER + " reaching this needs a second fault in the same\n" +
        "  // call, and the refusal thrown below is the verdict, so a\n" +
        "  // release that refuses here must not replace it.\n" +
        "  try { g(); } catch (e) { return null; }\n}\n" },
    { what: "above a single-line try opener, so the block sits with the statement " +
        "rather than with whichever half of it the catch keyword landed on",
      src: "function f() {\n" +
        "  // " + MARKER + " reaching this needs a second fault in the same\n" +
        "  // call, and the write's own refusal is rethrown below.\n" +
        "  try { nodeFs.rmSync(target); }\n" +
        "  catch (e) { return null; }\n}\n" },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    count("isMarked: the marker is read " + cases[i].what, markedIn(cases[i].src) === true);
  }
}

// The other edge. A marker has to stay attached to the catch it was
// written for, or one of them silences a swallow nobody looked at.
function theMarkerDoesNotReachPastTheCodeItIsWrittenAbove() {
  var acrossCode = "function f() {\n" +
    "  // " + MARKER + " this one is about the call below it\n" +
    "  h();\n" +
    "  var x = 1;\n" +
    "  try { g(); }\n" +
    "  catch (e) { return null; }\n}\n";
  count("isMarked: a marker separated from the catch by ordinary code does not mark it",
    markedIn(acrossCode) === false);

  var earlierSwallow = "function f() {\n" +
    "  try { g(); }\n" +
    "  catch (e) { return null; }\n" +
    "  // " + MARKER + " this one belongs to the catch below\n" +
    "  try { h(); } catch (e2) { return null; }\n}\n";
  var lines = earlierSwallow.split("\n");
  var found = swallowsIn(earlierSwallow);
  count("isMarked: two swallows and one marker written between them",
    found.length === 2, "found " + found.length);
  count("isMarked: the marker does not reach backwards to the catch above it",
    gate.isMarked(lines, found[0].startLine, found[0].endLine) === false);
  count("isMarked: and it does mark the one it was written above",
    gate.isMarked(lines, found[1].startLine, found[1].endLine) === true);

  var unmarked = "function f() {\n  try { g(); }\n  catch (e) { return null; }\n}\n";
  count("isMarked: a swallow with no marker anywhere near it is unmarked",
    markedIn(unmarked) === false);
}

// The walk upward steps over the opener of the statement the catch belongs
// to, so a block written above `try { ... }` reaches the `catch` on the next
// line. A COMPLETE single-line `try { ... } catch (e) { ... }` opens with the
// same word, and stepping over one of those carries the marker to a catch it
// was not written for. Nothing bounds how many it carries across: every
// adjacent statement of that shape is one more step, so one marker answers
// for a whole run of swallows and the file reads as though each of them had
// been thought about.
function theMarkerDoesNotReachOverACompleteTryCatchStatement() {
  var adjacent = "function f() {\n" +
    "  // " + MARKER + " this one is about the write directly below it\n" +
    "  try { g(); } catch (e) { return null; }\n" +
    "  try { h(); } catch (e2) { return null; }\n" +
    "  try { k(); } catch (e3) { return null; }\n}\n";
  var lines = adjacent.split("\n");
  var found = swallowsIn(adjacent);
  count("isMarked: three adjacent single-line statements and one marker above the first",
    found.length === 3, "found " + found.length);
  count("isMarked: the marker marks the statement it is written above",
    gate.isMarked(lines, found[0].startLine, found[0].endLine) === true);
  count("isMarked: it does not reach over that complete statement to the next one",
    gate.isMarked(lines, found[1].startLine, found[1].endLine) === false);
  count("isMarked: nor to the one after that, which is what an unbounded walk gives",
    gate.isMarked(lines, found[2].startLine, found[2].endLine) === false);

  // The same over-reach with the statement spelled `} catch`, which is the
  // other way a complete try/catch fits on one line.
  var closingBraceForm = "function f() {\n" +
    "  // " + MARKER + " this one is about the write directly below it\n" +
    "  try { g(); } catch (e) { return null; }\n" +
    "  try {\n    h();\n  } catch (e2) { return null; }\n}\n";
  var braceLines = closingBraceForm.split("\n");
  var braceFound = swallowsIn(closingBraceForm);
  count("isMarked: a following multi-line try is not marked through the statement above it",
    gate.isMarked(braceLines, braceFound[1].startLine, braceFound[1].endLine) === false);
}

// A marker written for a cleanup nested INSIDE a catch body sits on a line
// the enclosing catch also spans, so the in-body scan reads it for both. The
// enclosing swallow is then reported as marked by a sentence that describes
// something else, and the reason a reader would check answers about the
// inner call.
function aMarkerWrittenForAnInnerCleanupDoesNotMarkTheEnclosingCatch() {
  var nested = "function f() {\n" +
    "  try { g(); }\n" +
    "  catch (e) {\n" +
    "    record(e);\n" +
    "    try { cleanup(); }\n" +
    "    catch (e2) {\n" +
    "      // " + MARKER + " reaching this needs the cleanup to fault as well\n" +
    "    }\n" +
    "    return null;\n" +
    "  }\n}\n";
  var lines = nested.split("\n");
  var found = swallowsIn(nested);
  count("isMarked: an outer catch and the cleanup catch inside it are two swallows",
    found.length === 2, "found " + found.length);
  count("isMarked: the marker marks the cleanup it is written in",
    gate.isMarked(lines, found[1].startLine, found[1].endLine) === true);
  count("isMarked: and the enclosing catch, which spans that line, is not marked by it",
    gate.isMarked(lines, found[0].startLine, found[0].endLine) === false);

  // The other placement of the same mistake: the reason is written as a
  // comment block ABOVE the inner statement rather than inside its catch.
  var above = "function f() {\n" +
    "  try { g(); }\n" +
    "  catch (e) {\n" +
    "    record(e);\n" +
    "    // " + MARKER + " reaching this needs the cleanup to fault as well\n" +
    "    try { cleanup(); } catch (e2) { /* drop-silent */ }\n" +
    "    return null;\n" +
    "  }\n}\n";
  var aboveLines = above.split("\n");
  var aboveFound = swallowsIn(above);
  count("isMarked: a block above the inner statement marks the inner statement",
    gate.isMarked(aboveLines, aboveFound[1].startLine, aboveFound[1].endLine) === true);
  count("isMarked: and not the catch that encloses it",
    gate.isMarked(aboveLines, aboveFound[0].startLine, aboveFound[0].endLine) === false);

  // The enclosing catch keeps its own marker when one is written for it: the
  // block directly above the catch, and the leading comment of its body.
  var ownAbove = "function f() {\n" +
    "  try { g(); }\n" +
    "  // " + MARKER + " the outer one, written for the outer one\n" +
    "  catch (e) {\n" +
    "    try { cleanup(); } catch (e2) { /* drop-silent */ }\n" +
    "    return null;\n" +
    "  }\n}\n";
  count("isMarked: an enclosing catch is still marked by the block written above it",
    gate.isMarked(ownAbove.split("\n"), swallowsIn(ownAbove)[0].startLine,
      swallowsIn(ownAbove)[0].endLine) === true);

  var ownInside = "function f() {\n" +
    "  try { g(); }\n" +
    "  catch (e) {\n" +
    "    // " + MARKER + " the outer one, written for the outer one\n" +
    "    return null;\n" +
    "  }\n}\n";
  count("isMarked: and by the comment that opens its own body",
    markedIn(ownInside) === true);

  // The shape the real sites are written in: an enclosing catch that
  // RE-THROWS, so it is not a swallow and never asks for a marker, with the
  // reason for the cleanup inside it written as the block above that
  // cleanup. The block opens the enclosing catch's body as well, and the
  // marker still belongs to the one swallow in the function.
  var rethrowingOuter = "function f() {\n" +
    "  try { write(); }\n" +
    "  catch (writeError) {\n" +
    "    // " + MARKER + " reaching this needs a second fault in the same\n" +
    "    // call, and the write's own refusal is rethrown below.\n" +
    "    try { undo(); }\n" +
    "    catch (_undoError) { /* drop-silent */ }\n" +
    "    throw writeError;\n" +
    "  }\n}\n";
  count("isMarked: a cleanup inside a re-throwing catch is marked by the block above it",
    markedIn(rethrowingOuter) === true);
}

// The reach rules decide, one catch at a time, which marker is attached to
// it. Asked from the other end the same invariant needs no reach rule and
// cannot be got wrong: a written reason answers for ONE swallow. Two behind
// one sentence means the sentence describes at most one of them.
function aMarkerAnswersForOneSwallow() {
  count("sharedMarkers: a marker excusing one swallow is not shared",
    gate.sharedMarkers({ "lib/a.js:10": ["lib/a.js:12 catch (e)"] }).length === 0);

  var shared = gate.sharedMarkers({
    "lib/a.js:10": ["lib/a.js:12 catch (e)", "lib/a.js:20 catch (e2)"],
    "lib/b.js:4":  ["lib/b.js:6 catch (e)"],
  });
  count("sharedMarkers: a marker excusing two is reported",
    shared.length === 1, "reported " + shared.length);
  count("sharedMarkers: named by the marker line, so a reader can open it",
    shared.length === 1 && shared[0].marker === "lib/a.js:10");
  count("sharedMarkers: with both swallows listed, since either could be the one meant",
    shared.length === 1 && shared[0].swallows.length === 2);

  // The residual shape: a block that both opens a swallowing catch's body
  // and sits directly above a nested statement. No rule over one catch at a
  // time can say which of the two it was written for, so both read it and
  // the gate refuses the line rather than picking one.
  var ambiguous = "function f() {\n" +
    "  try { g(); }\n" +
    "  catch (e) {\n" +
    "    // " + MARKER + " which of the two is this about\n" +
    "    try { cleanup(); } catch (e2) { /* drop-silent */ }\n" +
    "    return null;\n" +
    "  }\n}\n";
  var lines = ambiguous.split("\n");
  var found = swallowsIn(ambiguous);
  var outerAt = gate.markerLineFor(lines, found[0].startLine, found[0].endLine);
  var innerAt = gate.markerLineFor(lines, found[1].startLine, found[1].endLine);
  count("markerLineFor: reports the line a swallow was excused by, not just that it was",
    outerAt === 4, "outer read line " + outerAt);
  count("markerLineFor: and both swallows here read the same line",
    innerAt === outerAt, "inner read line " + innerAt);
  var claims = {};
  claims["lib/probe.js:" + outerAt] = ["outer", "inner"];
  count("sharedMarkers: which the gate refuses rather than attributing to one of them",
    gate.sharedMarkers(claims).length === 1);
}

// ---- runner ---------------------------------------------------------------

async function run() {
  theFinderSeparatesPropagationFromSwallowing();
  theFinderDoesNotReadThrowOutOfProseOrStrings();
  theFinderReportsTheCatchsOwnLines();
  theMarkerIsReadInEveryShapeItIsWrittenIn();
  theMarkerDoesNotReachPastTheCodeItIsWrittenAbove();
  theMarkerDoesNotReachOverACompleteTryCatchStatement();
  aMarkerWrittenForAnInnerCleanupDoesNotMarkTheEnclosingCatch();
  aMarkerAnswersForOneSwallow();
  return helpers.getChecks();
}

module.exports = { name: "swallow-gate", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
