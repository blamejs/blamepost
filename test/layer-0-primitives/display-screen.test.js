// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * display-screen: the one screen between text a stranger wrote and a
 * person reading it.
 *
 * Eight places in this server used to answer this question, and they
 * answered it differently. Each composed the framework's balanced
 * profile, each took the C1 range off afterwards, three folded a tab to a
 * space and five did not, one folded the whole carriage return and line
 * feed run and the rest left it. A subject that misaligned a console
 * table was safe on the browser page, and a record value that read as one
 * line in the browser broke the zone diff into three.
 *
 * So the screen is one reader now, and this file is what that reader
 * promises.
 *
 * WHAT IT REMOVES. Bidirectional overrides, zero-width and invisible
 * formatting characters, the Unicode Tags block, null bytes and the C0
 * controls, all of which the balanced profile takes. The C1 range at
 * U+0080 to U+009F on top of it, because the balanced profile leaves that
 * range and U+009B is the single-byte form of CSI, the escape introducer
 * a terminal acts on.
 *
 * WHAT IT FOLDS. Tab, line feed and carriage return become a space. Those
 * three are the C0 characters the balanced profile keeps, because they
 * are ordinary in free text, and the values screened here are single
 * lines: a subject in a table column, a refusal quoting what it refused, a
 * record value in a diff. A caller holding several lines splits them and
 * screens each one.
 *
 * WHAT SURVIVES. Every writing system. A screen that damaged Arabic,
 * Japanese or an emoji would be an outage for everyone who writes in
 * them, which is worse than the problem it closes.
 *
 * WHAT IT REFUSES. Nothing. Repairing is the posture a diagnostic needs:
 * throwing over the shape of the text would lose the refusal the message
 * exists to explain. The refusal half is the other primitive here, which
 * answers whether a value carries any of those characters at all, and it
 * is what a write gate asks before storing a field.
 *
 * No sockets, no database, no network.
 *
 * Run standalone: node test/layer-0-primitives/display-screen.test.js
 */

var helpers = require("../helpers");
var text    = require("../../lib/text");

var count = helpers.count;

// Built from code points rather than typed, so this file carries no
// invisible character of its own and no C1 octet, which does not survive
// being written into a source file at all.
var CSI    = String.fromCharCode(0x9b);   // C1 control sequence introducer
var NEL    = String.fromCharCode(0x85);   // C1 next line
var PAD    = String.fromCharCode(0x80);   // the first C1 code point
var APC    = String.fromCharCode(0x9f);   // the last C1 code point
var TAB    = String.fromCharCode(0x09);
var LF     = String.fromCharCode(0x0a);
var CR     = String.fromCharCode(0x0d);
var NUL    = String.fromCharCode(0x00);
var DEL    = String.fromCharCode(0x7f);
var ESC    = String.fromCharCode(0x1b);
var RLO    = String.fromCharCode(0x202e);   // right-to-left override
var ZWS    = String.fromCharCode(0x200b);   // zero width space

var ARABIC = "تقرير ربع سنوي";
var CJK    = "四半期レポート";
var EMOJI  = "👩‍👩‍👧";

// The vectors this file drives, published so a run that exercised one
// group and a run that exercised all of them do not report the same
// total in silence.
var SCREEN_GROUPS_EXAMINED = 6;

// ---------------------------------------------------------------------------
// forDisplay
// ---------------------------------------------------------------------------

function theC1RangeIsRemoved() {
  var screened = text.forDisplay("Quarterly" + CSI + "2K" + CSI + "31m report");
  count("the single-byte CSI is gone from a screened value",
    screened.indexOf(CSI) === -1, JSON.stringify(screened));
  count("and the text around it is still there to read",
    screened.indexOf("Quarterly") !== -1 && screened.indexOf("report") !== -1,
    JSON.stringify(screened));

  [["PAD, the first", PAD], ["NEL, the middle", NEL], ["APC, the last", APC]].forEach(
    function (pair) {
      var out = text.forDisplay("before" + pair[1] + "after");
      count("the C1 code point " + pair[0] + ", does not survive the screen",
        out === "beforeafter", JSON.stringify(out));
    });
}

function theC0RangeAndDeleteAreRemoved() {
  [["a null byte", NUL], ["the escape", ESC], ["delete", DEL]].forEach(function (pair) {
    var out = text.forDisplay("before" + pair[1] + "after");
    count(pair[0] + " does not survive the screen", out === "beforeafter", JSON.stringify(out));
  });
}

// The half the eight screens disagreed about. A value shown on one line
// carries no character that starts a second one, and none that moves the
// reader across a column that a heading is sitting over.
function tabLineFeedAndCarriageReturnBecomeASpace() {
  count("a tab in a screened value becomes a space",
    text.forDisplay("held" + TAB + "since Tuesday") === "held since Tuesday",
    JSON.stringify(text.forDisplay("held" + TAB + "since Tuesday")));
  count("a line feed becomes a space",
    text.forDisplay("first" + LF + "second") === "first second",
    JSON.stringify(text.forDisplay("first" + LF + "second")));
  count("a carriage return becomes a space",
    text.forDisplay("first" + CR + "second") === "first second",
    JSON.stringify(text.forDisplay("first" + CR + "second")));
  count("a carriage return and line feed pair becomes two spaces rather than a new line",
    text.forDisplay("first" + CR + LF + "second") === "first  second",
    JSON.stringify(text.forDisplay("first" + CR + LF + "second")));

  var row = text.forDisplay("250 2.0.0 accepted" + CR + LF + "550 5.7.1 rejected");
  count("a value forging a second line of a transcript stays on one line",
    row.indexOf(LF) === -1 && row.indexOf(CR) === -1, JSON.stringify(row));
}

function theInvisiblesAreRemoved() {
  var flipped = text.forDisplay("Invoice " + RLO + "gpj.exe");
  count("a bidirectional override does not survive the screen",
    flipped.indexOf(RLO) === -1, JSON.stringify(flipped));
  var padded = text.forDisplay("Pay" + ZWS + "Pal");
  count("a zero-width space does not survive the screen",
    padded.indexOf(ZWS) === -1, JSON.stringify(padded));
}

// The other half of the claim. A screen that damaged the world's writing
// systems would be worse than the problem it closes.
function legitimateTextIsUntouched() {
  count("Arabic is screened unchanged", text.forDisplay(ARABIC) === ARABIC,
    JSON.stringify(text.forDisplay(ARABIC)));
  count("Japanese is screened unchanged", text.forDisplay(CJK) === CJK,
    JSON.stringify(text.forDisplay(CJK)));
  count("an ordinary sentence is screened unchanged",
    text.forDisplay("Delivery to bob@example.net was refused.") ===
      "Delivery to bob@example.net was refused.",
    JSON.stringify(text.forDisplay("Delivery to bob@example.net was refused.")));
}

// A multi-part emoji is joined by a zero-width joiner, which the balanced
// profile removes, so it comes apart into its people. That is why the
// reader is for single-line values a person reads rather than for message
// bodies, and the case is here so the boundary is measured rather than
// assumed.
function aJoinedEmojiComesApart() {
  count("a zero-width-joined emoji is not carried through the screen intact",
    text.forDisplay(EMOJI) !== EMOJI, JSON.stringify(text.forDisplay(EMOJI)));
}

function whatIsNotAStringIsStillAnswered() {
  count("null screens to the empty string", text.forDisplay(null) === "",
    JSON.stringify(text.forDisplay(null)));
  count("undefined screens to the empty string", text.forDisplay(undefined) === "",
    JSON.stringify(text.forDisplay(undefined)));
  count("a number screens to its own text", text.forDisplay(451) === "451",
    JSON.stringify(text.forDisplay(451)));
  count("the empty string screens to the empty string", text.forDisplay("") === "",
    JSON.stringify(text.forDisplay("")));
}

// Screening a diagnostic must never cost the diagnostic. A value the
// guard will not take answers with a sentence saying so rather than with
// an empty string, which a reader takes for a refusal carrying no words.
function aValueTheGuardRefusesStillAnswers() {
  var enormous = "a".repeat(5 * 1024 * 1024);
  var out = text.forDisplay(enormous);
  count("a value past the guard's own ceiling is answered rather than thrown over",
    typeof out === "string" && out.length > 0, typeof out);
  count("and the answer says the value could not be rendered rather than reading as empty",
    out === text.UNRENDERABLE, JSON.stringify(out.slice(0, 80)));
}

// The other way the screen can be handed something it cannot read, and
// the one the guard never sees. `forDisplay` converts a value to text
// before the guard is asked, so a shape whose CONVERSION throws takes the
// diagnostic with it, which is the outcome this function exists to
// prevent. Its own block says a caller may hold "a shape it did not
// choose", so the conversion is part of the promise rather than a caller
// error.
//
// A value with no prototype has no `toString` to call, and an object may
// carry a `toString` or a `Symbol.toPrimitive` that throws. None of the
// three is exotic: the first is what `Object.create(null)` builds, which
// is the ordinary way to make a map with no inherited keys.
function aShapeThatCannotBecomeTextStillAnswers() {
  var throwingToString = { toString: function () { throw new Error("boom"); } };
  var throwingPrimitive = {};
  throwingPrimitive[Symbol.toPrimitive] = function () { throw new Error("boom"); };

  [["a value with no prototype", Object.create(null)],
    ["a value whose toString throws", throwingToString],
    ["a value whose Symbol.toPrimitive throws", throwingPrimitive],
  ].forEach(function (pair) {
    var out;
    var threw = null;
    try { out = text.forDisplay(pair[1]); } catch (e) { threw = e; }
    count("screening " + pair[0] + " answers rather than throwing",
      threw === null, threw === null ? "answered" : threw.name + ": " + threw.message);
    count("and " + pair[0] + " answers with the sentence saying so",
      threw === null && out === text.UNRENDERABLE,
      threw === null ? JSON.stringify(String(out).slice(0, 60)) : "threw");
  });
}

// ---------------------------------------------------------------------------
// hasControlChar
// ---------------------------------------------------------------------------

// The write-gate half. A field stored with one of these in it is a field
// every later reader has to remember to screen, so the gate that accepts
// it asks once.
function theRefusalPredicateCoversEveryControlRange() {
  [["a null byte", NUL], ["the escape", ESC], ["a tab", TAB], ["a line feed", LF],
    ["a carriage return", CR], ["delete", DEL], ["the C1 CSI", CSI],
    ["the first C1 code point", PAD], ["the last C1 code point", APC],
  ].forEach(function (pair) {
    count("a value carrying " + pair[0] + " is reported as carrying a control character",
      text.hasControlChar("Dana" + pair[1] + "Reyes") === true, JSON.stringify(pair[0]));
  });

  count("an ordinary name carries none", text.hasControlChar("Dana Reyes") === false,
    "Dana Reyes");
  count("a name in Arabic carries none", text.hasControlChar(ARABIC) === false, ARABIC);
  count("a name in Japanese carries none", text.hasControlChar(CJK) === false, CJK);
  count("a bidirectional override is not a control character, and is refused elsewhere",
    text.hasControlChar("Dana" + RLO + "Reyes") === false, "bidi is the guard's question");
  count("the empty string carries none", text.hasControlChar("") === false, "empty");
}

// ---- runner ----------------------------------------------------------------

function run() {
  theC1RangeIsRemoved();
  theC0RangeAndDeleteAreRemoved();
  tabLineFeedAndCarriageReturnBecomeASpace();
  theInvisiblesAreRemoved();
  legitimateTextIsUntouched();
  aJoinedEmojiComesApart();
  whatIsNotAStringIsStillAnswered();
  aValueTheGuardRefusesStillAnswers();
  aShapeThatCannotBecomeTextStillAnswers();
  theRefusalPredicateCoversEveryControlRange();

  console.log("EXAMINED " + SCREEN_GROUPS_EXAMINED + " screen-groups");
  return helpers.getChecks();
}

module.exports = {
  name:      "display-screen",
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
