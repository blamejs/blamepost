// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The planted set `scripts/check-regex-growth.js` proves itself against.
 *
 * Nothing here runs. The file exists to be read by that gate's own literal
 * scanner, in ordinary code positions rather than as a list of pattern
 * strings, so a run exercises the scanner, the alphabet builder, the
 * subject builder and the judge together.
 *
 * Every regex literal below carries its expectation as a trailing comment
 * on its own line, in one of two words. The growing half must be named by
 * the gate; the flat half must be left alone. Two directions rather than
 * one: a threshold that misses a quadratic pattern makes the gate useless,
 * and a threshold that names an ordinary one makes it a gate people learn
 * to route around, and only holding both edges pins it between them.
 *
 * The expectation lives on the literal's own line and nowhere else, so
 * there is no second list of what is planted to fall out of step with what
 * is written. One literal per marked line: a verdict on a line carrying two
 * cannot be attributed to either.
 *
 * The growing half is chosen to cover the ways this instrument has been
 * blind before, not just the shapes that are easy to write:
 *
 *   - A negated class with no start anchor, which is the shape that was
 *     live in this tree: a run of the opening character costs the engine a
 *     full retry from every position.
 *   - A quantified run of an ESCAPED punctuation mark, which needs the
 *     alphabet builder to read `\/` as a literal slash. Reading it as
 *     nothing leaves the pattern measured against letters it rejects at the
 *     first character of every position, which is a reading of nothing
 *     printed as a pass.
 *   - A run that only backtracks when a terminator follows it, which needs
 *     the subject builder to append a character the pattern refuses. A
 *     plain run of the character a quantifier wants usually matches on the
 *     first attempt and costs nothing.
 *   - A nested quantifier, whose cost is exponential rather than quadratic
 *     and which therefore has to be caught at a length where it is still
 *     cheap.
 *   - A literal written after `return`, where the character before the
 *     slash is a letter and a scanner that reads letters as division never
 *     sees the pattern at all.
 */

// ---------------------------------------------------------------------------
// The growing half
// ---------------------------------------------------------------------------

// An unanchored tag matcher over a body that never closes a bracket.
var TAG = /<[^>]*>/g;                                            // GROWS

// A quantified run of an escaped punctuation mark.
var TRAILING_SLASHES = /\/+$/;                                   // GROWS

// A quantified class that only backtracks when the anchor fails.
var TRAILING_SPACE = /\s*$/;                                     // GROWS

// A nested quantifier.
var NESTED = /^(a+)+$/;                                          // GROWS

// A quantified group holding its own quantifier, with a trailing anchor.
var WORD_RUN = /(\w+\s?)*$/;                                     // GROWS

// An unanchored address shape: every start position re-walks the run.
var ADDRESS = /[a-z]+@[a-z]+\.[a-z]+/;                           // GROWS

// An unanchored dotted run: every start position re-walks the digits
// before failing to find the separator.
var DOTTED_RUN = /(?:\d+\.)+\d+/;                                // GROWS

// A literal in a position a scanner that reads a preceding letter as
// division never reaches.
function looksNumeric(s) {
  return /(\d+)*x/.test(s);                                      // GROWS
}

// ---------------------------------------------------------------------------
// The flat half
// ---------------------------------------------------------------------------

var LOWER_WORD = /^[a-z]+$/;                                     // FLAT

var LINE_BREAK = /\r?\n/;                                        // FLAT

var MARKUP_CHARS = /[<>&"']/g;                                   // FLAT

var DOTTED_QUAD = /^(?:\d{1,3}\.){3}\d{1,3}$/;                   // FLAT

var TOKEN = /[A-Za-z0-9_-]{1,64}/;                               // FLAT

var ANCHORED_ADDRESS = /^[\w.-]+@[\w.-]+$/;                      // FLAT

var HEADER_LINE = /[^\r\n]{0,998}/;                              // FLAT

// The pattern most often quoted as catastrophic, and it is not. Its two
// classes accept no character in common, so there is only one way to split
// any subject between them and the engine never has an alternative to go
// back to. A gate that fired on the SHAPE of a quantified group inside a
// quantified group would name it; one that measures does not.
var SPLIT_WORDS = /^\s*(\S+\s+)*\S+$/;                           // FLAT

function mentionsWord(s) {
  return /\bfoo\b/.test(s);                                      // FLAT
}

module.exports = {
  TAG:              TAG,
  TRAILING_SLASHES: TRAILING_SLASHES,
  TRAILING_SPACE:   TRAILING_SPACE,
  NESTED:           NESTED,
  WORD_RUN:         WORD_RUN,
  ADDRESS:          ADDRESS,
  DOTTED_RUN:       DOTTED_RUN,
  looksNumeric:     looksNumeric,
  LOWER_WORD:       LOWER_WORD,
  LINE_BREAK:       LINE_BREAK,
  MARKUP_CHARS:     MARKUP_CHARS,
  DOTTED_QUAD:      DOTTED_QUAD,
  TOKEN:            TOKEN,
  ANCHORED_ADDRESS: ANCHORED_ADDRESS,
  HEADER_LINE:      HEADER_LINE,
  SPLIT_WORDS:      SPLIT_WORDS,
  mentionsWord:     mentionsWord,
};
