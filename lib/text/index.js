// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.text
 * @nav    Server and configuration
 * @title  Text on its way to a person
 * @order  40
 *
 * The screen between text somebody else wrote and somebody here reading
 * it.
 *
 * A mail server shows its operator, and its account holders, a great deal
 * of text that neither of them wrote. A subject and a sender's name come
 * off a message a stranger sent. A refusal reason is the words a far side
 * gave. A record value is what a third party published in their own zone.
 * A provider's error body is whatever that provider returned. A filter
 * script and a mailbox name are what the account holder typed. Every one
 * of those is printed into a terminal, a structured log line, an audit
 * row and a rendered page, and the reading is where the harm is: a
 * bidirectional override shows a file named `Invoice exe.jpg` when the
 * bytes say `gpj.exe`, and the single-byte control sequence introducer at
 * U+009B repaints the row above the one it is on.
 *
 * It is a module of its own because it is none of the others. The five
 * domains that need it are the mail listeners, the store, the browser
 * surface, the DNS writer and the command line, and putting the screen
 * inside any one of them makes the other four require across a boundary
 * that runs the wrong way: the store would reach into the mail layer for
 * a display question, and the DNS writer into the browser. It holds one
 * subject, and the rule that admits anything else here is that the new
 * function answers the same question this one does.
 *
 * WHAT IT IS BUILT ON. `b.guardText` owns the codepoint threat catalogue
 * and `b.codepointClass` owns the range tables. Neither is re-implemented
 * here. What this module adds is the two things the framework's balanced
 * profile leaves behind, and the fact that there is now one answer rather
 * than eight.
 *
 * THE BALANCED PROFILE, AND WHY. It repairs rather than refuses. That is
 * the posture a diagnostic needs: a refusal quotes the input it refused,
 * because that is the only way the person who wrote it can see what was
 * wrong, and throwing over the shape of the quoted text would lose the
 * refusal the message exists to explain. The strict profile also reports
 * ordinary Japanese as a mixed-script confusable, so it would turn
 * hostile mail and legitimate mail into the same outage.
 *
 * THE TWO THINGS ADDED. The profile passes the C1 range at U+0080 to
 * U+009F, which is the single-byte form of the escape sequences the C0
 * range spells with two bytes, so that range is removed. And it passes
 * tab, line feed and carriage return, which are ordinary in free text and
 * are not ordinary in a value shown on one line, so those three become a
 * space.
 *
 * ONE LINE IS THE CONTRACT. Every value this screen is for is read on one
 * line: a column in a console table, a refusal sentence, a record value
 * in a zone diff, a subject in a folder listing. A caller holding several
 * lines splits them first and screens each one, which is what the reply
 * quoting in the browser surface does. Folding rather than removing is
 * what keeps two words from running together where a line break was.
 *
 * WHAT IT DOES NOT DO. It does not refuse markup, at any profile. The
 * template's own escaping is what stops a decoded script tag reaching a
 * browser, and that control is separate and load bearing. It does not
 * touch what is stored: the value on the volume stays as it arrived, so
 * a record of what a peer actually sent survives, and the screen runs on
 * every read.
 *
 * THE OTHER HALF. `hasControlChar` is the refusal side, for a field this
 * server accepts and stores rather than one it is showing. An account's
 * display name is the case: it is written into outbound headers and into
 * every surface that names the account, so a control character in one is
 * refused where it is written rather than repaired at each of the places
 * it is read.
 *
 * AFTER A VENDOR REFRESH. blamejs 0.20.30 adds the C1 range to
 * `b.codepointClass.CTRL_RANGES` and to `isForbiddenControlChar`, which
 * makes the C1 half of both functions here redundant: the balanced
 * profile strips the range on its own, and `firstControlCharOffset`
 * reports it. The whitespace fold stays, because `C0_CTRL_RANGES` still
 * exempts tab, line feed and carriage return at that version and the
 * balanced profile still passes all three.
 */

var b = require("../vendor/blamejs");

// The profile every display screen in this server runs. Balanced rather
// than strict, for the reason the module block gives above.
var DISPLAY_GUARD = Object.freeze({ profile: "balanced" });

// The C1 controls. The balanced profile passes them, and U+009B is CSI:
// one code point that opens an escape sequence, so a value carrying it
// colors or moves whatever reads it as a stream.
var C1_RANGES = Object.freeze([[0x0080, 0x009f]]);

// Tab, line feed, vertical tab, form feed and carriage return. The
// profile removes the middle two with the rest of the C0 range and keeps
// the other three, because RFC 5322 section 3.2.2 counts tab as folding
// whitespace and the other two end a line. The whole run is named in one
// range because the result is the same either way and one range is one
// thing to read.
var FOLD_RANGES = Object.freeze([[0x0009, 0x000d]]);

// Every control character a stored field is refused for: the C0 range,
// the delete code point and the C1 range. Wider than the framework's
// `CTRL_RANGES`, which exempts tab, line feed and carriage return
// because they are ordinary in free text. They are not ordinary in a
// name that is written into a header and printed in a table.
var REFUSED_RANGES = Object.freeze([[0x0000, 0x001f], 0x007f, [0x0080, 0x009f]]);

// What a value answers with when the guard will not take it at all. A
// sentence rather than an empty string, which a reader takes for a
// refusal that carried no words.
var UNRENDERABLE = "this value could not be rendered safely";

/**
 * @primitive blamepost.text.forDisplay
 * @signature blamepost.text.forDisplay(value)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one screen between somebody else's text and a reader)
 * @related   blamepost.text.hasControlChar
 *
 * One value made safe to print, on one line. Every place this server
 * shows text a stranger wrote goes through here: a console table, a log
 * line, an audit row, a refusal sentence, a zone diff and a rendered
 * page.
 *
 * Removed: bidirectional overrides, zero-width and invisible formatting
 * characters, the Unicode Tags block, null bytes, the C0 controls and
 * the C1 controls. Folded to a space: tab, line feed and carriage
 * return. Left alone: every writing system, so Arabic, Hebrew, Japanese
 * and an emoji arrive as themselves.
 *
 * `null` and `undefined` answer with the empty string, and anything else
 * that is not a string is read as its own text first, so a caller
 * holding a number or a shape it did not choose still gets a string back.
 *
 * It never throws. Screening a diagnostic must not cost the diagnostic,
 * so a value the guard will not take at all answers with a sentence
 * saying so.
 *
 * A caller holding several lines splits them and calls this on each,
 * because the fold is what makes a single-line value safe and is not what
 * a message body wants.
 *
 * @example
 *   var text = require("./lib/text");
 *   text.forDisplay("held\tsince Tuesday");
 *   // "held since Tuesday"
 */
function forDisplay(value) {
  if (value === null || value === undefined) return "";
  try {
    // The conversion is inside the try because it is part of the promise
    // above, not a step before it. A value with no prototype has no
    // `toString` to call, and an object may carry a `toString` or a
    // `Symbol.toPrimitive` that throws, so reading a shape the caller did
    // not choose can fail on its own before any guard is asked.
    var raw = typeof value === "string" ? value : String(value);
    if (raw.length === 0) return "";
    return b.codepointClass.replaceRanges(
      b.codepointClass.replaceRanges(
        b.guardText.sanitize(raw, DISPLAY_GUARD), C1_RANGES, ""),
      FOLD_RANGES, " ");
  } catch (_e) {
    // Drop-silent by design: the caller is holding a refusal or a report
    // that has to reach somebody, and a screen that threw would take it
    // with it.
    return UNRENDERABLE;
  }
}

/**
 * @primitive blamepost.text.hasControlChar
 * @signature blamepost.text.hasControlChar(text)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: one control-character table for stored fields)
 * @related   blamepost.text.forDisplay
 *
 * Whether a value carries a character a reader would act on rather than
 * see: the C0 controls including tab, line feed and carriage return, the
 * delete code point, and the C1 controls.
 *
 * This is the write side. A field a caller is storing and this server
 * will later print in a header, a table and a page is refused here once,
 * rather than repaired at each of the places it is read. A value that is
 * not a string carries nothing, because there is nothing in it to carry.
 *
 * It answers about control characters and nothing else. Bidirectional
 * overrides, zero-width characters and mixed scripts are
 * `b.guardText.validate`'s question, and a write gate asks both.
 *
 * @example
 *   var text = require("./lib/text");
 *   text.hasControlChar("Dana Reyes");
 *   // false
 */
function hasControlChar(text) {
  if (typeof text !== "string" || text.length === 0) return false;
  return b.codepointClass.firstInRanges(text, REFUSED_RANGES) !== -1;
}

module.exports = {
  forDisplay:     forDisplay,
  hasControlChar: hasControlChar,
  UNRENDERABLE:   UNRENDERABLE,
};
