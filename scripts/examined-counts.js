// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/examined-counts.js
 *
 * The one reader of the published-count contract.
 *
 * WHAT THE CONTRACT IS. A gate publishes what it examined as trailing lines
 * of stdout:
 *
 *   EXAMINED <n> <unit>
 *
 * one line per unit it answers for, on a passing run and a failing one
 * alike. The detector suite publishes `CHECKS <n>` instead, a count with no
 * unit, frozen in that spelling because test/smoke.js reads it too.
 *
 * WHY THE COUNT EXISTS. "OK, no findings" is byte-identical whether the gate
 * read every file in the tree or none of them. A glob that stopped matching,
 * a walk pointed at a directory that moved, reads resolved against the wrong
 * base: all of them land on a clean verdict over an empty set, and a clean
 * verdict over an empty set answers for no part of the tree. The number is
 * the only thing that tells them apart.
 *
 * WHY THE READER IS ONE FILE. Three callers read these lines: the runner
 * that executes the declared chain, the release battery, and the layer-0
 * cases that hold both to the contract. Three copies of "read the last
 * lines, refuse a zero" is three places for the refusal to quietly differ,
 * and the one that drifts is the one nobody watches run.
 *
 * HOW THE LINES ARE FOUND. From the END of stdout, stopping at the first
 * line that is not one of them. That keeps the contract cheap for the gate,
 * which prints its ordinary human report and then its counts, and it means a
 * gate that prints its counts and then says something else stops being
 * counted, which is the intended reading: the counts are the last word.
 *
 * WHY THE PUBLISHER IS HERE TOO. A reader only speaks for the gates somebody
 * SPAWNS. Several gates are invoked bare instead: by a workflow step, by an
 * npm lifecycle hook, by a line in the release flow that wants the verdict and
 * not the transcript. Nothing captures their stdout, so nothing reads the count
 * they publish, and their exit code is the whole of what they say. A gate in
 * that position has to refuse its own empty set or the refusal does not exist
 * for it at all.
 *
 * `publish` below is that half. It is here rather than copied into each gate
 * for the reason the reader is: the two halves are one contract, and a
 * publisher that spelled a unit differently from what the reader parses would
 * be a gate answering into the void with nobody able to say so. Each gate still
 * owns its OWN units, which is the part that must not be centralized. A second
 * file that knew which gate answers in which unit would be the hand-maintained
 * list this repository keeps being bitten by.
 */

// One count line: a token, a number, and an optional unit. The unit is
// lowercase-with-hyphens so a sentence ending in a capitalised word cannot
// be mistaken for one.
var COUNT_LINE_RE = /^([A-Z]+)\s+(\d+)(?:\s+([a-z0-9-]+))?$/;

var DEFAULT_TOKENS = ["EXAMINED"];

/**
 * publishedCounts(stdout, tokens?) -> [ { token, n, unit } ]
 *
 * The counts a gate published, in the order it printed them. `tokens` is the
 * set of count words this caller accepts, defaulting to `EXAMINED` alone; a
 * caller expecting `CHECKS` passes that instead, so a gate that answered in
 * the wrong vocabulary reads as one that did not answer rather than as one
 * that did.
 *
 * An empty array means the gate published nothing this caller can read,
 * which is never a pass.
 */
function publishedCounts(stdout, tokens) {
  var accepted = Array.isArray(tokens) && tokens.length > 0 ? tokens : DEFAULT_TOKENS;
  // Trailing whitespace is stripped BEFORE the scan. A gate's stdout ends
  // with a newline, so the last element of a raw split is the empty string,
  // and a scan that starts from the end and stops at the first non-count
  // line stops on it having read nothing. Measured: a gate publishing a
  // perfectly good count read as one that published none, and the runner
  // called it unanswered. The caller that gets this right does so by
  // trimming its capture first, which is a property of that caller rather
  // than of the contract, so the trim belongs here.
  var text = String(stdout === null || stdout === undefined ? "" : stdout).replace(/\s+$/, "");
  var lines = text.split(/\r?\n/);
  var counts = [];
  for (var i = lines.length - 1; i >= 0; i -= 1) {
    var m = COUNT_LINE_RE.exec(lines[i].trim());
    if (m === null || accepted.indexOf(m[1]) === -1) break;
    counts.unshift({ token: m[1], n: Number(m[2]), unit: m[3] || "checks" });
  }
  return counts;
}

/**
 * emptyUnits(counts) -> [ "<unit>" ]
 *
 * The units that came back zero and are refused for it. Every one of them,
 * not just the first: a gate answering in several units fails on ANY of them
 * being empty, because a validator that opened 200 files and extracted 0
 * documentation blocks proved exactly as little as one that opened none, and
 * a reader that stopped at the healthy first number would call that run
 * measured.
 *
 * A unit carrying `zeroIs` is not one of them. That field is a publisher's
 * written statement that an empty set is this gate's expected steady state,
 * and it only ever exists on the publishing side: counts PARSED off a gate's
 * stdout carry a token, a number and a unit and nothing else, so for the
 * runner and the release battery the field is never set and this is the
 * plain zero refusal. Reading it here rather than filtering separately in
 * `publish` is what keeps one definition of a refusable zero, so a gate
 * cannot decide it is clean by a rule its caller does not share.
 */
// The one definition of a refusable zero, shared by the reader below and the
// publisher further down rather than spelled twice. Two spellings of this is
// how a gate comes to call itself clean by a rule its caller does not share.
function _isRefusableZero(c) {
  return c && c.n === 0 && c.zeroIs === undefined;
}

function emptyUnits(counts) {
  return (counts || [])
    .filter(_isRefusableZero)
    .map(function (c) { return c.unit; });
}

/**
 * format(counts) -> "22 lib-source-files, 115 primitive-blocks"
 *
 * What the gate said it looked at, for the line a caller prints back. The
 * count is echoed rather than summarised so the reader of a transcript can
 * see the number that was actually read, not a caller's opinion of it.
 */
function format(counts) {
  return (counts || []).map(function (c) { return c.n + " " + c.unit; }).join(", ");
}

// A unit name the reader above can parse back. Publishing one it cannot is a
// gate talking to itself, so the spelling is checked where it is written
// rather than discovered later by a caller that read no counts.
var UNIT_RE = /^[a-z0-9-]+$/;

// How long a `zeroIs` has to be before it counts as one.
//
// `zeroIs` is the only way past the empty-set refusal, and a mechanism that
// accepted any non-empty string would be guarded by nothing: "n/a" is a
// non-empty string, and so is the unit's own name. The floor is what makes
// the allowance cost a sentence, which is the entire design. It is not a
// style rule about length; it is the difference between an argument a later
// reader can check and a token somebody typed to make a gate stop talking.
//
// The number is the one the gate-exemption declarations are held to, because
// the two are the same mechanism aimed at different scopes: one says this
// UNIT is expected to be empty, the other says this GATE has no unit to
// count. Holding them to different bars would make the cheaper one the way
// through.
var MIN_ZERO_IS = 80;

/**
 * publish(units, opts?) -> 0 when every unit answered for something, 1 when
 * one of them did not.
 *
 * The publishing half of the contract, for a gate whose exit code is the only
 * thing anybody reads. `units` is what this run looked at, in the gate's own
 * vocabulary:
 *
 *   [ { unit: "series-releases", n: 3 },
 *     { unit: "document-links",  n: 0 } ]
 *
 * Every unit is published as its `EXAMINED <n> <unit>` line, whatever the
 * verdict, because the number belongs beside the findings as much as beside a
 * pass. A unit that came back zero is then refused BY NAME: a run that found
 * nothing to look at has a clean verdict answering for no part of the tree, and
 * saying which unit emptied is the difference between a fault somebody can act
 * on and a gate that just went red.
 *
 * A unit may declare `zeroIs`, which is the one way past the refusal and is
 * deliberately expensive to use: it is a sentence, written down, saying why an
 * empty set is this gate's expected steady state. It is for the case where zero
 * is genuinely the healthy answer, a set the flow itself empties on purpose,
 * and it turns a silent pass into a stated one. It is not for a unit somebody
 * would rather not fix: a `zeroIs` on a unit that CAN legitimately be non-empty
 * is how this whole defect class comes back.
 *
 * A `zeroIs` unit that IS zero is stated in prose and NOT published, and that
 * asymmetry is the point rather than an omission. `EXAMINED <n> <unit>` and the
 * zero refusal are one statement read from two sides: `emptyUnits` above
 * refuses every zero it is handed, so a line reading `EXAMINED 0 anything`
 * means, to every caller that spawns this gate, "refuse me". A publisher
 * emitting one it believes is fine would be handing the reader a line the
 * reader is right to reject, and the two halves of one contract would disagree
 * in the tree. So the allowance lives where it can be read by a person, and
 * every EXAMINED line that is ever emitted is a count somebody stands behind.
 * A run where EVERY unit was suppressed publishes nothing at all, which is a
 * gate that said nothing, and that is refused too.
 *
 * `opts.stream` takes the count lines, defaulting to stdout because that is
 * where the reader looks. A gate whose stdout IS its artifact passes stderr
 * instead and accepts that nothing can spawn it as a counted gate; its exit
 * code still carries the refusal, which is the part that gates.
 * `opts.diagnostics` takes the prose, defaulting to stderr, and is written
 * FIRST so that a gate sending both to one stream still leaves the counts as
 * the last word.
 */
function publish(units, opts) {
  opts = opts || {};
  var list = units || [];
  if (!Array.isArray(list) || list.length === 0) {
    throw new TypeError("publish(units): a gate must name at least one unit it answers for");
  }
  var seen = {};
  list.forEach(function (u, i) {
    if (!u || typeof u.unit !== "string" || !UNIT_RE.test(u.unit)) {
      throw new TypeError("publish(units): units[" + i + "].unit must match " + String(UNIT_RE) +
        ", got " + JSON.stringify(u && u.unit));
    }
    if (typeof u.n !== "number" || !isFinite(u.n) || u.n < 0 || Math.floor(u.n) !== u.n) {
      throw new TypeError("publish(units): units[" + i + "].n must be a non-negative integer, got " +
        JSON.stringify(u && u.n));
    }
    if (u.zeroIs !== undefined &&
        (typeof u.zeroIs !== "string" || u.zeroIs.trim().length < MIN_ZERO_IS)) {
      throw new TypeError("publish(units): units[" + i + "].zeroIs must be the written reason an " +
        "empty set is expected here, in at least " + MIN_ZERO_IS + " characters, or absent. It " +
        "is the one way past the empty-set refusal, so it has to argue rather than assert: say " +
        "what empties this unit in the ordinary course of things, and which unit beside it is " +
        "refused at zero and therefore proves the run measured anything at all");
    }
    // One unit answered for twice is a gate making two claims a reader cannot
    // tell apart, and it is the shape that would let a healthy count stand in
    // for an empty one carrying the same name.
    if (seen[u.unit]) {
      throw new TypeError("publish(units): " + JSON.stringify(u.unit) + " is answered for twice");
    }
    seen[u.unit] = true;
  });

  var stream      = opts.stream      || process.stdout;
  var diagnostics = opts.diagnostics || process.stderr;
  var tag         = opts.tag ? opts.tag + " " : "";

  var refused   = list.filter(_isRefusableZero);
  var stated    = list.filter(function (u) { return u.n === 0 && u.zeroIs !== undefined; });
  var published = list.filter(function (u) { return u.n > 0; });

  stated.forEach(function (u) {
    diagnostics.write(tag + "0 " + u.unit + ", which is expected here: " + u.zeroIs + "\n");
  });
  refused.forEach(function (u) {
    diagnostics.write(tag + "REFUSED: 0 " + u.unit + ". This run found nothing to look at, so a " +
      "clean verdict from it answers for no part of the tree. Either the discovery is pointed " +
      "somewhere the " + u.unit.replace(/-/g, " ") + " no longer are, or they are genuinely gone " +
      "and that is the finding.\n");
  });
  if (refused.length === 0 && published.length === 0) {
    diagnostics.write(tag + "REFUSED: every unit this gate answers for came back empty, so it " +
      "published no count at all. A gate that says nothing about what it looked at is not " +
      "reporting a clean tree, it is reporting that it did not look.\n");
  }

  published.forEach(function (u) {
    stream.write("EXAMINED " + u.n + " " + u.unit + "\n");
  });

  return (refused.length > 0 || published.length === 0) ? 1 : 0;
}

module.exports = {
  COUNT_LINE_RE:   COUNT_LINE_RE,
  DEFAULT_TOKENS:  DEFAULT_TOKENS,
  UNIT_RE:         UNIT_RE,
  MIN_ZERO_IS:     MIN_ZERO_IS,
  publishedCounts: publishedCounts,
  emptyUnits:      emptyUnits,
  format:          format,
  publish:         publish,
};
