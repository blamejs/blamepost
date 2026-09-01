// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Two named sets, compared by name.
 *
 * The same shape keeps coming up in this suite. Something outside this
 * repository publishes a set of names, something inside it holds a
 * second copy of that set, and the two are supposed to stay equal:
 * the listener table the loader validates against the one the mail
 * stack builds, the rate-limit ceilings the framework accepts against
 * the ones this server passes it. Each copy is written by hand, and
 * each one falls behind silently, because a name the framework added
 * and nobody here wired is not an error anywhere. It is a default the
 * operator cannot see and cannot move.
 *
 * A comparison written inline reports it as a failed string equality:
 * two sorted lists in one message, and the reader diffs them by eye.
 * That is the part worth extracting. What a person needs is the NAMES
 * on each side of the difference and which side they are on, because
 * the two sides need opposite fixes. A name the source has and this
 * repository does not is something new to wire or to withhold on
 * purpose. A name this repository has and the source does not is a
 * setting connected to nothing, which is the quieter of the two and
 * the one that survives longest.
 *
 * `compare` is the arithmetic and `report` is the arithmetic plus the
 * checks, so a caller that wants the difference for its own message can
 * take the first and a caller that just wants the gate takes the
 * second.
 *
 * No sockets, no disk, no framework. It compares arrays of strings.
 */

// ---- the arithmetic --------------------------------------------------------

function _names(value, label) {
  if (!Array.isArray(value)) {
    throw new TypeError("helpers/parity: " + label + " must be an array of names");
  }
  var out = [];
  for (var i = 0; i < value.length; i += 1) {
    if (typeof value[i] !== "string" || value[i].length === 0) {
      throw new TypeError("helpers/parity: " + label + "[" + i + "] must be a non-empty string. " +
        "The comparison is by name, so a name that is not a string is a comparison that " +
        "silently matches nothing.");
    }
    if (out.indexOf(value[i]) === -1) out.push(value[i]);
  }
  return out.sort();
}

/**
 * The difference between two sets of names, both ways.
 *
 * `have` is what this repository holds and `want` is what the source of
 * truth publishes. `missing` is in `want` and not in `have`; `extra` is
 * in `have` and not in `want`. Both come back sorted, so a message
 * built from them reads the same on every run.
 */
function compare(have, want) {
  var mine   = _names(have, "have");
  var theirs = _names(want, "want");
  return {
    have:    mine,
    want:    theirs,
    missing: theirs.filter(function (n) { return mine.indexOf(n) === -1; }),
    extra:   mine.filter(function (n) { return theirs.indexOf(n) === -1; }),
    equal:   mine.join(",") === theirs.join(","),
  };
}

// ---- the gate --------------------------------------------------------------

// One check per name on each side of the difference, plus one that the
// comparison ran against something rather than against nothing.
//
// A check per NAME rather than one check over the whole set is what
// makes the failure readable: the label carries the name that drifted
// and the sentence that says what to do about it, so the person who
// added a framework version reads the fix rather than two sorted lists.
//
// The empty-set guard is the same idea the source scans in this suite
// carry a canary for. A parity check whose source of truth came back
// empty compares nothing to nothing and reports green, which is the one
// failure mode of a gate that nobody notices.
function report(count, opts) {
  if (typeof count !== "function") {
    throw new TypeError("helpers/parity.report: pass helpers.count as the first argument");
  }
  opts = opts || {};
  var verdict = compare(opts.have, opts.want);
  var haveLabel = String(opts.haveLabel || "this repository");
  var wantLabel = String(opts.wantLabel || "the source");

  count(wantLabel + " publishes at least one name to compare against",
    verdict.want.length > 0,
    "a comparison against an empty set passes without comparing anything");

  verdict.missing.forEach(function (name) {
    count(wantLabel + " has " + name + " and " + haveLabel + " accounts for it",
      false,
      opts.missingHint || (name + " is new here"));
  });
  verdict.extra.forEach(function (name) {
    count(haveLabel + " has " + name + " and " + wantLabel + " does not",
      false,
      opts.extraHint || (name + " is connected to nothing"));
  });

  if (verdict.missing.length === 0 && verdict.extra.length === 0) {
    count(haveLabel + " accounts for every name " + wantLabel + " publishes",
      true, verdict.want.join(", "));
  }
  return verdict;
}

module.exports = {
  compare: compare,
  report:  report,
};
