// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * rate-limit-key-parity: every ceiling the framework accepts is either
 * wired here or withheld on purpose, and nothing is neither.
 *
 * The framework's rate limiter publishes its own table of ceilings.
 * This repository holds a hand-written copy of that table in two
 * places: the list `lib/mail/listeners.js` reads out of `config.limits`
 * and hands to every listener, and the field table in `lib/config` that
 * decides which of them an operator may set at all. Three copies of one
 * list, and only the framework's is authoritative.
 *
 * A copy that falls behind is silent in the direction that matters. The
 * framework gains a ceiling, nobody here adds it, and every listener
 * runs on the framework's number for it: a real bound, applied on every
 * connection, that the operator cannot see in their configuration and
 * cannot move. Nothing fails, nothing is logged, and the setting simply
 * does not exist. That has already happened twice on this list.
 *
 * So the list is reconciled rather than reviewed. Every name the
 * framework's defaults publish is in exactly one of two places here:
 * wired, or on a withheld list that carries the reason it is not. A
 * framework release that adds a seventh name fails this file, by name,
 * with the two things to do about it.
 *
 * The withheld list is the half that makes the check honest. Without it
 * the only way past a new framework key would be to wire it, so the
 * pressure would be to wire a ceiling nobody had thought about; with it,
 * declining is a decision somebody wrote down and a reader can argue
 * with.
 *
 * The other direction is checked too, and it is the quieter failure: a
 * ceiling this repository passes that the framework no longer accepts is
 * an option the limiter ignores, so an operator sets a number and gets
 * the default. The framework refuses an unknown key nowhere, which is
 * exactly why it has to be caught here.
 *
 * No sockets, no disk, no database. It reads three exported tables.
 *
 * Run standalone: node test/layer-0-primitives/rate-limit-key-parity.test.js
 */

var helpers = require("../helpers");
var parity  = require("../helpers/parity");

var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var listeners = require("../../lib/mail/listeners");

var check = helpers.check;
var count = helpers.count;

// The framework's own table, read from the module that owns it rather
// than restated. It is the only authoritative copy, and reading it here
// is the whole point: a list retyped into this file would fall behind
// alongside the ones it is supposed to be checking.
var FRAMEWORK_DEFAULTS = b.mail.server.rateLimit.DEFAULTS;

// The one setting on `config.limits` that is not a rate-limiter ceiling.
// It is the largest message a listener accepts, which the two SMTP
// listeners carry directly rather than through the limiter, so it is
// absent from the framework's rate-limit table by design and must not
// read as drift.
var NOT_A_RATE_LIMIT_FIELD = "maxMessageBytes";

// ---- the framework's table is a table -------------------------------------

// Read before anything is compared against it. A parity check whose
// source of truth came back undefined, empty, or as something other than
// an object of names compares nothing and reports green, which is the
// one way a gate like this fails without telling anybody.
function theFrameworkPublishesItsCeilings() {
  check("the framework exposes its rate-limit defaults",
    FRAMEWORK_DEFAULTS !== undefined && FRAMEWORK_DEFAULTS !== null &&
    typeof FRAMEWORK_DEFAULTS === "object");
  count("the framework's rate-limit defaults are frozen, so the copy read here is the one it uses",
    Object.isFrozen(FRAMEWORK_DEFAULTS), String(Object.isFrozen(FRAMEWORK_DEFAULTS)));
  count("the framework publishes more than one ceiling",
    Object.keys(FRAMEWORK_DEFAULTS).length > 1,
    Object.keys(FRAMEWORK_DEFAULTS).join(", "));
}

// ---- the two lists this repository holds ----------------------------------

// Both halves exist and are frozen. A withheld list that a caller can
// push a name onto is a list that grows quietly to make this file pass,
// which is the opposite of what it is for.
function theMailStackDeclaresBothHalves() {
  check("the mail stack exports the rate-limit ceilings it wires",
    Array.isArray(listeners.RATE_LIMIT_KEYS));
  check("the mail stack exports the ceilings it withholds, and why",
    listeners.WITHHELD_RATE_LIMIT_KEYS !== undefined &&
    listeners.WITHHELD_RATE_LIMIT_KEYS !== null &&
    typeof listeners.WITHHELD_RATE_LIMIT_KEYS === "object" &&
    !Array.isArray(listeners.WITHHELD_RATE_LIMIT_KEYS));

  count("the wired list is frozen", Object.isFrozen(listeners.RATE_LIMIT_KEYS),
    String(Object.isFrozen(listeners.RATE_LIMIT_KEYS)));
  count("the withheld list is frozen", Object.isFrozen(listeners.WITHHELD_RATE_LIMIT_KEYS),
    String(Object.isFrozen(listeners.WITHHELD_RATE_LIMIT_KEYS)));

  // A withheld name with no reason beside it is a name somebody skipped
  // rather than declined. The reason is the entire content of the
  // decision, so an empty string or a few words fails here: the length
  // floor is what stops the withheld list from becoming the cheap way
  // past this file.
  Object.keys(listeners.WITHHELD_RATE_LIMIT_KEYS).forEach(function (name) {
    var why = listeners.WITHHELD_RATE_LIMIT_KEYS[name];
    count(name + " is withheld with a written reason",
      typeof why === "string" && why.length >= 40,
      typeof why === "string" ? why.length + " characters" : typeof why);
  });

  // A name on both lists is a list that has stopped meaning anything: it
  // reads as wired from one side and declined from the other, and the
  // parity below would pass either way.
  listeners.RATE_LIMIT_KEYS.forEach(function (name) {
    count(name + " is wired, so it is not also on the withheld list",
      !Object.prototype.hasOwnProperty.call(listeners.WITHHELD_RATE_LIMIT_KEYS, name),
      "it is on both lists");
  });
}

// ---- the comparison still detects a difference -----------------------------

// The canary. Everything below reports green when the two sets agree,
// and it would report exactly the same green if the comparison had
// quietly stopped comparing: a reader that returned an empty list, a
// name normalization that folded every key to one, an argument passed in
// the wrong order. A gate that cannot fail is the worst of the failure
// modes here, because it is the one nobody investigates.
//
// So the arithmetic is run against a set that is deliberately wrong,
// both ways, and has to say so. The framework's real key names are used
// as the base, so this exercises the same strings the real comparison
// does rather than a toy alphabet.
function theComparisonStillNoticesADifference() {
  var real = Object.keys(FRAMEWORK_DEFAULTS);

  var added = parity.compare(real, real.concat(["aSeventhCeilingTheFrameworkAdded"]));
  count("a name the framework added and nothing here answers for is reported as missing",
    added.missing.length === 1 && added.missing[0] === "aSeventhCeilingTheFrameworkAdded",
    JSON.stringify(added.missing));
  count("and the comparison does not call that agreement", added.equal === false,
    String(added.equal));

  var removed = parity.compare(real.concat(["aCeilingTheFrameworkDropped"]), real);
  count("a name this server passes and the framework no longer accepts is reported as extra",
    removed.extra.length === 1 && removed.extra[0] === "aCeilingTheFrameworkDropped",
    JSON.stringify(removed.extra));

  var same = parity.compare(real.slice().reverse(), real);
  count("two spellings of the same set are equal whatever order they arrive in",
    same.equal === true && same.missing.length === 0 && same.extra.length === 0,
    JSON.stringify(same.missing) + JSON.stringify(same.extra));
}

// ---- the parity itself -----------------------------------------------------

// Every name the framework publishes, against every name this repository
// has an answer for. The answer may be "wired" or "withheld, because";
// what it may not be is absent.
function everyFrameworkCeilingHasAnAnswerHere() {
  var accounted = listeners.RATE_LIMIT_KEYS
    .concat(Object.keys(listeners.WITHHELD_RATE_LIMIT_KEYS));

  parity.report(count, {
    have:      accounted,
    want:      Object.keys(FRAMEWORK_DEFAULTS),
    haveLabel: "the mail stack",
    wantLabel: "the framework's rate-limit defaults",
    missingHint: "a ceiling the framework applies on every connection that no operator " +
      "can see or move. Add it to RATE_LIMIT_KEYS in lib/mail/listeners.js together with a " +
      "bounded field in lib/config and a line in the operator guide, or add it to " +
      "WITHHELD_RATE_LIMIT_KEYS with the reason it is not offered",
    extraHint: "a ceiling this server passes that the framework no longer accepts, so the " +
      "operator sets a number and the limiter uses its own. Drop it from lib/mail/listeners.js " +
      "and from lib/config, and say so in the release notes",
  });
}

// The loader's own field table, against the ceilings the mail stack
// wires. This is the copy an operator actually writes into, and it is
// the copy that decides whether a value is even read: a ceiling the mail
// stack passes and the loader has no field for cannot be set from a
// configuration file at all, and a field the loader accepts that the
// mail stack never passes is a number the operator changes and the
// server discards.
function theLoaderOffersExactlyTheCeilingsTheMailStackWires() {
  var limits = null;
  config.SETTINGS.forEach(function (setting) {
    if (setting.key === "limits") limits = setting;
  });
  check("the loader declares a limits setting", limits !== null && limits.fields !== undefined);

  var offered = Object.keys(limits.fields).filter(function (name) {
    return name !== NOT_A_RATE_LIMIT_FIELD;
  });

  parity.report(count, {
    have:      offered,
    want:      listeners.RATE_LIMIT_KEYS.slice(),
    haveLabel: "the loader's limits table",
    wantLabel: "the ceilings the mail stack wires",
    missingHint: "the mail stack passes this ceiling and the loader has no field for it, so " +
      "an operator writing it into the configuration file is refused an unknown field",
    extraHint: "the loader accepts this field and the mail stack passes nothing for it, so " +
      "the operator sets a number and the listeners run on the framework's",
  });

  // The one field that is deliberately not a rate-limit ceiling still
  // has to be there. Losing it would pass the parity above while
  // removing the largest-message setting from the configuration.
  count("the loader still offers the largest-message ceiling beside them",
    Object.prototype.hasOwnProperty.call(limits.fields, NOT_A_RATE_LIMIT_FIELD),
    Object.keys(limits.fields).join(", "));
}

// ---- runner ----------------------------------------------------------------

function run() {
  theFrameworkPublishesItsCeilings();
  theMailStackDeclaresBothHalves();
  theComparisonStillNoticesADifference();
  everyFrameworkCeilingHasAnAnswerHere();
  theLoaderOffersExactlyTheCeilingsTheMailStackWires();
  return helpers.getChecks();
}

module.exports = { name: "rate-limit-key-parity", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
