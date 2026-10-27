// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.settings
 * @nav    Server and configuration
 * @title  Runtime settings
 * @order  30
 *
 * The server-wide settings an operator changes while the server runs,
 * and the audit rows recording who changed them.
 *
 * Everything in `lib/config` is read once, at boot, and frozen. That is
 * the right shape for a port, a data directory and a passphrase: a
 * listener is bound to the port it was given, and a value that moved
 * underneath a running process would describe a server nobody is
 * serving. It is the wrong shape for a posture the administration
 * console offers as a switch, because a switch that needs the container
 * restarted to take effect is a switch an operator reads as broken.
 *
 * So a setting that the console changes has two answers and a fixed
 * order between them. The configuration file answers for a volume no
 * operator has written to, which is the first boot and every boot after
 * it until somebody touches the console. A row here answers for every
 * boot afterwards, and it is the one that wins. Reading them in that
 * order is what makes a change survive a restart without also making
 * the file a setting nobody can act on.
 *
 * `get` therefore answers null rather than a default. A stored `false`
 * and a name nobody has set are different states that a boolean cannot
 * hold apart, and folding them together would either pin the first
 * boot's configuration permanently or discard the operator's answer on
 * the next restart, depending on which way the fold went. The caller
 * lays the config value under the answer, and null is what says there is
 * nothing on top of it.
 *
 * Which names may be written is closed, and the closure is the point.
 * The console posts a name, the name reaches a table, and an open table
 * is one where a posted field becomes a row nothing reads and nothing
 * removes. A name outside the list is refused at the call rather than
 * stored, so this table holds what this server acts on and nothing else.
 */

var b          = require("../vendor/blamejs");
var auditActor = require("./actor");
var tables     = require("./tables");

// The settings this server acts on. A name outside it is refused, and
// adding one here is the same change as teaching something to read it:
// a row nothing reads is a setting an operator believes they set.
var NAMES = ["publicSiteEnabled"];

// What the identity column may carry. The bound is the one the domains
// table holds its acknowledging operator to, because it is the same kind
// of value and the same sealed column shape.
var MAX_ACTOR_CHARS = 200;

var MAX_REASON_CHARS = 500;

function _requireOpts(opts, fn) {
  if (typeof opts !== "object" || opts === null) {
    throw new TypeError("blamepost.store.settings." + fn + " takes an options object.");
  }
  return opts;
}

function _readName(value, fn) {
  if (NAMES.indexOf(value) === -1) {
    throw new TypeError("blamepost.store.settings." + fn + ": name must be one of " +
      NAMES.join(", ") + ", got " + JSON.stringify(value) + ". The list is closed because a " +
      "name this server reads nowhere becomes a row an operator believes they set and " +
      "nothing acts on.");
  }
  return value;
}

function _readValue(value) {
  if (typeof value !== "boolean") {
    throw new TypeError("blamepost.store.settings.set: value must be a boolean, got " +
      JSON.stringify(value) + ". The column holds one bit and a truthy reading of a string " +
      "would store the operator's typo as an answer.");
  }
  return value;
}

function _readChangedBy(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError("blamepost.store.settings.set: changedBy must be a non-empty string " +
      "when given.");
  }
  var text = value.trim();
  if (text.length > MAX_ACTOR_CHARS) {
    throw new TypeError("blamepost.store.settings.set: changedBy is longer than the " +
      MAX_ACTOR_CHARS + " characters the field may carry.");
  }
  return text;
}

function _readReason(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError("blamepost.store.settings.set: reason must be a non-empty string " +
      "when given.");
  }
  var text = value.trim();
  if (text.length > MAX_REASON_CHARS) {
    throw new TypeError("blamepost.store.settings.set: reason is longer than the " +
      MAX_REASON_CHARS + " characters the column may carry.");
  }
  return text;
}

function _rowFor(name) {
  return b.db.from(tables.SETTINGS).where({ name: name }).first();
}

function _present(row) {
  if (!row) return null;
  return {
    name:      row.name,
    value:     row.value === 1,
    changedAt: row.changedAt,
    changedBy: row.changedBy === undefined ? null : row.changedBy,
  };
}

function create() {
  /**
   * @primitive blamepost.store.settings.get
   * @signature blamepost.store.settings.get(name)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: server-wide settings an operator changes while the server runs)
   * @related   blamepost.store.settings.set
   *
   * The stored answer for one setting, or null when no operator has ever
   * given one. Null is a third state rather than a missing boolean: the
   * caller lays the configuration file's value under it, so a stored
   * `false` keeps the switch off across a restart while an untouched
   * setting keeps following the file.
   *
   * A name outside the closed list is refused rather than answered null,
   * because null reads as "never set" and a caller asking about a name
   * this server does not hold would follow the configuration file
   * forever without anything saying why.
   *
   * @example
   *   var stored = store.settings.get("publicSiteEnabled");
   *   var inEffect = stored === null ? cfg.publicSiteEnabled : stored;
   */
  function get(name) {
    var key = _readName(name, "get");
    var row = _rowFor(key);
    if (!row) return null;
    return row.value === 1;
  }

  /**
   * @primitive blamepost.store.settings.set
   * @signature blamepost.store.settings.set(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: server-wide settings an operator changes while the server runs)
   * @related   blamepost.store.settings.get
   *
   * Record an operator's answer for one setting, and file the change.
   * The row is written whether or not one was already there, and the
   * answer it holds wins over the configuration file from the next read
   * onward, this process included.
   *
   * The audit row carries the value before the change and the value
   * after it. The first is null the first time a setting is written,
   * which is the same distinction `get` reports: a trail that recorded
   * `false` there would say an operator turned something off that had
   * never been on.
   *
   * `changedBy` is the operator's claim about who made the change and is
   * sealed on the row. It is not the actor: the actor is who ran the
   * call, taken from the surrounding scope, and folding either into the
   * other leaves the trail unable to answer the question the other one
   * holds.
   *
   * @opts
   *   name:      string,    // required, one of the names this server reads
   *   value:     boolean,   // required
   *   changedBy: string,    // who made the change, sealed on the row
   *   reason:    string,    // recorded in the audit trail
   *
   * @example
   *   await store.settings.set({
   *     name: "publicSiteEnabled", value: true,
   *     changedBy: "operator@example.com", reason: "publishing the front page",
   *   });
   */
  async function set(opts) {
    _requireOpts(opts, "set");
    var key    = _readName(opts.name, "set");
    var value  = _readValue(opts.value);
    var actor  = _readChangedBy(opts.changedBy);
    var reason = _readReason(opts.reason);
    var now = Date.now();

    // The reading of what was there and the write that replaces it are
    // one transaction, so the value the trail reports as the previous one
    // is the value this call actually replaced. Two calls landing at once
    // would otherwise both read the same original and both report it,
    // leaving a trail where one change is missing from the chain of
    // values without anything saying a change was lost.
    var previous = null;
    var row = b.db.transaction(function () {
      var held = _rowFor(key);
      previous = held ? held.value === 1 : null;
      if (!held) {
        return tables.insertRow(tables.SETTINGS, {
          name:      key,
          value:     value ? 1 : 0,
          changedAt: now,
          changedBy: actor,
        });
      }
      tables.updateRow(tables.SETTINGS, held._id, {
        value:     value ? 1 : 0,
        changedAt: now,
        changedBy: actor,
      });
      return _rowFor(key);
    });

    await auditActor.record({
      action:   "blamepost.store.settings.changed",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "setting", id: key },
      metadata: { setting: key, from: previous, to: value },
    });

    return _present(row);
  }

  return {
    get: get,
    set: set,
  };
}

module.exports = {
  create: create,
  NAMES:  Object.freeze(NAMES),
};
