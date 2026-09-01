// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.aliases
 *
 * Addresses that route somewhere other than a mailbox of their own:
 * a second name for an existing account, a distribution address that
 * fans out to several people, a forward to a mailbox on another server,
 * and the catch-all that takes whatever the domain is sent that nothing
 * else claimed.
 *
 * One row is one source and one destination. An address that fans out
 * to three people is three rows, which is what makes adding, removing
 * and auditing a single leg of a fan-out possible, and what lets the
 * unique index refuse the same pair twice instead of quietly delivering
 * two copies.
 *
 * A catch-all is stored as an at sign followed by the domain. It is
 * deliberately not a valid mailbox address, so it can never collide
 * with a real one, and it sits in the same sealed, indexed column as
 * every other alias rather than in a second lookup path that would
 * eventually disagree with the first.
 *
 * An alias may not take an address an account already holds. Shadowing
 * a mailbox with a forward is how mail silently stops arriving.
 */

var b       = require("../vendor/blamejs");
var address = require("./address");
var auditActor = require("./actor");
var errors  = require("./errors");
var tables  = require("./tables");

var err = errors.err;

function _requireOpts(opts, fn) {
  if (typeof opts !== "object" || opts === null) {
    throw err("store/bad-argument", "aliases." + fn + " takes an options object.");
  }
  return opts;
}

function _requireReason(value, fn) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err("store/bad-argument", "aliases." + fn + " needs a reason.");
  }
  return value.trim();
}

function _present(row) {
  if (!row) return null;
  return {
    id:                 row._id,
    address:            row.address,
    domain:             row.domain,
    isCatchAll:         row.isCatchAll === 1,
    destination:        row.destination,
    destinationMailbox: row.destinationMailbox,
    status:             row.status,
    createdAt:          row.createdAt,
    updatedAt:          row.updatedAt,
  };
}

// The source side of an alias, resolved from either a plain address or
// a catch-all request. Both forms come back as the stored address and
// the domain it belongs to.
function _readSource(opts, fn) {
  if (opts.catchAll === true) {
    var name = address.canonicalDomain(opts.domain, "domain");
    return { address: address.catchAllFor(name), domain: name, isCatchAll: true };
  }
  var parsed = address.canonical(opts.address, "address");
  if (parsed.tag !== null) {
    throw err("store/bad-address",
      "aliases." + fn + ": an alias address cannot carry a plus tag. A tag is a suffix the " +
      "sender chose, and routing strips it before the lookup, so " + JSON.stringify(opts.address) +
      " would never be reached. Create the alias on " + parsed.address + " instead.");
  }
  return { address: parsed.address, domain: parsed.domain, isCatchAll: false };
}

function _hostedDomain(name) {
  return b.db.from(tables.DOMAINS).where({ domain: name }).first();
}

function create() {
  /**
   * @primitive blamepost.store.aliases.add
   * @signature blamepost.store.aliases.add(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 5321 section 3.9, RFC 5233
   * @related   blamepost.store.aliases.remove, blamepost.store.resolve
   *
   * Point an address at a destination. The source domain has to be
   * hosted and active, the source address has to be free of accounts
   * and of this exact destination already, and the destination has to
   * be a usable address, local or not. Pass `catchAll: true` with a
   * domain instead of an address to claim everything the domain is sent
   * that nothing else matches.
   *
   * The destination keeps its plus tag, because forwarding to a tagged
   * address is what the tag is for. Routing remembers the untagged
   * mailbox alongside it, so erasing an account still finds the aliases
   * aimed at it.
   *
   * @opts
   *   address:     string,    // the source address, unless catchAll is set
   *   domain:      string,    // the domain, when catchAll is set
   *   catchAll:    boolean,   // claim everything the domain is sent that nothing else matches
   *   destination: string,    // required, where the mail goes
   *
   * @example
   *   await store.aliases.add({
   *     address: "sales@example.com", destination: "alice+sales@example.com",
   *   });
   */
  async function add(opts) {
    _requireOpts(opts, "add");
    var source = _readSource(opts, "add");
    var target = address.canonical(opts.destination, "destination");

    var domainRow = _hostedDomain(source.domain);
    if (!domainRow) {
      throw err("store/no-such-domain",
        source.domain + " is not hosted here. Add the domain before pointing an address in it anywhere.");
    }
    if (domainRow.status !== "active") {
      throw err("store/domain-disabled",
        source.domain + " is " + domainRow.status + ", so it cannot take a new alias.");
    }
    if (!source.isCatchAll && source.address === target.address) {
      throw err("store/alias-loop",
        source.address + " cannot be an alias for itself.");
    }

    var now = Date.now();
    var row = b.db.transaction(function () {
      if (!source.isCatchAll) {
        var account = b.db.from(tables.ACCOUNTS).where({ address: source.address }).first();
        if (account) {
          throw err("store/address-taken",
            source.address + " is a mailbox. An alias on the same address would shadow it, " +
            "so its mail would stop arriving.");
        }
      }
      var clash = b.db.from(tables.ALIASES)
        .where({ address: source.address, destination: target.written }).first();
      if (clash) {
        throw err("store/alias-exists",
          source.address + " already forwards to " + target.written + ".");
      }
      return tables.insertRow(tables.ALIASES, {
        address:            source.address,
        domain:             source.domain,
        isCatchAll:         source.isCatchAll ? 1 : 0,
        destination:        target.written,
        destinationMailbox: target.address,
        status:             "active",
        createdAt:          now,
        updatedAt:          now,
      });
    });

    await auditActor.record({
      action:   source.isCatchAll ? "alias.catch_all_added" : "alias.added",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "alias", id: row._id },
      metadata: { address: source.address, domain: source.domain, destination: target.written },
    });

    return _present(row);
  }

  /**
   * @primitive blamepost.store.aliases.list
   * @signature blamepost.store.aliases.list(opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one source and destination pair per row)
   * @related   blamepost.store.aliases.add
   *
   * Aliases narrowed by domain, by source address, or by the mailbox
   * they point at. Asking by destination is how the admin views answer
   * what still forwards to an account before it is deleted, and it
   * matches on the untagged mailbox, so a forward to a tagged form of
   * the same address is found too.
   *
   * @opts
   *   domain:          string,    // aliases belonging to this hosted domain
   *   address:         string,    // one source address
   *   catchAllFor:     string,    // the catch-all rules of this domain
   *   destination:     string,    // aliases pointing at this mailbox
   *   includeDisabled: boolean,   // keep disabled rows in the result
   *
   * @example
   *   store.aliases.list({ destination: "alice@example.com" }).length;
   */
  function list(opts) {
    opts = opts || {};
    var query = b.db.from(tables.ALIASES);

    if (opts.domain !== undefined && opts.domain !== null) {
      query = query.where({ domain: address.canonicalDomain(opts.domain, "domain") });
    }
    if (opts.address !== undefined && opts.address !== null) {
      query = query.where({ address: address.canonical(opts.address, "address").address });
    }
    if (opts.catchAllFor !== undefined && opts.catchAllFor !== null) {
      query = query.where({ address: address.catchAllFor(opts.catchAllFor) });
    }
    if (opts.destination !== undefined && opts.destination !== null) {
      query = query.where({
        destinationMailbox: address.canonical(opts.destination, "destination").address,
      });
    }
    if (opts.includeDisabled !== true) {
      query = query.where({ status: "active" });
    }

    return query.orderBy("createdAt", "asc").all().map(_present);
  }

  /**
   * @primitive blamepost.store.aliases.setStatus
   * @signature blamepost.store.aliases.setStatus(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one source and destination pair per row)
   * @related   blamepost.store.aliases.remove
   *
   * Turn one alias off or back on without deleting it. Disabling is the
   * reversible answer when a distribution address is being abused: the
   * row and its history stay, and resolution stops offering the
   * destination immediately.
   *
   * @opts
   *   id:          string,   // the alias id, or name the pair below
   *   address:     string,   // the source address
   *   domain:      string,   // the domain, with catchAll
   *   catchAll:    boolean,  // the catch-all rule of that domain
   *   destination: string,   // the destination, when naming the pair
   *   status:      string,   // required, active or disabled
   *   reason:      string,   // required, recorded in the audit trail
   *
   * @example
   *   await store.aliases.setStatus({
   *     id: alias.id, status: "disabled", reason: "abuse report",
   *   });
   */
  async function setStatus(opts) {
    _requireOpts(opts, "setStatus");
    if (tables.ALIAS_STATUS.indexOf(opts.status) === -1) {
      throw err("store/bad-argument",
        "aliases.setStatus: status must be one of " + tables.ALIAS_STATUS.join(", ") + ".");
    }
    var reason = _requireReason(opts.reason, "setStatus");
    var row = _locate(opts, "setStatus");

    tables.updateRow(tables.ALIASES, row._id, {
      status:    opts.status,
      updatedAt: Date.now(),
    });
    await auditActor.record({
      action:   "alias.status_changed",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "alias", id: row._id },
      metadata: {
        address: row.address, destination: row.destination,
        from: row.status, to: opts.status,
      },
    });
    return _present(b.db.from(tables.ALIASES).where({ _id: row._id }).first());
  }

  /**
   * @primitive blamepost.store.aliases.remove
   * @signature blamepost.store.aliases.remove(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: one source and destination pair per row)
   * @related   blamepost.store.aliases.add, blamepost.store.aliases.setStatus
   *
   * Delete one alias, named either by its id or by the source and
   * destination pair it holds. One leg of a fan-out at a time, on
   * purpose: an address forwarding to four people has four rows, and
   * removing the wrong three because the source matched is exactly the
   * mistake this shape prevents.
   *
   * @opts
   *   id:          string,   // the alias id, or name the pair below
   *   address:     string,   // the source address
   *   domain:      string,   // the domain, with catchAll
   *   catchAll:    boolean,  // the catch-all rule of that domain
   *   destination: string,   // the destination, when naming the pair
   *   reason:      string,   // required, recorded in the audit trail
   *
   * @example
   *   await store.aliases.remove({
   *     address: "sales@example.com", destination: "alice+sales@example.com",
   *     reason: "role retired",
   *   });
   */
  async function remove(opts) {
    _requireOpts(opts, "remove");
    var reason = _requireReason(opts.reason, "remove");
    var row = _locate(opts, "remove");

    tables.deleteRow(tables.ALIASES, row._id);
    await auditActor.record({
      action:   "alias.removed",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "alias", id: row._id },
      metadata: { address: row.address, destination: row.destination },
    });
    return { id: row._id, address: row.address, destination: row.destination, outcome: "removed" };
  }

  // Find the one row an operation names, by id or by the source and
  // destination pair. Naming a source without a destination is refused
  // rather than guessed at, because a fan-out has several rows under
  // one source and picking one of them is not a decision this layer
  // gets to make.
  function _locate(opts, fn) {
    if (typeof opts.id === "string" && opts.id.length > 0) {
      var byId = b.db.from(tables.ALIASES).where({ _id: opts.id }).first();
      if (!byId) {
        throw err("store/no-such-alias", "no alias with id " + JSON.stringify(opts.id) + ".");
      }
      return byId;
    }
    if (opts.destination === undefined || opts.destination === null) {
      throw err("store/bad-argument",
        "aliases." + fn + " needs either an id, or a source address and the destination it " +
        "points at. One source can hold several destinations, so the source alone does not " +
        "name a single alias.");
    }
    var source = _readSource(opts, fn);
    var target = address.canonical(opts.destination, "destination");
    var row = b.db.from(tables.ALIASES)
      .where({ address: source.address, destination: target.written }).first();
    if (!row) {
      throw err("store/no-such-alias",
        source.address + " does not forward to " + target.written + ".");
    }
    return row;
  }

  return {
    add:       add,
    list:      list,
    setStatus: setStatus,
    remove:    remove,
  };
}

module.exports = { create: create };
