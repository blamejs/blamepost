// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.routing
 *
 * The lookup every wire listener runs on a recipient: is this address
 * ours, and if it is, where does mail for it go.
 *
 * One function answers it, because the alternative is an SMTP path, an
 * IMAP path and a JMAP path that each decide separately what an address
 * means and eventually disagree. The order it applies is fixed:
 *
 *   1. the domain has to be hosted here and active;
 *   2. an alias on the address wins, and expands to what it points at;
 *   3. otherwise an account on the address;
 *   4. otherwise the domain's catch-all, if it has one.
 *
 * Steps two and three cannot both match, because adding an alias on an
 * address a mailbox already holds is refused. The order is written down
 * anyway, so the answer does not depend on which row was inserted first.
 *
 * An address whose aliases are all disabled stops at step two under the
 * reason `alias-disabled`. It does not go on to step four: disabling is
 * how an operator answers an address that is being abused, and letting
 * it fall through would carry the abuse into whatever the catch-all
 * points at while the operator believed they had stopped it. A suspended
 * mailbox behaves the same way at step three.
 *
 * The catch-all applies to the address the sender wrote, not to the
 * destination of a forward. A catch-all is how a domain accepts mail
 * for a name nobody has claimed; a forward already names its target.
 *
 * Alias chains are followed to their ends, so the result is the set of
 * mailboxes and remote addresses that should actually receive the
 * message. A chain that comes back to an address already on the path is
 * reported as a loop and left out of the delivery set rather than
 * followed, which is what keeps a mistake in two alias rows from
 * turning into a mail loop between two servers.
 *
 * Nothing here throws. Every caller is holding a recipient an untrusted
 * peer supplied, and the answer to a malformed one is a verdict the
 * listener turns into its own protocol code, not an exception unwinding
 * through a wire handler.
 */

var b       = require("../vendor/blamejs");
var address = require("./address");
var tables  = require("./tables");

// How many alias rows a single recipient may traverse. A forward to a
// role address that forwards to a team address that forwards to a
// person is three, and anything past this is a configuration mistake
// rather than a delivery path.
var MAX_ALIAS_DEPTH = 10;

function _verdict(fields) {
  return Object.assign({
    local:       false,
    deliverable: false,
    reason:      null,
    kind:        null,
    address:     null,
    written:     null,
    localPart:   null,
    domain:      null,
    tag:         null,
    accountId:   null,
    status:      null,
    targets:     [],
    loops:       [],
  }, fields);
}

function _accountFor(canonicalAddress) {
  return b.db.from(tables.ACCOUNTS).where({ address: canonicalAddress }).first();
}

// Every alias on the address, whatever its status. Filtering the
// disabled ones out in the query would make the address read as one
// nobody has claimed, and an unclaimed address is what the catch-all
// takes, so an operator disabling an address under an abuse report
// would have its mail carry on into somebody else's mailbox.
function _aliasesFor(canonicalAddress) {
  return b.db.from(tables.ALIASES)
    .where({ address: canonicalAddress })
    .orderBy("createdAt", "asc")
    .all();
}

function _active(rows) {
  return rows.filter(function (row) { return row.status === "active"; });
}

function _hostedDomain(name) {
  return b.db.from(tables.DOMAINS).where({ domain: name }).first();
}

function create() {
  /**
   * @primitive blamepost.store.resolve
   * @signature blamepost.store.resolve(recipient)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 5321 section 3.9, RFC 5233, RFC 4343
   * @related   blamepost.store.accounts.get, blamepost.store.aliases.add
   *
   * Decide what one recipient address means to this server and return a
   * verdict. `local` says the domain is hosted here, `deliverable` says
   * something will actually accept the message, `reason` names why not
   * when it will not, and `targets` carries the mailboxes and remote
   * addresses the message should reach once aliases have been followed.
   *
   * The two flags are separate on purpose. A suspended mailbox is local
   * and undeliverable, which is a different answer to give a sender than
   * an address on a domain this server never heard of, and the listener
   * needs to tell them apart to pick between refusing the recipient and
   * refusing the connection.
   *
   * It never throws. A malformed recipient comes back with the reason
   * `invalid-address` and the listener answers with its own code.
   *
   * @example
   *   var verdict = store.resolve("Alice+Receipts@Example.com");
   *   verdict.deliverable;
   *   // true
   *   verdict.tag;
   *   // "receipts"
   */
  function resolve(recipient) {
    var parsed = address.parse(recipient);
    if (!parsed.ok) {
      return _verdict({ reason: "invalid-address" });
    }

    var base = {
      address:   parsed.address,
      written:   parsed.written,
      localPart: parsed.localPart,
      domain:    parsed.domain,
      tag:       parsed.tag,
    };

    var domainRow = _hostedDomain(parsed.domain);
    if (!domainRow) {
      return _verdict(Object.assign({ reason: "unknown-domain" }, base));
    }
    if (domainRow.status !== "active") {
      return _verdict(Object.assign({ local: true, reason: "domain-disabled" }, base));
    }

    var aliasRows = _aliasesFor(parsed.address);
    var liveAliases = _active(aliasRows);
    if (liveAliases.length > 0) {
      return _fromAliases(base, "alias", parsed.address, liveAliases);
    }
    if (aliasRows.length > 0) {
      return _verdict(Object.assign({
        local: true, kind: "alias", reason: "alias-disabled",
      }, base));
    }

    var account = _accountFor(parsed.address);
    if (account) {
      var deliverable = account.status === "active";
      return _verdict(Object.assign({
        local:       true,
        deliverable: deliverable,
        reason:      deliverable ? null : "account-" + account.status,
        kind:        "account",
        accountId:   account._id,
        status:      account.status,
        targets:     [{
          address:     account.address,
          mailbox:     account.address,
          local:       true,
          accountId:   account._id,
          status:      account.status,
          deliverable: deliverable,
          reason:      deliverable ? null : "account-" + account.status,
        }],
      }, base));
    }

    // A catch-all that is disabled is a claim the operator withdrew, so
    // the address goes back to having nobody who wants it.
    var catchAllRows = _active(_aliasesFor(address.catchAllFor(parsed.domain)));
    if (catchAllRows.length > 0) {
      return _fromAliases(base, "catch-all", parsed.address, catchAllRows);
    }

    return _verdict(Object.assign({ local: true, reason: "no-such-mailbox" }, base));
  }

  function _fromAliases(base, kind, startAddress, rows) {
    var targets = [];
    var loops   = [];
    // The chain of addresses this branch came through, so a loop is an
    // address on the path back to the start rather than any address the
    // walk has already been to. Two branches meeting on one mailbox is a
    // fan-out, and calling that a loop points an operator at the one
    // address that is working.
    var path     = [startAddress];
    // The hops already followed, so a shared mailbox is walked once
    // however many branches converge on it. Without it, unwinding the
    // path above would let a wide graph be re-walked on every branch.
    var expanded = [];
    _expand(rows, path, expanded, 1, targets, loops);

    var deliverable = false;
    for (var i = 0; i < targets.length; i += 1) {
      if (targets[i].deliverable) { deliverable = true; break; }
    }

    var reason = null;
    if (!deliverable) {
      reason = targets.length === 0 ? "alias-loop" : "no-deliverable-target";
    }

    return _verdict(Object.assign({
      local:       true,
      deliverable: deliverable,
      reason:      reason,
      kind:        kind,
      targets:     targets,
      loops:       loops,
    }, base));
  }

  // Walk one level of alias rows, following any destination that is
  // itself an alias, and collect the addresses that actually receive
  // the message.
  function _expand(rows, path, expanded, depth, targets, loops) {
    for (var i = 0; i < rows.length; i += 1) {
      var row = rows[i];
      var mailbox = row.destinationMailbox;

      if (path.indexOf(mailbox) !== -1) {
        if (loops.indexOf(mailbox) === -1) loops.push(mailbox);
        continue;
      }

      var parsed = address.parse(mailbox);
      if (!parsed.ok) {
        _push(targets, {
          address: row.destination, mailbox: mailbox, local: false,
          accountId: null, status: null, deliverable: false, reason: "invalid-address",
        });
        continue;
      }

      var domainRow = _hostedDomain(parsed.domain);
      if (!domainRow) {
        // Somewhere else entirely. Whether it accepts the message is
        // the outbound delivery chain's question, not this one's.
        _push(targets, {
          address: row.destination, mailbox: mailbox, local: false,
          accountId: null, status: null, deliverable: true, reason: null,
        });
        continue;
      }
      if (domainRow.status !== "active") {
        _push(targets, {
          address: row.destination, mailbox: mailbox, local: true,
          accountId: null, status: null, deliverable: false, reason: "domain-disabled",
        });
        continue;
      }

      var nextRows = _aliasesFor(mailbox);
      var nextLive = _active(nextRows);
      if (nextLive.length > 0) {
        if (expanded.indexOf(mailbox) !== -1) continue;
        if (depth >= MAX_ALIAS_DEPTH) {
          if (loops.indexOf(mailbox) === -1) loops.push(mailbox);
          continue;
        }
        expanded.push(mailbox);
        path.push(mailbox);
        _expand(nextLive, path, expanded, depth + 1, targets, loops);
        path.pop();
        continue;
      }
      if (nextRows.length > 0) {
        _push(targets, {
          address: row.destination, mailbox: mailbox, local: true,
          accountId: null, status: null, deliverable: false, reason: "alias-disabled",
        });
        continue;
      }

      var account = _accountFor(mailbox);
      if (!account) {
        _push(targets, {
          address: row.destination, mailbox: mailbox, local: true,
          accountId: null, status: null, deliverable: false, reason: "no-such-mailbox",
        });
        continue;
      }

      var live = account.status === "active";
      _push(targets, {
        address:     row.destination,
        mailbox:     mailbox,
        local:       true,
        accountId:   account._id,
        status:      account.status,
        deliverable: live,
        reason:      live ? null : "account-" + account.status,
      });
    }
  }

  // Two aliases converging on one mailbox deliver one message, not two.
  function _push(targets, target) {
    for (var i = 0; i < targets.length; i += 1) {
      if (targets[i].mailbox === target.mailbox) return;
    }
    targets.push(target);
  }

  return { resolve: resolve, MAX_ALIAS_DEPTH: MAX_ALIAS_DEPTH };
}

module.exports = { create: create };
