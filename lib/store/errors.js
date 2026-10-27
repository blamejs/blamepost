// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.errors
 * @nav    Storage and audit
 * @title  Store errors
 * @order  50
 *
 * One error class for the identity and routing store, so a caller can
 * tell a refusal from this layer apart from a database fault or a
 * framework error with a single `instanceof`.
 *
 * Every throw carries a stable `code` of the form `store/<reason>`.
 * Codes are part of the contract: the command line interface and the
 * admin views branch on them, and a wire listener maps them onto its
 * own protocol reply. Renaming one is a breaking change.
 */

var b = require("../vendor/blamejs");

// alwaysPermanent: a refusal from this layer is a verdict about the
// request, never a transient condition, so nothing should retry it.
var StoreError = b.frameworkError.defineClass("StoreError", { alwaysPermanent: true });

// The distinct rule names out of a guard verdict, joined for a refusal
// message. Every guard in the framework reports the same
// `{ kind, ... }` shape, so a refusal here can name the rule that was
// broken rather than only that one was, and it reads the same whichever
// guard produced it.
function issueKinds(issues) {
  if (!Array.isArray(issues) || issues.length === 0) return "";
  var kinds = [];
  for (var i = 0; i < issues.length; i += 1) {
    var kind = issues[i] && issues[i].kind;
    if (kind && kinds.indexOf(kind) === -1) kinds.push(kind);
  }
  return kinds.join(", ");
}

// The refusals `b.db.eraseHard` raises that mean something is
// deliberately keeping a row, as against something being wrong with it.
//
// An erasure destroys several kinds of row and any one of them can be
// refused. A preservation order over the subject, or a governance gate
// wanting a second approver, is the system working: the row stays, the
// operator releases the order or obtains the grant, and running the
// erasure again reaches it. Anything else is a fault, and the two need
// opposite responses from whoever reads the result, so a caller reporting
// what it could not erase has to say which of the two it met.
//
// The list is the framework's own gate codes, read from the erase path
// that raises them. It lives here because more than one layer erases rows
// and every one of them owes its caller the same distinction: the mailbox
// adapter classifies the refusals over an account's filter scripts,
// annotations and mailbox rows, and the identity layer classifies the
// ones over its aliases. A private copy per layer is how two answers to
// one question start disagreeing, and the answer an operator acts on is
// whether to go and look at something.
//
// An unrecognized code is a fault rather than preservation, and
// deliberately so: a code this list has not caught up with is more safely
// read as something to investigate than as something that meant to
// happen. The quiet classification is the one that has to be earned.
var PRESERVATION_REFUSALS = [
  "db/erase-hard-legal-hold",
  "db/erase-hard-dual-control-required",
  "db/erase-hard-grant-not-ready",
];

function isPreservationRefusal(code) {
  return PRESERVATION_REFUSALS.indexOf(code) !== -1;
}

module.exports = {
  StoreError:            StoreError,
  err:                   StoreError.factory,
  issueKinds:            issueKinds,
  isPreservationRefusal: isPreservationRefusal,
};
