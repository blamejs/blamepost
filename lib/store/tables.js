// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.tables
 *
 * The identity layer's table declarations and the row-write rules they
 * impose. Message storage is not here: `b.mailStore` already owns
 * folders, messages, flags, threading, quota counters, legal hold and
 * full text search, and reimplementing any of that would give the
 * server two answers to the same question.
 *
 * What is here is the layer the framework deliberately leaves to the
 * application: who has a mailbox, which domains this server answers
 * for, which addresses forward where, and which DKIM selectors are
 * published.
 *
 * Two properties of these declarations are load bearing.
 *
 * Sealing. Every address, display name and password hash is a sealed
 * column, so a stolen database file is ciphertext rather than a mailing
 * list. Sealed columns cannot be searched, so each one that needs a
 * lookup carries a derived hash column beside it, and the framework
 * rewrites an equality match onto that column. The hash is keyed by a
 * per-deployment secret, so two deployments produce different hashes
 * for the same address.
 *
 * Binding. Each sealed table is registered with `aad: true`, which ties
 * every sealed cell to its table, its row identity and its column. An
 * attacker with write access to the database file cannot lift the
 * sealed password hash out of one row and drop it into another. The
 * price is that a row identity has to be present in the change set of
 * every update, which is why `updateRow` below is the only write path.
 */

var b       = require("../vendor/blamejs");
var address = require("./address");

var ACCOUNTS  = "blamepost_accounts";
var DOMAINS   = "blamepost_domains";
var ALIASES   = "blamepost_aliases";
var SELECTORS = "blamepost_dkim_selectors";

// An account is active, suspended by an operator, archived, or erasing.
// Archived is what deletion produces by default: the mailbox stops
// accepting mail and stops authenticating, and the row stays for the
// retention the operator owes. Erasing it outright is a separate,
// explicit request.
//
// Erasing is what an outright erasure produces when it could not finish.
// The delete path refuses per message, so a preservation order or the
// retention floor can leave mail on the volume that the erasure was
// asked to destroy, and that mail needs an owner: every surface that
// could produce it for the court or the regulator keeping it resolves
// the account first. So the identity row stays, holding nothing but the
// answer to who that mail belongs to, and the erasure finishes on a
// later run once the rule keeping the mail lets go.
//
// It is its own value rather than a second reading of archived because
// the two need opposite handling. Archived is reversible and hidden from
// the default listing; this is neither. Reinstating it would return an
// account whose mail has already been destroyed, and hiding it would
// leave an operator reading an unfinished erasure as a finished one,
// which is the whole failure it exists to make visible.
var ACCOUNT_STATUS = ["active", "suspended", "archived", "erasing"];

var DOMAIN_STATUS = ["active", "disabled"];

var ALIAS_STATUS = ["active", "disabled"];

// A selector is published and signing, published and being rotated out,
// or kept only so a verifier can still check mail that left before the
// rotation. RFC 6376 section 3.6.2.2 is why the retired row stays: the
// public key has to answer for messages already in flight.
var SELECTOR_STATUS = ["active", "retiring", "retired"];

// The signing algorithms a selector may carry. These are the two the
// DKIM-Signature `a=` tag admits, so the list is set by the wire format
// rather than by preference. The shipped default mints one selector of
// each, which is the dual signing RFC 8463 section 3 describes.
//
// There is deliberately no post-quantum entry. The `a=` tag draws from an
// IANA registry that has no ML-DSA value, so a selector carrying one would
// produce signatures no receiver could verify. Admitting the value here
// would let a domain be configured into exactly that state.
var SELECTOR_ALGORITHMS = ["ed25519", "rsa-sha256"];

// Overlap between a new selector taking over and the old one being
// removed from DNS. Mail that left before the rotation is still being
// delivered and retried during that window, and its signature has to
// keep verifying.
var SELECTOR_OVERLAP_MS = b.constants.TIME.days(7);

var TABLES = [
  {
    name: ACCOUNTS,
    columns: {
      _id:               "TEXT PRIMARY KEY",
      address:           "TEXT NOT NULL",
      addressHash:       "TEXT NOT NULL",
      domain:            "TEXT NOT NULL",
      displayName:       "TEXT",
      passwordHash:      "TEXT NOT NULL",
      isAdmin:           "INTEGER NOT NULL DEFAULT 0",
      status:            "TEXT NOT NULL DEFAULT 'active'",
      statusReason:      "TEXT",
      quotaBytes:        "INTEGER NOT NULL DEFAULT 0",
      createdAt:         "INTEGER NOT NULL",
      updatedAt:         "INTEGER NOT NULL",
      archivedAt:        "INTEGER",
      passwordChangedAt: "INTEGER NOT NULL",
      // When an erasure was recorded against this row, and null on every
      // row no erasure has run against.
      //
      // It says the same thing the `erasing` status says, and it is here
      // because the status is ONE write and that write can be refused. A
      // records-retention posture puts a trigger on a status column and
      // refuses the transition itself, so the erasure writes this in a
      // change set of its own when that happens, and every gate reads
      // the two together. An account whose mail an erasure destroyed is
      // then out of service whichever of the two writes the volume took.
      erasureHeldAt:     "INTEGER",
    },
    indexes: [
      { name: "idx_blamepost_accounts_address", columns: ["addressHash"], unique: true },
      { name: "idx_blamepost_accounts_domain",  columns: ["domain"] },
      { name: "idx_blamepost_accounts_status",  columns: ["status"] },
    ],
    sealedFields:  ["address", "displayName", "passwordHash", "statusReason"],
    derivedHashes: { addressHash: { from: "address", normalize: address.fold } },
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
    subjectField:  "address",
    personalDataCategories: { address: "email", displayName: "name" },
  },
  {
    name: DOMAINS,
    columns: {
      _id:               "TEXT PRIMARY KEY",
      domain:            "TEXT NOT NULL",
      status:            "TEXT NOT NULL DEFAULT 'active'",
      dnsAcknowledged:   "INTEGER NOT NULL DEFAULT 0",
      dnsAcknowledgedAt: "INTEGER",
      dnsAcknowledgedBy: "TEXT",
      createdAt:         "INTEGER NOT NULL",
      updatedAt:         "INTEGER NOT NULL",
    },
    indexes: [
      { name: "idx_blamepost_domains_domain", columns: ["domain"], unique: true },
    ],
    // The domain name itself stays in the clear. It is published in DNS
    // by definition, and the listeners match on it for every connection,
    // so sealing it would buy nothing and cost every lookup.
    sealedFields:  ["dnsAcknowledgedBy"],
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
  },
  {
    name: ALIASES,
    columns: {
      _id:                    "TEXT PRIMARY KEY",
      address:                "TEXT NOT NULL",
      addressHash:            "TEXT NOT NULL",
      domain:                 "TEXT NOT NULL",
      isCatchAll:             "INTEGER NOT NULL DEFAULT 0",
      destination:            "TEXT NOT NULL",
      destinationHash:        "TEXT NOT NULL",
      destinationMailbox:     "TEXT NOT NULL",
      destinationMailboxHash: "TEXT NOT NULL",
      status:                 "TEXT NOT NULL DEFAULT 'active'",
      createdAt:              "INTEGER NOT NULL",
      updatedAt:              "INTEGER NOT NULL",
    },
    // One row per source and destination pair, so an address that fans
    // out to three mailboxes is three rows. The unique index is what
    // makes adding the same pair twice a refusal rather than a silent
    // duplicate delivery, and its leading column also serves the lookup
    // that resolution runs on every recipient.
    //
    // The destination is kept twice: as the operator wrote it, tag
    // included, because forwarding to a tagged address is the point of
    // the tag, and again with the tag stripped, because that is the
    // form that answers the question of which aliases point at a given
    // mailbox. Erasing an account reads the second one.
    indexes: [
      { name: "idx_blamepost_aliases_pair",   columns: ["addressHash", "destinationHash"], unique: true },
      { name: "idx_blamepost_aliases_target", columns: ["destinationMailboxHash"] },
      { name: "idx_blamepost_aliases_domain", columns: ["domain"] },
    ],
    sealedFields:  ["address", "destination", "destinationMailbox"],
    derivedHashes: {
      addressHash:            { from: "address",            normalize: address.fold },
      destinationHash:        { from: "destination",        normalize: address.fold },
      destinationMailboxHash: { from: "destinationMailbox", normalize: address.fold },
    },
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
    subjectField:  "address",
    personalDataCategories: {
      address:            "email",
      destination:        "email",
      destinationMailbox: "email",
    },
  },
  {
    name: SELECTORS,
    columns: {
      _id:         "TEXT PRIMARY KEY",
      domain:      "TEXT NOT NULL",
      selector:    "TEXT NOT NULL",
      algorithm:   "TEXT NOT NULL",
      publicKey:   "TEXT NOT NULL",
      keyRef:      "TEXT NOT NULL",
      status:      "TEXT NOT NULL DEFAULT 'active'",
      createdAt:   "INTEGER NOT NULL",
      updatedAt:   "INTEGER NOT NULL",
      retiresAt:   "INTEGER",
    },
    indexes: [
      { name: "idx_blamepost_selectors_name",   columns: ["domain", "selector", "algorithm"], unique: true },
      { name: "idx_blamepost_selectors_domain", columns: ["domain"] },
    ],
    // Nothing here is secret. A selector name, its algorithm and its
    // public key are published in DNS, and `keyRef` names a file under
    // the data directory's keys folder where the private half lives
    // sealed by the vault. Private key material never enters the
    // database.
    sealedFields: [],
  },
];

// The write paths. Every insert and update in this layer goes through
// these two, because the sealed columns are bound to the row identity
// and a change set that omits it seals cells nothing can reopen. The
// framework refuses that write outright rather than corrupting the row,
// so the failure is loud, but the way not to hit it is to write here.

function insertRow(table, row) {
  var full = Object.assign({ _id: b.uuid.v7() }, row);
  return b.db.from(table).insertOne(full);
}

function updateRow(table, id, changes) {
  var patch = Object.assign({}, changes);
  patch._id = id;
  return b.db.from(table).where({ _id: id }).updateOne(patch);
}

function deleteRow(table, id) {
  return b.db.from(table).where({ _id: id }).deleteOne();
}

module.exports = {
  TABLES:              TABLES,
  ACCOUNTS:            ACCOUNTS,
  DOMAINS:             DOMAINS,
  ALIASES:             ALIASES,
  SELECTORS:           SELECTORS,
  ACCOUNT_STATUS:      Object.freeze(ACCOUNT_STATUS),
  DOMAIN_STATUS:       Object.freeze(DOMAIN_STATUS),
  ALIAS_STATUS:        Object.freeze(ALIAS_STATUS),
  SELECTOR_STATUS:     Object.freeze(SELECTOR_STATUS),
  SELECTOR_ALGORITHMS: Object.freeze(SELECTOR_ALGORITHMS),
  SELECTOR_OVERLAP_MS: SELECTOR_OVERLAP_MS,
  insertRow:           insertRow,
  updateRow:           updateRow,
  deleteRow:           deleteRow,
};
