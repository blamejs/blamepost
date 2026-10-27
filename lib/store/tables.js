// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.tables
 * @nav    Storage and audit
 * @title  Table declarations
 * @order  20
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
 * The three DMARC tables at the end are the same kind of declaration
 * for a different subject. They hold what peers report back about mail
 * claiming a hosted domain, and the columns they declare are the whole
 * of what may be stored: a forensic report arrives carrying somebody
 * else's message, and there is no column for it here, so there is no
 * setting anywhere that could put one on the volume.
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

// The server-wide settings an operator changes from the administration
// console while the server runs. `blamepost.store.settings` is their only
// writer and carries the rule about which names may be written.
var SETTINGS = "blamepost_settings";

// The three tables holding what peers report about mail claiming a
// hosted domain. `blamepost.store.reports` is their only writer and
// carries the reasoning about what may be stored in them.
var DMARC_REPORTS  = "blamepost_dmarc_reports";
var DMARC_RECORDS  = "blamepost_dmarc_records";
var DMARC_FORENSIC = "blamepost_dmarc_forensic";

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

// What this server concluded about the message that carried a report.
// A report is a document anybody who can send mail to a published
// reporting address may compose, so a reading that counts one nobody
// authenticated is a reading an attacker writes. The three report tables
// carry this column and `blamepost.store.reports` leaves the rows that
// do not count out of its reading.
//
// The column holds the verdict rather than a flag, because the reasons
// need different responses. A missing header is a receiving path that is
// not writing one. A failing verdict is a reporter with a broken
// posture. A mismatch is somebody sending reports about a domain they
// have no part in. A per-message failure report names no reporter at
// all, so its binding stops at the domain the carrier was authenticated
// as, which is the second value below.
//
// `blamepost.mail.reports` produces every value except the last. The
// last is what a row carries when no verdict reached the write, and it
// is the declared default, so a row written before this column existed
// carries it as well. It is deliberately not the value the reading
// counts: a row saying nothing about its carrier reads as
// unauthenticated rather than as evidence.
var REPORT_EVIDENCE_VERIFIED     = "verified";
var REPORT_EVIDENCE_NOT_RECORDED = "not-recorded";

var REPORT_EVIDENCE = [
  REPORT_EVIDENCE_VERIFIED,
  "carrier-verified-no-reporter-identity",
  "carrier-not-authenticated-here",
  "carrier-dmarc-not-pass",
  "carrier-domain-unreadable",
  "carrier-domain-is-not-the-reporter",
  "reporter-not-named-in-report",
  REPORT_EVIDENCE_NOT_RECORDED,
];

// The declaration the three report tables share, written once so the
// default in the DDL and the value the readers compare against cannot
// come apart. The reconciler adds a column with this declaration to a
// table that already exists, and SQLite fills the rows already there
// with the default.
var REPORT_EVIDENCE_COLUMN =
  "TEXT NOT NULL DEFAULT '" + REPORT_EVIDENCE_NOT_RECORDED + "'";

// The organization an aggregate report counts as: the registered domain
// of the address the carrier message passed DMARC for, which is the one
// identity in a report that this server established for itself. The
// `<org_name>` element and the contact mailbox are text the sender wrote,
// so neither is recorded here.
//
// Only a report whose verdict is `verified` records one. Every other row
// carries the empty string, and so does every row written before this
// column existed. The readings count an organization only by a non-empty
// value, so a row with none counts toward no organization.
var REPORT_ORGANIZATION_NONE = "";

var REPORT_ORGANIZATION_COLUMN =
  "TEXT NOT NULL DEFAULT '" + REPORT_ORGANIZATION_NONE + "'";

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
  {
    // One row per server-wide setting an operator has changed from the
    // administration console, and no row at all for one they have not.
    //
    // The absence of a row is what makes the configuration file's value
    // reachable. A stored `false` and a setting nobody has touched are
    // different states: the first is the operator's answer and the
    // second is nothing, so a table seeded with every name at its
    // configured value would pin the first boot's configuration
    // permanently and leave later edits to the file with no effect.
    //
    // The value is an integer rather than a text flag, which is how
    // `dnsAcknowledged` on the domains table above is held. The actor is
    // sealed for the reason `dnsAcknowledgedBy` beside it is: it is a
    // person's address, and a stolen database file is ciphertext rather
    // than a list of who runs this server.
    name: SETTINGS,
    columns: {
      _id:       "TEXT PRIMARY KEY",
      name:      "TEXT NOT NULL",
      value:     "INTEGER NOT NULL",
      changedAt: "INTEGER NOT NULL",
      changedBy: "TEXT",
    },
    indexes: [
      { name: "idx_blamepost_settings_name", columns: ["name"], unique: true },
    ],
    sealedFields:  ["changedBy"],
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
  },
  {
    // One row per aggregate report a peer sent about a hosted domain.
    // RFC 7489 section 7.2 describes what a reporter puts in one.
    name: DMARC_REPORTS,
    columns: {
      _id:             "TEXT PRIMARY KEY",
      // The reporting organization as it wrote itself, and the folded
      // form the unique index below is built on. Both are kept because
      // the first is what an operator reads and the second is what two
      // spellings of one reporter have to collapse to.
      orgName:         "TEXT NOT NULL",
      orgKey:          "TEXT NOT NULL",
      reportId:        "TEXT NOT NULL",
      // The reporter's contact mailbox. It is a person's address at the
      // reporting organization, so it is sealed like every other address
      // this server holds, and the hash beside it is what an erasure
      // request finds the row by.
      reportEmail:     "TEXT",
      reportEmailHash: "TEXT",
      policyDomain:    "TEXT NOT NULL",
      alignmentDkim:   "TEXT",
      alignmentSpf:    "TEXT",
      requestedPolicy: "TEXT",
      subdomainPolicy: "TEXT",
      samplePercent:   "INTEGER",
      failureOptions:  "TEXT",
      // The window the report covers, in milliseconds since the epoch.
      // The wire form is seconds; it is converted once, on the way in,
      // so every reader of these rows works in the unit the rest of this
      // server works in.
      windowBegin:     "INTEGER NOT NULL",
      windowEnd:       "INTEGER NOT NULL",
      storedCount:     "INTEGER NOT NULL DEFAULT 0",
      refusedCount:    "INTEGER NOT NULL DEFAULT 0",
      // What this server concluded about the message that carried this
      // report. It is a property of the report, so this row is where it
      // is written, and the record rows below carry a copy of it for the
      // reading that groups over them.
      evidence:        REPORT_EVIDENCE_COLUMN,
      // The registered domain the carrier passed DMARC for, on a verified
      // report, and the empty string on every other row. The reporter
      // listing and the policy stepper count organizations by this
      // column and never by `orgName`.
      verifiedOrgDomain: REPORT_ORGANIZATION_COLUMN,
      receivedAt:      "INTEGER NOT NULL",
    },
    // The unique index is the authenticated organization, the reporting
    // organization's own name and the report identifier together. RFC 7489
    // section 7.2.1.1 makes the identifier unique to the generator that
    // issued it, so two reporters both numbering a report `1` leave two
    // rows. The authenticated organization leads the key, so a report
    // filed under another reporter's name and identifier occupies a
    // different key from that reporter's own report and does not stop it
    // being stored. A report nobody authenticated carries the empty value
    // and can only collide with other reports nobody authenticated.
    //
    // The index this replaced was on `orgKey` and `reportId` alone. The
    // reconcile cannot remove an index, so the migration under
    // `lib/store/migrations/` drops it on a volume that still has it.
    indexes: [
      { name: "idx_blamepost_dmarc_reports_org_id",
        columns: ["verifiedOrgDomain", "orgKey", "reportId"], unique: true },
      { name: "idx_blamepost_dmarc_reports_domain", columns: ["policyDomain", "windowBegin"] },
      { name: "idx_blamepost_dmarc_reports_age",    columns: ["receivedAt"] },
    ],
    sealedFields:  ["reportEmail"],
    derivedHashes: { reportEmailHash: { from: "reportEmail", normalize: address.fold } },
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
    personalDataCategories: { reportEmail: "email" },
  },
  {
    // One row per source address a report counted, which is the record
    // element of RFC 7489 Appendix C.
    name: DMARC_RECORDS,
    columns: {
      _id:            "TEXT PRIMARY KEY",
      reportRowId:    "TEXT NOT NULL",
      // The domain and the window are copied from the report rather than
      // reached through it. The reading an operator acts on groups by
      // both and sums one column, and a join per group would be a second
      // table read on the one query the console runs on every page.
      policyDomain:   "TEXT NOT NULL",
      windowBegin:    "INTEGER NOT NULL",
      windowEnd:      "INTEGER NOT NULL",
      // The sending address a peer saw. An address identifies the
      // subscriber behind it closely enough that GDPR Article 4(1) treats
      // it as personal data, so it is sealed, and the hash beside it is
      // what counts distinct senders without unsealing every row.
      sourceIp:       "TEXT NOT NULL",
      sourceIpHash:   "TEXT NOT NULL",
      messageCount:   "INTEGER NOT NULL",
      disposition:    "TEXT NOT NULL",
      alignedDkim:    "TEXT NOT NULL",
      alignedSpf:     "TEXT NOT NULL",
      authDkimDomain: "TEXT",
      authDkimResult: "TEXT",
      authSpfDomain:  "TEXT",
      authSpfResult:  "TEXT",
      // The three identifier fields RFC 7489 Appendix C carries, each
      // held as a domain. A reporter that writes a full address into one
      // of them has its local part dropped on the way in.
      headerFrom:     "TEXT",
      envelopeFrom:   "TEXT",
      envelopeTo:     "TEXT",
      overrideReason: "TEXT",
      // The carrier verdict, copied from the report for the same reason
      // the domain and the window above are. The reading an operator
      // acts on groups over these rows and leaves out the ones that do
      // not count, and reaching through to the report row for that
      // answer would put a second table read on the one query the
      // console runs on every page. The copy is written in the
      // transaction that writes the row and is never updated after it,
      // so there is no second write for it to fall behind.
      evidence:       REPORT_EVIDENCE_COLUMN,
      receivedAt:     "INTEGER NOT NULL",
    },
    indexes: [
      { name: "idx_blamepost_dmarc_records_report", columns: ["reportRowId"] },
      { name: "idx_blamepost_dmarc_records_window", columns: ["policyDomain", "windowBegin"] },
      { name: "idx_blamepost_dmarc_records_age",    columns: ["receivedAt"] },
    ],
    sealedFields:  ["sourceIp"],
    derivedHashes: { sourceIpHash: { from: "sourceIp", normalize: address.fold } },
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
    personalDataCategories: { sourceIp: "network-address" },
  },
  {
    // One row per recipient named by a forensic report, which is the
    // per-message failure report of RFC 6591 in the profile RFC 9991
    // gives it.
    //
    // What is NOT here is the point of it. RFC 6591 section 3.2 puts the
    // message that failed authentication in the report, headers and
    // often body, and that message belongs to somebody with no account
    // on this server. No column below can hold it, so no setting can
    // turn storing it on: the columns are the whole of what may be kept,
    // and `blamepost.store.reports` reads a fixed list of fields off the
    // parsed report to fill them.
    name: DMARC_FORENSIC,
    columns: {
      _id:                  "TEXT PRIMARY KEY",
      // A forensic report carries no identifier of its own, and
      // reporters resend. The fingerprint stands in for one: it is a
      // digest over the fields below, taken after the addresses have
      // been through the deployment-keyed derivation, so it is stable
      // across a resend and is not a dictionary target for the addresses
      // that went into it.
      fingerprint:          "TEXT NOT NULL",
      reportedDomain:       "TEXT NOT NULL",
      sourceIp:             "TEXT",
      sourceIpHash:         "TEXT",
      // The envelope of the message that failed. Both are a stranger's
      // mailbox address, sealed, each with the hash an erasure request
      // finds its rows by.
      originalMailFrom:     "TEXT",
      originalMailFromHash: "TEXT",
      originalRcptTo:       "TEXT",
      originalRcptToHash:   "TEXT",
      authFailure:          "TEXT NOT NULL",
      deliveryResult:       "TEXT",
      identityAlignment:    "TEXT",
      dkimDomain:           "TEXT",
      dkimSelector:         "TEXT",
      spfDomain:            "TEXT",
      arrivalAt:            "INTEGER",
      // What this server concluded about the message that carried the
      // report these rows came from. A failure report names no reporting
      // organization, so the binding stops at the domain the carrier was
      // authenticated as and an operator reads the verdict and decides.
      evidence:             REPORT_EVIDENCE_COLUMN,
      receivedAt:           "INTEGER NOT NULL",
    },
    indexes: [
      { name: "idx_blamepost_dmarc_forensic_print",  columns: ["fingerprint"], unique: true },
      { name: "idx_blamepost_dmarc_forensic_domain", columns: ["reportedDomain"] },
      { name: "idx_blamepost_dmarc_forensic_from",   columns: ["originalMailFromHash"] },
      { name: "idx_blamepost_dmarc_forensic_rcpt",   columns: ["originalRcptToHash"] },
      { name: "idx_blamepost_dmarc_forensic_age",    columns: ["receivedAt"] },
    ],
    sealedFields:  ["sourceIp", "originalMailFrom", "originalRcptTo"],
    derivedHashes: {
      sourceIpHash:         { from: "sourceIp",         normalize: address.fold },
      originalMailFromHash: { from: "originalMailFrom", normalize: address.fold },
      originalRcptToHash:   { from: "originalRcptTo",   normalize: address.fold },
    },
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
    personalDataCategories: {
      sourceIp:         "network-address",
      originalMailFrom: "email",
      originalRcptTo:   "email",
    },
  },
];

// What state one account row is in, read from both of the columns that
// answer for it.
//
// It lives here rather than beside either reader because an account row
// is read by the identity verbs, by the recipient lookup the wire
// listeners run, and by the browser surface, and each of those decides
// whether a mailbox is in service. The two columns are declared together
// above, so the reading of them is declared with them and there is one
// answer for every caller to compose rather than one answer per caller.
//
// The marker outranks the status column, and in that direction only. An
// erasure destroys the account's mail before it reaches the identity, and
// it writes both columns; the status transition is one write and a
// records-retention posture puts a trigger on a status column and refuses
// it, so a row whose mail is already gone can carry the marker while the
// column still reads `active`. Reading the column alone answers that such
// a mailbox is in service, which is how mail gets accepted for an account
// whose owner cannot sign in and whose mailbox is part-way through being
// destroyed.
//
// A row that is not there has no state, and the answer is null rather
// than a status standing in for one.
function accountStatus(row) {
  if (!row) return null;
  if (typeof row.erasureHeldAt === "number" && row.erasureHeldAt > 0) return "erasing";
  return row.status;
}

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
  SETTINGS:            SETTINGS,
  DMARC_REPORTS:       DMARC_REPORTS,
  DMARC_RECORDS:       DMARC_RECORDS,
  DMARC_FORENSIC:      DMARC_FORENSIC,
  ACCOUNT_STATUS:      Object.freeze(ACCOUNT_STATUS),
  DOMAIN_STATUS:       Object.freeze(DOMAIN_STATUS),
  ALIAS_STATUS:        Object.freeze(ALIAS_STATUS),
  SELECTOR_STATUS:     Object.freeze(SELECTOR_STATUS),
  SELECTOR_ALGORITHMS: Object.freeze(SELECTOR_ALGORITHMS),
  SELECTOR_OVERLAP_MS: SELECTOR_OVERLAP_MS,
  REPORT_EVIDENCE:     Object.freeze(REPORT_EVIDENCE),
  REPORT_EVIDENCE_VERIFIED:     REPORT_EVIDENCE_VERIFIED,
  REPORT_EVIDENCE_NOT_RECORDED: REPORT_EVIDENCE_NOT_RECORDED,
  REPORT_ORGANIZATION_NONE:     REPORT_ORGANIZATION_NONE,
  accountStatus:       accountStatus,
  insertRow:           insertRow,
  updateRow:           updateRow,
  deleteRow:           deleteRow,
};
