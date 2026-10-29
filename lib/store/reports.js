// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.reports
 * @nav    DNS and domain authentication
 * @title  DMARC report storage
 * @order  50
 *
 * What peers report back about mail claiming a hosted domain, and how
 * long any of it is kept.
 *
 * A domain publishing a DMARC record asks receivers for two kinds of
 * report. An aggregate report (RFC 7489 section 7.2) is a day's counting
 * from one receiver: how many messages arrived from each sending
 * address, whether they aligned, and what the receiver did with them.
 * That is the reading an operator moves a policy on. A forensic report
 * (RFC 6591, in the profile RFC 9991 gives it) is one message that
 * failed, sent back at the moment it failed.
 *
 * Three tables hold them, declared in `blamepost.store.tables` and
 * written from here and nowhere else.
 *
 * A report is only evidence when this server authenticated the message
 * that carried it. Anybody who can send mail to a published reporting
 * address can compose a well formed report, so the caller hands its
 * verdict about the carrier to the ingest verbs, every row the report
 * produces is written carrying it, and `rollup` counts the rows whose
 * verdict says the carrier was authenticated for the organization the
 * report names. The verdict is written in the transaction that writes
 * the row and never updated afterwards. A row that says nothing about
 * its carrier, which is what a row written before the column existed
 * says, is left out rather than counted, and the volume left out is
 * reported beside the counting so a reading is never quietly short of
 * what arrived.
 *
 * An organization is counted by who authenticated its reports, not by
 * what a report calls itself. The caller hands in the domain the carrier
 * passed DMARC for beside its verdict, and a verified report row records
 * the registered domain of it. `reporters` groups and counts by that
 * column. `<org_name>` is stored for display and for telling two reports
 * apart, and nothing counts organizations by it. A row with no recorded
 * organization, which includes every row written before the column
 * existed, counts toward none.
 *
 * The reported message is the constraint everything here is shaped
 * around. RFC 6591 section 3.2 puts the failing message inside the
 * forensic report, headers and often body, and the parser hands it back
 * under `reportedMessage` along with the parsed `reportedHeaders`. That
 * message belongs to somebody who has no account on this server, was
 * never told this server would hold their mail, and can reach no verb
 * here to ask for it back. So none of it is stored, on any setting.
 *
 * That is made true by construction rather than by a flag. The insert
 * path reads a fixed list of fields off the parsed report and drops
 * everything else before a value reaches a statement, and the forensic
 * table declares no column any of it could go in. There is deliberately
 * no option to turn storage of it on, because an option to store a
 * stranger's mail is an option that is on somewhere.
 *
 * The same reasoning runs through the rest of the fields. The reporter's
 * contact mailbox, the sending address a receiver saw, and the envelope
 * of a failed message are all sealed columns with a deployment-keyed
 * hash beside them, so a stolen database file is ciphertext and an
 * erasure request can still find its rows. `forgetAddress` is the verb
 * for that request: somebody with no account here writes in, an operator
 * runs it, and the rows naming that address are destroyed with the
 * reason recorded.
 *
 * Sealing is a posture toward a copy of the file, not toward the
 * operator. One of those columns is unsealed for reading, and it is the
 * sending address: `failingSources` answers which addresses failed
 * alignment for a hosted domain. An aggregate report exists to carry
 * that address to the domain owner, the finding is not actionable
 * without it, and the report already arrived at a mailbox on this
 * server. What the unsealing changes is that the reading is bounded, is
 * over authenticated reports only, and leaves a row saying somebody
 * looked. The trail records the domain and the size of the answer and
 * not the addresses, because a second copy of them would sit in a table
 * with a longer window and no erasure path. The reporter's contact
 * mailbox and the envelope of a failed message stay sealed and are
 * answered by no verb here: they belong to people with no account on
 * this server, and no page needs them.
 *
 * Retention is a deadline rather than a floor. `b.retention.complianceFloor`
 * answers whether something may be destroyed yet, and the legal-hold
 * substrate suppresses destruction; neither can say that something must
 * be gone by now, which is what data belonging to nobody on this server
 * needs. `b.retention.create` can: a rule per table, an age field, a
 * window, and a sweep that destroys what has passed it. The two windows
 * are separate settings and the forensic one is the shorter, so a
 * server keeping a year of counting does not keep a year of strangers'
 * headers with it.
 *
 * Everything read out of a report is untrusted input from the internet.
 * Addresses and domains go through `blamepost.store.address`, which is
 * the one place that composes the framework's address and domain guards,
 * and free text goes through `b.guardText`. A record that fails any of
 * that is refused on its own and counted, and the rest of the report is
 * stored: one malformed record in a report of five hundred must not
 * cost the other four hundred and ninety nine. A report that cannot be
 * parsed at all, or that names a domain this server does not host, is
 * refused whole, because there is nothing in it to salvage.
 *
 * Refusals from the ingest verbs are verdicts rather than throws. The
 * caller is a filing seam holding a message a peer sent, and an
 * exception unwinding through it would take the delivery with it. The
 * operator-facing verbs throw instead: a handle built with a window it
 * cannot act on, an erasure with no reason recorded, and a rollup asked
 * about something that is not a domain are all mistakes a person makes
 * and reads back at the terminal.
 */

var nodeNet = require("node:net");

var b          = require("../vendor/blamejs");
var address    = require("./address");
var auditActor = require("./actor");
var errors     = require("./errors");
var tables     = require("./tables");
// The control-character table every stored field is refused against. A
// report is a peer's bytes and the fields taken out of it are printed
// into a console table beside a count.
var displayText = require("../text");

var err = errors.err;

// The refusal an operator-facing entry point raises when it is handed
// something it cannot act on. Named once so the throws and the sentences
// that branch on them cannot come apart.
var BAD_OPTS = "store/bad-reports-opts";

var TIME  = b.constants.TIME;
var BYTES = b.constants.BYTES;

// The windows an operator may set. The aggregate floor is a day because
// a report covers one and a window shorter than the thing it measures
// destroys evidence before it is complete; the ceiling is a little over
// a year, which is the longest window a DMARC record's reporting
// interval makes any sense over. The forensic floor is a minute and its
// ceiling a month: these rows are somebody else's mail, and an operator
// who wants a year of them is asking for something this server does not
// offer.
var MIN_AGGREGATE_RETENTION_MS = TIME.days(1);
var MAX_AGGREGATE_RETENTION_MS = TIME.days(400);
var MIN_FORENSIC_RETENTION_MS  = TIME.minutes(1);
var MAX_FORENSIC_RETENTION_MS  = TIME.days(30);

// How often the sweep runs when the handle is started, and the bounds on
// it. A sweep more often than a minute spends the volume on scanning,
// and one less often than a day leaves rows past their window for longer
// than the window itself on the short setting.
var DEFAULT_SWEEP_INTERVAL_MS = TIME.hours(1);
var MIN_SWEEP_INTERVAL_MS     = TIME.minutes(1);
var MAX_SWEEP_INTERVAL_MS     = TIME.days(1);

// The report bytes this server will read. It is the framework parsers'
// own ceiling, applied here as well so the aggregate path has one: the
// aggregate parser holds the cap in a constant rather than taking it as
// an option, and a reader that never measured would be handing whatever
// arrived to a decompressor.
var DEFAULT_MAX_REPORT_BYTES = BYTES.mib(8);
var MIN_MAX_REPORT_BYTES     = BYTES.kib(1);
var MAX_MAX_REPORT_BYTES     = BYTES.mib(8);

// Records per aggregate report. The framework refuses above ten thousand
// and this cannot usefully be raised past it; an operator lowers it when
// a peer is sending more than the volume should hold.
var DEFAULT_MAX_RECORDS = 10000;
var MIN_MAX_RECORDS     = 1;
var MAX_MAX_RECORDS     = 10000;

// How many rows one sweep pass takes at a time. Not an operator setting:
// it is a working-set bound rather than a policy, and the sweep runs
// until the table is clear whatever it is set to.
var SWEEP_BATCH = 500;

// Bounds on the free text a reporter sends. Every one of these fields is
// chosen by whoever sent the report, so an unbounded one is a peer
// deciding how large this server's rows are.
var MAX_ORG_NAME_CHARS  = 200;
var MAX_REPORT_ID_CHARS  = 200;
var MAX_TOKEN_CHARS      = 64;

// How many rows a listing verb answers with, and the bounds a caller's
// request is held to. A listing unseals one address for every row it
// answers with, so an unbounded one is a request deciding how much
// personal data a single read discloses. The default is what a console
// page shows without being asked for more, and the ceiling is what a
// reader working through the whole picture may ask for.
var DEFAULT_LISTED_ROWS = 50;
var MIN_LISTED_ROWS     = 1;
var MAX_LISTED_ROWS     = 500;

// How reporter text is screened. `b.guardText` owns the codepoint
// threat catalogue: bidi overrides, zero-width and invisible formatting
// characters, the Unicode Tags block and null bytes. An organization
// name is rendered into the console beside a policy decision, so a name
// that renders as one thing and sorts as another is a decision made
// about the wrong reporter. Confusables are audited rather than refused,
// which is the guard's own default: reporting organizations are named
// in every script there is.
var REPORT_TEXT_GUARD = { profile: "strict", confusablePolicy: "audit" };

// The guard above allows tab, carriage return and line feed, which are
// ordinary in free text, and it reports the C1 range as clean. None of
// them is ordinary in a value printed into a console table beside a
// count, so `blamepost.text.hasControlChar` refuses all of them beside
// it.

// The rule names the retention controller declares. Records are declared
// before the reports they belong to, because `runAll` sweeps in
// declaration order and a report row removed ahead of its records would
// leave rows pointing at a report that is not there for the rest of the
// pass.
var RECORD_RULE   = "blamepost.dmarc.records";
var REPORT_RULE   = "blamepost.dmarc.reports";
var FORENSIC_RULE = "blamepost.dmarc.forensic";

// The three tests the reading is built out of, named once so the
// arithmetic has one definition rather than one per column.
//
// The alignment tests are the rule RFC 7489 section 4.2 states: a
// message is aligned when it passed on either identifier, which is also
// what the framework's own parser reports under `totals`, so the stored
// answer and the reported one cannot disagree.
//
// The evidence test is a comparison against a fixed token, the same
// shape the two beside it are, and the token comes from the table
// declaration rather than from a second spelling here. Only the
// aggregate verdict reaches these rows, and `verified` is the one
// aggregate verdict that says this server authenticated the carrier for
// the organization the report names itself as.
var IS_ALIGNED  = "(alignedDkim = 'pass' OR alignedSpf = 'pass')";
var IS_FAILING  = "(alignedDkim <> 'pass' AND alignedSpf <> 'pass')";
var IS_EVIDENCE = "evidence = '" + tables.REPORT_EVIDENCE_VERIFIED + "'";

// A report row that counts toward an organization: evidence, with the
// registered domain its carrier passed DMARC for recorded on it. Only the
// report table carries that column, so only the reporter reading uses
// this.
var IS_ATTRIBUTED = "(" + IS_EVIDENCE +
  " AND verifiedOrgDomain <> '" + tables.REPORT_ORGANIZATION_NONE + "')";

// The reading the console and the policy stepper run. Built here from
// the table constant so the two shapes are the only SQL in this module
// and the prepared-statement cache holds two entries rather than one per
// domain asked about.
//
// Six aggregates rather than three, because both readings come out of
// one pass. A caller reading the counting that policy rests on wants the
// rows this server authenticated; a caller asking why the numbers look
// low wants the volume that was left out. Filtering in the WHERE clause
// would answer the first and delete the second, and it would also delete
// the whole group row for a window whose every report was unauthenticated,
// which is a domain reading as quiet when it is the opposite.
//
// Distinct failing senders are counted over the deployment-keyed hash
// rather than the sealed column, because a sealed cell is bound to its
// row and two rows holding one address hold different ciphertext.
var ROLLUP_SELECT =
  "SELECT policyDomain AS domain, windowBegin AS windowBegin, windowEnd AS windowEnd," +
  " SUM(messageCount) AS countedAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " THEN messageCount ELSE 0 END) AS counted," +
  " SUM(CASE WHEN " + IS_ALIGNED + " THEN messageCount ELSE 0 END) AS alignedAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " AND " + IS_ALIGNED +
  "     THEN messageCount ELSE 0 END) AS aligned," +
  " COUNT(DISTINCT CASE WHEN " + IS_FAILING +
  "     THEN sourceIpHash ELSE NULL END) AS failingSourcesAll," +
  " COUNT(DISTINCT CASE WHEN " + IS_EVIDENCE + " AND " + IS_FAILING +
  "     THEN sourceIpHash ELSE NULL END) AS failingSources" +
  " FROM " + tables.DMARC_RECORDS +
  " WHERE windowEnd >= ? AND windowBegin <= ?";

var ROLLUP_GROUP =
  " GROUP BY policyDomain, windowBegin, windowEnd" +
  " ORDER BY windowBegin ASC, policyDomain ASC";

var ROLLUP_EVERY_DOMAIN = ROLLUP_SELECT + ROLLUP_GROUP;
var ROLLUP_ONE_DOMAIN   = ROLLUP_SELECT + " AND policyDomain = ?" + ROLLUP_GROUP;

// ---------------------------------------------------------------------------
// The two listings the counting cannot give
// ---------------------------------------------------------------------------
//
// The reading above answers how many distinct senders failed and how much
// volume arrived. An operator opens the console to find out WHICH senders
// and WHO reported, and neither question has an answer in a count.
//
// Both listings take one hosted domain and one window. A list of senders
// mixed across domains is not something anybody can act on, because the
// fix for a failing sender is a change to one domain's SPF record or to
// one relay, and both readings sit beside a page that is already narrowed
// to a domain.
//
// The senders group over the deployment-keyed hash rather than over the
// sealed column, for the reason the distinct count above does: a sealed
// cell is bound to its row, so two rows holding one address hold
// different ciphertext and would group as two senders. `sampleRowId`
// carries one row of each group back, so the address is unsealed once per
// sender rather than once per row.
var SOURCE_COLUMNS =
  " sourceIpHash AS sourceIpHash," +
  " MIN(_id) AS sampleRowId," +
  " SUM(CASE WHEN " + IS_FAILING + " THEN messageCount ELSE 0 END) AS failedAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " AND " + IS_FAILING +
  "     THEN messageCount ELSE 0 END) AS failed," +
  " SUM(CASE WHEN " + IS_ALIGNED + " THEN messageCount ELSE 0 END) AS alignedAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " AND " + IS_ALIGNED +
  "     THEN messageCount ELSE 0 END) AS aligned," +
  // Every figure in a row comes from the same set of rows the volume
  // beside it came from, which is what these four are two of rather than
  // one of each. A window count and a last-seen date taken over
  // everything would put a stranger's report inside a row whose other
  // figures are evidence, and it is the harder half to notice because
  // the number that moved is small and plausible.
  //
  // They are over the FAILING rows as well, not merely the authenticated
  // ones. The row is a sender that is failing, so a window in which it
  // only aligned is not a window it was seen failing in.
  " COUNT(DISTINCT CASE WHEN " + IS_FAILING +
  "     THEN windowBegin ELSE NULL END) AS windowsAll," +
  " COUNT(DISTINCT CASE WHEN " + IS_EVIDENCE + " AND " + IS_FAILING +
  "     THEN windowBegin ELSE NULL END) AS windows," +
  " MAX(CASE WHEN " + IS_FAILING + " THEN windowEnd ELSE NULL END) AS lastSeenAll," +
  " MAX(CASE WHEN " + IS_EVIDENCE + " AND " + IS_FAILING +
  "     THEN windowEnd ELSE NULL END) AS lastSeen";

var SOURCE_FROM =
  " FROM " + tables.DMARC_RECORDS +
  " WHERE windowEnd >= ? AND windowBegin <= ? AND policyDomain = ?" +
  " GROUP BY sourceIpHash";

// The order is the verb. Volume first, because the sender that failed on
// nine hundred messages is the one to fix; then the most recent window,
// so a sender still failing outranks one that stopped weeks ago; then the
// hash, so two readings of one volume list the same senders in the same
// order rather than in whatever order the scan produced.
//
// The `HAVING` clause is where the authenticity rule lands for a list.
// The counting above cannot filter in its `WHERE`, because that would
// delete the row for a window whose every report went unauthenticated. A
// list has the opposite requirement: a sender that failed only inside a
// report nobody authenticated has to be absent from it, because naming it
// hands an operator an address a stranger chose. The excluded volume is
// answered beside the list rather than inside it.
var SOURCE_TAIL_COUNTED =
  " HAVING failed > 0 ORDER BY failed DESC, lastSeen DESC, sourceIpHash ASC LIMIT ?";
var SOURCE_TAIL_EVERY =
  " HAVING failedAll > 0 ORDER BY failedAll DESC, lastSeenAll DESC, sourceIpHash ASC LIMIT ?";

var SOURCE_LIST_COUNTED = "SELECT" + SOURCE_COLUMNS + SOURCE_FROM + SOURCE_TAIL_COUNTED;
var SOURCE_LIST_EVERY   = "SELECT" + SOURCE_COLUMNS + SOURCE_FROM + SOURCE_TAIL_EVERY;

// How many senders there are, counted separately from how many were
// listed. One number read as both is a page reporting that the loudest
// fifty of fifty senders are shown, which is what a list that is quietly
// short looks like from the outside.
var SOURCE_TOTAL_SELECT =
  "SELECT COUNT(*) AS total FROM (SELECT sourceIpHash," +
  " SUM(CASE WHEN " + IS_FAILING + " THEN messageCount ELSE 0 END) AS failedAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " AND " + IS_FAILING +
  "     THEN messageCount ELSE 0 END) AS failed" +
  SOURCE_FROM + " HAVING ";
var SOURCE_TOTAL_COUNTED = SOURCE_TOTAL_SELECT + "failed > 0)";
var SOURCE_TOTAL_EVERY   = SOURCE_TOTAL_SELECT + "failedAll > 0)";

// The failing volume nobody authenticated, taken over the whole domain
// and window rather than over the rows that fit in the answer. Summing
// the listed rows would shrink the excluded number every time the list
// was cut short, and that is the one number that must not move when the
// bound does.
var SOURCE_EXCLUDED =
  "SELECT SUM(CASE WHEN " + IS_FAILING + " THEN messageCount ELSE 0 END) AS failedAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " AND " + IS_FAILING +
  "     THEN messageCount ELSE 0 END) AS failed" +
  " FROM " + tables.DMARC_RECORDS +
  " WHERE windowEnd >= ? AND windowBegin <= ? AND policyDomain = ?";

// Who reported, how often, and when the most recent report arrived. This
// is the one reading over the reports table. The counting groups the
// records inside reports and can therefore say nothing about a reporter
// that has stopped sending them, and a receiver that went quiet produces
// the same empty page as a domain whose mail all aligns.
//
// `newestAt` is when a report reached this server, not the window it
// covered. A reporter that has gone quiet is one whose last report
// ARRIVED a while ago, and the window a report declares is a range the
// reporter chose.
//
// The arrival is taken twice for the reason the sender listing takes its
// window count twice. `newestAt` is the whole answer to whether a
// reporter has gone quiet, so a moment that took an unauthenticated
// report in would let whoever wrote that report hold a domain open: every
// real receiver stops, one forged report a week arrives, and the page
// reads as freshly reported on.
//
// A reporter is grouped by who authenticated its reports rather than by
// what it called itself. `<org_name>` and the contact mailbox are text
// the sender wrote, so one domain that passes DMARC can send reports
// under any number of names. The group key is two expressions:
//
//   - a row that counts toward an organization groups under
//     `verifiedOrgDomain`, whatever name it carries, so every name one
//     authenticated domain used is one group;
//   - every other row, which is a report nobody authenticated or a row
//     written before the column existed, groups under `orgKey`, the
//     folded name the report gave, and carries no organization.
//
// The reading an operator and the policy stepper act on lists the first
// kind only. The wider reading lists both.
//
// A name has to be chosen out of each group for display. It is chosen by
// an aggregate over the name itself rather than by taking whichever row
// an adjacent aggregate settled on, because which one a bare column would
// follow depends on SQLite's query optimizer. Every candidate is a name a
// report in the group carried.
var REPORTER_ORGANIZATION = "CASE WHEN " + IS_ATTRIBUTED +
  " THEN verifiedOrgDomain ELSE NULL END";
var REPORTER_NAME_KEY = "CASE WHEN " + IS_ATTRIBUTED + " THEN NULL ELSE orgKey END";

var REPORTER_COLUMNS =
  " " + REPORTER_ORGANIZATION + " AS organization," +
  " " + REPORTER_NAME_KEY + " AS nameKey," +
  " MAX(orgName) AS orgName," +
  " COUNT(DISTINCT orgKey) AS names," +
  " MAX(receivedAt) AS newestAtAll," +
  " MAX(CASE WHEN " + IS_EVIDENCE + " THEN receivedAt ELSE NULL END) AS newestAt," +
  " COUNT(*) AS reportsAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " THEN 1 ELSE 0 END) AS reports," +
  " SUM(storedCount) AS recordsAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " THEN storedCount ELSE 0 END) AS records";

// A report row an interrupted erasure left under its pending key holds a
// negative `storedCount` until the next write settles it, and is left out
// here so a read, which may run over a read-only snapshot, has nothing to
// settle.
var REPORTER_WHERE =
  " FROM " + tables.DMARC_REPORTS +
  " WHERE windowEnd >= ? AND windowBegin <= ? AND policyDomain = ? AND storedCount >= 0";

var REPORTER_FROM = REPORTER_WHERE + " GROUP BY organization, nameKey";

var REPORTER_LIST_COUNTED = "SELECT" + REPORTER_COLUMNS + REPORTER_FROM +
  " HAVING organization IS NOT NULL" +
  " ORDER BY reports DESC, newestAt DESC, organization ASC LIMIT ?";
var REPORTER_LIST_EVERY = "SELECT" + REPORTER_COLUMNS + REPORTER_FROM +
  " ORDER BY reportsAll DESC, newestAtAll DESC, organization ASC, nameKey ASC LIMIT ?";

var REPORTER_TOTAL_COUNTED =
  "SELECT COUNT(DISTINCT verifiedOrgDomain) AS total" + REPORTER_WHERE +
  " AND " + IS_ATTRIBUTED;
var REPORTER_TOTAL_EVERY =
  "SELECT COUNT(*) AS total FROM (SELECT " + REPORTER_ORGANIZATION + " AS organization, " +
  REPORTER_NAME_KEY + " AS nameKey" + REPORTER_FROM + ")";

// `unattributed` is the evidence that counts toward no organization,
// which on a volume written by this build is empty and on an upgraded one
// is every verified report filed before the column existed.
var REPORTER_EXCLUDED =
  "SELECT COUNT(*) AS reportsAll," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " THEN 1 ELSE 0 END) AS reports," +
  " SUM(CASE WHEN " + IS_EVIDENCE + " AND NOT " + IS_ATTRIBUTED +
  "     THEN 1 ELSE 0 END) AS unattributed" +
  REPORTER_WHERE;

// ---------------------------------------------------------------------------
// Reading a setting
// ---------------------------------------------------------------------------

function _window(value, label, floor, ceiling, fallback) {
  var given = value;
  if ((given === undefined || given === null) && fallback !== undefined) given = fallback;
  if (typeof given !== "number" || !isFinite(given)) {
    throw err(BAD_OPTS, label + " must be a number of milliseconds" +
      (fallback === undefined
        ? ", and it is what decides when these rows are destroyed, so there is no " +
          "default for it here."
        : "."));
  }
  if (given < floor || given > ceiling) {
    throw err(BAD_OPTS, label + " is " + given + " milliseconds, and it has to be between " +
      floor + " and " + ceiling + ".");
  }
  return given;
}

// The range a reading covers, read the same way by every verb that takes
// one. Three of them do, and the check has to be identical across them:
// a reader that accepted a string where its neighbor refused one would
// answer about a range nobody asked for, and the two would disagree about
// the same page.
//
// Absent means the whole of what is on the volume on one side and the
// present moment on the other, which is what an operator asking about a
// domain and naming no dates means.
function _span(opts, label) {
  var since = (opts.since === undefined || opts.since === null) ? 0 : opts.since;
  var until = (opts.until === undefined || opts.until === null) ? Date.now() : opts.until;
  if (typeof since !== "number" || !isFinite(since) ||
      typeof until !== "number" || !isFinite(until)) {
    throw err(BAD_OPTS,
      label + " since and until are moments in milliseconds since the epoch.");
  }
  return { since: since, until: until };
}

function _whole(value, label, floor, ceiling, fallback) {
  var given = value;
  if (given === undefined || given === null) given = fallback;
  if (typeof given !== "number" || !Number.isInteger(given)) {
    throw err(BAD_OPTS, label + " must be a whole number.");
  }
  if (given < floor || given > ceiling) {
    throw err(BAD_OPTS, label + " is " + given + ", and it has to be between " +
      floor + " and " + ceiling + ".");
  }
  return given;
}

// ---------------------------------------------------------------------------
// Reading a value out of a report
// ---------------------------------------------------------------------------
//
// Every reader below answers with a value or with null, and never
// throws. A report is a peer's bytes: what a caller needs is which
// record could not be taken and why, so a refusal is a return value that
// the ingest loop counts.

// One screened, bounded field of reporter text, or null when the value
// is absent or unusable. Absence and refusal are the same answer here
// because every caller treats them the same way: the column is optional
// and a value that will not render is not better than no value.
function _text(value, limit) {
  if (typeof value !== "string") return null;
  var trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > limit) return null;
  if (displayText.hasControlChar(trimmed)) return null;
  return b.guardText.validate(trimmed, REPORT_TEXT_GUARD).ok ? trimmed : null;
}

// A count of messages. RFC 7489 Appendix C makes it a whole number of
// messages seen, so zero is a record about nothing and a negative one is
// a reporter sending arithmetic rather than a count.
function _messageCount(value) {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) return null;
  return value;
}

// The share of mail a published policy asks receivers to apply it to.
// RFC 7489 section 6.3 makes it a whole percentage, and zero is a real
// setting there: it asks receivers to apply the policy to none of the
// mail, which is how an operator publishes a policy without acting on
// it yet. It cannot go through the count reader above, which refuses
// zero because a record counting no messages is a record about nothing.
function _percent(value) {
  if (typeof value !== "number" || !Number.isInteger(value)) return null;
  if (value < 0 || value > 100) return null;
  return value;
}

// A sending address as a receiver saw it. `nodeNet.isIP` answers exactly,
// for both families, which is the same reader the configuration layer
// puts in front of an operator-supplied address.
function _sourceIp(value) {
  var text = _text(value, MAX_TOKEN_CHARS);
  if (text === null) return null;
  return nodeNet.isIP(text) === 0 ? null : text;
}

// An identifier field, held as a domain whatever the reporter wrote.
// RFC 7489 Appendix C describes these as domains and reporters mostly
// send domains, but some send a full address, and the local part of one
// is somebody's mailbox name. Taking the domain half of an address and
// refusing everything else keeps the field useful and keeps the mailbox
// out of the row.
function _identifierDomain(value) {
  if (typeof value !== "string") return null;
  var text = value.trim();
  if (text.length === 0) return null;
  if (text.indexOf("@") !== -1) {
    var asAddress = address.parse(text);
    return asAddress.ok ? asAddress.domain : null;
  }
  var asDomain = address.parseDomain(text);
  return asDomain.ok ? asDomain.domain : null;
}

// A moment, from the seconds a report's date range carries. Bounded so a
// reporter cannot write a window that sorts before every real one or
// past the end of the range a signed millisecond count holds.
var MIN_REPORT_SECONDS = 0;
var MAX_REPORT_SECONDS = 4102444800;

function _momentFromSeconds(value) {
  if (typeof value !== "number" || !isFinite(value)) return null;
  if (value < MIN_REPORT_SECONDS || value > MAX_REPORT_SECONDS) return null;
  return Math.round(value) * 1000;
}

function _momentFromDate(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  var moment = Date.parse(value);
  if (!isFinite(moment)) return null;
  return _momentFromSeconds(Math.round(moment / 1000));
}

// The first entry of an authentication-result list, which is what a
// record's stored columns hold. A reporter may send several; the row
// keeps the first and the count of messages is the same either way,
// because the alignment a policy is decided on is the evaluated result
// beside it rather than this.
function _firstResult(list) {
  return (Array.isArray(list) && list.length > 0) ? list[0] : null;
}

// What the caller concluded about the message that carried the report,
// as the column will hold it. A caller that says nothing, and a caller
// that says something the column does not admit, both get the value that
// records no verdict, which is the value the reading leaves out.
//
// It is a coercion rather than a refusal for the reason the alignment
// columns take `none` when a reporter sends one half of a pair: a report
// is a day of somebody's counting, and discarding it over a caller's
// bookkeeping would lose evidence to fix a bookkeeping fault. The
// coercion only ever moves a row out of the counting, never into it, and
// the volume it moved is published beside the counting so it is visible
// rather than silent.
function _evidence(value) {
  if (typeof value !== "string") return tables.REPORT_EVIDENCE_NOT_RECORDED;
  return tables.REPORT_EVIDENCE.indexOf(value) === -1
    ? tables.REPORT_EVIDENCE_NOT_RECORDED
    : value;
}

// The organization a report counts as: the registered domain of the
// address the caller says the carrier passed DMARC for, and only when the
// verdict beside it is `verified`. Subdomains of one registered domain
// are one organization.
//
// Anything else records no organization: another verdict, a value that is
// not a domain, and a domain `b.publicSuffix.organizationalDomain` answers
// with no registered parent for, such as a public suffix itself. Like the
// verdict coercion above, this only ever moves a row out of the count.
// `<org_name>` and the contact mailbox are never read here.
function _organization(evidence, value) {
  if (evidence !== tables.REPORT_EVIDENCE_VERIFIED) return tables.REPORT_ORGANIZATION_NONE;
  if (typeof value !== "string") return tables.REPORT_ORGANIZATION_NONE;
  var parsed = address.parseDomain(value);
  if (!parsed.ok) return tables.REPORT_ORGANIZATION_NONE;
  var registered;
  try {
    registered = b.publicSuffix.organizationalDomain(parsed.domain);
  } catch (_e) {
    // The reader throws on a name it will not take the shape of, which
    // records no organization, the same as the other refusals above.
    return tables.REPORT_ORGANIZATION_NONE;
  }
  return (typeof registered === "string" && registered.length > 0)
    ? registered
    : tables.REPORT_ORGANIZATION_NONE;
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

/**
 * @primitive blamepost.store.reports.create
 * @signature blamepost.store.reports.create(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 7489 section 7.2, RFC 6591, RFC 9991
 * @related   blamepost.store.reports.ingestAggregate, blamepost.store.reports.forgetAddress
 *
 * Build the handle that takes DMARC reports, reads them back and
 * destroys them on their windows. Returns
 * `{ ingestAggregate, ingestForensic, rollup, failingSources, reporters,
 * forgetAddress, sweep, start, stop, describe }`.
 *
 * Every bound and every switch is handed in rather than read here, so
 * the settings an operator sets live in one place and this module has
 * one answer about what is in force. Bad ones are refused at
 * construction: an operator finds a window they cannot have at boot
 * rather than at the sweep that would have acted on it.
 *
 * `hostedDomain` is how this module asks whether a name is one this
 * server answers for. A report about a domain hosted somewhere else is
 * refused, which is what keeps any peer from choosing how much of the
 * volume reports occupy.
 *
 * Nothing is armed by construction. `start` arms the sweep and `stop`
 * disarms it, so a command that ingests one report and exits never holds
 * the event loop open.
 *
 * @opts
 *   aggregateRetentionMs: number,    // required, 1 day to 400 days
 *   forensicRetentionMs:  number,    // required, 1 minute to 30 days, and never longer
 *                                    //   than aggregateRetentionMs
 *   sweepIntervalMs:      number,    // 1 minute to 1 day, default 1 hour
 *   forensicEnabled:      boolean,   // default false; when off, a forensic report is
 *                                    //   refused rather than stored
 *   maxReportBytes:       number,    // 1 KiB to 8 MiB, default 8 MiB
 *   maxRecordsPerReport:  number,    // 1 to 10000, default 10000
 *   hostedDomain:         function,  // required, (domain) => boolean
 *
 * @example
 *   var reports = require("./lib/store/reports");
 *   var handle = reports.create({
 *     aggregateRetentionMs: 30 * 86400000,
 *     forensicRetentionMs:  7 * 86400000,
 *     forensicEnabled:      true,
 *     hostedDomain:         function (name) { return name === "example.com"; },
 *   });
 *   handle.describe().aggregateRetentionMs;
 */
function create(opts) {
  opts = opts || {};

  var aggregateRetentionMs = _window(opts.aggregateRetentionMs, "aggregateRetentionMs",
    MIN_AGGREGATE_RETENTION_MS, MAX_AGGREGATE_RETENTION_MS);
  var forensicRetentionMs = _window(opts.forensicRetentionMs, "forensicRetentionMs",
    MIN_FORENSIC_RETENTION_MS, MAX_FORENSIC_RETENTION_MS);
  if (forensicRetentionMs > aggregateRetentionMs) {
    throw err(BAD_OPTS,
      "forensicRetentionMs is " + forensicRetentionMs + " milliseconds and " +
      "aggregateRetentionMs is " + aggregateRetentionMs + ", so a stranger's message " +
      "envelope would be kept longer than the counting it belongs to. The forensic " +
      "window is the shorter of the two.");
  }
  var sweepIntervalMs = _window(opts.sweepIntervalMs, "sweepIntervalMs",
    MIN_SWEEP_INTERVAL_MS, MAX_SWEEP_INTERVAL_MS, DEFAULT_SWEEP_INTERVAL_MS);
  var maxReportBytes = _whole(opts.maxReportBytes, "maxReportBytes",
    MIN_MAX_REPORT_BYTES, MAX_MAX_REPORT_BYTES, DEFAULT_MAX_REPORT_BYTES);
  var maxRecordsPerReport = _whole(opts.maxRecordsPerReport, "maxRecordsPerReport",
    MIN_MAX_RECORDS, MAX_MAX_RECORDS, DEFAULT_MAX_RECORDS);
  var forensicEnabled = opts.forensicEnabled === true;

  if (typeof opts.hostedDomain !== "function") {
    throw err(BAD_OPTS,
      "hostedDomain must be a function taking a domain name and answering whether this " +
      "server hosts it. Without it every peer decides what this volume holds.");
  }
  var hostedDomain = opts.hostedDomain;

  var sweepTimer = null;

  // The controller these rules are declared on. It is built per handle,
  // so a second handle in the same process declares its own rules rather
  // than colliding with the first one's names.
  var rules = b.retention.create({ db: b.db, audit: true });

  // What a rule does to a row whose window has passed. `b.db.eraseHard`
  // destroys the wrapped per-row key along with the row, so the sealed
  // cells left in the write-ahead log and in any copy of the file read
  // as absent rather than as ciphertext somebody may still hold a key
  // for. A plain delete would leave them recoverable, which for a
  // stranger's envelope is the whole difference.
  //
  // A refusal here is per row. The controller collects it into the
  // sweep's errors and goes on to the next row, which is what a
  // preservation order over one domain should cost: that domain's rows
  // and no others.
  function _destroys(table, why) {
    return function (row) {
      var result = b.db.eraseHard(table, row._id, { reason: why });
      return { destroyed: (result && result.rowsDeleted) || 0 };
    };
  }

  rules.declare({
    name:      RECORD_RULE,
    table:     tables.DMARC_RECORDS,
    ageField:  "receivedAt",
    ttlMs:     aggregateRetentionMs,
    action:    _destroys(tables.DMARC_RECORDS, "dmarc aggregate retention window passed"),
    batchSize: SWEEP_BATCH,
    // The domain a hold is placed on. It is the hosted domain rather
    // than the sending address, because the sending address is sealed
    // and the sweep reads its candidate rows without unsealing them, so
    // a hold consulted against that column would be consulted against
    // ciphertext and would never match anything.
    subjectField: "policyDomain",
  });

  rules.declare({
    name:         REPORT_RULE,
    table:        tables.DMARC_REPORTS,
    ageField:     "receivedAt",
    ttlMs:        aggregateRetentionMs,
    action:       _destroys(tables.DMARC_REPORTS, "dmarc aggregate retention window passed"),
    batchSize:    SWEEP_BATCH,
    subjectField: "policyDomain",
  });

  rules.declare({
    name:         FORENSIC_RULE,
    table:        tables.DMARC_FORENSIC,
    ageField:     "receivedAt",
    ttlMs:        forensicRetentionMs,
    action:       _destroys(tables.DMARC_FORENSIC, "dmarc forensic retention window passed"),
    batchSize:    SWEEP_BATCH,
    subjectField: "reportedDomain",
  });

  function _refused(reason, detail) {
    return { ok: false, reason: reason, detail: detail || null,
      reportRowId: null, duplicate: false, stored: 0, refused: [] };
  }

  function _tooLarge(raw) {
    if (typeof raw === "string") return b.safeBuffer.byteLengthOf(raw) > maxReportBytes;
    if (Buffer.isBuffer(raw)) return raw.length > maxReportBytes;
    return false;
  }

  // The hosted-domain question, asked through the derivation rather than
  // on the spelling a peer sent. A name that will not derive is refused
  // for that reason rather than reported as a domain nobody hosts, so an
  // operator reading the refusal knows which of the two happened.
  function _hostedName(value) {
    var verdict = address.parseDomain(value);
    if (!verdict.ok) return { ok: false, reason: "domain-refused" };
    if (hostedDomain(verdict.domain) !== true) {
      return { ok: false, reason: "domain-not-hosted" };
    }
    return { ok: true, domain: verdict.domain };
  }

  // ---- aggregate ----------------------------------------------------------

  // One record of an aggregate report, read down to the fields the row
  // holds. Answers a row to insert or the reason it cannot be taken.
  function _readRecord(record, report, now) {
    if (!record || typeof record !== "object") return { reason: "record-not-an-object" };

    var sourceIp = _sourceIp(record.sourceIp);
    if (sourceIp === null) return { reason: "source-ip-refused" };

    var messageCount = _messageCount(record.count);
    if (messageCount === null) return { reason: "message-count-refused" };

    var evaluated = record.dispositions || {};
    var disposition = _text(evaluated.disposition, MAX_TOKEN_CHARS);
    if (disposition === null) return { reason: "disposition-refused" };

    var alignedDkim = _text(evaluated.dkim, MAX_TOKEN_CHARS);
    var alignedSpf  = _text(evaluated.spf, MAX_TOKEN_CHARS);
    if (alignedDkim === null && alignedSpf === null) {
      return { reason: "alignment-refused" };
    }

    var identifiers = record.identifiers || {};
    var authResults = record.authResults || {};
    var dkim = _firstResult(authResults.dkim) || {};
    var spf  = _firstResult(authResults.spf) || {};
    var reasons = Array.isArray(evaluated.reasons) ? evaluated.reasons : [];
    var override = reasons.length > 0 ? _text(reasons[0].type, MAX_TOKEN_CHARS) : null;

    return {
      row: {
        reportRowId:    null,
        policyDomain:   report.policyDomain,
        windowBegin:    report.windowBegin,
        windowEnd:      report.windowEnd,
        sourceIp:       sourceIp,
        messageCount:   messageCount,
        disposition:    disposition,
        // A reporter that sends one half and not the other has said
        // nothing about the half it left out, and the stored value has
        // to sort with the failures rather than with the passes. `none`
        // is the value RFC 7489 Appendix C uses for exactly that.
        alignedDkim:    alignedDkim === null ? "none" : alignedDkim,
        alignedSpf:     alignedSpf === null ? "none" : alignedSpf,
        authDkimDomain: _identifierDomain(dkim.domain),
        authDkimResult: _text(dkim.result, MAX_TOKEN_CHARS),
        authSpfDomain:  _identifierDomain(spf.domain),
        authSpfResult:  _text(spf.result, MAX_TOKEN_CHARS),
        headerFrom:     _identifierDomain(identifiers.headerFrom),
        envelopeFrom:   _identifierDomain(identifiers.envelopeFrom),
        envelopeTo:     _identifierDomain(identifiers.envelopeTo),
        overrideReason: override,
        evidence:       report.evidence,
        receivedAt:     now,
      },
    };
  }

  /**
   * @primitive blamepost.store.reports.ingestAggregate
   * @signature reports.ingestAggregate(raw, opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 7489 section 7.2
   * @related   blamepost.store.reports.rollup, blamepost.store.reports.create
   *
   * Take one aggregate report and store what is usable in it. `raw` is
   * the report bytes as they arrived: XML, or the gzip a reporter
   * usually sends, which the framework parser detects and expands under
   * its own decompression bound.
   *
   * Answers
   * `{ ok, reason, detail, reportRowId, duplicate, stored, refused }`.
   * `detail` is `null` on every answer except a `report-unreadable`
   * refusal, where it is the code of the error the framework parser
   * threw, or `null` when that error carries no code. `stored`
   * counts the record rows written and `refused` names the records that
   * could not be taken, each with the index it held in the report and
   * the rule that refused it. A report resent by the same reporting
   * organization under the same identifier answers `duplicate: true`,
   * stores nothing further, and names the row already holding it.
   *
   * A report that will not parse, is larger than this handle reads,
   * carries more records than it will take, or names a domain hosted
   * somewhere else is refused whole with a reason. Nothing here throws:
   * the caller is holding a message a peer sent.
   *
   * `evidence` is what the caller concluded about the message that
   * carried the report, from the values `blamepost.store.tables`
   * declares. It is written on the report row and on every record row
   * the report produced, and `rollup` leaves out the rows whose verdict
   * is anything but `verified`. A call that passes none, and one that
   * passes a value the column does not admit, both store the report with
   * no verdict recorded, which the reading leaves out.
   *
   * `authenticatedAs` is the domain the carrier passed DMARC for. On a
   * `verified` report the registered domain of it is written on the report
   * row, and `reporters` counts organizations by that value. `<org_name>`
   * is stored for display and never counted. A call with no
   * `authenticatedAs`, or with a verdict other than `verified`, records no
   * organization, and the report counts toward none.
   *
   * A report is a resend when a row already holds the same organization,
   * the same `<org_name>` and the same report identifier. A report carrying
   * another reporter's name and identifier under a different organization,
   * or under none, is a different report and does not stop that reporter's
   * own report being stored.
   *
   * @opts
   *   now:             number,   // the moment the rows are stamped with, default the clock
   *   contentType:     string,   // the media type the report arrived under
   *   evidence:        string,   // the carrier verdict, default no verdict recorded
   *   authenticatedAs: string,   // the domain the carrier passed DMARC for, default none
   *
   * @example
   *   var verdict = handle.ingestAggregate(reportBytes, {
   *     evidence: "verified", authenticatedAs: "reporter.example",
   *   });
   *   verdict.stored;
   */
  function ingestAggregate(raw, ingestOpts) {
    ingestOpts = ingestOpts || {};
    var now = typeof ingestOpts.now === "number" ? ingestOpts.now : Date.now();

    if (_tooLarge(raw)) return _refused("report-too-large");

    var shaped;
    try {
      shaped = b.mail.dmarc.parseAggregateReport(raw, { contentType: ingestOpts.contentType });
    } catch (e) {
      return _refused("report-unreadable", (e && e.code) || null);
    }

    var metadata = shaped.reportMetadata || {};
    var published = shaped.policyPublished || {};
    var records = Array.isArray(shaped.records) ? shaped.records : [];
    if (records.length > maxRecordsPerReport) return _refused("too-many-records");

    var hosted = _hostedName(published.domain);
    if (!hosted.ok) return _refused(hosted.reason);

    var orgName = _text(metadata.orgName, MAX_ORG_NAME_CHARS);
    if (orgName === null) return _refused("reporting-organization-refused");
    var reportId = _text(metadata.reportId, MAX_REPORT_ID_CHARS);
    if (reportId === null) return _refused("report-identifier-refused");

    var range = metadata.dateRange || {};
    var windowBegin = _momentFromSeconds(range.begin);
    var windowEnd   = _momentFromSeconds(range.end);
    if (windowBegin === null || windowEnd === null || windowEnd < windowBegin) {
      return _refused("report-window-refused");
    }

    // The reporter's contact mailbox. A reporter that sends something
    // that is not an address has not given one, which is not a reason to
    // discard a day of counting.
    var contact = address.parse(metadata.email);
    var reportEmail = contact.ok ? contact.address : null;

    var evidence = _evidence(ingestOpts.evidence);
    var report = {
      orgName:      orgName,
      orgKey:       address.fold(orgName),
      reportId:     reportId,
      policyDomain: hosted.domain,
      windowBegin:  windowBegin,
      windowEnd:    windowEnd,
      evidence:     evidence,
      verifiedOrgDomain: _organization(evidence, ingestOpts.authenticatedAs),
    };

    // A resend leaves the row that is already there, verdict included, and
    // no resend raises a row into the counting.
    //
    // The lookup is scoped by the organization recorded above. A report
    // filed first under a real reporter's `<org_name>` and report
    // identifier, by a sender nobody authenticated or by a different
    // authenticated domain, holds a different key from the reporter's own
    // report, so the reporter's report is stored rather than read as its
    // resend. Two reports nobody authenticated that share a name and an
    // identifier still collide with each other, and neither counts.
    var dedupKey = {
      verifiedOrgDomain: report.verifiedOrgDomain,
      orgKey:            report.orgKey,
      reportId:          report.reportId,
    };
    // A report row an erasure was rewriting when it stopped carries a
    // pending key until it is settled, and is matched on the report's own
    // key only after that.
    _settlePendingRewrites();
    var held = b.db.from(tables.DMARC_REPORTS).where(dedupKey).first();
    if (held) {
      return { ok: true, reason: null, detail: null, reportRowId: held._id,
        duplicate: true, stored: 0, refused: [] };
    }

    var taken = [];
    var refused = [];
    for (var i = 0; i < records.length; i += 1) {
      var read = _readRecord(records[i], report, now);
      if (read.reason) {
        refused.push({ index: i, reason: read.reason });
        continue;
      }
      taken.push(read.row);
    }

    var written = b.db.transaction(function () {
      // Read again, inside the write. Two reports from one organization
      // can be filed at once, and the check above ran before any of the
      // record rows were shaped.
      var raced = b.db.from(tables.DMARC_REPORTS).where(dedupKey).first();
      if (raced) return { row: raced, duplicate: true };

      var reportRow = tables.insertRow(tables.DMARC_REPORTS, {
        orgName:         report.orgName,
        orgKey:          report.orgKey,
        reportId:        report.reportId,
        reportEmail:     reportEmail,
        policyDomain:    report.policyDomain,
        alignmentDkim:   _text(published.adkim, MAX_TOKEN_CHARS),
        alignmentSpf:    _text(published.aspf, MAX_TOKEN_CHARS),
        requestedPolicy: _text(published.p, MAX_TOKEN_CHARS),
        subdomainPolicy: _text(published.sp, MAX_TOKEN_CHARS),
        samplePercent:   _percent(published.pct),
        failureOptions:  _text(published.fo, MAX_TOKEN_CHARS),
        windowBegin:     report.windowBegin,
        windowEnd:       report.windowEnd,
        storedCount:     taken.length,
        refusedCount:    refused.length,
        evidence:        report.evidence,
        verifiedOrgDomain: report.verifiedOrgDomain,
        receivedAt:      now,
      });
      for (var w = 0; w < taken.length; w += 1) {
        taken[w].reportRowId = reportRow._id;
        tables.insertRow(tables.DMARC_RECORDS, taken[w]);
      }
      return { row: reportRow, duplicate: false };
    });

    if (written.duplicate) {
      return { ok: true, reason: null, detail: null, reportRowId: written.row._id,
        duplicate: true, stored: 0, refused: [] };
    }

    // Emitted rather than awaited. This verb is synchronous because the
    // caller is a filing seam holding a message a peer sent, and there
    // is no moment in it to wait for a row: the rows the report produced
    // are already committed, and the durable writer is the one the
    // destroying verb below uses, where a caller can be told.
    b.audit.safeEmit({
      action:   "blamepost.store.reports.aggregate_stored",
      // Written flat rather than chosen from the refusals. The framework's
      // outcome normalizer maps `warning` onto `success`, so a condition
      // here writes one value under two names and an operator filtering
      // the trail for partial ingests finds nothing. What separates a
      // clean report from one that lost records is `metadata.refused`
      // beside `metadata.stored`, and both survive the emit.
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "dmarc-report", id: written.row._id },
      metadata: { domain: report.policyDomain, org: report.orgName,
        organization: report.verifiedOrgDomain === tables.REPORT_ORGANIZATION_NONE
          ? null : report.verifiedOrgDomain,
        reportId: report.reportId, stored: taken.length, refused: refused.length },
    });

    return { ok: true, reason: null, detail: null, reportRowId: written.row._id,
      duplicate: false, stored: taken.length, refused: refused };
  }

  // ---- forensic -----------------------------------------------------------

  // The dedup key for a forensic report, which carries no identifier of
  // its own. Every address that goes into it goes in as the
  // deployment-keyed hash the row is indexed by rather than as itself,
  // so the stored fingerprint is not a value somebody holding the file
  // can run a dictionary against.
  //
  // The carrier verdict is deliberately not one of the parts. A resend
  // is the same account of the same failed message however it traveled,
  // and folding the verdict in would file a second row for it. The row
  // already there keeps the verdict it was written with, so a report
  // this server did not authenticate cannot raise a row into the
  // counting by arriving again.
  function _fingerprint(row) {
    var parts = [
      row.reportedDomain,
      row.arrivalAt,
      row.authFailure,
      b.db.hashFor(tables.DMARC_FORENSIC, "sourceIp", row.sourceIp),
      b.db.hashFor(tables.DMARC_FORENSIC, "originalMailFrom", row.originalMailFrom),
      b.db.hashFor(tables.DMARC_FORENSIC, "originalRcptTo", row.originalRcptTo),
    ];
    return b.crypto.sha3Hash(JSON.stringify(parts));
  }

  /**
   * @primitive blamepost.store.reports.ingestForensic
   * @signature reports.ingestForensic(raw, opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 6591, RFC 9991
   * @related   blamepost.store.reports.forgetAddress, blamepost.store.reports.create
   *
   * Take one per-message failure report and store the envelope and the
   * verdict, and none of the message it is about. A report naming
   * several recipients is stored as one row each, so an erasure request
   * from one of them reaches their row and leaves the others alone.
   *
   * The reported message is not stored. The parser returns it, this
   * reads a fixed list of fields off the parsed report, and the table
   * declares no column it could go in, so there is no setting that
   * changes this.
   *
   * Answers `{ ok, reason, detail, stored, duplicates, refused }`.
   * `detail` is `null` on every answer except a `report-unreadable`
   * refusal, where it is the code of the error the framework parser
   * returned, or `null` when that error carries no code. `duplicates`
   * counts the rows a resend matched. A handle built with forensic rows
   * turned off refuses the report under `forensic-not-kept` rather than
   * storing part of it.
   *
   * `evidence` is what the caller concluded about the message that
   * carried the report, from the values `blamepost.store.tables`
   * declares, and it is written on every row the report produced. A
   * failure report names no reporting organization, so the strongest
   * verdict it reaches is the domain the carrier was authenticated as,
   * which an operator reads and decides on. A call that passes none, and
   * one that passes a value the column does not admit, both store the
   * report with no verdict recorded.
   *
   * @opts
   *   now:      number,   // the moment the rows are stamped with, default the clock
   *   evidence: string,   // the carrier verdict, default no verdict recorded
   *
   * @example
   *   var verdict = handle.ingestForensic(reportBytes, { evidence: "verified" });
   *   verdict.stored;
   */
  function ingestForensic(raw, ingestOpts) {
    ingestOpts = ingestOpts || {};
    var now = typeof ingestOpts.now === "number" ? ingestOpts.now : Date.now();

    if (!forensicEnabled) {
      return { ok: false, reason: "forensic-not-kept", detail: null,
        stored: 0, duplicates: 0, refused: [] };
    }
    if (_tooLarge(raw)) {
      return { ok: false, reason: "report-too-large", detail: null,
        stored: 0, duplicates: 0, refused: [] };
    }

    var parsed = b.mail.dmarc.parseForensicReport(raw, { maxBytes: maxReportBytes });
    if (!parsed.ok) {
      return { ok: false, reason: "report-unreadable",
        detail: (parsed.error && parsed.error.code) || null,
        stored: 0, duplicates: 0, refused: [] };
    }

    // The fixed field list. Everything the parser returns that is not
    // named here is dropped before a value reaches a statement, and
    // seven fields stop at this line:
    //
    //   reportedMessage, reportedHeaders, reportedHeaderMap and
    //   reportedHeadersTruncated are the failing message, whole and
    //   parsed and counted;
    //   reportedUri is a link taken out of its body;
    //   authenticationResults is a verbatim header carrying addresses
    //   this row already holds in bounded columns beside it;
    //   extraFields is whatever else the reporter chose to send.
    //
    // The same seven are named in the test that reads the declared
    // columns of all three tables back, so the list and the schema
    // cannot come apart without one of them failing.
    var report = parsed.report;
    var hosted = _hostedName(report.reportedDomain);
    if (!hosted.ok) {
      return { ok: false, reason: hosted.reason, detail: null,
        stored: 0, duplicates: 0, refused: [] };
    }

    var authFailure = _text(report.authFailure, MAX_TOKEN_CHARS);
    if (authFailure === null) {
      return { ok: false, reason: "auth-failure-refused", detail: null,
        stored: 0, duplicates: 0, refused: [] };
    }

    var mailFrom = address.parse(report.originalFrom);
    var common = {
      evidence:          _evidence(ingestOpts.evidence),
      reportedDomain:    hosted.domain,
      sourceIp:          _sourceIp(report.sourceIp),
      originalMailFrom:  mailFrom.ok ? mailFrom.address : null,
      authFailure:       authFailure,
      deliveryResult:    _text(report.deliveryResult, MAX_TOKEN_CHARS),
      identityAlignment: _text(report.identityAlignment, MAX_TOKEN_CHARS),
      dkimDomain:        _identifierDomain(report.dkim && report.dkim.domain),
      dkimSelector:      _text(report.dkim && report.dkim.selector, MAX_TOKEN_CHARS),
      spfDomain:         _identifierDomain(report.spf && report.spf.domain),
      arrivalAt:         _momentFromDate(report.arrivalDate),
      receivedAt:        now,
    };

    // A report naming no recipient still says a message from that sender
    // failed for that domain, which is the finding an operator acts on,
    // so it is stored as one row with no recipient rather than discarded.
    var recipients = Array.isArray(report.originalRcptTo) && report.originalRcptTo.length > 0
      ? report.originalRcptTo
      : [null];

    var refused = [];
    // One transaction for the whole report rather than one per
    // recipient. A report is a single account of a single message, so
    // either every row it produces is on the volume or none is; two
    // recipients half stored is a state no reader of these rows has a
    // way to recognize.
    var written = b.db.transaction(function () {
      var storedRows = 0;
      var duplicateRows = 0;
      for (var i = 0; i < recipients.length; i += 1) {
        var rcpt = recipients[i] === null ? { ok: false } : address.parse(recipients[i]);
        if (recipients[i] !== null && !rcpt.ok) {
          refused.push({ index: i, reason: "recipient-refused" });
          continue;
        }
        var row = Object.assign({ originalRcptTo: rcpt.ok ? rcpt.address : null }, common);
        row.fingerprint = _fingerprint(row);

        var held = b.db.from(tables.DMARC_FORENSIC)
          .where({ fingerprint: row.fingerprint }).first();
        if (held) {
          duplicateRows += 1;
          continue;
        }
        tables.insertRow(tables.DMARC_FORENSIC, row);
        storedRows += 1;
      }
      return { stored: storedRows, duplicates: duplicateRows };
    });
    var stored = written.stored;
    var duplicates = written.duplicates;

    if (stored > 0) {
      b.audit.safeEmit({
        action:   "blamepost.store.reports.forensic_stored",
        // Flat, for the reason given at the aggregate emit above: the
        // normalizer folds `warning` into `success`, and the refusal count
        // in the metadata is what a reader filters on.
        outcome:  "success",
        actor:    auditActor.current(),
        resource: { kind: "dmarc-forensic", id: hosted.domain },
        metadata: { domain: hosted.domain, authFailure: authFailure,
          stored: stored, duplicates: duplicates, refused: refused.length },
      });
    }

    return { ok: true, reason: null, detail: null,
      stored: stored, duplicates: duplicates, refused: refused };
  }

  // ---- the reading an operator acts on ------------------------------------

  /**
   * @primitive blamepost.store.reports.rollup
   * @signature reports.rollup(opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 7489 section 4.2
   * @related   blamepost.store.reports.ingestAggregate
   *
   * The counting the console and the policy stepper read, one row per
   * hosted domain and reporting window:
   * `{ domain, windowBegin, windowEnd, counted, aligned, unaligned,
   * failingSources, unauthenticated }`.
   *
   * The window is the range the reporters themselves declared, not a
   * bucket this server chose. Receivers that report on the same day
   * boundary group together and one that reports on a different range
   * answers in a row of its own, which is what the reports actually
   * said rather than an average over ranges that do not line up.
   *
   * Reports this server did not authenticate are left out of the
   * counting. Anybody who can send mail to a published reporting address
   * can write a well formed report saying whatever they like, and a
   * policy moved on one is a policy moved by whoever wanted it moved, so
   * `counted`, `aligned` and `failingSources` are over the reports whose
   * carrier passed DMARC for the reporting organization and over nothing
   * else.
   *
   * `unauthenticated` is the message volume that was left out, and it is
   * reported on both readings, so a total is never quietly short of what
   * arrived. A window whose every report was unauthenticated still
   * answers in a row of its own, with `counted` at zero and the volume
   * beside it, rather than disappearing from the reading. Pass
   * `includeUnauthenticated` to fold the excluded rows into the counting
   * as well, which is what an operator investigating a number does.
   *
   * `counted` is every message the reports counted for that domain and
   * window. `aligned` is the part of it that passed on either
   * identifier, which is the rule a DMARC policy is evaluated by.
   * `failingSources` is how many distinct sending addresses failed on
   * both, which is the number that says whether a policy can be moved:
   * one misconfigured relay is one source however many messages it sent.
   *
   * Moments are milliseconds since the epoch, on the way in and on the
   * way out.
   *
   * @opts
   *   domain: string,    // one hosted domain, default every domain reported on
   *   since:  number,    // windows ending at or after this moment, default all
   *   until:  number,    // windows beginning at or before this moment, default now
   *   includeUnauthenticated: boolean,   // count the reports nobody authenticated
   *                                      //   too, default false
   *
   * @example
   *   handle.rollup({ domain: "example.com" });
   */
  function rollup(rollupOpts) {
    rollupOpts = rollupOpts || {};
    var span  = _span(rollupOpts, "rollup");
    var since = span.since;
    var until = span.until;
    // Anything but an explicit true leaves the unauthenticated rows out,
    // so a caller that passes a string, or a value it read out of a
    // query parameter and never converted, gets the narrower reading
    // rather than the one a policy must not rest on.
    var everything = rollupOpts.includeUnauthenticated === true;

    var rows;
    if (rollupOpts.domain === undefined || rollupOpts.domain === null) {
      rows = b.db.prepare(ROLLUP_EVERY_DOMAIN).all(since, until);
    } else {
      var wanted = address.canonicalDomain(rollupOpts.domain, "rollup domain");
      rows = b.db.prepare(ROLLUP_ONE_DOMAIN).all(since, until, wanted);
    }

    return rows.map(function (row) {
      var countedAll = row.countedAll || 0;
      var evidence   = row.counted || 0;
      var counted = everything ? countedAll : evidence;
      var aligned = everything ? (row.alignedAll || 0) : (row.aligned || 0);
      return {
        domain:         row.domain,
        windowBegin:    row.windowBegin,
        windowEnd:      row.windowEnd,
        counted:        counted,
        aligned:        aligned,
        // Derived rather than summed a second time. Two sums over one
        // set is two answers to one question, and they come apart the
        // first time a record is refused between them.
        unaligned:      counted - aligned,
        failingSources: everything
          ? (row.failingSourcesAll || 0)
          : (row.failingSources || 0),
        // Derived the same way, and reported on both readings. On the
        // narrow one it is the volume the three numbers above leave out;
        // on the wide one it is how much of them nobody authenticated.
        unauthenticated: countedAll - evidence,
      };
    });
  }

  // ---- the two listings ---------------------------------------------------

  // The hosted domain a listing is about. Both verbs answer about one and
  // neither has a useful answer without one, so an absent name is refused
  // here rather than widened into a reading over everything.
  function _listedDomain(value, label) {
    if (value === undefined || value === null || value === "") {
      throw err(BAD_OPTS,
        label + " answers about one hosted domain and has to be told which one. A listing " +
        "mixed across every domain is not one an operator can act on, because what fixes a " +
        "failing sender is a change to one domain's records.");
    }
    return address.canonicalDomain(value, label + " domain");
  }

  // The address behind one group, read back through the chainable query so
  // the sealed cell is opened. The grouping runs over the hash beside it,
  // which is what makes one row of the group enough to answer for all of
  // them.
  //
  // A group whose row will not read keeps its place in the answer and says
  // the address could not be read. Dropping it would shorten the list
  // without shortening the count beside it, and a list that is quietly one
  // shorter than it says is the failure this whole verb exists to avoid.
  function _sourceAddress(rowId) {
    var row = b.db.from(tables.DMARC_RECORDS).where({ _id: rowId }).first();
    return (row && typeof row.sourceIp === "string" && row.sourceIp.length > 0)
      ? row.sourceIp
      : null;
  }

  /**
   * @primitive blamepost.store.reports.failingSources
   * @signature reports.failingSources(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 7489 section 7.2, RFC 7489 section 4.2
   * @related   blamepost.store.reports.rollup, blamepost.store.reports.forgetAddress
   *
   * The sending addresses failing on both identifiers for one hosted
   * domain, largest first. Answers
   * `{ domain, since, until, includeUnauthenticated, sources, listed,
   * total, truncated, limit, unauthenticated }`, where each entry of
   * `sources` is
   * `{ sourceIp, readable, messages, aligned, windows, lastSeen }`.
   *
   * `rollup` answers how many distinct senders are failing, which says
   * whether a policy can be moved. This answers which ones, which is what
   * an operator changes something over: `messages` is the volume that
   * sender failed on, `aligned` is what it did get through, and the two
   * apart are the difference between a relay of the operator's that is
   * misconfigured and somebody else's machine claiming the domain.
   *
   * The sending address is sealed on the volume with a deployment-keyed
   * hash beside it, and it is unsealed here. It is the address a receiver
   * saw sending mail that claimed this operator's domain, an aggregate
   * report exists to hand it to them, and nothing about the finding is
   * actionable without it. The read is recorded before the addresses are
   * answered, so the trail carries that somebody looked, at which domain,
   * over what range and how much was disclosed. The addresses themselves
   * are not written into that row: a second copy of them would sit in a
   * table with its own retention and no erasure path, and
   * `forgetAddress` is the erasure path for the copy that already exists.
   *
   * Reports this server did not authenticate name no sender here. Anybody
   * who can send mail to a published reporting address can compose a
   * report naming an address and a number, so a list drawn from one is a
   * list of machines a stranger chose. The volume those reports carried
   * is answered as `unauthenticated` beside the list rather than folded
   * into it, and it is measured over the whole domain and window rather
   * than over the rows that fit, so it does not shrink when `limit` does.
   * Pass `includeUnauthenticated` to list them too, which is what an
   * operator investigating a number does.
   *
   * `total` is how many senders there are and `listed` is how many came
   * back, kept apart so `truncated` can be true rather than implied.
   *
   * Moments are milliseconds since the epoch. Bad arguments throw: a
   * missing domain, a name that is not one, a bound outside the range and
   * a moment that is not a number are all mistakes a person reads back at
   * a terminal.
   *
   * @opts
   *   domain: string,    // required, one hosted domain
   *   since:  number,    // windows ending at or after this moment, default all
   *   until:  number,    // windows beginning at or before this moment, default now
   *   limit:  number,    // 1 to 500 senders, default 50
   *   includeUnauthenticated: boolean,   // list the senders only unauthenticated
   *                                      //   reports named too, default false
   *
   * @example
   *   var found = await handle.failingSources({ domain: "example.com", limit: 10 });
   *   found.sources[0].sourceIp;
   */
  async function failingSources(listOpts) {
    listOpts = listOpts || {};
    var wanted = _listedDomain(listOpts.domain, "failingSources");
    var span   = _span(listOpts, "failingSources");
    var limit  = _whole(listOpts.limit, "failingSources limit",
      MIN_LISTED_ROWS, MAX_LISTED_ROWS, DEFAULT_LISTED_ROWS);
    // Anything but an explicit true leaves the unauthenticated senders
    // out, so a caller handing on a value it read off a query string and
    // never converted gets the narrower list rather than the one that
    // names whoever wrote the report.
    var everything = listOpts.includeUnauthenticated === true;

    // Every statement runs before anything is awaited, so no sweep can
    // destroy a row between the grouping and the address it names.
    var grouped = b.db.prepare(everything ? SOURCE_LIST_EVERY : SOURCE_LIST_COUNTED)
      .all(span.since, span.until, wanted, limit);
    var counted = b.db.prepare(everything ? SOURCE_TOTAL_EVERY : SOURCE_TOTAL_COUNTED)
      .get(span.since, span.until, wanted);
    var volume = b.db.prepare(SOURCE_EXCLUDED).get(span.since, span.until, wanted) || {};

    var sources = grouped.map(function (row) {
      var found = _sourceAddress(row.sampleRowId);
      return {
        sourceIp: found,
        readable: found !== null,
        messages: (everything ? row.failedAll : row.failed) || 0,
        aligned:  (everything ? row.alignedAll : row.aligned) || 0,
        windows:  (everything ? row.windowsAll : row.windows) || 0,
        lastSeen: (everything ? row.lastSeenAll : row.lastSeen) || 0,
      };
    });

    var total = (counted && counted.total) || 0;
    var answer = {
      domain:      wanted,
      since:       span.since,
      until:       span.until,
      includeUnauthenticated: everything,
      sources:     sources,
      listed:      sources.length,
      total:       total,
      truncated:   total > sources.length,
      limit:       limit,
      // Reported on both readings, the way the counting reports it. On
      // the narrow list it is the volume the list leaves out; on the wide
      // one it is how much of what was listed nobody authenticated.
      unauthenticated: ((volume.failedAll || 0) - (volume.failed || 0)),
    };

    // Recorded before the addresses are handed back rather than after, so
    // a caller that reads them has left a row behind whatever happens
    // next. The write is drop-silent, so a sink that cannot take the row
    // never turns a read into a refusal.
    //
    // No reason is asked for and none is recorded. The verbs that require
    // one reach into a named account's own private data, and the operator
    // has to name that account to get at it; this answers about the
    // operator's own domain and names nobody on this server, and it is
    // rendered on a page an operator opens to ask whether their domain is
    // being spoofed. A reason typed on every page render would be the
    // same sentence on every row, which reads as accountability and
    // carries none.
    await auditActor.record({
      action:   "blamepost.store.reports.sources_read",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "dmarc-report", id: wanted },
      metadata: { domain: wanted, since: span.since, until: span.until,
        listed: answer.listed, total: answer.total, truncated: answer.truncated,
        includeUnauthenticated: everything },
    });

    return answer;
  }

  /**
   * @primitive blamepost.store.reports.reporters
   * @signature reports.reporters(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 7489 section 7.2
   * @related   blamepost.store.reports.rollup, blamepost.store.reports.failingSources
   *
   * The organizations that reported on one hosted domain, most heard from
   * first. Answers
   * `{ domain, since, until, includeUnauthenticated, reporters, listed,
   * total, truncated, limit, unauthenticatedReports, unattributedReports }`,
   * where each entry of `reporters` is
   * `{ organization, orgName, orgKey, names, reports, records, newestAt }`.
   *
   * An organization is the registered domain the carriers of its reports
   * passed DMARC for, as `ingestAggregate` recorded it. `organization` is
   * that domain and `total` counts distinct ones, which is the number the
   * policy stepper compares against its rules. One domain sending reports
   * under several `<org_name>` values is one entry, and `names` says how
   * many it used. Several subdomains of one registered domain are one
   * entry. Several registered domains are several entries, whoever holds
   * them.
   *
   * `orgName` is one of the names the organization's reports gave
   * themselves, and `orgKey` is its folded form. Both are the reporter's
   * own description, written by whoever sent the report, and neither is a
   * verified identity.
   *
   * A receiver that has stopped reporting and a domain whose mail all
   * aligns produce the same empty counting, and those are the two states
   * that most need telling apart. `newestAt` is when the most recent
   * report ARRIVED here, which is the reading that separates them; the
   * window a report declares is a range the reporter chose and says
   * nothing about whether they are still sending. It follows the same
   * exclusion as the count beside it, so a report nobody authenticated
   * cannot hold a domain open by arriving.
   *
   * `records` is how many record rows a reporter's reports contributed,
   * so a reporter sending a report a day with nothing in it reads
   * differently from one carrying the volume.
   *
   * Reports this server did not authenticate name no reporter here, on
   * the same rule the sender listing follows: a reporter heard from only
   * in reports nobody authenticated has not been heard from, and listing
   * it would answer the question about an absence with the thing that
   * caused it. `unauthenticatedReports` counts those reports beside the
   * list. It counts reports rather than messages, which is why it does
   * not share the name the sender listing uses for a volume.
   *
   * `unattributedReports` counts the reports that are evidence and carry
   * no recorded organization, which are the verified reports a volume
   * held before the organization was recorded. Their volume is still in
   * `rollup`. They name no entry here and count toward no organization.
   *
   * With `includeUnauthenticated`, every report that counts toward no
   * organization is listed as well, one entry per `orgKey`, with
   * `organization` null.
   *
   * Nothing here is sealed and nothing is unsealed. A reporting
   * organization names itself in a document it published to a domain that
   * asked for it, and the contact mailbox on the report is a person's
   * address, so it is not among the fields answered. The read is
   * therefore not recorded: a row per page render naming the companies an
   * operator's own DNS record invited is noise in the trail that the rows
   * worth reading have to be found among.
   *
   * Moments are milliseconds since the epoch, and the range is the same
   * one `rollup` reads, so one window control cannot show a counting over
   * one range beside a reporter list over another. Bad arguments throw.
   *
   * @opts
   *   domain: string,    // required, one hosted domain
   *   since:  number,    // windows ending at or after this moment, default all
   *   until:  number,    // windows beginning at or before this moment, default now
   *   limit:  number,    // 1 to 500 reporters, default 50
   *   includeUnauthenticated: boolean,   // list the reporters heard from only in
   *                                      //   reports nobody authenticated, default false
   *
   * @example
   *   var heard = handle.reporters({ domain: "example.com" });
   *   heard.reporters[0].newestAt;
   */
  function reporters(listOpts) {
    listOpts = listOpts || {};
    var wanted = _listedDomain(listOpts.domain, "reporters");
    var span   = _span(listOpts, "reporters");
    var limit  = _whole(listOpts.limit, "reporters limit",
      MIN_LISTED_ROWS, MAX_LISTED_ROWS, DEFAULT_LISTED_ROWS);
    var everything = listOpts.includeUnauthenticated === true;

    var grouped = b.db.prepare(everything ? REPORTER_LIST_EVERY : REPORTER_LIST_COUNTED)
      .all(span.since, span.until, wanted, limit);
    var counted = b.db.prepare(everything ? REPORTER_TOTAL_EVERY : REPORTER_TOTAL_COUNTED)
      .get(span.since, span.until, wanted);
    var filed = b.db.prepare(REPORTER_EXCLUDED).get(span.since, span.until, wanted) || {};

    var heard = grouped.map(function (row) {
      return {
        organization: typeof row.organization === "string" ? row.organization : null,
        orgName:  row.orgName,
        // The folded form of the name shown, so the two describe the same
        // spelling. A group under an organization can hold several names,
        // and `MAX` over each column separately could pick two different
        // rows.
        orgKey:   address.fold(row.orgName),
        names:    row.names || 0,
        reports:  (everything ? row.reportsAll : row.reports) || 0,
        records:  (everything ? row.recordsAll : row.records) || 0,
        newestAt: (everything ? row.newestAtAll : row.newestAt) || 0,
      };
    });

    var total = (counted && counted.total) || 0;
    return {
      domain:      wanted,
      since:       span.since,
      until:       span.until,
      includeUnauthenticated: everything,
      reporters:   heard,
      listed:      heard.length,
      total:       total,
      truncated:   total > heard.length,
      limit:       limit,
      unauthenticatedReports: ((filed.reportsAll || 0) - (filed.reports || 0)),
      unattributedReports:    filed.unattributed || 0,
    };
  }

  // ---- an erasure request from somebody with no account here --------------

  // Every row one address appears in, across the two tables that hold an
  // address at all. The lookup is on the sealed column and the framework
  // rewrites it onto the deployment-keyed hash, which is what makes a
  // sealed column searchable for exactly this.
  function _rowsNaming(canonicalAddress) {
    var found = [];
    var forensicFrom = b.db.from(tables.DMARC_FORENSIC)
      .where({ originalMailFrom: canonicalAddress }).all();
    var forensicRcpt = b.db.from(tables.DMARC_FORENSIC)
      .where({ originalRcptTo: canonicalAddress }).all();
    var contact = b.db.from(tables.DMARC_REPORTS)
      .where({ reportEmail: canonicalAddress }).all();
    var seen = {};
    for (var i = 0; i < forensicFrom.length; i += 1) {
      seen[forensicFrom[i]._id] = true;
      found.push({ table: tables.DMARC_FORENSIC, rowId: forensicFrom[i]._id });
    }
    for (var j = 0; j < forensicRcpt.length; j += 1) {
      if (seen[forensicRcpt[j]._id]) continue;
      found.push({ table: tables.DMARC_FORENSIC, rowId: forensicRcpt[j]._id });
    }
    for (var k = 0; k < contact.length; k += 1) {
      found.push({ table: tables.DMARC_REPORTS, rowId: contact[k]._id });
    }
    return found;
  }

  // The fields of an aggregate report row other than its contact
  // address, which are what a resend is matched by and what the records
  // under it are read with.
  var REPORT_FIELDS_KEPT = [
    "orgName", "orgKey", "reportId", "policyDomain", "alignmentDkim", "alignmentSpf",
    "requestedPolicy", "subdomainPolicy", "samplePercent", "failureOptions", "windowBegin",
    "windowEnd", "storedCount", "refusedCount", "evidence", "verifiedOrgDomain", "receivedAt",
  ];

  // A report row written again without its contact is first stored under
  // a pending key, which is the report's own key with the old row's id
  // after `PENDING_KEY_MARK`. The old row is then erased, and settling
  // moves the records onto the new row and gives it the report's key.
  // Each step is durable on its own, so a failure or a stopped process
  // between them leaves a pending row that the next settle finishes.
  // The mark is two unit separators around a word. An organization name
  // carrying a control character is refused at ingest, so no stored key
  // holds one, and the query builder refuses a NUL in any parameter.
  //
  // A pending row is found by its `storedCount`, which it holds as
  // `-(n + 1)` for a report that stored `n` records. A count is never
  // negative otherwise, and a comparison on it is a plain indexed read.
  var PENDING_KEY_MARK = "\u001fpending\u001f";

  function _beginRewrite(kept) {
    var copy = { reportEmail: null };
    for (var f = 0; f < REPORT_FIELDS_KEPT.length; f += 1) {
      var name = REPORT_FIELDS_KEPT[f];
      if (kept[name] !== undefined) copy[name] = kept[name];
    }
    copy.orgKey = kept.orgKey + PENDING_KEY_MARK + kept._id;
    copy.storedCount = -((Number(kept.storedCount) || 0) + 1);
    return tables.insertRow(tables.DMARC_REPORTS, copy);
  }

  // Finish one pending row. Where the old row is still there its erasure
  // never happened, so the pending row is removed and the old row keeps
  // the report's key.
  function _settleRewrite(pending) {
    var cut = pending.orgKey.indexOf(PENDING_KEY_MARK);
    if (cut === -1) return;
    var realKey = pending.orgKey.slice(0, cut);
    var oldId = pending.orgKey.slice(cut + PENDING_KEY_MARK.length);
    if (b.db.from(tables.DMARC_REPORTS).where({ _id: oldId }).first()) {
      tables.deleteRow(tables.DMARC_REPORTS, pending._id);
      return;
    }
    b.db.transaction(function () {
      var records = b.db.from(tables.DMARC_RECORDS).where({ reportRowId: oldId }).all();
      for (var r = 0; r < records.length; r += 1) {
        tables.updateRow(tables.DMARC_RECORDS, records[r]._id, { reportRowId: pending._id });
      }
      tables.updateRow(tables.DMARC_REPORTS, pending._id, {
        orgKey:      realKey,
        storedCount: -(Number(pending.storedCount) || -1) - 1,
      });
    });
  }

  // Finish every pending row on the volume. Run before a report is
  // matched against the ones already stored and before an erasure, so a
  // rewrite a stopped process left half done is completed first.
  function _settlePendingRewrites() {
    var pending = b.db.from(tables.DMARC_REPORTS).where("storedCount", "<", 0).all();
    for (var p = 0; p < pending.length; p += 1) _settleRewrite(pending[p]);
  }

  /**
   * @primitive blamepost.store.reports.forgetAddress
   * @signature reports.forgetAddress(address, reason)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: an erasure request from somebody with no account here)
   * @related   blamepost.store.reports.ingestForensic, blamepost.store.reports.sweep
   *
   * Destroy every report row naming one address, and record that it was
   * asked for. The person asking has no account on this server and no
   * verb of their own to reach, so an operator receiving the request
   * runs this on their behalf; `reason` is what the row records about
   * why, and it is required for the same reason a destroying account
   * verb requires one.
   *
   * Answers `{ address, destroyed, preserved, failed }`. `address` is
   * the folded form the rows were found by. `preserved` names the rows
   * something is deliberately keeping, which is a preservation order or
   * a governance gate rather than a fault, and `failed` names the rest,
   * because those two need opposite responses from whoever reads the
   * result.
   *
   * Destruction is `b.db.eraseHard`, so the row's wrapped key is
   * destroyed with it and the sealed cells left behind in the
   * write-ahead log read as absent rather than as ciphertext.
   *
   * An aggregate report whose contact address is the one named is erased
   * the same way and then written again with no contact address, and its
   * records are moved onto the new row. A resend of that report is still
   * recognized as one, so its records are not counted a second time and
   * the address it carries is not stored again.
   *
   * @example
   *   await handle.forgetAddress("stranger@example.net", "erasure request received by post");
   */
  async function forgetAddress(wanted, reason) {
    var parsed = address.canonical(wanted, "address");
    if (typeof reason !== "string" || reason.trim().length === 0) {
      throw err(BAD_OPTS,
        "forgetAddress needs the reason the erasure was asked for. It is what the trail " +
        "records about why these rows are gone, and there is nobody else to ask afterwards.");
    }
    var recorded = reason.trim();

    _settlePendingRewrites();
    var rows = _rowsNaming(parsed.address);
    var destroyed = 0;
    var preserved = [];
    var failed = [];
    for (var i = 0; i < rows.length; i += 1) {
      try {
        // A report row is what a resend of that report is matched against,
        // and its records count toward the policy evidence. The row naming
        // the address is erased and written again without it, and its
        // records are moved onto the new row, so a resend is still read as
        // one and its records are not counted twice.
        var kept = rows[i].table === tables.DMARC_REPORTS
          ? b.db.from(tables.DMARC_REPORTS).where({ _id: rows[i].rowId }).first()
          : null;
        var pending = kept ? _beginRewrite(kept) : null;
        var result;
        try {
          result = b.db.eraseHard(rows[i].table, rows[i].rowId,
            { reason: "erasure requested: " + recorded, subjectId: parsed.address });
        } catch (eraseError) {
          // Nothing was erased, so the copy is not needed.
          if (pending) tables.deleteRow(tables.DMARC_REPORTS, pending._id);
          throw eraseError;
        }
        destroyed += (result && result.rowsDeleted) || 0;
        if (pending) _settleRewrite(pending);
      } catch (e) {
        // Two outcomes, kept apart. Something holding a row on purpose
        // is the system working and the request is finished by releasing
        // the hold; anything else is a fault and somebody has to go and
        // look at it. One bucket would send an operator to the wrong one.
        var entry = { table: rows[i].table, rowId: rows[i].rowId,
          code: (e && e.code) || null };
        if (errors.isPreservationRefusal(entry.code)) preserved.push(entry);
        else failed.push(entry);
      }
    }

    // Recorded after the rows are gone, not before. A trail saying an
    // erasure happened, written ahead of an erasure that then refused,
    // is the one reading nobody can correct afterwards.
    await auditActor.record({
      action:   "blamepost.store.reports.address_forgotten",
      outcome:  failed.length > 0 ? "failure" : "success",
      actor:    auditActor.current(),
      resource: { kind: "dmarc-forensic", id: parsed.address },
      metadata: { reason: recorded, destroyed: destroyed,
        preserved: preserved.length, failed: failed.length },
    });

    return { address: parsed.address, destroyed: destroyed,
      preserved: preserved, failed: failed };
  }

  // ---- the sweep ----------------------------------------------------------

  /**
   * @primitive blamepost.store.reports.sweep
   * @signature reports.sweep(runOpts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: report rows carry a deadline rather than a floor)
   * @related   blamepost.store.reports.start, blamepost.store.reports.create
   *
   * Run every retention rule once and answer what it did:
   * `{ destroyed, dryRun, summaries }`. The forensic rule and the two
   * aggregate rules each act on their own window, so the shorter one
   * destroys a stranger's envelope while the counting it belonged to
   * stays. On a dry run nothing is touched and `destroyed` is the count
   * that would have gone, which is what `dryRun` in the answer is there
   * to tell a reader.
   *
   * Records are swept before the reports they belong to, so no pass
   * leaves a record row pointing at a report that is already gone.
   *
   * A row something is deliberately keeping is skipped and counted, and
   * a row that will not destroy is collected into that rule's errors;
   * neither stops the pass. `start` calls this on a timer, and an
   * operator verb can call it directly.
   *
   * @opts
   *   dryRun: boolean,   // count what would go and destroy nothing
   *
   * @example
   *   var swept = await handle.sweep({ dryRun: true });
   *   swept.destroyed;
   */
  async function sweep(runOpts) {
    var settings = runOpts || {};
    var summaries = await rules.runAll(settings);
    var destroyed = 0;
    for (var i = 0; i < summaries.length; i += 1) {
      destroyed += summaries[i].processed || 0;
    }
    return { destroyed: destroyed, dryRun: settings.dryRun === true, summaries: summaries };
  }

  /**
   * @primitive blamepost.store.reports.start
   * @signature reports.start()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: report retention sweep lifecycle)
   * @related   blamepost.store.reports.stop, blamepost.store.reports.sweep
   *
   * Arm the sweep so rows are destroyed as their windows pass. Calling
   * it twice keeps the first timer. A process that only reads, such as
   * one command line invocation, never calls this and so never holds the
   * event loop open.
   *
   * @example
   *   handle.start();
   */
  function start() {
    if (sweepTimer) return sweepTimer;
    sweepTimer = b.safeAsync.repeating(function () {
      return sweep({});
    }, sweepIntervalMs, {
      unref: true,
      name:  "blamepost-dmarc-report-sweep",
      onError: function (sweepError) {
        // Hot path observability sink. A pass that could not finish is
        // recorded and the timer keeps running; throwing here would take
        // the process down over one row that would not destroy, and the
        // next pass reaches the same rows.
        try {
          b.audit.safeEmit({
            action:   "blamepost.store.reports.sweep_failed",
            outcome:  "failure",
            actor:    auditActor.current(),
            metadata: {
              error: displayText.forDisplay(
                (sweepError && sweepError.message) || String(sweepError)),
            },
          });
        } catch (_e) {
          // allow:swallow-unverified the audit sink is the reporting path
          // itself and swallows inside safeEmit, and this handler runs on
          // a repeating timer where a throw ends the process.
        }
      },
    });
    return sweepTimer;
  }

  /**
   * @primitive blamepost.store.reports.stop
   * @signature reports.stop()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: report retention sweep lifecycle)
   * @related   blamepost.store.reports.start
   *
   * Disarm the sweep. Shutdown calls it before the store closes, so no
   * pass is reading rows while the volume is being written back. Rows
   * past their window stay and the next boot destroys them.
   *
   * @example
   *   handle.stop();
   */
  function stop() {
    if (!sweepTimer) return;
    sweepTimer.stop();
    sweepTimer = null;
  }

  /**
   * @primitive blamepost.store.reports.describe
   * @signature reports.describe()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the settings in force, published rather than recomputed)
   * @related   blamepost.store.reports.create
   *
   * The bounds and switches this handle is running under, and whether
   * the sweep is armed. It is what the console and `blamepost doctor`
   * report, so an operator reading how long these rows are kept reads
   * the numbers actually in force rather than the ones a document says.
   *
   * @example
   *   handle.describe().forensicRetentionMs;
   */
  function describe() {
    return {
      aggregateRetentionMs: aggregateRetentionMs,
      forensicRetentionMs:  forensicRetentionMs,
      sweepIntervalMs:      sweepIntervalMs,
      forensicEnabled:      forensicEnabled,
      maxReportBytes:       maxReportBytes,
      maxRecordsPerReport:  maxRecordsPerReport,
      sweeping:             sweepTimer !== null,
      rules:                rules.list(),
    };
  }

  return {
    ingestAggregate: ingestAggregate,
    ingestForensic:  ingestForensic,
    rollup:          rollup,
    failingSources:  failingSources,
    reporters:       reporters,
    forgetAddress:   forgetAddress,
    sweep:           sweep,
    start:           start,
    stop:            stop,
    describe:        describe,
  };
}

module.exports = {
  create: create,
  MIN_AGGREGATE_RETENTION_MS: MIN_AGGREGATE_RETENTION_MS,
  MAX_AGGREGATE_RETENTION_MS: MAX_AGGREGATE_RETENTION_MS,
  MIN_FORENSIC_RETENTION_MS:  MIN_FORENSIC_RETENTION_MS,
  MAX_FORENSIC_RETENTION_MS:  MAX_FORENSIC_RETENTION_MS,
  MIN_SWEEP_INTERVAL_MS:      MIN_SWEEP_INTERVAL_MS,
  MAX_SWEEP_INTERVAL_MS:      MAX_SWEEP_INTERVAL_MS,
  DEFAULT_SWEEP_INTERVAL_MS:  DEFAULT_SWEEP_INTERVAL_MS,
  DEFAULT_MAX_REPORT_BYTES:   DEFAULT_MAX_REPORT_BYTES,
  DEFAULT_MAX_RECORDS:        DEFAULT_MAX_RECORDS,
};
