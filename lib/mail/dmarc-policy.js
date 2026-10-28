// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.mail.dmarcPolicy
 * @nav    DNS and domain authentication
 * @title  DMARC policy steps
 * @order  30
 *
 * @intro
 *   Whether a hosted domain's evidence justifies moving its DMARC policy
 *   from `p=none` to `p=quarantine`, and from there to `p=reject`, and
 *   the exact record text each level would be published as. It decides;
 *   it publishes nothing.
 *
 *   It is a file of its own because neither of the two files beside it
 *   owns the question. `blamepost.mail.posture` resolves what a zone publishes and
 *   compares it against what this server expects, and it reaches no
 *   store. `blamepost.mail.reports` reads reports off the wire and files
 *   them, and it reaches no resolver. The step decision needs both
 *   readings at once and owns neither, so putting it in either would give
 *   one of them a dependency on the other's whole layer.
 *
 *   ## The counting is the only evidence, and the wider reading is not
 *   reachable from here
 *
 *   `blamepost.store.reports.rollup` counts the reports whose carrier
 *   this server authenticated and publishes the volume it left out beside
 *   the counting. Anybody who can send mail to the address in a published
 *   `rua=` record can compose a well formed report saying whatever they
 *   like, so a step taken on the wider reading is a step taken by
 *   whoever wanted it taken.
 *
 *   Three things keep the wider reading out rather than one, because a
 *   rule that is merely not asked for is a rule one edit away from being
 *   asked for.
 *
 *   The evaluation never holds the store handle. `create` captures it in
 *   the reader built below and hands the evaluation that reader, so there
 *   is no argument, option or setting through which a caller reaches
 *   `rollup`, `failingSources` or `reporters` from here.
 *
 *   The reader passes `includeUnauthenticated: false` as a literal on
 *   every call, in an object built here from fixed keys. Nothing a caller
 *   passed is merged into it and there is no spread and no
 *   `Object.assign`, so a caller's value cannot reach the flag. Those
 *   three verbs widen on an explicit `true` and on nothing else, which
 *   makes a literal `false` the narrow reading whatever else was in
 *   flight.
 *
 *   The reader copies a fixed list of fields out of each answer and the
 *   wider figures are not on that list, so no arithmetic below can reach
 *   them even by name. The two lists are checked against each other at
 *   load, and a field belonging to the wider reading appearing on the
 *   kept list stops the process rather than quietly widening what a step
 *   rests on.
 *
 *   ## What a source marking is, and where it lives
 *
 *   A failing source is a sending address that failed both alignments for
 *   a hosted domain, over a floor, in the window being read. The rules
 *   below do not ask what share of the volume those sources carry,
 *   because the alignment threshold already counts every failing message.
 *   They ask whether an operator has LOOKED at each one and written down
 *   what it is, and that writing is the evidence.
 *
 *   A marking says one of two things. `ours-and-fixed` says the address
 *   is a sending path of the operator's and its alignment has been
 *   corrected. `not-ours` says it is not, so its failures are the
 *   forgeries a policy exists to stop. The pair is not decoration: a
 *   source marked `ours-and-fixed` that is still failing in a window
 *   ending well after the marking was written has had its claim
 *   contradicted by the reporters, and that blocks the step. A source
 *   marked `not-ours` that keeps failing is the expected case and blocks
 *   nothing.
 *
 *   The marking is written to the audit trail and read back from it, and
 *   there is no column anywhere holding a current answer. Three
 *   properties decide that. The trail is hash-linked and
 *   operator-attributed, so a marking carries who wrote it and cannot be
 *   edited afterwards without the chain saying so, and a marking is the
 *   thing that lets a policy tighten. It already carries a first-class
 *   `reason` column, which is the sentence the operator wrote. And it is
 *   append-only, so a later marking supersedes an earlier one and both
 *   stay readable, which is what an operator asking why a domain stepped
 *   needs.
 *
 *   The address itself is not written into the row. What identifies the
 *   source is the deployment-keyed hash the record rows are already
 *   indexed by, derived here through `b.db.hashFor` from the same
 *   declaration the store seals that column under. A second copy of the
 *   address in the trail would sit in a table with its own window and no
 *   erasure path, and `blamepost.store.reports.forgetAddress` is the
 *   erasure path for the copy that already exists.
 *
 *   Reading the trail costs a row. `b.audit.query` records every read of
 *   the trail before it answers, so an evaluation writes two of those
 *   rows, and the failing-source listing it also makes writes a third of
 *   its own. Those rows come with keeping the marking in the trail rather
 *   than in a column somebody can edit, and they are written when an
 *   operator opens a page rather than on any message path.
 *
 *   ## How long a domain has been at quarantine
 *
 *   The reject step asks for time already served at `p=quarantine`.
 *   Nothing on this volume records when a zone changed, and a record an
 *   operator published by hand leaves no trace here at all, so the answer
 *   is measured rather than looked up: each evaluation reads the record
 *   the domain publishes now, and writes an observation to the trail when
 *   the policy differs from the last one it recorded. The age of the run
 *   of observations carrying `quarantine` is what the rule reads.
 *
 *   A domain evaluated for the first time today therefore has one day of
 *   observation whatever its zone has held, and the refusal says so and
 *   names the date the rule would clear. Not knowing is its own verdict
 *   here, exactly as it is for a lookup that ran out of budget.
 *
 *   ## Stepping down is not gated
 *
 *   Every refusal below is about tightening. Weakening a policy needs no
 *   evidence, no threshold and no marking: an operator whose mail is
 *   being discarded needs the shortest path back, and a check on the way
 *   out is a check on the way out of an incident. The record text for
 *   every level is answered on every reading, including the readings that
 *   refuse to step up, so the text an operator publishes to reverse is in
 *   front of them before they need it and does not depend on this server
 *   being healthy when they do.
 *
 *   ## Refusals
 *
 *   An operator-facing verb throws on an argument it cannot act on: a
 *   domain that is not one, a disposition outside the pair, a marking
 *   with no reason. A domain whose evidence does not carry a step is not
 *   an error and does not throw. It is a verdict, with a code naming
 *   which rule was not met and a sentence naming what is missing and what
 *   would clear it.
 *
 *   A lookup that did not complete is kept apart from a domain that
 *   publishes nothing, for the reason `blamepost.mail.posture` keeps them
 *   apart: folding the two would let whoever can stall a query decide
 *   when this server tightens a policy.
 */

var nodeNet = require("node:net");

var b          = require("../vendor/blamejs");
var address    = require("../store/address");
var auditActor = require("../store/actor");
// The table the sending address is sealed on. It is required rather than
// spelled out because the hash this module matches a marking on has to be
// the one the store's own rows are indexed by, and the declaration is
// where that is decided.
var tables     = require("../store/tables");
var posture    = require("./posture");

var TIME = b.constants.TIME;

var DAY_MS = TIME.days(1);

// Whole parts per thousand, so an alignment threshold with a half
// percent in it is compared as integers. A percentage held as a floating
// point number and multiplied out is a threshold that answers
// differently for two volumes that should compare the same way.
var PER_MILLE = 1000;

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------
//
// These are constants and not settings, and that is the decision rather
// than an omission. Every one of them is the security property: an
// operator who can set the alignment threshold to half can clear the gate
// without clearing anything, and a gate with a way past it is not one.
// They are published by `describe` so a console can render what is
// required beside what a domain has, which is the part an operator
// actually needs.

// The policy levels, weakest first. The order is the whole of what
// "stepping up" and "stepping down" mean here.
//
// Every member is a policy this server will judge a step to and print a
// record for, so this is a list of what it OFFERS: a level leaving it is
// a record an operator can no longer ask for, and one arriving is a
// policy the stepper now reasons about.
//
// @membership blamepost.mail.dmarcPolicy.LEVELS capability
var LEVEL_NONE       = "none";
var LEVEL_QUARANTINE = "quarantine";
var LEVEL_REJECT     = "reject";

var LEVELS = Object.freeze([LEVEL_NONE, LEVEL_QUARANTINE, LEVEL_REJECT]);
// The two readings recorded beside a policy that publish none: no record
// at the domain's own name, and one no receiver reads a policy from.
var GAPS = Object.freeze(["absent", "unusable"]);

// Moving to quarantine.
//
// The span is what says the evidence covers a working month's worth of
// sending patterns rather than a quiet week. The distinct days are what
// says the span was actually reported on. The organizations are what says
// one reporter's outage is not being read as a clean domain, which a
// single reporter cannot tell apart from silence.
var QUARANTINE_SPAN_DAYS     = 14;
var QUARANTINE_REPORT_DAYS   = 7;
var QUARANTINE_ORGANIZATIONS = 2;
var QUARANTINE_ALIGNED_PER_MILLE = 980;

// Moving to reject.
var REJECT_SPAN_DAYS     = 30;
var REJECT_REPORT_DAYS   = 21;
var REJECT_ORGANIZATIONS = 3;
var REJECT_ALIGNED_PER_MILLE = 995;

// How long the domain must already have been publishing quarantine, by
// this server's own observation, before reject is offered.
var REJECT_HELD_DAYS = 14;

// The volume each threshold is measured over, and the reason there is one
// at all.
//
// An alignment threshold is a claim about a rate, and a rate needs a
// denominator large enough to express it. At 98 percent the smallest
// failure a domain can have and still pass is one message in fifty, so a
// window carrying fewer than fifty counted messages cannot distinguish a
// domain that aligns from one that has not sent anything worth measuring:
// three messages, all aligned, reads as a hundred percent. Fifty and two
// hundred are the arithmetic floors for the two thresholds. The numbers
// below are twice those, so one message does not decide a step, and the
// doubling is a judgment rather than a derivation.
var QUARANTINE_MIN_MESSAGES = 100;
var REJECT_MIN_MESSAGES     = 500;

// The largest run of days inside the window, and at the end of it, that
// may carry no report. Evidence with a hole in it is evidence about the
// days on either side of the hole, and a policy stepped on it is stepped
// over whatever happened in the middle.
var MAX_GAP_DAYS = 3;

// The failing volume a source has to reach before an operator is asked to
// write down what it is. Below it a single stray message from a
// misdirected bounce would require a written marking, and the alignment
// threshold already counts that message whether it is marked or not: the
// floor governs which sources need a sentence, never which messages
// count. Five is a judgment and it is exposed by `describe` so it is at
// least a visible one.
var SOURCE_FLOOR_MESSAGES = 5;

// How long a claim that a source was fixed has to take effect before the
// reporters get to contradict it. Reports arrive a day or two behind the
// window they cover, so a marking written today is answered by a report
// for yesterday, and a claim held to that would be contradicted the
// moment it was made.
var FIX_GRACE_DAYS = 7;

// What one marking may say. Two values, because they are the two things
// an operator can find out about a source that is failing, and because
// the pair is what makes a marking evidence rather than a checkbox.
var MARK_OURS_FIXED = "ours-and-fixed";
var MARK_NOT_OURS   = "not-ours";

// Every member is something an operator may write about a failing
// source, so this is a list of what the marking verb OFFERS: a value
// leaving it is a finding that can no longer be recorded, and one
// arriving is a finding the rules can be taught to read.
//
// @membership blamepost.mail.dmarcPolicy.DISPOSITIONS capability
var DISPOSITIONS = Object.freeze([MARK_OURS_FIXED, MARK_NOT_OURS]);

// The reason an operator writes on a marking, bounded. It is read later
// by whoever is asking why a domain stepped, and it is not a place to put
// a document.
var MAX_REASON_CHARS = 1000;

// How many senders one evaluation lists, and how many markings it reads.
// Both are ceilings the answer is checked against rather than bounds it
// quietly stops at: an evaluation that saw part of the list would be
// answering "no source is unreviewed" about the part it saw, which is the
// shape of every gate that passes because its instrument stopped early.
var SOURCE_LIST_LIMIT = 500;
var MARKING_LIMIT     = 2000;
var OBSERVATION_LIMIT = 500;

// The trail rows this module writes and reads.
//
// The two emits below write the action out as a literal rather than
// reading it from here, because a name assembled at the emit is one the
// namespace check cannot read, and an action under a namespace nothing
// registered is a row that never lands. These constants are what the
// READ side asks for and what a caller filtering the trail is given, and
// the test over a row this module actually wrote compares the two, so a
// rename that reached one and not the other fails there.
// The action names are lowercase because the trail's own grammar is: an
// action is a namespace, a verb and its qualifiers, dot separated and
// lowercase, and a name outside it is refused at the emit and the row is
// gone. So they are not the module's dotted name with a capital in it.
var MARKED_ACTION   = "blamepost.mail.dmarc_policy.source_marked";
var OBSERVED_ACTION = "blamepost.mail.dmarc_policy.policy_observed";
var SOURCE_KIND     = "dmarc-source";
var DOMAIN_KIND     = "dmarc-domain";

// What separates the domain from the source digest in a marking's
// resource identifier. A digest is hexadecimal and a domain name cannot
// contain this character, so the two halves come apart again exactly.
var RESOURCE_SEPARATOR = "|";

// ---------------------------------------------------------------------------
// Every reason a step is refused
// ---------------------------------------------------------------------------
//
// One code per reason, and each one carries a sentence naming what is
// missing and what would clear it. They are separate because the remedies
// have nothing in common: a lookup that did not complete is a question
// about the resolver, a record that is not published is a question about
// the zone, and a source nobody has looked at is a question for the
// operator.

var POSTURE_UNRESOLVED   = "posture-unresolved";
var POSTURE_UNPUBLISHED  = "posture-unpublished";
var POSTURE_UNUSABLE     = "posture-unusable";
var SAMPLE_NOT_WHOLE     = "sample-not-whole";
var SPF_NOT_STRICT       = "spf-not-strict";
var DKIM_UNPUBLISHED     = "dkim-unpublished";
var AT_STRONGEST_POLICY  = "at-strongest-policy";
var EVIDENCE_ABSENT      = "evidence-absent";
var EVIDENCE_YOUNG       = "evidence-young";
var EVIDENCE_SPARSE      = "evidence-sparse";
var EVIDENCE_STALE       = "evidence-stale";
var EVIDENCE_GAPPED      = "evidence-gapped";
var REPORTERS_THIN       = "reporters-thin";
var VOLUME_THIN          = "volume-thin";
var ALIGNMENT_SHORT      = "alignment-short";
var SOURCES_UNREVIEWED   = "sources-unreviewed";
var FIX_CONTRADICTED     = "fix-claim-contradicted";
var SOURCE_UNREADABLE    = "source-address-unreadable";
var SOURCES_TRUNCATED    = "sources-not-fully-listed";
var MARKINGS_TRUNCATED   = "markings-not-fully-listed";
var QUARANTINE_UNOBSERVED = "quarantine-age-unobserved";
var QUARANTINE_SHORT     = "quarantine-held-short";
var RETENTION_TOO_SHORT  = "retention-shorter-than-window";

var CODES = Object.freeze({
  postureUnresolved:      POSTURE_UNRESOLVED,
  postureUnpublished:     POSTURE_UNPUBLISHED,
  postureUnusable:        POSTURE_UNUSABLE,
  sampleNotWhole:         SAMPLE_NOT_WHOLE,
  spfNotStrict:           SPF_NOT_STRICT,
  dkimUnpublished:        DKIM_UNPUBLISHED,
  atStrongestPolicy:      AT_STRONGEST_POLICY,
  evidenceAbsent:         EVIDENCE_ABSENT,
  evidenceYoung:          EVIDENCE_YOUNG,
  evidenceSparse:         EVIDENCE_SPARSE,
  evidenceStale:          EVIDENCE_STALE,
  evidenceGapped:         EVIDENCE_GAPPED,
  reportersThin:          REPORTERS_THIN,
  volumeThin:             VOLUME_THIN,
  alignmentShort:         ALIGNMENT_SHORT,
  sourcesUnreviewed:      SOURCES_UNREVIEWED,
  fixClaimContradicted:   FIX_CONTRADICTED,
  sourceAddressUnreadable: SOURCE_UNREADABLE,
  sourcesNotFullyListed:  SOURCES_TRUNCATED,
  markingsNotFullyListed: MARKINGS_TRUNCATED,
  quarantineAgeUnobserved: QUARANTINE_UNOBSERVED,
  quarantineHeldShort:    QUARANTINE_SHORT,
  retentionShorterThanWindow: RETENTION_TOO_SHORT,
});

// ---------------------------------------------------------------------------
// The narrowing reader
// ---------------------------------------------------------------------------

// The figures the evaluation is allowed to see, and the figures that
// belong to the wider reading. Written as two lists rather than as one
// rule, because the check below is the thing that has to hold and a rule
// nothing tests is a comment.
var KEPT_WINDOW_FIELDS = Object.freeze([
  "domain", "windowBegin", "windowEnd", "counted", "aligned", "unaligned", "failingSources",
]);
var KEPT_SOURCE_FIELDS = Object.freeze([
  "sourceIp", "readable", "messages", "aligned", "windows", "lastSeen",
]);

// What `rollup`, `failingSources` and `reporters` call the reading that
// includes the reports nobody authenticated, and the flag that asks for
// it. None of these may appear on either list above.
var WIDE_FIELDS = Object.freeze([
  "countedAll", "alignedAll", "failingSourcesAll", "failedAll", "windowsAll", "lastSeenAll",
  "reportsAll", "recordsAll", "newestAtAll",
  "unauthenticated", "unauthenticatedReports", "includeUnauthenticated",
]);

// Checked at load rather than trusted to review, in the shape
// `blamepost.mail.posture` checks its own absence set.
//
// A step taken on the wider reading is a step taken by whoever wrote the
// report, and the way that happens is not somebody arguing for it: it is
// one field name added to a list of fields to copy, in a change about
// something else, reviewed by somebody who did not know what the list
// was for. So the field name arriving on the kept list stops the process
// with the reason on the line rather than widening what a policy rests
// on.
(function _refuseWideFieldsOnTheKeptLists() {
  var kept = KEPT_WINDOW_FIELDS.concat(KEPT_SOURCE_FIELDS);
  for (var i = 0; i < WIDE_FIELDS.length; i += 1) {
    if (kept.indexOf(WIDE_FIELDS[i]) !== -1) {
      throw new TypeError("blamepost.mail.dmarcPolicy: " + WIDE_FIELDS[i] + " belongs to the " +
        "reading that includes reports this server did not authenticate, and it is on the " +
        "list of figures the step evaluation copies. Anybody who can send mail to a " +
        "published reporting address can write those numbers, so a policy stepped on them " +
        "is a policy stepped by whoever wanted it stepped.");
    }
  }
}());

// The three questions the evaluation asks about volume, over a store
// handle it never sees. Every call builds its own options object from
// fixed keys, and `includeUnauthenticated` is written as a literal false
// on each one: those verbs widen on an explicit true and on nothing else,
// so a value that arrived from anywhere cannot reach the flag because
// nothing is merged in.
function _evidenceReader(store) {
  function _keep(row, fields) {
    var out = {};
    for (var i = 0; i < fields.length; i += 1) {
      var value = row[fields[i]];
      out[fields[i]] = value === undefined ? null : value;
    }
    return Object.freeze(out);
  }

  return Object.freeze({
    // What the store is running under. Read once so a window longer than
    // the rows are kept for is answered as the deployment question it is
    // rather than as a domain that never accumulates evidence.
    retentionMs: function () {
      var settings = store.describe();
      return (settings && settings.aggregateRetentionMs) || 0;
    },

    windows: function (domain, since, until) {
      var rows = store.rollup({
        domain: domain,
        since:  since,
        until:  until,
        includeUnauthenticated: false,
      });
      var out = [];
      for (var i = 0; i < rows.length; i += 1) out.push(_keep(rows[i], KEPT_WINDOW_FIELDS));
      return out;
    },

    failing: async function (domain, since, until) {
      var answer = await store.failingSources({
        domain: domain,
        since:  since,
        until:  until,
        limit:  SOURCE_LIST_LIMIT,
        includeUnauthenticated: false,
      });
      var listed = Array.isArray(answer.sources) ? answer.sources : [];
      var out = [];
      for (var i = 0; i < listed.length; i += 1) out.push(_keep(listed[i], KEPT_SOURCE_FIELDS));
      return Object.freeze({
        sources:   out,
        total:     answer.total || 0,
        truncated: answer.truncated === true,
      });
    },

    organizations: function (domain, since, until) {
      var answer = store.reporters({
        domain: domain,
        since:  since,
        until:  until,
        limit:  1,
        includeUnauthenticated: false,
      });
      // Only the count is copied out. `total` is the number of distinct
      // registered domains the carriers of counted reports passed DMARC
      // for, so one domain sending reports under several names is one.
      // The names are not evidence for any rule here, and a reporter's own
      // spelling of itself is text somebody else wrote.
      return answer.total || 0;
    },
  });
}

// ---------------------------------------------------------------------------
// Reading a value
// ---------------------------------------------------------------------------

function _dayOf(moment) {
  return Math.floor(moment / DAY_MS);
}

function _wholeDays(fromMoment, toMoment) {
  return Math.floor((toMoment - fromMoment) / DAY_MS);
}

function _asDate(moment) {
  return new Date(moment).toISOString().slice(0, 10);
}

// The percentage a share reads as, for a sentence rather than for a
// comparison. The comparisons above are integer arithmetic over parts per
// thousand; this is the same number rounded for printing, and it is
// deliberately not what any threshold is tested against.
function _percentOf(part, whole) {
  if (whole <= 0) return 0;
  return Math.round((part * PER_MILLE * 100) / whole) / PER_MILLE;
}

// The tag grammar RFC 9989 §4.8 gives a DMARC tag value: printable ASCII
// with the semicolon excluded, since that is what separates one tag from
// the next. A tag from a published record that falls outside it is not
// carried into a record this server offers an operator to publish.
function _printableTagValue(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  for (var i = 0; i < value.length; i += 1) {
    var code = value.charCodeAt(i);
    if (code < 0x21 || code > 0x7E || code === 0x3B) return false;
  }
  return true;
}

var TAG_KEY_MAX = 32;

function _printableTagKey(key) {
  if (typeof key !== "string" || key.length === 0 || key.length > TAG_KEY_MAX) return false;
  for (var i = 0; i < key.length; i += 1) {
    var code = key.charCodeAt(i);
    var alpha = (code >= 0x41 && code <= 0x5A) || (code >= 0x61 && code <= 0x7A);
    var digit = code >= 0x30 && code <= 0x39;
    if (!alpha && !digit && code !== 0x2D && code !== 0x5F) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// The record an operator would publish
// ---------------------------------------------------------------------------

/**
 * @primitive blamepost.mail.dmarcPolicy.recordFor
 * @signature blamepost.mail.dmarcPolicy.recordFor(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 9989 §4.8, RFC 7489 §6.3
 * @related   blamepost.mail.dmarcPolicy.evaluate, blamepost.mail.posture.dmarcRecord
 *
 * The exact `_dmarc` TXT value one policy level would be published as.
 * Returns `{ value, dropped }`, where `value` is the record text and
 * `dropped` names any tag of the published record that was left out of
 * it.
 *
 * It is built from the record the domain already publishes when there is
 * one: `v` first, `p` set to the level second, and every other published
 * tag after them in the order it was published. A step changes the
 * policy and nothing else, so the reporting addresses, the alignment
 * modes and the subdomain policy an operator chose all survive it.
 *
 * Two tags are treated differently. A `pct` tag is never carried,
 * because RFC 7489 §6.3 makes an absent one mean the whole of the mail
 * and RFC 9989 removed the tag; a record this server offers applies its
 * policy to all of the mail, which is what the evidence rules ask for. A
 * `rua` tag is added, pointing at the address this server collects
 * reports at, when the published record carries none and when there is
 * no published record at all, because a domain that asks for no reports
 * accumulates no evidence.
 *
 * A published tag whose name or value falls outside the RFC 9989 §4.8
 * grammar is left out and named in `dropped`. The record came from DNS,
 * the value is printed into a terminal and pasted into a provider's
 * form, and a tag carrying something a terminal would act on rather than
 * print is not carried into either.
 *
 * Bad arguments throw. A level outside the three, and a reporting
 * address that is not an address, are mistakes a person reads back at a
 * terminal.
 *
 * @opts
 *   level:            string,   // required, one of none / quarantine / reject
 *   reportingAddress: string,   // required, the address the rua tag names
 *   published:        string,   // the record the domain publishes today, if any
 *
 * @example
 *   var policy = require("./lib/mail/dmarc-policy");
 *   policy.recordFor({
 *     level:            "quarantine",
 *     reportingAddress: "dmarc-reports@example.com",
 *     published:        "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com",
 *   }).value;
 */
function recordFor(opts) {
  opts = opts || {};
  if (LEVELS.indexOf(opts.level) === -1) {
    throw new TypeError("blamepost.mail.dmarcPolicy.recordFor: opts.level must be one of " +
      LEVELS.join(", ") + ", and it is " + JSON.stringify(String(opts.level)) + ".");
  }
  var reportingAddress = address.canonical(opts.reportingAddress,
    "blamepost.mail.dmarcPolicy.recordFor: opts.reportingAddress").address;

  var published = typeof opts.published === "string" ? opts.published : "";
  if (published.length > posture.MAX_DMARC_RECORD_CHARS) published = "";

  var pairs = published.length === 0
    ? []
    : b.structuredFields.parseTagList(published, { unfold: true, stripValueWs: true });

  var tags = ["v=DMARC1", "p=" + opts.level];
  var dropped = [];
  var haveRua = false;
  for (var i = 0; i < pairs.length; i += 1) {
    var key = String(pairs[i][0] || "").toLowerCase();
    var value = pairs[i][1];
    if (key === "v" || key === "p" || key === "pct") continue;
    if (!_printableTagKey(key) || !_printableTagValue(value)) {
      if (dropped.indexOf(key) === -1) dropped.push(_printableTagKey(key) ? key : "a tag");
      continue;
    }
    if (key === "rua") haveRua = true;
    tags.push(key + "=" + value);
  }
  if (!haveRua) tags.splice(2, 0, "rua=mailto:" + reportingAddress);

  return { value: tags.join("; "), dropped: dropped };
}

// The three record texts, answered together on every reading so an
// operator has the one they need to reverse with in front of them before
// they need it.
function _recordsFor(published, reportingAddress) {
  var out = { records: {}, dropped: [] };
  for (var i = 0; i < LEVELS.length; i += 1) {
    var built = recordFor({
      level: LEVELS[i], reportingAddress: reportingAddress, published: published,
    });
    out.records[LEVELS[i]] = built.value;
    for (var d = 0; d < built.dropped.length; d += 1) {
      if (out.dropped.indexOf(built.dropped[d]) === -1) out.dropped.push(built.dropped[d]);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

/**
 * @primitive blamepost.mail.dmarcPolicy.create
 * @signature blamepost.mail.dmarcPolicy.create(opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 9989 §4.9, RFC 7489 §4.2
 * @related   blamepost.mail.dmarcPolicy.evaluate, blamepost.mail.dmarcPolicy.markSource
 *
 * Build the policy stepper. Returns
 * `{ evaluate, markSource, markings, describe }`.
 *
 * Everything it reads is handed in. It holds no settings of its own and
 * opens no volume, and the thresholds it decides on are constants rather
 * than options, because a threshold an operator can lower is a way past
 * the rule it states.
 *
 * `store` is a `blamepost.store.reports` handle, and this module is the
 * only thing that ever holds it: the evaluation is handed a reader built
 * around it that asks for the counted reading and copies out a fixed set
 * of figures, so the reading that includes reports nobody authenticated
 * is not reachable from the evaluation at all.
 *
 * `posture` is a `blamepost.mail.posture` handle, which answers whether
 * the SPF and DKIM records the rules require are actually published.
 * `dnsLookup` is the reader `blamepost.mail.posture.txtLookup` builds
 * over the resolver the operator pinned, and it is what reads the DMARC
 * record the domain publishes today.
 *
 * `reportingAddress` is the address this server collects aggregate
 * reports at. It is the `rua` tag of a record offered for a domain that
 * publishes none.
 *
 * @opts
 *   store:            object,     // required, a blamepost.store.reports handle
 *   posture:          object,     // required, a blamepost.mail.posture handle
 *   dnsLookup:        function,   // required, from blamepost.mail.posture.txtLookup
 *   reportingAddress: string,     // required, the address the rua tag names
 *
 * @example
 *   var policy = require("./lib/mail/dmarc-policy").create({
 *     store:            storeReports,
 *     posture:          postureChecker,
 *     dnsLookup:        blamepost.mail.posture.txtLookup(resolver),
 *     reportingAddress: "dmarc-reports@example.com",
 *   });
 *   (await policy.evaluate({ domain: "example.com" })).ok;
 */
function create(opts) {
  opts = opts || {};

  var store = opts.store;
  if (!store || typeof store.rollup !== "function" ||
      typeof store.failingSources !== "function" ||
      typeof store.reporters !== "function" ||
      typeof store.describe !== "function") {
    throw new TypeError("blamepost.mail.dmarcPolicy.create: opts.store must be a " +
      "blamepost.store.reports handle. The counting a step rests on lives there, and this " +
      "module holds no rows of its own.");
  }

  var postureChecker = opts.posture;
  if (!postureChecker || typeof postureChecker.check !== "function") {
    throw new TypeError("blamepost.mail.dmarcPolicy.create: opts.posture must be a " +
      "blamepost.mail.posture handle. A step asks whether the SPF and DKIM records the " +
      "rules require are published, and nothing else here can resolve them.");
  }

  if (typeof opts.dnsLookup !== "function") {
    throw new TypeError("blamepost.mail.dmarcPolicy.create: opts.dnsLookup is required " +
      "(blamepost.mail.posture.txtLookup builds one over the resolver the operator pinned). " +
      "The record a domain publishes today decides which step is the next one.");
  }
  var dnsLookup = opts.dnsLookup;

  var reportingAddress = address.canonical(opts.reportingAddress,
    "blamepost.mail.dmarcPolicy.create: opts.reportingAddress").address;

  var evidence = _evidenceReader(store);

  // ---- what a step is measured against ------------------------------------

  function _ruleFor(level) {
    if (level === LEVEL_QUARANTINE) {
      return {
        level:          LEVEL_QUARANTINE,
        spanDays:       QUARANTINE_SPAN_DAYS,
        reportDays:     QUARANTINE_REPORT_DAYS,
        organizations:  QUARANTINE_ORGANIZATIONS,
        alignedPerMille: QUARANTINE_ALIGNED_PER_MILLE,
        minMessages:    QUARANTINE_MIN_MESSAGES,
        heldDays:       0,
      };
    }
    return {
      level:          LEVEL_REJECT,
      spanDays:       REJECT_SPAN_DAYS,
      reportDays:     REJECT_REPORT_DAYS,
      organizations:  REJECT_ORGANIZATIONS,
      alignedPerMille: REJECT_ALIGNED_PER_MILLE,
      minMessages:    REJECT_MIN_MESSAGES,
      heldDays:       REJECT_HELD_DAYS,
    };
  }

  // ---- the trail ----------------------------------------------------------

  // The identifier one marking is filed under. The domain in the clear,
  // because it is published in DNS by definition, and the source as the
  // deployment-keyed hash the record rows are indexed by, because the
  // address belongs to somebody with no account here.
  function _sourceResource(domain, sourceIp) {
    var digest = b.db.hashFor(tables.DMARC_RECORDS, "sourceIp", sourceIp);
    return digest === null ? null : domain + RESOURCE_SEPARATOR + digest;
  }

  function _detailOf(row) {
    if (typeof row.metadata !== "string" || row.metadata.length === 0) return {};
    var parsed;
    try { parsed = JSON.parse(row.metadata); }
    catch (_e) { return {}; }
    return (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed))
      ? parsed : {};
  }

  // Every marking filed for one domain, newest first, as a map from the
  // resource identifier to the marking that governs it. A later marking
  // supersedes an earlier one and both stay in the trail, so the first
  // row seen on a newest-first read is the one in force.
  //
  // The whole set is read in one query rather than one query per source,
  // because `b.audit.query` files a row for every read of the trail and a
  // console page listing fifty senders would otherwise file fifty. A read
  // that came back full may be short of the oldest markings, which is
  // exactly the ones a rarely-changed source carries, so the answer says
  // it was truncated instead of reporting a source as unreviewed because
  // its marking fell off the end.
  async function _markingsFor(domain) {
    var rows;
    try {
      rows = await b.audit.query({
        action: MARKED_ACTION, order: "desc", limit: MARKING_LIMIT,
        actor: auditActor.current(),
      });
    } catch (_sinkError) {
      // A trail that cannot answer leaves this reader with nothing, and
      // nothing is not the same as no marking. The caller is told it
      // could not be read rather than handed an empty set that would
      // report every source as unreviewed.
      return { ok: false, truncated: false, held: {} };
    }
    if (!Array.isArray(rows)) return { ok: false, truncated: false, held: {} };

    var prefix = domain + RESOURCE_SEPARATOR;
    var held = {};
    for (var i = 0; i < rows.length; i += 1) {
      var id = typeof rows[i].resourceId === "string" ? rows[i].resourceId : "";
      if (id.slice(0, prefix.length) !== prefix) continue;
      if (Object.prototype.hasOwnProperty.call(held, id)) continue;
      var detail = _detailOf(rows[i]);
      if (DISPOSITIONS.indexOf(detail.disposition) === -1) continue;
      held[id] = {
        disposition: detail.disposition,
        at:          Number(rows[i].recordedAt) || 0,
        reason:      typeof rows[i].reason === "string" ? rows[i].reason : "",
      };
    }
    return { ok: true, truncated: rows.length >= MARKING_LIMIT, held: held };
  }

  // What this server has recorded about the policy one domain publishes,
  // newest first.
  async function _observationsFor(domain) {
    var rows;
    try {
      rows = await b.audit.query({
        action: OBSERVED_ACTION, resourceId: domain, order: "desc",
        limit: OBSERVATION_LIMIT, actor: auditActor.current(),
      });
    } catch (_sinkError) {
      return { ok: false, seen: [] };
    }
    if (!Array.isArray(rows)) return { ok: false, seen: [] };
    var seen = [];
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i].resourceId !== domain) continue;
      var detail = _detailOf(rows[i]);
      if (LEVELS.indexOf(detail.level) === -1 && GAPS.indexOf(detail.level) === -1) continue;
      seen.push({
        level:   detail.level,
        percent: typeof detail.percent === "number" ? detail.percent : null,
        at:      Number(rows[i].recordedAt) || 0,
      });
    }
    return { ok: true, seen: seen };
  }

  // One observed state: the level, and the share of mail it applies to,
  // where a record carrying no pct applies to all of it. Two readings
  // with the same level at different percentages are different states.
  function _stateOf(level, percent) {
    return level + "@" + (typeof percent === "number" ? percent : 100);
  }

  // When the run of observations carrying the current state began, or
  // null when this server has recorded none. The rows come back newest
  // first, so the run ends at the first row carrying a different state,
  // which includes a record that was absent or unusable in between.
  function _heldSince(seen, level, percent) {
    var state = _stateOf(level, percent);
    var since = null;
    for (var i = 0; i < seen.length; i += 1) {
      if (_stateOf(seen[i].level, seen[i].percent) !== state) break;
      since = seen[i].at;
    }
    return since;
  }

  // Record what the domain publishes, when it differs from the last thing
  // recorded. Written on a change rather than on a reading, so the trail
  // holds one row per policy move and a console rendering the same page
  // every few seconds files nothing. A record that is absent or unusable
  // is recorded as that, so the run it interrupted ends there.
  //
  // Drop-silent by design: the answer the caller is waiting for is about
  // the zone and the reports, and a trail that could not take a row does
  // not change any of it.
  async function _observe(domain, level, percent, seen) {
    if (seen.length > 0 &&
        _stateOf(seen[0].level, seen[0].percent) === _stateOf(level, percent)) {
      return;
    }
    await auditActor.record({
      action:   "blamepost.mail.dmarc_policy.policy_observed",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: DOMAIN_KIND, id: domain },
      metadata: { domain: domain, level: level, percent: percent },
    });
  }

  // ---- the checks ---------------------------------------------------------

  function _check(name, ok, code, detail, found, required) {
    return {
      name:     name,
      ok:       ok === true,
      reason:   ok === true ? null : code,
      detail:   ok === true ? "" : detail,
      found:    found === undefined ? null : found,
      required: required === undefined ? null : required,
    };
  }

  // What the posture rules ask for, read off the report the checker
  // produced. The three the rules name are the ones read: the SPF record
  // has to refuse the hosts it did not list, and at least one DKIM
  // selector this server holds a key for has to be published. A lookup
  // that did not complete is its own answer and comes first, because a
  // resolver nobody could reach says nothing about a zone.
  function _postureChecks(report) {
    var findings = (report.domains[0] && report.domains[0].findings) || [];
    var spf = null;
    var dkim = [];
    var unresolved = null;
    for (var i = 0; i < findings.length; i += 1) {
      var finding = findings[i];
      if (finding.unresolved === true && unresolved === null &&
          (finding.record === "SPF" || finding.record === "DKIM" || finding.record === "DMARC")) {
        unresolved = finding;
      }
      if (finding.record === "SPF") spf = finding;
      if (finding.record === "DKIM") dkim.push(finding);
    }

    var checks = [];
    if (unresolved !== null) {
      checks.push(_check("posture", false, POSTURE_UNRESOLVED,
        "The " + unresolved.record + " record for this domain could not be read, so nothing " +
        "was learned about it and it may well be published and correct. " +
        unresolved.detail + " Until the resolver answers, this server has no reading to " +
        "step a policy on. Nothing about the zone has to change for this to clear.",
        null, null));
      return checks;
    }

    checks.push(_check("spf", spf !== null && spf.ok === true, SPF_NOT_STRICT,
      spf === null
        ? "No SPF finding was produced for this domain."
        : "The SPF policy that applies does not end in -all, so it asks receivers to accept " +
          "mail from hosts the domain did not authorize. " + spf.detail + " A DMARC policy " +
          "over a permissive SPF record refuses less than it appears to.",
      spf === null ? null : spf.found, "a record ending in -all"));

    var published = 0;
    for (var d = 0; d < dkim.length; d += 1) if (dkim[d].ok === true) published += 1;
    checks.push(_check("dkim", published > 0, DKIM_UNPUBLISHED,
      dkim.length === 0
        ? "This server holds no DKIM selector for the domain, so nothing it sends can be " +
          "verified on the DKIM identifier and alignment rests on SPF alone. Generate a " +
          "key pair for the domain and publish both selector records."
        : "None of the " + dkim.length + " selector records this server expects is published " +
          "with the key it signs with, so nothing it sends verifies on the DKIM identifier. " +
          "Publish the record each selector names.",
      published, "at least one published selector matching a key this server holds"));
    return checks;
  }

  // The evidence a window carries, read from the counted rows alone.
  function _readWindows(rows) {
    var counted = 0;
    var aligned = 0;
    var days = {};
    for (var i = 0; i < rows.length; i += 1) {
      var row = rows[i];
      if ((row.counted || 0) <= 0) continue;
      counted += row.counted;
      aligned += row.aligned || 0;
      // One report contributes the day its window opens on and no more,
      // whatever range it declares, so a reporter sending one report over
      // a month cannot answer for a month of days.
      days[_dayOf(row.windowBegin)] = true;
    }
    var ordered = Object.keys(days).map(Number).sort(function (one, other) {
      return one - other;
    });
    return { counted: counted, aligned: aligned, days: ordered };
  }

  // The largest run of days inside the window carrying no report. A hole
  // is measured between two days that were reported on, so a window with
  // one day in it has no interior gap rather than an infinite one.
  function _largestGap(days) {
    var largest = 0;
    for (var i = 1; i < days.length; i += 1) {
      var gap = days[i] - days[i - 1] - 1;
      if (gap > largest) largest = gap;
    }
    return largest;
  }

  // ---- the verdict --------------------------------------------------------

  function _verdict(domain, at, level, next) {
    return {
      domain:    domain,
      at:        at,
      level:     level,
      next:      next,
      ok:        false,
      reason:    null,
      detail:    "",
      checks:    [],
      evidence:  null,
      records:   {},
      recordsDropped: [],
      reversal:  null,
    };
  }

  // What stepping down offers, which is every level weaker than the one
  // published and no conditions on reaching any of them.
  function _reversal(level) {
    var at = LEVELS.indexOf(level);
    return {
      gated: false,
      to:    at <= 0 ? [] : LEVELS.slice(0, at),
      detail: at <= 0
        ? "The domain publishes the weakest policy there is, so there is nothing to step " +
          "down to."
        : "Publishing any of these needs no evidence and no threshold. Mail being discarded " +
          "is answered by publishing the weaker record and looking afterwards.",
    };
  }

  /**
   * @primitive blamepost.mail.dmarcPolicy.evaluate
   * @signature policy.evaluate(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 9989 §4.9, RFC 7489 §4.2
   * @related   blamepost.mail.dmarcPolicy.markSource, blamepost.mail.dmarcPolicy.recordFor
   *
   * Whether one hosted domain's evidence carries the next DMARC policy
   * step, and the record text for every level either way. Answers
   * `{ domain, at, level, next, ok, reason, detail, checks, evidence,
   * records, recordsDropped, reversal }`.
   *
   * `level` is the policy the domain publishes today and `next` is the
   * step being judged, which is quarantine for a domain at none and
   * reject for one at quarantine. `ok` says whether every rule is met.
   * `reason` names the first that is not, and `checks` carries every one
   * of them with what was found beside what is required, so a console can
   * show an operator how far along they are rather than only that they
   * are not there yet.
   *
   * The counting it reads is the counted reading and nothing else. A
   * report whose carrier this server did not authenticate contributes no
   * volume, no reporting organization, no reported day and no failing
   * source to any of it, and there is no option on this verb that changes
   * that.
   *
   * `records` carries the exact `_dmarc` TXT value for each of the three
   * levels, on a refusal as much as on a pass, so the text an operator
   * publishes to reverse is in front of them without this server having
   * to agree first. `reversal` says plainly that stepping down is not
   * gated.
   *
   * A domain nobody has reported on is not an error. It answers with
   * `evidence-absent` and the records beside it. Bad arguments throw: a
   * domain that is not one is a mistake a person reads back at a
   * terminal.
   *
   * Each call reads the policy the domain publishes and writes an
   * observation to the audit trail when it differs from the last one
   * recorded, which is what the reject step reads to answer how long the
   * domain has already been at quarantine.
   *
   * @opts
   *   domain: string,   // required, one hosted domain
   *   now:    number,   // the moment to read the evidence against, default the clock
   *
   * @example
   *   var verdict = await policy.evaluate({ domain: "example.com" });
   *   verdict.reason;   // "evidence-sparse"
   */
  async function evaluate(evaluateOpts) {
    var options = evaluateOpts || {};
    var domain = address.canonicalDomain(options.domain,
      "blamepost.mail.dmarcPolicy.evaluate: opts.domain");
    if (options.now !== undefined && options.now !== null &&
        (typeof options.now !== "number" || !isFinite(options.now))) {
      throw new TypeError("blamepost.mail.dmarcPolicy.evaluate: opts.now is a moment in " +
        "milliseconds since the epoch.");
    }
    var now = typeof options.now === "number" ? options.now : Date.now();

    var found = await posture.dmarcRecord(domain, { dnsLookup: dnsLookup });
    var built = _recordsFor(found.record, reportingAddress);

    var level = found.state === "published" ? found.policy : null;
    var verdict = _verdict(domain, now, level, null);
    verdict.records        = built.records;
    verdict.recordsDropped = built.dropped;
    verdict.reversal       = _reversal(level === null ? LEVEL_NONE : level);

    if (found.state === "unsettled") {
      return _refuse(verdict, POSTURE_UNRESOLVED,
        "The DMARC record at " + found.name + " could not be read, so which policy this " +
        "domain publishes is not known and neither is which step would be the next one: " +
        found.why + ". Nothing was learned about the record, so it may well be published " +
        "and correct. This is a question about the resolver this server reads rather than " +
        "about the zone.");
    }
    if (found.state === "unusable" || found.state === "absent") {
      var interrupted = await _observationsFor(domain);
      if (interrupted.ok) await _observe(domain, found.state, null, interrupted.seen);
    }
    if (found.state === "unusable") {
      return _refuse(verdict, POSTURE_UNUSABLE,
        "The DMARC record at " + found.name + " is published but no receiver reads a policy " +
        "from it: " + found.why + ". Leave one record there, in the shape the quarantine " +
        "value below carries, and the reading starts again from what it publishes.");
    }
    if (found.state === "absent") {
      return _refuse(verdict, POSTURE_UNPUBLISHED,
        "The domain publishes no DMARC record of its own at " + found.name + ", so there is " +
        "no policy to step from and no reports are being asked for. Publish the none value " +
        "below, wait for reporters to answer it, and this reading fills in.");
    }

    var observations = await _observationsFor(domain);
    if (observations.ok) await _observe(domain, level, found.percent, observations.seen);

    if (level === LEVEL_REJECT) {
      return _refuse(verdict, AT_STRONGEST_POLICY,
        "The domain already publishes p=reject, which is the strongest policy DMARC has. " +
        "There is no step up from it.");
    }
    // A published state carries a policy that is one of the three, and a
    // record whose p tag is anything else answers `unusable` above, so
    // there is no fourth branch here to write a code for.
    var next = level === LEVEL_NONE ? LEVEL_QUARANTINE : LEVEL_REJECT;
    var rule = _ruleFor(next);
    verdict.next = next;

    verdict.checks.push(_check("sample", found.percent === null || found.percent >= 100,
      SAMPLE_NOT_WHOLE,
      "The record carries pct=" + found.percent + ", so receivers apply the policy to " +
      found.percent + " percent of the mail and deliver the rest normally. What the " +
      "reports measure is therefore not what the next policy would do. Publish the " +
      level + " value below, which carries no pct tag and so applies to all of it.",
      found.percent, 100));

    var postureReport;
    try { postureReport = await postureChecker.check({ domains: [domain] }); }
    catch (postureError) {
      return _refuse(verdict, POSTURE_UNRESOLVED,
        "The SPF and DKIM records for this domain could not be resolved, so whether the " +
        "posture the rules ask for is published is not known: " +
        ((postureError && postureError.message) || String(postureError)) + ".");
    }
    var postureChecks = _postureChecks(postureReport);
    for (var p = 0; p < postureChecks.length; p += 1) verdict.checks.push(postureChecks[p]);

    var retentionMs = evidence.retentionMs();
    var windowMs = rule.spanDays * DAY_MS;
    if (retentionMs < windowMs) {
      verdict.checks.push(_check("retention", false, RETENTION_TOO_SHORT,
        "This server keeps aggregate report rows for " + _wholeDays(0, retentionMs) +
        " days and the step to " + next + " is measured over " + rule.spanDays + ". The " +
        "evidence is destroyed before it can span the window, so this rule can never be " +
        "met on this setting. Raise the aggregate retention window past " + rule.spanDays +
        " days.", _wholeDays(0, retentionMs), rule.spanDays));
    }

    var since = now - windowMs;
    var windows = evidence.windows(domain, since, now);
    var read = _readWindows(windows);

    // The whole record, not the window, because how long a domain has
    // been reported on at all is a different question from what the last
    // fortnight says.
    var everything = _readWindows(evidence.windows(domain, 0, now));
    var spanDays = everything.days.length === 0
      ? 0 : _wholeDays(everything.days[0] * DAY_MS, now);

    var organizations = evidence.organizations(domain, since, now);
    var listed = await evidence.failing(domain, since, now);
    var marked = await _markingsFor(domain);

    verdict.evidence = Object.freeze({
      windowDays:      rule.spanDays,
      spanDays:        spanDays,
      reportDays:      read.days.length,
      organizations:   organizations,
      counted:         read.counted,
      aligned:         read.aligned,
      alignedPercent:  _percentOf(read.aligned, read.counted),
      failingSources:  listed.total,
      largestGapDays:  _largestGap(read.days),
      staleDays:       read.days.length === 0
        ? null : _dayOf(now) - read.days[read.days.length - 1],
    });

    _evidenceChecks(verdict, rule, read, everything, spanDays, organizations, now);
    _sourceChecks(verdict, rule, listed, marked);
    _heldChecks(verdict, rule, level, found.percent, observations, now);

    for (var c = 0; c < verdict.checks.length; c += 1) {
      if (verdict.checks[c].ok) continue;
      return _refuse(verdict, verdict.checks[c].reason, verdict.checks[c].detail);
    }
    verdict.ok = true;
    verdict.detail = "Every rule for the step to " + next + " is met. Publish the " + next +
      " value below at " + found.name + ".";
    return verdict;
  }

  function _refuse(verdict, code, detail) {
    verdict.ok     = false;
    verdict.reason = code;
    verdict.detail = detail;
    return verdict;
  }

  function _evidenceChecks(verdict, rule, read, everything, spanDays, organizations, now) {
    if (everything.counted === 0) {
      verdict.checks.push(_check("evidence", false, EVIDENCE_ABSENT,
        "No report this server authenticated has counted a message for this domain. Either " +
        "no receiver is reporting, which the rua tag on the record below asks them to do, " +
        "or the reports that arrived were not authenticated and are being left out. The " +
        "DMARC console names which of the two it is.", 0, rule.minMessages));
      return;
    }
    verdict.checks.push(_check("span", spanDays >= rule.spanDays, EVIDENCE_YOUNG,
      "The earliest counted report for this domain covers a day " + spanDays + " days ago " +
      "and the step to " + rule.level + " is measured over " + rule.spanDays + ". Nothing " +
      "has to change; the rule clears on " +
      _asDate(now + (rule.spanDays - spanDays) * DAY_MS) + " if reports keep arriving.",
      spanDays, rule.spanDays));

    verdict.checks.push(_check("days", read.days.length >= rule.reportDays, EVIDENCE_SPARSE,
      "Reports cover " + read.days.length + " distinct days of the last " + rule.spanDays +
      " and the step to " + rule.level + " asks for " + rule.reportDays + ". A window " +
      "reported on for a few of its days says what happened on those days.",
      read.days.length, rule.reportDays));

    var stale = read.days.length === 0 ? null : _dayOf(now) - read.days[read.days.length - 1];
    verdict.checks.push(_check("fresh", stale !== null && stale <= MAX_GAP_DAYS, EVIDENCE_STALE,
      (stale === null
        ? "No counted report covers the last " + rule.spanDays + " days at all, so there is " +
          "nothing recent enough to step on."
        : "The most recent counted report covers a day " + stale + " days ago and " +
          MAX_GAP_DAYS + " is the most this server steps on.") +
      " Reporters send a day behind the window they cover, so a longer silence is a reporter " +
      "that has stopped rather than a lag, and stepping on it is stepping on what was true " +
      "last week.", stale, MAX_GAP_DAYS));

    var gap = _largestGap(read.days);
    verdict.checks.push(_check("continuous", gap <= MAX_GAP_DAYS, EVIDENCE_GAPPED,
      "The reports for the last " + rule.spanDays + " days have a run of " + gap +
      " days with nothing in them, and " + MAX_GAP_DAYS + " is the most this server steps " +
      "on. The alignment below is measured over a window that was not observed for part of " +
      "its length.", gap, MAX_GAP_DAYS));

    verdict.checks.push(_check("reporters", organizations >= rule.organizations, REPORTERS_THIN,
      organizations + " reporting organization" + (organizations === 1 ? "" : "s") +
      " answered for this domain and the step to " + rule.level + " asks for " +
      rule.organizations + ". An organization is counted once per registered domain its " +
      "reports passed DMARC for, whatever names the reports give. One reporter going quiet " +
      "and a domain nobody is spoofing produce the same empty counting, and a second " +
      "reporter is what tells them apart.",
      organizations, rule.organizations));

    verdict.checks.push(_check("volume", read.counted >= rule.minMessages, VOLUME_THIN,
      "The counted reports cover " + read.counted + " messages and the step to " + rule.level +
      " is measured over at least " + rule.minMessages + ". An alignment share taken over " +
      "fewer messages than that cannot express the threshold it is compared against.",
      read.counted, rule.minMessages));

    verdict.checks.push(_check("alignment",
      read.aligned * PER_MILLE >= read.counted * rule.alignedPerMille, ALIGNMENT_SHORT,
      "Of " + read.counted + " counted messages " + read.aligned + " aligned, which is " +
      _percentOf(read.aligned, read.counted) + " percent, and the step to " + rule.level +
      " asks for " + (rule.alignedPerMille / 10) + ". The " + (read.counted - read.aligned) +
      " that did not align are what the new policy would act on.",
      _percentOf(read.aligned, read.counted), rule.alignedPerMille / 10));
  }

  function _sourceChecks(verdict, rule, listed, marked) {
    if (listed.truncated) {
      verdict.checks.push(_check("sources", false, SOURCES_TRUNCATED,
        "This domain has " + listed.total + " failing sources and this reading lists " +
        SOURCE_LIST_LIMIT + ". Whether every one of them has been looked at cannot be " +
        "answered over part of the list, so the step is refused rather than judged on what " +
        "fit. Work the list down in the DMARC console.", listed.total, SOURCE_LIST_LIMIT));
      return;
    }
    if (!marked.ok) {
      verdict.checks.push(_check("sources", false, MARKINGS_TRUNCATED,
        "The audit trail could not be read, so which sources an operator has already looked " +
        "at is not known. Reporting them as unreviewed would be an answer about the trail " +
        "rather than about the domain.", null, null));
      return;
    }
    if (marked.truncated) {
      verdict.checks.push(_check("sources", false, MARKINGS_TRUNCATED,
        "The trail holds at least " + MARKING_LIMIT + " source markings and this reading " +
        "takes that many, so an older one may be missing from it. A source reported as " +
        "unreviewed because its marking fell off the end of a read is the wrong answer, so " +
        "the step is refused instead.", MARKING_LIMIT, null));
      return;
    }

    var unreviewed = 0;
    var contradicted = 0;
    var unreadable = 0;
    var grace = FIX_GRACE_DAYS * DAY_MS;
    for (var i = 0; i < listed.sources.length; i += 1) {
      var source = listed.sources[i];
      if ((source.messages || 0) < SOURCE_FLOOR_MESSAGES) continue;
      if (source.readable !== true || typeof source.sourceIp !== "string") {
        unreadable += 1;
        continue;
      }
      var id = _sourceResource(verdict.domain, source.sourceIp);
      var held = id === null ? undefined : marked.held[id];
      if (held === undefined) { unreviewed += 1; continue; }
      if (held.disposition !== MARK_OURS_FIXED) continue;
      if ((source.lastSeen || 0) > held.at + grace) contradicted += 1;
    }

    verdict.checks.push(_check("readable", unreadable === 0, SOURCE_UNREADABLE,
      unreadable + " failing source" + (unreadable === 1 ? "" : "s") + " could not be read " +
      "back from the volume, so whether an operator has looked at them cannot be answered " +
      "and neither can the rule that asks. This is a fault in the stored rows rather than a " +
      "finding about the domain.", unreadable, 0));

    verdict.checks.push(_check("reviewed", unreviewed === 0, SOURCES_UNREVIEWED,
      unreviewed + " sending address" + (unreviewed === 1 ? "" : "es") + " failed both " +
      "alignments on at least " + SOURCE_FLOOR_MESSAGES + " messages and carries no marking. " +
      "Each one is either a sending path of yours that is not aligned yet or somebody else " +
      "claiming the domain, and the step to " + rule.level + " starts discarding the mail " +
      "either way. Mark each in the DMARC console with what it is and why.", unreviewed, 0));

    verdict.checks.push(_check("fix", contradicted === 0, FIX_CONTRADICTED,
      contradicted + " sending address" + (contradicted === 1 ? "" : "es") + " marked as " +
      "yours and fixed has kept failing in a window ending more than " + FIX_GRACE_DAYS +
      " days after the marking was written, so the reporters have contradicted the claim. " +
      "The step to " + rule.level + " would discard that mail. Look at the address again " +
      "and mark it with what is actually true.", contradicted, 0));
  }

  function _heldChecks(verdict, rule, level, percent, observations, now) {
    if (rule.heldDays <= 0) return;
    if (!observations.ok) {
      verdict.checks.push(_check("held", false, QUARANTINE_UNOBSERVED,
        "The audit trail could not be read, so how long this domain has published " +
        "p=quarantine is not known.", null, rule.heldDays));
      return;
    }
    var since = _heldSince(observations.seen, level, percent);
    if (since === null) {
      verdict.checks.push(_check("held", false, QUARANTINE_UNOBSERVED,
        "This server has no record of when " + verdict.domain + " began publishing " +
        "p=quarantine. It records the published policy each time this runs, so a domain " +
        "checked for the first time today has one reading whatever its zone has held, and " +
        "the record starts from here.", null, rule.heldDays));
      return;
    }
    var heldDays = _wholeDays(since, now);
    verdict.checks.push(_check("held", heldDays >= rule.heldDays, QUARANTINE_SHORT,
      "This server has seen " + verdict.domain + " publishing p=quarantine since " +
      _asDate(since) + ", which is " + heldDays + " day" + (heldDays === 1 ? "" : "s") +
      ", and the step to reject asks for " + rule.heldDays + ". Nothing has to change; the " +
      "rule clears on " + _asDate(since + rule.heldDays * DAY_MS) + ".",
      heldDays, rule.heldDays));
  }

  /**
   * @primitive blamepost.mail.dmarcPolicy.markSource
   * @signature policy.markSource(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: an operator's written finding about one failing sender)
   * @related   blamepost.mail.dmarcPolicy.markings, blamepost.mail.dmarcPolicy.evaluate
   *
   * Write down what one failing sending address is, and why. Answers
   * `{ domain, disposition, reason, at, recorded }`, where `recorded`
   * says whether the trail took the row.
   *
   * `disposition` is `ours-and-fixed` for a sending path of the
   * operator's whose alignment has been corrected, or `not-ours` for an
   * address that is not theirs, whose failures are what a policy exists
   * to stop. The two are not interchangeable: a source marked
   * `ours-and-fixed` that keeps failing well after the marking was
   * written has had the claim contradicted by the reporters and blocks
   * the step, and one marked `not-ours` that keeps failing is the
   * expected case and blocks nothing.
   *
   * The marking goes to the audit trail and nowhere else. It carries who
   * wrote it, when, and the reason as its own column, and a later marking
   * for the same address supersedes it without erasing it.
   *
   * The address is not written into the row. What identifies the source
   * is the deployment-keyed hash the report rows are already indexed by,
   * because the address belongs to somebody with no account on this
   * server and a second copy of it would sit in a table with its own
   * window and no erasure path.
   *
   * Everything here throws on an argument it cannot act on: a domain that
   * is not one, an address that is not one, a disposition outside the
   * pair, and a marking with no reason are all mistakes a person reads
   * back at a terminal.
   *
   * @opts
   *   domain:      string,   // required, the hosted domain the source failed for
   *   sourceIp:    string,   // required, the sending address a reporter named
   *   disposition: string,   // required, ours-and-fixed or not-ours
   *   reason:      string,   // required, what was found out and how
   *
   * @example
   *   await policy.markSource({
   *     domain:      "example.com",
   *     sourceIp:    "198.51.100.20",
   *     disposition: "not-ours",
   *     reason:      "a hosting range with no relationship to this domain",
   *   });
   */
  async function markSource(markOpts) {
    var options = markOpts || {};
    var domain = address.canonicalDomain(options.domain,
      "blamepost.mail.dmarcPolicy.markSource: opts.domain");

    if (typeof options.sourceIp !== "string" || nodeNet.isIP(options.sourceIp.trim()) === 0) {
      throw new TypeError("blamepost.mail.dmarcPolicy.markSource: opts.sourceIp must be the " +
        "sending address a reporter named, as an IPv4 or IPv6 address.");
    }
    var sourceIp = options.sourceIp.trim();

    if (DISPOSITIONS.indexOf(options.disposition) === -1) {
      throw new TypeError("blamepost.mail.dmarcPolicy.markSource: opts.disposition must be " +
        DISPOSITIONS.join(" or ") + ". A source is either a sending path of yours whose " +
        "alignment is fixed or one that is not yours, and the two are read differently: the " +
        "first is contradicted by continued failure and the second is not.");
    }

    if (typeof options.reason !== "string" || options.reason.trim().length === 0) {
      throw new TypeError("blamepost.mail.dmarcPolicy.markSource: opts.reason is required. " +
        "The marking is what lets a policy tighten, and a marking with no reason answers " +
        "nothing later about why mail from this address was accounted for.");
    }
    var reason = options.reason.trim();
    if (reason.length > MAX_REASON_CHARS) {
      throw new TypeError("blamepost.mail.dmarcPolicy.markSource: the reason runs to " +
        reason.length + " characters and " + MAX_REASON_CHARS + " is the most that is " +
        "recorded. Say what the address is and how you found out.");
    }

    var id = _sourceResource(domain, sourceIp);
    if (id === null) {
      throw new TypeError("blamepost.mail.dmarcPolicy.markSource: the store could not derive " +
        "the identifier this address is indexed under, so a marking written now would never " +
        "be found again. The store has to be open before a source can be marked.");
    }

    var at = Date.now();
    var recorded = await auditActor.record({
      action:   "blamepost.mail.dmarc_policy.source_marked",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: SOURCE_KIND, id: id },
      metadata: { domain: domain, disposition: options.disposition },
    });

    return {
      domain:      domain,
      disposition: options.disposition,
      reason:      reason,
      at:          at,
      recorded:    recorded === true,
    };
  }

  /**
   * @primitive blamepost.mail.dmarcPolicy.markings
   * @signature policy.markings(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the markings in force for one hosted domain)
   * @related   blamepost.mail.dmarcPolicy.markSource, blamepost.mail.dmarcPolicy.evaluate
   *
   * The markings in force for one hosted domain. Answers
   * `{ domain, ok, truncated, marked }`, where `marked` is one entry per
   * marked source carrying `{ disposition, at, reason }`.
   *
   * `ok` is false when the trail could not be read, which is not the same
   * as a domain nobody has marked anything for: reporting no marking
   * because the trail was unavailable would report every source as
   * unreviewed. `truncated` says the read reached its own ceiling and may
   * be short of the oldest markings.
   *
   * The entries are keyed by the identifier the marking was filed under,
   * which is the domain and the deployment-keyed hash of the address. The
   * address is not in the trail and is not answered here; the DMARC
   * console pairs these with the addresses the report rows hold.
   *
   * @opts
   *   domain: string,   // required, a hosted domain; refused when not a domain name
   *
   * @example
   *   var held = await policy.markings({ domain: "example.com" });
   *   held.truncated;
   */
  async function markings(listOpts) {
    var options = listOpts || {};
    var domain = address.canonicalDomain(options.domain,
      "blamepost.mail.dmarcPolicy.markings: opts.domain");
    var held = await _markingsFor(domain);
    return {
      domain:    domain,
      ok:        held.ok,
      truncated: held.truncated,
      marked:    held.held,
    };
  }

  /**
   * @primitive blamepost.mail.dmarcPolicy.describe
   * @signature policy.describe()
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: the rules in force, published rather than recomputed)
   * @related   blamepost.mail.dmarcPolicy.evaluate, blamepost.mail.dmarcPolicy.create
   *
   * The rules this stepper decides on. They are constants rather than
   * settings, so this is what a console renders beside what a domain has
   * rather than a table of knobs, and an operator reading what a step
   * asks for reads the numbers actually in force.
   *
   * @example
   *   policy.describe().quarantine.spanDays;   // 14
   */
  function describe() {
    return {
      reportingAddress: reportingAddress,
      levels:           LEVELS.slice(),
      dispositions:     DISPOSITIONS.slice(),
      maxGapDays:       MAX_GAP_DAYS,
      sourceFloorMessages: SOURCE_FLOOR_MESSAGES,
      fixGraceDays:     FIX_GRACE_DAYS,
      sourceListLimit:  SOURCE_LIST_LIMIT,
      markingLimit:     MARKING_LIMIT,
      quarantine:       _describeRule(_ruleFor(LEVEL_QUARANTINE)),
      reject:           _describeRule(_ruleFor(LEVEL_REJECT)),
    };
  }

  function _describeRule(rule) {
    return {
      spanDays:       rule.spanDays,
      reportDays:     rule.reportDays,
      organizations:  rule.organizations,
      alignedPercent: rule.alignedPerMille / 10,
      minMessages:    rule.minMessages,
      heldDays:       rule.heldDays,
    };
  }

  return {
    evaluate:   evaluate,
    markSource: markSource,
    markings:   markings,
    describe:   describe,
  };
}

module.exports = {
  create:    create,
  recordFor: recordFor,
  CODES:     CODES,
  LEVELS:    LEVELS,
  DISPOSITIONS: DISPOSITIONS,
  MARK_OURS_FIXED: MARK_OURS_FIXED,
  MARK_NOT_OURS:   MARK_NOT_OURS,
  MARKED_ACTION:   MARKED_ACTION,
  OBSERVED_ACTION: OBSERVED_ACTION,
  MAX_GAP_DAYS:          MAX_GAP_DAYS,
  SOURCE_FLOOR_MESSAGES: SOURCE_FLOOR_MESSAGES,
  FIX_GRACE_DAYS:        FIX_GRACE_DAYS,
  SOURCE_LIST_LIMIT:     SOURCE_LIST_LIMIT,
  MARKING_LIMIT:         MARKING_LIMIT,
};
