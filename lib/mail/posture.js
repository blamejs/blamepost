// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module   blamepost.mail.posture
 * @nav      DNS and domain authentication
 * @title    DNS posture verification
 * @order    10
 * @featured true
 *
 * @intro
 *   Resolve what a hosted domain actually publishes and compare it
 *   against what this server expects. `blamepost doctor` is the front
 *   end; the admin UI renders the same result.
 *
 *   The boot gate in `blamepost.mail.listeners` asks the operator to
 *   confirm the records exist, which is a claim about the world. This
 *   module goes and looks. The two answer different questions and both
 *   are worth having: the gate stops a server from collecting mail for
 *   a domain nobody prepared, and this names the record that is wrong
 *   once it is collecting.
 *
 *   ## What gets checked, and why each one matters
 *
 *   `MX` has to name this server, or mail arrives somewhere else.
 *
 *   `SPF` has to exist exactly once, fit in the 450 octets RFC 7208 §3.4
 *   caps a published record at, and refuse the hosts it did not list.
 *   Two records is a permanent error under RFC 7208 §4.5, and every
 *   receiver treats it as one. So is a record over the cap, and a
 *   receiver reaches that verdict from the length before it reads the
 *   policy, so a record that names every sending host correctly and ends
 *   in `-all` still authorizes nobody once it is long enough. A `~all`
 *   ending asks receivers to accept forgeries and merely note them,
 *   which is the posture this project does not ship. The record is read
 *   the way a receiver reads it rather than by looking at the end of the
 *   line: modifiers may follow the `all` mechanism, and a record with no
 *   `all` of its own hands the decision to its `redirect=` target, which
 *   is where a provider-hosted policy lives.
 *
 *   `DMARC` has to publish a policy of `quarantine` or `reject`.
 *   A `p=none` record collects reports and protects nobody, which is a
 *   fine place to start and a bad place to stay. The policy that
 *   applies is not always published at the domain itself: RFC 9989
 *   §4.10 walks the DNS tree upward, so a hosted subdomain under a
 *   parent that publishes `p=reject` is already covered and the report
 *   names where its policy comes from.
 *
 *   `DKIM` selector records have to carry the public key this server
 *   holds the private half of. This is where rotation goes wrong: a
 *   selector published with a truncated key, or a retiring selector
 *   pulled from the zone too early, both show up here as a specific
 *   selector name rather than as mail that mysteriously fails.
 *
 *   `MTA-STS` needs both halves, the TXT record and the policy the
 *   record points at, and the policy should list this server and say
 *   `mode: enforce`. A policy in testing mode reports violations and
 *   permits the downgrade it is reporting.
 *
 *   `TLS-RPT` is how the operator finds out that senders are failing
 *   to reach this server over TLS, which is the failure nobody notices
 *   without it. The record is read here the way a sender reads it,
 *   through the same framework primitive the outbound reporter uses, so
 *   a record this check calls healthy is one that senders will actually
 *   act on. A check more forgiving than the senders it is modeling
 *   reports a posture that is done and a zone nobody will ever send a
 *   report to.
 *
 *   `TLSA` is checked when the operator runs DANE, and the records are
 *   half of what that check asks. RFC 7672 §1.3 lets a sender
 *   authenticate this server against a TLSA record only when the answer
 *   carrying it was DNSSEC-authenticated, so a zone publishing the
 *   records with no DNSSEC over them is authenticated by nobody. The
 *   report reads the authentication of the answer rather than counting
 *   the records, and it keeps a resolver that says the answer was not
 *   authenticated apart from one that says nothing about it: the first
 *   is answered by signing the zone and the second by pointing this
 *   server at a validating resolver.
 *
 *   ## Findings, not exceptions
 *
 *   A lookup that fails is the answer, not an error. Every check
 *   catches its own resolution failure and reports it as the finding
 *   for that record, so one missing zone cannot end the run before the
 *   rest of the domains are checked.
 *
 *   A record that is not published and a resolver that could not answer
 *   are kept apart, because the remedies have nothing in common: one is
 *   fixed by publishing a record and the other by looking at the
 *   resolver. A name that does not exist is the ordinary case for a
 *   record an operator has not got to yet, so it reads as a missing
 *   record and says what publishing it would buy. A lookup that did not
 *   complete carries `unresolved`, names no expected or found value, and
 *   says so in as many words: this server learned nothing about that
 *   record and the zone may be perfectly correct.
 *
 *   Every lookup is bounded. The resolver belongs to the operator, and a
 *   handle that accepts a question and never answers it is ordinary
 *   rather than exotic, so without a bound the command an operator is
 *   watching and the administration request rendering the same report
 *   both stay open for as long as the resolver stays silent. A lookup
 *   that runs out of budget is a lookup that FAILED and never a name
 *   that publishes nothing: folding the two would let whoever can stall
 *   a query delete the policy the query was about.
 *
 *   Every lookup goes through the resolver the operator pinned,
 *   including the one the MTA-STS policy fetch makes on its own behalf.
 *   A spoofed `_mta-sts` record downgrades mail TLS, so it is the last
 *   question that should be answered by a resolver nobody chose.
 *
 *   ## Everything in a finding came from somewhere else
 *
 *   A receiver's MX name, the text of an SPF or DMARC record, the
 *   message a failed lookup carried: none of it is written by this
 *   server, and all of it is printed as plain lines by `blamepost
 *   doctor` and rendered on the admin page. So every value that goes
 *   into a finding is screened on the way in to it, at the one place
 *   findings are built, rather than at each of the surfaces that print
 *   one. An escape sequence in a record repaints the terminal of the
 *   person running the check, which is the moment they are deciding
 *   what to change in their zone.
 *
 * @card
 *   Resolves the MX, SPF, DMARC, DKIM, MTA-STS and TLS-RPT records of each
 *   hosted domain, plus its TLSA records when DANE is in use. It reports
 *   each record that is missing or differs from what this server expects,
 *   and `blamepost doctor` and the administration console show the same
 *   findings.
 */

var b = require("../vendor/blamejs");
// The one derivation that decides which domain a name means. A report is
// addressed to a hosted domain, and the names it resolves are built
// around that domain, so the name it is about is folded the way the
// selector rows and the hosted-domain rows are folded.
var address = require("../store/address");
// The screen between text somebody else wrote and a person reading it.
// Every value a finding carries came out of a zone this server does not
// control, and `blamepost doctor` prints them as plain lines.
var displayText = require("../text");

var SEVERITY_REQUIRED = "required";
var SEVERITY_ADVISED = "advised";

// How long this module waits on the DNS handle it was given.
//
// The handle is not this server's. An operator pins one, and what it
// does when a question cannot be answered is its own business. A handle
// that REJECTS is harmless, because every check below already has a
// verdict for a lookup that failed. A handle that ACCEPTS the question
// and never answers it is the one shape with no verdict at all, and it
// is ordinary rather than exotic: a nameserver that takes the query and
// drops the response, a firewall that blackholes the reply, and a handle
// written around an internal service that has stopped answering all
// present exactly that way. Measured against one, a report on an
// otherwise correct zone was still unsettled a minute and a half later,
// because nothing in this module would ever have ended it.
//
// That matters here for two reasons. `blamepost doctor` is a command an
// operator watches, and a command that never returns is one they kill
// without learning anything. The administration surface renders the same
// report with a browser request open on it, so an unbounded check is a
// way to hold a request for as long as the resolver stays silent.
//
// The number is deliberately generous rather than tight. The resolver
// this server builds already bounds every upstream fetch at ten seconds,
// so this never fires against it; it exists for the handle that carries
// no bound of its own, where the alternative is a report that does not
// come back. It is the same budget the connection path holds, because a
// second number would be a second answer to one question.
var DNS_ANSWER_BUDGET_MS = b.constants.TIME.seconds(45);

// The code `b.safeAsync.withTimeout` raises when a budget runs out.
// Named once, because two places below have to agree about it: the
// finding that says a record could not be read, and the absence set that
// must never contain it.
var DNS_TIMEOUT_CODE = "async/timeout";

function _assertBudget(value, label) {
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    throw new TypeError(label + " must be a positive finite number of milliseconds. It is " +
      "how long this server waits on the DNS handle it was given before reporting that it " +
      "could not find out, and there is no value for it that means no limit.");
  }
  return value;
}

/**
 * @primitive blamepost.mail.posture.withinDnsBudget
 * @signature blamepost.mail.posture.withinDnsBudget(work, budgetMs, label)
 * @since     0.1.0
 * @status    stable
 * @spec      internal (design: one bound over every DNS handle this server was given)
 * @related   blamepost.mail.posture.txtLookup, blamepost.mail.posture.create
 *
 * A bound over one question asked of a DNS handle this server does not
 * own. Composes `b.safeAsync.withTimeout`, so a question that is
 * accepted and never answered ends as a rejection carrying
 * `async/timeout` instead of as a wait with nothing on the other end of
 * it.
 *
 * `label` names the question in the rejection's message, because the
 * operator reading it needs to know which record the wait was for.
 *
 * One bound, composed by every caller, rather than a number per module.
 * The connection path and the posture report ask the same handle the
 * same kind of question, and two budgets would be two answers to when
 * this server stops waiting.
 *
 * A lookup that runs out of budget is a lookup that FAILED. It is never
 * folded into "this name publishes nothing": a policy that disappears
 * when its query stalls is a policy an attacker removes by stalling the
 * query, and on a report it tells an operator to publish a record that
 * is already there.
 *
 * @example
 *   var answer = await blamepost.mail.posture.withinDnsBudget(
 *     resolver.queryTxt(name), 45000, "posture TXT " + name);
 */
function withinDnsBudget(work, budgetMs, label) {
  _assertBudget(budgetMs, "blamepost.mail.posture.withinDnsBudget: budgetMs");
  return b.safeAsync.withTimeout(Promise.resolve(work), budgetMs, { name: label });
}

// Two names published in a zone, folded far enough to be compared with
// each other. Case is not a difference (RFC 4343) and the DNS root's
// trailing dot is not a difference (RFC 1035 section 2.3.1), and a
// resolver hands back either spelling, so an MX answer and a configured
// hostname have to meet somewhere.
//
// This is deliberately NOT the identity layer's derivation, and it must
// not be replaced by it. Every value it folds arrived from DNS or from a
// policy document fetched over HTTPS, which are places this server does
// not control, and the identity derivation refuses a raw Unicode label,
// an A-label and a mixed-script label outright. Refusing here would
// throw away the finding: a zone that is wrong in a hostile way is
// exactly the zone the operator has to be told about, and a name that
// vanished on the way into the comparison would report as a record that
// matched nothing rather than as the record that is published.
//
// So the boundary is: names this server IS, folded by the identity
// layer; names a zone SAYS, folded here and only ever compared, never
// used to key anything.
function _normalizeName(name) {
  var value = String(name || "").trim().toLowerCase();
  return value.charAt(value.length - 1) === "." ? value.slice(0, -1) : value;
}

// A value on its way into a finding, made safe to print.
//
// Every one of them arrived from DNS, which is a place this server does
// not control: a receiver's MX name, the text of an SPF or DMARC
// record, the message a failed lookup carried. `blamepost doctor`
// writes findings into a terminal as plain lines, so an escape sequence
// in one repaints the screen of whoever ran the check, a carriage
// return overwrites the line above it, and a bidi override reverses the
// record name they are about to act on.
//
// `blamepost.text` is the screen, shared with every other surface that
// shows somebody else's text, and it repairs rather than refuses: a zone
// that is wrong in a hostile way is exactly the zone the operator has to
// be told about, and throwing over the shape of a bad record would
// withhold the finding it produced.
//
// What this adds is the shape of the answer. A finding's value is often
// the set of hosts or records that were published, so a list is screened
// item by item, and an absent value stays absent rather than becoming an
// empty string, which an operator would read as a record published with
// nothing in it.
function _printable(value) {
  if (value === null || value === undefined) return value === undefined ? undefined : null;
  if (Array.isArray(value)) return value.map(_printable);
  return displayText.forDisplay(value);
}

// A finding carries three verdicts rather than two. `ok` says whether
// the record is what this server expects, and `unresolved` says whether
// anything was learned about it at all.
//
// The third one is not a refinement of the second. "Your record is not
// published" and "I could not find out" call for opposite actions: the
// first is fixed by editing a zone and the second by looking at the
// resolver, and an operator sent to edit a zone that is already correct
// stops reading the report. So an unresolved finding names no expected
// value and no found value, because this server saw neither.
function _finding(record, ok, opts) {
  opts = opts || {};
  return {
    record:     record,
    name:       opts.name === undefined || opts.name === null ? null : _printable(opts.name),
    ok:         ok,
    unresolved: opts.unresolved === true,
    severity:   opts.severity || SEVERITY_REQUIRED,
    found:      opts.found === undefined ? null : _printable(opts.found),
    expected:   opts.expected === undefined ? null : _printable(opts.expected),
    detail:     _printable(opts.detail || ""),
  };
}

function _timedOut(err) {
  return !!err && err.code === DNS_TIMEOUT_CODE;
}

// What a check says when it could not settle.
//
// Every unsettled branch reports through here, so the report has one
// way of saying it rather than one per record, and the operator reading
// any of them is pointed at the same place. The wording is deliberate
// about what is NOT known: the record may be published and correct, and
// this server has no opinion either way.
function _unresolved(record, qname, err, severity) {
  return _finding(record, false, {
    name:       qname,
    severity:   severity || SEVERITY_REQUIRED,
    unresolved: true,
    detail:     (_timedOut(err)
      ? "This server waited for an answer about " + qname + " and gave up: " + _why(err) + "."
      : "The lookup for " + qname + " did not complete: " + _why(err) + ".") +
      " Nothing was learned about the record, so it may well be published and correct. " +
      "This is a question about the resolver this server reads rather than about the zone.",
  });
}

// A name that does not exist and a resolver that could not answer are
// different findings with different remedies: one is fixed by publishing
// a record, the other by looking at the resolver. Telling an operator
// their lookup failed for a record they simply have not published sends
// them to the wrong place, and it is the answer they get most often,
// because a name with no record usually does not exist at all.
//
// RFC 1035 §4.1.1 RCODE 3 is that case, and the resolver carries it
// under its own code. `resolver/query-failed` is every other non-zero
// RCODE, a SERVFAIL or a REFUSED, and it deliberately does NOT read as
// absence here: a lookup nobody answered is not a record nobody
// published, and reading it as one lets whoever can break the query
// delete the policy that would have refused them.
//
// `ENOTFOUND` and `ENODATA` stay in the set because they are how a
// `dnsLookup` an operator supplied signals the same thing, and one of
// them is what `txtLookup` below raises on its own behalf.
var ABSENT_NAME_CODES = Object.freeze(["ENOTFOUND", "ENODATA", "resolver/nxdomain"]);

// The one thing that must never be true of that list, checked at load
// rather than trusted to review.
//
// A lookup that ran out of its budget is a lookup that FAILED, and it is
// the most tempting thing on this page to fold into absence, because the
// handle answered nothing and a name that publishes nothing also answers
// nothing. The two are not the same fact. Reading a stalled query as an
// empty zone hands whoever can stall the query the power to delete the
// policy that would have refused them, and it turns this report into one
// that tells an operator to publish a record they published years ago.
//
// Adding the code above therefore stops the boot rather than quietly
// widening what counts as absence.
if (ABSENT_NAME_CODES.indexOf(DNS_TIMEOUT_CODE) !== -1) {
  throw new TypeError("blamepost.mail.posture: " + DNS_TIMEOUT_CODE + " is a lookup that did " +
    "not complete and must never be read as a name that publishes nothing. A policy that " +
    "disappears when its query stalls is a policy an attacker removes by stalling the query.");
}

function _isAbsence(err) {
  if (!err) return false;
  return ABSENT_NAME_CODES.indexOf(err.code) !== -1;
}

function _why(err) {
  return (err && err.message) || String(err);
}

// The signal the mail-authentication and TLS-policy primitives read for
// "this name publishes nothing", which is not the one a resolver
// raises. They were written against `dnsPromises`, so absence is
// `ENODATA`, while a resolver answers a name that does not exist with a
// code of its own. Handing one straight to the other turns the
// commonest answer in DNS into a lookup failure, so the translation
// happens here, once, at the boundary between the two.
var TXT_ABSENT_CODE = "ENODATA";

// Every TXT string of one record set, each record joined from the
// character strings RFC 1035 §3.3.14 splits it into. `null` means the
// name publishes nothing, which is an answer rather than an error; only
// a lookup that could not complete throws.
async function _txtRecords(resolver, name, budgetMs) {
  var answer;
  try {
    answer = await withinDnsBudget(resolver.queryTxt(name), budgetMs, "posture TXT " + name);
  } catch (err) {
    if (_isAbsence(err)) return null;
    throw err;
  }
  var out = [];
  var rrs = (answer && answer.rrs) || [];
  for (var i = 0; i < rrs.length; i += 1) {
    var decoded = rrs[i].decoded;
    if (Array.isArray(decoded)) out.push(decoded.join(""));
    else if (typeof decoded === "string") out.push(decoded);
  }
  return out.length > 0 ? out : null;
}

/**
 * @primitive blamepost.mail.posture.txtLookup
 * @signature blamepost.mail.posture.txtLookup(resolver)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 1035 §3.3.14, RFC 1035 §4.1.1
 * @related   blamepost.mail.posture.create, blamepost.resolver
 *
 * The TXT reader the framework's mail-authentication and TLS-policy
 * primitives accept, over a resolver this server pinned. Every one of
 * them takes a `dnsLookup(qname, type)` and builds its own resolver
 * when none is given, which reads whatever the host would answer with.
 * A forged SPF, DMARC or MTA-STS record is exactly what pinning a
 * resolver is for, so the same reader is handed to all of them.
 *
 * It answers `string[][]`, the character strings a TXT record is split
 * into, and it refuses anything but a TXT question rather than
 * quietly answering the wrong one.
 *
 * Absence is the part that has to be right. Those primitives read
 * `ENODATA` as "this name publishes nothing" and treat any other
 * failure as a lookup that could not complete, while a resolver names
 * a name that does not exist with a code of its own. Handing one
 * straight to the other turns the commonest answer in DNS, a name that
 * does not exist, into a transient failure, and an enforcing sender
 * then stops delivering to every domain that never published a policy.
 *
 * The reverse mistake costs more. A lookup that was refused, that
 * failed upstream, or that ran out of the budget this reader holds over
 * the handle keeps reading as a failure and is never folded into
 * absence, because a policy that disappears when its query breaks or
 * stalls is a policy an attacker can remove by breaking or stalling the
 * query.
 *
 * The bound is the reader's own. Every consumer of this handed it a
 * resolver nobody here wrote, so a question that is accepted and never
 * answered would otherwise be a wait with nothing on the other end of
 * it, on whichever surface asked.
 *
 * @example
 *   var lookup = blamepost.mail.posture.txtLookup(blamepost.resolver());
 *   var policy = await b.network.smtp.mtaSts.fetch("example.com", { dnsLookup: lookup });
 */
function txtLookup(resolver) {
  return _txtLookupWithin(resolver, DNS_ANSWER_BUDGET_MS);
}

// The same reader over a budget the caller chose, which is what the
// posture checker composes: a report an operator is watching may want to
// give up sooner than a connection would.
function _txtLookupWithin(resolver, budgetMs) {
  if (!resolver || typeof resolver.queryTxt !== "function") {
    throw new TypeError("blamepost.mail.posture.txtLookup: a resolver handle with queryTxt " +
      "is required (blamepost.resolver() builds one)");
  }
  _assertBudget(budgetMs, "blamepost.mail.posture.txtLookup: the DNS answer budget");
  return async function dnsLookup(qname, type) {
    var qtype = String(type || "TXT").toUpperCase();
    if (qtype !== "TXT") {
      throw new Error("blamepost.mail.posture: the policy lookups this server makes are TXT " +
        "only, and something asked for " + qtype + " at " + qname);
    }
    var records = await _txtRecords(resolver, qname, budgetMs);
    if (records === null) {
      var err = new Error("no TXT records for " + qname);
      err.code = TXT_ABSENT_CODE;
      throw err;
    }
    return records.map(function (record) { return [record]; });
  };
}

// Every TXT string at one name, read through the `dnsLookup` shape the
// framework's policy primitives take rather than through a resolver
// handle. `null` means the name publishes nothing, which is an answer;
// only a lookup that could not complete throws.
//
// The same reading of absence as everywhere else in this module. A
// caller may hand in `txtLookup`'s output, which raises the code the
// policy primitives expect, or an operator's own lookup, or a resolver
// error that reached here unchanged, and a second answer to "was this
// name absent" is how those three drift apart.
//
// The budget is held here as well as inside `txtLookup`, because two of
// those three callers are lookups this module did not build. A second
// bound over an already bounded reader costs nothing: the inner one
// fires first and the outer never runs.
async function _recordsVia(dnsLookup, qname, budgetMs) {
  var rows;
  try {
    rows = await withinDnsBudget(dnsLookup(qname, "TXT"), budgetMs, "posture TXT " + qname);
  } catch (err) {
    if (_isAbsence(err)) return null;
    throw err;
  }
  var out = [];
  for (var i = 0; i < (rows || []).length; i += 1) {
    var row = rows[i];
    out.push(Array.isArray(row) ? row.join("") : String(row));
  }
  return out.length > 0 ? out : null;
}

// RFC 8460 §3 anchors the version tag at the start of the record and
// follows it with a field delimiter, optional whitespace and `;`, so
// `v=TLSRPTv1..` is not a version tag. It separates two answers that
// need different remedies once the framework primitive below has said
// no, a record written in a shape senders skip past and a record senders
// read and find no destination in, and it holds a record the primitive
// accepted to the same grammar a sender reads it under.
var TLS_RPT_VERSION_RE = /^v=TLSRPTv1[ \t]*;/i;

/**
 * @primitive blamepost.mail.posture.tlsRptEndpoint
 * @signature blamepost.mail.posture.tlsRptEndpoint(domain, opts)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 8460 §3
 * @related   blamepost.mail.posture.txtLookup, blamepost.mail.delivery.tlsRpt
 *
 * Where a domain wants aggregate reports about the transport security
 * of mail sent to it, if anywhere. Composes
 * `b.network.smtp.tlsRpt.fetchPolicy`, so the verdict is the one a
 * sender reaches rather than a second reading of the same record.
 *
 * Returns `{ state, rua, records, why, code }`. `state` is one of:
 *
 *   - `published`: an endpoint exists and `rua` lists it.
 *   - `absent`: nothing a sender would act on is published. `records`
 *     carries what the name did publish, so a caller can say which of
 *     the two shapes it was.
 *   - `unsettled`: the lookup could not complete, `why` says what the
 *     resolver reported and `code` carries the failure's own code, so a
 *     caller can tell a query that ran out of time from one that was
 *     refused.
 *
 * Keeping `absent` and `unsettled` apart is the whole point of the
 * three-way answer. They call for opposite responses: nobody is owed a
 * report by a domain that published nothing, and a domain whose record
 * could not be read may well be owed one, so throwing its observations
 * away because a resolver was briefly unreachable destroys evidence it
 * asked for. A lookup that stalls is `unsettled` for the same reason:
 * folding it into `absent` would let a silent resolver withdraw a
 * domain's claim on the reports it asked for.
 *
 * A budget is held over the lookup, because the reader is the caller's
 * and may be one that accepts a question and never answers it.
 *
 * @opts
 *   dnsLookup:         function,   // required; (qname, "TXT") => string[][], from txtLookup
 *   dnsAnswerBudgetMs: number,     // optional; how long to wait on that reader, default 45s
 *
 * @example
 *   var lookup = blamepost.mail.posture.txtLookup(blamepost.resolver());
 *   var where  = await blamepost.mail.posture.tlsRptEndpoint("example.net", { dnsLookup: lookup });
 *   where.state;   // "published"
 */
async function tlsRptEndpoint(domain, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new TypeError("blamepost.mail.posture.tlsRptEndpoint: domain must be a non-empty string");
  }
  opts = opts || {};
  if (typeof opts.dnsLookup !== "function") {
    throw new TypeError("blamepost.mail.posture.tlsRptEndpoint: opts.dnsLookup is required " +
      "(blamepost.mail.posture.txtLookup builds one over the resolver the operator pinned)");
  }
  var budgetMs = opts.dnsAnswerBudgetMs === undefined
    ? DNS_ANSWER_BUDGET_MS
    : _assertBudget(opts.dnsAnswerBudgetMs,
      "blamepost.mail.posture.tlsRptEndpoint: opts.dnsAnswerBudgetMs");
  var qname = "_smtp._tls." + domain;

  // The framework primitive decides, and it decides first. It is the
  // one a sender reaches, so anything read here before it would be a
  // second opinion about a record this server does not get a vote on.
  // The budget sits around it rather than inside it, because the reader
  // it resolves through is the caller's and this is the only place that
  // knows how long the answer is worth waiting for.
  var policy;
  try {
    policy = await withinDnsBudget(
      b.network.smtp.tlsRpt.fetchPolicy(domain, { dnsLookup: opts.dnsLookup }),
      budgetMs, "posture TLS-RPT " + qname);
  } catch (err) {
    return {
      state: "unsettled", rua: [], records: null,
      why:   _why(err), code: (err && err.code) || null,
    };
  }
  var records;
  if (policy !== null && Array.isArray(policy.rua) && policy.rua.length > 0) {
    // The primitive takes a record whose version tag runs straight into
    // other text, which a sender reading RFC 8460 §3 skips. So the
    // records are read back and the endpoint is published only when
    // exactly one of them carries the version tag the RFC writes. A read
    // that fails leaves the primitive's answer standing.
    try { records = await _recordsVia(opts.dnsLookup, qname, budgetMs); }
    catch (_readErr) { records = null; }
    var versionedRecords = Array.isArray(records)
      ? records.filter(function (r) { return TLS_RPT_VERSION_RE.test(r); }) : null;
    if (versionedRecords === null || versionedRecords.length === 1) {
      return { state: "published", rua: policy.rua.slice(), records: null, why: "", code: null };
    }
    return {
      state: "absent", rua: [], records: records,
      why:   "", code: null,
    };
  }

  // Nothing a sender would act on is published, and the two shapes that
  // produce that answer need different remedies. Reading the name back
  // separates them; a read that fails here costs the detail rather than
  // the verdict, which is already settled.
  try { records = await _recordsVia(opts.dnsLookup, qname, budgetMs); }
  catch (_e) { records = null; }
  return {
    state: "absent", rua: [], records: records === undefined ? null : records,
    why:   "", code: null,
  };
}

// The name a domain publishes its own DMARC policy at, RFC 9989 §4.9.
var DMARC_NAME_PREFIX = "_dmarc.";

// The version tag every DMARC record opens with, RFC 9989 §4.8, and the
// length of it. A receiver reads the strings at the name and skips every
// one that does not begin with it, so this is what separates a policy
// from whatever else the operator publishes beside it.
var DMARC_VERSION_TAG = "v=dmarc1";

// The longest published record this server will take apart. RFC 1035
// §3.3.14 splits a TXT record into 255-octet strings and a record may
// carry several, so this leaves room for a policy naming several
// reporting addresses and no room for a document.
var MAX_DMARC_RECORD_CHARS = 4096;

function _isDmarcRecord(record) {
  return record.slice(0, DMARC_VERSION_TAG.length).toLowerCase() === DMARC_VERSION_TAG;
}

/**
 * @primitive blamepost.mail.posture.dmarcRecord
 * @signature blamepost.mail.posture.dmarcRecord(domain, opts)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 9989 §4.8, RFC 9989 §4.9, RFC 7489 §6.3
 * @related   blamepost.mail.posture.txtLookup, blamepost.mail.posture.tlsRptEndpoint
 *
 * The DMARC record a domain publishes at its own `_dmarc` name, read as
 * the tags it carries rather than as a verdict about them. Returns
 * `{ state, record, policy, subdomainPolicy, percent, name, why, code }`.
 *
 * `state` is one of:
 *
 *   - `published`: one record is there and it parses. `record` is the
 *     text as published, `policy` is its `p` tag, `subdomainPolicy` its
 *     `sp` tag, and `percent` its `pct` tag, which RFC 7489 §6.3
 *     defaults to 100 for a record that carries none.
 *   - `absent`: the name publishes no DMARC record.
 *   - `unusable`: the name publishes more than one, or one that will not
 *     parse, or one longer than this reader takes apart. A receiver
 *     reads no policy from any of those, so neither does this.
 *   - `unsettled`: the lookup did not complete. `why` carries what the
 *     resolver reported and `code` its own code.
 *
 * It does not walk upward, and `blamepost.mail.posture.check` does. The
 * two answer different questions: which policy REACHES a domain is what
 * says whether its mail is protected, and what the domain itself
 * publishes is what anyone editing that record needs. Offering a
 * parent's record as this one's would have an operator edit a zone they
 * may not own.
 *
 * `absent` and `unsettled` are kept apart for the reason every other
 * lookup in this module keeps them apart: a policy that disappears when
 * its query stalls is a policy an attacker removes by stalling the
 * query.
 *
 * @opts
 *   dnsLookup:         function,   // required; (qname, "TXT") => string[][], from txtLookup
 *   dnsAnswerBudgetMs: number,     // optional; how long to wait on that reader, default 45s
 *
 * @example
 *   var lookup = blamepost.mail.posture.txtLookup(blamepost.resolver());
 *   var found  = await blamepost.mail.posture.dmarcRecord("example.com", { dnsLookup: lookup });
 *   found.policy;   // "none"
 */
async function dmarcRecord(domain, opts) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new TypeError("blamepost.mail.posture.dmarcRecord: domain must be a non-empty string");
  }
  opts = opts || {};
  if (typeof opts.dnsLookup !== "function") {
    throw new TypeError("blamepost.mail.posture.dmarcRecord: opts.dnsLookup is required " +
      "(blamepost.mail.posture.txtLookup builds one over the resolver the operator pinned)");
  }
  var budgetMs = opts.dnsAnswerBudgetMs === undefined
    ? DNS_ANSWER_BUDGET_MS
    : _assertBudget(opts.dnsAnswerBudgetMs,
      "blamepost.mail.posture.dmarcRecord: opts.dnsAnswerBudgetMs");
  var qname = DMARC_NAME_PREFIX + domain;

  var found;
  try { found = await _recordsVia(opts.dnsLookup, qname, budgetMs); }
  catch (err) {
    return _dmarcAnswer("unsettled", qname, null, _why(err), (err && err.code) || null);
  }

  var records = (found || []).filter(_isDmarcRecord);
  if (records.length === 0) return _dmarcAnswer("absent", qname, null, "", null);
  if (records.length > 1) {
    return _dmarcAnswer("unusable", qname, null,
      "the name publishes " + records.length + " DMARC records, and RFC 9989 §4.9 has a " +
      "receiver read no policy at all when more than one is there", null);
  }
  if (records[0].length > MAX_DMARC_RECORD_CHARS) {
    return _dmarcAnswer("unusable", qname, null,
      "the record runs to " + records[0].length + " characters, and " +
      MAX_DMARC_RECORD_CHARS + " is the most this server takes apart", null);
  }

  var parsed;
  try { parsed = b.mail.dmarc.parseRecord(records[0]); }
  catch (parseErr) {
    return _dmarcAnswer("unusable", qname, records[0], _why(parseErr),
      (parseErr && parseErr.code) || null);
  }
  var badPercent = _badDmarcPercent(records[0], parsed.pct);
  if (badPercent !== null) {
    return _dmarcAnswer("unusable", qname, records[0],
      "the record's pct tag is " + JSON.stringify(badPercent) + ", and RFC 7489 §6.3 makes it " +
      "a whole number from 0 to 100", null);
  }
  var answer = _dmarcAnswer("published", qname, records[0], "", null);
  answer.policy = String(parsed.p || "").toLowerCase();
  answer.subdomainPolicy = parsed.sp === null || parsed.sp === undefined
    ? null : String(parsed.sp).toLowerCase();
  answer.percent = typeof parsed.pct === "number" && isFinite(parsed.pct) ? parsed.pct : null;
  return answer;
}

// The `pct` value a record states that is not a whole number from 0 to
// 100, or null when every `pct` tag it carries is one. The framework
// parser reads the tag with `parseInt`, so `1.5` arrives as 1 and `250`
// as 250; the record's own text is checked as well as the number.
var DMARC_PCT_TAG_RE   = /^[ \t]*pct[ \t]*=[ \t]*([^;]*?)[ \t]*$/i;
var DMARC_PCT_VALUE_RE = /^[0-9]{1,3}$/;

function _badDmarcPercent(record, parsedPct) {
  var tags = String(record).split(";");
  for (var i = 0; i < tags.length; i += 1) {
    var m = DMARC_PCT_TAG_RE.exec(tags[i]);
    if (m === null) continue;
    if (!DMARC_PCT_VALUE_RE.test(m[1]) || parseInt(m[1], 10) > 100) return m[1];
  }
  if (typeof parsedPct === "number" && (!isFinite(parsedPct) || parsedPct < 0 ||
      parsedPct > 100)) {
    return String(parsedPct);
  }
  return null;
}

// One answer shape, built in one place, so the five branches above cannot
// disagree about which fields a reading carries. Everything a caller
// prints came out of DNS, so the record and the reason both go through
// the same screening a finding does.
function _dmarcAnswer(state, qname, record, why, code) {
  return {
    state:           state,
    record:          record === null ? null : _printable(record),
    policy:          null,
    subdomainPolicy: null,
    percent:         null,
    name:            qname,
    why:             _printable(why),
    code:            code,
  };
}

// One tag out of a published policy record, read the way the verifier
// reads it. RFC 6376 §3.2 allows folding whitespace around a tag's `=`,
// and §3.6.1 ignores whitespace inside the base64 of `p=`, so a
// provider that wraps a long value and an operator who pastes a key
// across two lines both publish records every receiver accepts.
//
// `b.mail.dkim.verify` takes a record apart with this same call, so a
// signature against one of those records passes. A reader here that
// kept the whitespace made the two disagree about one record: the
// verifier accepted it and the report told the operator the published
// key did not match the key this server signs with, blaming a
// truncated paste for a record that was signing mail correctly.
function _tag(record, name) {
  var pairs = b.structuredFields.parseTagList(record, { unfold: true, stripValueWs: true });
  for (var i = 0; i < pairs.length; i += 1) {
    if (pairs[i][0] === name) return pairs[i][1];
  }
  return null;
}

// The modifier list `b.mail.spf.parseRecord` hangs off the mechanisms it
// returns. RFC 7208 §4.6 makes it a name=value pair with no qualifier.
function _modifier(mechanisms, name) {
  var modifiers = (mechanisms && mechanisms.modifiers) || [];
  for (var i = 0; i < modifiers.length; i += 1) {
    if (modifiers[i].name === name) return modifiers[i];
  }
  return null;
}

function _isSpfRecord(record) {
  var lower = record.toLowerCase();
  return lower.slice(0, 7) === "v=spf1 " || lower === "v=spf1";
}

// RFC 7208 §6.1 caps a whole evaluation at ten DNS lookups. Following a
// redirect chain further than this is not a posture question any more,
// and a zone that needs more than three hops to say what its policy is
// has a finding of its own.
var SPF_REDIRECT_MAX_HOPS = 3;

// The longest published record a receiver reads, RFC 7208 §3.4, counted
// the way the receiver counts it: the character strings joined, before
// anything is parsed.
//
// A receiver answers a longer record with a permanent error, which means
// the domain has no usable SPF at all. That verdict arrives from the
// length alone, so a record over it can end in `-all`, name every
// sending host correctly, and still authorize nobody.
//
// It is here because a report that reads the record and stops at the
// policy would call one of those correct. A domain reaches this length
// by adding one sending provider at a time, each addition obviously
// right, and the message it produces is mail that starts failing SPF
// everywhere with a zone the operator can read and see nothing wrong
// with. `test/layer-1-state/inbound-posture.test.js` holds the verdict
// this reaches against the verdict `b.mail.spf.verify` reaches for the
// same record, so the two cannot drift apart on either side of the
// number.
var MAX_SPF_RECORD_OCTETS = 450;

/**
 * @primitive blamepost.mail.posture.create
 * @signature blamepost.mail.posture.create(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 7208 (SPF), RFC 6376 (DKIM), RFC 9989 (DMARC), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 7672 (DANE)
 *
 * Build the posture checker. Returns `{ check }`.
 *
 * The DKIM handle is optional and its absence narrows the result
 * rather than failing it: without it there is no expected public key
 * to compare a selector record against, so the selector checks are
 * left out of the report instead of guessed at. A handle that IS given
 * and cannot answer which selectors to expect is refused here instead,
 * because that is not absence: left to narrow the report the same way,
 * it removes the selector rows from a run that then closes by saying
 * everything is in place.
 *
 * The resolver is refused here too when it is short of any reader the
 * report calls. Every one of them is asked for each hosted domain, and a
 * missing one produced a finding saying the record could not be looked
 * up, which sends the operator to a resolver that was never asked.
 *
 * A budget is held over every lookup the report makes. The resolver is
 * the operator's, so a question it accepts and never answers would
 * otherwise leave the command and the browser request that asked for it
 * waiting for as long as the resolver stayed silent. A lookup that runs
 * out of it is reported as one this server could not settle, which is
 * neither a missing record nor a wrong one.
 *
 * @opts
 *   hostname:          string,   // required; the name the MX record must point at
 *   resolver:          object,   // b.network.dns.resolver handle; one is built when omitted
 *   dkim:              object,   // optional; supplies the expected selector records
 *   dnsAnswerBudgetMs: number,   // optional; how long one lookup may take, default 45s
 *
 * @example
 *   var posture = blamepost.mail.posture.create({ hostname: "mx.example.com" });
 *   var report = await posture.check({ domains: ["example.com"] });
 *   report.ok;   // false when any required record is wrong
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.mail.posture.create: opts object is required");
  }
  if (typeof opts.hostname !== "string" || opts.hostname.length === 0) {
    throw new TypeError("blamepost.mail.posture.create: opts.hostname is required " +
      "(it is the name the MX record has to point at)");
  }
  var hostname = _normalizeName(opts.hostname);
  var resolver = opts.resolver || b.network.dns.resolver.create({ profile: "strict" });
  // Every reader this report calls, refused at construction rather than
  // at the lookup that wanted one.
  //
  // `txtLookup` below already refuses a handle with no `queryTxt`, and
  // the MX and TLSA readers were reached without being checked, so a
  // handle short of either produced a report saying those records could
  // not be looked up. That sentence sends an operator to their resolver,
  // and it is the wrong instruction twice over: the resolver answered
  // nothing because nothing asked it, and the fault is in the handle the
  // caller built. So all three throw here, where the checker is built.
  ["queryTxt", "queryMx", "queryTlsa"].forEach(function (reader) {
    if (typeof resolver[reader] !== "function") {
      throw new TypeError("blamepost.mail.posture.create: opts.resolver has no " + reader +
        ", and the report asks every hosted domain for that record. " +
        "blamepost.resolver() builds a handle carrying all of them.");
    }
  });
  // The DKIM handle is optional, and a handle that cannot answer which
  // selectors to expect is not the same as not passing one. Left
  // unchecked, the selector rows vanished from the report and the run
  // closed by saying everything this server expects is in place, which is
  // a clean verdict over a question nobody asked.
  if (opts.dkim !== undefined && opts.dkim !== null &&
      typeof opts.dkim.dnsRecords !== "function") {
    throw new TypeError("blamepost.mail.posture.create: opts.dkim was given and has no " +
      "dnsRecords(domain), which is where the selector records this server expects come " +
      "from. Pass a blamepost.mail.dkim handle, or pass none and the selector checks are " +
      "left out of the report rather than reported as passing.");
  }
  var dkim = opts.dkim || null;
  // Read and refused at construction, so a budget written as a string is
  // a failure the operator sees when they build the checker rather than
  // a bound that quietly reverted to the default on the first lookup.
  // There is no value that turns it off: the value that would is the
  // behavior it exists to end.
  var budgetMs = opts.dnsAnswerBudgetMs === undefined
    ? DNS_ANSWER_BUDGET_MS
    : _assertBudget(opts.dnsAnswerBudgetMs,
      "blamepost.mail.posture.create: opts.dnsAnswerBudgetMs");

  // One reader for every policy lookup this report hands to a
  // framework primitive, so the whole report sees one view of DNS and
  // one bound on how long it waits for it.
  var _dnsLookup = _txtLookupWithin(resolver, budgetMs);

  async function _checkMx(domain) {
    try {
      var answer;
      try {
        answer = await withinDnsBudget(resolver.queryMx(domain), budgetMs,
          "posture MX " + domain);
      } catch (lookupErr) {
        if (!_isAbsence(lookupErr)) throw lookupErr;
        answer = null;
      }
      var rrs = (answer && answer.rrs) || [];
      var hosts = [];
      var nullMx = false;
      for (var i = 0; i < rrs.length; i += 1) {
        var decoded = rrs[i].decoded;
        var exchange = decoded && typeof decoded === "object" ? decoded.exchange : decoded;
        var name = _normalizeName(exchange === undefined || exchange === null ? "" : exchange);
        // RFC 7505: a single MX with an empty exchange and preference 0
        // is the domain saying it accepts no mail at all.
        if (name.length === 0) { nullMx = true; continue; }
        hosts.push(name);
      }
      if (nullMx && hosts.length === 0) {
        return _finding("MX", false, {
          name: domain, expected: hostname,
          detail: "The domain publishes a null MX (RFC 7505), which tells every sender it " +
            "accepts no mail at all. Replace it with an MX pointing at " + hostname + ".",
        });
      }
      if (hosts.length === 0) {
        return _finding("MX", false, {
          name: domain, expected: hostname,
          detail: "The domain publishes no MX record, so nothing tells other servers " +
            "where to deliver its mail.",
        });
      }
      if (hosts.indexOf(hostname) === -1) {
        return _finding("MX", false, {
          name: domain, found: hosts, expected: hostname,
          detail: "The MX records point at " + hosts.join(", ") + " and none of them is " +
            hostname + ". Mail for this domain is being delivered somewhere else.",
        });
      }
      return _finding("MX", true, { name: domain, found: hosts, expected: hostname });
    } catch (err) {
      return _unresolved("MX", domain, err);
    }
  }

  // Walk to the record that actually decides. A receiver reads the
  // mechanisms left to right and `all` always matches, so the first one
  // is the policy and anything after it is unreachable. A record with no
  // `all` hands the decision to its `redirect=` target (RFC 7208 §6.1),
  // which is where a provider-hosted policy lives. Reporting the pointer
  // instead of the policy would fail a zone that is correct and tell the
  // operator to delete the delegation.
  async function _spfPolicyFor(domain) {
    var chain = [];
    var name = domain;
    for (var hop = 0; hop <= SPF_REDIRECT_MAX_HOPS; hop += 1) {
      if (chain.indexOf(name) !== -1) return { problem: "loop", at: name, chain: chain };
      chain.push(name);

      var found = await _txtRecords(resolver, name, budgetMs);
      var records = (found || []).filter(_isSpfRecord);
      if (records.length === 0) return { problem: "missing", at: name, chain: chain };
      if (records.length > 1) {
        return { problem: "multiple", at: name, found: records, chain: chain };
      }
      // Checked before the record is parsed, because a receiver answers
      // on the length without parsing either. Reading the policy first
      // and reporting on it would describe an ending nobody ever reaches.
      if (records[0].length > MAX_SPF_RECORD_OCTETS) {
        return { problem: "too-long", at: name, found: records[0],
                 octets: records[0].length, chain: chain };
      }

      var mechanisms;
      try { mechanisms = b.mail.spf.parseRecord(records[0]); }
      catch (err) {
        return { problem: "unreadable", at: name, found: records[0], why: _why(err), chain: chain };
      }

      var all = null;
      for (var i = 0; i < mechanisms.length; i += 1) {
        if (mechanisms[i].mechanism === "all") { all = mechanisms[i]; break; }
      }
      if (all) return { at: name, found: records[0], qualifier: all.qualifier, chain: chain };

      var redirect = _modifier(mechanisms, "redirect");
      if (!redirect) return { problem: "no-policy", at: name, found: records[0], chain: chain };
      // A macro expands per message (RFC 7208 §7), so the name it points
      // at is not one thing this check could resolve on its own.
      if (redirect.value.indexOf("%") !== -1) {
        return { problem: "macro-redirect", at: name, found: records[0],
                 target: redirect.value, chain: chain };
      }
      name = _normalizeName(redirect.value);
    }
    return { problem: "too-many-redirects", at: name, chain: chain };
  }

  // "the record at example.com", or "the record at _spf.provider.example,
  // which example.com redirects to", so a finding about a delegated
  // policy says whose record it is talking about.
  function _spfWhere(policy, domain) {
    if (policy.at === domain) return "the SPF record for " + domain;
    return "the SPF record at " + policy.at + ", which " +
      policy.chain.slice(0, policy.chain.indexOf(policy.at)).join(" redirects to ") +
      " redirects to";
  }

  async function _checkSpf(domain) {
    var policy;
    try { policy = await _spfPolicyFor(domain); }
    catch (err) {
      return _unresolved("SPF", domain, err);
    }

    if (policy.problem === "missing" && policy.at === domain) {
      return _finding("SPF", false, {
        name: domain, expected: "v=spf1 ... -all",
        detail: "No SPF record. Receivers have nothing to check the sending host against.",
      });
    }
    if (policy.problem === "missing") {
      return _finding("SPF", false, {
        name: policy.at, expected: "v=spf1 ... -all",
        detail: "The record for " + domain + " redirects to " + policy.at + ", and " +
          policy.at + " publishes no SPF record. RFC 7208 §6.1 makes that a permanent error, " +
          "so the domain has no usable SPF at all.",
      });
    }
    if (policy.problem === "multiple") {
      return _finding("SPF", false, {
        name: policy.at, found: policy.found, expected: "exactly one v=spf1 record",
        detail: "There are " + policy.found.length + " SPF records at " + policy.at + ". " +
          "RFC 7208 §4.5 makes that a permanent error, and receivers treat the domain as " +
          "having no usable SPF at all.",
      });
    }
    if (policy.problem === "too-long") {
      return _finding("SPF", false, {
        name: policy.at, found: policy.found, expected: "a record of 450 octets or fewer",
        detail: _spfWhere(policy, domain) + " runs to " + policy.octets + " octets, and RFC " +
          "7208 caps a published record at " + MAX_SPF_RECORD_OCTETS + ". A receiver answers " +
          "a longer record with a permanent error without reading the policy in it, so the " +
          "domain authorizes nobody however the record ends. Replace the include terms with " +
          "the addresses they resolve to, or drop the senders the domain no longer uses.",
      });
    }
    if (policy.problem === "unreadable") {
      return _finding("SPF", false, {
        name: policy.at, found: policy.found, expected: "v=spf1 ... -all",
        detail: "The SPF record could not be read: " + policy.why + " A receiver that cannot " +
          "parse the record treats the result as a permanent error.",
      });
    }
    if (policy.problem === "no-policy") {
      return _finding("SPF", false, {
        name: policy.at, found: policy.found, expected: "a record ending in -all",
        detail: _spfWhere(policy, domain) + " has no all mechanism and no redirect, so it says " +
          "nothing about hosts it did not list.",
      });
    }
    if (policy.problem === "macro-redirect") {
      return _finding("SPF", false, {
        name: policy.at, found: policy.found, expected: "a redirect target this check can resolve",
        detail: "The record redirects to " + policy.target + ", which expands per message, so " +
          "the policy that applies cannot be resolved here. Check the target's record by hand.",
      });
    }
    if (policy.problem === "loop" || policy.problem === "too-many-redirects") {
      return _finding("SPF", false, {
        name: policy.at, found: policy.chain, expected: "a redirect chain that ends in a policy",
        detail: "The redirect chain " + policy.chain.join(" to ") + " does not reach a record " +
          "with an all mechanism. Receivers give up on it as a permanent error.",
      });
    }
    if (policy.qualifier !== "-") {
      return _finding("SPF", false, {
        name: policy.at, found: policy.found, expected: "-all",
        detail: _spfWhere(policy, domain) + " ends in " + policy.qualifier + "all. That asks " +
          "receivers to accept mail from hosts the domain did not authorize. Change the " +
          "ending to -all.",
      });
    }
    return _finding("SPF", true, { name: policy.at, found: policy.found, expected: "-all" });
  }

  function _dmarcVerdictFor(policy, name, found, inherited) {
    if (policy !== "quarantine" && policy !== "reject") {
      return _finding("DMARC", false, {
        name: name, found: found, expected: "p=quarantine or p=reject",
        detail: "The policy that applies is p=" + (policy || "absent") + ", published at " +
          name + ". Reports still arrive, but receivers are told to deliver forgeries " +
          "normally." + (inherited
            ? " Publishing a record of its own at " + inherited + " is how a subdomain gets a " +
              "stricter policy than its parent."
            : ""),
      });
    }
    return _finding("DMARC", true, { name: name, found: found, expected: "p=" + policy });
  }

  async function _checkDmarc(domain) {
    var qname = "_dmarc." + domain;
    var found;
    try { found = await _txtRecords(resolver, qname, budgetMs); }
    catch (err) {
      return _unresolved("DMARC", qname, err);
    }

    var records = (found || []).filter(_isDmarcRecord);
    if (records.length > 1) {
      return _finding("DMARC", false, {
        name: qname, found: records, expected: "exactly one v=DMARC1 record",
        detail: "There are " + records.length + " DMARC records at " + qname + ". Receivers " +
          "ignore the policy entirely when more than one is published, so this domain has no " +
          "DMARC protection at all until one of them is removed.",
      });
    }
    if (records.length === 1) {
      // Checked before the record is parsed, the way the SPF path above
      // checks its own. `blamepost.mail.posture.dmarcRecord` answers
      // `unusable` on a record longer than this without reading it, so a
      // report that read the policy out of one would call a zone correct
      // that every other reader here treats as unreadable.
      //
      // The record is not quoted back. The two findings beside this one
      // quote what they refused, and both of those values are bounded by
      // the rule that refused them; this one is refusing a record for
      // being unbounded, so printing it would put the document in front
      // of the reader it was kept away from. The name and the length are
      // what an operator edits the zone from.
      if (records[0].length > MAX_DMARC_RECORD_CHARS) {
        return _finding("DMARC", false, {
          name: qname,
          expected: "a record of " + MAX_DMARC_RECORD_CHARS + " characters or fewer",
          detail: "The DMARC record at " + qname + " runs to " + records[0].length +
            " characters, and " + MAX_DMARC_RECORD_CHARS + " is the most this server takes " +
            "apart. Shorten it to one policy with the reporting addresses the domain uses.",
        });
      }

      var parsed;
      try { parsed = b.mail.dmarc.parseRecord(records[0]); }
      catch (err) {
        return _finding("DMARC", false, {
          name: qname, found: records[0], expected: "v=DMARC1; p=quarantine",
          detail: "The DMARC record could not be read: " + _why(err) + " A receiver that " +
            "cannot parse it treats the domain as having no policy.",
        });
      }
      return _dmarcVerdictFor(String(parsed.p || "").toLowerCase(), qname, records[0], null);
    }

    // No record at this name is not the same as no policy. RFC 9989
    // §4.10 walks the DNS tree from the sending domain upward, so a
    // record at an ancestor governs this one through its sp= tag, and a
    // hosted subdomain under a parent that publishes p=reject is already
    // covered. Reporting it as unprotected sends the operator to fix a
    // zone that is right, which is how a report stops being read.
    //
    // The walk is the one a receiver runs rather than a second
    // implementation of it, so this check and the verdict on an inbound
    // message cannot disagree about which record applies.
    var verdict;
    try {
      verdict = await b.mail.dmarc.evaluate({
        from:      "postmaster@" + domain,
        spf:       { result: "none", domain: null },
        dkim:      [],
        dnsLookup: _dnsLookup,
      });
    } catch (err) {
      return _unresolved("DMARC", qname, err);
    }

    // The walk itself could not settle. The record at this name may be
    // absent and a record above it may be perfectly correct; nobody
    // knows which, so this is the same verdict as a lookup that failed
    // rather than a report that the domain is unprotected.
    if (verdict.result === "temperror") {
      return _finding("DMARC", false, {
        name: qname, unresolved: true,
        detail: "A name above " + domain + " could not be resolved, so which DMARC policy " +
          "applies cannot be settled: " +
          (verdict.explanation || "the lookup did not complete") +
          ". Nothing was learned about the policy that governs this domain, so it may well " +
          "be published and correct. This is a question about the resolver this server " +
          "reads rather than about the zone.",
      });
    }
    if (verdict.result === "permerror" || !verdict.policy) {
      return _finding("DMARC", false, {
        name: qname, expected: "v=DMARC1; p=quarantine",
        detail: "No DMARC record here or at any name above it. Nothing tells receivers what " +
          "to do with mail that fails both SPF and DKIM alignment." +
          (verdict.explanation ? " (" + verdict.explanation + ")" : ""),
      });
    }

    var origin = "_dmarc." + (verdict.policyOriginDomain || domain);

    // A policy published by a public-suffix operator governs every name
    // registered under it, which is a different thing from a policy the
    // domain's own owner published. It can be withdrawn or weakened by
    // somebody the operator of this server has no relationship with, and
    // RFC 9989 §4.10.2 narrows relaxed alignment to the boundary it
    // declares, so a subdomain of this domain no longer aligns with it.
    // Leaning on it is not a posture this server reports as done.
    if (verdict.psdPolicyApplied === true) {
      return _finding("DMARC", false, {
        name: qname, expected: "v=DMARC1; p=quarantine",
        detail: domain + " publishes no DMARC record of its own. The policy reaching it " +
          "today is p=" + String(verdict.policy.p || "").toLowerCase() + " at " + origin +
          ", published by the operator of that suffix rather than by this domain's owner, " +
          "and it can change without notice. Publish a record at " + qname + ".",
      });
    }

    return _dmarcVerdictFor(String(verdict.policy.p || "").toLowerCase(), origin,
      "policy inherited by " + domain + " from " + origin, qname);
  }

  async function _checkDkim(domain) {
    if (!dkim || typeof dkim.dnsRecords !== "function") return [];
    var expected = await dkim.dnsRecords(domain);
    var findings = [];
    for (var i = 0; i < expected.length; i += 1) {
      var want = expected[i];
      var wantKey = _tag(want.dnsTxtValue, "p");
      try {
        var records = await _txtRecords(resolver, want.dnsName, budgetMs);
        var live = (records || []).filter(function (r) { return r.indexOf("v=DKIM1") !== -1; });
        if (live.length === 0) {
          findings.push(_finding("DKIM", false, {
            name: want.dnsName, expected: want.dnsTxtValue,
            severity: want.state === "retiring" ? SEVERITY_ADVISED : SEVERITY_REQUIRED,
            detail: want.state === "retiring"
              ? "This selector is retiring and its record is already gone. Mail signed " +
                "before the rotation and still in transit will fail DKIM at the receiver."
              : "The selector record is missing, so nothing this server signs for " + domain +
                " can be verified.",
          }));
          continue;
        }
        if (live.length > 1) {
          // RFC 6376 §3.6.2 gives a selector one key. Which of two
          // records a receiver reads is its own business, so half the
          // mail signed under this selector can fail while the other
          // half passes, which reads as an intermittent problem
          // somewhere else entirely.
          findings.push(_finding("DKIM", false, {
            name: want.dnsName, found: live, expected: want.dnsTxtValue,
            detail: "There are " + live.length + " DKIM records at this selector name. A " +
              "receiver reads one of them, and which one is not something the sender decides. " +
              "Leave only the value above.",
          }));
          continue;
        }
        var liveKey = _tag(live[0], "p");
        if (liveKey === "") {
          // RFC 6376 §3.6.1: an empty p= revokes the key rather than
          // publishing one. Receivers treat every signature under this
          // selector as a failure, which is a different problem from a
          // record that merely disagrees.
          findings.push(_finding("DKIM", false, {
            name: want.dnsName, found: live[0], expected: want.dnsTxtValue,
            detail: "The record publishes an empty key, which revokes the selector. Every " +
              "signature this server makes under it fails at the receiver. Replace the " +
              "record with the value above.",
          }));
          continue;
        }
        if (liveKey !== wantKey) {
          findings.push(_finding("DKIM", false, {
            name: want.dnsName, found: live[0], expected: want.dnsTxtValue,
            detail: "The published key does not match the private key this server signs " +
              "with. A record truncated by the DNS provider is the usual cause; check that " +
              "the whole value was pasted.",
          }));
          continue;
        }
        findings.push(_finding("DKIM", true, {
          name: want.dnsName, found: live[0], expected: want.dnsTxtValue,
        }));
      } catch (err) {
        findings.push(_unresolved("DKIM", want.dnsName, err,
          want.state === "retiring" ? SEVERITY_ADVISED : SEVERITY_REQUIRED));
      }
    }
    return findings;
  }

  async function _checkMtaSts(domain) {
    var qname = "_mta-sts." + domain;
    var findings = [];
    var haveTxt = false;
    try {
      var records = ((await _txtRecords(resolver, qname, budgetMs)) || []).filter(function (r) {
        return r.indexOf("v=STSv1") !== -1;
      });
      if (records.length === 0) {
        findings.push(_finding("MTA-STS TXT", false, {
          name: qname, expected: "v=STSv1; id=<token>",
          detail: "No MTA-STS TXT record. Senders will not look for the policy, so the " +
            "policy file alone does nothing.",
        }));
      } else if (!_tag(records[0], "id")) {
        findings.push(_finding("MTA-STS TXT", false, {
          name: qname, found: records[0], expected: "v=STSv1; id=<token>",
          detail: "The record has no id tag. Senders use it to notice a policy change, and " +
            "without it a cached policy is never refreshed.",
        }));
      } else {
        haveTxt = true;
        findings.push(_finding("MTA-STS TXT", true, { name: qname, found: records[0] }));
      }
    } catch (err) {
      findings.push(_unresolved("MTA-STS TXT", qname, err));
    }

    if (!haveTxt) return findings;

    var policyUrl = "https://mta-sts." + domain + "/.well-known/mta-sts.txt";
    try {
      // The fetch re-reads the TXT record on its own behalf before it
      // will touch the policy, and a spoofed one downgrades mail TLS, so
      // that lookup goes to the pinned resolver too rather than to
      // whatever the host would answer with.
      var policy = await b.network.smtp.mtaSts.fetch(domain, { dnsLookup: _dnsLookup });
      if (!policy) {
        findings.push(_finding("MTA-STS policy", false, {
          name: policyUrl,
          detail: "The TXT record is published but the policy could not be fetched. The " +
            "host has to serve it over HTTPS with a certificate valid for mta-sts." + domain + ".",
        }));
        return findings;
      }
      var mode = String(policy.mode || "").toLowerCase();
      var mx = Array.isArray(policy.mx) ? policy.mx.map(_normalizeName) : [];
      if (!b.network.smtp.mtaSts.matchMx(hostname, mx)) {
        findings.push(_finding("MTA-STS policy", false, {
          name: policyUrl, found: mx, expected: hostname,
          detail: "The policy lists " + (mx.join(", ") || "no hosts") + " and none of them " +
            "matches " + hostname + ". Senders honoring the policy will refuse to deliver here.",
        }));
        return findings;
      }
      if (mode !== "enforce") {
        findings.push(_finding("MTA-STS policy", false, {
          name: policyUrl, found: "mode: " + (mode || "absent"), expected: "mode: enforce",
          severity: SEVERITY_ADVISED,
          detail: "The policy is in " + (mode || "an unset") + " mode, which reports a " +
            "downgrade and then allows it.",
        }));
        return findings;
      }
      findings.push(_finding("MTA-STS policy", true, {
        name: policyUrl, found: "mode: enforce, mx: " + mx.join(", "),
      }));
    } catch (err) {
      // The fetch asks two questions: the TXT record, through the reader
      // this module bounds, and the policy file over HTTPS, which the
      // framework bounds at ten seconds of its own. A budget that ran
      // out is therefore the DNS half, and it says nothing about whether
      // the host serves the policy, so it is not reported as though it
      // did.
      findings.push(_timedOut(err)
        ? _unresolved("MTA-STS policy", qname, err)
        : _finding("MTA-STS policy", false, {
          name: policyUrl,
          detail: "Fetching the policy failed: " + _why(err),
        }));
    }
    return findings;
  }

  async function _checkTlsRpt(domain) {
    var qname = "_smtp._tls." + domain;
    var where;
    try {
      where = await tlsRptEndpoint(domain,
        { dnsLookup: _dnsLookup, dnsAnswerBudgetMs: budgetMs });
    } catch (err) {
      return _unresolved("TLS-RPT", qname, err, SEVERITY_ADVISED);
    }

    // The primitive already tells a record nobody published from a
    // lookup nobody answered, and it carries the failure's own code so
    // this can say which of the two the second one was.
    if (where.state === "unsettled") {
      return _unresolved("TLS-RPT", qname,
        { code: where.code, message: where.why }, SEVERITY_ADVISED);
    }

    if (where.state === "absent") {
      var published = where.records || [];
      if (published.length === 0) {
        return _finding("TLS-RPT", false, {
          name: qname, expected: "v=TLSRPTv1; rua=mailto:...",
          severity: SEVERITY_ADVISED,
          detail: "No TLS-RPT record. Senders that cannot reach this server over TLS have " +
            "nowhere to report it, so the failure stays invisible.",
        });
      }
      var versioned = published.filter(function (r) { return TLS_RPT_VERSION_RE.test(r); });
      if (versioned.length === 0) {
        return _finding("TLS-RPT", false, {
          name: qname, found: published, expected: "v=TLSRPTv1; rua=mailto:...",
          severity: SEVERITY_ADVISED,
          detail: "The name publishes a record that does not begin with the version tag. " +
            "RFC 8460 §3 puts v=TLSRPTv1 first, and senders skip past anything else, so " +
            "this record collects no reports at all.",
        });
      }
      return _finding("TLS-RPT", false, {
        name: qname, found: versioned[0], expected: "v=TLSRPTv1; rua=mailto:...",
        severity: SEVERITY_ADVISED,
        detail: "The record names no rua destination, so the reports have nowhere to go.",
      });
    }

    return _finding("TLS-RPT", true, {
      name: qname, found: where.rua, severity: SEVERITY_ADVISED,
    });
  }

  async function _checkTlsa() {
    var qname = "_25._tcp." + hostname;
    var answer;
    try {
      answer = await withinDnsBudget(resolver.queryTlsa(qname), budgetMs,
        "posture TLSA " + qname);
    } catch (err) {
      if (!_isAbsence(err)) return _unresolved("TLSA", qname, err);
      answer = null;
    }
    var count = ((answer && answer.rrs) || []).length;
    if (count === 0) {
      return _finding("TLSA", false, {
        name: qname, expected: "at least one TLSA record",
        detail: "DANE was asked for but no TLSA record covers the SMTP port on " + hostname + ".",
      });
    }

    // Whether a sender is allowed to use what was just read. RFC 7672
    // §1.3 lets a sender authenticate a peer against a TLSA record only
    // when the answer carrying it was DNSSEC-authenticated, and the
    // primitive this server sends through refuses an unauthenticated one
    // rather than using it. So a zone with TLSA records and no DNSSEC
    // over them is a zone nobody DANE-authenticates, and counting the
    // records is not the question.
    //
    // RFC 4035 §3.2.3 makes that a fact about the response rather than
    // about the record, which the resolver carries back as `validated`.
    // Three answers rather than two, because a handle that does not
    // report it has told this server nothing: reading silence as
    // authenticated claims a guarantee nobody gave, and reading it as
    // unauthenticated sends an operator to sign a zone that may already
    // be signed.
    var authenticated = answer === null ? undefined : answer.validated;
    if (authenticated === true) {
      return _finding("TLSA", true, { name: qname, found: count + " record(s)" });
    }
    if (authenticated === false) {
      return _finding("TLSA", false, {
        name: qname, found: count + " record(s), unauthenticated",
        expected: "records carried by a DNSSEC-authenticated answer",
        detail: "The records are published and the answer carrying them was not " +
          "DNSSEC-authenticated, so no sender is permitted to use them and none will. " +
          "Either the zone is unsigned, which is answered by signing it and lodging a DS " +
          "record with the parent, or the resolver this server reads does not validate, " +
          "which is answered by pointing it at one that does.",
      });
    }
    return _finding("TLSA", false, {
      name: qname, unresolved: true,
      detail: "The " + count + " record(s) were read and the resolver did not say whether " +
        "the answer was DNSSEC-authenticated, so whether any sender may use them is not " +
        "known. RFC 7672 §1.3 makes that the question DANE turns on. This is a question " +
        "about the resolver this server reads rather than about the zone.",
    });
  }

  /**
   * @primitive blamepost.mail.posture.check
   * @signature posture.check(opts)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 7208, RFC 6376, RFC 9989, RFC 8461, RFC 8460, RFC 7672
   * @related   blamepost.mail.posture.create
   *
   * Resolve and compare every record for the given domains. Returns
   * `{ ok, unresolved, checkedAt, hostname, domains }` where each domain
   * carries a list of findings. `ok` is false when any finding marked
   * required failed; advisory findings are reported without failing the
   * run, so an operator who has deliberately left TLS-RPT off is not
   * told they have a broken server.
   *
   * `unresolved` is true when any record could not be read at all. It
   * is reported beside `ok` rather than folded into it because the two
   * answer different questions: `ok` says whether the zone matches what
   * this server expects, and `unresolved` says whether the run knew
   * enough to have an opinion. A caller rendering the report can then
   * say "this record is wrong" and "I could not find out" in different
   * words, which is the difference between sending the operator to
   * their zone and sending them to their resolver.
   *
   * @opts
   *   domains: string[],   // required; the hosted domains to check
   *   dane:    boolean,    // also check the TLSA record for this server, and whether the
   *                        // answer carrying it was DNSSEC-authenticated (RFC 7672 §1.3)
   *
   * @example
   *   var report = await posture.check({ domains: ["example.com"] });
   *   report.domains[0].findings.filter(function (f) { return !f.ok; });
   */
  async function check(checkOpts) {
    checkOpts = checkOpts || {};
    if (!Array.isArray(checkOpts.domains) || checkOpts.domains.length === 0) {
      throw new TypeError("posture.check: opts.domains must be a non-empty array of the " +
        "domains this server hosts");
    }
    var out = [];
    var allOk = true;
    var anyUnresolved = false;
    for (var i = 0; i < checkOpts.domains.length; i += 1) {
      // The domain being reported on is an identity: it names the hosted
      // domain the report is about, it is compared against the selector
      // rows the signer keeps, and it becomes the DKIM, DMARC, MTA-STS
      // and TLS-RPT names this looks up. So it is folded through the
      // derivation the identity layer owns rather than through the
      // comparison fold below, which exists for the answers that come
      // back and is a different job.
      //
      // A name that derivation will not take still gets a report. It
      // arrived from an operator asking about it, and a domain that
      // silently produced no findings would read as a zone with nothing
      // wrong in it, which is the opposite of the answer.
      var asked = address.parseDomain(checkOpts.domains[i]);
      var domain = asked.ok ? asked.domain : _normalizeName(checkOpts.domains[i]);
      var findings = [];
      findings.push(await _checkMx(domain));
      findings.push(await _checkSpf(domain));
      findings.push(await _checkDmarc(domain));
      findings = findings.concat(await _checkDkim(domain));
      findings = findings.concat(await _checkMtaSts(domain));
      findings.push(await _checkTlsRpt(domain));
      var domainOk = findings.every(function (f) {
        return f.ok || f.severity !== SEVERITY_REQUIRED;
      });
      var domainUnresolved = findings.some(function (f) { return f.unresolved === true; });
      if (!domainOk) allOk = false;
      if (domainUnresolved) anyUnresolved = true;
      out.push({
        domain: domain, ok: domainOk, unresolved: domainUnresolved, findings: findings,
      });
    }
    if (checkOpts.dane === true) {
      var tlsa = await _checkTlsa();
      if (!tlsa.ok) allOk = false;
      if (tlsa.unresolved === true) anyUnresolved = true;
      out.push({
        domain: hostname, ok: tlsa.ok, unresolved: tlsa.unresolved === true, findings: [tlsa],
      });
    }
    return {
      ok:         allOk,
      unresolved: anyUnresolved,
      checkedAt:  Date.now(),
      hostname:   hostname,
      domains:    out,
    };
  }

  return { check: check };
}

module.exports = {
  create:               create,
  txtLookup:            txtLookup,
  tlsRptEndpoint:       tlsRptEndpoint,
  dmarcRecord:          dmarcRecord,
  withinDnsBudget:      withinDnsBudget,
  DNS_ANSWER_BUDGET_MS:   DNS_ANSWER_BUDGET_MS,
  MAX_DMARC_RECORD_CHARS: MAX_DMARC_RECORD_CHARS,
  MAX_SPF_RECORD_OCTETS:  MAX_SPF_RECORD_OCTETS,
  SEVERITY:             Object.freeze({
    required: SEVERITY_REQUIRED, advised: SEVERITY_ADVISED,
  }),
};
