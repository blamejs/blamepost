// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What `blamepost doctor` says about a zone, checked against what a
 * receiver would actually compute for it.
 *
 * The posture report is the only thing standing between an operator and
 * a silently mis-published record, so its two failure modes cost real
 * mail. A check that passes a zone a receiver refuses leaves the
 * operator confident and undelivered. A check that fails a zone a
 * receiver accepts trains the operator to ignore the report, which
 * costs them the next finding as well.
 *
 * So each claim here is settled against the primitive a receiver runs:
 * the DMARC policy is the one `b.mail.dmarc.evaluate` selects by
 * walking the DNS tree (RFC 9989 §4.10), the SPF record is read with
 * `b.mail.spf.parseRecord`, and a DKIM selector claim is settled by
 * verifying a signature this server made against the record it tells
 * the operator to publish.
 *
 * The other half is the difference between a record that is missing and
 * a lookup that did not complete. They have nothing in common: one is
 * fixed by publishing a record, the other by looking at the resolver.
 * A report that says "lookup failed" for a record nobody published
 * sends the operator to the wrong place.
 *
 * Run standalone: node test/layer-1-state/inbound-posture.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var zone       = require("../helpers/dns-zone");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var postureMod = require("../../lib/mail/posture");

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The assertion that quotes the value that produced the verdict. It is
// the shared one rather than a copy, because a private wrapper that
// formats a failure differently is a failure line nobody can grep for.
var count = helpers.count;

function findingFor(report, domain, record) {
  var entry = report.domains.filter(function (d) { return d.domain === domain; })[0];
  if (!entry) return null;
  return entry.findings.filter(function (f) { return f.record === record; })[0] || null;
}

function findingsFor(report, domain, record) {
  var entry = report.domains.filter(function (d) { return d.domain === domain; })[0];
  if (!entry) return [];
  return entry.findings.filter(function (f) { return f.record === record; });
}

// The records a correct zone carries, so each case can vary one of them
// and leave the rest right.
function baseZone(domain) {
  var z = {};
  z[domain] = { mx: [HOSTNAME], txt: ["v=spf1 mx -all"] };
  z["_dmarc." + domain] = { txt: ["v=DMARC1; p=reject; rua=mailto:dmarc@" + domain] };
  z["_mta-sts." + domain] = { txt: ["v=STSv1; id=20260823T000000"] };
  z["_smtp._tls." + domain] = { txt: ["v=TLSRPTv1; rua=mailto:tls@" + domain] };
  return z;
}

async function checkZone(z, domain, opts) {
  var resolver = zone.resolverOver(z);
  var checker = postureMod.create(Object.assign({
    hostname: HOSTNAME,
    resolver: resolver,
  }, opts || {}));
  var report = await checker.check({ domains: [domain] });
  return { report: report, resolver: resolver };
}

// ---- a missing record is not a broken resolver ------------------------------

// Every one of these names does not exist, which is what a zone looks
// like before the operator has published anything. The resolver signals
// that by refusing the query, and a report that repeats the refusal
// verbatim tells the operator their DNS is broken when their DNS is
// fine and their zone is empty.
async function aMissingRecordReadsAsMissing() {
  var domain = "bare.example.com";
  var z = {};
  z[domain] = { mx: [HOSTNAME], txt: [] };

  var out = await checkZone(z, domain);

  var spf = findingFor(out.report, domain, "SPF");
  count("a domain with no SPF record is told it has no SPF record",
    spf !== null && !spf.ok && /no spf record/i.test(spf.detail), spf && spf.detail);

  var dmarc = findingFor(out.report, domain, "DMARC");
  count("a domain with no DMARC name at all is told it has no DMARC record",
    dmarc !== null && !dmarc.ok && /no dmarc record/i.test(dmarc.detail), dmarc && dmarc.detail);
  count("and the report does not blame the lookup for it",
    dmarc !== null && !/lookup failed/i.test(dmarc.detail), dmarc && dmarc.detail);

  var sts = findingFor(out.report, domain, "MTA-STS TXT");
  count("a domain with no MTA-STS name is told the record is missing",
    sts !== null && !sts.ok && /no mta-sts txt record/i.test(sts.detail), sts && sts.detail);

  var tlsrpt = findingFor(out.report, domain, "TLS-RPT");
  count("a domain with no TLS-RPT name is told the record is missing",
    tlsrpt !== null && !tlsrpt.ok && /no tls-rpt record/i.test(tlsrpt.detail), tlsrpt && tlsrpt.detail);
}

// The zone this file builds answers a name that does not exist the way
// the shipped resolver does, and a fixture that drifted from the real
// one would leave every check above proving that two of this file's own
// mocks agree. The resolver names absence and failure with two separate
// codes, which is what the report reads to tell a missing record from a
// failed lookup, so a refresh that renames either has to be met here
// rather than in production.
//
// It is read out of the vendored source rather than asserted from
// memory because that source is the only place the answer lives, and a
// refresh rewrites it without telling anybody.
function theAbsenceSignalIsStillTheOneTheResolverSends() {
  var source = nodeFs.readFileSync(
    nodePath.join(helpers.VENDOR_ROOT, "lib", "network-dns-resolver.js"), "utf8");
  count("the resolver names a name that does not exist under its own code",
    source.indexOf("\"resolver/nxdomain\"") !== -1,
    "resolver/nxdomain");
  count("and names a lookup that was not answered under a different one",
    source.indexOf("\"resolver/query-failed\"") !== -1,
    "resolver/query-failed");
  count("and the two are still separate, which is the whole distinction",
    source.indexOf("\"resolver/nxdomain-or-error\"") === -1,
    "no single folded code");
}

// A resolver handle that answers only in the two codes the shipped
// resolver raises, so the checks below run against the wire behavior
// rather than against a fixture that agrees with them by construction.
//
// `zone` maps `<name>|<QTYPE>` to an `rrs` array, to ABSENT for a name
// that does not exist, or to UNANSWERED for a query nobody answered.
var ABSENT     = { absent: true };
var UNANSWERED = { unanswered: true };

function resolverInResolverCodes(zone) {
  function query(name, type) {
    var qname = String(name).toLowerCase().replace(/\.$/, "");
    var qtype = String(type).toUpperCase();
    var entry = zone[qname + "|" + qtype];
    if (entry === undefined || entry === ABSENT) {
      // RFC 1035 §4.1.1 RCODE 3, in the shape
      // lib/vendor/blamejs/lib/network-dns-resolver.js raises it.
      var gone = new Error("query: upstream RCODE=3 for " + qname + "/" + qtype);
      gone.code = "resolver/nxdomain";
      throw gone;
    }
    if (entry === UNANSWERED) {
      // Every other non-zero RCODE, a SERVFAIL or a REFUSED.
      var down = new Error("query: upstream RCODE=2 for " + qname + "/" + qtype);
      down.code = "resolver/query-failed";
      throw down;
    }
    return Promise.resolve({
      rrs: entry.slice(), authority: [], additional: [],
      ttl: 60000, fromCache: false, stale: false, validated: true,
    });
  }
  var handle = { query: query };
  ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT", "SRV", "TLSA"].forEach(function (qtype) {
    handle["query" + qtype.charAt(0) + qtype.slice(1).toLowerCase()] =
      function (name) { return query(name, qtype); };
  });
  return handle;
}

function txt(value) { return [{ type: 16, decoded: [value] }]; }

// The two verdicts, driven through the codes the shipped resolver
// actually raises. A classifier that recognizes neither reports every
// unpublished record as a broken resolver, which is the report that
// sends an operator to look at a resolver that is working. A classifier
// that recognizes both as absence is the more expensive mistake: a
// policy nobody could look up reads as a policy nobody published, so
// breaking the query removes the policy.
async function theResolversOwnCodesAreReadCorrectly() {
  var domain = "codes.example.com";
  var z = {};
  z[domain + "|MX"] = [{ type: 15, decoded: { exchange: HOSTNAME, preference: 10 } }];
  z[domain + "|TXT"] = txt("v=spf1 mx -all");
  z["_mta-sts." + domain + "|TXT"] = txt("v=STSv1; id=20260823T000000");
  z["_smtp._tls." + domain + "|TXT"] = txt("v=TLSRPTv1; rua=mailto:tls@" + domain);
  // The one name nobody published, answered the way the resolver
  // answers a name that does not exist.
  z["_dmarc." + domain] = undefined;

  var checker = postureMod.create({
    hostname: HOSTNAME,
    resolver: resolverInResolverCodes(z),
  });
  var report = await checker.check({ domains: [domain] });

  var dmarc = findingFor(report, domain, "DMARC");
  count("a name the resolver says does not exist reads as a record nobody published",
    dmarc !== null && !dmarc.ok && /no dmarc record/i.test(dmarc.detail),
    dmarc && dmarc.detail);
  count("and the operator is not sent to look at a resolver that is working",
    dmarc !== null && !/lookup failed/i.test(dmarc.detail), dmarc && dmarc.detail);

  var spf = findingFor(report, domain, "SPF");
  count("and a record that IS published under the same resolver still passes",
    spf !== null && spf.ok, spf && (spf.detail || spf.found));

  // The other direction, on the same resolver and the same name.
  var broken = {};
  Object.keys(z).forEach(function (k) { broken[k] = z[k]; });
  broken["_dmarc." + domain + "|TXT"] = UNANSWERED;

  var brokenChecker = postureMod.create({
    hostname: HOSTNAME,
    resolver: resolverInResolverCodes(broken),
  });
  var brokenReport = await brokenChecker.check({ domains: [domain] });
  var brokenDmarc = findingFor(brokenReport, domain, "DMARC");
  count("a query nobody answered is reported as a lookup, not as an empty zone",
    brokenDmarc !== null && !brokenDmarc.ok && /lookup/i.test(brokenDmarc.detail),
    brokenDmarc && brokenDmarc.detail);
  count("and never as a policy the operator forgot to publish",
    brokenDmarc !== null && !/^no dmarc record/i.test(brokenDmarc.detail),
    brokenDmarc && brokenDmarc.detail);
}

// A resolver that cannot answer is the other thing, and it has to keep
// reading as the other thing, or the distinction above is worthless.
async function aBrokenLookupReadsAsABrokenLookup() {
  var domain = "unreachable.example.com";
  var z = baseZone(domain);
  z["_dmarc." + domain] = zone.FAILING;

  var out = await checkZone(z, domain);
  var dmarc = findingFor(out.report, domain, "DMARC");
  count("a DMARC name that cannot be resolved is reported as a lookup that failed",
    dmarc !== null && !dmarc.ok && /lookup/i.test(dmarc.detail), dmarc && dmarc.detail);
  count("and is not reported as a record the operator forgot to publish",
    dmarc !== null && !/^no dmarc record/i.test(dmarc.detail), dmarc && dmarc.detail);
}

// ---- a lookup that is accepted and never answered ---------------------------

// A resolver that REJECTS is harmless here: every check above already
// has a verdict for a lookup that failed. A resolver that ACCEPTS the
// question and never answers it is the one shape with no verdict at
// all, and it is ordinary rather than exotic. A nameserver that takes
// the query and drops the response, a firewall that blackholes the
// reply, and a handle an operator wrote around an internal service that
// stopped answering all present exactly that way.
//
// It matters here because the report is not only a command an operator
// watches. The administration surface renders the same result with a
// browser waiting on it, so a check with no bound of its own is a
// request that stays open for as long as the resolver stays silent.
//
// The budget is pinned short so a run reads the bound the checker holds
// rather than waiting out the shipped default.
var STALLED_BUDGET_MS = 750;

// How much longer than the budget an answer may take and still be that
// budget's doing. Wide enough that a loaded runner does not read as a
// missing bound, and it does not need a ceiling above it: nothing else
// ends this wait at all.
var STALLED_SLACK = 8;

// The deadline this file puts on the report itself. Without it an
// unbounded checker does not fail here, it hangs the whole run until
// somebody kills it, and a gate that hangs reports nothing at all.
var REPORT_DEADLINE_MS = STALLED_BUDGET_MS * STALLED_SLACK;

var EXPIRED = { expired: true };

async function _reportWithin(promise, ms) {
  var timer = null;
  var settled = await Promise.race([
    promise,
    new Promise(function (resolve) {
      timer = setTimeout(function () { resolve(EXPIRED); }, ms);
    }),
  ]);
  if (timer !== null) clearTimeout(timer);
  return settled === EXPIRED ? null : settled;
}

// A zone that is correct in every respect except the one name the case
// varies, so a failure below is about the stall and not about the rest.
function pinnedBaseZone(domain) {
  var z = {};
  z[domain + "|MX"]  = [{ type: 15, decoded: { exchange: HOSTNAME, preference: 10 } }];
  z[domain + "|TXT"] = txt("v=spf1 mx -all");
  z["_dmarc." + domain + "|TXT"]     = txt("v=DMARC1; p=reject; rua=mailto:dmarc@" + domain);
  z["_mta-sts." + domain + "|TXT"]   = txt("v=STSv1; id=20260823T000000");
  z["_smtp._tls." + domain + "|TXT"] = txt("v=TLSRPTv1; rua=mailto:tls@" + domain);
  return z;
}

// The TXT reader, which is every policy record this report asks about:
// the SPF record, the DMARC record, the selector keys, the MTA-STS
// pointer and the TLS-RPT endpoint.
async function aStalledPolicyLookupIsAnsweredRatherThanWaitedOn() {
  var domain = "stalled.example.com";
  var z = pinnedBaseZone(domain);
  z["_dmarc." + domain + "|TXT"] = zone.HANGING;

  var checker = postureMod.create({
    hostname:          HOSTNAME,
    resolver:          zone.pinnedResolverOver(z),
    dnsAnswerBudgetMs: STALLED_BUDGET_MS,
  });

  var askedAt = Date.now();
  var report  = await _reportWithin(checker.check({ domains: [domain] }), REPORT_DEADLINE_MS);
  var waited  = Date.now() - askedAt;

  count("a report whose resolver never answers still finishes, rather than holding the " +
    "operator and the request that asked for it open indefinitely",
    report !== null, waited + "ms waited, deadline " + REPORT_DEADLINE_MS + "ms");
  if (report === null) return;

  count("and it finishes inside the budget the checker holds",
    waited < REPORT_DEADLINE_MS,
    waited + "ms waited on a budget of " + STALLED_BUDGET_MS + "ms");

  var dmarc = findingFor(report, domain, "DMARC");
  count("the record whose lookup never came back is reported as one this server could " +
    "not find out about",
    dmarc !== null && dmarc.unresolved === true, dmarc && JSON.stringify(dmarc));
  // The whole hazard in one assertion. A stalled query read as an empty
  // zone lets whoever can stall the query delete the policy: the report
  // would tell the operator to publish a record that is already there,
  // and the same reading on the inbound path accepts forged mail.
  count("and never as a record the operator forgot to publish",
    dmarc !== null && !/no dmarc record/i.test(dmarc.detail || ""), dmarc && dmarc.detail);
  count("and the detail sends the operator to the resolver rather than to the zone",
    dmarc !== null && /resolver/i.test(dmarc.detail || ""), dmarc && dmarc.detail);

  // The half a careless bound breaks: one silent name must not decide
  // the rest of the report. The records asked before the stall keep
  // their verdicts, and the records asked after it are still asked.
  var mx = findingFor(report, domain, "MX");
  var spf = findingFor(report, domain, "SPF");
  count("the records read before the stall keep the verdicts the zone earned",
    mx !== null && mx.ok && spf !== null && spf.ok,
    JSON.stringify({ mx: mx && mx.ok, spf: spf && spf.ok }));
  count("and the records after it are still checked, so one silent name costs one finding",
    findingFor(report, domain, "MTA-STS TXT") !== null &&
    findingFor(report, domain, "TLS-RPT") !== null,
    (findingFor(report, domain, "TLS-RPT") || {}).record + "");
  count("a report carrying a record nobody could read does not claim the server is ready",
    report.ok === false, String(report.ok));
}

// The other two readers. The TXT reader is composed from one place and
// the MX and TLSA readers are not, so a bound proven on TXT proves
// nothing about either of them.
async function aStalledMxOrTlsaLookupIsBoundedToo() {
  var mxDomain = "stalled-mx.example.com";
  var mxZone = pinnedBaseZone(mxDomain);
  mxZone[mxDomain + "|MX"] = zone.HANGING;

  var mxChecker = postureMod.create({
    hostname:          HOSTNAME,
    resolver:          zone.pinnedResolverOver(mxZone),
    dnsAnswerBudgetMs: STALLED_BUDGET_MS,
  });
  var mxReport = await _reportWithin(
    mxChecker.check({ domains: [mxDomain] }), REPORT_DEADLINE_MS);
  count("an MX lookup that never answers is bounded as well",
    mxReport !== null, "deadline " + REPORT_DEADLINE_MS + "ms");
  var mx = mxReport && findingFor(mxReport, mxDomain, "MX");
  count("and reads as a record this server could not find out about",
    mx !== null && mx !== undefined && mx.unresolved === true, mx && JSON.stringify(mx));
  count("rather than as a domain that publishes no MX at all",
    mx !== null && mx !== undefined && !/publishes no mx/i.test(mx.detail || ""),
    mx && mx.detail);

  var tlsaDomain = "stalled-tlsa.example.com";
  var tlsaZone = pinnedBaseZone(tlsaDomain);
  tlsaZone["_25._tcp." + HOSTNAME + "|TLSA"] = zone.HANGING;

  var tlsaChecker = postureMod.create({
    hostname:          HOSTNAME,
    resolver:          zone.pinnedResolverOver(tlsaZone),
    dnsAnswerBudgetMs: STALLED_BUDGET_MS,
  });
  var tlsaReport = await _reportWithin(
    tlsaChecker.check({ domains: [tlsaDomain], dane: true }), REPORT_DEADLINE_MS);
  count("a TLSA lookup that never answers is bounded as well",
    tlsaReport !== null, "deadline " + REPORT_DEADLINE_MS + "ms");
  var tlsa = tlsaReport && findingFor(tlsaReport, HOSTNAME, "TLSA");
  count("and reads as a record this server could not find out about",
    tlsa !== null && tlsa !== undefined && tlsa.unresolved === true, tlsa && JSON.stringify(tlsa));
  count("rather than as DANE being asked for with no record behind it",
    tlsa !== null && tlsa !== undefined && !/no tlsa record/i.test(tlsa.detail || ""),
    tlsa && tlsa.detail);
}

// The bound itself, and the code it ends a stalled question with.
//
// That code is a frozen contract rather than an implementation detail:
// it is what tells a lookup that ran out of time apart from a name that
// publishes nothing, and every classifier in the tree is written
// against it. A budget that rejected under one of the absence codes
// would make a silent resolver look like an empty zone, which is the
// whole hazard this bound exists inside of.
async function theBudgetRejectsAStalledQuestionAsAFailure() {
  var never = new Promise(function () { /* never settles, by design */ });
  var code = null;
  try {
    await postureMod.withinDnsBudget(never, 50, "a question nobody answers");
  } catch (err) { code = (err && err.code) || null; }
  count("a question the handle never answers ends as a rejection rather than a wait",
    code !== null, String(code));
  count("and it carries the timeout code rather than one of the absence codes",
    code === "async/timeout", String(code));
  count("which is not a code any absence classifier accepts",
    ["ENODATA", "ENOTFOUND", "resolver/nxdomain"].indexOf(code) === -1, String(code));

  var passed = await postureMod.withinDnsBudget(Promise.resolve("answered"), 5000, "answered");
  count("a question that is answered inside the budget passes its answer through",
    passed === "answered", String(passed));
}

// A budget is not a setting with an off position. The value that would
// turn it off is the behavior it exists to end, so it is refused where
// every other bad opt is refused: at construction, where the operator
// finds out at boot rather than at the report that never came back.
function aBudgetHasNoOffPosition() {
  [0, -1, "45000", NaN, Infinity, null].forEach(function (value) {
    var threw = false;
    try {
      postureMod.create({ hostname: HOSTNAME, dnsAnswerBudgetMs: value });
    } catch (_e) { threw = true; }
    count("a DNS budget of " + JSON.stringify(value) + " is refused at construction",
      threw, JSON.stringify(value));
  });
}

// ---- the DMARC policy is the one that applies -------------------------------

// A hosted subdomain need not publish its own record. RFC 9989 §4.10
// walks the tree from the sending domain upward, so a policy at the
// parent governs the subdomain through its `sp=` tag. Reporting the
// subdomain as unprotected is telling the operator to fix a zone that
// is already right.
async function aSubdomainCoveredByItsParentIsNotReportedUnprotected() {
  var domain = "mail.example.com";
  var z = baseZone(domain);
  delete z["_dmarc." + domain];
  z["_dmarc.example.com"] = { txt: ["v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com"] };

  var out = await checkZone(z, domain);
  var dmarc = findingFor(out.report, domain, "DMARC");
  count("a subdomain covered by its parent's policy passes the DMARC check",
    dmarc !== null && dmarc.ok, dmarc && (dmarc.detail || dmarc.found));
  count("and the report names the domain the policy came from",
    dmarc !== null && /example\.com/.test(String(dmarc.name || "") + String(dmarc.found || "")),
    dmarc && JSON.stringify({ name: dmarc.name, found: dmarc.found }));
}

// The walk is not an excuse to pass everything: a parent policy of
// p=none protects the subdomain exactly as little as it protects the
// parent, and has to be reported that way.
async function aWeakInheritedPolicyStillFails() {
  var domain = "lists.example.net";
  var z = baseZone(domain);
  delete z["_dmarc." + domain];
  z["_dmarc.example.net"] = { txt: ["v=DMARC1; p=none; rua=mailto:dmarc@example.net"] };

  var out = await checkZone(z, domain);
  var dmarc = findingFor(out.report, domain, "DMARC");
  count("an inherited p=none is still reported as too weak",
    dmarc !== null && !dmarc.ok, dmarc && dmarc.detail);
  count("and the report says the policy came from the parent rather than from here",
    dmarc !== null && /example\.net/.test(String(dmarc.name || "")), dmarc && String(dmarc.name));
}

// The walk reaches past the operator's own names as well. A policy the
// operator of a public suffix publishes does govern every name
// registered under it, and leaning on it is still not a posture this
// server calls done: it belongs to somebody the operator has no
// relationship with, and RFC 9989 §4.10.2 narrows relaxed alignment to
// the boundary such a record declares.
async function aPublicSuffixPolicyDoesNotCountAsThisDomainsOwn() {
  var domain = "tenant.platform.example";
  var z = baseZone(domain);
  delete z["_dmarc." + domain];
  z["_dmarc.platform.example"] = { txt: ["v=DMARC1; p=reject; psd=y; rua=mailto:abuse@platform.example"] };

  var out = await checkZone(z, domain);
  var dmarc = findingFor(out.report, domain, "DMARC");
  count("a policy published by the operator of the suffix does not pass this domain",
    dmarc !== null && !dmarc.ok, dmarc && dmarc.detail);
  count("and the report says whose policy it is and where to publish one",
    dmarc !== null && /_dmarc\.tenant\.platform\.example/.test(dmarc.detail || ""),
    dmarc && dmarc.detail);
}

// A record published twice at the same name is the one case the tree
// walk reads as no record at all, and the operator needs to be told
// which of the two things happened.
async function twoDmarcRecordsAreNamedAsTwo() {
  var domain = "doubled.example.com";
  var z = baseZone(domain);
  z["_dmarc." + domain] = { txt: [
    "v=DMARC1; p=reject; rua=mailto:one@" + domain,
    "v=DMARC1; p=quarantine; rua=mailto:two@" + domain,
  ] };

  var out = await checkZone(z, domain);
  var dmarc = findingFor(out.report, domain, "DMARC");
  count("two DMARC records at one name is reported as two",
    dmarc !== null && !dmarc.ok && /2 dmarc records|two dmarc/i.test(dmarc.detail),
    dmarc && dmarc.detail);
}

// ---- the SPF record is read the way a receiver reads it ---------------------

// RFC 7208 §6 modifiers are name=value pairs that may sit anywhere in
// the record, including after the `all` mechanism. A check that only
// looks at the last token on the line reports a correct record as
// having no policy at all.
async function anSpfRecordWithAModifierAfterAllPasses() {
  var domain = "explained.example.com";
  var z = baseZone(domain);
  z[domain] = { mx: [HOSTNAME], txt: ["v=spf1 mx -all exp=why." + domain] };

  var out = await checkZone(z, domain);
  var spf = findingFor(out.report, domain, "SPF");
  count("a record ending in -all followed by an exp= modifier passes",
    spf !== null && spf.ok, spf && spf.detail);
}

// A record whose policy lives in a redirect= modifier has no `all` of
// its own by design, and the advice for it is not "change the ending to
// -all", which would delete the policy it does have.
async function anSpfRecordThatRedirectsIsDescribedAsRedirecting() {
  var domain = "redirected.example.com";
  var z = baseZone(domain);
  z[domain] = { mx: [HOSTNAME], txt: ["v=spf1 mx redirect=_spf.provider.example"] };

  var out = await checkZone(z, domain);
  var spf = findingFor(out.report, domain, "SPF");
  count("a record whose policy is in a redirect= is reported as redirecting",
    spf !== null && /redirect/i.test(spf.detail || ""), spf && spf.detail);
  count("and it names where the policy actually lives",
    spf !== null && /_spf\.provider\.example/.test(spf.detail || ""), spf && spf.detail);
}

// The posture this project ships refuses a soft ending, and that has to
// keep holding whichever way the record is written.
async function aSoftFailEndingStillFails() {
  var domain = "soft.example.com";
  var z = baseZone(domain);
  z[domain] = { mx: [HOSTNAME], txt: ["v=spf1 mx ~all"] };

  var out = await checkZone(z, domain);
  var spf = findingFor(out.report, domain, "SPF");
  count("a record ending in ~all is refused",
    spf !== null && !spf.ok, spf && spf.detail);
  count("and the refusal names -all as the fix",
    spf !== null && /-all/.test(spf.detail || ""), spf && spf.detail);
}

// ---- the selector record and the key that signs with it ---------------------

// This is the check the whole module exists for. A selector record that
// has drifted from its private key is invisible from the sending side,
// so the report has to catch it, and the test has to prove the drift by
// failing a real signature rather than by comparing two strings.
async function aDriftedSelectorRecordIsCaughtAndProvenByASignature(dkim, identity) {
  var domain = "selector-drift.example.com";
  await identity.domains.add({ domain: domain });
  await dkim.generate({ domain: domain, selector: "bpdrift" });
  var published = dkim.dnsRecords(domain);

  // The zone as the operator was told to publish it.
  var good = baseZone(domain);
  published.forEach(function (r) { good[r.dnsName] = { txt: [r.dnsTxtValue] }; });
  var okReport = (await checkZone(good, domain, { dkim: dkim })).report;
  count("a selector published exactly as instructed passes",
    findingsFor(okReport, domain, "DKIM").every(function (f) { return f.ok; }),
    findingsFor(okReport, domain, "DKIM").map(function (f) { return f.name + ":" + f.ok; }).join(","));

  // The same zone with one selector's key truncated the way a DNS
  // provider that split the value badly would leave it.
  var drifted = baseZone(domain);
  published.forEach(function (r) {
    var value = r.algorithm === "ed25519" ? r.dnsTxtValue.slice(0, r.dnsTxtValue.length - 8) : r.dnsTxtValue;
    drifted[r.dnsName] = { txt: [value] };
  });
  var driftReport = (await checkZone(drifted, domain, { dkim: dkim })).report;
  var driftFindings = findingsFor(driftReport, domain, "DKIM");
  count("a selector whose published key has been truncated is reported",
    driftFindings.some(function (f) { return !f.ok; }),
    driftFindings.map(function (f) { return f.name + ":" + f.ok; }).join(","));

  // And the drift is real: mail this server signs does not verify
  // against the zone as published.
  var signed = dkim.signerFor(domain).sign(zone.messageFrom(domain, "drifted"));
  var results = await zone.verifyAgainst(signed, published.map(function (r) {
    return {
      dnsName:     r.dnsName,
      dnsTxtValue: r.algorithm === "ed25519"
        ? r.dnsTxtValue.slice(0, r.dnsTxtValue.length - 8)
        : r.dnsTxtValue,
    };
  }));
  count("and a message signed here does not verify against the drifted record",
    !zone.allPass(results), zone.summarize(results));

  // A selector name carrying two records is a receiver coin toss, and
  // the one it picks may not be the one this server signs with.
  var doubled = baseZone(domain);
  published.forEach(function (r) { doubled[r.dnsName] = { txt: [r.dnsTxtValue] }; });
  doubled[published[0].dnsName] = {
    txt: [published[0].dnsTxtValue, "v=DKIM1; k=ed25519; p=" + "A".repeat(43) + "="],
  };
  var doubledReport = (await checkZone(doubled, domain, { dkim: dkim })).report;
  count("a selector name publishing two records is reported",
    findingsFor(doubledReport, domain, "DKIM").some(function (f) {
      return !f.ok && f.name === published[0].dnsName;
    }),
    findingsFor(doubledReport, domain, "DKIM").map(function (f) { return f.name + ":" + f.ok; }).join(","));

  // An empty p= revokes the selector, which is a different failure from
  // a value that merely disagrees.
  var revoked = baseZone(domain);
  published.forEach(function (r) { revoked[r.dnsName] = { txt: [r.dnsTxtValue] }; });
  revoked[published[0].dnsName] = { txt: ["v=DKIM1; k=ed25519; p="] };
  var revokedReport = (await checkZone(revoked, domain, { dkim: dkim })).report;
  var revokedFinding = findingsFor(revokedReport, domain, "DKIM").filter(function (f) {
    return f.name === published[0].dnsName;
  })[0];
  count("a selector published with an empty key is reported as revoked",
    revokedFinding && !revokedFinding.ok && /revoke/i.test(revokedFinding.detail),
    revokedFinding && revokedFinding.detail);
}

// ---- the operator's resolver is the one that answers ------------------------

// The operator pins a resolver because the host's is not trusted. Every
// lookup the report makes has to go through it, including the one the
// MTA-STS policy fetch makes on its own behalf: a spoofed _mta-sts TXT
// record downgrades mail TLS, so it is the last lookup that should be
// allowed to take the unpinned path.
async function everyLookupGoesThroughThePinnedResolver() {
  var domain = "pinned.example.com";
  var z = baseZone(domain);

  var out = await checkZone(z, domain);
  var asked = out.resolver.calls.join(" ");
  count("the MX lookup went to the pinned resolver",
    asked.indexOf("MX " + domain) !== -1, asked);
  count("the SPF lookup went to the pinned resolver",
    asked.indexOf("TXT " + domain) !== -1, asked);
  count("the DMARC lookup went to the pinned resolver",
    asked.indexOf("TXT _dmarc." + domain) !== -1, asked);

  var stsLookups = out.resolver.calls.filter(function (c) {
    return c === "TXT _mta-sts." + domain;
  }).length;
  count("and so did the one the MTA-STS policy fetch makes for itself",
    stsLookups >= 2, stsLookups + " lookup(s) for _mta-sts." + domain);
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("inbound-posture");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  try {
    theAbsenceSignalIsStillTheOneTheResolverSends();
    await theResolversOwnCodesAreReadCorrectly();
    await aMissingRecordReadsAsMissing();
    await aBrokenLookupReadsAsABrokenLookup();
    await theBudgetRejectsAStalledQuestionAsAFailure();
    aBudgetHasNoOffPosition();
    await aStalledPolicyLookupIsAnsweredRatherThanWaitedOn();
    await aStalledMxOrTlsaLookupIsBoundedToo();
    await aSubdomainCoveredByItsParentIsNotReportedUnprotected();
    await aWeakInheritedPolicyStillFails();
    await aPublicSuffixPolicyDoesNotCountAsThisDomainsOwn();
    await twoDmarcRecordsAreNamedAsTwo();
    await anSpfRecordWithAModifierAfterAllPasses();
    await anSpfRecordThatRedirectsIsDescribedAsRedirecting();
    await aSoftFailEndingStillFails();
    await everyLookupGoesThroughThePinnedResolver();

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    identity = await store.open(cfg);
    var dkim = require("../../lib/mail/dkim").create({
      store:   identity,
      dataDir: cfg.paths.dataDir,
    });
    await aDriftedSelectorRecordIsCaughtAndProvenByASignature(dkim, identity);

    return helpers.getChecks();
  } finally {
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "inbound-posture", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
