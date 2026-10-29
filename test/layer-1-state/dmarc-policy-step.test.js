// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether a hosted domain's evidence carries a DMARC policy step, driven
 * over a real volume with real reports on it.
 *
 * Tokens exercised here:
 *
 *   blamepost.mail.dmarcPolicy.create
 *   blamepost.mail.dmarcPolicy.evaluate
 *   blamepost.mail.dmarcPolicy.markSource
 *   blamepost.mail.dmarcPolicy.markings
 *
 * The rules are written as the failures they stop:
 *
 *   - a report this server did not authenticate carries no volume, no
 *     reporting organization, no reported day and no failing source into
 *     any threshold, so nobody who can send mail to a published reporting
 *     address can step a policy;
 *   - every threshold is actually read, which is measured by moving one
 *     input across each boundary and watching the verdict flip;
 *   - a sending address failing on both identifiers over the floor blocks
 *     the step until an operator writes down what it is;
 *   - a claim that a source is theirs and fixed is contradicted by the
 *     reporters when it keeps failing, and a claim that it is not theirs
 *     is not;
 *   - a lookup that did not complete is never read as a domain that
 *     publishes nothing;
 *   - and stepping down is offered on every reading, including the ones
 *     that refuse to step up.
 *
 * Real database, real sealed columns, real vault, real audit chain,
 * temporary data directory. The zone is a table and the DKIM selector
 * inventory is a stand-in, because what is under test is the decision
 * rather than either of those.
 *
 * Run standalone: node test/layer-1-state/dmarc-policy-step.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var b          = require("../../lib/vendor/blamejs");
var dnsZone    = require("../helpers/dns-zone");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var reports    = require("../../lib/store/reports");
var tables     = require("../../lib/store/tables");
var postureMod = require("../../lib/mail/posture");
var policyMod  = require("../../lib/mail/dmarc-policy");

var count = helpers.count;

var HOSTNAME         = "mx.example.com";
var RUA              = "dmarc-reports@example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var DAY_MS = 86400000;

// The moment every seeded window is measured back from. Taken once so the
// arithmetic below is about offsets rather than about what the clock said
// between two ingests.
var NOW = Date.now();

// The selector record the stand-in inventory publishes and the zone
// carries, so the posture reading finds the key this server would sign
// with. Its bytes are not under test here; that a published record
// matching one is what the step asks for is.
var DKIM_TXT = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

var ORGS = ["alpha.example", "beta.example", "gamma.example"];

var ALIGNED_SOURCE = "203.0.113.10";

var UNREVIEWED = { evidence: "carrier-dmarc-not-pass" };
var AUTHENTIC  = { evidence: tables.REPORT_EVIDENCE_VERIFIED };

// Every domain this run seeds, filled as the fixtures build so the store
// handle answers the hosted question for all of them.
var hosted = {};

// The zone every posture reading is taken over, filled the same way.
var zone = {};

// ---- fixtures --------------------------------------------------------------

function dayStart(offset) {
  return (Math.floor(NOW / DAY_MS) + offset) * DAY_MS;
}

function xmlRecord(sourceIp, messages, aligned) {
  var verdict = aligned ? "pass" : "fail";
  return "  <record>\n" +
    "    <row><source_ip>" + sourceIp + "</source_ip><count>" + messages + "</count>\n" +
    "      <policy_evaluated><disposition>none</disposition>" +
    "<dkim>" + verdict + "</dkim><spf>" + verdict + "</spf></policy_evaluated>\n" +
    "    </row>\n" +
    "    <identifiers><header_from>example.com</header_from></identifiers>\n" +
    "  </record>\n";
}

function aggregateXml(opts) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" +
    "<feedback>\n" +
    "  <report_metadata>\n" +
    "    <org_name>" + opts.org + "</org_name>\n" +
    "    <email>dmarc-noreply@" + opts.org + "</email>\n" +
    "    <report_id>" + opts.reportId + "</report_id>\n" +
    "    <date_range><begin>" + Math.floor(opts.begin / 1000) + "</begin>" +
    "<end>" + Math.floor(opts.end / 1000) + "</end></date_range>\n" +
    "  </report_metadata>\n" +
    "  <policy_published>\n" +
    "    <domain>" + opts.domain + "</domain><adkim>r</adkim><aspf>r</aspf>\n" +
    "    <p>none</p><pct>100</pct>\n" +
    "  </policy_published>\n" +
    opts.records.join("") +
    "</feedback>\n";
}

// One hosted domain with reports on it, and the zone entries a posture
// reading of it needs.
//
// `dayOffsets` are the days a report covers, counted back from the moment
// above. `orgs` is how many reporting organizations answer on each of
// them. `failing` names the sending addresses that failed both
// identifiers and how many messages each failed on per day.
function seed(handle, opts) {
  var domain = opts.domain;
  hosted[domain] = true;

  var record = opts.record === undefined
    ? "v=DMARC1; p=none; rua=mailto:" + RUA : opts.record;
  zone[domain] = { txt: [opts.spf === undefined ? "v=spf1 -all" : opts.spf],
    mx: [HOSTNAME] };
  if (record !== null) zone["_dmarc." + domain] = { txt: [record] };
  else zone["_dmarc." + domain] = { txt: [] };
  if (opts.dkimPublished !== false) {
    zone["sel1._domainkey." + domain] = { txt: [DKIM_TXT] };
  }

  var evidence = opts.evidence === undefined ? AUTHENTIC : opts.evidence;
  var orgs = ORGS.slice(0, opts.orgs === undefined ? 2 : opts.orgs);
  var failing = opts.failing || [];

  for (var d = 0; d < opts.dayOffsets.length; d += 1) {
    var offset = opts.dayOffsets[d];
    var begin  = dayStart(offset);
    var end    = begin + DAY_MS - 1000;
    for (var o = 0; o < orgs.length; o += 1) {
      var rows = [xmlRecord(ALIGNED_SOURCE, opts.aligned === undefined ? 40 : opts.aligned,
        true)];
      if (o === 0) {
        for (var f = 0; f < failing.length; f += 1) {
          if (failing[f].onDays && failing[f].onDays.indexOf(offset) === -1) continue;
          rows.push(xmlRecord(failing[f].ip, failing[f].perDay, false));
        }
      }
      handle.ingestAggregate(aggregateXml({
        org: orgs[o], reportId: domain + "-" + offset + "-" + o,
        domain: domain, begin: begin, end: end, records: rows,
      }), { now: begin + DAY_MS, evidence: evidence.evidence, authenticatedAs: orgs[o] });
    }
  }
}

// ---- the handles -----------------------------------------------------------

function dkimStandIn() {
  return {
    dnsRecords: async function (domain) {
      return [{ dnsName: "sel1._domainkey." + domain, dnsTxtValue: DKIM_TXT,
        state: "active" }];
    },
  };
}

function policyOver() {
  var resolver = dnsZone.resolverOver(zone);
  return policyMod.create({
    store:   reports.create({
      aggregateRetentionMs: 400 * DAY_MS,
      forensicRetentionMs:  DAY_MS,
      hostedDomain: function (name) { return hosted[name] === true; },
    }),
    posture: postureMod.create({
      hostname: HOSTNAME, resolver: resolver, dkim: dkimStandIn(),
    }),
    dnsLookup:        postureMod.txtLookup(resolver),
    reportingAddress: RUA,
  });
}

// The same stepper over a store whose answer about failing senders has
// been altered on the way out. Everything else stays real, so what is
// under test is what the step does with an answer it cannot judge over,
// rather than a second implementation of the reading.
function policyOverSourceAnswer(alter) {
  var resolver = dnsZone.resolverOver(zone);
  var real = reports.create({
    aggregateRetentionMs: 400 * DAY_MS,
    forensicRetentionMs:  DAY_MS,
    hostedDomain: function (name) { return hosted[name] === true; },
  });
  var altered = Object.assign({}, real, {
    failingSources: async function (opts) { return alter(await real.failingSources(opts)); },
  });
  return policyMod.create({
    store:   altered,
    posture: postureMod.create({
      hostname: HOSTNAME, resolver: resolver, dkim: dkimStandIn(),
    }),
    dnsLookup:        postureMod.txtLookup(resolver),
    reportingAddress: RUA,
  });
}

// The days a domain is reported on for a quarantine step that clears.
//
// The day exactly one window-length back is deliberately not among them.
// A window opens at the moment the reading is taken minus its length, and
// a report covering that same day falls on one side of it or the other
// depending on the time of day the run happens at. A fixture that lands
// there passes in the morning and fails in the evening, which is the one
// failure a test can have that nothing about it looks wrong from.
//
// So the thirteen days behind the reading carry a report each, and the
// span the rule measures is answered by one report far enough back to be
// unambiguously outside the window.
function fullFortnight() {
  var days = [-20];
  for (var i = 13; i >= 1; i -= 1) days.push(-i);
  return days;
}

// The days behind and ahead of the reading that a reject step is measured
// over. Its window is thirty days wide and the readings below are taken
// at two moments a fortnight apart, so the run has to be wide enough to
// fill the window at both of them.
function fullMonth() {
  var days = [-40];
  for (var i = -15; i <= 15; i += 1) days.push(i);
  return days;
}

// The policy states this server has recorded for one domain, oldest
// first, as `level@percent`. The trail stamps each row with its own
// monotonic clock, so a case cannot place two observations days apart;
// it reads the states instead, because the hold is measured from the
// newest run of one state.
async function observedStates(domain) {
  var rows = await b.audit.query({
    action: "blamepost.mail.dmarc_policy.policy_observed", resourceId: domain,
    order: "desc", limit: 1000,
  });
  return rows.filter(function (row) { return row.resourceId === domain; }).reverse()
    .map(function (row) {
    var detail = JSON.parse(row.metadata || "{}");
    return detail.level + "@" + (typeof detail.percent === "number" ? detail.percent : 100);
  });
}

async function verdictFor(domain, at) {
  return policyOver().evaluate({ domain: domain, now: at === undefined ? NOW : at });
}

// One boundary, measured from both sides. `shy` is the seed that falls
// one step short and `met` is the seed that reaches it, and the test is
// that the code the shy side answers with is gone on the other. A
// threshold that is declared and never read passes the first half and
// fails here.
async function boundary(label, code, shy, met) {
  var below = await verdictFor(shy);
  var above = await verdictFor(met);
  count(label + ": one step short refuses with " + code,
    below.reason === code, below.reason + " " + below.detail);
  count(label + ": one step across, that rule no longer refuses",
    above.reason !== code, above.reason + " " + above.detail);
}

// ---- what a step rests on --------------------------------------------------

async function evidenceNobodyAuthenticatedRaisesNothing(handle) {
  // The same fourteen days, the same two organizations and five times the
  // volume, in reports whose carrier this server did not authenticate.
  // Anybody who can send mail to a published reporting address can write
  // exactly this.
  seed(handle, {
    domain: "forged.example", dayOffsets: fullFortnight(), orgs: 3, aligned: 200,
    evidence: UNREVIEWED,
  });
  var forged = await verdictFor("forged.example");
  count("a domain reported on only by reports nobody authenticated has no evidence",
    forged.reason === policyMod.CODES.evidenceAbsent, forged.reason + " " + forged.detail);
  count("and none of that volume reached the counting",
    forged.evidence === null || forged.evidence.counted === 0,
    JSON.stringify(forged.evidence));

  // The same domain, now also carrying real evidence that is one step
  // short of the volume floor. If the unauthenticated volume were
  // reachable it would carry this over the line five times about.
  seed(handle, {
    domain: "forged.example", dayOffsets: [-99], orgs: 2, aligned: 40,
  });
  var mixed = await verdictFor("forged.example");
  count("counted evidence beside it is measured on its own",
    mixed.evidence !== null && mixed.evidence.counted === 0,
    JSON.stringify(mixed.evidence));
  count("and the forged volume raises no threshold it is not part of",
    mixed.ok === false, mixed.reason + " " + mixed.detail);
}

async function theWholeSetOfRulesClears(handle) {
  seed(handle, { domain: "clear.example", dayOffsets: fullFortnight(), orgs: 2 });
  var verdict = await verdictFor("clear.example");
  count("a domain meeting every rule is offered the step to quarantine",
    verdict.ok === true && verdict.next === "quarantine",
    verdict.reason + " " + verdict.detail);
  count("and it is handed the exact record to publish",
    verdict.records.quarantine === "v=DMARC1; p=quarantine; rua=mailto:" + RUA,
    verdict.records.quarantine);
  count("the evidence it cleared on is published beside the verdict",
    verdict.evidence.counted === 13 * 2 * 40 && verdict.evidence.reportDays === 13 &&
    verdict.evidence.organizations === 2, JSON.stringify(verdict.evidence));
  count("every check it ran is answered rather than only the first failure",
    verdict.checks.length >= 10 && verdict.checks.every(function (one) { return one.ok; }),
    JSON.stringify(verdict.checks.map(function (one) { return one.name; })));
}

// ---- the boundaries --------------------------------------------------------

async function everyThresholdIsActuallyRead(handle) {
  // Thirteen days of span against fourteen. The window is the same on
  // both sides; what moves is how far back the earliest report reaches.
  var inWindow = fullFortnight().slice(1);
  seed(handle, { domain: "span13.example", dayOffsets: inWindow, orgs: 2 });
  seed(handle, { domain: "span14.example", dayOffsets: [-14].concat(inWindow), orgs: 2 });
  await boundary("the span the evidence covers", policyMod.CODES.evidenceYoung,
    "span13.example", "span14.example");

  // Six reported days inside the window against seven, with the span
  // itself satisfied on both sides by a report outside it.
  seed(handle, { domain: "days6.example", orgs: 2,
    dayOffsets: [-20, -6, -5, -4, -3, -2, -1] });
  seed(handle, { domain: "days7.example", orgs: 2,
    dayOffsets: [-20, -7, -6, -5, -4, -3, -2, -1] });
  await boundary("the days inside the window that carry a report",
    policyMod.CODES.evidenceSparse, "days6.example", "days7.example");

  seed(handle, { domain: "org1.example", dayOffsets: fullFortnight(), orgs: 1,
    aligned: 80 });
  seed(handle, { domain: "org2.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 40 });
  await boundary("the reporting organizations that answered",
    policyMod.CODES.reportersThin, "org1.example", "org2.example");

  // Seventy eight counted messages against a hundred and four, either
  // side of the floor a share is measured over.
  seed(handle, { domain: "vol78.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 3 });
  seed(handle, { domain: "vol104.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 4 });
  var shy = await verdictFor("vol78.example");
  var met = await verdictFor("vol104.example");
  count("the volume a threshold is measured over: 78 messages is short of the floor",
    shy.reason === policyMod.CODES.volumeThin, shy.reason + " " + shy.detail);
  count("the volume a threshold is measured over: 104 messages reaches it",
    met.reason !== policyMod.CODES.volumeThin, met.reason + " " + met.detail);

  // Alignment either side of ninety eight percent, over a volume well
  // past the floor. Thirteen days, two organizations, fifty aligned each,
  // which is 1300 counted before the failing source is added: 39 failing
  // messages reads as 97.09 percent and 3 reads as 99.77.
  seed(handle, { domain: "align97.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 50, failing: [{ ip: "198.51.100.31", perDay: 3 }] });
  seed(handle, { domain: "align98.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 50, failing: [{ ip: "198.51.100.32", perDay: 3, onDays: [-1] }] });
  var low = await verdictFor("align97.example");
  count("alignment below the threshold refuses",
    low.reason === policyMod.CODES.alignmentShort, low.reason + " " + low.detail);
  count("and the share it refused on is the counted one",
    low.evidence.alignedPercent < 98, String(low.evidence.alignedPercent));
  var high = await verdictFor("align98.example");
  count("alignment above the threshold does not refuse on alignment",
    high.reason !== policyMod.CODES.alignmentShort, high.reason + " " + high.detail);
  count("and the share it read is above the threshold",
    high.evidence.alignedPercent >= 98, String(high.evidence.alignedPercent));

  // A hole in the middle of the window: four days against three.
  seed(handle, { domain: "gap4.example", orgs: 2,
    dayOffsets: [-20, -13, -12, -11, -10, -9, -8, -3, -2, -1] });
  seed(handle, { domain: "gap3.example", orgs: 2,
    dayOffsets: [-20, -13, -12, -11, -10, -9, -8, -4, -3, -2, -1] });
  await boundary("the largest run of days with nothing in them",
    policyMod.CODES.evidenceGapped, "gap4.example", "gap3.example");

  // A silence at the end of the window: four days against three.
  seed(handle, { domain: "stale4.example", orgs: 2,
    dayOffsets: [-20, -13, -12, -11, -10, -9, -8, -7, -6, -5, -4] });
  seed(handle, { domain: "stale3.example", orgs: 2,
    dayOffsets: [-20, -13, -12, -11, -10, -9, -8, -7, -6, -5, -4, -3] });
  await boundary("the silence at the end of the window",
    policyMod.CODES.evidenceStale, "stale4.example", "stale3.example");
}

async function thePostureTheRulesAskForIsRead(handle) {
  seed(handle, { domain: "spfsoft.example", dayOffsets: fullFortnight(), orgs: 2,
    spf: "v=spf1 ~all" });
  var soft = await verdictFor("spfsoft.example");
  count("a domain whose SPF record asks receivers to accept forgeries is refused",
    soft.reason === policyMod.CODES.spfNotStrict, soft.reason + " " + soft.detail);

  seed(handle, { domain: "nodkim.example", dayOffsets: fullFortnight(), orgs: 2,
    dkimPublished: false });
  var noKey = await verdictFor("nodkim.example");
  count("a domain publishing no selector record matching a key this server holds is refused",
    noKey.reason === policyMod.CODES.dkimUnpublished, noKey.reason + " " + noKey.detail);

  seed(handle, { domain: "sampled.example", dayOffsets: fullFortnight(), orgs: 2,
    record: "v=DMARC1; p=none; pct=99; rua=mailto:" + RUA });
  var sampled = await verdictFor("sampled.example");
  count("a policy applied to part of the mail is not the policy the evidence measured",
    sampled.reason === policyMod.CODES.sampleNotWhole,
    sampled.reason + " " + sampled.detail);
  count("and the record it is offered carries no sampling tag",
    sampled.records.quarantine.indexOf("pct") === -1, sampled.records.quarantine);

  seed(handle, { domain: "unread.example", dayOffsets: fullFortnight(), orgs: 2 });
  zone["unread.example"] = dnsZone.FAILING;
  var unresolved = await verdictFor("unread.example");
  count("an SPF lookup that did not complete is its own verdict rather than a wrong record",
    unresolved.reason === policyMod.CODES.postureUnresolved,
    unresolved.reason + " " + unresolved.detail);
  count("and it is not reported as a domain whose SPF record is permissive",
    unresolved.reason !== policyMod.CODES.spfNotStrict, unresolved.reason);
}

// ---- the source markings ---------------------------------------------------

async function aFailingSourceBlocksTheStepUntilItIsWrittenDown(handle) {
  // Four failing messages against five, which is the floor a source has
  // to reach before an operator is asked to write down what it is.
  seed(handle, { domain: "src4.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 50, failing: [{ ip: "198.51.100.41", perDay: 4, onDays: [-1] }] });
  seed(handle, { domain: "src5.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 50, failing: [{ ip: "198.51.100.42", perDay: 5, onDays: [-1] }] });
  var below = await verdictFor("src4.example");
  var above = await verdictFor("src5.example");
  count("a source under the floor needs no marking",
    below.reason !== policyMod.CODES.sourcesUnreviewed, below.reason + " " + below.detail);
  count("a source at the floor blocks the step until it is written down",
    above.reason === policyMod.CODES.sourcesUnreviewed, above.reason + " " + above.detail);

  var policy = policyOver();
  var marked = await policy.markSource({
    domain: "src5.example", sourceIp: "198.51.100.42",
    disposition: policyMod.MARK_NOT_OURS,
    reason: "a hosting range with no relationship to this domain",
  });
  count("the marking is recorded", marked.recorded === true, JSON.stringify(marked));

  // The emit writes the action out as a literal and the read asks for the
  // published constant, so the two are separate spellings of one name.
  // A row this run actually wrote is what says they agree.
  var written = await helpers.b.audit.query({
    action: policyMod.MARKED_ACTION, order: "desc", limit: 5 });
  count("the action a marking is filed under is the one the published constant names",
    Array.isArray(written) && written.length > 0,
    policyMod.MARKED_ACTION + " " + (Array.isArray(written) ? written.length : "no rows"));
  count("and the reason the operator wrote is on the row's own column",
    written.length > 0 &&
    written[0].reason === "a hosting range with no relationship to this domain",
    written.length > 0 ? String(written[0].reason) : "no rows");

  var held = await policy.markings({ domain: "src5.example" });
  count("and it reads back as the marking in force for that source",
    held.ok === true && Object.keys(held.marked).length === 1 &&
    held.marked[Object.keys(held.marked)[0]].disposition === policyMod.MARK_NOT_OURS,
    JSON.stringify(held.marked));
  count("and the address itself is not in what the trail answers with",
    JSON.stringify(held.marked).indexOf("198.51.100.42") === -1,
    JSON.stringify(held.marked));

  var after = await verdictFor("src5.example");
  count("a source an operator has accounted for no longer blocks the step",
    after.reason !== policyMod.CODES.sourcesUnreviewed, after.reason + " " + after.detail);
  count("and a source named as not the operator's does not read as a contradicted fix",
    after.reason !== policyMod.CODES.fixClaimContradicted, after.reason);
}

async function aFixClaimTheReportersContradictBlocksTheStep(handle) {
  seed(handle, { domain: "fixed.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 50, failing: [{ ip: "198.51.100.51", perDay: 6, onDays: [-1] }] });

  var policy = policyOver();
  await policy.markSource({
    domain: "fixed.example", sourceIp: "198.51.100.51",
    disposition: policyMod.MARK_OURS_FIXED,
    reason: "the relay in the branch office, its SPF entry was added on the same day",
  });

  var soon = await verdictFor("fixed.example");
  count("a fix claim is not contradicted by reports covering the days around it",
    soon.reason !== policyMod.CODES.fixClaimContradicted, soon.reason + " " + soon.detail);

  // The same domain read a fortnight later, with the source still failing
  // in a window that ended well after the claim was written.
  seed(handle, { domain: "fixed.example", orgs: 2, aligned: 50,
    dayOffsets: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
    failing: [{ ip: "198.51.100.51", perDay: 6, onDays: [23] }] });
  var later = await verdictFor("fixed.example", NOW + 24 * DAY_MS);
  count("a source still failing well after it was called fixed contradicts the claim",
    later.reason === policyMod.CODES.fixClaimContradicted, later.reason + " " + later.detail);

  // The same shape with the other disposition, which continued failure is
  // the expected case for.
  seed(handle, { domain: "theirs.example", orgs: 2, aligned: 50,
    dayOffsets: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
    failing: [{ ip: "198.51.100.52", perDay: 6, onDays: [23] }] });
  await policyOver().markSource({
    domain: "theirs.example", sourceIp: "198.51.100.52",
    disposition: policyMod.MARK_NOT_OURS,
    reason: "a residential range that has never sent for this domain",
  });
  var theirs = await verdictFor("theirs.example", NOW + 24 * DAY_MS);
  count("a source named as somebody else's is not contradicted by carrying on",
    theirs.reason !== policyMod.CODES.fixClaimContradicted,
    theirs.reason + " " + theirs.detail);
}

// ---- the step to reject ----------------------------------------------------

// The hold the step to reject asks for is time at full quarantine. Days
// spent at a sampled quarantine do not count toward it, so the run starts
// when the record stops carrying a percentage below 100.
async function aSampledQuarantineDoesNotCountTowardTheHold(handle) {
  var domain = "raised.example";
  seed(handle, { domain: domain, dayOffsets: fullMonth(), orgs: 3, aligned: 40,
    record: "v=DMARC1; p=quarantine; pct=10; rua=mailto:" + RUA });
  // A resolver reads the zone when it is built, so each change to the
  // zone is read through a stepper built after it.
  await policyOver().evaluate({ domain: domain, now: NOW });

  zone["_dmarc." + domain] = { txt: ["v=DMARC1; p=quarantine; rua=mailto:" + RUA] };
  await policyOver().evaluate({ domain: domain, now: NOW });
  await policyOver().evaluate({ domain: domain, now: NOW });
  var states = await observedStates(domain);
  count("raising pct to 100 is recorded as a new state, so the hold starts there, and a " +
    "reading that finds nothing changed records nothing",
    states.join(",") === "quarantine@10,quarantine@100", states.join(","));
}

// A record that goes away, or stops being readable, ends the run at
// quarantine. Publishing it again starts a new one.
async function aGapInThePolicyRestartsTheHold(handle) {
  var domain = "gap.example";
  var quarantine = "v=DMARC1; p=quarantine; rua=mailto:" + RUA;
  seed(handle, { domain: domain, dayOffsets: fullMonth(), orgs: 3, aligned: 40,
    record: quarantine });
  await policyOver().evaluate({ domain: domain, now: NOW });

  zone["_dmarc." + domain] = { txt: [] };
  await policyOver().evaluate({ domain: domain, now: NOW });
  zone["_dmarc." + domain] = { txt: ["v=DMARC1; p=discard"] };
  await policyOver().evaluate({ domain: domain, now: NOW });
  zone["_dmarc." + domain] = { txt: [quarantine] };
  var returned = await policyOver().evaluate({ domain: domain, now: NOW });
  var returnedHeld = returned.checks.filter(function (one) { return one.name === "held"; })[0];
  count("the reading that finds quarantine published again has no run of it to measure yet",
    returnedHeld !== undefined &&
      returnedHeld.reason === policyMod.CODES.quarantineAgeUnobserved,
    JSON.stringify(returnedHeld));
  var restored = await policyOver().evaluate({ domain: domain, now: Date.now() });
  var states = await observedStates(domain);
  count("a record that goes away and one no receiver reads are each recorded, so the run " +
    "at quarantine ends at the first and starts again when it is published",
    states.join(",") === "quarantine@100,absent@100,unusable@100,quarantine@100",
    states.join(","));
  var held = restored.checks.filter(function (one) { return one.name === "held"; })[0];
  count("and the reading after the return is held from that return",
    held !== undefined && held.ok === false && held.found === 0, JSON.stringify(held));
}

async function theRejectStepReadsTimeAlreadyServedAtQuarantine(handle) {
  seed(handle, { domain: "held.example", dayOffsets: fullMonth(), orgs: 3, aligned: 40,
    record: "v=DMARC1; p=quarantine; rua=mailto:" + RUA });

  // The observation is stamped by the trail at the moment it is written,
  // which is a few milliseconds after the anchor above. So the reading
  // that is one day short is taken an hour inside the fourteenth day
  // rather than on its boundary.
  var thirteenDays = NOW + 14 * DAY_MS - 3600000;
  var fifteenDays  = NOW + 15 * DAY_MS;

  var policy = policyOver();
  var first = await policy.evaluate({ domain: "held.example", now: thirteenDays });
  count("a domain at quarantine this server has no record of is refused on that",
    first.reason === policyMod.CODES.quarantineAgeUnobserved,
    first.reason + " " + first.detail);

  var second = await policy.evaluate({ domain: "held.example", now: thirteenDays });
  count("the reading records what the domain publishes, so the next one has a record",
    second.reason === policyMod.CODES.quarantineHeldShort,
    second.reason + " " + second.detail);
  count("thirteen days at quarantine is one step short of the step to reject",
    second.checks.some(function (one) {
      return one.name === "held" && one.ok === false && one.found === 13;
    }), JSON.stringify(second.checks[second.checks.length - 1]));

  var cleared = await policy.evaluate({ domain: "held.example", now: fifteenDays });
  count("time enough already served at quarantine clears the rule that asks for it",
    cleared.reason !== policyMod.CODES.quarantineHeldShort &&
    cleared.reason !== policyMod.CODES.quarantineAgeUnobserved,
    cleared.reason + " " + cleared.detail);
  count("and the whole set of rules for the step to reject is met",
    cleared.ok === true && cleared.next === "reject",
    cleared.reason + " " + cleared.detail);
  count("the record to publish is the one it was already publishing with p changed",
    cleared.records.reject === "v=DMARC1; p=reject; rua=mailto:" + RUA,
    cleared.records.reject);

  // The reject step reads a stricter alignment than the quarantine step,
  // measured on the same shape of evidence. One failing message a day
  // against three organizations sending forty each reads as 99.17
  // percent, which clears one threshold and not the other.
  seed(handle, { domain: "loose.example", dayOffsets: fullMonth(), orgs: 3, aligned: 40,
    record: "v=DMARC1; p=quarantine; rua=mailto:" + RUA,
    failing: [{ ip: "198.51.100.61", perDay: 1 }] });
  await policyOver().markSource({
    domain: "loose.example", sourceIp: "198.51.100.61",
    disposition: policyMod.MARK_NOT_OURS,
    reason: "a range that has never sent for this domain",
  });
  var loose = await verdictFor("loose.example", fifteenDays);
  count("alignment that clears the quarantine threshold can still be short of reject's",
    loose.reason === policyMod.CODES.alignmentShort &&
    loose.evidence.alignedPercent >= 98 && loose.evidence.alignedPercent < 99.5,
    loose.reason + " " + String(loose.evidence && loose.evidence.alignedPercent));
}

// The three readings a step cannot be judged over, each of which is a
// refusal rather than a pass on the part that was read. A gate that
// answered "no source is unreviewed" over half a list, or over a window
// the evidence is destroyed before it can span, is the shape of every
// check that passes because its instrument stopped early.
async function aReadingThatCouldNotBeCompletedRefuses(handle) {
  seed(handle, { domain: "partial.example", dayOffsets: fullFortnight(), orgs: 2,
    aligned: 50, failing: [{ ip: "198.51.100.71", perDay: 6, onDays: [-1] }] });

  var truncated = await policyOverSourceAnswer(function (answer) {
    return Object.assign({}, answer, { total: 900, truncated: true });
  }).evaluate({ domain: "partial.example", now: NOW });
  count("a failing-source list that came back short refuses rather than judging what fit",
    truncated.reason === policyMod.CODES.sourcesNotFullyListed,
    truncated.reason + " " + truncated.detail);

  var unreadable = await policyOverSourceAnswer(function (answer) {
    return Object.assign({}, answer, {
      sources: answer.sources.map(function (one) {
        return Object.assign({}, one, { sourceIp: null, readable: false });
      }),
    });
  }).evaluate({ domain: "partial.example", now: NOW });
  count("a failing source whose address will not read back refuses rather than passing",
    unreadable.reason === policyMod.CODES.sourceAddressUnreadable,
    unreadable.reason + " " + unreadable.detail);

  // A deployment keeping report rows for less time than the step is
  // measured over destroys the evidence before it can span the window.
  var resolver = dnsZone.resolverOver(zone);
  var shortWindow = policyMod.create({
    store: reports.create({
      aggregateRetentionMs: 10 * DAY_MS,
      forensicRetentionMs:  DAY_MS,
      hostedDomain: function (name) { return hosted[name] === true; },
    }),
    posture: postureMod.create({
      hostname: HOSTNAME, resolver: resolver, dkim: dkimStandIn(),
    }),
    dnsLookup:        postureMod.txtLookup(resolver),
    reportingAddress: RUA,
  });
  var kept = await shortWindow.evaluate({ domain: "clear.example", now: NOW });
  count("a retention window shorter than the step is measured over is named as the reason",
    kept.reason === policyMod.CODES.retentionShorterThanWindow,
    kept.reason + " " + kept.detail);
}

async function aRecordNoReceiverReadsAPolicyFromRefusesTheStep(handle) {
  seed(handle, { domain: "twice.example", dayOffsets: fullFortnight(), orgs: 2 });
  zone["_dmarc.twice.example"] = {
    txt: ["v=DMARC1; p=none; rua=mailto:" + RUA, "v=DMARC1; p=reject"],
  };
  var verdict = await verdictFor("twice.example");
  count("two DMARC records at one name refuse the step rather than picking one",
    verdict.reason === policyMod.CODES.postureUnusable,
    verdict.reason + " " + verdict.detail);
  count("and the operator is still handed one well formed record for each level",
    verdict.records.quarantine === "v=DMARC1; p=quarantine; rua=mailto:" + RUA,
    verdict.records.quarantine);
}

async function steppingDownIsOfferedOnEveryReading(handle) {
  seed(handle, { domain: "down.example", dayOffsets: [-1], orgs: 1, aligned: 1,
    record: "v=DMARC1; p=reject; rua=mailto:" + RUA });
  var verdict = await verdictFor("down.example");
  count("a domain that cannot step up is still told what it can step down to",
    verdict.reversal.gated === false &&
    verdict.reversal.to.join(",") === "none,quarantine",
    JSON.stringify(verdict.reversal));
  count("with the record text for each of them beside it",
    verdict.records.none.indexOf("p=none") !== -1 &&
    verdict.records.quarantine.indexOf("p=quarantine") !== -1,
    JSON.stringify(verdict.records));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dmarc-policy-step");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  try {
    // The store refuses to open without this: it decrypts a working copy
    // of the database and will not put one somewhere it was not told to.
    process.env.BLAMEJS_TMPDIR = workDir;

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    await store.open(cfg);

    var handle = reports.create({
      aggregateRetentionMs: 400 * DAY_MS,
      forensicRetentionMs:  DAY_MS,
      hostedDomain: function (name) { return hosted[name] === true; },
    });

    await evidenceNobodyAuthenticatedRaisesNothing(handle);
    await theWholeSetOfRulesClears(handle);
    await everyThresholdIsActuallyRead(handle);
    await thePostureTheRulesAskForIsRead(handle);
    await aFailingSourceBlocksTheStepUntilItIsWrittenDown(handle);
    await aFixClaimTheReportersContradictBlocksTheStep(handle);
    await theRejectStepReadsTimeAlreadyServedAtQuarantine(handle);
    await aReadingThatCouldNotBeCompletedRefuses(handle);
    await aRecordNoReceiverReadsAPolicyFromRefusesTheStep(handle);
    await steppingDownIsOfferedOnEveryReading(handle);
    await aSampledQuarantineDoesNotCountTowardTheHold(handle);
    await aGapInThePolicyRestartsTheHold(handle);

    return helpers.getChecks();
  } finally {
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "dmarc-policy-step",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
