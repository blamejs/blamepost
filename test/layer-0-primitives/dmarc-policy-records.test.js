// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The record text a DMARC policy step would be published as, the reading
 * of the record a domain publishes today, and the one property the whole
 * step decision rests on: that the counting it reads is the counting this
 * server authenticated and nothing else.
 *
 * Tokens exercised here:
 *
 *   blamepost.mail.posture.dmarcRecord
 *   blamepost.mail.dmarcPolicy.create
 *   blamepost.mail.dmarcPolicy.recordFor
 *   blamepost.mail.dmarcPolicy.describe
 *   blamepost.mail.dmarcPolicy.evaluate
 *
 * What is written as the failures it stops:
 *
 *   - a step changes the policy and nothing else, so the reporting
 *     addresses and alignment modes an operator published survive it;
 *   - the offered record carries no pct tag, because a policy applied to
 *     part of the mail is not the policy the evidence measured;
 *   - a domain that publishes nothing is told what to publish rather than
 *     handed a record built out of a parent's zone;
 *   - a lookup that did not complete is never read as a domain that
 *     publishes nothing;
 *   - and the three store readings are asked for with the narrow flag
 *     written as a literal, which no value a caller passes can reach.
 *
 * No sockets, no volume. The zone is a table and the store is a double
 * that records what it was asked.
 *
 * Run standalone: node test/layer-0-primitives/dmarc-policy-records.test.js
 */

var helpers    = require("../helpers");
var dnsZone    = require("../helpers/dns-zone");
var postureMod = require("../../lib/mail/posture");
var policyMod  = require("../../lib/mail/dmarc-policy");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";
var RUA      = "dmarc-reports@example.com";

// A published record carrying every tag an operator is likely to have
// chosen, so the step can be measured against what survives it.
var PUBLISHED_NONE =
  "v=DMARC1; p=none; sp=none; rua=mailto:dmarc-reports@example.com; " +
  "ruf=mailto:forensic@example.com; adkim=s; aspf=s; fo=1";

// The character a terminal acts on rather than prints. Built rather than
// written, because a raw one in a source file is a finding of its own.
var BELL = String.fromCharCode(7);

// The C1 range, whose members are the single-byte forms of the escape
// sequences a terminal acts on. Built from its numbers for the same
// reason as BELL above.
var C1_CONTROL_RE = new RegExp("[\\u0080-\\u009f]");

function _refuses(label, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null, thrown === null ? "accepted" : String(thrown.message));
  return thrown;
}

async function _refusesAsync(label, fn) {
  var thrown = null;
  try { await fn(); } catch (e) { thrown = e; }
  count(label, thrown !== null, thrown === null ? "accepted" : String(thrown.message));
  return thrown;
}

// ---- the record an operator would publish ----------------------------------

function theStepChangesThePolicyAndNothingElse() {
  var built = policyMod.recordFor({
    level: "quarantine", reportingAddress: RUA, published: PUBLISHED_NONE,
  });

  count("the offered record opens on the version tag",
    built.value.slice(0, 9) === "v=DMARC1;", built.value);
  count("the policy tag is second and carries the level asked for",
    built.value.split("; ")[1] === "p=quarantine", built.value);
  count("the reporting addresses the operator published survive the step",
    built.value.indexOf("rua=mailto:dmarc-reports@example.com") !== -1 &&
    built.value.indexOf("ruf=mailto:forensic@example.com") !== -1, built.value);
  count("the alignment modes and the failure options survive the step",
    built.value.indexOf("adkim=s") !== -1 && built.value.indexOf("aspf=s") !== -1 &&
    built.value.indexOf("fo=1") !== -1, built.value);
  count("the subdomain policy survives the step and is not rewritten",
    built.value.indexOf("sp=none") !== -1, built.value);
  count("nothing was dropped from a record that was well formed",
    built.dropped.length === 0, JSON.stringify(built.dropped));
}

function theOfferedRecordAppliesToAllOfTheMail() {
  var sampled = policyMod.recordFor({
    level: "quarantine", reportingAddress: RUA,
    published: "v=DMARC1; p=none; pct=50; rua=mailto:" + RUA,
  });
  count("a published pct tag is not carried into the offered record",
    sampled.value.indexOf("pct") === -1, sampled.value);
}

function aDomainPublishingNothingIsToldWhatToPublish() {
  var fresh = policyMod.recordFor({ level: "none", reportingAddress: RUA, published: null });
  count("a domain with no record is offered one naming this server's reporting address",
    fresh.value === "v=DMARC1; p=none; rua=mailto:" + RUA, fresh.value);

  var noRua = policyMod.recordFor({
    level: "reject", reportingAddress: RUA, published: "v=DMARC1; p=quarantine; adkim=s",
  });
  count("a published record asking for no reports gains a reporting address",
    noRua.value === "v=DMARC1; p=reject; rua=mailto:" + RUA + "; adkim=s", noRua.value);
}

function aTagATerminalWouldActOnIsNotCarriedIntoTheRecord() {
  var hostile = policyMod.recordFor({
    level: "quarantine", reportingAddress: RUA,
    published: "v=DMARC1; p=none; rua=mailto:" + RUA + "; note=one" + BELL + "two",
  });
  count("a tag whose value carries a control byte is left out of the offered record",
    hostile.value.indexOf(BELL) === -1, JSON.stringify(hostile.value));
  count("and the tag that was left out is named rather than dropped in silence",
    hostile.dropped.indexOf("note") !== -1, JSON.stringify(hostile.dropped));

  var huge = policyMod.recordFor({
    level: "quarantine", reportingAddress: RUA,
    published: "v=DMARC1; p=none; x=" + new Array(6000).join("a"),
  });
  count("a published record longer than the reader takes apart is not built on",
    huge.value === "v=DMARC1; p=quarantine; rua=mailto:" + RUA, huge.value.slice(0, 80));
}

function theRecordBuilderRefusesArgumentsItCannotActOn() {
  _refuses("a level outside the three is refused", function () {
    policyMod.recordFor({ level: "discard", reportingAddress: RUA });
  });
  _refuses("a reporting address that is not an address is refused", function () {
    policyMod.recordFor({ level: "none", reportingAddress: "not-an-address" });
  });
}

// ---- the record a domain publishes today -----------------------------------

function _lookupOver(zone) {
  return postureMod.txtLookup(dnsZone.resolverOver(zone));
}

async function theRecordAtTheDomainsOwnNameIsRead() {
  var found = await postureMod.dmarcRecord(DOMAIN, {
    dnsLookup: _lookupOver({ "_dmarc.example.com": { txt: [PUBLISHED_NONE] } }),
  });
  count("a published record reads as published", found.state === "published", found.state);
  count("and its policy tag is answered", found.policy === "none", String(found.policy));
  count("and its subdomain policy is answered",
    found.subdomainPolicy === "none", String(found.subdomainPolicy));
  count("a record carrying no pct tag reads as the whole of the mail",
    found.percent === 100, String(found.percent));

  var sampled = await postureMod.dmarcRecord(DOMAIN, {
    dnsLookup: _lookupOver({
      "_dmarc.example.com": { txt: ["v=DMARC1; p=quarantine; pct=25"] },
    }),
  });
  count("a published pct tag is answered as it was published",
    sampled.percent === 25, String(sampled.percent));
}

async function absenceAndAFailedLookupAreDifferentAnswers() {
  var absent = await postureMod.dmarcRecord(DOMAIN, {
    dnsLookup: _lookupOver({ "example.com": { txt: [] } }),
  });
  count("a name that publishes no DMARC record reads as absent",
    absent.state === "absent", absent.state);

  var unsettled = await postureMod.dmarcRecord(DOMAIN, {
    dnsLookup: _lookupOver({ "_dmarc.example.com": dnsZone.FAILING }),
  });
  count("a lookup that could not complete is never read as a name publishing nothing",
    unsettled.state === "unsettled", unsettled.state);
  count("and it carries the resolver's own code so a caller can tell which failure it was",
    unsettled.code === "resolver/upstream-failed", String(unsettled.code));
}

async function aRecordNoReceiverReadsAPolicyFromIsUnusable() {
  var doubled = await postureMod.dmarcRecord(DOMAIN, {
    dnsLookup: _lookupOver({
      "_dmarc.example.com": { txt: ["v=DMARC1; p=none", "v=DMARC1; p=reject"] },
    }),
  });
  count("two records at one name read as unusable rather than as either of them",
    doubled.state === "unusable", doubled.state);

  var broken = await postureMod.dmarcRecord(DOMAIN, {
    dnsLookup: _lookupOver({ "_dmarc.example.com": { txt: ["v=DMARC1; p=discard"] } }),
  });
  count("a record whose policy tag no receiver accepts reads as unusable",
    broken.state === "unusable", broken.state);
}

// What the reader hands back is printed to an operator, in the doctor
// report and in the browser, and the zone it came out of belongs to
// somebody else. The C1 range carries the single-byte forms of the
// escape sequences the C0 range spells with two bytes: U+009B is CSI,
// which introduces a cursor movement or a color change, so a record
// carrying one writes the rest of the line into a terminal as a command.
async function aRecordCarryingAControlTheTerminalActsOnIsScreened() {
  // Built from its number so this file's own bytes stay ASCII.
  var CSI = String.fromCharCode(0x9b);
  var found = await postureMod.dmarcRecord(DOMAIN, {
    dnsLookup: _lookupOver({
      "_dmarc.example.com": { txt: ["v=DMARC1; p=discard" + CSI + "quarantine"] },
    }),
  });
  count("a record whose policy tag no receiver accepts still reads as unusable",
    found.state === "unusable", found.state);
  count("the record handed back for printing carries no C1 control",
    !C1_CONTROL_RE.test(String(found.record)), JSON.stringify(found.record));
  count("and neither does the reason printed beside it",
    !C1_CONTROL_RE.test(String(found.why)), JSON.stringify(found.why));
}

async function theReadingDoesNotWalkUpwardToAParentsRecord() {
  var found = await postureMod.dmarcRecord("mail.example.com", {
    dnsLookup: _lookupOver({
      "_dmarc.example.com":      { txt: ["v=DMARC1; p=reject"] },
      "_dmarc.mail.example.com": { txt: [] },
    }),
  });
  count("a subdomain publishing nothing is not answered with its parent's record",
    found.state === "absent", found.state + " " + String(found.policy));
}

async function theRecordReaderRefusesArgumentsItCannotActOn() {
  await _refusesAsync("a reader with no domain is refused", function () {
    return postureMod.dmarcRecord("", { dnsLookup: _lookupOver({}) });
  });
  await _refusesAsync("a reader with no lookup is refused", function () {
    return postureMod.dmarcRecord(DOMAIN, {});
  });
  await _refusesAsync("a budget that is not a number is refused", function () {
    return postureMod.dmarcRecord(DOMAIN,
      { dnsLookup: _lookupOver({}), dnsAnswerBudgetMs: "soon" });
  });
}

// ---- the reading a step rests on -------------------------------------------

// A store double that records what it was asked for. It answers the same
// rows whichever way it is asked, so a reading that quietly widened would
// not be visible in the numbers: what is under test is the REQUEST, and
// the request is what the double keeps.
function _storeDouble() {
  var asked = { rollup: [], failingSources: [], reporters: [] };
  return {
    asked: asked,
    describe: function () { return { aggregateRetentionMs: 400 * 86400000 }; },
    rollup: function (opts) { asked.rollup.push(opts); return []; },
    failingSources: async function (opts) {
      asked.failingSources.push(opts);
      return { sources: [], total: 0, truncated: false, unauthenticated: 9999 };
    },
    reporters: function (opts) {
      asked.reporters.push(opts);
      return { reporters: [], total: 0, truncated: false, unauthenticatedReports: 9999 };
    },
  };
}

function _policyOver(zone, store) {
  var resolver = dnsZone.resolverOver(zone);
  return policyMod.create({
    store:            store,
    posture:          postureMod.create({ hostname: HOSTNAME, resolver: resolver }),
    dnsLookup:        postureMod.txtLookup(resolver),
    reportingAddress: RUA,
  });
}

async function theWiderReadingIsNotWhatTheStepAsksFor() {
  var store = _storeDouble();
  var policy = _policyOver({ "_dmarc.example.com": { txt: [PUBLISHED_NONE] } }, store);

  // The flag is passed on the way in as well, which is the shape a
  // console reading a query string and handing it on produces.
  await policy.evaluate({ domain: DOMAIN, includeUnauthenticated: true });

  var everyAsk = store.asked.rollup
    .concat(store.asked.failingSources)
    .concat(store.asked.reporters);
  count("the step asked the store for something",
    everyAsk.length >= 3, JSON.stringify(everyAsk));

  var widened = everyAsk.filter(function (one) {
    return one.includeUnauthenticated !== false;
  });
  count("every reading a step rests on asks for the counted reading, as a written false",
    widened.length === 0, JSON.stringify(widened));

  count("a caller's own widening flag reaches none of them",
    everyAsk.every(function (one) { return one.includeUnauthenticated === false; }),
    JSON.stringify(everyAsk));
}

async function aTrailThatCannotBeReadIsNotADomainNobodyMarkedAnything() {
  // No volume is open here, so the trail cannot answer. Reporting no
  // marking would report every failing source as unreviewed, which is an
  // answer about the trail wearing the shape of an answer about the
  // domain.
  var policy = _policyOver({ "_dmarc.example.com": { txt: [PUBLISHED_NONE] } },
    _storeDouble());
  var verdict = await policy.evaluate({ domain: DOMAIN });
  var sources = verdict.checks.filter(function (one) { return one.name === "sources"; });
  count("a trail that could not be read refuses under its own code",
    sources.length === 1 && sources[0].reason === policyMod.CODES.markingsNotFullyListed,
    JSON.stringify(sources));
  count("and it is never reported as a domain with unreviewed sources",
    verdict.checks.every(function (one) {
      return one.reason !== policyMod.CODES.sourcesUnreviewed;
    }), JSON.stringify(verdict.checks.map(function (one) { return one.reason; })));
}

async function theStepRefusesADomainThatPublishesNothing() {
  var verdict = await _policyOver({ "example.com": { txt: [] } }, _storeDouble())
    .evaluate({ domain: DOMAIN });
  count("a domain publishing no DMARC record is a verdict rather than an error",
    verdict.reason === policyMod.CODES.postureUnpublished, String(verdict.reason));
  count("and it is handed the record text to publish anyway",
    verdict.records.none === "v=DMARC1; p=none; rua=mailto:" + RUA,
    JSON.stringify(verdict.records));
}

async function aStalledLookupIsNotADomainWithNoPolicy() {
  var verdict = await _policyOver({ "_dmarc.example.com": dnsZone.FAILING }, _storeDouble())
    .evaluate({ domain: DOMAIN });
  count("a DMARC lookup that did not complete refuses under its own code",
    verdict.reason === policyMod.CODES.postureUnresolved, String(verdict.reason));
  count("and it is kept apart from a domain that publishes nothing",
    verdict.reason !== policyMod.CODES.postureUnpublished, String(verdict.reason));
}

async function theStrongestPolicyHasNoStepUpAndAFullStepDown() {
  var verdict = await _policyOver(
    { "_dmarc.example.com": { txt: ["v=DMARC1; p=reject; rua=mailto:" + RUA] } },
    _storeDouble()).evaluate({ domain: DOMAIN });
  count("a domain already at reject is told there is no step up",
    verdict.reason === policyMod.CODES.atStrongestPolicy, String(verdict.reason));
  count("stepping down is offered without a condition on it",
    verdict.reversal.gated === false && verdict.reversal.to.length === 2,
    JSON.stringify(verdict.reversal));
  count("and the record text for the weaker levels is in the answer",
    verdict.records.none.indexOf("p=none") !== -1 &&
    verdict.records.quarantine.indexOf("p=quarantine") !== -1,
    JSON.stringify(verdict.records));
}

// ---- the handle ------------------------------------------------------------

function theHandleRefusesWhatItCannotDecideOn() {
  var resolver = dnsZone.resolverOver({});
  var posture = postureMod.create({ hostname: HOSTNAME, resolver: resolver });
  var lookup = postureMod.txtLookup(resolver);

  _refuses("a stepper with no store is refused", function () {
    policyMod.create({ posture: posture, dnsLookup: lookup, reportingAddress: RUA });
  });
  _refuses("a stepper with no posture checker is refused", function () {
    policyMod.create({ store: _storeDouble(), dnsLookup: lookup, reportingAddress: RUA });
  });
  _refuses("a stepper with no way to read the published record is refused", function () {
    policyMod.create({ store: _storeDouble(), posture: posture, reportingAddress: RUA });
  });
  _refuses("a stepper with no reporting address is refused", function () {
    policyMod.create({ store: _storeDouble(), posture: posture, dnsLookup: lookup });
  });
}

async function theStepRefusesADomainNameThatIsNotOne() {
  var policy = _policyOver({}, _storeDouble());
  await _refusesAsync("a step asked about something that is not a domain is refused",
    function () { return policy.evaluate({ domain: "not a domain" }); });
  await _refusesAsync("a step asked about no domain at all is refused",
    function () { return policy.evaluate({}); });
  await _refusesAsync("a moment that is not a number is refused",
    function () { return policy.evaluate({ domain: DOMAIN, now: "yesterday" }); });
  await _refusesAsync("a marking with no reason is refused", function () {
    return policy.markSource({
      domain: DOMAIN, sourceIp: "198.51.100.20", disposition: policyMod.MARK_NOT_OURS,
    });
  });
  await _refusesAsync("a marking whose disposition is outside the pair is refused", function () {
    return policy.markSource({
      domain: DOMAIN, sourceIp: "198.51.100.20", disposition: "probably-fine", reason: "a guess",
    });
  });
  await _refusesAsync("a marking about something that is not a sending address is refused",
    function () {
      return policy.markSource({
        domain: DOMAIN, sourceIp: "the mail server", disposition: policyMod.MARK_NOT_OURS,
        reason: "a hosting range with no relationship to this domain",
      });
    });
}

function theRulesInForceArePublished() {
  var rules = _policyOver({}, _storeDouble()).describe();
  count("the quarantine rule is published with the span it is measured over",
    rules.quarantine.spanDays === 14 && rules.quarantine.reportDays === 7 &&
    rules.quarantine.organizations === 2 && rules.quarantine.alignedPercent === 98,
    JSON.stringify(rules.quarantine));
  count("the reject rule is published beside it",
    rules.reject.spanDays === 30 && rules.reject.reportDays === 21 &&
    rules.reject.organizations === 3 && rules.reject.alignedPercent === 99.5 &&
    rules.reject.heldDays === 14, JSON.stringify(rules.reject));
  count("the volume each threshold is measured over is published",
    rules.quarantine.minMessages === 100 && rules.reject.minMessages === 500,
    JSON.stringify([rules.quarantine.minMessages, rules.reject.minMessages]));
  count("no threshold is offered as a setting a deployment can lower",
    Object.prototype.hasOwnProperty.call(rules, "alignedPercent") === false,
    Object.keys(rules).join(","));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  theStepChangesThePolicyAndNothingElse();
  theOfferedRecordAppliesToAllOfTheMail();
  aDomainPublishingNothingIsToldWhatToPublish();
  aTagATerminalWouldActOnIsNotCarriedIntoTheRecord();
  theRecordBuilderRefusesArgumentsItCannotActOn();

  await theRecordAtTheDomainsOwnNameIsRead();
  await absenceAndAFailedLookupAreDifferentAnswers();
  await aRecordNoReceiverReadsAPolicyFromIsUnusable();
  await aRecordCarryingAControlTheTerminalActsOnIsScreened();
  await theReadingDoesNotWalkUpwardToAParentsRecord();
  await theRecordReaderRefusesArgumentsItCannotActOn();

  await theWiderReadingIsNotWhatTheStepAsksFor();
  await aTrailThatCannotBeReadIsNotADomainNobodyMarkedAnything();
  await theStepRefusesADomainThatPublishesNothing();
  await aStalledLookupIsNotADomainWithNoPolicy();
  await theStrongestPolicyHasNoStepUpAndAFullStepDown();

  theHandleRefusesWhatItCannotDecideOn();
  await theStepRefusesADomainNameThatIsNotOne();
  theRulesInForceArePublished();

  return helpers.getChecks();
}

module.exports = {
  name:      "dmarc-policy-records",
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
