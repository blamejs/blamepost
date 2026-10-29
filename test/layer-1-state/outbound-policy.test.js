// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which resolver answers the question that decides outbound TLS.
 *
 * RFC 8461 §3.1 makes the `_mta-sts.<domain>` TXT record the gate on
 * everything else: a receiver that publishes no record has no policy,
 * and a sender that sees no record enforces nothing. So whoever answers
 * that one question decides whether this server's mail to that domain
 * is protected, and an answer of "no record" is indistinguishable from
 * a suppressed one unless the question went somewhere the operator
 * chose.
 *
 * The operator pins a resolver precisely because the host's is not
 * trusted. These cases assert the question reaches it, on the first
 * send and on every sweep afterwards.
 *
 * The other half is the one that breaks mail rather than TLS. A name
 * that does not exist is the ordinary answer for the overwhelming
 * majority of domains, and a sender that reads it as a failed lookup
 * stops delivering to every domain that never published a policy. So
 * absence and failure are asserted apart, with a zone that answers
 * neither the same way.
 *
 * Two resolvers answer that one question on an enforcing delivery, and
 * only the first is the operator's. This server asks over the pinned
 * resolver and withholds the recipient when the answer does not settle.
 * The framework's delivery composer then asks again for itself, and no
 * option it accepts reaches that second lookup, so it goes to the
 * resolver the framework shares. Every case below measures the first
 * asking, which is the one this server decides.
 *
 * The composer's verdict over the same record is deliberately not
 * asserted here. It follows whatever the machine running the file can
 * resolve, so a check on it passes on a host with DNS and fails on a
 * host without, which is a result about the runner rather than about
 * this server. `test/layer-1-state/outbound-sts-verdict.test.js` holds
 * that verdict, with the shared resolver pointed somewhere that answers
 * the same way every time.
 *
 * No sockets and no HTTPS. Every case here stops at the TXT record,
 * which is where the RFC puts the decision.
 *
 * Run standalone: node test/layer-1-state/outbound-policy.test.js
 */

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var blamepost = require("../../lib");

var check = helpers.check;

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// The status this server writes on a recipient it withheld itself,
// because the record question it asked over the pinned resolver did not
// settle. No other path in this file produces it.
var UNSETTLED_RECORD_STATUS = "4.7.0";

// A domain that publishes an MX and no MTA-STS record at all, which is
// what most of the internet looks like.
var NO_POLICY_ZONE = {
  "example.net": { mx: ["mx.example.net"] },
};

// The same domain, with a resolver that cannot answer the MTA-STS
// question. Nothing here says whether a policy exists.
var UNANSWERABLE_POLICY_ZONE = {
  "example.net":           { mx: ["mx.example.net"] },
  "_mta-sts.example.net":  zone.FAILING,
};

// The same domain again, with the pinned resolver reporting a record.
// Used to show what the pinned answer does and does not reach.
var PUBLISHED_RECORD_ZONE = {
  "example.net":          { mx: ["mx.example.net"] },
  "_mta-sts.example.net": { txt: ["v=STSv1; id=20260822T120000"] },
};

function handleOn(dataDir, resolver, mtaSts) {
  return blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: resolver,
    policy:   { mtaSts: mtaSts, dane: "off" },
    audit:    false,
  });
}

function sendOne(delivery) {
  return delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
}

function asked(resolver, question) {
  return resolver.calls.indexOf(question) !== -1;
}

// The one verdict a single-recipient send came back with, whichever list
// it landed on. Read across all three so a case can say what a recipient
// was NOT withheld under without also claiming which list holds it.
function verdictFor(outcome) {
  var rows = (outcome.failed || [])
    .concat(outcome.deferred || [])
    .concat(outcome.delivered || []);
  return rows.length === 1 ? rows[0] : null;
}

// ---------------------------------------------------------------------------
// The question goes to the resolver the operator pinned
// ---------------------------------------------------------------------------

async function theMtaStsQuestionGoesToThePinnedResolver(dataDir) {
  var resolver = zone.resolverOver(NO_POLICY_ZONE);
  var delivery = handleOn(dataDir, resolver, "enforce");

  await sendOne(delivery);

  check("the pinned resolver is asked for the domain's MX",
    asked(resolver, "MX example.net"));
  check("and it is asked whether the domain publishes an MTA-STS policy",
    asked(resolver, "TXT _mta-sts.example.net"));
}

async function theQuestionIsNotAskedWhenThePostureIsOff(dataDir) {
  var resolver = zone.resolverOver(NO_POLICY_ZONE);
  var delivery = handleOn(dataDir, resolver, "off");

  await sendOne(delivery);

  check("an operator who turned MTA-STS off is not charged a lookup for it",
    !asked(resolver, "TXT _mta-sts.example.net"));
}

// ---------------------------------------------------------------------------
// Absence is not failure
// ---------------------------------------------------------------------------

// A name that does not exist is the ordinary answer for the
// overwhelming majority of domains. Reading it as a failed lookup would
// have this server withhold mail to every domain that never published a
// record, and say MTA-STS while doing it.
//
// The withholding decision is this server's, it is made on the pinned
// resolver's answer alone, and it is what this case measures. The
// verdict the recipient finally carries is the composer's and is left to
// `outbound-sts-verdict.test.js`, for the reason in this file's header.
async function aDomainThatPublishesNoRecordIsNotWithheldOverOne(dataDir) {
  var resolver = zone.resolverOver(NO_POLICY_ZONE);
  var delivery = handleOn(dataDir, resolver, "enforce");

  var outcome = await sendOne(delivery);
  var verdict = verdictFor(outcome);

  check("the pinned resolver is asked whether the domain publishes a record",
    asked(resolver, "TXT _mta-sts.example.net"));
  check("the recipient comes back with exactly one verdict", verdict !== null);
  if (verdict === null) return;
  check("a domain that never published a record is not withheld under the status " +
    "this server writes on a record question it could not settle",
    verdict.reasonCode !== UNSETTLED_RECORD_STATUS);
  // The second anchor on the same decision, independent of the status.
  // Only the withholding path phrases a reason this way, so a status
  // that was renamed would still be caught here.
  check("and the reason it carries is not this server holding it back",
    !/could not be looked up/i.test(String(verdict.reason)));
}

// What the pinned answer reaches, measured by changing it and looking
// for a difference.
//
// The composer asks the record question a second time, and the option
// surface of `b.mail.send.deliver.create` carries nothing that reaches
// that lookup: `resolver` is threaded to the MX query and to the DANE
// TLSA query and not to this one. So the pinned resolver can report a
// published record or no record at all and the composer returns the same
// verdict either way, because it never read either answer.
//
// This is filed upstream as blamejs #784. The case is written to hold
// while that is true and to fail when it stops being true, so the fix
// arrives as a failing check here rather than as a silent change of
// behavior.
async function thePinnedAnswerDoesNotReachTheComposer(dirA, dirB) {
  var absentResolver = zone.resolverOver(NO_POLICY_ZONE);
  var recordResolver = zone.resolverOver(PUBLISHED_RECORD_ZONE);

  var absentVerdict = verdictFor(await sendOne(handleOn(dirA, absentResolver, "enforce")));
  var recordVerdict = verdictFor(await sendOne(handleOn(dirB, recordResolver, "enforce")));

  check("both sends come back with exactly one verdict",
    absentVerdict !== null && recordVerdict !== null);
  if (absentVerdict === null || recordVerdict === null) return;
  check("the pinned resolver answered the record question differently in the two runs",
    asked(absentResolver, "TXT _mta-sts.example.net") &&
    asked(recordResolver, "TXT _mta-sts.example.net"));
  check("and the verdict is the same on both, because the answer the operator's " +
    "resolver gave never reached the lookup that decided it",
    absentVerdict.reasonCode === recordVerdict.reasonCode);
  check("neither run was withheld by this server, so the sameness is the " +
    "composer's doing rather than this server's",
    absentVerdict.reasonCode !== UNSETTLED_RECORD_STATUS &&
    recordVerdict.reasonCode !== UNSETTLED_RECORD_STATUS);
}

async function aResolverThatCannotAnswerDefersRatherThanDelivering(dataDir) {
  var resolver = zone.resolverOver(UNANSWERABLE_POLICY_ZONE);
  var delivery = handleOn(dataDir, resolver, "enforce");

  var outcome = await sendOne(delivery);

  check("a lookup that could not complete does not read as no policy",
    outcome.deferred.length === 1 && outcome.failed.length === 0);
  check("the recipient is held under the security status rather than a peer's",
    outcome.deferred[0].reasonCode === "4.7.0");
  check("and the reason names MTA-STS so an operator knows where to look",
    /MTA-STS/i.test(String(outcome.deferred[0].reason)));
  check("the message is on disk waiting, not discarded",
    delivery.queue.count() === 1);
}

// The reader both halves of the question go through. Asserted directly
// as well as through a send, because the signal it converts is the one
// the framework's policy fetcher reads and a resolver never raises: a
// name that does not exist has to arrive as the absence signal, and a
// lookup that could not complete has to keep its own.
async function absenceAndFailureArriveAsDifferentSignals() {
  var resolver = zone.resolverOver(UNANSWERABLE_POLICY_ZONE);
  var lookup = blamepost.mail.posture.txtLookup(resolver);

  var absent = null;
  try { await lookup("_mta-sts.nothing-here.example", "TXT"); }
  catch (err) { absent = err; }
  check("a name that does not exist raises the signal the policy fetcher reads as absence",
    absent !== null && absent.code === "ENODATA");

  var failed = null;
  try { await lookup("_mta-sts.example.net", "TXT"); }
  catch (err) { failed = err; }
  check("a lookup that could not complete keeps its own code instead",
    failed !== null && failed.code !== "ENODATA");

  var wrongType = null;
  try { await lookup("example.net", "MX"); }
  catch (err) { wrongType = err; }
  check("and a question it cannot answer is refused rather than answered wrongly",
    wrongType !== null);
}

// ---------------------------------------------------------------------------
// The posture reported is the posture run
// ---------------------------------------------------------------------------

// `describe().policy` is what `blamepost doctor` prints and what the
// admin console renders, and an operator reads it to find out what
// transport security produced the queue in front of them.
//
// Both halves of the posture have a default, and the configuration
// object carries whichever fields the operator wrote. Naming one and
// leaving the other alone is the ordinary case, because the two settings
// are independent: an operator turning MTA-STS off has said nothing
// about DANE. What the composer then runs is its own default, so a
// report that echoes the option instead of the resolved value describes
// a posture this server is not keeping.
async function thePostureReportedIsThePostureRun(dataDir) {
  var resolver = zone.resolverOver(NO_POLICY_ZONE);

  var partial = blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: resolver,
    policy:   { mtaSts: "off" },
    audit:    false,
  }).describe().policy;

  check("a configuration naming no DANE posture reports the one the composer runs",
    partial.dane === "opportunistic");
  check("and the MTA-STS posture it did name is reported as written",
    partial.mtaSts === "off");

  var other = blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: resolver,
    policy:   { dane: "off" },
    audit:    false,
  }).describe().policy;

  check("the pair holds the other way round as well",
    other.mtaSts === "enforce" && other.dane === "off");
}

// ---------------------------------------------------------------------------
// The sweep asks the same question the first send did
// ---------------------------------------------------------------------------

// The first send is only here to leave an entry for the sweep to find,
// and it runs under a posture that reaches no policy verdict at all, so
// what it leaves is the message that was sent. Under an enforcing
// posture the composer can refuse the recipient outright over its own
// record lookup, and what waits on the volume afterwards is then the
// notice to the sender rather than the original. The count alone does
// not tell those two apart, so the recipient is read as well.
async function theSweepAsksTheSameQuestion(dataDir) {
  var firstResolver = zone.resolverOver(NO_POLICY_ZONE);
  var delivery = handleOn(dataDir, firstResolver, "testing");
  await sendOne(delivery);
  check("one entry is waiting after the first attempt", delivery.queue.count() === 1);
  var waiting = await delivery.queue.list();
  check("and the entry waiting is the message that was sent",
    waiting.length === 1 && waiting[0].recipient === "bob@example.net");

  // A second handle over the same spool, so the sweep's lookups are the
  // only ones this resolver records.
  var sweepResolver = zone.resolverOver(UNANSWERABLE_POLICY_ZONE);
  var sweeper = handleOn(dataDir, sweepResolver, "enforce");
  var run = await sweeper.queue.runDue({ force: true });

  check("the sweep attempted the waiting entry", run.ran === 1);
  check("and the entry it attempted is still the message that was sent",
    run.results[0].recipient === "bob@example.net");
  check("and asked the pinned resolver the MTA-STS question again",
    asked(sweepResolver, "TXT _mta-sts.example.net"));
  check("a retry whose policy lookup failed stays waiting",
    run.results[0].outcome === "waiting" && sweeper.queue.count() === 1);
  check("under the security status rather than a peer's",
    run.results[0].reasonCode === "4.7.0");
}

// ---------------------------------------------------------------------------
// What a resolver answered, on its way to an operator's terminal
// ---------------------------------------------------------------------------

// `blamepost doctor` reads the same records and prints its findings as
// plain lines. Every value in one arrived from DNS, which is a place
// this server does not control: a receiver's MX name, the text of an
// SPF or DMARC record, the message a failed lookup carried. An escape
// sequence in any of them repaints the terminal of the person running
// the check.
var ESC  = String.fromCharCode(0x1b);
var NUL  = String.fromCharCode(0x00);
var RTLO = String.fromCharCode(0x202e);

var BIDI_RE = new RegExp("[" +
  String.fromCharCode(0x202a) + "-" + String.fromCharCode(0x202e) +
  String.fromCharCode(0x2066) + "-" + String.fromCharCode(0x2069) +
  String.fromCharCode(0x200e) + String.fromCharCode(0x200f) +
  String.fromCharCode(0x061c) + "]");

// A zone whose every answer carries something that forges a row.
var HOSTILE_ZONE = {
  "hostile.example": {
    mx:  ["mx" + ESC + "[2J.elsewhere.example"],
    txt: ["v=spf1 include:" + RTLO + "moc.elpmaxe" + " ~all"],
  },
  "_dmarc.hostile.example":     { txt: ["v=DMARC1; p=none" + ESC + "[1;1H"] },
  "_smtp._tls.hostile.example": { txt: ["v=TLSRPTv1" + NUL] },
};

function isSafeToPrint(value) {
  if (value === null || value === undefined) return true;
  if (Array.isArray(value)) return value.every(isSafeToPrint);
  var s = String(value);
  if (s.indexOf(ESC) !== -1 || s.indexOf(NUL) !== -1) return false;
  if (s.indexOf("\r") !== -1 || s.indexOf("\n") !== -1) return false;
  return !BIDI_RE.test(s);
}

async function aHostileZoneCannotForgeARowInTheReport() {
  var checker = blamepost.mail.posture.create({
    hostname: "mx.example.com",
    resolver: zone.resolverOver(HOSTILE_ZONE),
  });
  var report = await checker.check({ domains: ["hostile.example"] });

  var findings = report.domains[0].findings;
  check("the report reaches a verdict on the zone rather than throwing",
    findings.length > 0 && report.ok === false);

  var unsafe = findings.filter(function (f) {
    return !isSafeToPrint(f.detail) || !isSafeToPrint(f.found) ||
           !isSafeToPrint(f.expected) || !isSafeToPrint(f.name);
  });
  check("no value a resolver answered with can forge a row in the report: " +
    unsafe.map(function (f) { return f.record; }).join(", "),
  unsafe.length === 0);

  var spf = findings.filter(function (f) { return f.record === "SPF"; })[0];
  check("and the record it complains about is still recognizable",
    spf !== undefined && /v=spf1/.test(String(spf.found || spf.detail)));
}

// ---------------------------------------------------------------------------

async function run() {
  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }
  try {
    await helpers.withTestTimeout("outbound policy: the MTA-STS question goes to the pinned resolver",
      function () { return theMtaStsQuestionGoesToThePinnedResolver(freshDir("out-sts-pinned")); });
    await helpers.withTestTimeout("outbound policy: the question is not asked when the posture is off",
      function () { return theQuestionIsNotAskedWhenThePostureIsOff(freshDir("out-sts-off")); });
    await helpers.withTestTimeout("outbound policy: a domain publishing no record is not withheld",
      function () { return aDomainThatPublishesNoRecordIsNotWithheldOverOne(freshDir("out-sts-none")); });
    await helpers.withTestTimeout("outbound policy: the pinned answer does not reach the composer",
      function () {
        return thePinnedAnswerDoesNotReachTheComposer(
          freshDir("out-sts-reach-a"), freshDir("out-sts-reach-b"));
      });
    await helpers.withTestTimeout("outbound policy: a resolver that cannot answer defers",
      function () { return aResolverThatCannotAnswerDefersRatherThanDelivering(freshDir("out-sts-fail")); });
    await helpers.withTestTimeout("outbound policy: absence and failure arrive as different signals",
      function () { return absenceAndFailureArriveAsDifferentSignals(); });
    await helpers.withTestTimeout("outbound policy: the posture reported is the posture run",
      function () { return thePostureReportedIsThePostureRun(freshDir("out-sts-posture")); });
    await helpers.withTestTimeout("outbound policy: the sweep asks the same question",
      function () { return theSweepAsksTheSameQuestion(freshDir("out-sts-sweep")); });
    await helpers.withTestTimeout("outbound policy: a hostile zone cannot forge a row in the report",
      function () { return aHostileZoneCannotForgeARowInTheReport(); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "outbound-policy", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
