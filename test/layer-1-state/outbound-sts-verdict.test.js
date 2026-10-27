// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What an enforcing MTA-STS posture actually does to a message, and what
 * the receiver is told about it.
 *
 * `test/layer-1-state/outbound-policy.test.js` covers the record question
 * this server asks over the resolver the operator pinned. What it does not
 * cover is the verdict at the other end of that question: the enhanced
 * status a refused message carries, and the result type the receiver's
 * TLS report is keyed on. `5.7.10` appeared in no test in the tree, and
 * `lib/mail/delivery.js` reads that exact status to decide which MTA-STS
 * result type a receiver is sent, so a change to it would have moved a
 * report silently.
 *
 * That status covers two conditions rather than one. The composer writes
 * it for a policy it could not fetch and for a policy whose mail
 * exchanger list covers none of the domain's own, and RFC 8460 section
 * 4.3 registers a separate result type for each. What this file drives is
 * the first of them: the record lookup below never completes, so no
 * policy document is ever read and nothing about one is known to be
 * wrong. `test/layer-1-state/tlsrpt-refusal-cause.test.js` holds the
 * second, which nothing in the tree can drive.
 *
 * The MTA-STS question is asked twice on every enforcing delivery, and
 * the two askings do not go to the same place. This server asks first,
 * over the pinned resolver, and holds the message back when that answer
 * is missing. The framework's delivery composer then asks again for
 * itself, and nothing on its option surface reaches that lookup, so it
 * goes to the resolver the framework shares. Both cases below are one
 * record question about one domain; they differ only in which of the two
 * resolvers could not answer it, and they produce different enhanced
 * statuses and different result types.
 *
 * The shared resolver is pointed at a port nothing listens on, through
 * the framework's own DNS-over-HTTPS setting and the endpoint
 * `test/helpers/dns-quiet.js` already owns. That is the whole fault:
 * every lookup that goes there fails to complete, through the shipped
 * transport, with nothing replaced and nothing patched. It is set for
 * this file only, which runs in a process of its own.
 *
 * Two branches of the composer's enforcement are NOT reachable from here
 * and are not claimed. A published policy whose mail exchanger list does
 * not cover the domain's own, and a policy published in `none` mode, both
 * need the policy document itself, which RFC 8461 §3.3 puts behind an
 * HTTPS fetch of `mta-sts.<domain>` that the framework's own request
 * guard refuses to direct at a loopback address. Nothing in the tree can
 * stand that document up.
 *
 * No sockets. Every case here stops before a mail exchanger is reached.
 *
 * Run standalone: node test/layer-1-state/outbound-sts-verdict.test.js
 */

var helpers   = require("../helpers");
var quiet     = require("../helpers/dns-quiet");
var zone      = require("../helpers/dns-zone");
var blamepost = require("../../lib");

var b = helpers.b;

var check = helpers.check;
var count = helpers.count;

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// The status RFC 8461 §10.3 gives a message refused over a policy, and
// the one `lib/mail/delivery.js` keys its report classification on.
var POLICY_REFUSAL_STATUS = "5.7.10";

// The status this server writes itself when the record question it asked
// over the pinned resolver did not settle.
var RECORD_UNSETTLED_STATUS = "4.7.0";

// A domain publishing a mail exchanger and no MTA-STS record, which is
// what most of the internet looks like. The pinned resolver answers the
// record question here, so this server's own gate passes the message on.
var NO_RECORD_ZONE = {
  "example.net": { mx: ["mx.example.net"] },
};

// The same domain, with the pinned resolver unable to answer the record
// question. This server's own gate stops the message before the composer
// sees it.
var UNANSWERABLE_RECORD_ZONE = {
  "example.net":          { mx: ["mx.example.net"] },
  "_mta-sts.example.net": zone.FAILING,
};

function handleOn(dataDir, resolver, mtaSts) {
  return blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: resolver,
    policy:   { mtaSts: mtaSts, dane: "off" },
    // Room for a second attempt, so a temporary refusal stays temporary.
    // A budget of one converts it on the spot and sends the report that
    // follows, which is another message over this same handle.
    retry:    { maxAttempts: 2, backoffMs: [1000] },
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

// The verdict a recipient came back with, whichever list it is on.
function verdictFor(outcome) {
  var rows = (outcome.failed || []).concat(outcome.deferred || []);
  return rows.length === 1 ? rows[0] : null;
}

function failureTypes(rows) {
  var out = [];
  rows.forEach(function (record) {
    (record.failures || []).forEach(function (f) { out.push(f.resultType); });
  });
  return out;
}

// ---------------------------------------------------------------------------
// The enforcing verdict, and the status a report is keyed on
// ---------------------------------------------------------------------------

async function aPolicyQuestionTheComposerCannotSettleRefusesTheMessage(dataDir) {
  var resolver = zone.resolverOver(NO_RECORD_ZONE);
  var delivery = handleOn(dataDir, resolver, "enforce");

  var outcome = await sendOne(delivery);
  var verdict = verdictFor(outcome);

  count("nothing is delivered under an enforcing posture while the policy question " +
    "is unsettled", outcome.delivered.length === 0, JSON.stringify(outcome.delivered));
  count("the recipient comes back with one verdict", verdict !== null,
    JSON.stringify({ deferred: outcome.deferred, failed: outcome.failed }));
  if (verdict === null) return;
  count("carrying the enhanced status RFC 8461 gives a refusal over a policy",
    verdict.reasonCode === POLICY_REFUSAL_STATUS, String(verdict.reasonCode));
  count("and a reason naming MTA-STS, so an operator reading the queue knows what " +
    "refused it", /MTA-STS/i.test(String(verdict.reason)), String(verdict.reason));

  // The classification the status feeds. It is a frozen contract rather
  // than a phrase, and this is the case that holds the two ends of it
  // together: a change to the status at either end moves the result type
  // the receiver is sent.
  var observed = await delivery.tlsRpt.observed();
  var forDomain = observed.filter(function (r) { return r.domain === "example.net"; });
  count("the receiver's report carries one row for the domain the message was for",
    forDomain.length === 1, JSON.stringify(observed.map(function (r) { return r.domain; })));
  if (forDomain.length !== 1) return;
  // The lookup never completed, so the receiver's policy document was
  // never read and nothing in it was found wanting. RFC 8460 section 4.3
  // separates a policy that could not be retrieved from one that did not
  // validate, and the second of those, sent here, would tell a domain
  // whose policy is correct to go and change it.
  count("classified as an MTA-STS policy this server could not retrieve",
    failureTypes(forDomain).length === 1 &&
    failureTypes(forDomain)[0] === "sts-policy-fetch-error",
    JSON.stringify(forDomain[0].failures));
  count("and reported as an MTA-STS policy result rather than as a delivery this " +
    "server made no policy claim about",
    forDomain[0].policyType === "sts", String(forDomain[0].policyType));
  count("with the failure filed under that policy as well, so the report entry the " +
    "receiver reads is about the document they publish",
    forDomain[0].failures.length === 1 && forDomain[0].failures[0].policyType === "sts",
    JSON.stringify(forDomain[0].failures));
  count("with nothing counted as a success",
    forDomain[0].successful === 0, String(forDomain[0].successful));
}

// The same record question, unanswerable on the other resolver.
//
// This server asks first and has its own verdict, which is temporary and
// carries a status of its own. The composer asks again and its verdict is
// permanent. One domain, one record, and which of the two an operator
// gets depends on which resolver could not answer.
//
// The receiver is told the same thing either way, and that is the right
// answer rather than a gap: which of this sender's two resolvers went
// quiet is this sender's business, and what the receiver can act on is
// that their policy was not retrieved.
async function theSameQuestionOnTheOtherResolverEndsDifferently(dataDir) {
  var resolver = zone.resolverOver(UNANSWERABLE_RECORD_ZONE);
  var delivery = handleOn(dataDir, resolver, "enforce");

  var outcome = await sendOne(delivery);
  var verdict = verdictFor(outcome);

  count("the pinned resolver was the one asked", resolver.calls.indexOf(
    "TXT _mta-sts.example.net") !== -1, JSON.stringify(resolver.calls));
  count("the recipient comes back with one verdict", verdict !== null,
    JSON.stringify({ deferred: outcome.deferred, failed: outcome.failed }));
  if (verdict === null) return;
  count("under this server's own status rather than the one a policy refusal carries",
    verdict.reasonCode === RECORD_UNSETTLED_STATUS &&
    verdict.reasonCode !== POLICY_REFUSAL_STATUS, String(verdict.reasonCode));
  count("the message is held on the volume rather than given up on",
    delivery.queue.count() === 1, String(delivery.queue.count()));

  var observed = await delivery.tlsRpt.observed();
  var forDomain = observed.filter(function (r) { return r.domain === "example.net"; });
  count("and the receiver is told their policy could not be retrieved, which is what " +
    "happened whichever of this sender's resolvers went quiet",
    forDomain.length === 1 &&
    failureTypes(forDomain).length === 1 &&
    failureTypes(forDomain)[0] === "sts-policy-fetch-error",
    JSON.stringify(forDomain));
}

// ---------------------------------------------------------------------------
// The postures that do not refuse
// ---------------------------------------------------------------------------

// RFC 8461 §5.2: a policy published in testing mode records validation
// failures and does not block delivery. A sender that cannot settle the
// policy question at all is in a weaker position still, so a testing
// posture that refused there would be refusing on less evidence than the
// mode it is named after was written to tolerate.
async function aTestingPostureDoesNotRefuse(dataDir) {
  var resolver = zone.resolverOver(NO_RECORD_ZONE);
  var delivery = handleOn(dataDir, resolver, "testing");

  var outcome = await sendOne(delivery);
  var verdict = verdictFor(outcome);

  count("the recipient comes back with one verdict", verdict !== null,
    JSON.stringify({ deferred: outcome.deferred, failed: outcome.failed }));
  if (verdict === null) return;
  count("a testing posture does not refuse the message over the policy question",
    verdict.reasonCode !== POLICY_REFUSAL_STATUS &&
    verdict.reasonCode !== RECORD_UNSETTLED_STATUS, String(verdict.reasonCode));
  count("and what it is waiting on is the mail exchanger rather than a policy",
    !/MTA-STS/i.test(String(verdict.reason)), String(verdict.reason));
  count("the message is held on the volume rather than given up on",
    delivery.queue.count() === 1, String(delivery.queue.count()));
}

async function thePostureOffAsksNothingAndRefusesNothing(dataDir) {
  var resolver = zone.resolverOver(NO_RECORD_ZONE);
  var delivery = handleOn(dataDir, resolver, "off");

  var outcome = await sendOne(delivery);
  var verdict = verdictFor(outcome);

  check("an operator who turned MTA-STS off is not charged a record lookup for it",
    resolver.calls.indexOf("TXT _mta-sts.example.net") === -1);
  count("the recipient comes back with one verdict", verdict !== null,
    JSON.stringify({ deferred: outcome.deferred, failed: outcome.failed }));
  if (verdict === null) return;
  count("and nothing is refused over a policy",
    verdict.reasonCode !== POLICY_REFUSAL_STATUS &&
    !/MTA-STS/i.test(String(verdict.reason)), String(verdict.reasonCode));
}

// The posture this server reports is the posture the refusal above came
// from, so an operator reading `blamepost doctor` against a queue full of
// policy refusals is reading the setting that produced them.
function thePostureReportedIsTheOneThatRefused(dataDir) {
  var resolver = zone.resolverOver(NO_RECORD_ZONE);
  var reported = handleOn(dataDir, resolver, "enforce").describe().policy;
  check("the enforcing posture is what the handle reports running",
    reported.mtaSts === "enforce");
}

// ---------------------------------------------------------------------------

async function run() {
  // The whole fault this file rests on. A machine with something
  // listening on the discard port measures a lookup that is accepted and
  // never answered, which is a different failure and one that burns the
  // budget rather than failing in milliseconds.
  var refusing = await quiet.endpointIsRefusing();
  if (!refusing) {
    helpers.skip("something is listening on " + quiet.HOST + ":" + quiet.PORT + ", so the " +
      "resolver this file makes unanswerable would stall instead of failing");
    return helpers.getChecks();
  }
  b.network.dns.useDnsOverHttps({ url: quiet.ENDPOINT });

  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }
  try {
    await helpers.withTestTimeout("outbound sts verdict: a policy question the composer cannot settle",
      function () {
        return aPolicyQuestionTheComposerCannotSettleRefusesTheMessage(freshDir("sts-verdict-enforce"));
      });
    await helpers.withTestTimeout("outbound sts verdict: the same question on the other resolver",
      function () {
        return theSameQuestionOnTheOtherResolverEndsDifferently(freshDir("sts-verdict-pinned"));
      });
    await helpers.withTestTimeout("outbound sts verdict: a testing posture does not refuse",
      function () { return aTestingPostureDoesNotRefuse(freshDir("sts-verdict-testing")); });
    await helpers.withTestTimeout("outbound sts verdict: the posture off asks nothing",
      function () { return thePostureOffAsksNothingAndRefusesNothing(freshDir("sts-verdict-off")); });
    await helpers.withTestTimeout("outbound sts verdict: the posture reported is the one that refused",
      function () { return thePostureReportedIsTheOneThatRefused(freshDir("sts-verdict-describe")); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "outbound-sts-verdict", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
