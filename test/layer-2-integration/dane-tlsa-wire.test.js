// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * dane-tlsa-wire: whether a peer is authenticated against the records its
 * own zone publishes.
 *
 * DANE (RFC 7672) is one of the three transport-security policies the
 * outbound path is composed to carry. What it promises is narrow and
 * checkable: for each mail exchanger tried, the TLSA records published
 * for that host are fetched over the operator's resolver and matched
 * against the certificate chain the peer presents, and a peer that
 * matches none of its own records is not delivered to.
 *
 * None of that was measured anywhere. Every resolver in the suite
 * answered the TLSA question with an empty list or a rejection, and every
 * enforcing DANE posture in a test was a refusal at construction or a
 * setting read back out of `describe()`. A lookup that is never made and a
 * lookup that answers nothing produce the same delivery, so the whole
 * clause read as satisfied while nothing exercised it.
 *
 * The cases here are the two claims and the four runs that stop them
 * passing for the wrong reason.
 *
 *   - A peer whose certificate matches a record it publishes is delivered
 *     to. The zone publishes a record that does not match alongside the
 *     one that does, so a delivery proves a match rather than the
 *     presence of records.
 *   - The same peer publishing only the record that does not match is not
 *     delivered to, and is never offered the message at all. The refusal
 *     has to come before the envelope, because a message already handed
 *     over has gone to a peer this server could not authenticate whatever
 *     it decides afterwards.
 *   - The opportunistic posture refuses that peer as well. RFC 7672
 *     section 2.2 makes opportunistic a statement about which peers are
 *     asked about. A peer whose records are in hand and do not match is
 *     refused under that posture and under the enforcing one alike.
 *   - Under the posture this server ships, the same peer with the same
 *     records IS delivered to, and the resolver is never asked a TLSA
 *     question. `dnssecValidated` is the operator's statement that their
 *     resolver validates, RFC 7672 section 1.3 forbids using a record
 *     without it, and it is off on a default install. The operator guide
 *     and the threat model both say so; this is the case that holds them
 *     to it.
 *   - Turning the posture off outright looks the same, which is what
 *     makes the run above a measurement of the assertion rather than of
 *     the posture.
 *   - A TLSA lookup that cannot complete takes the mail exchanger out
 *     under the enforcing posture and does not under the opportunistic
 *     one.
 *
 * Every run reads back what this server accumulated for the receiver's
 * TLS report, because a peer that failed authentication and is reported
 * to nobody is a failure the receiver cannot fix.
 *
 * Each run is a child process. The peer's certificate is verified against
 * the trust store the process started with in the runs where DANE does
 * not supply the trust anchor, and `NODE_EXTRA_CA_CERTS` is read once at
 * startup. The authority is in the environment for every run, so what
 * differs between two rows is the posture and the records rather than
 * whether the certificate was trusted.
 *
 * Run standalone: node test/layer-2-integration/dane-tlsa-wire.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var certs   = require("../helpers/certs");
var spawn   = require("../helpers/spawn");

var count = helpers.count;

var FIXTURE = nodePath.join(__dirname, "dane-tlsa-fixture.js");

// The name on the peer's certificate. RFC 6761 section 6.3 reserves it
// for the loopback address on every host, which makes it both resolvable
// by the transport's own lookup and nobody's real domain.
var PEER_NAME = "localhost";

// A run's own ceiling. One SMTP conversation over loopback with one TLS
// handshake; a run that takes longer than this has stopped rather than
// slowed.
var RUN_CEILING_MS = 45000;

function verdictOf(result) {
  var line = String(result.out).split(/\r?\n/).filter(function (l) {
    return l.indexOf("VERDICT ") === 0;
  }).pop();
  if (!line) return null;
  try { return JSON.parse(line.slice("VERDICT ".length)); }
  catch (_e) { return null; }
}

async function runMode(mode, certDir, dataRoot) {
  var dataDir = helpers.dataDir(dataRoot, mode);
  nodeFs.mkdirSync(nodePath.join(dataDir, "queue"), { recursive: true });
  var env = Object.assign({}, process.env, {
    NODE_EXTRA_CA_CERTS: nodePath.join(certDir, "authority.pem"),
  });
  var result = await spawn.runNodeScript([FIXTURE, mode, certDir, dataDir], {
    cwd:       nodePath.join(__dirname, "..", ".."),
    env:       env,
    ceilingMs: RUN_CEILING_MS,
  });
  return { result: result, verdict: verdictOf(result) };
}

function answered(run) {
  return run.verdict !== null;
}

function detail(run) {
  return run.verdict === null
    ? spawn.lastLines(run.result.out, 6)
    : JSON.stringify(run.verdict);
}

// Every failure type this server recorded for the receiver in one run.
function reportedTypes(v) {
  var out = [];
  (v.tlsRpt || []).forEach(function (record) {
    (record.failures || []).forEach(function (f) { out.push(f.resultType); });
  });
  return out;
}

// The policy each of those failures is reported under. RFC 8460 section
// 4.4 spells the receiver's TLSA records `tlsa`, and a failure their own
// records produced has to arrive under them: a report saying no policy
// was found tells a domain running DANE that nothing was applied to the
// delivery its records refused.
function reportedPolicies(v) {
  var out = [];
  (v.tlsRpt || []).forEach(function (record) {
    (record.failures || []).forEach(function (f) { out.push(f.policyType); });
  });
  return out;
}

function reportedSuccesses(v) {
  return (v.tlsRpt || []).reduce(function (n, record) { return n + (record.successful || 0); }, 0);
}

// ---- the cases -------------------------------------------------------------

function aMatchingRecordAuthenticatesThePeer(run) {
  var v = run.verdict;
  count("the outbound path reaches a peer that publishes TLSA records",
    answered(run), detail(run));
  if (!answered(run)) return;
  count("the records are looked up for the mail exchanger the message is going to",
    v.tlsaAsked.length === 1 && /^_\d+\._tcp\.127\.0\.0\.1$/.test(v.tlsaAsked[0]),
    JSON.stringify(v.tlsaAsked));
  count("and the peer is delivered to, so a record that matches its key authenticates it",
    v.delivered === 1,
    JSON.stringify({ deferred: v.deferred, failed: v.failed, threw: v.threw }));
  count("and the message body reached the peer rather than only the envelope",
    v.bodyArrived === true, String(v.mailFrom));
  count("the zone published a record that does not match beside the one that does, " +
    "so the delivery is a match rather than records being present",
    v.published === 2, String(v.published));
  count("and the receiver's report counts the attempt as a success",
    reportedSuccesses(v) === 1 && reportedTypes(v).length === 0,
    JSON.stringify(v.tlsRpt));
}

function aPeerMatchingNoneOfItsRecordsIsNotDeliveredTo(run) {
  var v = run.verdict;
  count("a peer whose key matches none of its own TLSA records is answered at all",
    answered(run), detail(run));
  if (!answered(run)) return;
  count("the records were looked up",
    v.tlsaAsked.length === 1, JSON.stringify(v.tlsaAsked));
  count("nothing is delivered",
    v.delivered === 0, JSON.stringify({ delivered: v.delivered, threw: v.threw }));
  count("and the message is never offered to it, because a message on the wire has " +
    "already gone to a peer this server could not authenticate",
    v.mailFrom === null && v.bodyArrived === false,
    JSON.stringify({ mailFrom: v.mailFrom, commands: v.commands }));
  count("the recipient is held rather than discarded",
    v.deferred.length === 1 && v.failed.length === 0,
    JSON.stringify({ deferred: v.deferred, failed: v.failed }));
  count("and the reason names the records the peer did not match",
    v.deferred.length === 1 && /TLSA record/i.test(String(v.deferred[0].reason)),
    JSON.stringify(v.deferred));
  // The receiver is the only party who can fix this, and they learn about
  // it from the report or not at all. RFC 8460 section 4.3 carries a
  // result type for a peer that failed validation, and a failure this
  // server saw and did not record is one the receiver never hears about.
  count("and the receiver's report carries the failure rather than nothing at all",
    reportedTypes(v).length === 1 && reportedTypes(v)[0] === "validation-failure",
    JSON.stringify(v.tlsRpt));
  count("filed under the TLSA records that refused the peer, which is the document the " +
    "receiver has to go and look at",
    reportedPolicies(v).length === 1 && reportedPolicies(v)[0] === "tlsa",
    JSON.stringify(v.tlsRpt));
}

function theOpportunisticPostureRefusesItToo(run) {
  var v = run.verdict;
  count("the same peer under the opportunistic posture is answered",
    answered(run), detail(run));
  if (!answered(run)) return;
  count("the records are looked up, because the operator stated their resolver validates",
    v.tlsaAsked.length === 1, JSON.stringify(v.tlsaAsked));
  count("and the peer is refused, so opportunistic decides which peers are asked " +
    "about rather than what happens to one whose records do not match",
    v.delivered === 0 && v.mailFrom === null,
    JSON.stringify({ delivered: v.delivered, mailFrom: v.mailFrom }));
}

function theShippedPostureAsksNothingAndDelivers(run) {
  var v = run.verdict;
  count("the shipped posture reaches the same peer with the same records",
    answered(run), detail(run));
  if (!answered(run)) return;
  count("no TLSA question is asked at all, so the records the peer publishes are " +
    "never seen",
    v.tlsaAsked.length === 0, JSON.stringify(v.tlsaAsked));
  count("the posture it ran is the composer's own default rather than one named here",
    v.policy.dane === undefined && v.policy.dnssecValidated === undefined,
    JSON.stringify(v.policy));
  count("and the message is delivered to a peer whose key matches none of its own " +
    "records, which is what RFC 7672 section 1.3 requires without the operator's " +
    "statement that their resolver validates",
    v.delivered === 1 && v.bodyArrived === true,
    JSON.stringify({ delivered: v.delivered, deferred: v.deferred, failed: v.failed }));
}

function turningItOffLooksTheSame(run) {
  var v = run.verdict;
  count("the posture turned off outright reaches the same peer", answered(run), detail(run));
  if (!answered(run)) return;
  count("no TLSA question is asked", v.tlsaAsked.length === 0, JSON.stringify(v.tlsaAsked));
  count("and the message is delivered, which is what makes the shipped default a " +
    "measurement of the assertion rather than of the posture",
    v.delivered === 1 && v.bodyArrived === true,
    JSON.stringify({ delivered: v.delivered, deferred: v.deferred }));
}

function aLookupThatCannotCompleteTakesTheHostOut(run) {
  var v = run.verdict;
  count("a TLSA lookup that cannot complete under the enforcing posture is answered",
    answered(run), detail(run));
  if (!answered(run)) return;
  count("the question was asked", v.tlsaAsked.length === 1, JSON.stringify(v.tlsaAsked));
  count("nothing is delivered and the peer is never reached",
    v.delivered === 0 && v.commands.length === 0,
    JSON.stringify({ delivered: v.delivered, commands: v.commands }));
  count("the recipient waits rather than being told the address failed, because a " +
    "lookup that did not answer this minute may answer the next",
    v.deferred.length === 1 && v.failed.length === 0,
    JSON.stringify({ deferred: v.deferred, failed: v.failed }));
  count("and the receiver's report says DANE was required and not obtained",
    reportedTypes(v).length === 1 && reportedTypes(v)[0] === "dane-required",
    JSON.stringify(v.tlsRpt));
  count("under their TLSA records rather than under no policy at all",
    reportedPolicies(v).length === 1 && reportedPolicies(v)[0] === "tlsa",
    JSON.stringify(v.tlsRpt));
}

function theSameLookupFailureIsNotARefusalWhenOpportunistic(run) {
  var v = run.verdict;
  count("the same lookup failure under the opportunistic posture is answered",
    answered(run), detail(run));
  if (!answered(run)) return;
  count("the question was asked", v.tlsaAsked.length === 1, JSON.stringify(v.tlsaAsked));
  count("and the message is delivered, so a lookup that could not complete costs the " +
    "authentication rather than the mail",
    v.delivered === 1 && v.bodyArrived === true,
    JSON.stringify({ delivered: v.delivered, deferred: v.deferred, failed: v.failed }));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root     = helpers.tempDir("dane-tlsa-wire");
  var certDir  = nodePath.join(root, "certs");
  var dataRoot = nodePath.join(root, "data");
  nodeFs.mkdirSync(certDir, { recursive: true });
  nodeFs.mkdirSync(dataRoot, { recursive: true });
  try {
    var material = await certs.pair({ hostname: PEER_NAME });
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.key"), material.key, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.cert.pem"), material.cert, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.chain.pem"), material.chain, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "authority.pem"), material.caPem, "utf8");

    aMatchingRecordAuthenticatesThePeer(await runMode("matched", certDir, dataRoot));
    aPeerMatchingNoneOfItsRecordsIsNotDeliveredTo(
      await runMode("mismatched", certDir, dataRoot));
    theOpportunisticPostureRefusesItToo(
      await runMode("opportunistic-mismatched", certDir, dataRoot));
    theShippedPostureAsksNothingAndDelivers(await runMode("default", certDir, dataRoot));
    turningItOffLooksTheSame(await runMode("off", certDir, dataRoot));
    aLookupThatCannotCompleteTakesTheHostOut(
      await runMode("unanswerable", certDir, dataRoot));
    theSameLookupFailureIsNotARefusalWhenOpportunistic(
      await runMode("unanswerable-opportunistic", certDir, dataRoot));

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "dane-tlsa-wire", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
