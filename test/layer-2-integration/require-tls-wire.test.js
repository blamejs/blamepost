// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * require-tls-wire: what a receiving peer is actually asked for.
 *
 * `requireTls` is a protection an operator turns on, and the whole value
 * of it is a keyword on the `MAIL FROM` line that a receiver reads and
 * acts on. Everything between the setting and that keyword is plumbing:
 * the loader, the composition object, this server's outbound handle, the
 * framework's delivery composer, and the SMTP transport. A layer that
 * accepts the value and drops it produces a server that keeps delivering
 * mail, bounces nothing, reports nothing, and applies no protection,
 * while the operator reads their own configuration and believes it does.
 * That is not a hypothetical shape: the transport carried this option
 * with no reader for it, and the only evidence that anything was wrong
 * was the absence of a keyword nobody was looking at.
 *
 * So the assertion is the octets a peer received, and the peer is a real
 * one on a real socket.
 *
 * Three runs. The first is the claim and the other two are what stop it
 * passing for the wrong reason.
 *
 *   - A peer that advertises REQUIRETLS is asked for it.
 *   - The same peer, with the posture off, is NOT asked for it. A
 *     transport appending the keyword unconditionally satisfies the
 *     first run, and turns every message this server sends into one that
 *     a receiver without the extension may refuse.
 *   - A peer that does not advertise it is not delivered to. RFC 8689
 *     section 4.1 makes such a peer undeliverable rather than a peer to
 *     fall back to in the clear, because delivering anyway is
 *     indistinguishable, to the sender, from the request having been
 *     made.
 *   - A peer that defers the first envelope is asked for it again on the
 *     retry. Between the two attempts the posture is written to a queue
 *     descriptor and read back off it, and a descriptor that drops it
 *     leaves the first attempt looking right while every one after it
 *     delivers in the clear.
 *   - An envelope that states the posture as something other than true
 *     or false is refused. An envelope's own posture wins over the
 *     handle's, so that reading is the one that decides what goes on the
 *     wire, and a value read as off there turns a server the operator
 *     configured to ask into one that never asks.
 *
 * Each run is a child process. The outbound transport verifies the
 * peer's certificate against the trust store the process started with,
 * and `NODE_EXTRA_CA_CERTS` is read once at startup, so the private
 * authority this file mints has to be in the environment before node
 * begins. The alternative is turning verification off, which measures a
 * delivery this server would never make.
 *
 * Run standalone: node test/layer-2-integration/require-tls-wire.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var certs   = require("../helpers/certs");
var spawn   = require("../helpers/spawn");

var count = helpers.count;

var FIXTURE = nodePath.join(__dirname, "require-tls-fixture.js");

// The name on the peer's certificate, and the MX host the fixture
// resolves every recipient domain to. RFC 6761 section 6.3 reserves it
// for the loopback address on every host, which is what makes it both
// resolvable by the transport's own lookup and nobody's real domain.
var PEER_NAME = "localhost";

// A run's own ceiling. At most two SMTP conversations over loopback with
// one TLS handshake each; a run that takes longer than this has stopped
// rather than slowed.
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

// ---- the cases -------------------------------------------------------------

function aPeerThatAdvertisesItIsAskedForIt(run) {
  var v = run.verdict;
  count("the outbound path reaches a peer that advertises REQUIRETLS",
    v !== null && v.mailFrom !== null,
    v === null ? spawn.lastLines(run.result.out, 4) : JSON.stringify(v.commands));
  if (v === null || v.mailFrom === null) return;
  count("and the keyword is on the MAIL FROM line the peer received",
    v.keywordOnTheWire === true, v.mailFrom);
  count("and the message is delivered, so asking for it is not what refused it",
    v.delivered === 1, JSON.stringify({ failed: v.failed, deferred: v.deferred, threw: v.threw }));
}

function thePostureOffAsksForNothing(run) {
  var v = run.verdict;
  count("the same peer is reached with the posture off",
    v !== null && v.mailFrom !== null,
    v === null ? spawn.lastLines(run.result.out, 4) : JSON.stringify(v.commands));
  if (v === null || v.mailFrom === null) return;
  count("and the MAIL FROM line carries no REQUIRETLS keyword",
    v.keywordOnTheWire === false, v.mailFrom);
  count("and the message is still delivered",
    v.delivered === 1, JSON.stringify({ failed: v.failed, deferred: v.deferred, threw: v.threw }));
}

function aPeerThatDoesNotAdvertiseItIsNotDeliveredTo(run) {
  var v = run.verdict;
  count("a peer that does not advertise REQUIRETLS is answered at all",
    v !== null, v === null ? spawn.lastLines(run.result.out, 4) : "answered");
  if (v === null) return;
  // The refusal happens on the EHLO response, before an envelope is
  // offered, which is what "not delivered to" has to mean: a MAIL FROM
  // line reaching this peer would already have handed it the message.
  count("and the message is never offered to it",
    v.mailFrom === null, String(v.mailFrom));
  count("and nothing is delivered",
    v.delivered === 0, JSON.stringify({ delivered: v.delivered }));
  count("and the recipient is permanently failed rather than deferred, because " +
    "every host for the domain has been asked and the answer will not change",
    v.failed.length === 1 && v.deferred.length === 0,
    JSON.stringify({ failed: v.failed, deferred: v.deferred }));
  count("and the reason names the extension the peer did not advertise",
    v.failed.length === 1 && /REQUIRETLS/i.test(v.failed[0]),
    JSON.stringify(v.failed));
}

// The posture has to survive the on-disk queue.
//
// A deferred recipient is written to a descriptor and read back off it
// before the next attempt, and RFC 8689 section 4.1 gives the retry the
// same obligation as the first attempt: a peer that cannot honor the
// request must not be delivered to as though it had been made. A
// descriptor that drops the flag produces a first attempt carrying the
// keyword and every attempt after it delivering in the clear, which is
// the shape no single-send measurement can see.
function theRetryAsksForItToo(run) {
  var v = run.verdict;
  count("the peer is offered the message twice, once on the send and once on the sweep",
    v !== null && v.mailFroms.length === 2,
    v === null ? spawn.lastLines(run.result.out, 4) : JSON.stringify(v.mailFroms));
  if (v === null || v.mailFroms.length !== 2) return;
  count("the deferred recipient reached the queue with the posture recorded on it",
    v.spooledRequireTls === true, String(v.spooledRequireTls));
  count("the first MAIL FROM line carries the keyword",
    v.keywordOnEachLine[0] === true, v.mailFroms[0]);
  count("and so does the one the sweep sent after reading the descriptor back",
    v.keywordOnEachLine[1] === true, v.mailFroms[1]);
  count("the retry is the attempt that delivered, so the keyword is not what stopped it",
    Array.isArray(v.swept) && v.swept.length === 1 && v.swept[0] === "delivered",
    JSON.stringify(v.swept));
}

// An envelope decides the posture, so an envelope has to be held to it.
//
// The handle refuses a posture that is not a boolean at the moment it is
// built, and says why: a value that is neither true nor false leaves the
// question undecided where the answer changes whether mail is delivered
// or bounced. An envelope carries the same setting and wins over the
// handle, so it is the reading that actually reaches the transport, and
// a value read as off there is the protection an operator turned on
// being turned back off by a caller that meant to turn it on. Nothing
// says so afterwards: the message is delivered, the queue is empty and
// the configuration still reads the way the operator wrote it.
function anEnvelopePostureThatIsNotABooleanIsRefused(run) {
  var v = run.verdict;
  count("an envelope stating REQUIRETLS as something other than true or false is answered",
    v !== null, v === null ? spawn.lastLines(run.result.out, 4) : "answered");
  if (v === null) return;
  count("and it is refused rather than read as the posture being off",
    typeof v.threw === "string" && v.threw.length > 0, String(v.threw));
  count("and the refusal names the option, so the caller is told which value to fix",
    typeof v.threw === "string" && /requireTls/.test(v.threw), String(v.threw));
  count("and the message is never offered to the peer, because a message offered " +
    "without the keyword has already been delivered without the protection",
    v.mailFrom === null, String(v.mailFrom));
  count("and nothing is delivered",
    v.delivered === 0, JSON.stringify({ delivered: v.delivered }));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("require-tls-wire");
  var certDir = nodePath.join(root, "certs");
  var dataRoot = nodePath.join(root, "data");
  nodeFs.mkdirSync(certDir, { recursive: true });
  nodeFs.mkdirSync(dataRoot, { recursive: true });
  try {
    var material = await certs.pair({ hostname: PEER_NAME });
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.key"), material.key, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.chain.pem"), material.chain, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "authority.pem"), material.caPem, "utf8");

    aPeerThatAdvertisesItIsAskedForIt(await runMode("asked", certDir, dataRoot));
    thePostureOffAsksForNothing(await runMode("off", certDir, dataRoot));
    aPeerThatDoesNotAdvertiseItIsNotDeliveredTo(await runMode("refused", certDir, dataRoot));
    theRetryAsksForItToo(await runMode("retried", certDir, dataRoot));
    anEnvelopePostureThatIsNotABooleanIsRefused(
      await runMode("not-a-boolean", certDir, dataRoot));

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "require-tls-wire", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
