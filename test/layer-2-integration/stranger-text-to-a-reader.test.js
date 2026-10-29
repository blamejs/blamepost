// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * stranger-text-to-a-reader: text this server did not write, on its way
 * to somebody reading it.
 *
 * A diagnostic is rarely this server's own prose. An argument parser
 * quotes the token it could not read, a resolver quotes what it was
 * trying to look up, and a delivery failure carries what the far side
 * said. The codepoints in any of those are somebody else's to choose,
 * and both places they end up act on them: a terminal runs an escape
 * sequence, so a value carrying the single-byte introducer at U+009B
 * repaints the row above the one it is on, and a bidirectional override
 * reverses the sentence an operator is reading before they decide what
 * to do about it.
 *
 * Three surfaces, because they are three different exits and a screen on
 * one says nothing about the others.
 *
 *   - The command line. What an operator reads comes off the shipped
 *     binary, so the run here is the real `bin/blamepost.js` in a child
 *     process and the assertion is the octets on its own two streams.
 *   - `delivery.send`, driven over a resolver that fails. The handle
 *     gives its caller the composer's per recipient outcome, and the
 *     `reason` on a row is what the failure said.
 *   - `delivery.send`, driven at a real receiving peer over a real
 *     socket, in `stranger-text-fixture.js`. Whether a peer's own reply
 *     text reaches a caller is the transport's decision rather than this
 *     server's, so the assertion is on the row either way: a refusal
 *     that starts carrying the reply text after a vendor refresh must
 *     still arrive screened.
 *
 * Every case asserts the readable words survive as well as that the
 * dangerous codepoints are gone. A screen that threw the diagnostic away
 * would satisfy a check for the absence of an escape sequence and leave
 * the operator with nothing to act on, which is the worse of the two
 * failures.
 *
 * Run standalone: node test/layer-2-integration/stranger-text-to-a-reader.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var cli      = require("../helpers/cli");
var certs    = require("../helpers/certs");
var spawn    = require("../helpers/spawn");
var delivery = require("../../lib/mail/delivery");

var count = helpers.count;

var FIXTURE = nodePath.join(__dirname, "stranger-text-fixture.js");

// The name on the peer's certificate. RFC 6761 section 6.3 reserves it
// for the loopback address on every host, which makes it both resolvable
// by the transport's own lookup and nobody's real domain.
var PEER_NAME = "localhost";

// At most one SMTP conversation over loopback with one TLS handshake per
// run; a run longer than this has stopped rather than slowed.
var RUN_CEILING_MS = 45000;

// The four codepoints, each chosen for a different thing it does to the
// reader. U+001B opens an escape sequence in two bytes and U+009B opens
// the same sequence in one, U+202E reverses the run that follows it so
// `gpj.exe` is read as `exe.jpg`, and a carriage return puts the cursor
// back at the start of the line so what follows overwrites what came
// before.
//
// Built from character codes rather than written out, because a raw C1
// byte does not survive being written into a source file.
var ESC = String.fromCharCode(0x1b);
var CSI = String.fromCharCode(0x9b);
var RLO = String.fromCharCode(0x202e);
var CR  = String.fromCharCode(0x0d);

var NAMED = [
  { key: "esc", name: "escape introducer at U+001B", ch: ESC },
  { key: "csi", name: "control sequence introducer at U+009B", ch: CSI },
  { key: "rlo", name: "right-to-left override at U+202E", ch: RLO },
  { key: "cr",  name: "carriage return", ch: CR },
];

// The readable half of every hostile value here, so a check can tell a
// screen that removed the dangerous codepoints from one that threw the
// whole diagnostic away.
var WORDS = "mailboxunavailable";

var HOSTILE = WORDS + ESC + "[2K" + CSI + "1A" + RLO + "gpj.exe" + CR + "HELD";

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// ---- the command line ------------------------------------------------------

// A token this server quotes back at the operator. Two shapes, because
// they leave by two different writes and a screen on one says nothing
// about the other: a flag the parser will not read comes back as a
// caught error's message written straight to a stream, and an argument a
// verb does not take is quoted by the verb's own reporter.
function terminalRefusal(what, run) {
  var both = String(run.stdout) + "\n" + String(run.stderr);
  for (var i = 0; i < NAMED.length; i += 1) {
    count(what + ": what the operator reads carries no " + NAMED[i].name,
      both.indexOf(NAMED[i].ch) === -1,
      "status " + run.status + ", transcript " + JSON.stringify(both.slice(0, 400)));
  }
  count(what + ": the refusal still quotes the readable part of the token",
    both.indexOf(WORDS) !== -1, JSON.stringify(both.slice(0, 400)));
  count(what + ": the run still refuses rather than proceeding",
    run.status !== 0, "status " + run.status);
}

// ---- delivery.send, over a resolver that fails -----------------------------

// A resolver whose failure carries the four codepoints. A lookup failure
// is where a receiving domain's own zone reaches this server as text, and
// the message travels into the outcome row the caller is handed.
function loudResolver() {
  return {
    queryMx: function () { return Promise.reject(new Error("451 4.7.0 " + HOSTILE)); },
  };
}

function rowsOf(outcome) {
  return (outcome.failed || [])
    .concat(outcome.deferred || [])
    .concat(outcome.delivered || []);
}

async function aResolverFailureReachesTheCallerScreened(dataDir) {
  var handle = delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: loudResolver(),
    policy:   { mtaSts: "off", dane: "off" },
    retry:    { maxAttempts: 4, backoffMs: [60000] },
    audit:    false,
  });
  var outcome = await handle.send({
    from: "alice@example.com", to: ["bob@example.net"], rfc822: MESSAGE,
  });
  var rows = rowsOf(outcome);
  count("a lookup failure reaches the caller as a row",
    rows.length > 0, JSON.stringify(outcome).slice(0, 400));
  if (rows.length === 0) return;
  var reason = String(rows[0].reason || "");
  for (var i = 0; i < NAMED.length; i += 1) {
    count("the reason a caller is handed carries no " + NAMED[i].name,
      reason.indexOf(NAMED[i].ch) === -1, JSON.stringify(reason.slice(0, 300)));
  }
  count("the failure's own words survive the screen",
    reason.indexOf(WORDS) !== -1, JSON.stringify(reason.slice(0, 300)));
}

// ---- delivery.send, at a real peer -----------------------------------------

function verdictOf(result) {
  var line = String(result.out).split(/\r?\n/).filter(function (l) {
    return l.indexOf("VERDICT ") === 0;
  }).pop();
  if (!line) return null;
  try { return JSON.parse(line.slice("VERDICT ".length)); }
  catch (_e) { return null; }
}

async function runPeerMode(mode, certDir, dataRoot) {
  var dataDir = helpers.dataDir(dataRoot, "peer-" + mode);
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

function aPeersRefusalReachesTheCallerScreened(mode, run) {
  var v = run.verdict;
  if (v === null) {
    count("the outbound path answered for a peer that refused with a " + mode + " reply",
      false, spawn.lastLines(run.result.out, 8));
    return;
  }
  count(mode + ": the peer's refusal reached the caller as a row",
    v.rows.length > 0, JSON.stringify(v).slice(0, 400));
  if (v.rows.length === 0) return;
  var row = v.rows[0];
  for (var i = 0; i < NAMED.length; i += 1) {
    count(mode + ": the reason a caller is handed carries no " + NAMED[i].name,
      row.reason[NAMED[i].key] === false, JSON.stringify(row.reason.text));
    count(mode + ": the receiver name a caller is handed carries no " + NAMED[i].name,
      row.mxHost[NAMED[i].key] === false, JSON.stringify(row.mxHost.text));
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root     = helpers.tempDir("stranger-text");
  var certDir  = nodePath.join(root, "certs");
  var dataRoot = nodePath.join(root, "data");
  var cliData  = helpers.dataDir(root, "cli");
  var cliWork  = nodePath.join(root, "work");
  nodeFs.mkdirSync(certDir, { recursive: true });
  nodeFs.mkdirSync(dataRoot, { recursive: true });
  nodeFs.mkdirSync(cliWork, { recursive: true });

  try {
    var runCli = cli.create({ dataDir: cliData, workDir: cliWork });
    terminalRefusal("an unreadable flag", runCli(["--" + HOSTILE]));
    // `doctor` takes no arguments, so it quotes the one it was given
    // back through the reporter every verb answers through. The volume
    // is never opened on this path, which is what makes it the cheapest
    // reporter refusal to drive.
    terminalRefusal("an argument a verb does not take",
      runCli(["doctor", HOSTILE]));

    await helpers.withTestTimeout(
      "stranger text: a lookup failure reaches the caller screened",
      function () {
        return aResolverFailureReachesTheCallerScreened(
          helpers.dataDir(dataRoot, "resolver"));
      });

    var material = await certs.pair({ hostname: PEER_NAME });
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.key"), material.key, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.chain.pem"), material.chain, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "authority.pem"), material.caPem, "utf8");

    aPeersRefusalReachesTheCallerScreened("refused",
      await runPeerMode("refused", certDir, dataRoot));
    aPeersRefusalReachesTheCallerScreened("deferred",
      await runPeerMode("deferred", certDir, dataRoot));

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "stranger-text-to-a-reader", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
