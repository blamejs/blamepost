// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * outbound-octet-fidelity: the octets a receiving peer is given.
 *
 * `data-terminator-parity.test.js` measures what this server stores for
 * a message that arrives. This measures what it writes for a message
 * that leaves, which is the other half of the same question and the half
 * no wire has answered.
 *
 * The end of an SMTP `DATA` body is a sequence rather than a count. RFC
 * 5321 section 4.1.1.4 writes it as `<CRLF>.<CRLF>` and says the first
 * CRLF "is actually the terminator of the previous line", so a writer
 * holding a message has to decide whether the buffer already ends with
 * the CRLF that ends its last line. The transport decides by looking at
 * the last two octets. A reader that decides the same question the same
 * way loses two octets that belonged to the sender, so the writer's
 * version is measured here rather than argued from the reader's.
 *
 * Each captured body is read twice, and the second reading is what stops
 * the first from passing for the wrong reason:
 *
 *   naive     the body ends where `<CRLF>.<CRLF>` begins. This is the
 *             reading that costs two octets.
 *   counted   the body is everything before the terminating `.\r\n`
 *             line, which is where RFC 5321 section 4.1.1.4 puts it.
 *
 * A writer that dropped a message's last CRLF and a reader that forgave
 * it would agree with each other and disagree with every other host on
 * the internet, so both readings are reported for every fixture and the
 * cases below name which one has to hold.
 *
 * Three runs.
 *
 *   - Six fixtures handed straight to the outbound handle. Five of them
 *     have to arrive as the octets they were given. The sixth has a last
 *     line with no terminator, which cannot be transmitted as it stands
 *     (RFC 5321 section 2.3.8), and it has to gain exactly the missing
 *     CRLF and nothing else.
 *   - A message a peer transmits to the MX listener, forwarded off this
 *     server by an alias, measured at the second peer. Two wires, one
 *     message, and no recomposition in between.
 *   - A message the composer sends and files, where the octets the peer
 *     received and the octets an IMAP client is served for the Sent copy
 *     have to be the same message.
 *
 * Each run is a child process. The outbound transport verifies the
 * peer's certificate against the trust store the process started with,
 * and `NODE_EXTRA_CA_CERTS` is read once at startup, so the private
 * authority this file mints has to be in the environment before node
 * begins. Nothing this repository composes can turn that verification
 * off, and a run with it off would measure a delivery this server would
 * never make.
 *
 * Run standalone: node test/layer-2-integration/outbound-octet-fidelity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var certs   = require("../helpers/certs");
var spawn   = require("../helpers/spawn");

var count = helpers.count;

var FIXTURE = nodePath.join(__dirname, "outbound-octet-fidelity-fixture.js");

// The name on the peer's certificate. RFC 6761 section 6.3 reserves it
// for the loopback address on every host.
var PEER_NAME = "localhost";

// A run's own ceiling. One of the three opens a data volume and binds
// listeners, which is the slowest of them; a run past this has stopped
// rather than slowed.
var RUN_CEILING_MS = 120000;

function verdictOf(result) {
  var line = String(result.out).split(/\r?\n/).filter(function (l) {
    return l.indexOf("VERDICT ") === 0;
  }).pop();
  if (!line) return null;
  try { return JSON.parse(line.slice("VERDICT ".length)); }
  catch (_e) { return null; }
}

// What a run that produced no verdict has to say for itself.
//
// A child that dies before it prints anything leaves `lastLines` with an
// empty string, and a check whose only detail is that string reports a
// failure that names nothing: not the exit status, not whether the
// ceiling was reached, not even whether the process wrote a byte. That
// is the one failure shape a log cannot be read for afterwards, because
// there is nothing in it, so the run's own numbers are carried here
// whether or not the child managed to speak.
function whyNoVerdict(run) {
  return "exit " + run.result.code +
    ", ceiling " + (run.result.ceilingHit ? "reached" : "not reached") +
    " after " + run.result.ms + "ms" +
    ", " + String(run.result.out).length + " bytes of output" +
    (String(run.result.out).trim().length === 0
      ? ", none of it on either stream"
      : ": " + spawn.lastLines(run.result.out, 6));
}

async function runMode(mode, certDir, dataRoot, workDir) {
  var dataDir = helpers.dataDir(dataRoot, mode);
  nodeFs.mkdirSync(nodePath.join(dataDir, "queue"), { recursive: true });
  var env = Object.assign({}, process.env, {
    NODE_EXTRA_CA_CERTS: nodePath.join(certDir, "authority.pem"),
    // The framework keeps the decrypted working copy of the database on
    // a memory backed directory and reads this to find it. Pointing it
    // inside this run's own temporary tree keeps the encrypted at rest
    // path exactly as it ships.
    BLAMEJS_TMPDIR:      workDir,
  });
  var result = await spawn.runNodeScript([FIXTURE, mode, certDir, dataDir], {
    cwd:       nodePath.join(__dirname, "..", ".."),
    env:       env,
    ceilingMs: RUN_CEILING_MS,
  });
  return { result: result, verdict: verdictOf(result) };
}

// ---- the cases --------------------------------------------------------------

// Five of the six fixtures are octet-for-octet claims. Each is named
// here with the property that makes it worth sending, so a failure says
// which shape stopped surviving the hop.
var VERBATIM = [
  ["ordinary",
    "an ordinary message reaches the peer as the octets it was given"],
  ["blankTail",
    "a message whose last line is blank keeps that line, because a blank line is body " +
    "content and the CRLF that ends it is the message's rather than the terminator's"],
  ["twoBlankTail",
    "a message ending in two blank lines keeps both, so a reading that loses one is not " +
    "read as a reading that loses none"],
  ["headerOnly",
    "a message with no body keeps the empty line that ends its header block, so a receiver " +
    "looking for the header/body separator finds the one that was sent"],
  ["dotLines",
    "lines that open with a dot survive the doubling RFC 5321 section 4.5.2 asks for and " +
    "come back to the octets that were held"],
];

function theOctetsHeldAreTheOctetsWritten(run) {
  var v = run.verdict;
  count("the outbound path reaches a peer that offers STARTTLS",
    v !== null && v.fixtures !== undefined,
    v === null ? whyNoVerdict(run) : "reached");
  if (v === null || !v.fixtures) return;

  for (var i = 0; i < VERBATIM.length; i += 1) {
    var name = VERBATIM[i][0];
    var claim = VERBATIM[i][1];
    var f = v.fixtures[name];
    count(name + ": the message is delivered, so the case is about the body rather than " +
      "about a refusal",
      f !== undefined && f.delivered === 1 && f.captured === true,
      JSON.stringify(f === undefined ? null
        : { delivered: f.delivered, failed: f.failed, deferred: f.deferred, threw: f.threw }));
    if (f === undefined || f.captured !== true) continue;

    count(name + ": " + claim,
      f.countedEquals === true,
      "held " + f.sentBytes + " octets ending " + f.sentTail + ", the peer received " +
        f.countedBytes + " ending " + f.countedTail + "; the wire carried " + f.wireBytes +
        " ending " + f.wireTail);
  }

  // The reading that costs two octets, stated as its own claim rather
  // than left implicit. Four of the five fixtures above end with a CRLF
  // the naive reading takes for the terminator's, so a run where the
  // naive reading also matched would mean the writer had stopped
  // sending that CRLF and the two errors had cancelled.
  var naiveDisagrees = ["ordinary", "blankTail", "twoBlankTail", "headerOnly", "dotLines"]
    .filter(function (name) {
      var f = v.fixtures[name];
      return f !== undefined && f.captured === true && f.naiveEquals === false;
    });
  count("a receiver that ends the message where the terminator sequence begins reads every " +
    "one of those five short, which is what makes the CRLF before the dot the sender's",
    naiveDisagrees.length === 5, naiveDisagrees.join(", ") + " disagree");
}

// The one fixture whose octets cannot survive unchanged, and the bound
// on how much they may change.
function anUnterminatedLastLineGainsExactlyOneCrlf(run) {
  var v = run.verdict;
  if (v === null || !v.fixtures) return;
  var f = v.fixtures.noTrailingCrlf;
  count("noTrailingCrlf: a message whose last line carries no terminator is still delivered",
    f !== undefined && f.delivered === 1 && f.captured === true,
    JSON.stringify(f === undefined ? null : { delivered: f.delivered, failed: f.failed }));
  if (f === undefined || f.captured !== true) return;

  count("noTrailingCrlf: it gains exactly the CRLF RFC 5321 section 2.3.8 requires on every " +
    "line and nothing else, so the writer supplies what is missing rather than deciding how " +
    "the message ends",
    f.countedBytes === f.sentBytes + 2,
    "held " + f.sentBytes + " octets ending " + f.sentTail + ", the peer received " +
      f.countedBytes + " ending " + f.countedTail);

  // Here the two readings swap places: the message did not end with a
  // CRLF, so the sequence the naive reading looks for starts at the one
  // the writer added, and it recovers the held octets exactly. Reporting
  // it keeps the pair honest about which reading is right for the reason
  // rather than for the answer.
  count("noTrailingCrlf: and this is the one fixture the two readings answer the other way " +
    "round, because the CRLF before the dot is the writer's here rather than the sender's",
    f.naiveEquals === true && f.countedEquals === false,
    "naive " + f.naiveBytes + " octets, counted " + f.countedBytes + " octets");
}

// ---- the round trip ---------------------------------------------------------

function whatOnePeerSentTheOtherReceives(run) {
  var v = run.verdict;
  count("a peer's message reaches the MX listener and the alias forwards it off this server",
    v !== null && v.captured === true,
    v === null ? whyNoVerdict(run)
      : JSON.stringify({ accepted: v.accepted, commands: v.commands }));
  if (v === null || v.captured !== true) return;

  count("the first peer's message is accepted", /^250 /.test(String(v.accepted)),
    String(v.accepted));

  // RFC 8601 section 5 has the receiver write its own
  // `Authentication-Results` header at the front, so this is a suffix
  // claim: what the first peer transmitted occurs in what the second
  // peer received once, contiguously, and at the end.
  count("the octets one peer transmitted are the octets the other peer receives, " +
    "contiguously and at the end, so a message crossing two wires is one message",
    v.suffixAt !== -1 && v.suffixAt === v.suffixExpectedAt,
    "found at " + v.suffixAt + ", expected at " + v.suffixExpectedAt + "; transmitted " +
      v.transmittedBytes + " octets ending " + v.transmittedTail + ", received " +
      v.receivedBytes + " ending " + v.receivedTail);

  count("and the header the receiver wrote is what the two lengths differ by, so nothing " +
    "else was added on the way through",
    v.receivedBytes - v.transmittedBytes === v.suffixExpectedAt &&
      /^Authentication-Results:/.test(String(v.prefix)),
    JSON.stringify(String(v.prefix).slice(0, 80)));

  // The forwarded message's last line is blank, so the reading that
  // costs two octets loses it. Stating that here is what makes the
  // suffix claim above a claim about this message rather than about a
  // message that happened to survive either reading.
  count("and the second peer reading the message where the terminator sequence begins would " +
    "have lost the blank line the first peer sent",
    v.naiveSuffixAt === -1 && v.naiveBytes === v.receivedBytes - 2,
    "naive read " + v.naiveBytes + " octets and did not find the transmitted message");
}

// ---- the filed copy ---------------------------------------------------------

function theCopyAndTheWireAreOneMessage(run) {
  var v = run.verdict;
  count("the composer sends a message and files a copy",
    v !== null && v.delivered === 1 && v.filed === true && v.captured === true,
    v === null ? whyNoVerdict(run)
      : JSON.stringify({ delivered: v.delivered, filed: v.filed, threw: v.threw }));
  if (v === null || v.captured !== true) return;

  count("the Sent copy an IMAP client is served announces a literal count matching the " +
    "octets that follow it",
    v.announced === v.present, "announced " + v.announced + ", present " + v.present);

  count("and it is octet for octet the message the peer received, so the record of what was " +
    "sent is the thing that was sent",
    v.identical === true,
    "the peer received " + v.receivedBytes + " octets ending " + v.receivedTail +
      ", the Sent copy is " + v.servedBytes + " octets ending " + v.servedTail);
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root     = helpers.tempDir("outbound-octet-fidelity");
  var certDir  = nodePath.join(root, "certs");
  var dataRoot = nodePath.join(root, "data");
  var workDir  = nodePath.join(root, "work");
  nodeFs.mkdirSync(certDir, { recursive: true });
  nodeFs.mkdirSync(dataRoot, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  try {
    var material = await certs.pair({ hostname: PEER_NAME });
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.key"), material.key, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.chain.pem"), material.chain, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "authority.pem"), material.caPem, "utf8");

    var direct = await runMode("direct", certDir, dataRoot, workDir);
    theOctetsHeldAreTheOctetsWritten(direct);
    anUnterminatedLastLineGainsExactlyOneCrlf(direct);

    whatOnePeerSentTheOtherReceives(await runMode("roundtrip", certDir, dataRoot, workDir));
    theCopyAndTheWireAreOneMessage(await runMode("sent", certDir, dataRoot, workDir));

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "outbound-octet-fidelity",
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
