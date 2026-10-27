// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The scans a peer's own bytes drive stay linear in the length of those
 * bytes, and they reach the same verdicts they always did.
 *
 * Two surfaces are measured here, both over the wire an operator's
 * client speaks. Each one screens a value the peer chooses, and each
 * one used to walk the same characters once per position, so the cost
 * of a single request grew with the SQUARE of its length. A request
 * that stays inside every byte cap the server enforces can still take
 * a core for a noticeable fraction of a second, and a peer may send
 * them one after another.
 *
 *   - The trailing modifier list on an IMAP FETCH. A parts-spec that is
 *     a run of spaces with no parenthesis in it is the shape: the
 *     server looks for a parenthesized group at the end, does not find
 *     one, and starts again one character along. The IMAP command line
 *     is capped at 8192 bytes, so that is the whole budget a peer needs.
 *   - The smuggled-SMTP-verb screen the outbound transport runs over
 *     the assembled RFC 822 wire before it opens a socket. A carriage
 *     return is itself whitespace, so a body of carriage returns made
 *     the screen re-read the same run once per position. The bytes
 *     reach that screen from a message this server relays, so the peer
 *     that chose them need not be the one being delivered to.
 *
 * Cost is measured as a DIFFERENCE between two values of the same
 * length over the same connection, not as an absolute stopwatch
 * reading. One of the pair is the hostile shape and the other is a
 * benign shape of identical size, so the round trip, the message, the
 * store and the machine are common to both and what is left is the
 * scan. A single absolute ceiling then bounds the difference well
 * below what the quadratic form costs and well above what the linear
 * one does.
 *
 * The verdicts are pinned as hard as the timings, and they are the
 * half that matters more. A scan rewritten to walk its input once is
 * exactly the kind of change that moves an edge case: an empty value, a
 * value that is entirely the delimiter, a group that is never closed, a
 * value sitting on the byte cap. Every one of those is driven here, and
 * the answers are the answers the old spelling gave.
 *
 * It needs no external service. The ports are ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/wire-scan-linearity.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var certs     = require("../helpers/certs");
var spawn     = require("../helpers/spawn");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var visible     = wire.visible;
var LOOPBACK    = wire.LOOPBACK;

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The IMAP command line is capped at 8192 bytes, so a parts-spec is
// built to sit just under it. That cap is the budget the peer has and
// therefore the size the scan has to be measured at: a shorter line
// would understate what one request costs.
var IMAP_LINE_BUDGET = 8100;

// How many times each parts-spec is sent. The two shapes are the same
// length and go over the same connection, so everything except the scan
// cancels between them. The repeat count turns a per-call difference of
// tens of milliseconds into one large enough to read past ordinary
// scheduling noise.
var FETCH_REPEATS = 120;

// The most the hostile parts-spec may cost over the benign one across
// all the repeats. Measured on this tree, the quadratic spelling cost
// about 27 ms per call at the line cap, so 120 calls put roughly 3.2
// seconds on this difference; the single-pass spelling puts about 15
// milliseconds on it. The ceiling sits between those with room on
// both sides.
var FETCH_EXCESS_CEILING_MS = 1200;

// The outbound half runs in its own process, because the transport
// verifies the peer's certificate and the only way to make a test
// authority verifiable to it is `NODE_EXTRA_CA_CERTS`, which node reads
// at startup.
var OUTBOUND_FIXTURE = nodePath.join(__dirname, "wire-scan-outbound-fixture.js");

// Long enough that the quadratic form would finish rather than be
// killed, because a fixture that ran out of time reports nothing and
// this file needs its readings to assert on.
var OUTBOUND_RUN_CEILING_MS = 120000;

// The peer's certificate carries this name, which is resolvable
// everywhere and is nobody's real domain.
var PEER_NAME = "localhost";

// The most the larger carriage-return message may take to be screened
// and refused. The quadratic spelling took about 4.6 seconds for a
// 64 KiB body on this tree and the single pass takes a few
// milliseconds; the ceiling leaves room for the socket, the spool and a
// loaded runner without approaching what the old cost was.
var OUTBOUND_CEILING_MS = 1500;

function repeat(ch, n) { return new Array(n + 1).join(ch); }

function elapsedMs(startedAt) {
  return Number(process.hrtime.bigint() - startedAt) / 1e6;
}

// ---- the IMAP half ---------------------------------------------------------

// One FETCH round trip, returning the tagged reply.
async function fetchOnce(session, spec) {
  var tag = session.tag();
  session.send(tag + " FETCH 1 " + spec);
  return await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    "FETCH answered");
}

function ok(reply, tag) { return new RegExp("^" + tag + " OK", "m").test(reply); }

// A FETCH whose reply is expected to be OK, with the untagged line kept
// so an assertion can read what the server actually fetched.
async function fetchExpectOk(session, spec, what) {
  var tag = session.tag();
  session.send(tag + " FETCH 1 " + spec);
  var reply = await session.read(new RegExp("^" + tag + " (OK|NO|BAD)", "m"),
    what + " answered");
  count("FETCH " + what + " is answered", ok(reply, tag), visible(reply));
  return reply;
}

// Send one parts-spec `FETCH_REPEATS` times and return the wall clock
// the whole run took.
async function timeFetchRun(session, spec, what) {
  var startedAt = process.hrtime.bigint();
  var failures = 0;
  for (var i = 0; i < FETCH_REPEATS; i += 1) {
    var reply = await fetchOnce(session, spec);
    if (!/^\S+ OK/m.test(reply)) failures += 1;
  }
  var took = elapsedMs(startedAt);
  count(FETCH_REPEATS + " FETCH round trips with " + what +
    " are all answered, so the two runs did the same work",
    failures === 0, failures + " of " + FETCH_REPEATS + " were not OK");
  return took;
}

// ---- the outbound half -----------------------------------------------------

// The fixture's one machine-readable line.
function verdictOf(result) {
  var line = String(result.out || "").split(/\r?\n/).filter(function (l) {
    return l.indexOf("VERDICT ") === 0;
  }).pop();
  if (!line) return null;
  try { return JSON.parse(line.slice("VERDICT ".length)); }
  catch (_e) { return null; }
}

// What a refusal said, whichever way the handle reported it. A
// rejection may arrive as a throw or as a per recipient verdict, and
// the assertion is about the screen having run either way.
function refusalText(result) {
  return (result.threw || "") + " " + (result.reasons || "");
}

// The screen this file is about is the one the outbound transport runs
// over the assembled RFC 822 wire, and it names itself in the refusal.
function refusedByOutboundScreen(result) {
  return /failed guardEmail/.test(refusalText(result));
}

// ---- the run ---------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("wire-scan-linearity");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  var sendDir = nodePath.join(root, "send");
  var certDir = nodePath.join(root, "certs");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.mkdirSync(nodePath.join(sendDir, "queue"), { recursive: true });
  nodeFs.mkdirSync(certDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;
  try {
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });

    var identity = helpers.closeWithTempDir(root, await store.open(cfg));
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({ domain: DOMAIN, by: "wire scan linearity test" });
    var alice = await identity.accounts.create({
      address: "alice@" + DOMAIN, password: ALICE_PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, listeners: sections, inbound: { mode: "monitor" },
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var session = await Wire.imap(sections.imap.port, {
      caPem: leaf.ca, servername: HOSTNAME,
      address: alice.address, password: ALICE_PASSWORD,
      label: "wire-scan-linearity-alice",
    });

    // One message to fetch, so every FETCH below does the same amount
    // of real work and the difference between two runs is the scan.
    var appendTag = session.tag();
    await session.sendLiteral(appendTag + " APPEND INBOX", [
      "From: sender@example.net",
      "To: " + alice.address,
      "Subject: a message to fetch",
      "Message-ID: <scan-linearity-fixture@example.net>",
      "",
      "The body the repeated fetches read.",
      "",
    ].join("\r\n"), "the fixture message");
    var appendReply = await session.read(
      new RegExp("^" + appendTag + " (OK|NO|BAD)", "m"), "APPEND answered");
    count("the mailbox holds a message, so every FETCH below reads the same bytes",
      ok(appendReply, appendTag), visible(appendReply));

    var selectTag = session.tag();
    session.send(selectTag + " SELECT INBOX");
    var selectReply = await session.read(
      new RegExp("^" + selectTag + " (OK|NO|BAD)", "m"), "SELECT answered");
    count("alice selects INBOX", ok(selectReply, selectTag), visible(selectReply));

    // ---- IMAP: the verdicts the modifier scan reaches --------------------
    //
    // The trailing parenthesized group is read off the END of the
    // parts-spec and what is left is handed to the store. These pin the
    // four shapes where a single-pass reader could differ from the
    // pattern it replaces: no group, a group with something after it, a
    // group nested inside the fetch-att itself, and a group with
    // whitespace after it.

    await fetchExpectOk(session, "(UID)", "a parts-spec with no modifier list");
    await fetchExpectOk(session, "(UID) (CHANGEDSINCE 0)",
      "a modifier list at the end");
    await fetchExpectOk(session, "(UID) (CHANGEDSINCE 0)   ",
      "a modifier list with whitespace after it");
    await fetchExpectOk(session, "BODY[HEADER.FIELDS (FROM TO)]",
      "a parenthesized group inside the fetch-att and no modifier list");
    await fetchExpectOk(session, "BODY[HEADER.FIELDS (FROM TO)] (CHANGEDSINCE 0)",
      "a modifier list after a fetch-att that itself carries parentheses");

    // CHANGEDSINCE is read off that group, so a modseq higher than
    // anything in the mailbox must return no message at all. This is the
    // assertion that the group's BODY was read rather than merely
    // located: a reader that found the group and dropped its text would
    // pass every check above and fail this one.
    var highTag = session.tag();
    session.send(highTag + " FETCH 1:* (UID) (CHANGEDSINCE 4294967295)");
    var highReply = await session.read(
      new RegExp("^" + highTag + " (OK|NO|BAD)", "m"), "a high CHANGEDSINCE answered");
    count("CHANGEDSINCE above every modseq in the mailbox reports no message, " +
      "so the modifier list's text was read and not just found",
      ok(highReply, highTag) && !/^\* \d+ FETCH/m.test(highReply), visible(highReply));

    var lowTag = session.tag();
    session.send(lowTag + " FETCH 1:* (UID) (CHANGEDSINCE 0)");
    var lowReply = await session.read(
      new RegExp("^" + lowTag + " (OK|NO|BAD)", "m"), "a low CHANGEDSINCE answered");
    count("CHANGEDSINCE 0 reports the message, so the same reader answers both ways",
      ok(lowReply, lowTag) && /^\* \d+ FETCH/m.test(lowReply), visible(lowReply));

    // ---- IMAP: what the scan costs at the line cap ------------------------
    //
    // Both specs are the same length and both end the same FETCH. The
    // hostile one ends in a run of spaces with no parenthesis anywhere
    // after the fetch-att, which is the value that has nothing to find
    // and so was searched for from every position. The benign one ends
    // in a group, which the pattern finds on its first successful
    // attempt.

    // The fetch-att carries NO parentheses of its own. One that did
    // would be found by the pattern at the first position it tried, and
    // the run of spaces after it would never be searched: a
    // `(UID)` prefix makes both shapes cheap and measures nothing.
    var benignTail  = " (CHANGEDSINCE 0)";
    var attribute   = "UID";
    var padding     = IMAP_LINE_BUDGET - attribute.length - benignTail.length;
    var hostileSpec = attribute + repeat(" ", padding + benignTail.length);
    var benignSpec  = attribute + repeat(" ", padding) + benignTail;
    count("the two parts-specs are the same length, so only their shape differs",
      hostileSpec.length === benignSpec.length,
      hostileSpec.length + " vs " + benignSpec.length);
    count("the hostile parts-spec carries no parenthesis for the modifier scan " +
      "to find, which is what makes it the shape being measured",
      hostileSpec.indexOf("(") === -1 && benignSpec.indexOf("(") !== -1,
      "hostile has " + (hostileSpec.indexOf("(") === -1 ? "none" : "one"));

    // Run each twice and keep the second reading. The first run pays for
    // the store's own first fetch of the message and for whatever the
    // engine compiles on the way through, and that cost belongs to
    // neither shape.
    await timeFetchRun(session, benignSpec,  "the benign parts-spec, warming");
    await timeFetchRun(session, hostileSpec, "the hostile parts-spec, warming");
    var benignMs  = await timeFetchRun(session, benignSpec,  "the benign parts-spec");
    var hostileMs = await timeFetchRun(session, hostileSpec, "the hostile parts-spec");
    var excessMs  = hostileMs - benignMs;

    // Printed whether the check passes or fails. A ceiling that holds
    // says nothing about how much room was left, and the next person to
    // move the ceiling needs the reading rather than the verdict.
    console.log("MEASURED imap-fetch hostile=" + hostileMs.toFixed(0) +
      "ms benign=" + benignMs.toFixed(0) + "ms excess=" + excessMs.toFixed(0) +
      "ms over " + FETCH_REPEATS + " requests at a " + IMAP_LINE_BUDGET + "-byte line");

    count("a parts-spec with nothing for the modifier scan to find costs no more " +
      "than " + FETCH_EXCESS_CEILING_MS + " ms over " + FETCH_REPEATS +
      " requests than one of the same length that it finds immediately",
      excessMs < FETCH_EXCESS_CEILING_MS,
      "hostile " + hostileMs.toFixed(0) + " ms, benign " + benignMs.toFixed(0) +
      " ms, difference " + excessMs.toFixed(0) + " ms over " + FETCH_REPEATS +
      " requests at a " + IMAP_LINE_BUDGET + "-byte line");

    session.send(session.tag() + " LOGOUT");
    session.close();

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;

    // ---- outbound: the smuggling screen over the assembled wire ----------

    var material = await certs.pair({ hostname: PEER_NAME });
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.key"), material.key, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "peer.chain.pem"), material.chain, "utf8");
    nodeFs.writeFileSync(nodePath.join(certDir, "authority.pem"), material.caPem, "utf8");

    var outbound = await spawn.runNodeScript([OUTBOUND_FIXTURE, certDir, sendDir], {
      cwd:       nodePath.join(__dirname, "..", ".."),
      env:       Object.assign({}, process.env, {
        NODE_EXTRA_CA_CERTS: nodePath.join(certDir, "authority.pem"),
        BLAMEJS_TMPDIR:      workDir,
      }),
      ceilingMs: OUTBOUND_RUN_CEILING_MS,
    });
    var v = verdictOf(outbound);
    count("the outbound fixture reported its readings",
      v !== null, spawn.lastLines(outbound.out, 6));

    if (v !== null) {
      console.log("MEASURED outbound-screen small=" + v.small.ms.toFixed(0) +
        "ms at " + v.smallBytes + " bytes, large=" + v.large.ms.toFixed(0) +
        "ms at " + v.largeBytes + " bytes, ordinary=" + v.plain.ms.toFixed(0) + "ms");

      // An ordinary message goes out, which is what makes the refusals
      // below a verdict about the message rather than about the peer.
      count("an ordinary message reaches the peer, so the transport is working",
        v.plain.delivered === 1 && v.plain.threw === null,
        "delivered " + v.plain.delivered + ", threw " + v.plain.threw +
        ", reasons " + v.plain.reasons);

      // The shape the screen exists for: a bare carriage return followed
      // by an SMTP verb. It must be refused rather than relayed, and the
      // refusal must name the smuggling finding rather than only the
      // bare carriage return, because the two are different findings and
      // only one of them is the attack.
      count("a message carrying a bare line ending followed by an SMTP verb is " +
        "refused rather than sent, and the refusal names the smuggling finding",
        v.smuggle.delivered === 0 && /smtp-smuggling/.test(refusalText(v.smuggle)),
        "delivered " + v.smuggle.delivered + ", threw " + v.smuggle.threw +
        ", reasons " + v.smuggle.reasons);

      // Two bodies of carriage returns, the larger four times the
      // smaller. Both are refused by the same screen with the same
      // finding, and the larger does not cost sixteen times the smaller.
      count("a body of " + v.smallBytes + " carriage returns is refused by the " +
        "outbound screen, naming the bare carriage return",
        v.small.delivered === 0 && refusedByOutboundScreen(v.small) &&
        /bare-cr/.test(refusalText(v.small)),
        "delivered " + v.small.delivered + ", threw " + v.small.threw +
        ", reasons " + v.small.reasons + ", took " + v.small.ms.toFixed(0) + " ms");
      count("a body of " + v.largeBytes + " carriage returns draws the same " +
        "finding, so four times the value did not change the verdict",
        v.large.delivered === 0 && refusedByOutboundScreen(v.large) &&
        v.large.reasons === v.small.reasons,
        "delivered " + v.large.delivered + ", threw " + v.large.threw +
        ", reasons " + v.large.reasons + " against " + v.small.reasons +
        ", took " + v.large.ms.toFixed(0) + " ms");

      // A body of carriage returns is not the smuggling shape, and
      // saying so is what keeps the vector above meaningful: if every
      // carriage return drew the smuggling finding, the pair would be
      // measuring one verdict twice.
      count("a body of carriage returns alone is not read as smuggling",
        !/smtp-smuggling/.test(refusalText(v.large)), v.large.reasons);

      count("screening a " + v.largeBytes + "-byte body of carriage returns " +
        "takes under " + OUTBOUND_CEILING_MS + " ms",
        v.large.ms < OUTBOUND_CEILING_MS,
        v.large.ms.toFixed(0) + " ms for " + v.largeBytes + " bytes, against " +
        v.small.ms.toFixed(0) + " ms for " + v.smallBytes);

      // Four times the input may not cost sixteen times the time. The
      // bound is loose because both readings are small once the scan is
      // linear, and a small reading is mostly the socket and the spool.
      count("four times the carriage returns does not cost the square of the time",
        v.large.ms < (v.small.ms * 8) + 250,
        v.small.ms.toFixed(1) + " ms at " + v.smallBytes + " bytes, " +
        v.large.ms.toFixed(1) + " ms at " + v.largeBytes);
    }

    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "wire-scan-linearity", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count_) {
    console.log("CHECKS " + count_);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
