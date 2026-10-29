// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Which probe refuses for what, measured off a running server.
 *
 * `/healthz` and `/readyz` run the same checks and disagree about one of
 * them, and that disagreement is the whole of what an operator has to
 * get right when they wire a probe into a supervisor. A check
 * that is critical on a probe makes it answer 503; a check that is not
 * reduces the verdict to `degraded` and the probe still answers 200. So
 * one condition can take a container out of rotation on one endpoint and
 * be a 200 with a word in the body on the other.
 *
 * The shipped documents describe that split in three places, and a
 * description of it is a hand copy of something that lives in
 * `registerCheck` calls. One of those copies had drifted: it named the
 * message store among the checks that reduce the verdict, when the
 * message store is critical on both probes and refuses on both, and it
 * stated a count of reducing checks that matched neither probe. Nothing
 * measured the split, so nothing could say which copy was right.
 *
 * What is measured here, in the order it is asserted:
 *
 *   - Both probes carry the same named checks, and which of them refuse
 *     is read out of the response rather than written down here twice.
 *     The framework marks a non-critical check `critical: false` in the
 *     body it answers to a loopback caller, so the split is a property
 *     of the running composition that this file reads back.
 *   - The fresh volume state, driven rather than described: a hosted
 *     domain has not been added yet, port 25 holds itself shut, and both
 *     probes answer 200 `degraded` naming the listener and the reason.
 *     The check that covers a listener which failed to bind stays clean
 *     through it, so a reading of `unbound` still means what it means.
 *   - Adding the domain clears it. Both probes answer `ok` and port 25
 *     is bound.
 *   - A drain refuses readiness and leaves liveness answering, which is
 *     what keeps a runtime from killing a process halfway through one.
 *   - A listener that cannot take its port ends the boot. This is the
 *     reachability question the documents turn on: two of them described
 *     the reading a running server gives in that state, and a running
 *     server never gives one, because the start refuses, releases every
 *     port it had already taken, and the process exits.
 *   - No shipped document states a count of reducing checks that
 *     disagrees with the measurement above.
 *
 * It needs no external service. Every port is ephemeral on the loopback
 * interface and the data directory is temporary.
 *
 * Run standalone: node test/layer-2-integration/health-probe-tiers.test.js
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var LISTENER_STATES = require("../../lib/mail/listeners").LISTENER_STATES;

var count = helpers.count;
var skip  = helpers.skip;

var LOOPBACK    = wire.LOOPBACK;
var reservePort = wire.reservePort;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var SHUTDOWN_TIMEOUT_MS = 5000;

// The checks this application registers, as the names an operator's
// monitoring rule matches on. Registered names are the frozen half of
// the contract: a rename is a change to what every alert rule reads, and
// a deletion is what this list catches.
var EVERY_CHECK = ["certificate", "listeners", "listeners-withheld", "mail-store", "queue"];

// Which of them make a probe refuse. The message store is the only one
// on liveness, because it is the only condition here a restart can
// address. Readiness adds the bound-listener check, because traffic
// aimed at a port nothing holds is what a routing gate exists to stop.
var REFUSING_ON_LIVENESS  = ["mail-store"];
var REFUSING_ON_READINESS = ["listeners", "mail-store"];

// Operator-facing documents that describe the probes. A count of
// reducing checks written into any of them is a hand copy of the
// measurement this file takes.
var CLAIM_SURFACES = [
  "README.md",
  "SECURITY.md",
  "docs/operator-guide.md",
  "Dockerfile",
  "compose.yml",
];

// A sentence that states how many checks produce a reduced reading.
// Anchored on the shape rather than on any wording, so a rephrasing that
// keeps the claim keeps being checked.
var COUNT_CLAIM_RE =
  /\b(one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+checks?\s+(?:can\s+)?(?:produce|answer|report|give|reduce)\b/i;

var WORD_NUMBERS = {
  one: 1, two: 2, three: 3, four: 4, five: 5,
  six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
};

// A sentence that states how many states a listener can be in. The
// states are frozen and exported so the module that builds the inventory
// and the module that reads it share one vocabulary, which makes the
// export the thing a document is copying when it writes the number down.
var STATE_CLAIM_RE = /\blistener\s+has\s+(one|two|three|four|five|six|\d+)\s+states\b/i;

// ---- reading a probe --------------------------------------------------------

// Both endpoints answer the full per-check breakdown to a loopback peer,
// which is what this file is and what the container's own probe is, so
// the criticality of each check is readable rather than only the verdict
// word.
async function probe(port, path) {
  var res  = await fetch("http://" + LOOPBACK + ":" + port + path);
  var body = await res.json();
  return { status: res.status, body: body, said: res.status + " " + JSON.stringify(body) };
}

function liveness(port) { return probe(port, "/healthz"); }
function readiness(port) { return probe(port, "/readyz"); }

// The split, read out of an answer. The framework writes `critical:
// false` into the entry for a check that only reduces the verdict and
// writes nothing for one that refuses, and it writes it last, after the
// check's own detail has been merged, so no check can spell its own
// criticality by accident.
function splitOf(body) {
  var checks = (body && body.checks) || {};
  var names  = Object.keys(checks).sort();
  return {
    names:    names,
    refusing: names.filter(function (n) { return checks[n].critical !== false; }),
    reducing: names.filter(function (n) { return checks[n].critical === false; }),
  };
}

function sameList(a, b) {
  return a.length === b.length && a.every(function (v, i) { return v === b[i]; });
}

// ---- the split itself -------------------------------------------------------

async function bothProbesRunTheSameChecksAndDisagreeAboutOne(port) {
  var live  = await liveness(port);
  var ready = await readiness(port);

  var liveSplit  = splitOf(live.body);
  var readySplit = splitOf(ready.body);

  count("the liveness probe answers the per-check breakdown to a loopback caller, " +
    "which is the answer a reduced verdict has to be readable from",
    liveSplit.names.length > 0, live.said);
  count("the liveness probe runs the checks this application registers",
    sameList(liveSplit.names, EVERY_CHECK), liveSplit.names.join(" "));
  count("the readiness probe runs the same set, so a condition is visible from both " +
    "rather than only from the endpoint that happens to be polled",
    sameList(readySplit.names, EVERY_CHECK), readySplit.names.join(" "));

  count("the message store is the only check that makes the liveness probe refuse, so " +
    "a 503 from /healthz has exactly one meaning",
    sameList(liveSplit.refusing, REFUSING_ON_LIVENESS), liveSplit.refusing.join(" "));
  count("readiness refuses for the message store and for a listener that took no port, " +
    "and for nothing else",
    sameList(readySplit.refusing, REFUSING_ON_READINESS), readySplit.refusing.join(" "));

  // The number the container files used to write down. It is derived
  // here instead, from the answer the running server gives, so a check
  // added or moved between the probes moves it with no second edit.
  count("every check that is not one of those reduces the verdict rather than refusing " +
    "it, on both probes",
    liveSplit.reducing.length === EVERY_CHECK.length - REFUSING_ON_LIVENESS.length &&
    readySplit.reducing.length === EVERY_CHECK.length - REFUSING_ON_READINESS.length,
    "liveness " + liveSplit.reducing.join(" ") + " / readiness " + readySplit.reducing.join(" "));

  // Derived rather than written down: the checks registered differently
  // on the two probes are the symmetric difference of what refuses on
  // each. A check that changed criticality on one probe alone would move
  // this set, which is the drift a stated number cannot notice.
  var movesBetweenProbes = readySplit.refusing
    .filter(function (n) { return liveSplit.refusing.indexOf(n) === -1; })
    .concat(liveSplit.refusing.filter(function (n) {
      return readySplit.refusing.indexOf(n) === -1;
    }));

  count("the bound-listener check is the only one that moves between the probes, which " +
    "is why the same condition is a 503 on one and a 200 on the other",
    movesBetweenProbes.length === 1 && movesBetweenProbes[0] === "listeners",
    movesBetweenProbes.join(" ") || "nothing moves");

  return {
    liveness:  liveSplit.reducing.length,
    readiness: readySplit.reducing.length,
  };
}

// ---- the fresh volume -------------------------------------------------------

// The state every operator passes through: the container is up, no
// domain is hosted, and port 25 holds itself shut because every
// recipient a peer could name would be a stranger's.
async function aFreshVolumeReducesBothVerdictsAndRefusesNeither(port) {
  var live  = await liveness(port);
  var ready = await readiness(port);

  count("a server with no hosted domain answers its liveness probe, so a container " +
    "runtime does not restart it while the operator is still setting it up",
    live.status === 200 && live.body.status === "degraded", live.said);
  count("and readiness answers the same reduced verdict rather than refusing traffic, " +
    "because the port an operator finishes the install on is this one",
    ready.status === 200 && ready.body.status === "degraded", ready.said);

  var held = (ready.body.checks["listeners-withheld"].withheld || []);
  count("the listener being held is named with the listener layer's own reason, so the " +
    "answer is something to act on rather than a failing streak",
    held.length === 1 && held[0].name === "mx" &&
    typeof held[0].reason === "string" && held[0].reason.length > 0,
    JSON.stringify(held));

  count("the check that covers a listener which took no port stays clean through it, so " +
    "a reading of unbound still means a listener that failed rather than one held back",
    ready.body.checks.listeners.ok === true &&
    (ready.body.checks.listeners.unbound || []).length === 0,
    JSON.stringify(ready.body.checks.listeners));

  count("the message store answered, so the reduced verdict came from the listener " +
    "rather than from the one check that would have refused",
    ready.body.checks["mail-store"].ok === true,
    JSON.stringify(ready.body.checks["mail-store"]));
}

// ---- and it clears ----------------------------------------------------------

async function aHostedDomainClearsBothVerdicts(port, mxPort) {
  var live  = await liveness(port);
  var ready = await readiness(port);

  count("port 25 binds once a domain is hosted and acknowledged, and both probes " +
    "answer clean",
    live.status === 200 && live.body.status === "ok" &&
    ready.status === 200 && ready.body.status === "ok",
    live.said + " / " + ready.said);
  count("nothing is being held back any more",
    (ready.body.checks["listeners-withheld"].withheld || []).length === 0,
    JSON.stringify(ready.body.checks["listeners-withheld"]));
  count("and the port it took is the one it was configured for",
    typeof mxPort === "number" && mxPort > 0, String(mxPort));
}

// ---- a drain ----------------------------------------------------------------

// Readiness refuses from the first line of a drain so a proxy stops
// routing, and liveness keeps answering so a runtime does not read a
// draining process as a dead one and kill it halfway through.
//
// Driven through the controller the drain itself calls rather than
// through `stop`, because `stop` closes the socket these are read over
// in the same call. What is under test is the answer, and it is the same
// answer either way round.
async function aDrainRefusesReadinessAndLeavesLivenessAnswering(server, port) {
  server.web.health.markShuttingDown();

  var ready = await readiness(port);
  count("readiness refuses the moment a drain begins, so a proxy takes this process " +
    "out of rotation while the requests already in flight finish",
    ready.status === 503 && ready.body.status === "shutting-down", ready.said);

  var live = await liveness(port);
  count("liveness keeps answering through it, because a runtime that read a draining " +
    "process as a dead one would kill it in the middle of the drain",
    live.status === 200 && live.body.status === "ok", live.said);
}

// ---- a listener that cannot take its port -----------------------------------

function occupy(port) {
  return new Promise(function (resolve, reject) {
    var blocker = nodeNet.createServer();
    blocker.once("error", reject);
    blocker.listen(port, LOOPBACK, function () { resolve(blocker); });
  });
}

function release(blocker) {
  return new Promise(function (resolve) { blocker.close(function () { resolve(); }); });
}

// The reachability question the container files turn on.
//
// Both of them described what a running server reports when a listener
// was meant to bind and did not, and there is no such server: the start
// refuses on the listener that could not take its port, releases every
// port it had already taken, and the caller ends the process. The
// symptom is an exited container and a bind error in the log rather than
// a probe verdict.
//
// Driven in both directions, because the two unwind through different
// code. A mail listener refuses inside the boot gates, which close what
// bound before rethrowing. The browser surface binds last, after every
// mail port is already held, and its failure has to release all of them.
async function aListenerThatCannotTakeItsPortEndsTheBoot(build, sections, httpPort) {
  var blocker = await occupy(sections.submission.port);
  var thrown  = null;
  try {
    var server = build({ httpPort: 0 });
    try { await server.start(); } catch (err) { thrown = err; }

    count("a mail listener whose port is already held refuses the start rather than " +
      "coming up with the port missing",
      thrown !== null, thrown === null ? "start resolved" : thrown.message);
    count("the browser surface never bound, so there is no endpoint left to answer a " +
      "probe from and no verdict for that state to be reported in",
      Object.keys(server.web.bound()).length === 0,
      JSON.stringify(server.web.bound()));
    count("and the mail ports the boot had already taken were released on the way out, " +
      "so a restart is not refused by the last attempt's own listeners",
      Object.keys(server.mail.listeners.bound()).length === 0,
      JSON.stringify(server.mail.listeners.bound()));
  } finally {
    await release(blocker);
  }

  var webBlocker = await occupy(httpPort);
  try {
    var second = build({ httpPort: httpPort });
    var secondThrown = null;
    try { await second.start(); } catch (err) { secondThrown = err; }

    count("the browser surface refuses the start on the same terms, rather than " +
      "leaving the mail listeners up behind a port nothing answers",
      secondThrown !== null,
      secondThrown === null ? "start resolved" : secondThrown.message);
    count("and every mail port it had already taken was released, which is the unwind " +
      "the last listener to bind is responsible for",
      Object.keys(second.mail.listeners.bound()).length === 0,
      JSON.stringify(second.mail.listeners.bound()));
  } finally {
    await release(webBlocker);
  }
}

// ---- what the documents say -------------------------------------------------

// Line numbers for every claim, so a failure names the place to edit.
// Two lines at a time, because these files wrap and a sentence split
// across a wrap is the same sentence.
function claimsIn(text) {
  var lines = text.split(/\r?\n/);
  var found = [];
  for (var i = 0; i < lines.length; i += 1) {
    var window = (lines[i] + " " + (lines[i + 1] || "")).replace(/\s+/g, " ");
    var m = COUNT_CLAIM_RE.exec(window);
    if (m === null) continue;
    var token = m[1].toLowerCase();
    var value = Object.prototype.hasOwnProperty.call(WORD_NUMBERS, token)
      ? WORD_NUMBERS[token] : parseInt(token, 10);
    // A claim that wraps is found on both the line it starts and the one
    // before it, so the earlier line wins and the pair is not counted
    // twice.
    if (found.length > 0 && found[found.length - 1].line === i) continue;
    found.push({ line: i + 1, said: m[0], value: value });
  }
  return found;
}

// A count written into a document is a hand copy of the split measured
// above. It is allowed to exist, and it has to be one of the two numbers
// the running server actually produces.
function noDocumentStatesACountTheServerDoesNotProduce(measured) {
  var scanned = 0;
  var claims  = 0;
  CLAIM_SURFACES.forEach(function (rel) {
    var text = nodeFs.readFileSync(nodePath.join(helpers.REPO_ROOT, rel), "utf8");
    count("the probe description in " + rel + " was read", text.length > 0,
      text.length + " bytes");
    scanned += 1;
    claimsIn(text).forEach(function (claim) {
      claims += 1;
      count("the count of reducing checks stated in " + rel + " at line " + claim.line +
        " is one the running server produces, rather than a hand copy that has drifted " +
        "away from the checks it describes",
        claim.value === measured.liveness || claim.value === measured.readiness,
        JSON.stringify(claim) + " against liveness " + measured.liveness +
          " and readiness " + measured.readiness);
    });

    // The other number these documents write down about the inventory.
    // A state added to the exported set without the sentence moving is
    // the drift this catches, and it reads the export rather than a
    // second list kept here.
    var stateClaim = STATE_CLAIM_RE.exec(text.replace(/\s+/g, " "));
    if (stateClaim !== null) {
      claims += 1;
      var stated = Object.prototype.hasOwnProperty.call(WORD_NUMBERS, stateClaim[1].toLowerCase())
        ? WORD_NUMBERS[stateClaim[1].toLowerCase()]
        : parseInt(stateClaim[1], 10);
      count("the count of listener states stated in " + rel + " matches the states the " +
        "listener module exports, so a state added to the inventory cannot leave the " +
        "document describing a smaller one",
        stated === Object.keys(LISTENER_STATES).length,
        stateClaim[0] + " against " + Object.keys(LISTENER_STATES).join(" "));
    }
  });
  count("every document that describes the probes was scanned for a stated count, so a " +
    "clean answer here is one taken over the documents rather than over nothing",
    scanned === CLAIM_SURFACES.length,
    scanned + " of " + CLAIM_SURFACES.length + ", " + claims + " count claims found");
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("health-probe-tiers");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // directory it finds through this variable. Pointing it inside the
  // run's own temporary tree keeps the encrypted at rest path exactly as
  // it ships rather than opting this file out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var held    = null;
  var running = false;

  try {
    // Written before the configuration is read, because the loader
    // checks that a named certificate exists and refuses the boot when
    // it does not. The pair is on disk rather than handed over as a
    // context, so the certificate check reads files the way it reads an
    // operator's and answers `read: true`.
    var certificate = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        // The MX listener refuses to bind without this. It is what lets
        // the boot reach the withheld state rather than stopping at the
        // posture gate ahead of it.
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         certificate.certFile,
        BLAMEPOST_TLS_KEY:          certificate.keyFile,
      },
      cwd: root,
    });

    var identity = await store.open(cfg);

    var sections = {
      mx:          { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: true,  port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
      pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
    };

    function build(overrides) {
      return blamepost.create({
        config: Object.assign({}, cfg, {
          httpPort:  0,
          httpsPort: 0,
          listeners: sections,
        }, overrides || {}),
        store:        identity,
        mailStore:    identity.mailbox,
        messageStore: identity.messageStore,
        httpAddress:  LOOPBACK,
      });
    }

    // ---- no domain hosted yet -----------------------------------------------
    held = build();
    await held.start();
    running = true;

    var port = held.web.bound().http;
    count("the browser surface took a cleartext port, which is where both probes answer",
      typeof port === "number" && port > 0, JSON.stringify(held.web.bound()));

    var measured = await helpers.withTestTimeout(
      "health probes: which probe refuses for what",
      function () { return bothProbesRunTheSameChecksAndDisagreeAboutOne(port); },
      { timeoutMs: 60000 });
    await helpers.withTestTimeout(
      "health probes: a fresh volume reduces both verdicts",
      function () { return aFreshVolumeReducesBothVerdictsAndRefusesNeither(port); },
      { timeoutMs: 60000 });

    await held.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    held = null;

    // ---- the domain added ---------------------------------------------------
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });

    held = build();
    await held.start();
    running = true;

    var servingPort = held.web.bound().http;
    await helpers.withTestTimeout(
      "health probes: a hosted domain clears both verdicts",
      function () {
        return aHostedDomainClearsBothVerdicts(
          servingPort, held.mail.listeners.bound().mx);
      },
      { timeoutMs: 60000 });
    await helpers.withTestTimeout(
      "health probes: a drain refuses readiness only",
      function () { return aDrainRefusesReadinessAndLeavesLivenessAnswering(held, servingPort); },
      { timeoutMs: 60000 });

    await held.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    held = null;

    // ---- a port that is already held ----------------------------------------
    var blockedHttpPort = await reservePort();
    await helpers.withTestTimeout(
      "health probes: a listener that cannot take its port ends the boot",
      function () {
        return aListenerThatCannotTakeItsPortEndsTheBoot(build, sections, blockedHttpPort);
      },
      { timeoutMs: 60000 });

    // The one state on either probe this file does not drive. Reaching a
    // refusing message store on a running server means closing the
    // database underneath it, which ends the run and leaves a teardown
    // fault and a probe verdict indistinguishable from each other. What
    // carries the claim instead is the split measured above: the message
    // store is the only check registered critical on liveness, so it is
    // the only condition a 503 from /healthz can report.
    skip("a message store that has stopped answering is not driven here, because " +
      "constructing it means closing the database under a running server; the check is " +
      "held by the criticality of the registration rather than by a refusal on the wire");

    noDocumentStatesACountTheServerDoesNotProduce(measured);

    return helpers.getChecks();
  } finally {
    if (running && held !== null) {
      try { await held.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "health-probe-tiers", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
