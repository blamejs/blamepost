// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A transport-security failure observed while the reporter is deciding
 * what to do with the file it is recorded in.
 *
 * RFC 8460 makes this server a reporter for every receiver it delivers
 * to, and the accumulator under `<dataDir>/tlsrpt` is the only place a
 * failure against a peer is written down. Nothing else on this server
 * holds it: no row, no counter, no log line a report is composed from.
 * So a run that destroys that file destroys the evidence, and the
 * receiver never hears that a session with them failed. That is the one
 * signal an operator on the far side has for a downgrade attack or a
 * policy that has stopped working.
 *
 * Writes to one domain's file are serialized, because a relay makes
 * many attempts against one receiver at once and a read-modify-write
 * per attempt would keep only the last. The reporting run touches the
 * same file, and the trap is that it can decide what to do OUTSIDE that
 * serialization and act INSIDE it. Between the two, delivery goes on:
 * the module's whole purpose is to be running while mail is moving. A
 * failure that lands in that gap is written into a file the run has
 * already judged to be something else, and the act destroys it.
 *
 * `_tlsRptSettle` in the same module is the shape that gets this right:
 * it takes the reading again inside the turn that writes, and it
 * subtracts what a report carried rather than removing the file, so
 * anything that arrived while the report was in flight survives. Both
 * vectors here hold the two whole-file removals against that same rule.
 *
 * The interleaving is arranged rather than raced. A test that sent mail
 * and hoped it overlapped a run would reproduce the failure only
 * sometimes, which is worse than no test. Instead one call parks until
 * this file releases it, and every other call runs the real primitive
 * untouched: the same reporter, the same accumulator, the same order.
 * Only the moment the parked call answers is this file's to choose.
 *
 * No sockets. The resolver answers from a table and the submission goes
 * to a recording client.
 *
 * Run standalone: node test/layer-1-state/tlsrpt-observation-window.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var b         = require("../../lib/vendor/blamejs");
var posture   = require("../../lib/mail/posture");
var blamepost = require("../../lib");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var MESSAGE  = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// How long a parked call may wait for the run that is supposed to reach
// it. Generous, because the work landing there reads and writes the
// volume, and a fixed budget is what a loaded runner gets wrong.
var PARK_TIMEOUT_MS = 30000;

// The two whole-file removals this file answers for, printed at the end
// as the unit examined. A run that drove one of them and a run that
// drove both otherwise report the same check total and neither says
// which happened.
var REMOVALS_EXAMINED = 2;

// A receiver that wants reports and whose MTA-STS record cannot be
// looked up, which is a real RFC 8460 policy failure rather than a
// local fault, so an attempt to it is something the receiver is owed.
var WANTS_REPORTS = {
  "example.net":            { mx: ["mx.example.net"] },
  "_mta-sts.example.net":   zone.FAILING,
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=https://reports.example.net/tlsrpt"] },
};

// The same receiver with no TLS-RPT record at all, which is what most
// of the internet looks like.
var WANTS_NOTHING = {
  "example.org":          { mx: ["mx.example.org"] },
  "_mta-sts.example.org": zone.FAILING,
};

function handleOn(dataDir, resolver) {
  return blamepost.mail.delivery.create({
    hostname:   HOSTNAME,
    dataDir:    dataDir,
    postmaster: "postmaster@example.com",
    resolver:   resolver,
    policy:     { mtaSts: "enforce", dane: "off" },
    audit:      false,
  });
}

function sendTo(delivery, recipient) {
  return delivery.send({
    from:   "alice@example.com",
    to:     [recipient],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
}

function recordingClient() {
  var posts = [];
  return {
    posts: posts,
    request: async function (opts) {
      posts.push(opts);
      return { statusCode: 202, headers: {}, body: "" };
    },
  };
}

async function domainRow(delivery, domain) {
  var rows = (await delivery.tlsRpt.observed()).filter(function (r) {
    return r.domain === domain;
  });
  return rows.length === 1 ? rows[0] : null;
}

// The accumulator as it is on disk, by the name the module builds. Read
// directly so a vector can plant one and can see a write land without
// going back through the reader under test.
function recordPath(dataDir, domain) {
  return nodePath.join(dataDir, "tlsrpt", "d." + domain + ".json");
}

// An accumulator carrying no observations. It is the state the run
// treats as nothing owed and removes, and it is reachable on a volume
// whose last write was cut short.
function plantEmptyRecord(dataDir, domain) {
  nodeFs.mkdirSync(nodePath.join(dataDir, "tlsrpt"), { recursive: true });
  nodeFs.writeFileSync(recordPath(dataDir, domain), JSON.stringify({
    domain:       domain,
    since:        Date.now() - 60000,
    policyType:   "no-policy-found",
    policyString: [],
    mxHosts:      [],
    successful:   0,
    failures:     [],
  }, null, 2), "utf8");
}

// ---------------------------------------------------------------------------
// The seams
// ---------------------------------------------------------------------------

// The accumulator read, wrapped so one read of one file parks. The
// reading is TAKEN at the moment the caller asked for it and handed back
// when this file says so, because what the window is made of is a caller
// holding a description of the file as it stood earlier.
function installRecordReadGate(target) {
  var real  = b.atomicFile.readJson;
  var state = { parked: null, calls: 0 };
  b.atomicFile.readJson = function (path) {
    if (state.parked !== null || String(path) !== target) {
      return real.apply(b.atomicFile, arguments);
    }
    state.calls += 1;
    var taken = Promise.resolve(real.apply(b.atomicFile, arguments))
      .then(function (v) { return { value: v, error: null }; },
        function (e) { return { value: null, error: e }; });
    return new Promise(function (resolve, reject) {
      state.parked = { taken: taken, resolve: resolve, reject: reject };
    });
  };
  state.release = function () {
    var held = state.parked;
    if (held === null) throw new Error("installRecordReadGate: nothing is parked to release");
    return held.taken.then(function (settled) {
      if (settled.error !== null) held.reject(settled.error);
      else held.resolve(settled.value);
    });
  };
  state.remove = function () { b.atomicFile.readJson = real; };
  return state;
}

// The receiver's own zone reading, wrapped the same way. It stands on
// the posture module's exported object, which is what the reporter binds
// at require time, so the run reaches it without knowing anything
// happened.
function installEndpointGate(wanted) {
  var real  = posture.tlsRptEndpoint;
  var state = { parked: null, calls: 0 };
  posture.tlsRptEndpoint = function (domain) {
    var args = arguments;
    if (state.parked !== null || domain !== wanted) return real.apply(posture, args);
    state.calls += 1;
    return new Promise(function (resolve, reject) {
      state.parked = { args: args, resolve: resolve, reject: reject };
    });
  };
  state.release = function () {
    var held = state.parked;
    if (held === null) throw new Error("installEndpointGate: nothing is parked to release");
    return Promise.resolve(real.apply(posture, held.args)).then(held.resolve, held.reject);
  };
  state.remove = function () { posture.tlsRptEndpoint = real; };
  return state;
}

function parked(gate, what) {
  return helpers.waitUntil(function () { return gate.parked !== null; }, {
    timeoutMs: PARK_TIMEOUT_MS,
    label:     "tlsrpt-observation-window: " + what,
  });
}

// ---------------------------------------------------------------------------
// The accumulator the run judged to be empty
// ---------------------------------------------------------------------------

// The run reads a file carrying nothing, concludes there is nothing to
// report, and removes it. A failure written into that file between the
// reading and the removal is the first thing this server has ever had to
// say about that receiver, and removing the file takes it with no error
// anywhere and nothing left to report next time.
async function aFailureWrittenWhileAnEmptyRecordIsBeingRemovedSurvives(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(WANTS_REPORTS));
  plantEmptyRecord(dataDir, "example.net");
  count("the receiver's accumulator carries no observations, so the run will remove it",
    (await domainRow(delivery, "example.net")) !== null &&
      (await domainRow(delivery, "example.net")).failed === 0,
    JSON.stringify(await domainRow(delivery, "example.net")));

  var client = recordingClient();
  var gate = installRecordReadGate(recordPath(dataDir, "example.net"));
  var ran;
  try {
    var running = delivery.tlsRpt.run({ httpClient: client });
    var caught = running.then(function (r) { return r; }, function (e) { return e; });
    await parked(gate, "the run taking its reading of the receiver's accumulator");

    await sendTo(delivery, "bob@example.net");
    var onDisk = JSON.parse(nodeFs.readFileSync(recordPath(dataDir, "example.net"), "utf8"));
    count("a session with the receiver fails while the run holds that reading",
      Array.isArray(onDisk.failures) && onDisk.failures.length === 1,
      JSON.stringify(onDisk.failures));

    await gate.release();
    ran = await caught;
  } finally {
    gate.remove();
  }

  count("the run answers rather than raising", ran !== null && typeof ran === "object" &&
    Array.isArray(ran.results), JSON.stringify(ran));

  var row = await domainRow(delivery, "example.net");
  count("and the failure written inside the window is still there to be reported",
    row !== null && row.failed === 1, JSON.stringify(row));
}

// ---------------------------------------------------------------------------
// The accumulator for a receiver that publishes no endpoint
// ---------------------------------------------------------------------------

// Nobody asked for reports, so what the run judged is not owed to
// anybody and goes. What arrives while the receiver's zone is being read
// was never judged, and the zone can say something different by the time
// the next run asks: a receiver that publishes a TLS-RPT record tomorrow
// is owed what failed today.
async function aFailureWrittenWhileTheZoneIsBeingReadSurvives(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(WANTS_NOTHING));
  await sendTo(delivery, "bob@example.org");
  var before = await domainRow(delivery, "example.org");
  count("one session with the receiver has failed", before !== null && before.failed === 1,
    JSON.stringify(before));

  var client = recordingClient();
  var gate = installEndpointGate("example.org");
  try {
    var running = delivery.tlsRpt.run({ httpClient: client });
    var caught = running.then(function (r) { return r; }, function (e) { return e; });
    await parked(gate, "the run reading the receiver's own zone");

    await sendTo(delivery, "carol@example.org");
    var onDisk = JSON.parse(nodeFs.readFileSync(recordPath(dataDir, "example.org"), "utf8"));
    var written = onDisk.failures.reduce(function (n, r) { return n + r.count; }, 0);
    count("a second session fails while the run is reading that zone", written === 2,
      JSON.stringify(onDisk.failures));

    await gate.release();
    await caught;
  } finally {
    gate.remove();
  }

  count("nothing is posted to a receiver that asked for nothing", client.posts.length === 0,
    String(client.posts.length));

  var after = await domainRow(delivery, "example.org");
  count("what the run judged is gone, because nobody asked for it, and what arrived after it " +
    "judged is kept",
    after !== null && after.failed === 1, JSON.stringify(after));
}

// The same removal with nothing arriving beside it, so the vector above
// reads as the window closing rather than as the reporter having stopped
// clearing what nobody wants.
async function anUncontestedNoEndpointRunStillClearsTheAccumulator(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(WANTS_NOTHING));
  await sendTo(delivery, "bob@example.org");
  count("the attempt was observed", (await domainRow(delivery, "example.org")) !== null,
    JSON.stringify(await domainRow(delivery, "example.org")));

  var client = recordingClient();
  var ran = await delivery.tlsRpt.run({ httpClient: client });

  count("the run says the receiver published no endpoint",
    ran.results.length === 1 && ran.results[0].outcome === "no-endpoint",
    JSON.stringify(ran.results));
  count("and the accumulator is cleared, because nobody is owed it",
    (await domainRow(delivery, "example.org")) === null,
    JSON.stringify(await domainRow(delivery, "example.org")));
  count("nothing is counted as unsent, because nothing was owed",
    delivery.describe().tlsRpt.reportsUnsent === 0,
    String(delivery.describe().tlsRpt.reportsUnsent));
}

// And the empty accumulator with nothing arriving beside it, so the
// first vector reads the same way.
async function anUncontestedEmptyRecordIsStillRemoved(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(WANTS_REPORTS));
  plantEmptyRecord(dataDir, "example.net");

  var client = recordingClient();
  var ran = await delivery.tlsRpt.run({ httpClient: client });

  count("an accumulator carrying nothing draws no report", client.posts.length === 0 &&
    ran.results.length === 0, JSON.stringify(ran));
  count("and it is taken off the volume rather than left to be read on every run",
    !nodeFs.existsSync(recordPath(dataDir, "example.net")),
    JSON.stringify(nodeFs.readdirSync(nodePath.join(dataDir, "tlsrpt"))));
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
    await helpers.withTestTimeout(
      "tlsrpt-observation-window: a failure written while an empty record is being removed",
      function () {
        return aFailureWrittenWhileAnEmptyRecordIsBeingRemovedSurvives(freshDir("tlsrpt-win-empty"));
      });
    await helpers.withTestTimeout(
      "tlsrpt-observation-window: a failure written while the zone is being read",
      function () {
        return aFailureWrittenWhileTheZoneIsBeingReadSurvives(freshDir("tlsrpt-win-zone"));
      });
    await helpers.withTestTimeout(
      "tlsrpt-observation-window: an uncontested no-endpoint run still clears the accumulator",
      function () {
        return anUncontestedNoEndpointRunStillClearsTheAccumulator(freshDir("tlsrpt-win-none"));
      });
    await helpers.withTestTimeout(
      "tlsrpt-observation-window: an uncontested empty record is still removed",
      function () {
        return anUncontestedEmptyRecordIsStillRemoved(freshDir("tlsrpt-win-plain"));
      });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = {
  name:      "tlsrpt-observation-window",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// whole-file removal and a run that drove both otherwise report the same
// total and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + REMOVALS_EXAMINED + " accumulator-removal");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
