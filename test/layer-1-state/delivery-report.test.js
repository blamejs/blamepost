// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The one thing a message must never do is disappear with nobody told.
 *
 * When a peer refuses permanently, the composer builds the report the
 * sender is owed and hands it to this server's hook. The hook is where
 * the record of that report is made, and the record is the only thing
 * standing between a sender and silence while a report cannot reach the
 * wire.
 *
 * There is a path where the hook never runs at all. The report is built
 * before the hook is called, from the original sender address, the
 * failed recipient and the enhanced status, and its header guards refuse
 * a value that could smuggle report headers. When they refuse, the
 * composer records its own reason for that and reports the recipient as
 * failed with no report sent. Everything after that ran as though the
 * sender had been told: the sweep took the message off disk, no counter
 * moved, and no line said so.
 *
 * That is the same silent-at-both-ends shape the retry budget once
 * produced, arriving by a different door, so it is pinned the same way:
 * both on the direct send and on the sweep, because those are two
 * separate places the message can be dropped.
 *
 * Run standalone: node test/layer-1-state/delivery-report.test.js
 */

var helpers   = require("../helpers");
var blamepost = require("../../lib");

var check = helpers.check;
var fs    = helpers.fs;
var path  = helpers.path;

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// A domain publishing the RFC 7505 null MX, which the composer reads as
// a permanent refusal on the first look.
var REFUSING_MX = {
  queryMx: function () {
    return Promise.resolve([{ priority: 0, exchange: "" }]);
  },
};

var UNREACHABLE_MX = {
  queryMx: function () {
    return Promise.reject(new Error("probe resolver: MX lookup unavailable"));
  },
};

// A reverse path carrying a header separator. The report is addressed
// to whoever sent the message, so this value reaches the report's own
// header block, and the guard that builds the report refuses it there.
var SMUGGLING_SENDER = "alice@example.com\r\nX-Injected: yes";

function handleOn(dataDir, resolver, extra) {
  var opts = {
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: resolver,
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
  };
  if (extra) Object.assign(opts, extra);
  return blamepost.mail.delivery.create(opts);
}

function spoolFiles(dataDir) {
  var dir = path.join(dataDir, "queue");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).sort();
}

function onlyId(dataDir) {
  var files = spoolFiles(dataDir);
  return files.length ? files[0].replace(/\.(json|eml)$/, "") : null;
}

function readDescriptor(dataDir, id) {
  return JSON.parse(fs.readFileSync(path.join(dataDir, "queue", id + ".json"), "utf8"));
}

function writeDescriptor(dataDir, id, descriptor) {
  fs.writeFileSync(path.join(dataDir, "queue", id + ".json"),
    JSON.stringify(descriptor, null, 2), "utf8");
}

// ---------------------------------------------------------------------------

async function aReportThatCouldNotBeBuiltIsStillRecorded(dataDir) {
  var delivery = handleOn(dataDir, REFUSING_MX);

  var outcome = await delivery.send({
    from:   SMUGGLING_SENDER,
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });

  check("the recipient is permanently refused",
    outcome.failed.length === 1 && outcome.deferred.length === 0);
  check("and the composer says outright that no report went with it",
    outcome.failed[0].dsnSent !== true);
  check("the sender is counted as owed a report nobody sent",
    delivery.describe().reportsUnsent === 1);
  check("nothing is left in the spool for a message nowhere will take",
    spoolFiles(dataDir).length === 0);
}

// The same failure reaching the sweep instead of the send, which is
// where it costs a message that is already on disk.
async function aSweepDoesNotDropAMessageInSilence(dataDir) {
  var spooler = handleOn(dataDir, UNREACHABLE_MX);
  await spooler.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  var id = onlyId(dataDir);
  check("a message is waiting to be retried", id !== null);

  // Stand the entry up as one whose sender address cannot be put in a
  // report header, which is what an older build or a peer that got past
  // the wire guard leaves behind.
  var descriptor = readDescriptor(dataDir, id);
  descriptor.from = SMUGGLING_SENDER;
  writeDescriptor(dataDir, id, descriptor);

  var delivery = handleOn(dataDir, REFUSING_MX);
  var run = await delivery.queue.runDue({ force: true });

  check("the sweep reports the entry as permanently refused",
    run.results.length === 1 && run.results[0].outcome === "failed");
  check("the message leaves the spool, because nowhere will take it",
    spoolFiles(dataDir).length === 0);
  check("but the sender it could not tell is counted",
    delivery.describe().reportsUnsent === 1);
}

// The ordinary permanent refusal moves the counter not at all, because
// the sender was told. The counter stays readable as the number of
// senders who heard nothing, so a report that went out must never
// appear in it.
async function anOrdinaryRefusalIsNotCountedAsUnsent(dataDir) {
  var delivery = handleOn(dataDir, REFUSING_MX);

  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("the report was built and sent",
    outcome.failed.length === 1 && outcome.failed[0].dsnSent === true);
  check("and nobody is counted as a sender who heard nothing",
    delivery.describe().reportsUnsent === 0);

  // A message that arrived with the empty reverse path has nobody to
  // tell, which is a correct silence and must not move the counter
  // either.
  var loopSafe = handleOn(dataDir, REFUSING_MX);
  var quiet = await loopSafe.send({
    from:   "<>",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("a report about a report is not generated at all",
    quiet.failed.length === 1 && quiet.failed[0].dsnSent === false);
  check("and is not counted as one this server owes",
    loopSafe.describe().reportsUnsent === 0);
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
    await helpers.withTestTimeout("delivery report: a report that could not be built is still recorded",
      function () { return aReportThatCouldNotBeBuiltIsStillRecorded(freshDir("dlv-rep-build")); });
    await helpers.withTestTimeout("delivery report: a sweep does not drop a message in silence",
      function () { return aSweepDoesNotDropAMessageInSilence(freshDir("dlv-rep-sweep")); });
    await helpers.withTestTimeout("delivery report: an ordinary refusal is not counted as unsent",
      function () { return anOrdinaryRefusalIsNotCountedAsUnsent(freshDir("dlv-rep-once")); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "delivery-report", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
