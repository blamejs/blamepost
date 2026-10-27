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
 * A third door is the report's own delivery. A report is a message and
 * goes out over the same outbound path as any other, so the path can
 * refuse it the moment it is handed over: the sender's own domain
 * publishes no mail exchanger, or publishes the RFC 7505 null MX. The
 * sender then hears nothing, and every reader that answers whether they
 * were told has to say so.
 *
 * Which is why the zone each case runs against is chosen rather than
 * shared. A resolver that refuses the sender's domain as well as the
 * recipient's refuses the report too, so a count of nought read against
 * it cannot tell a report that went from one nobody will ever receive.
 * The cases that assert nothing was owed publish a sender domain the
 * report can actually be handed to, and check that it reached the queue.
 *
 * Run standalone: node test/layer-1-state/delivery-report.test.js
 */

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;
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

// The recipient's domain publishes no mail exchanger, so the message is
// permanently refused. The sender's domain is absent from the zone
// entirely, which answers as a name that does not exist and is the
// ordinary transient, so the report about the refusal reaches the
// outbound queue and waits there.
var REPORT_CAN_LEAVE = {
  "example.net": { mx: [] },
};

// Both domains publish no mail exchanger, so the report composed about
// the refused message is itself permanently refused the moment it is
// handed over.
var REPORT_REFUSED_TOO = {
  "example.net": { mx: [] },
  "example.com": { mx: [] },
};

// The recipient's domain is absent, so the message defers and reaches
// the spool. The sender's domain publishes no mail exchanger, so a
// report about the message an operator then cancels cannot be delivered.
var CANCELLED_SENDER_UNREACHABLE = {
  "example.com": { mx: [] },
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
  var delivery = handleOn(dataDir, zone.resolverOver(REPORT_CAN_LEAVE));

  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("the report was built and handed to the outbound path",
    outcome.failed.length === 1 && outcome.failed[0].dsnSent === true);
  // The report has to be somewhere for a count of nought to mean the
  // sender was told. Asserting the counter alone passes just as readily
  // on a report the outbound path refused outright, which is the state
  // this case exists to be distinguishable from.
  check("and it is waiting in the outbound queue rather than gone",
    delivery.queue.count() === 1);
  check("so nobody is counted as a sender who heard nothing",
    delivery.describe().reportsUnsent === 0);

  // A message that arrived with the empty reverse path has nobody to
  // tell, which is a correct silence and must not move the counter
  // either.
  var loopSafe = handleOn(dataDir, zone.resolverOver(REPORT_CAN_LEAVE));
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
// A report the outbound path refuses the moment it is handed over
// ---------------------------------------------------------------------------

// The report is composed, the generation bound admits it, and the
// outbound path answers that the sender's own domain will not take mail.
// Nothing is retried and nothing is queued: that sender will never
// receive the report, and the message they sent is already off the
// volume.
//
// So this is the same outcome as a report the bound suppressed and a
// report the composer could not build, and it has to reach the same four
// readers: the counter describe() publishes, the audit trail, the
// operator's log, and the outcome the caller reads back. A path that
// records nothing leaves an operator with a queue that drains, a trail
// with no refusals in it, and senders who were never told.
async function aReportTheOutboundPathRefusesIsCountedAsUnsent(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(REPORT_REFUSED_TOO));

  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });

  check("the recipient is permanently refused",
    outcome.failed.length === 1 && outcome.deferred.length === 0);
  // The composer's own row says a report was handed over, because its
  // hook ran and did not throw. That is true and it is not the question
  // an operator is asking, which is whether the sender will receive one.
  check("the composer records that it handed the report over",
    outcome.failed[0].dsnSent === true);
  check("and nothing is waiting, so the report is not on its way either",
    delivery.queue.count() === 0);
  check("the sender who will never receive the report is counted",
    delivery.describe().reportsUnsent === 1);
}

// The same refusal on the path this server composes a report from its
// own verdict rather than from a peer's, which is what the MX listener
// reaches when an address does not resolve to a mailbox here.
async function aLocalReportTheOutboundPathRefusesSaysSo(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(REPORT_REFUSED_TOO));

  var outcome = await delivery.bounce({
    to:        "alice@example.com",
    recipient: "nobody@example.net",
    reason:    "No such mailbox on this server",
  });

  check("the caller is told the report was recorded rather than sent",
    outcome.reportUnsent === true);
  check("and the counter an operator reads moves with it",
    delivery.describe().reportsUnsent === 1);
  check("the composed report still travels back, so an operator can read what was owed",
    typeof outcome.report === "string" && outcome.report.length > 0);
}

// A cancellation destroys a message no receiver refused, so the verdict
// it hands back is the only record of whether its sender was told. A
// report the outbound path refused means they were not, and a verdict
// saying otherwise reads as an erasure everybody was told about.
async function aCancellationSaysWhenItsSenderCouldNotBeTold(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver(CANCELLED_SENDER_UNREACHABLE));

  await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  var id = onlyId(dataDir);
  check("a message is waiting to be cancelled", id !== null);

  var verdict = await delivery.queue.remove(id, {
    reason: "the receiving domain is never coming back",
    notice: { status: "5.7.1" },
  });

  check("the message is cancelled", verdict.removed === true && verdict.outcome === "removed");
  check("the verdict does not claim its sender was told",
    verdict.reported === false);
  check("and it names why they were not",
    verdict.withheld === "report-recorded-unsent");
  check("the counter an operator reads carries the same fact",
    delivery.describe().reportsUnsent === 1);
}

// ---------------------------------------------------------------------------
// What the outcome of a recorded report may carry back
// ---------------------------------------------------------------------------

// The single byte form of CSI at U+009B, built here rather than typed: a
// C1 code point does not survive being written into a source file. A
// terminal reads it as the introducer of a cursor movement or a color
// change, so a value carrying one repaints whatever prints it.
var CSI = String.fromCharCode(0x9b);

// The three branches of `bounce` that record a report rather than send
// one each name an address in what they hand back, and the address is
// whatever the failed message claimed to be from or was addressed to.
//
// The first also carries a header separator, which the report builder's
// own guard refuses, so it reaches the branch that records a report
// nobody could compose. The second is a sender the builder accepts and
// the outbound path will not carry, so it reaches the branch that
// records a report nobody will receive. The third is the recipient named
// by a message whose reverse path is the empty one, where no report is
// owed and the row recording that says who it was about.
var UNBUILDABLE_SENDER = "alice" + CSI + "@example.com\r\nX-Injected: yes";
var UNREACHABLE_SENDER = "alice" + CSI + "@example.com";
var CONTROL_RECIPIENT  = "nobody" + CSI + "@example.net";

function carriesNoControl(value) {
  var text = String(value);
  return text.indexOf(CSI) === -1 && text.indexOf("\r") === -1 && text.indexOf("\n") === -1;
}

// Every other place these two branches write the address is screened:
// the audit row and the operator's log line beside each of them. The
// outcome is the fourth reader, and it is the one the admin queue page
// and a caller composing its own message read, so an outcome that is not
// screened puts the same bytes in front of the same eyes by the route
// nobody looked at.
async function aRecordedReportNamesTheSenderSafely(unbuildableDir, unreachableDir) {
  var unbuildable = handleOn(unbuildableDir, zone.resolverOver(REPORT_CAN_LEAVE));
  var atComposition = await unbuildable.bounce({
    to:        UNBUILDABLE_SENDER,
    recipient: CONTROL_RECIPIENT,
    reason:    "No such mailbox on this server",
  });
  count("a report whose sender cannot go in a header is recorded rather than sent",
    atComposition.reportUnsent === true, JSON.stringify(atComposition.reportUnsent));
  count("and the outcome names that sender with nothing a terminal acts on left in it",
    atComposition.failed.length === 1 && carriesNoControl(atComposition.failed[0].recipient),
    JSON.stringify(atComposition.failed.length ? atComposition.failed[0].recipient : null));

  var unreachable = handleOn(unreachableDir, zone.resolverOver(REPORT_REFUSED_TOO));
  var atDelivery = await unreachable.bounce({
    to:        UNREACHABLE_SENDER,
    recipient: "bob@example.net",
    reason:    "No such mailbox on this server",
  });
  count("a report the outbound path will not carry is recorded rather than sent",
    atDelivery.reportUnsent === true, JSON.stringify(atDelivery.reportUnsent));
  count("and that outcome names the sender who will never receive it the same way",
    atDelivery.failed.length === 1 && carriesNoControl(atDelivery.failed[0].recipient),
    JSON.stringify(atDelivery.failed.length ? atDelivery.failed[0].recipient : null));
  count("and the reason it carries back is screened as well",
    atDelivery.failed.length === 1 && carriesNoControl(atDelivery.failed[0].reason),
    JSON.stringify(atDelivery.failed.length ? atDelivery.failed[0].reason : null));
}

// A message that arrived with the empty reverse path is owed no report,
// and the row recording that silence names the address the message was
// addressed to. That address came off the wire.
async function aSuppressedReportRecordsTheRecipientSafely(dataDir) {
  // Opening a store is what registers the namespace on the shipped
  // server, and nothing here opens one. Without it the row is discarded
  // before it reaches any sink and this case would pass by reading
  // nothing.
  helpers.b.audit.registerNamespace("blamepost");
  var capture = helpers.auditCapture();
  try {
    // Rows an earlier case left buffered drain on the first flush of the
    // process, whoever calls it, so the backlog is taken here rather than
    // arriving in the reading below and being counted as part of it.
    await helpers.b.audit.flush();
    var delivery = handleOn(dataDir, zone.resolverOver(REPORT_CAN_LEAVE), { audit: true });
    var outcome = await delivery.bounce({
      to:        "<>",
      recipient: CONTROL_RECIPIENT,
      reason:    "No such mailbox on this server",
    });
    count("no report is generated about a message with the empty reverse path",
      outcome.reportWithheld === "null-return-path", JSON.stringify(outcome.reportWithheld));

    await helpers.b.audit.flush();
    var rows = capture.forAction("blamepost.mail.delivery.report_suppressed");
    count("and the trail carries a row saying so",
      rows.length === 1, String(rows.length) + " row(s)");
    if (rows.length !== 1) return;
    var metadata = helpers.metadataOf(rows[0]);
    count("whose recipient is the one the message named, with nothing a reader acts on in it",
      carriesNoControl(metadata.recipient), JSON.stringify(metadata.recipient));
  } finally {
    capture.release();
  }
}

// ---------------------------------------------------------------------------
// How many reports this server will generate before it stops
// ---------------------------------------------------------------------------

// A report is addressed to whoever the failed message claimed to be
// from. On a run of mail forging a third party's address, one report
// per arriving message is this server sending that third party mail in
// a quantity the attacker chooses, so the two ceilings are what stands
// between an operator and their server being the instrument of somebody
// else's flood.
//
// Both are read out of the operator guide rather than out of the
// module. A case comparing the module against itself passes at any
// ceiling, including one high enough to relay a whole run, while the
// figure the guide gives an operator sizing capacity, and the figure
// an incident response reads to decide whether a run reached the bound,
// went on saying something else. The guide states them twice, in the
// reference and again where it explains the bound as a spam control, so
// the two statements are reconciled against each other first.
//
// Both edges of each ceiling are driven. A ceiling asserted only from
// above is satisfied by a server that reports nothing at all, which is
// the other way for a sender to hear nothing.
var SETTINGS_REFERENCE = "docs/operator-guide.md";
var PER_SENDER_RE = /\*\*(\d+) reports per original sender per hour\.\*\*/;
var PER_WINDOW_RE = /\*\*(\d+) reports in total per hour\.\*\*/;
var RESTATED_RE   =
  /at most (\d+) reports for any one claimed sender in an hour and\s+at most (\d+) in total/;

function documentedReportCeilings() {
  var text      = fs.readFileSync(path.join(helpers.REPO_ROOT, SETTINGS_REFERENCE), "utf8");
  var perSender = PER_SENDER_RE.exec(text);
  var perWindow = PER_WINDOW_RE.exec(text);
  var restated  = RESTATED_RE.exec(text);
  if (perSender === null || perWindow === null || restated === null) return null;
  return {
    perSender:         parseInt(perSender[1], 10),
    perWindow:         parseInt(perWindow[1], 10),
    restatedPerSender: parseInt(restated[1], 10),
    restatedPerWindow: parseInt(restated[2], 10),
  };
}

// Named apart from `helpers/dns-zone.js`'s `messageFrom`, which is a
// different function: that one takes a domain and a tag and carries every
// header the signer binds, because a message it builds is going to be
// signed and verified. This one takes a whole sender address and carries
// the four lines a delivery failure needs, because nothing here reads the
// message: it exists to be refused so a report is composed about it.
// Importing that one would make each of these sends do the work of a
// signing vector, and folding the two together would leave one of them
// asserting nothing.
function minimalMessageFrom(sender) {
  return Buffer.from("From: " + sender + "\r\nTo: bob@example.net\r\n\r\nbody\r\n", "utf8");
}

async function failOnce(delivery, sender) {
  return delivery.send({
    from:   sender,
    to:     ["bob@example.net"],
    rfc822: minimalMessageFrom(sender),
  });
}

async function theReportCeilingsAreTheOnesTheGuidePrints(perSenderDir, perWindowDir) {
  var caps = documentedReportCeilings();
  count("the operator guide prints both report ceilings, so this is comparing something",
    caps !== null && caps.perSender > 0 && caps.perWindow > caps.perSender,
    JSON.stringify(caps));
  if (caps === null) return;
  count("and it prints the same two numbers where it explains the bound as a spam control, " +
    "so an operator reading either passage acts on one figure",
    caps.restatedPerSender === caps.perSender && caps.restatedPerWindow === caps.perWindow,
    caps.restatedPerSender + " per sender and " + caps.restatedPerWindow + " in total");

  // The zone lets the reports leave. What is being measured here is the
  // generation bound, and the counter it moves also counts a report the
  // outbound path refused, so a zone that refuses the sender's own domain
  // would read every admitted report as a suppressed one.
  var one = "mistyping@example.com";
  var perSender = handleOn(perSenderDir, zone.resolverOver(REPORT_CAN_LEAVE));
  for (var i = 0; i < caps.perSender; i += 1) await failOnce(perSender, one);
  count("somebody whose mail fails as many times in an hour as the guide allows hears about " +
    "every one of them", perSender.describe().reportsUnsent === 0,
    String(perSender.describe().reportsUnsent) + " unsent after " + caps.perSender);
  count("and every one of those reports is on the outbound path rather than nowhere",
    perSender.queue.count() === caps.perSender,
    perSender.queue.count() + " waiting of " + caps.perSender);

  await failOnce(perSender, one);
  count("and the one past that is recorded rather than sent, so a run forging a single " +
    "address cannot spend an unbounded number of reports at it",
    perSender.describe().reportsUnsent === 1,
    String(perSender.describe().reportsUnsent) + " unsent after " + (caps.perSender + 1));

  // A different claimed sender every time, so each one is well under the
  // per sender ceiling and the only thing that can stop the run is the
  // total. Spreading the addresses is what an attacker does, and it is
  // the case the first ceiling on its own does not cover.
  var perWindow = handleOn(perWindowDir, zone.resolverOver(REPORT_CAN_LEAVE));
  for (var j = 0; j < caps.perWindow; j += 1) {
    await failOnce(perWindow, "forged-" + j + "@example.com");
  }
  count("a run naming a different sender each time is reported on up to the total the guide " +
    "prints", perWindow.describe().reportsUnsent === 0,
    String(perWindow.describe().reportsUnsent) + " unsent after " + caps.perWindow);

  await failOnce(perWindow, "forged-past-the-total@example.com");
  count("and the one past the total is recorded rather than sent, so spreading a run across " +
    "addresses does not buy a report for every one of them",
    perWindow.describe().reportsUnsent === 1,
    String(perWindow.describe().reportsUnsent) + " unsent after " + (caps.perWindow + 1));
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
    await helpers.withTestTimeout("delivery report: a report the outbound path refuses is counted",
      function () {
        return aReportTheOutboundPathRefusesIsCountedAsUnsent(freshDir("dlv-rep-refused"));
      });
    await helpers.withTestTimeout("delivery report: a local report the outbound path refuses says so",
      function () { return aLocalReportTheOutboundPathRefusesSaysSo(freshDir("dlv-rep-local")); });
    await helpers.withTestTimeout("delivery report: a cancellation says when its sender could not be told",
      function () {
        return aCancellationSaysWhenItsSenderCouldNotBeTold(freshDir("dlv-rep-cancel"));
      });
    await helpers.withTestTimeout("delivery report: a recorded report names the sender safely",
      function () {
        return aRecordedReportNamesTheSenderSafely(
          freshDir("dlv-rep-unbuildable-name"), freshDir("dlv-rep-unreachable-name"));
      });
    await helpers.withTestTimeout("delivery report: a suppressed report records the recipient safely",
      function () {
        return aSuppressedReportRecordsTheRecipientSafely(freshDir("dlv-rep-suppressed-name"));
      });
    await helpers.withTestTimeout("delivery report: the ceilings are the ones the guide prints",
      function () {
        return theReportCeilingsAreTheOnesTheGuidePrints(
          freshDir("dlv-rep-sender-cap"), freshDir("dlv-rep-window-cap"));
      });
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
