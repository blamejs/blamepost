// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The outbound path, driven against a real spool on a real temporary
 * data directory. Two behaviors are pinned here, both of which lose
 * mail when they regress.
 *
 * The first is what happens to a report this server owes somebody. A
 * report travels with the RFC 5321 §4.5.5 empty reverse path that §6.1
 * requires of it, and it goes out over the same outbound path as any
 * other message. Two things about that have to hold: the reverse path is
 * the empty one whichever spelling it arrived in, and generation is rate
 * bounded, because a report is addressed to the sender of the message it
 * is about and on a run of mail to addresses that do not exist here that
 * sender is whoever forged it. A report the bound refuses stays loud: an
 * outcome the caller can read, a counter describe() reports, and an
 * error line naming who was owed what.
 *
 * The second is the order the spool works in. A message leaves the
 * spool once an attempt has finished and there is nothing left to try,
 * never before one starts. Reversing those two costs the message on the
 * first sweep, and the cases that hit it are exactly the ones the spool
 * exists for.
 *
 * No sockets. The resolver decides every outcome: one that fails the MX
 * lookup produces a temporary refusal, and one publishing the RFC 7505
 * null MX produces a permanent one. Both are reached through the real
 * composer, so what is under test is the shipped path.
 *
 * Run standalone: node test/layer-1-state/mail-delivery.test.js
 */

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var blamepost = require("../../lib");

var b     = helpers.b;
var check = helpers.check;
var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var SENDER    = "sender@example.net";
var RECIPIENT = "nobody@example.com";
var MESSAGE   = "From: " + SENDER + "\r\nTo: " + RECIPIENT + "\r\n\r\nbody\r\n";

// A resolver whose MX lookup fails. Every recipient comes back as a
// temporary refusal, which is what puts an entry in the spool.
var UNREACHABLE_MX = {
  queryMx: function () {
    return Promise.reject(new Error("probe resolver: MX lookup unavailable"));
  },
};

// A resolver publishing the RFC 7505 null MX, which says the domain
// refuses mail outright. The composer classifies that as permanent and
// runs its permanent-failure hook.
var REFUSING_MX = {
  queryMx: function () {
    return Promise.resolve([{ priority: 0, exchange: "" }]);
  },
};

// A resolver that answers with a host, so the composer gets past MX
// lookup and policy and constructs a transport. The host does not
// resolve, so the attempt ends at the connect and no mail leaves the
// machine, but everything up to that point is the shipped path rather
// than a shortcut through an earlier refusal. Every other resolver here
// fails before the transport is reached, which is exactly how the
// outbound path came to be broken without a single test noticing.
var ANSWERING_MX = {
  queryMx: function () {
    return Promise.resolve([{ priority: 10, exchange: "mx.example.net" }]);
  },
};

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

function readDescriptor(dataDir, id) {
  return JSON.parse(fs.readFileSync(path.join(dataDir, "queue", id + ".json"), "utf8"));
}

function writeDescriptor(dataDir, id, descriptor) {
  fs.writeFileSync(path.join(dataDir, "queue", id + ".json"),
    JSON.stringify(descriptor, null, 2), "utf8");
}

// Put one entry in the spool and return its id. The MX lookup fails, so
// the recipient comes back as a temporary refusal and the send path
// writes the pair before it resolves.
async function spoolOne(delivery, dataDir) {
  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("an unreachable MX defers the recipient rather than failing it",
    outcome.deferred.length === 1 && outcome.failed.length === 0);
  var files = spoolFiles(dataDir);
  check("a deferred recipient leaves a descriptor and a body on disk",
    files.length === 2);
  return files[0].replace(/\.(json|eml)$/, "");
}

// ---------------------------------------------------------------------------
// A report this server owes somebody
// ---------------------------------------------------------------------------

async function reportsGoOutWithTheEmptyReversePath(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);

  check("a fresh handle owes nobody a report", delivery.describe().reportsUnsent === 0);

  // A refusal this server decided locally. The original sender is a real
  // address, so a report is genuinely owed and genuinely sent.
  var reported = await delivery.bounce({
    to:              SENDER,
    recipient:       RECIPIENT,
    reason:          "No mailbox by that name at this server.",
    statusCode:      "5.1.1",
    originalHeaders: "From: " + SENDER + "\r\n",
  });
  check("the report is handed to the outbound path rather than recorded",
    reported && reported.reportUnsent === undefined);
  check("it is addressed to the sender who was owed it",
    reported.deferred.length === 1 && reported.deferred[0].recipient === SENDER);
  check("nothing is counted as a report this server failed to send",
    delivery.describe().reportsUnsent === 0);
  check("the report is on disk waiting for its next attempt",
    spoolFiles(dataDir).length === 2);

  var reportId = spoolFiles(dataDir)[0].replace(/\.(json|eml)$/, "");
  check("and it travels with the empty reverse path RFC 5321 6.1 requires",
    readDescriptor(dataDir, reportId).from === "");
  check("the composed report is handed back so an operator can read it",
    reported.report.indexOf("Final-Recipient: rfc822; " + RECIPIENT) !== -1);

  // RFC 5321 §6.1: a message that arrived with the empty reverse path
  // has nobody to report to, and that silence is correct rather than a
  // failure. It must not read as a report this server owes anybody.
  var suppressed = await delivery.bounce({
    to:        "",
    recipient: RECIPIENT,
    reason:    "No mailbox by that name at this server.",
  });
  check("a report about a message from the null return path is not generated",
    suppressed.failed.length === 0 && suppressed.delivered.length === 0);
  check("suppressing that report is not counted as one this server owes",
    delivery.describe().reportsUnsent === 0);
  check("and nothing more is written to the spool for it",
    spoolFiles(dataDir).length === 2);

  // An arriving report being forwarded off this server by an alias. It
  // goes on with the reverse path it arrived with, which is the whole
  // point: sending it from a real address would make this server the
  // apparent originator of somebody else's bounce.
  var forwarded = await delivery.send({
    from:   "",
    to:     ["forward@example.org"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("forwarding a message that arrived with an empty reverse path is an ordinary send",
    forwarded && forwarded.reportUnsent === undefined);
  check("the forward names the address it is bound for",
    forwarded.deferred.length === 1 &&
    forwarded.deferred[0].recipient === "forward@example.org");
  check("and it is waiting on the attempt rather than permanently refused",
    forwarded.failed.length === 0);
  check("the message this server accepted is on disk rather than discarded",
    spoolFiles(dataDir).length === 4);
}

// The bound on generation, which is what keeps a report path from being
// a backscatter amplifier. A report is addressed to the sender of the
// message it is about, and on a run of mail to addresses that do not
// exist here that sender is whoever forged it.
async function reportGenerationIsBounded(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);

  var sentCount = 0;
  var recordedCount = 0;
  // Comfortably past the per sender bound, so the crossing is observed
  // rather than assumed to be at a particular number.
  for (var i = 0; i < 40; i += 1) {
    var outcome = await delivery.bounce({
      to:        "forged@example.net",
      recipient: "nobody" + i + "@example.com",
      reason:    "No mailbox by that name at this server.",
    });
    if (outcome.reportUnsent === true) recordedCount += 1; else sentCount += 1;
  }

  count("a run against one forged sender stops being reported at some point",
    recordedCount > 0, "sent " + sentCount + ", recorded " + recordedCount);
  count("but the sender hears about the first of them",
    sentCount > 0, "sent " + sentCount);
  check("every report the bound refused is counted where an operator reads it",
    delivery.describe().reportsUnsent === recordedCount);
  check("and the refusal says why rather than reading as a delivery failure",
    /already generated as many delivery reports/.test(
      String((await delivery.bounce({
        to: "forged@example.net", recipient: "x@example.com", reason: "y",
      })).failed[0].reason)));

  // The bound is per sender as well as global, so a different
  // correspondent is not buried by somebody else's run.
  var other = await delivery.bounce({
    to:        "real@example.org",
    recipient: "nobody@example.com",
    reason:    "No mailbox by that name at this server.",
  });
  check("a different sender is not silenced by another sender's run",
    other.reportUnsent === undefined);
}

async function aPermanentPeerRefusalRunsTheReportPath(dataDir) {
  // The recipient's domain refuses mail outright and the sender's is
  // absent from the zone, which answers as a name that does not exist.
  // So the message is permanently refused and the report about it can
  // still be handed to the outbound path, where it waits.
  //
  // A single resolver refusing both domains would refuse the report too,
  // and a counter of nought read against that cannot tell a report that
  // went from a report nobody will ever receive.
  var delivery = handleOn(dataDir, zone.resolverOver({ "example.net": { mx: [] } }));

  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("a domain publishing no mail exchanger is a permanent refusal",
    outcome.failed.length === 1 && outcome.deferred.length === 0);
  check("the composer's permanent-failure hook completed rather than throwing",
    outcome.failed[0].dsnSent === true);
  check("the report it handed over is waiting on the outbound path",
    delivery.queue.count() === 1);
  check("nothing is counted as a report the sender did not get",
    delivery.describe().reportsUnsent === 0);

  // The angle bracket spelling is the same reverse path as the empty
  // string, and the send path has to read it that way. Handing the
  // literal to the composer reaches the address guard, which reads it as
  // a malformed address and refuses the message.
  var bracketed = handleOn(dataDir, REFUSING_MX);
  var loopSafe = await bracketed.send({
    from:   "<>",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("the angle bracket spelling of the null return path reaches the composer",
    loopSafe.failed.length === 1 && loopSafe.delivered.length === 0);
  check("and no report is generated about a message that had no return path",
    loopSafe.failed[0].dsnSent === false &&
    bracketed.describe().reportsUnsent === 0);
}

// RFC 5321 §6.1, through the composer rather than around it. A spooled
// entry whose reverse path is empty reaches the composer directly, and
// when the peer refuses it permanently the composer runs its
// permanent-failure hook. There is nobody to report to, so the hook
// must stay silent: a report about a report is the loop the rule
// exists to stop, and a server that generates one bounces forever with
// whichever peer is doing the same thing.
async function aReportAboutAReportIsNotGenerated(dataDir) {
  var spooler = handleOn(dataDir, UNREACHABLE_MX);
  var id = await spoolOne(spooler, dataDir);

  var descriptor = readDescriptor(dataDir, id);
  descriptor.from = "<>";
  writeDescriptor(dataDir, id, descriptor);

  var delivery = handleOn(dataDir, REFUSING_MX, { retry: { maxAttempts: 1 } });
  var run = await delivery.queue.runDue({ force: true });
  check("a spooled report the peer refuses permanently is reported as failed",
    run.results[0].outcome === "failed");
  check("the composer's permanent-failure hook completed rather than throwing",
    delivery.describe().reportsUnsent === 0);
  check("the entry leaves the spool once there is nothing left to try",
    spoolFiles(dataDir).length === 0);
}

// ---------------------------------------------------------------------------
// An envelope with no message
// ---------------------------------------------------------------------------

// A send that carries no message is a caller fault, and it has to be
// refused where the caller can still do something about it.
//
// Taken instead, it becomes an envelope of nought bytes: the composer
// offers a receiver a DATA with nothing in it, which is a message with
// no headers and no body, and a recipient that defers puts a
// nought-byte body on the volume where it spends the whole retry budget
// over five days. Neither the sender nor the operator has anything to
// read afterwards, because there is nothing to read.
async function anEnvelopeWithNoMessageIsRefused(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);

  var absent = null;
  try {
    await delivery.send({ from: "alice@example.com", to: ["bob@example.net"] });
  } catch (err) { absent = err; }
  check("an envelope carrying no message at all is refused",
    absent !== null && absent instanceof TypeError);
  check("and the refusal names the option the caller left out",
    absent !== null && /rfc822/.test(String(absent.message)));

  var empty = null;
  try {
    await delivery.send({
      from:   "alice@example.com",
      to:     ["bob@example.net"],
      rfc822: Buffer.alloc(0),
    });
  } catch (err) { empty = err; }
  check("a message of nought bytes is refused the same way",
    empty !== null && empty instanceof TypeError);

  check("and neither of them reached the volume",
    spoolFiles(dataDir).length === 0);
}

// ---------------------------------------------------------------------------
// An envelope's place in the retry budget
// ---------------------------------------------------------------------------

// `attempt` says how many attempts have already been made on a message,
// and two decisions are taken from it: whether the budget is spent, and
// which wait stands before the next attempt.
//
// Both are arithmetic, and neither one refuses a value that is not a
// number. A count written as text is added to rather than summed, so
// `"5"` becomes `"51"`, which compares above the budget and ends the
// message on its first try with a report to its sender saying it failed.
// A count that is not whole, or is below nought, indexes the schedule
// outside itself and produces a next attempt time that is not a time, so
// the entry comes due on every sweep with no wait between attempts and
// the peer is asked again as fast as the timer runs.
//
// A count that really is one still has to work, or the guard has traded
// one broken budget for another.
async function aRetryBudgetPositionThatIsNotACountIsRefused(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);

  var asText = null;
  try {
    await delivery.send({
      from:    SENDER,
      to:      [RECIPIENT],
      rfc822:  Buffer.from(MESSAGE, "utf8"),
      attempt: "5",
    });
  } catch (err) { asText = err; }
  check("an attempt count written as text is refused",
    asText !== null && asText instanceof TypeError);
  check("and the refusal names the option the caller got wrong",
    asText !== null && /attempt/.test(String(asText.message)));

  var fraction = null;
  try {
    await delivery.send({
      from:    SENDER,
      to:      [RECIPIENT],
      rfc822:  Buffer.from(MESSAGE, "utf8"),
      attempt: 1.5,
    });
  } catch (err) { fraction = err; }
  check("a count that is not whole is refused, because there is no half attempt",
    fraction !== null && fraction instanceof TypeError);

  var below = null;
  try {
    await delivery.send({
      from:    SENDER,
      to:      [RECIPIENT],
      rfc822:  Buffer.from(MESSAGE, "utf8"),
      attempt: -2,
    });
  } catch (err) { below = err; }
  check("a count below nought is refused", below !== null && below instanceof TypeError);

  check("none of them reached the volume", spoolFiles(dataDir).length === 0);

  var outcome = await delivery.send({
    from:    SENDER,
    to:      [RECIPIENT],
    rfc822:  Buffer.from(MESSAGE, "utf8"),
    attempt: 2,
  });
  count("a message that really has been tried twice is still taken",
    outcome.deferred.length === 1 && outcome.failed.length === 0,
    JSON.stringify({ failed: outcome.failed, deferred: outcome.deferred.length }));
  count("and it takes the next place in the budget rather than the first",
    outcome.deferred.length === 1 && outcome.deferred[0].attempt === 3,
    String(outcome.deferred.length === 1 ? outcome.deferred[0].attempt : "not deferred"));
  count("and it waits the rung that place stands on",
    outcome.deferred.length === 1 &&
    outcome.deferred[0].retryAfterMs === b.constants.TIME.minutes(15),
    String(outcome.deferred.length === 1 ? outcome.deferred[0].retryAfterMs : "not deferred"));
}

// ---------------------------------------------------------------------------
// The spool works in the order that keeps the message
// ---------------------------------------------------------------------------

async function aFaultedAttemptKeepsTheMessage(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);
  var id = await spoolOne(delivery, dataDir);

  // Poison the descriptor so the attempt throws out of the composer
  // rather than coming back with an answer. A recipient that is not an
  // address at all does it: the composer reads one before it can
  // classify anything, so there is no outcome list to come back on. A
  // descriptor is a file on a volume other things also write to, so a
  // corrupt one is a fault this server has to survive rather than a
  // shape nobody could produce.
  var descriptor = readDescriptor(dataDir, id);
  var recipient = descriptor.recipient;
  descriptor.recipient = null;
  writeDescriptor(dataDir, id, descriptor);

  var run = await delivery.queue.runDue({ force: true });
  check("the sweep reports the entry it could not attempt", run.ran === 1);
  check("a faulted attempt is reported as an error rather than a delivery",
    run.results[0].outcome === "error" && typeof run.results[0].error === "string");
  check("the entry survives the attempt that threw",
    spoolFiles(dataDir).length === 2);

  var after = readDescriptor(dataDir, id);
  check("the descriptor still names what it named before the attempt",
    after.recipient === null && recipient !== null);
  check("the attempt counter moved, so the entry cannot be retried forever",
    after.attempt === descriptor.attempt + 1);
  check("the next attempt is scheduled ahead rather than immediately",
    after.nextAttemptAt > Date.now());
  check("the sweep says when it will look again",
    run.results[0].retryAt === after.nextAttemptAt);
  check("the message body is still on disk beside the descriptor",
    fs.existsSync(path.join(dataDir, "queue", id + ".eml")));
}

async function aTemporaryRefusalKeepsTheMessage(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);
  var id = await spoolOne(delivery, dataDir);
  var before = readDescriptor(dataDir, id);

  var run = await delivery.queue.runDue({ force: true });
  check("a recipient still refusing temporarily is reported as waiting",
    run.results[0].outcome === "waiting");
  check("the entry stays spooled for its next attempt",
    spoolFiles(dataDir).length === 2);

  var after = readDescriptor(dataDir, id);
  // Two counts, and both move. A lookup that could not complete is an
  // ordinary transient: the domain's nameservers may answer on the next
  // attempt and may never answer again, and the retry budget is what
  // decides how long this server waits to find out before telling the
  // sender it gave up. The record of how many times the message has been
  // tried moves alongside it, because an operator asking "has anything
  // happened to this" has to be able to tell a stalled entry from an
  // untouched one.
  check("a lookup nobody completed spends its place in the retry budget",
    after.attempt === before.attempt + 1);
  check("and the entry counts that it was tried again",
    after.attemptsRecorded > before.attemptsRecorded);
  check("the entry keeps the moment it was first queued",
    after.queuedAt === before.queuedAt);

  // How an operator abandons a message addressed to a domain that is
  // never coming back.
  var removed = await delivery.queue.remove(id, {
    reason: "the domain is never coming back",
    notice: { withheld: "fixture-removal" },
  });
  check("remove names the entry it cleared",
    removed.id === id && removed.removed === true);
  check("removing an entry clears both files off disk",
    spoolFiles(dataDir).length === 0);
}

async function aPermanentRefusalClearsTheEntry(dataDir) {
  var spooler = handleOn(dataDir, UNREACHABLE_MX);
  var id = await spoolOne(spooler, dataDir);

  // A second handle over the same spool. Its resolver refuses the
  // recipient's domain outright and cannot answer for the sender's, so
  // the original message ends and the report it produces stays on disk
  // where this case can read it. Two answers from one resolver, because
  // the report and the message it is about travel to different domains
  // and this file is about what happens to both.
  var SPLIT = {
    queryMx: function (name) {
      if (String(name).toLowerCase() === "example.net") {
        return Promise.resolve([{ priority: 0, exchange: "" }]);
      }
      return Promise.reject(new Error("probe resolver: MX lookup unavailable"));
    },
  };
  var delivery = handleOn(dataDir, SPLIT);
  var run = await delivery.queue.runDue({ force: true });
  check("a permanently refused recipient is reported as failed",
    run.results[0].outcome === "failed");
  check("the entry with nothing left to try leaves the spool",
    !fs.existsSync(path.join(dataDir, "queue", id + ".json")));
  check("the sender is told, rather than counted as somebody nobody could tell",
    delivery.describe().reportsUnsent === 0);

  // What replaced it is the report, on its way to the original sender
  // with the reverse path RFC 5321 §6.1 requires.
  check("a report to the original sender took its place", spoolFiles(dataDir).length === 2);
  var reportId = spoolFiles(dataDir)[0].replace(/\.(json|eml)$/, "");
  var report = readDescriptor(dataDir, reportId);
  check("the report is addressed to the sender of the message that failed",
    report.recipient === "alice@example.com");
  check("and travels with the empty reverse path", report.from === "");
}

// Running out of attempts ends the message, and ends it by telling the
// sender.
//
// A local fault is this server's by construction: an unreadable body, a
// corrupt descriptor, a resolver that failed. No receiver declined the
// message, so ending it destroys mail nobody rejected, and that is only
// a fair trade because the sender hears about it. A sender who is told
// "this never arrived" can send it again; one who is told nothing
// believes it arrived. The budget is the timer on that trade.
async function attemptsAgainstALocalFaultEndTheMessage(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX, { retry: { maxAttempts: 2 } });
  var id = await spoolOne(delivery, dataDir);

  var descriptor = readDescriptor(dataDir, id);
  descriptor.recipient = null;
  descriptor.attempt = 1;
  writeDescriptor(dataDir, id, descriptor);

  var run = await delivery.queue.runDue({ force: true });
  check("the last attempt against a fault gives up rather than looping forever",
    run.results[0].outcome === "abandoned");
  check("the sweep still reports what went wrong",
    typeof run.results[0].error === "string" && run.results[0].error.length > 0);
  check("the entry it gave up on is off disk",
    !fs.existsSync(path.join(dataDir, "queue", id + ".json")) &&
    !fs.existsSync(path.join(dataDir, "queue", id + ".eml")));
  check("and nothing is left held with no deadline against it",
    (await delivery.queue.held()).messages === 0);
}

// The abandonment that survives, because it destroys nothing. When the
// message itself has already gone from beside the descriptor, there is
// nothing left for an attempt to send, and rewriting the descriptor
// would put a cancelled message back into a queue an operator has just
// cleared.
async function anEntryWithNothingLeftToSendIsAbandoned(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX, { retry: { maxAttempts: 2 } });
  var id = await spoolOne(delivery, dataDir);

  var descriptor = readDescriptor(dataDir, id);
  descriptor.from = "";
  writeDescriptor(dataDir, id, descriptor);
  fs.rmSync(path.join(dataDir, "queue", id + ".eml"), { force: true });

  var run = await delivery.queue.runDue({ force: true });
  check("an entry whose message is gone is abandoned",
    run.results[0].outcome === "abandoned");
  check("and the descriptor left behind goes with it",
    spoolFiles(dataDir).length === 0);
  check("the sweep says the message was what was missing",
    /nothing left to send/.test(String(run.results[0].error)));
}

// ---------------------------------------------------------------------------
// Whether this build can reach a peer at all
// ---------------------------------------------------------------------------

// The answer has to be measured against the framework surface rather
// than recorded in a constant beside it. A recorded answer goes stale in
// silence, and it did: an earlier form of this check looked for an
// export the framework never had, so it reported an outage that had
// already been repaired and never fired the staleness error it carried
// for exactly that case. What is asked now is whether the transport the
// composer reaches for is callable, which is the same question the
// composer asks at the first send.
async function theBuildSaysWhetherItCanReachAPeer(dataDir) {
  var delivery = handleOn(dataDir, ANSWERING_MX);

  var status = delivery.describe().wireDelivery;
  check("the handle says outright whether a message can reach a peer",
    status.available === true);
  check("and a working path leaves an operator nothing to follow up",
    status.issues.length === 0 && status.reason === "");

  // The regression direction, asked of a surface that has no transport
  // rather than by altering the real one. This is the half a type check
  // can answer; whether the bytes survive the wire is a separate case
  // driven against a real receiver.
  var missing = blamepost.mail.delivery.wireDeliveryStatus({ transports: {} });
  check("a build whose composer has no transport behind it says so",
    missing.available === false);
  check("and says what an operator would do about it",
    /vendor-update/.test(missing.reason));
  check("an empty surface is read the same way, rather than throwing",
    blamepost.mail.delivery.wireDeliveryStatus({}).available === false);

  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });

  // The host does not resolve, so the attempt ends at the connect. That
  // is an ordinary transient with a verdict behind it, and it spends its
  // place in the budget like any other.
  check("a message that reached the wire and got no answer is deferred, not failed",
    outcome.deferred.length === 1 && outcome.failed.length === 0);
  check("nothing is held outside the retry budget",
    outcome.deferred[0].held === undefined && outcome.deferred[0].attempt >= 1);

  var files = spoolFiles(dataDir);
  check("the message is on disk, descriptor and body both", files.length === 2);

  var id = files[0].replace(/\.(json|eml)$/, "");
  var descriptor = readDescriptor(dataDir, id);
  check("the spooled attempt count advanced", descriptor.attempt === 1);
  check("and nothing on the descriptor claims it is being held back",
    descriptor.held === false);
}

// The budget question, asked directly. Sweeping past the operator's
// retry budget has to end the message and tell its sender, because a
// message that is retried forever is one nobody is ever told about.
async function theRetryBudgetEndsTheMessageAndTellsTheSender(dataDir) {
  var delivery = handleOn(dataDir, ANSWERING_MX, {
    // Two attempts, so exhaustion is reachable in a test rather than in
    // five hours.
    retry: { maxAttempts: 2, backoffMs: [1, 1] },
  });

  await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  var id = spoolFiles(dataDir)[0].replace(/\.(json|eml)$/, "");
  check("the first attempt already spent its place in the budget",
    readDescriptor(dataDir, id).attempt === 1);

  var descriptor = readDescriptor(dataDir, id);
  descriptor.nextAttemptAt = Date.now() - 1;
  writeDescriptor(dataDir, id, descriptor);
  var run = await delivery.queue.runDue();

  check("the sweep that exhausts the budget ends the message",
    run.results.length === 1 && run.results[0].outcome === "failed");
  check("the entry it ended is off disk",
    !fs.existsSync(path.join(dataDir, "queue", id + ".json")));
  check("the sender is told rather than counted as somebody nobody could tell",
    delivery.describe().reportsUnsent === 0);
  check("and nothing is left waiting without a deadline against it",
    (await delivery.queue.held()).messages === 0);
}

// A decision this server made itself still spends the budget, and still
// carries this server's own words rather than a peer's.
//
// Under an enforcing MTA-STS posture, a record the pinned resolver could
// not settle makes this server withhold the message under its own
// enhanced status. Nothing reached the composer, so there is no peer
// reason to report and no peer to name, and the recipient still has to
// come back on the deferral list with its place in the budget spent:
// otherwise a receiver whose record never settles is retried forever and
// its sender is never told.
async function aVerdictStillSpendsTheBudget(dataDir) {
  var delivery = handleOn(dataDir, zone.resolverOver({
    "example.net":          { mx: ["mx.example.net"] },
    "_mta-sts.example.net": zone.FAILING,
  }), {
    policy: { mtaSts: "enforce", dane: "off" },
    retry:  { maxAttempts: 3, backoffMs: [1, 1, 1] },
  });

  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("a message this server withheld is not mistaken for one nobody answered",
    outcome.deferred[0].held === undefined);
  check("and it keeps this server's own words for the decision",
    /could not be looked up/.test(outcome.deferred[0].reason));
  check("it names no peer, because none was reached",
    outcome.deferred[0].mxHost === undefined || outcome.deferred[0].mxHost === null);
  check("its attempt count advanced the way a retry budget needs it to",
    outcome.deferred[0].attempt === 1);
}

// Narrowing the queue to one sender or one receiving domain. The two
// questions an operator actually asks of a backlog are "is this one
// account flooding" and "is this one receiver deferring me", and both
// are unanswerable against a list of everything.
//
// The filters have to be right in both directions. One that returns too
// much wastes a reading. One that returns too little says a sender or a
// destination has nothing waiting when it does, which is worse, because
// it is the same sentence a genuinely empty queue produces.
async function theQueueNarrowsToOneSenderOrDestination(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);

  async function spool(from, to) {
    await delivery.send({ from: from, to: [to], rfc822: Buffer.from(MESSAGE, "utf8") });
  }
  await spool("alice@example.com", "bob@example.net");
  await spool("alice@example.com", "carol@example.org");
  await spool("dave@example.com",  "erin@example.net");

  check("three messages are waiting", (await delivery.queue.list()).length === 3);

  var byAccount = await delivery.queue.list({ account: "alice@example.com" });
  check("one sender's messages are the ones returned for that sender",
    byAccount.length === 2 &&
    byAccount.every(function (e) { return e.from === "alice@example.com"; }));

  var byDestination = await delivery.queue.list({ destination: "example.net" });
  check("one receiving domain's messages are the ones returned for that domain",
    byDestination.length === 2 &&
    byDestination.every(function (e) { return /@example\.net$/.test(e.recipient); }));

  var both = await delivery.queue.list({
    account: "alice@example.com", destination: "example.net" });
  check("the two filters narrow together rather than either winning",
    both.length === 1 && both[0].recipient === "bob@example.net");

  // Capitalization is the operator's, not the queue's. A filter that
  // depended on it would answer "nothing waiting" for a correct address
  // typed the other way.
  var shouted = await delivery.queue.list({ account: "Alice@EXAMPLE.com" });
  check("the answer does not depend on how the address was capitalized",
    shouted.length === 2);

  var absent = await delivery.queue.list({ account: "nobody@example.com" });
  check("a sender with nothing waiting returns nothing rather than everything",
    absent.length === 0);

  // A filter nobody can act on is refused rather than answered with an
  // empty list, because an empty list reads as a settled fact.
  var threw = null;
  try { await delivery.queue.list({ account: "not an address" }); }
  catch (e) { threw = e; }
  check("an unusable address filter is refused rather than matched against nothing",
    threw !== null && threw.code === "store/bad-address");

  threw = null;
  try { await delivery.queue.list({ destination: "not a domain!!" }); }
  catch (e) { threw = e; }
  check("and an unusable domain filter is refused the same way",
    threw !== null && threw.code === "store/bad-domain");
}

// The answer has to track the framework, not a name somebody once
// guessed at.
//
// This check previously asked whether the surface exported
// `smtpTransport`, which was the name the composer had wrongly reached
// for and which nothing has ever defined. The repair renamed the reach
// instead of adding the export, so the question could never change its
// answer: it went on reporting an outage that had been fixed, and the
// staleness error it carried for exactly that case never fired. A probe
// for a symptom cannot notice the symptom's cause being removed.
//
// So it asks for the capability. Every case below drives a surface
// rather than the real framework, which is what lets the regression
// direction be exercised without altering anything that ships.
function theStatusTracksTheFrameworkSurface() {
  var wireDeliveryStatus = blamepost.mail.delivery.wireDeliveryStatus;

  check("a surface carrying the transport the composer reaches for reports the path open",
    wireDeliveryStatus({ transports: { smtp: function () {} } }).available === true);

  var missing = wireDeliveryStatus({ transports: {} });
  check("a surface without it reports the path closed",
    missing.available === false && missing.reason.length > 0);
  check("and the reason is one an operator can act on rather than a report to follow",
    /vendor-update/.test(missing.reason) && missing.issues.length === 0);

  // Shapes that are not a transport must not read as one. A truthy
  // value that cannot be called is the failure this whole check exists
  // for: the composer would call it and throw, and every recipient would
  // come back deferred with a TypeError for a reason.
  check("a transports table whose smtp is not callable reports the path closed",
    wireDeliveryStatus({ transports: { smtp: {} } }).available === false);
  check("a surface with no transports table at all reports the path closed",
    wireDeliveryStatus({}).available === false);
  check("and a missing surface is read the same way rather than throwing",
    wireDeliveryStatus(null).available === false);

  // The real framework, which is the whole point: the answer this build
  // gives has to be the one measured against what it actually vendors.
  check("the vendored framework this build ships can reach a peer",
    wireDeliveryStatus(b.mail).available === true);
}

// The DANE posture is the operator's statement about their own resolver,
// and it cannot be inferred. RFC 7672 §2.1.1 and §2.2 forbid using a TLSA record
// that was not DNSSEC validated, and asserting validation falsely is
// worse than not running DANE: it authenticates peers against records
// anybody on the path could have rewritten.
function daneEnforcementNeedsTheOperatorsAssertion() {
  var daneEnforcementStatus = blamepost.mail.delivery.daneEnforcementStatus;

  check("enforcing with the assertion beside it is allowed",
    daneEnforcementStatus(b.mail.send, { dane: "enforce", dnssecValidated: true }).available === true);

  var unstated = daneEnforcementStatus(b.mail.send, { dane: "enforce" });
  check("enforcing without it is refused", unstated.available === false);
  check("and the refusal names the setting to add and the value to use instead",
    /dnssecValidated/.test(unstated.reason) && /opportunistic/.test(unstated.reason));
  check("an unstated assertion is not read as a stated one",
    daneEnforcementStatus(b.mail.send, {}).available === false &&
    daneEnforcementStatus(b.mail.send, null).available === false);
  check("and a value that is not the boolean true does not count as the statement",
    daneEnforcementStatus(b.mail.send, { dnssecValidated: "yes" }).available === false);
}

async function run() {
  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }
  try {
    await helpers.withTestTimeout("delivery: reports go out with the empty reverse path",
      function () { return reportsGoOutWithTheEmptyReversePath(freshDir("delivery-report")); });
    await helpers.withTestTimeout("delivery: report generation is bounded",
      function () { return reportGenerationIsBounded(freshDir("delivery-bound")); });
    await helpers.withTestTimeout("delivery: a permanent peer refusal runs the report path",
      function () { return aPermanentPeerRefusalRunsTheReportPath(freshDir("delivery-perm")); });
    await helpers.withTestTimeout("delivery: a report about a report is not generated",
      function () { return aReportAboutAReportIsNotGenerated(freshDir("delivery-loop")); });
    await helpers.withTestTimeout("delivery: an envelope with no message is refused",
      function () { return anEnvelopeWithNoMessageIsRefused(freshDir("delivery-nobody")); });
    await helpers.withTestTimeout("delivery: a retry budget position that is not a count is refused",
      function () { return aRetryBudgetPositionThatIsNotACountIsRefused(freshDir("delivery-budget-shape")); });
    await helpers.withTestTimeout("delivery: a faulted attempt keeps the message",
      function () { return aFaultedAttemptKeepsTheMessage(freshDir("delivery-fault")); });
    await helpers.withTestTimeout("delivery: a temporary refusal keeps the message",
      function () { return aTemporaryRefusalKeepsTheMessage(freshDir("delivery-wait")); });
    await helpers.withTestTimeout("delivery: a permanent refusal clears the entry",
      function () { return aPermanentRefusalClearsTheEntry(freshDir("delivery-clear")); });
    await helpers.withTestTimeout("delivery: attempts against a local fault end the message",
      function () { return attemptsAgainstALocalFaultEndTheMessage(freshDir("delivery-abandon")); });
    await helpers.withTestTimeout("delivery: an entry with nothing left to send is abandoned",
      function () { return anEntryWithNothingLeftToSendIsAbandoned(freshDir("delivery-gone")); });
    await helpers.withTestTimeout("delivery: the build says whether it can reach a peer",
      function () { return theBuildSaysWhetherItCanReachAPeer(freshDir("delivery-held")); });
    await helpers.withTestTimeout("delivery: the retry budget ends the message and tells the sender",
      function () { return theRetryBudgetEndsTheMessageAndTellsTheSender(freshDir("delivery-budget")); });
    await helpers.withTestTimeout("delivery: a verdict still spends the budget",
      function () { return aVerdictStillSpendsTheBudget(freshDir("delivery-peer")); });
    await helpers.withTestTimeout("delivery: the queue narrows to one sender or destination",
      function () { return theQueueNarrowsToOneSenderOrDestination(freshDir("delivery-filter")); });
    await helpers.withTestTimeout("delivery: the status tracks the framework surface",
      function () { return Promise.resolve(theStatusTracksTheFrameworkSurface()); });
    await helpers.withTestTimeout("delivery: dane enforcement needs the operator's assertion",
      function () { return Promise.resolve(daneEnforcementNeedsTheOperatorsAssertion()); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "mail-delivery", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
