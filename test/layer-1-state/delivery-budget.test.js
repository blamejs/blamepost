// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The retry budget, and the one question it has to get right: what
 * happens to a message on the attempt that exhausts it?
 *
 * The answer is that the message ends and its sender is told. Both
 * halves are load-bearing and neither works without the other. Ending it
 * takes it off disk, which is only defensible because a report goes to
 * the sender, who can then send it again; a server that ends messages
 * silently loses mail at both ends, and one that never ends them
 * accumulates a spool nobody is ever told about.
 *
 * How that decision is reached matters as much as the decision. It is
 * made from which of the composer's lists a recipient came back on,
 * which is an explicit verdict, and never from reading the words in a
 * refusal. A classifier built on recognizing a sentence keeps exactly
 * the failures somebody already thought of and charges every other one
 * to a peer's budget, and the failures nobody has enumerated are the
 * whole population of the future ones. A peer can also write whatever it
 * likes into a refusal, including this server's own vocabulary, so a
 * decision that reads text is a decision a stranger can steer.
 *
 * The resolver decides every outcome. ANSWERING_MX is the one that gets
 * past MX lookup and policy to a transport; the host it names does not
 * resolve, so the attempt ends at the connect and nothing leaves the
 * machine.
 *
 * Run standalone: node test/layer-1-state/delivery-budget.test.js
 */

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// Answers with a host, so the composer clears MX lookup and policy and
// builds a transport. The host does not resolve, so the attempt ends at
// the connect and nothing leaves the machine.
var ANSWERING_MX = {
  queryMx: function () {
    return Promise.resolve([{ priority: 10, exchange: "mx.example.net" }]);
  },
};

// The RFC 7505 null MX. The domain refuses mail outright, which the
// composer classifies as permanent on the first look.
var REFUSING_MX = {
  queryMx: function () {
    return Promise.resolve([{ priority: 0, exchange: "" }]);
  },
};

// A peer-side transient: the lookup itself fails, so the recipient is
// deferred with the resolver's own words.
var UNREACHABLE_MX = {
  queryMx: function () {
    return Promise.reject(new Error("probe resolver: MX lookup unavailable"));
  },
};

// The enhanced status the composer falls back to when no mail exchanger
// ever answered. RFC 3463 §3.4 X.4.4 is written verbatim at the end of
// the per-host loop, reached only when there is no reply to take a code
// from, so it is a frozen contract rather than a phrase.
var NO_ANSWER_STATUS = "4.4.4";

// The give-up time RFC 5321 §4.5.4.1 asks a sender to keep: the give-up
// time generally needs to be at least 4 to 5 days. Postfix ships five
// days under `maximal_queue_lifetime`, so a receiver measures its own
// maintenance window against days. A sender that abandons sooner turns a
// planned outage on the far side into a permanent bounce, and an
// operator migrating from an established MTA loses the mail that would
// have been delivered on the other side of it.
var RFC_5321_GIVE_UP_FLOOR_MS = helpers.b.constants.TIME.days(4);

// The other end of the same window. A week is the module's own ceiling
// on a single wait, and a message held past it has been resent by its
// sender long since, so the report it eventually produces answers a
// question nobody is still asking.
var GIVE_UP_CEILING_MS = helpers.b.constants.TIME.days(7);

// The settings table an operator reads to find out what they are running
// without changing anything.
var SETTINGS_REFERENCE = "docs/operator-guide.md";
var RETRY_SETTING      = "BLAMEPOST_OUTBOUND_RETRY";

// Two schedules match when they name the same waits in the same order.
// Read rather than compared as objects, because the guide's cell is
// parsed JSON and the handle's is a live array.
function sameWaits(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  for (var i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

// One measured wait against the schedule it should have come from. The
// waits taken off a sweep are exact, because the sweep is handed the
// moment it works from; the first one is set by `send`, which reads the
// clock itself, so it carries however long the send took.
//
// Half a minute of slack for that, which is a runner under load rather
// than a schedule, and which still tells the rungs apart: the shipped
// schedule's closest pair is four minutes wide.
var WAIT_SLACK_MS = 30000;

function isWait(measured, want) {
  return Math.abs(measured - want) < WAIT_SLACK_MS;
}

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

function sendOne(delivery, extra) {
  var envelope = {
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  };
  if (extra) Object.assign(envelope, extra);
  return delivery.send(envelope);
}

// ---------------------------------------------------------------------------
// The attempt that exhausts the budget
// ---------------------------------------------------------------------------

// A one-attempt budget is a configuration an operator can set today:
// the schema takes maxAttempts from 1 and says what it means. On that
// setting every single outbound message reaches the composer with the
// budget already on its last attempt, so the first send is also the
// last and the message ends there.
async function aOneAttemptBudgetEndsTheMessageAndTellsTheSender(dataDir) {
  var delivery = handleOn(dataDir, ANSWERING_MX, {
    retry: { maxAttempts: 1, backoffMs: [1000] },
  });

  var outcome = await sendOne(delivery);

  check("the attempt that exhausts the budget ends the message",
    outcome.failed.length === 1 && outcome.deferred.length === 0);
  check("and what the attempt actually met is kept rather than overwritten",
    outcome.failed[0].reason.length > 0);
  check("the sender was told rather than counted as somebody nobody could tell",
    outcome.failed[0].dsnSent === true && delivery.describe().reportsUnsent === 0);
  check("nothing is left waiting without a deadline against it",
    (await delivery.queue.held()).messages === 0);
  // The message it was about is gone, which is the whole trade: it can
  // be sent again by somebody who now knows it never arrived. On this
  // budget the report is on its last attempt too, so nothing is left
  // behind for either of them.
  check("and the message that ended is not still on disk",
    spoolFiles(dataDir).length === 0);
}

// A spooled entry that spent its attempts against a real outage arrives
// at the composer one attempt short of the budget. That attempt is the
// one that ends it, and it has to end it rather than rescheduling
// forever.
async function aSpooledEntryAtTheEndOfItsBudgetEnds(dataDir) {
  var delivery = handleOn(dataDir, ANSWERING_MX, {
    retry: { maxAttempts: 3, backoffMs: [1000, 1000, 1000] },
  });

  await sendOne(delivery);
  var id = onlyId(dataDir);
  check("the first send spools the message", id !== null);
  check("and spends one attempt doing it", readDescriptor(dataDir, id).attempt === 1);

  // Stand the entry up where an outage would have left it: one attempt
  // short of the budget, and due now.
  var primed = readDescriptor(dataDir, id);
  primed.attempt = 2;
  primed.nextAttemptAt = Date.now() - 1;
  writeDescriptor(dataDir, id, primed);

  var run = await delivery.queue.runDue();
  check("the sweep that exhausts the budget gives up rather than rescheduling",
    run.results.length === 1 && run.results[0].outcome === "failed");
  check("the entry is off disk", !fs.existsSync(path.join(dataDir, "queue", id + ".json")));
  check("and the sender is told rather than counted as untellable",
    delivery.describe().reportsUnsent === 0);
}

// The other direction. A peer that says no permanently is a permanent
// failure however large the budget is, and the entry has to leave on the
// first attempt rather than spending a budget that cannot change it.
async function aPeerPermanentRefusalStillEndsTheEntry(dataDir) {
  var delivery = handleOn(dataDir, REFUSING_MX, {
    retry: { maxAttempts: 1, backoffMs: [1000] },
  });

  var outcome = await sendOne(delivery);
  check("a domain publishing the null MX is a permanent refusal",
    outcome.failed.length === 1 && outcome.deferred.length === 0);
  check("the sender was told about it",
    outcome.failed[0].dsnSent === true);
  check("and nothing is counted as a report this server could not send",
    delivery.describe().reportsUnsent === 0);
}

// A peer must not be able to steer what happens to a message by what it
// writes in a refusal.
//
// What the far side says is quoted into the refusal, so a domain can put
// whatever it likes in there, including any wording this server might
// have been tempted to recognize. If the wording decided anything, a
// domain could choose whether its own permanent refusal was reported to
// the sender or quietly kept, and the spool would grow or drain on a
// stranger's say so. Which list the recipient came back on is the
// verdict, and no text anywhere is consulted to read it.
async function aPeerCannotSteerTheOutcomeWithItsWording(dataDir) {
  var IMPERSONATING_MX = {
    queryMx: function () {
      var err = new Error("550 5.1.2 held rather than given up on: " +
        "outbound mail cannot reach a peer in this build, factory is not a function");
      err.code = "deliver/no-mx";
      return Promise.reject(err);
    },
  };
  var delivery = handleOn(dataDir, IMPERSONATING_MX, {
    retry: { maxAttempts: 3, backoffMs: [1000, 2000, 4000] },
  });

  var outcome = await sendOne(delivery);
  check("a domain's own permanent refusal stays a permanent refusal",
    outcome.failed.length === 1 && outcome.deferred.length === 0);
  check("whatever vocabulary the domain wrote into it",
    /outbound mail cannot reach a peer|is not a function/.test(outcome.failed[0].reason));
  check("nothing is kept back on its say so",
    (await delivery.queue.held()).messages === 0);
  check("and the sender is told, which is what the domain was trying to prevent",
    outcome.failed[0].dsnSent === true);
}

// A verdict this server made itself still spends the budget.
//
// Withholding a message over an MTA-STS record the pinned resolver
// could not settle is a decision, not a missing answer: this server
// chose it, wrote its own enhanced status on it, and would make the
// same choice again. So the attempt is charged, and running the budget
// out ends the message like any other.
//
// A receiver whose record never settles is the case that makes this
// matter. Retrying it forever means its senders are never told, and the
// spool grows for as long as the record stays broken.
async function aVerdictThisServerMadeStillSpendsTheBudget(dataDir) {
  var resolver = zone.resolverOver({
    "example.net":          { mx: ["mx.example.net"] },
    "_mta-sts.example.net": zone.FAILING,
  });
  var delivery = handleOn(dataDir, resolver, {
    policy: { mtaSts: "enforce", dane: "off" },
    retry:  { maxAttempts: 2, backoffMs: [1000, 1000] },
  });

  var outcome = await sendOne(delivery);
  check("a record this server could not settle defers the recipient",
    outcome.deferred.length === 1 && outcome.failed.length === 0);
  check("under this server's own enhanced status rather than a missing answer",
    outcome.deferred[0].reasonCode === "4.7.0");
  check("and the attempt is charged, because the verdict was a real one",
    outcome.deferred[0].attempt === 1 && readDescriptor(dataDir, onlyId(dataDir)).attempt === 1);

  var id = onlyId(dataDir);
  for (var i = 0; i < 4; i += 1) {
    await delivery.queue.runDue({ force: true });
  }

  check("running out of attempts ends the message rather than retrying it forever",
    !fs.existsSync(path.join(dataDir, "queue", id + ".json")));
  check("and nothing is left held with no deadline against it",
    (await delivery.queue.held()).messages === 0);
}

// ---------------------------------------------------------------------------
// What decides whether an unsent message is kept
// ---------------------------------------------------------------------------

// An enforcing DANE posture with nothing standing behind it is refused
// at the boot rather than accepted and allowed to authenticate against
// records nobody validated.
//
// RFC 7672 §2.1.1 and §2.2 forbid using a TLSA record that was not DNSSEC
// validated. Whether the resolver this server was given validates is a
// fact about that resolver, which may be a local validating one, a
// forwarder that strips the authenticated-data bit, or a public endpoint
// reached over DoH. Nothing here can check it, so the operator states it
// and this server refuses to state it on their behalf: asserting it
// falsely is worse than not running DANE, because it authenticates peers
// against records anybody on the path could have rewritten under a
// banner saying they were verified.
//
// The operator has to hear that while they are setting it, not from a
// queue days later.
function daneEnforcementNeedsTheAssertion(dataDir) {
  var threw = null;
  try {
    handleOn(dataDir, ANSWERING_MX, { policy: { mtaSts: "off", dane: "enforce" } });
  } catch (e) { threw = e; }

  check("enforcing without the assertion is refused rather than accepted",
    threw !== null);
  check("the refusal says what the rule is",
    /RFC 7672/.test(String(threw.message)) && /DNSSEC/.test(String(threw.message)));
  check("names the setting that would satisfy it",
    /dnssecValidated/.test(String(threw.message)));
  check("says what goes wrong if it is asserted untruthfully",
    /rewritten/.test(String(threw.message)));
  check("and names the value to use instead of leaving the operator guessing",
    /opportunistic/.test(String(threw.message)));

  var asserted = handleOn(dataDir, ANSWERING_MX, {
    policy: { mtaSts: "off", dane: "enforce", dnssecValidated: true },
  });
  check("enforcing with the assertion beside it builds a handle",
    typeof asserted.send === "function");
  check("and the handle reports the posture it is actually running",
    asserted.describe().policy.dane === "enforce" &&
    asserted.describe().policy.dnssecValidated === true);

  var ok = handleOn(dataDir, ANSWERING_MX, { policy: { mtaSts: "off", dane: "opportunistic" } });
  check("the shipped posture still builds a handle", typeof ok.send === "function");
  check("and does not claim an assertion nobody made",
    ok.describe().policy.dnssecValidated === false);
  var off = handleOn(dataDir, ANSWERING_MX, { policy: { mtaSts: "off", dane: "off" } });
  check("and so does turning it off outright", typeof off.send === "function");
}

// A lookup that could not complete is an ordinary transient, and the
// budget is what decides how long this server waits before telling the
// sender it gave up.
//
// The words it fails in match nothing this server knows, and that is the
// point: the outcome is read from which list the recipient came back on
// and from the enhanced status, both of which are the composer's own
// contracts, so a fault nobody enumerated is handled the same way as one
// somebody did.
async function anUnrecognizedFaultStillSpendsTheBudget(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX, {
    retry: { maxAttempts: 2, backoffMs: [1000, 1000] },
  });

  var outcome = await sendOne(delivery);
  check("a lookup that could not complete leaves the recipient deferred",
    outcome.deferred.length === 1 && outcome.failed.length === 0);
  check("in words this server has never seen before",
    /MX lookup unavailable/.test(outcome.deferred[0].reason));
  check("carrying the status that means nobody answered, and naming no receiver",
    outcome.deferred[0].reasonCode === NO_ANSWER_STATUS && !outcome.deferred[0].mxHost);
  check("and it spends its place in the budget like any other transient",
    outcome.deferred[0].attempt === 1);

  var id = onlyId(dataDir);
  for (var i = 0; i < 4; i += 1) {
    await delivery.queue.runDue({ force: true });
  }

  check("running the budget out ends it rather than keeping it forever",
    !fs.existsSync(path.join(dataDir, "queue", id + ".json")));
  check("and nothing is left held with no deadline against it",
    (await delivery.queue.held()).messages === 0);
}

// The direction that must not move. A verdict is a verdict whoever
// makes it, and an answer that can never become a delivery has to end
// the entry on the first attempt rather than spending a budget against
// something no amount of waiting changes.
//
// Both of these are settled without a peer being reached at all, and
// that is correct: the domain's own zone answered in the first case and
// the address itself is unroutable in the second.
async function anAnswerThatCanNeverSucceedStillEndsTheEntry(dataDir) {
  var refusing = handleOn(dataDir, REFUSING_MX, {
    retry: { maxAttempts: 3, backoffMs: [1000, 1000, 1000] },
  });
  var outcome = await sendOne(refusing);
  check("a domain publishing the null MX ends the entry on the first attempt",
    outcome.failed.length === 1 && outcome.deferred.length === 0);
  check("without spending the rest of a budget that could not have changed it",
    outcome.failed[0].reasonCode === "5.1.2");
  check("and the sender is told about it",
    outcome.failed[0].dsnSent === true);

  var routed = handleOn(dataDir, ANSWERING_MX, {
    retry: { maxAttempts: 3, backoffMs: [1000, 1000, 1000] },
  });
  var bad = await routed.send({
    from:   "alice@example.com",
    to:     ["bob@example.net@elsewhere.example"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("an address that cannot be routed is refused rather than retried",
    bad.failed.length === 1 && bad.deferred.length === 0);
}

// ---------------------------------------------------------------------------
// Giving up on a fault this server owns
// ---------------------------------------------------------------------------

// The budget above is spent against peers, and the composer converts its
// last attempt into a permanent failure with a report. This is the other
// budget: an entry that never reaches a peer at all, because something
// on this side answered instead. A record the pinned resolver could not
// settle is the shipped example, and an entry that keeps throwing is the
// general one.
//
// The message ends the same way and it owes the same report. A sender
// who hears "this never arrived" can send it again; a sender who hears
// nothing believes it went. That the fault was this server's rather than
// a receiver's changes who should fix it and changes nothing at all
// about who has to be told.
//
// RFC 3463 §4.4 has the status for exactly this: the message was held
// as long as this server was willing to hold it. It is not the status a
// peer's refusal carries, because it is not a peer's refusal.
async function aFaultOnThisSideStillReportsToTheSender(dataDir) {
  var resolver = zone.resolverOver({
    "example.net":          { mx: ["mx.example.net"] },
    "_mta-sts.example.net": zone.FAILING,
    // The sender's own domain, so the report this server owes has
    // somewhere to be addressed. Its exchanger does not resolve, so the
    // report gets as far as the spool and no further, which is where a
    // test can read it.
    "example.com":          { mx: ["mx.example.com"] },
  });
  var delivery = handleOn(dataDir, resolver, {
    policy: { mtaSts: "enforce", dane: "off" },
    retry:  { maxAttempts: 2, backoffMs: [1000, 1000] },
  });

  await sendOne(delivery);
  var id = onlyId(dataDir);
  check("the withheld message is spooled", id !== null);

  // One sweep, because the send already spent the first attempt: the
  // next one reaches the end of the budget and ends the message. Any
  // more and the report this produces would be attempted too, and its
  // own budget would take it away before it could be read.
  await delivery.queue.runDue({ force: true });

  check("the entry this server gave up on is off disk",
    !fs.existsSync(path.join(dataDir, "queue", id + ".json")));

  var waiting = await delivery.queue.list();
  var reports = waiting.filter(function (row) { return row.recipient === "alice@example.com"; });
  count("giving up generates a delivery report addressed to the sender",
    reports.length === 1, JSON.stringify(waiting));
  check("carrying the empty reverse path, so a report that fails cannot start a second",
    reports.length === 1 && reports[0].from === "");
  check("and nothing is counted as a report this server owed and could not send",
    delivery.describe().reportsUnsent === 0);

  var composed = reports.length === 1
    ? fs.readFileSync(path.join(dataDir, "queue", reports[0].id + ".eml"), "utf8")
    : "";
  check("the report is the RFC 3464 shape a sender's client can read",
    /multipart\/report; report-type=delivery-status/.test(composed) &&
    /Content-Type: message\/delivery-status/.test(composed));
  check("it names the address that never got the message",
    /Final-Recipient: rfc822; bob@example\.net/.test(composed));
  check("says the delivery failed rather than that it is still being tried",
    /Action: failed/.test(composed));
  check("under the status for a message this server held as long as it would",
    /Status: 4\.4\.7/.test(composed));
  check("and says what the last attempt met, so the sender can act on it",
    /MTA-STS record for example\.net could not be looked up/.test(composed));

  // RFC 3462 §3 puts the original headers in the last part, and they are
  // how a sender tells this report from the others in their mailbox. A
  // report about "a message" is one they cannot act on: they sent
  // several, and the recipient and the status are the same on all of
  // them. The quoted block is the only thing that names which one.
  var quoted = composed.split("Content-Type: text/rfc822-headers")[1] || "";
  check("the report quotes the original message's headers, so the sender can tell which " +
    "message it is about",
    /^To: bob@example\.net$/m.test(quoted) && /^From: alice@example\.com$/m.test(quoted));
  check("and quotes the headers alone rather than the message, which RFC 3462 §3 is what " +
    "asks for and which is what keeps a report bounded",
    quoted.indexOf("body") === -1);

  // The report is now the only thing on the spool, and its own budget
  // runs out the same way. RFC 5321 §6.1: the sender of a report is
  // nobody, so this one ends in silence rather than in a report about a
  // report.
  for (var j = 0; j < 4; j += 1) {
    await delivery.queue.runDue({ force: true });
  }
  check("the report's own budget ends it rather than keeping it forever",
    (await delivery.queue.list()).length === 0);
  check("and generates nothing to send about it, so the loop is closed",
    delivery.describe().reportsUnsent === 0);
}

// The other way an entry is given up on, and the one that must NOT
// report.
//
// A descriptor whose message is no longer beside it is not a message
// this server lost. The spool writes the message first and removes it
// first, so a body missing under a descriptor that is still there is a
// removal that got half way: an operator cancelling the message, or an
// attempt that settled it and could not take the descriptor off the
// volume afterwards.
//
// Every one of those has already decided what the sender hears. A
// cancellation from the console writes to the sender itself; a
// cancellation from the command line deliberately does not, and the
// incident runbook reaches for that verb on mail a stolen credential
// sent, where the sender is whoever sent it. A message a peer accepted
// would be reported as failed to somebody whose mail arrived.
//
// So this abandonment tells the operator and nobody else, and the check
// below is what stops a later change from turning it into mail.
async function aMessageWhoseBodyHasGoneIsNotReportedToItsSender(dataDir) {
  var resolver = zone.resolverOver({
    "example.net": { mx: ["mx.example.net"] },
    "example.com": { mx: ["mx.example.com"] },
  });
  var delivery = handleOn(dataDir, resolver, {
    retry: { maxAttempts: 5, backoffMs: [1000, 1000, 1000, 1000, 1000] },
  });

  await sendOne(delivery);
  var id = onlyId(dataDir);
  check("the message is spooled with a body beside its descriptor",
    id !== null && fs.existsSync(path.join(dataDir, "queue", id + ".eml")));

  // What a cancellation interrupted between its two unlinks leaves
  // behind, and what a settled attempt leaves when the volume keeps the
  // descriptor.
  fs.unlinkSync(path.join(dataDir, "queue", id + ".eml"));

  var run = await delivery.queue.runDue({ force: true });
  count("the sweep gives up on an entry with nothing left to send",
    run.results.length === 1 && run.results[0].outcome === "abandoned",
    JSON.stringify(run.results));
  check("and takes the descriptor with it rather than retrying forever",
    !fs.existsSync(path.join(dataDir, "queue", id + ".json")));

  count("no report is generated about a message somebody else already settled",
    (await delivery.queue.list()).length === 0,
    JSON.stringify(await delivery.queue.list()));
  check("and none is recorded as owed, because none was owed",
    delivery.describe().reportsUnsent === 0);
}

// The message is NOT put back when the removal follows an attempt, and
// this is the vector that says so.
//
// One function takes an entry apart for both verbs, and the two need
// opposite answers to the same fault. A cancellation whose descriptor
// the volume keeps puts the message back, because nothing was cancelled
// and the message is still owed to its recipient. A removal that follows
// an attempt must not: the entry is being cleared BECAUSE the message
// was settled, so a body put back is a message the next sweep sends to a
// recipient who already has it, or a message reported to a sender whose
// mail arrived.
//
// The budget running out is the abandonment reachable without a peer,
// and it takes the same path a delivered message takes, so this pins the
// half that must stay gone. The cancellation half is pinned in
// test/layer-1-state/queue-removal-verdict.test.js, where a refused
// removal is asserted to leave a message the sweep can still send.
async function aSettledMessageIsNotPutBackWhenTheVolumeKeepsTheDescriptor(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX, {
    retry: { maxAttempts: 2, backoffMs: [1000, 1000] },
  });

  await sendOne(delivery);
  var id = onlyId(dataDir);
  check("the message is spooled with a body beside its descriptor",
    id !== null && fs.existsSync(path.join(dataDir, "queue", id + ".eml")));

  // Due now and one attempt short of the budget, which is where an
  // outage leaves an entry: the next sweep is the one that ends it.
  var primed = readDescriptor(dataDir, id);
  primed.nextAttemptAt = Date.now() - 1;
  writeDescriptor(dataDir, id, primed);

  var fault = helpers.installRemovalFault(id + ".json");
  var run;
  try { run = await delivery.queue.runDue({ force: true }); }
  finally { fault.remove(); }

  count("one recipient's volume fault does not stop the sweep, it is reported",
    run.results.length === 1 && run.results[0].outcome === "error",
    JSON.stringify(run.results));
  count("and the row names the volume keeping the entry, which is the actionable half",
    /could not be taken off/.test(String(run.results[0].error)),
    JSON.stringify(run.results));

  count("the message stays destroyed rather than being put back for a second delivery",
    !fs.existsSync(path.join(dataDir, "queue", id + ".eml")),
    JSON.stringify(spoolFiles(dataDir)));
  count("while the file that lists the entry is still there, which is why the sweep raised",
    fs.existsSync(path.join(dataDir, "queue", id + ".json")),
    JSON.stringify(spoolFiles(dataDir)));
  var mine = spoolFiles(dataDir).filter(function (name) { return name.indexOf(id) === 0; });
  count("so the entry's own remainder is the descriptor and nothing else",
    mine.length === 1 && mine[0] === id + ".json", JSON.stringify(mine));

  // The attempt that ended the message is what tells its sender, and it
  // did that before the volume refused anything. A descriptor the volume
  // keeps afterwards leaves the entry to be cleared; it does not un-tell
  // anybody, and it must not tell them twice either.
  var told = (await delivery.queue.list()).filter(function (row) {
    return row.recipient === "alice@example.com";
  });
  count("the sender was told once, by the attempt that ended the message",
    told.length === 1, JSON.stringify(await delivery.queue.list()));

  // The volume is willing again, which is the state an operator reaches
  // after clearing whatever held the file. What is left is an entry with
  // nothing to send, and it has to end there rather than becoming mail.
  var after = await delivery.queue.runDue({ force: true });
  var remainder = after.results.filter(function (row) { return row.id === id; });
  count("the sweep that meets the remainder gives up on it",
    remainder.length === 1 && remainder[0].outcome === "abandoned",
    JSON.stringify(after.results));
  count("the spool is empty rather than holding a message its recipient already has",
    spoolFiles(dataDir).length === 0, JSON.stringify(spoolFiles(dataDir)));
  count("and no second report was composed about a message whose sender had already been " +
    "told, which a report generated by the remainder would have left waiting here",
    (await delivery.queue.list()).length === 0 && delivery.describe().reportsUnsent === 0,
    JSON.stringify(await delivery.queue.list()));
}

// A waiting entry has to be findable, or the spool that keeps the mail
// becomes a place mail goes to be forgotten. The projection is what
// `blamepost queue show` prints, so it is where an operator reads why
// one entry is not moving and how it ends if nothing changes.
async function aWaitingEntrySaysHowItEnds(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX, {
    retry: { maxAttempts: 3, backoffMs: [1000, 1000, 1000] },
  });

  await sendOne(delivery);
  var shown = await delivery.queue.show(onlyId(dataDir));
  check("the entry is counted down towards the deadline it is spending",
    shown !== null && shown.projection.held === false &&
    shown.projection.attemptsSpent === 1 && shown.projection.attemptsRemaining === 2);
  check("the sentence says how many attempts are left",
    /2 more attempt/.test(shown.projection.ifItNeverSucceeds));
  check("and says the sender is the one who hears about it",
    /report is sent to/.test(shown.projection.ifItNeverSucceeds) &&
    /alice@example\.com/.test(shown.projection.ifItNeverSucceeds));
  check("the entry's own record still carries what the attempt met",
    /MX lookup unavailable/.test(shown.reason));

  var held = await delivery.queue.held();
  check("nothing is held, because nothing is waiting on anything but the budget",
    held.messages === 0 && delivery.describe().waiting === 1);
}

// ---------------------------------------------------------------------------
// The waits the budget is spent on
// ---------------------------------------------------------------------------

// A waiting entry climbs the operator's rising waits, one rung per
// attempt, and the rung it takes is the one its attempt number names.
// The first attempt waits the first interval, not the last one and not
// the shortest one in the list.
async function aWaitingEntryClimbsTheConfiguredWaits(dataDir) {
  var first = helpers.b.constants.TIME.minutes(30);
  var delivery = handleOn(dataDir, ANSWERING_MX, {
    retry: { maxAttempts: 4, backoffMs: [first, first * 2, first * 3] },
  });

  var before = Date.now();
  await sendOne(delivery);
  var descriptor = readDescriptor(dataDir, onlyId(dataDir));
  check("the first attempt waits the first interval the operator wrote",
    descriptor.nextAttemptAt - before >= first - 1000 &&
    descriptor.nextAttemptAt - before < first * 2);
}

// The budget an operator gets by changing nothing, walked end to end
// over the real spool.
//
// Two things have to hold of it and neither is visible from reading the
// schedule on its own. Every wait in the schedule has to be one a
// message actually waits: the delivery path clamps its index at the last
// entry so that entry repeats as the steady state, and an attempt count
// equal to the schedule's length reaches the one before it and stops, so
// the longest wait is written down and never used. And the total has to
// reach the give-up time RFC 5321 §4.5.4.1 asks for, because that number
// is what a receiver's maintenance window is measured against: a peer
// down for an afternoon must not turn every message addressed to it into
// a permanent bounce.
//
// The entry is driven with the resolver that fails the lookup, so every
// attempt is an ordinary transient and the budget is spent the way an
// outage spends it. Each sweep is handed the moment it works from, so
// the wait it schedules is the schedule rather than the schedule plus
// however long the sweep took.
async function theShippedBudgetHoldsMailForTheGiveUpTimeTheRfcAsksFor(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);
  var policy   = delivery.describe().policy;
  var ramp     = policy.backoffMs;

  var before = Date.now();
  await sendOne(delivery);
  var id = onlyId(dataDir);
  check("the budget an operator changes nothing to get spools a deferred message",
    id !== null);

  var waits = [readDescriptor(dataDir, id).nextAttemptAt - before];
  var ended = null;
  var clock = before;
  // One iteration per attempt the budget can hold, and a few beyond it:
  // a budget that never ends is the failure this is measuring, so the
  // loop has to stop on its own rather than run until the file is gone.
  var ceiling = policy.maxAttempts + 8;
  for (var i = 0; i < ceiling && ended === null; i += 1) {
    var run  = await delivery.queue.runDue({ force: true, now: clock });
    var mine = run.results.filter(function (row) { return row.id === id; });
    if (mine.length !== 1) break;
    if (mine[0].outcome === "waiting") { waits.push(mine[0].retryAt - clock); continue; }
    ended = mine[0];
  }

  helpers.count("the entry ends rather than being retried without a deadline",
    ended !== null && ended.outcome === "failed", JSON.stringify(ended));
  helpers.count("and it ends on the attempt the budget names, having waited once for every " +
    "attempt before it",
    waits.length === policy.maxAttempts - 1,
    waits.length + " wait(s) against " + policy.maxAttempts + " attempt(s)");

  var total = waits.reduce(function (a, w) { return a + w; }, 0);
  helpers.count("the message is held for at least the four days RFC 5321 §4.5.4.1 asks a sender " +
    "to keep, so a receiver down for an afternoon does not produce a permanent bounce",
    total >= RFC_5321_GIVE_UP_FLOOR_MS,
    "held " + total + "ms against a floor of " + RFC_5321_GIVE_UP_FLOOR_MS + "ms");
  helpers.count("and not past the week beyond which its sender has resent it anyway",
    total <= GIVE_UP_CEILING_MS,
    "held " + total + "ms against a ceiling of " + GIVE_UP_CEILING_MS + "ms");

  var longest = waits.reduce(function (a, w) { return w > a ? w : a; }, 0);
  helpers.count("the longest wait the schedule names is one a message actually waits, rather " +
    "than an entry the attempt count stops short of",
    isWait(longest, ramp[ramp.length - 1]),
    "longest wait " + longest + "ms against a schedule ending at " + ramp[ramp.length - 1] + "ms");

  var unreached = ramp.filter(function (rung) {
    return !waits.some(function (w) { return isWait(w, rung); });
  });
  helpers.count("and no wait in the schedule is unreachable",
    unreached.length === 0, JSON.stringify(unreached));

  helpers.count("the first wait is still the first rung, so a receiver that greylists is retried " +
    "within minutes rather than after the whole steady state",
    isWait(waits[0], ramp[0]), waits[0] + "ms against " + ramp[0] + "ms");
}

// The settings table is where an operator reads the budget without
// running anything, and it is the only copy of these numbers outside the
// delivery module. The generic defaults check in
// test/layer-1-state/docs-surface.test.js cannot reach it: the loader
// carries no fallback for this setting, because the delivery module owns
// the value, so the row is compared against the handle that publishes it
// instead.
function theGuidePrintsTheShippedRetryBudget(dataDir) {
  var policy = handleOn(dataDir, ANSWERING_MX).describe().policy;
  var text   = fs.readFileSync(path.join(helpers.REPO_ROOT, SETTINGS_REFERENCE), "utf8");

  var row = null;
  text.split("\n").forEach(function (line) {
    var m = new RegExp("^\\|\\s*`" + RETRY_SETTING + "`\\s*\\|(.*)$").exec(line);
    if (m) row = m[1].split("|").map(function (cell) { return cell.trim(); });
  });
  check("the settings table has a row for " + RETRY_SETTING, row !== null);

  // Cell 0 is the configuration key and cell 1 is the default. A cell
  // that is not the schedule at all reads as an absent one, so the
  // checks below name the table rather than raising a parse error.
  var printed;
  try { printed = JSON.parse(String((row && row[1]) || "").replace(/`/g, "")); }
  catch (_e) { printed = null; }
  helpers.count("and prints its default as a schedule a reader can act on",
    printed !== null && typeof printed === "object", String(row && row[1]));

  helpers.count("the attempt count it prints is the one the delivery path spends",
    printed !== null && printed.maxAttempts === policy.maxAttempts,
    "the guide prints " + JSON.stringify(printed && printed.maxAttempts) +
    " and the delivery path spends " + policy.maxAttempts);
  helpers.count("and the waits it prints are the ones the delivery path schedules",
    printed !== null && sameWaits(printed.backoffMs, policy.backoffMs),
    "the guide prints " + JSON.stringify(printed && printed.backoffMs) +
    " and the delivery path schedules " + JSON.stringify(policy.backoffMs));
}

// The waits are read straight into date arithmetic, so a value that is
// not a positive number of milliseconds produces a moment that is
// either in the past forever or not a number at all. Either one turns
// the sweep into a hot loop that spends the whole budget in a second.
// This is a create-time entry point, so it refuses rather than
// degrading to a default the operator never asked for.
function badRetrySettingsAreRefusedAtCreate(dataDir) {
  function refuses(label, retry, expect) {
    var threw = null;
    try {
      blamepost.mail.delivery.create({
        hostname: "mx.example.com",
        dataDir:  dataDir,
        policy:   { mtaSts: "off", dane: "off" },
        audit:    false,
        retry:    retry,
      });
    } catch (e) { threw = e; }
    check(label, threw !== null && expect.test(String(threw.message)));
  }

  refuses("a wait that is not a number is refused",
    { backoffMs: ["1000"] }, /backoffMs/);
  refuses("a wait that is not finite is refused",
    { backoffMs: [Number.NaN] }, /backoffMs/);
  refuses("a wait of infinity is refused",
    { backoffMs: [Number.POSITIVE_INFINITY] }, /backoffMs/);
  refuses("a negative wait is refused",
    { backoffMs: [-1] }, /backoffMs/);
  refuses("a wait of zero is refused, because it retries without waiting",
    { backoffMs: [0] }, /backoffMs/);
  // A wait this long is not a schedule. The moment it names is inside
  // the range a date can hold, so nothing throws and nothing overflows:
  // the entry simply never becomes due, is never retried, is never
  // given up on, and its sender is never told.
  refuses("a wait longer than a week is refused, because the entry would never come due",
    { backoffMs: [Number.MAX_VALUE] }, /backoffMs/);
  refuses("and so is one just over that ceiling",
    { backoffMs: [helpers.b.constants.TIME.days(7) + 1] }, /backoffMs/);
  refuses("a backoff list that is not a list is refused rather than ignored",
    { backoffMs: "1000" }, /backoffMs/);
  refuses("an empty backoff list is refused rather than silently defaulted",
    { backoffMs: [] }, /backoffMs/);
  refuses("an attempt count of zero is refused",
    { maxAttempts: 0 }, /maxAttempts/i);
  refuses("a fractional attempt count is refused",
    { maxAttempts: 2.5 }, /maxAttempts/i);

  // The settings an operator legitimately sets still build.
  var ok = blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
    retry:    { maxAttempts: 3, backoffMs: [1000, 2000, 4000] },
  });
  check("a usable retry setting still builds a handle", typeof ok.send === "function");

  var defaulted = blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
    retry:    { maxAttempts: 3 },
  });
  check("leaving the waits out keeps the shipped defaults",
    typeof defaulted.send === "function");
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
    await helpers.withTestTimeout("delivery budget: a one attempt budget ends the message and tells the sender",
      function () { return aOneAttemptBudgetEndsTheMessageAndTellsTheSender(freshDir("dlv-budget-one")); });
    await helpers.withTestTimeout("delivery budget: an entry at the end of its budget ends",
      function () { return aSpooledEntryAtTheEndOfItsBudgetEnds(freshDir("dlv-budget-last")); });
    await helpers.withTestTimeout("delivery budget: a peer permanent refusal still ends the entry",
      function () { return aPeerPermanentRefusalStillEndsTheEntry(freshDir("dlv-budget-perm")); });
    await helpers.withTestTimeout("delivery budget: a peer cannot steer the outcome with its wording",
      function () { return aPeerCannotSteerTheOutcomeWithItsWording(freshDir("dlv-budget-forge")); });
    await helpers.withTestTimeout("delivery budget: a verdict this server made still spends the budget",
      function () { return aVerdictThisServerMadeStillSpendsTheBudget(freshDir("dlv-budget-peer")); });
    await helpers.withTestTimeout("delivery budget: dane enforcement needs the assertion",
      function () {
        return Promise.resolve(daneEnforcementNeedsTheAssertion(freshDir("dlv-budget-dane")));
      });
    await helpers.withTestTimeout("delivery budget: an unrecognized fault still spends the budget",
      function () { return anUnrecognizedFaultStillSpendsTheBudget(freshDir("dlv-budget-unknown")); });
    await helpers.withTestTimeout("delivery budget: an answer that can never succeed still ends the entry",
      function () { return anAnswerThatCanNeverSucceedStillEndsTheEntry(freshDir("dlv-budget-verdict")); });
    await helpers.withTestTimeout("delivery budget: a fault on this side still reports to the sender",
      function () { return aFaultOnThisSideStillReportsToTheSender(freshDir("dlv-budget-local")); });
    await helpers.withTestTimeout("delivery budget: a message whose body has gone is not reported to its sender",
      function () { return aMessageWhoseBodyHasGoneIsNotReportedToItsSender(freshDir("dlv-budget-bodyless")); });
    await helpers.withTestTimeout("delivery budget: a settled message is not put back",
      function () {
        return aSettledMessageIsNotPutBackWhenTheVolumeKeepsTheDescriptor(
          freshDir("dlv-budget-noputback"));
      });
    await helpers.withTestTimeout("delivery budget: a waiting entry says how it ends",
      function () { return aWaitingEntrySaysHowItEnds(freshDir("dlv-budget-held")); });
    await helpers.withTestTimeout("delivery budget: a waiting entry climbs the configured waits",
      function () { return aWaitingEntryClimbsTheConfiguredWaits(freshDir("dlv-budget-wait")); });
    await helpers.withTestTimeout("delivery budget: the guide prints the shipped retry budget",
      function () {
        return Promise.resolve(theGuidePrintsTheShippedRetryBudget(freshDir("dlv-budget-guide")));
      });
    await helpers.withTestTimeout("delivery budget: the shipped budget holds mail for the " +
      "give-up time the RFC asks for",
      function () {
        return theShippedBudgetHoldsMailForTheGiveUpTimeTheRfcAsksFor(freshDir("dlv-budget-giveup"));
      },
      // One sweep per attempt in the shipped budget, each of them an
      // atomic descriptor rewrite, so the ceiling is the volume's rather
      // than the schedule's.
      { timeoutMs: 60000 });
    await helpers.withTestTimeout("delivery budget: bad retry settings are refused at create",
      function () { return Promise.resolve(badRetrySettingsAreRefusedAtCreate(freshDir("dlv-budget-opts"))); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "delivery-budget", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
