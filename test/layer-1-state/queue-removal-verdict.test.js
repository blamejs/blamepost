// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a cancellation says it did, held against what it did.
 *
 * `blamepost.mail.delivery.queue.remove` is the only way a message
 * leaves the outbound queue by somebody's decision rather than by a
 * receiver's answer. Two surfaces reach it. The command line files an
 * audit row on the strength of what it hands back; the browser console
 * files a row AND writes to the message's sender to say an operator
 * stopped it. Both of those are claims about the volume, so the verdict
 * they are built on has to be a reading of the volume rather than a
 * constant.
 *
 * Three states an id can be in when the removal runs, and the whole file
 * is about keeping them apart:
 *
 *   - It named a pair, and the pair is gone. The cancellation happened.
 *   - It named nothing. The message left on its own between whatever
 *     listed it and this call: a receiver took it, its attempts ran out,
 *     or another run cancelled it. Nothing was cancelled here, and a row
 *     saying otherwise tells an operator working through a compromised
 *     account's outbound mail that a message was stopped while it is
 *     with the receiver.
 *   - The volume would not give it up. This is the one that costs the
 *     most, because the operator is told the message is cancelled and it
 *     is still on disk waiting for its next attempt. Nothing else on
 *     this server will tell them: the sweep goes on retrying it.
 *
 * A removal made with the flag that ignores an absent path cannot tell
 * the first two apart, and a removal that raises on the third leaves the
 * caller with an exception rather than a state. So the verdict is read
 * off the unlink itself, one part at a time, and the parts are named
 * because which one refused decides what is left behind.
 *
 * The order the parts go in is load-bearing and is asserted here rather
 * than only described in the module: the message body goes first, so a
 * removal that stops half way leaves a descriptor with nothing to send,
 * which the sweep clears. Removing the descriptor first would leave a
 * message with nothing describing it, and a sweep already holding that
 * entry writes the descriptor back, which puts a cancelled message into
 * the queue the operator had just cleared.
 *
 * No sockets and no listeners. The resolver refuses every lookup, which
 * is what puts a real message on the spool through the shipped path
 * rather than through a planted fixture.
 *
 * Run standalone: node test/layer-1-state/queue-removal-verdict.test.js
 */

var helpers   = require("../helpers");
var blamepost = require("../../lib");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

// One file the volume will not give up, for the length of one call.
// Matched on the file name rather than on the whole path, because the
// spool builds the path and this file names the entry.
var installRemovalFault = helpers.installRemovalFault;

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// An id no message was ever minted under. Well formed, so the spool
// takes it as a name rather than refusing it as a path.
var ABSENT_ID = "0123456789abcdef01234567";

// A message body on the volume with no descriptor beside it. Nothing
// lists it and nothing would send it, and it is still spending the
// queue's room, so removing it is a removal that did something.
var ORPHAN_ID = "fedcba9876543210fedcba98";

// What every removal below is made for, and who it does not tell. The
// removal requires both and refuses without either, and most of this
// file is about the verdict rather than about the requirements, so one
// pair is written here and the tests that ARE about the requirements
// supply their own.
//
// Withheld rather than reported, so the cases below read a volume with
// nothing on it but the entry under test: a removal that reported would
// put the report on the same spool and every count of what is left would
// be counting two things.
var WHY = Object.freeze({
  reason: "the receiving domain is never coming back",
  notice: Object.freeze({ withheld: "operator-withheld-notice" }),
});

var UNREACHABLE_MX = {
  queryMx: function () {
    return Promise.reject(new Error("probe resolver: MX lookup unavailable"));
  },
};

function handleOn(dataDir) {
  return blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: UNREACHABLE_MX,
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
  });
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

function present(dataDir, name) {
  return fs.existsSync(path.join(dataDir, "queue", name));
}

// One waiting recipient, put there the way a message gets there: handed
// to the shipped send path against a resolver that answers nothing, so
// the recipient defers and the pair is written by the module under test.
async function spoolOne(delivery) {
  await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
}

// ---------------------------------------------------------------------------
// What the removal will not do without
// ---------------------------------------------------------------------------

// A cancellation is the one act on this spool that destroys a message
// nobody refused. It is what an operator reaches for while working
// through the outbound mail of an account somebody else has been using,
// and the question asked afterwards is always the same one: which
// messages went, and why. A removal with nothing recorded against it
// answers the first half and not the second.
//
// The requirement lives here, on the call that does the destroying,
// rather than on each surface that reaches it. Two surfaces reach it
// today and each used to carry its own copy of the rule; two copies of
// one rule is two things to keep in step, and the one that drifts is the
// one nobody is looking at. A surface still collects the sentence,
// because collecting it is what a surface is for, and this is what
// refuses the removal when it did not arrive.
async function aRemovalWithoutAReasonIsRefused(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  async function refuses(label, call) {
    var threw = null;
    try { await call(); } catch (e) { threw = e; }
    count(label, threw !== null && /reason/i.test(String(threw.message)),
      threw === null ? "no refusal" : String(threw.message));
  }

  await refuses("a removal with no options at all is refused",
    function () { return delivery.queue.remove(id); });
  await refuses("a removal with an empty options object is refused",
    function () { return delivery.queue.remove(id, {}); });
  await refuses("a reason that is not a string is refused",
    function () { return delivery.queue.remove(id, { reason: 7 }); });
  await refuses("an empty reason is refused",
    function () { return delivery.queue.remove(id, { reason: "" }); });
  await refuses("and a reason that is only spacing is refused, because it records nothing",
    function () { return delivery.queue.remove(id, { reason: "   \t  " }); });

  count("no refusal destroyed the message it refused to remove",
    spoolFiles(dataDir).length === 2, JSON.stringify(spoolFiles(dataDir)));

  // The id is read before the reason, so an operator who typed the id
  // wrong is told about the id rather than about a flag they did give.
  var wrongId = null;
  try { await delivery.queue.remove("../escape", { reason: "" }); }
  catch (e) { wrongId = e; }
  count("an id that is not one this server minted is still refused first",
    wrongId !== null && /minted/.test(String(wrongId.message)),
    wrongId === null ? "no refusal" : String(wrongId.message));

  var verdict = await delivery.queue.remove(id, {
    reason: "  the domain is never coming back  ",
    notice: { withheld: "operator-withheld-notice" },
  });
  count("a removal carrying a reason goes through", verdict.removed === true,
    JSON.stringify(verdict));
  count("and hands back the sentence it accepted, trimmed, so every surface records one value",
    verdict.requestedBecause === "the domain is never coming back",
    JSON.stringify(verdict));
}

// ---------------------------------------------------------------------------
// Who the removal tells, and the caller saying so
// ---------------------------------------------------------------------------

// The second thing a cancellation destroys is the sender's expectation.
// A message taken off this spool never reaches its recipient and never
// draws a refusal, so unless somebody writes to whoever sent it, they go
// on believing it arrived.
//
// Both answers are legitimate and they are not this module's to pick.
// One surface cancels routinely and writes to the sender; the other is
// reached during an incident, on mail a stolen credential sent, where
// the sender is whoever stole it and telling them is telling the
// attacker which messages were caught. A default here would hand one of
// those to a caller that never thought about it, and the trail would not
// say which had applied.
//
// So the removal requires the caller to say, the same way it requires
// the sentence, and refuses in front of the removal rather than after
// it: raising once the pair has gone would destroy a message to make the
// point.
async function aRemovalWithoutANoticeIsRefused(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);
  var because = "the receiving domain is never coming back";

  async function refuses(label, opts) {
    var threw = null;
    try { await delivery.queue.remove(id, opts); } catch (e) { threw = e; }
    count(label, threw !== null && /notice/i.test(String(threw.message)),
      threw === null ? "no refusal" : String(threw.message));
  }

  await refuses("a removal that names no notice at all is refused",
    { reason: because });
  await refuses("a notice that is not an object is refused",
    { reason: because, notice: "tell them" });
  await refuses("an empty notice is refused, because it decided nothing",
    { reason: because, notice: {} });
  await refuses("a notice naming neither a status to report under nor a reason for " +
    "withholding one is refused",
    { reason: because, notice: { status: "", withheld: "" } });

  count("no refusal destroyed the message it refused to remove",
    spoolFiles(dataDir).length === 2, JSON.stringify(spoolFiles(dataDir)));
  count("and none of them wrote to anybody about a message that is still queued",
    (await delivery.queue.list({})).length === 1,
    JSON.stringify(await delivery.queue.list({})));
}

// The caller that chooses to tell. The report goes out through the one
// report path this module has, so it carries the empty reverse path, is
// bounded by the same generator, and quotes the original headers RFC
// 3462 §3 asks for.
//
// The verdict says it went. Both surfaces file a row about a
// cancellation and an auditor reading that trail is deciding whether
// anybody still needs telling, so the answer belongs on the verdict
// rather than on each surface's reading of its own intent: a caller that
// asked for a report and did not get one would otherwise record that one
// went.
async function aCancellationTheCallerReportsWritesToTheSender(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var verdict = await delivery.queue.remove(id, {
    reason: "the account was taken over and this message is not the operator's",
    notice: { status: "5.7.1" },
  });

  count("the message is cancelled", verdict.removed === true && verdict.outcome === "removed",
    JSON.stringify(verdict));
  count("and the verdict says its sender was told, so a row does not have to guess",
    verdict.reported === true && verdict.withheld === null, JSON.stringify(verdict));

  var waiting = await delivery.queue.list({});
  var reports = waiting.filter(function (row) { return row.recipient === "alice@example.com"; });
  count("a report addressed to the sender is on the outbound path",
    reports.length === 1, JSON.stringify(waiting));
  count("carrying the empty reverse path, so a report that fails cannot start a second",
    reports.length === 1 && reports[0].from === "");

  var composed = reports.length === 1
    ? fs.readFileSync(path.join(dataDir, "queue", reports[0].id + ".eml"), "utf8")
    : "";
  count("it names the recipient the cancelled message was for",
    /Final-Recipient: rfc822; bob@example\.net/.test(composed), composed.slice(0, 200));
  count("under the status the caller asked for rather than one this module picked",
    /Status: 5\.7\.1/.test(composed), composed.slice(0, 400));

  // The headers are read off the spooled message BEFORE it is destroyed,
  // which is the only moment they exist. A report that reaches the
  // sender saying only that "a message" was cancelled names none of the
  // several they sent.
  var quoted = composed.split("Content-Type: text/rfc822-headers")[1] || "";
  count("and quotes the cancelled message's own headers, so the sender knows which message " +
    "this is about",
    /^To: bob@example\.net$/m.test(quoted) && /^From: alice@example\.com$/m.test(quoted),
    quoted.slice(0, 200));
}

// The caller that chooses not to. Nothing is written and the verdict
// says why not, so the trail answers "was the sender told" without the
// reader having to know which surface ran.
async function aCancellationTheCallerWithholdsTellsNobodyAndSaysWhy(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var verdict = await delivery.queue.remove(id, {
    reason: "cancelling mail a stolen credential sent",
    notice: { withheld: "operator-withheld-notice" },
  });

  count("the message is cancelled", verdict.removed === true, JSON.stringify(verdict));
  count("and the verdict says nobody was written to, naming the caller's own reason",
    verdict.reported === false && verdict.withheld === "operator-withheld-notice",
    JSON.stringify(verdict));
  count("with nothing put on the outbound path, so the attacker is not told which messages " +
    "were caught",
    (await delivery.queue.list({})).length === 0,
    JSON.stringify(await delivery.queue.list({})));
}

// A report has nobody to report to. RFC 5321 §6.1 puts the empty
// reverse path on every one, so cancelling a report that is itself
// waiting ends in silence rather than starting a loop of reports about
// reports. A caller that asked for one is overruled here rather than at
// the composer, so the verdict says what actually happened.
async function cancellingAReportTellsNobody(dataDir) {
  var delivery = handleOn(dataDir);
  var dir = path.join(dataDir, "queue");
  fs.mkdirSync(dir, { recursive: true });

  // A report on the spool, put there the way one gets there.
  await delivery.bounce({
    to:         "alice@example.com",
    recipient:  "bob@example.net",
    reason:     "no such mailbox",
    statusCode: "5.1.1",
  });
  var waiting = await delivery.queue.list({});
  count("a report is waiting, carrying the empty reverse path",
    waiting.length === 1 && waiting[0].from === "", JSON.stringify(waiting));

  var verdict = await delivery.queue.remove(waiting[0].id, {
    reason: "clearing a report nobody can read",
    notice: { status: "5.7.1" },
  });

  count("the report is cancelled", verdict.removed === true, JSON.stringify(verdict));
  count("and nobody is written to, because there is nobody to write to",
    verdict.reported === false && verdict.withheld === "null-return-path",
    JSON.stringify(verdict));
  count("so the spool is empty rather than holding a report about a report",
    (await delivery.queue.list({})).length === 0,
    JSON.stringify(await delivery.queue.list({})));
}

// The removal that cancelled nothing must never write to anybody, and it
// is the case a caller cannot see coming: the message left between
// whatever listed it and this call, or the volume kept it. Either way
// the message is with its receiver or still going out, and a report
// saying an operator stopped it is a claim about mail that arrived.
async function aRemovalThatCancelledNothingTellsNobody(dataDir) {
  var delivery = handleOn(dataDir);

  var absent = await delivery.queue.remove(ABSENT_ID, {
    reason: "clearing an id that is not there",
    notice: { status: "5.7.1" },
  });
  count("an id the queue does not hold cancelled nothing",
    absent.removed === false && absent.outcome === "not-spooled", JSON.stringify(absent));
  count("so nobody is told, and the verdict says which silence this was",
    absent.reported === false && absent.withheld === "message-not-cancelled",
    JSON.stringify(absent));

  await spoolOne(delivery);
  var id = onlyId(dataDir);
  var fault = installRemovalFault(id + ".eml");
  var refused;
  try {
    refused = await delivery.queue.remove(id, {
      reason: "cancelling a message the volume will not give up",
      notice: { status: "5.7.1" },
    });
  } finally {
    fault.remove();
  }
  count("a removal the volume refused cancelled nothing either",
    Boolean(refused) && refused.removed === false && refused.outcome === "refused",
    JSON.stringify(refused));
  count("so its sender is not told their message was stopped while it is still going out",
    Boolean(refused) && refused.reported === false &&
    refused.withheld === "message-not-cancelled", JSON.stringify(refused));

  var waiting = await delivery.queue.list({});
  count("and the only thing on the spool is the message that is still waiting",
    waiting.length === 1 && waiting[0].recipient === "bob@example.net",
    JSON.stringify(waiting));
}

// ---------------------------------------------------------------------------
// It named a pair, and the pair is gone
// ---------------------------------------------------------------------------

async function aWaitingMessageIsRemovedAndSaysSo(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);
  count("one recipient is waiting on the spool", id !== null && delivery.queue.count() === 1,
    JSON.stringify(spoolFiles(dataDir)));

  var verdict = await delivery.queue.remove(id, WHY);

  count("the removal names the entry it was asked about",
    verdict !== null && verdict.id === id, JSON.stringify(verdict));
  count("and says the message was removed", verdict.removed === true &&
    verdict.outcome === "removed", JSON.stringify(verdict));
  count("naming nothing it could not take off the volume",
    Array.isArray(verdict.left) && verdict.left.length === 0 && verdict.reason === null,
    JSON.stringify(verdict));
  count("and the pair really is gone", spoolFiles(dataDir).length === 0,
    JSON.stringify(spoolFiles(dataDir)));
}

// A body with no descriptor is still something on the volume, and
// removing it is still a removal. The command line reports its bytes
// back to the operator as room that has been freed, which is only true
// if something was freed.
async function aStrandedBodyIsRemovedAndSaysSo(dataDir) {
  var delivery = handleOn(dataDir);
  var dir = path.join(dataDir, "queue");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, ORPHAN_ID + ".eml"), Buffer.alloc(2048, 0x61), { mode: 0o600 });

  var verdict = await delivery.queue.remove(ORPHAN_ID, WHY);

  count("a message body with no descriptor is removed and reported as removed",
    verdict.removed === true && verdict.outcome === "removed", JSON.stringify(verdict));
  count("and it is off the volume", !present(dataDir, ORPHAN_ID + ".eml"),
    JSON.stringify(spoolFiles(dataDir)));
}

// ---------------------------------------------------------------------------
// It named nothing
// ---------------------------------------------------------------------------

async function anIdTheQueueDoesNotHoldSaysNothingWasRemoved(dataDir) {
  var delivery = handleOn(dataDir);

  var verdict = await delivery.queue.remove(ABSENT_ID, WHY);

  count("removing an id the queue does not hold is answered rather than raised",
    verdict !== null && typeof verdict === "object", JSON.stringify(verdict));
  count("and the answer says nothing was removed, so no caller can file a row saying it was",
    verdict.removed === false && verdict.outcome === "not-spooled", JSON.stringify(verdict));
  count("and it is told apart from a removal the volume refused",
    Array.isArray(verdict.left) && verdict.left.length === 0, JSON.stringify(verdict));
}

// The same answer reached the way an operator reaches it: the message
// leaves between whatever listed it and the call that erases it, which
// is what a receiver taking it or a sweep giving up on it looks like
// from here.
async function aMessageThatLeavesFirstSaysNothingWasRemoved(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var listed = await delivery.queue.list({});
  count("the message is listed as waiting", listed.length === 1 && listed[0].id === id,
    JSON.stringify(listed.map(function (r) { return r.id; })));

  // Gone by the time the removal runs, which is every one of the ways a
  // message leaves on its own.
  fs.rmSync(path.join(dataDir, "queue", id + ".json"), { force: true });
  fs.rmSync(path.join(dataDir, "queue", id + ".eml"), { force: true });

  var verdict = await delivery.queue.remove(id, WHY);
  count("the removal reports that there was nothing left to remove",
    verdict.removed === false && verdict.outcome === "not-spooled", JSON.stringify(verdict));
}

// ---------------------------------------------------------------------------
// The volume would not give it up
// ---------------------------------------------------------------------------

async function aBodyTheVolumeKeepsIsNotReportedAsCancelled(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var fault = installRemovalFault(id + ".eml");
  var verdict;
  var raised = null;
  try {
    verdict = await delivery.queue.remove(id, WHY);
  } catch (e) {
    raised = e;
  } finally {
    fault.remove();
  }

  count("a removal the volume refuses answers with a verdict rather than raising",
    raised === null, raised === null ? "(no refusal)" : String(raised.code || raised.message));
  count("and the verdict says the message was NOT removed",
    Boolean(verdict) && verdict.removed === false && verdict.outcome === "refused",
    JSON.stringify(verdict));
  count("and names the part the volume kept, so an operator knows what is still there",
    Boolean(verdict) && Array.isArray(verdict.left) && verdict.left.indexOf("body") !== -1 &&
      typeof verdict.reason === "string" && verdict.reason.length > 0,
    JSON.stringify(verdict));

  // The message is still a message. Nothing else on this server will
  // say so: the sweep goes on retrying it exactly as before.
  count("the message is still waiting, which is what the verdict said",
    present(dataDir, id + ".json") && present(dataDir, id + ".eml"),
    JSON.stringify(spoolFiles(dataDir)));
  count("and it is still in the listing an operator reads",
    (await delivery.queue.list({})).length === 1, JSON.stringify(spoolFiles(dataDir)));
}

// The descriptor is the half that makes an entry an entry, so a volume
// that keeps it has kept the message even though the body went. The
// order matters here as much as the verdict: taking the descriptor
// first and failing on the body would leave a message nothing describes,
// and a sweep already holding that entry writes the descriptor back.
async function aDescriptorTheVolumeKeepsIsNotReportedAsCancelled(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var fault = installRemovalFault(id + ".json");
  var verdict;
  var raised = null;
  try {
    verdict = await delivery.queue.remove(id, WHY);
  } catch (e) {
    raised = e;
  } finally {
    fault.remove();
  }

  count("a descriptor the volume refuses answers with a verdict rather than raising",
    raised === null, raised === null ? "(no refusal)" : String(raised.code || raised.message));
  count("and the verdict says the entry was NOT removed",
    Boolean(verdict) && verdict.removed === false && verdict.outcome === "refused",
    JSON.stringify(verdict));
  count("naming the descriptor as the part that stayed",
    Boolean(verdict) && Array.isArray(verdict.left) && verdict.left.indexOf("descriptor") !== -1,
    JSON.stringify(verdict));
  count("the descriptor is still on the volume, which is why the verdict refuses",
    present(dataDir, id + ".json"), JSON.stringify(spoolFiles(dataDir)));

  // What `refused` means to everybody who reads it. Both surfaces turn
  // this verdict into the sentence that nothing was cancelled and the
  // running server will attempt the message again on its own schedule,
  // and both file a row saying the volume kept a part. That sentence is
  // a claim about the message, so the message has to still be one: an
  // entry whose body has already been destroyed is past attempting, and
  // an operator told to clear the lock and run this again is being sent
  // to re-cancel a message that can never be sent.
  //
  // The body-first order is right and stays. What it is right ABOUT is a
  // crash: the module says so in as many words, and says a fault must
  // not be allowed to build the same state. A body the volume keeps
  // stops the removal where it stands for exactly that reason, and a
  // descriptor the volume keeps arrives one step too late for it.
  count("a removal reported as refused left the message able to be sent, because that is " +
    "what the operator is told and what the sweep is expected to do with it",
    present(dataDir, id + ".eml"), JSON.stringify(spoolFiles(dataDir)));
}

// The remediation the refusal offers, taken. An operator reading
// `refused` is told the message is still queued and the server will
// attempt it again, so the next sweep is the thing that has to agree.
async function aRefusedRemovalLeavesAMessageTheSweepCanStillSend(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var fault = installRemovalFault(id + ".json");
  var verdict;
  try { verdict = await delivery.queue.remove(id, WHY); }
  finally { fault.remove(); }

  count("the removal refused, so nothing was cancelled and the entry is still the queue's",
    Boolean(verdict) && verdict.outcome === "refused", JSON.stringify(verdict));

  // The lock is gone now, which is the state the operator reaches after
  // doing what the refusal told them to do. The message has to still be
  // there for them to remove.
  var sweep = await delivery.queue.runDue({ force: true });
  var results = (sweep && sweep.results) || [];
  var abandoned = results.filter(function (row) { return row.outcome === "abandoned"; });

  count("the sweep the operator was told to expect attempts the message rather than " +
    "giving up on it, because a refused removal cancelled nothing",
    abandoned.length === 0,
    JSON.stringify(results));

  var again = await delivery.queue.remove(id, WHY);
  count("and running the removal again, which is the remediation the refusal names, " +
    "reaches a message that is still there rather than one already past cancelling",
    again.outcome !== "not-spooled", JSON.stringify(again));
}

// A cancellation and the retry sweep reaching for one entry at the same
// moment.
//
// The sweep takes the entry's claim before it reads anything, because
// everything it does afterwards either sends the message or rewrites its
// schedule, and both are wrong to do to an entry somebody else is
// working on. A cancellation is the other verb that takes an entry
// apart, and it has exactly the same problem: it is two unlinks with a
// suspension between them, so the pair it is half way through taking
// apart is one the sweep can pick up and finish.
//
// The state that produces is the worst one this file has. The
// cancellation unlinks the message and the descriptor refuses; the sweep
// meanwhile reads an entry whose message is already gone, gives up on it
// as one with nothing left to send, and takes the descriptor off the
// volume. The cancellation then puts the message back beside a
// descriptor that is no longer there, which is a body nothing lists,
// nothing sends and nothing will ever clear, and hands back the verdict
// that says nothing was destroyed and the server will attempt the
// message again. The volume says otherwise on every count.
//
// So the two verbs hold the entry the same way, and this is the vector
// that says so: the interleaving is arranged at the moment the pair is
// half taken apart rather than left to timing, so it is a fact each run.
async function aCancellationAndASweepDoNotBothActOnOneEntry(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  // The sweep runs inside the removal, at the moment the message is off
  // the volume and the descriptor is still on it. The refusal is
  // transient: one attempt is refused and the volume takes the next,
  // which is what lets the sweep's own removal through and is the shape
  // a busy file actually has.
  var swept = null;
  var fault = installRemovalFault(id + ".json", {
    times:  1,
    before: async function () { swept = await delivery.queue.runDue({ force: true }); },
  });
  var verdict;
  try { verdict = await delivery.queue.remove(id, WHY); }
  finally { fault.remove(); }

  count("the fixture's own sweep ran without a fault of its own, so what follows is about " +
    "the code under test",
    fault.beforeErrors.length === 0,
    fault.beforeErrors.map(function (e) { return String(e && e.message); }).join("; "));

  var rows = (swept && swept.results) || [];
  var mine = rows.filter(function (r) { return r.id === id; });
  count("the sweep that met an entry a cancellation was holding reported it rather than " +
    "attempting it",
    mine.length === 1 && mine[0].outcome === "claimed", JSON.stringify(rows));
  count("so it did not give up on the message and take the entry the cancellation was " +
    "still working on",
    rows.filter(function (r) { return r.outcome === "abandoned"; }).length === 0,
    JSON.stringify(rows));

  // What the verdict says, held against the volume. `refused` is read by
  // both surfaces as nothing destroyed and a message the server will
  // attempt again, and each of those is a claim about these two files.
  count("the removal reports that the volume kept the entry and destroyed nothing",
    Boolean(verdict) && verdict.outcome === "refused" && verdict.destroyed.length === 0,
    JSON.stringify(verdict));
  count("and the entry really is whole, which is what that verdict promises",
    present(dataDir, id + ".json") && present(dataDir, id + ".eml"),
    JSON.stringify(spoolFiles(dataDir)));
  count("with no message body put back beside a descriptor that had gone, which nothing " +
    "lists, nothing sends and nothing clears",
    !(present(dataDir, id + ".eml") && !present(dataDir, id + ".json")),
    JSON.stringify(spoolFiles(dataDir)));
  count("and the message is still the one an operator reads in the queue",
    (await delivery.queue.list({})).length === 1,
    JSON.stringify(await delivery.queue.list({})));

  // The remediation the refusal names, taken. The claim is given back
  // when the removal returns, so the entry is the sweep's again.
  var after = await delivery.queue.runDue({ force: true });
  var attempted = ((after && after.results) || []).filter(function (r) { return r.id === id; });
  count("once the removal is finished the entry is attemptable again, so the claim it took " +
    "was given back rather than left on the volume",
    attempted.length === 1 && attempted[0].outcome !== "claimed", JSON.stringify(after));
}

// An entry another attempt is already holding, which is the case the
// cancellation cannot answer by waiting.
//
// This is the verb an operator reaches for during an incident, on mail
// an account somebody else is using is sending. Refusing it until the
// attempt in flight has finished would leave that mail going out for as
// long as a connect takes to time out, and the sweep runs every minute,
// so it goes ahead. What it gives up is the restore: the message is not
// put back beside a descriptor the attempt may already have cleared,
// because a body with nothing naming it is in no listing, reached by no
// verb, and spends the queue's room until somebody finds it by hand.
//
// So the pair is destroyed in part rather than restored whole, and the
// verdict says so in the word both surfaces already render as "the
// message is gone and the entry is still listed": neither of them tells
// an operator to clear the fault and cancel it again as though nothing
// had happened.
async function aCancellationUnderAnAttemptDestroysRatherThanPuttingBack(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var held = delivery.queue.claim(id);
  count("the entry is claimed, which is what an attempt in flight looks like",
    held !== null, String(held));

  // The volume keeps the descriptor, which is the only fault that makes
  // the restore a question at all.
  var fault = installRemovalFault(id + ".json");
  var verdict;
  try { verdict = await delivery.queue.remove(id, WHY); }
  finally { fault.remove(); }

  count("the cancellation goes ahead rather than waiting for the attempt to finish",
    Boolean(verdict) && verdict.destroyed.indexOf("body") !== -1, JSON.stringify(verdict));
  count("and reports the entry as destroyed in part, because that is what is on the volume",
    verdict.outcome === "incomplete" && verdict.removed === false &&
    verdict.left.indexOf("descriptor") !== -1, JSON.stringify(verdict));
  count("with the message left destroyed rather than put back beside a descriptor the " +
    "attempt may already have cleared",
    !present(dataDir, id + ".eml"), JSON.stringify(spoolFiles(dataDir)));
  count("and the verdict says why it was not put back, which is not the sentence a removal " +
    "after a delivery gives",
    typeof verdict.reason === "string" && /another attempt is holding this entry/
      .test(verdict.reason), JSON.stringify(verdict));
  count("nobody is written to, because the headers a report would quote went with the message",
    verdict.reported === false && verdict.withheld === "message-destroyed-in-part",
    JSON.stringify(verdict));

  // The remainder is an entry with nothing to send, which is the state
  // the sweep already knows how to end.
  held.release();
  var sweep = await delivery.queue.runDue({ force: true });
  var rows = ((sweep && sweep.results) || []).filter(function (r) { return r.id === id; });
  count("and the sweep ends the remainder rather than retrying a message that is not there",
    rows.length === 1 && rows[0].outcome === "abandoned", JSON.stringify(sweep));
  count("leaving nothing on the volume for the entry", spoolFiles(dataDir).length === 0,
    JSON.stringify(spoolFiles(dataDir)));
}

// The same fault with nobody else holding the entry, which is the
// ordinary case and the one where putting the message back is safe. It
// is the contrast that makes the vector above a decision rather than an
// accident: same fault, same verb, opposite answer, and what separates
// them is whether this call is holding the entry.
async function aCancellationHoldingTheEntryPutsTheMessageBack(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var fault = installRemovalFault(id + ".json");
  var verdict;
  try { verdict = await delivery.queue.remove(id, WHY); }
  finally { fault.remove(); }

  count("the removal that could hold the entry destroyed nothing",
    Boolean(verdict) && verdict.outcome === "refused" && verdict.destroyed.length === 0,
    JSON.stringify(verdict));
  count("and the message is back where it was, which is what that verdict promises",
    present(dataDir, id + ".eml") && present(dataDir, id + ".json"),
    JSON.stringify(spoolFiles(dataDir)));
}

// The body goes before the descriptor, so a removal that gets no further
// than the body leaves the pair whole rather than leaving a message
// nothing describes.
async function theBodyIsTakenBeforeTheDescriptor(dataDir) {
  var delivery = handleOn(dataDir);
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var fault = installRemovalFault(id + ".");
  try {
    await delivery.queue.remove(id, WHY);
  } finally {
    fault.remove();
  }

  count("the first part the removal reaches for is the message body",
    fault.attempts.length > 0 && fault.attempts[0].slice(-4) === ".eml",
    JSON.stringify(fault.attempts));
  count("and a body the volume kept stops the removal there, so the pair is still whole",
    present(dataDir, id + ".json") && present(dataDir, id + ".eml"),
    JSON.stringify(spoolFiles(dataDir)));
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
    await helpers.withTestTimeout("queue-removal-verdict: a removal without a reason is refused",
      function () { return aRemovalWithoutAReasonIsRefused(freshDir("qrv-reason")); });
    await helpers.withTestTimeout("queue-removal-verdict: a removal without a notice is refused",
      function () { return aRemovalWithoutANoticeIsRefused(freshDir("qrv-notice")); });
    await helpers.withTestTimeout("queue-removal-verdict: a cancellation the caller reports",
      function () {
        return aCancellationTheCallerReportsWritesToTheSender(freshDir("qrv-told"));
      });
    await helpers.withTestTimeout("queue-removal-verdict: a cancellation the caller withholds",
      function () {
        return aCancellationTheCallerWithholdsTellsNobodyAndSaysWhy(freshDir("qrv-quiet"));
      });
    await helpers.withTestTimeout("queue-removal-verdict: cancelling a report tells nobody",
      function () { return cancellingAReportTellsNobody(freshDir("qrv-report")); });
    await helpers.withTestTimeout("queue-removal-verdict: a removal that cancelled nothing tells nobody",
      function () { return aRemovalThatCancelledNothingTellsNobody(freshDir("qrv-nothing")); });
    await helpers.withTestTimeout("queue-removal-verdict: a waiting message is removed and says so",
      function () { return aWaitingMessageIsRemovedAndSaysSo(freshDir("qrv-removed")); });
    await helpers.withTestTimeout("queue-removal-verdict: a stranded body is removed and says so",
      function () { return aStrandedBodyIsRemovedAndSaysSo(freshDir("qrv-orphan")); });
    await helpers.withTestTimeout("queue-removal-verdict: an id the queue does not hold",
      function () { return anIdTheQueueDoesNotHoldSaysNothingWasRemoved(freshDir("qrv-absent")); });
    await helpers.withTestTimeout("queue-removal-verdict: a message that leaves first",
      function () { return aMessageThatLeavesFirstSaysNothingWasRemoved(freshDir("qrv-left")); });
    await helpers.withTestTimeout("queue-removal-verdict: a body the volume keeps",
      function () { return aBodyTheVolumeKeepsIsNotReportedAsCancelled(freshDir("qrv-body")); });
    await helpers.withTestTimeout("queue-removal-verdict: a descriptor the volume keeps",
      function () {
        return aDescriptorTheVolumeKeepsIsNotReportedAsCancelled(freshDir("qrv-descriptor"));
      });
    await helpers.withTestTimeout("queue-removal-verdict: the body is taken before the descriptor",
      function () { return theBodyIsTakenBeforeTheDescriptor(freshDir("qrv-order")); });
    await helpers.withTestTimeout("queue-removal-verdict: a cancellation and a sweep on one entry",
      function () {
        return aCancellationAndASweepDoNotBothActOnOneEntry(freshDir("qrv-race"));
      });
    await helpers.withTestTimeout("queue-removal-verdict: a cancellation under an attempt",
      function () {
        return aCancellationUnderAnAttemptDestroysRatherThanPuttingBack(freshDir("qrv-claimed"));
      });
    await helpers.withTestTimeout("queue-removal-verdict: a cancellation holding the entry",
      function () {
        return aCancellationHoldingTheEntryPutsTheMessageBack(freshDir("qrv-holding"));
      });
    await helpers.withTestTimeout("queue-removal-verdict: a refused removal leaves a sendable message",
      function () {
        return aRefusedRemovalLeavesAMessageTheSweepCanStillSend(freshDir("qrv-refused-sweep"));
      });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = {
  name:      "queue-removal-verdict",
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
