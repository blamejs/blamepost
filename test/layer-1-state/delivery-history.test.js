// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Why one message is still waiting, which is the question an operator
 * asks of a queue and the one a list of ids cannot answer.
 *
 * A listing says a message is waiting and when it will be tried again.
 * It does not say what happened on any of the attempts already made, so
 * "this has been stuck since Tuesday" and "this has never been tried at
 * all" look identical, and they need opposite responses.
 *
 * So each entry carries its own record of what was tried: when, which
 * receiver answered where the framework names one, what the far side
 * said in its own words, the enhanced status that says which step
 * refused, and the transport security in force at the time. On top of
 * that a projection of what happens if it never succeeds, because an
 * operator deciding whether to intervene needs the ending as much as
 * the history.
 *
 * The record is bounded in both directions. A peer that answers a
 * thousand times cannot grow the descriptor past what the reader will
 * accept, and a peer that answers with a very long line cannot either.
 *
 * Run standalone: node test/layer-1-state/delivery-history.test.js
 */

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// A domain this server withholds the message from itself, which is the
// deferral that spends the retry budget.
//
// The record these cases are about is a record of attempts, so the
// fixture has to be one that actually costs an attempt. That takes a
// verdict: a lookup nobody completed is not one, and an entry waiting
// on one is not counted down against.
//
// This is the reachable verdict of that kind. Under an enforcing
// MTA-STS posture, RFC 8461 §3.1 makes one TXT record the gate on the
// whole policy, so a record the pinned resolver could not settle leaves
// this server unable to tell "no policy" from "a policy somebody
// suppressed". It withholds the message, writes its own enhanced status
// on the decision, and would decide the same way again.
var WITHHELD_ZONE = {
  "example.net":          { mx: ["mx.example.net"] },
  "_mta-sts.example.net": zone.FAILING,
};

function withheldResolver() {
  return zone.resolverOver(WITHHELD_ZONE);
}

// The enhanced status this server writes on that decision. RFC 3463
// §3.8 X.7.0 is the security status for a refusal none of the more
// specific codes describes.
var WITHHELD_STATUS = "4.7.0";

var ANSWERING_MX = {
  queryMx: function () {
    return Promise.resolve([{ priority: 10, exchange: "mx.example.net" }]);
  },
};

// A peer whose refusal is longer than any descriptor should carry.
var LOUD_MX = {
  queryMx: function () {
    return Promise.reject(new Error("451 4.7.0 " + new Array(4000).join("verbose ")));
  },
};

// The bound on one answer, matching MAX_RECORDED_REASON_BYTES in
// lib/mail/delivery.js. Every assertion below is written as "no more
// than", so a run that lowers the bound there needs no edit here.
var REASON_BOUND_BYTES = 512;

// A peer whose refusal is long and is not ASCII. The far side writes its
// own words and picks its own charset, and a bound written in bytes is
// not a bound written in the units a JavaScript string is indexed by:
// one CJK character is three bytes, so a record cut at 512 of them holds
// three times what the bound allows.
var WIDE_MX = {
  queryMx: function () {
    return Promise.reject(new Error("451 4.7.0 " + new Array(4000).join("中")));
  },
};

// The same, in characters that a JavaScript string stores as two units
// each. A cut counted in those units can land between the halves of one
// character and leave the record holding an unpaired half, which is a
// string no encoder can write out and no reader can print.
var ASTRAL_MX = {
  queryMx: function () {
    return Promise.reject(new Error("451 4.7.0 " + new Array(4000).join("\u{1F600}")));
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

function onlyId(dataDir) {
  var files = spoolFiles(dataDir);
  return files.length ? files[0].replace(/\.(json|eml)$/, "") : null;
}

function descriptorPath(dataDir, id) {
  return path.join(dataDir, "queue", id + ".json");
}

function readDescriptor(dataDir, id) {
  return JSON.parse(fs.readFileSync(descriptorPath(dataDir, id), "utf8"));
}

function writeDescriptor(dataDir, id, descriptor) {
  fs.writeFileSync(descriptorPath(dataDir, id), JSON.stringify(descriptor, null, 2), "utf8");
}

function makeDue(dataDir, id) {
  var d = readDescriptor(dataDir, id);
  d.nextAttemptAt = Date.now() - 1;
  writeDescriptor(dataDir, id, d);
}

function spoolOne(delivery, extra) {
  var envelope = {
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  };
  if (extra) Object.assign(envelope, extra);
  return delivery.send(envelope);
}

// ---------------------------------------------------------------------------
// What was tried
// ---------------------------------------------------------------------------

async function everyAttemptIsRecordedAgainstTheEntry(dataDir) {
  var delivery = handleOn(dataDir, withheldResolver(), {
    policy: { mtaSts: "enforce", dane: "off" },
    retry:  { maxAttempts: 20, backoffMs: [1000, 2000, 4000] },
  });

  var before = Date.now();
  await spoolOne(delivery);
  var id = onlyId(dataDir);
  check("the recipient is spooled", id !== null);

  var first = await delivery.queue.show(id);
  check("an entry can be read on its own rather than picked out of a listing",
    first !== null && first.id === id);
  check("the first attempt is on the record", Array.isArray(first.history) &&
    first.history.length === 1);

  var row = first.history[0];
  check("the attempt is stamped with when it ran",
    typeof row.at === "number" && row.at >= before && row.at <= Date.now());
  check("and with what became of it", row.outcome === "deferred");
  check("the decision keeps the words it was made in",
    /MTA-STS record for example\.net could not be looked up/.test(String(row.reason)));
  check("and the enhanced status that says which step refused",
    row.reasonCode === WITHHELD_STATUS);
  // What this asserts is that the posture is RECORDED rather than
  // omitted: a row carrying `false` and a row carrying nothing are
  // different rows, and only one of them can be read back later to say
  // what was in force. The value itself cannot be anything but `false`
  // here, and that is deliberate rather than a weakened assertion:
  // `delivery.create` refuses a REQUIRETLS request outright, because the
  // parameter does not reach the wire and a posture that is recorded but
  // never applied is worse than one that was never asked for. When the
  // framework carries the extension, this is where the true case belongs.
  check("the transport security in force at the time is recorded with it",
    row.requireTls === false);
  check("a receiver the framework did not name is recorded as unknown rather than guessed",
    row.mxHost === null);
  check("the attempt is numbered", row.attempt === 1);
  check("and it is not marked as held, because a verdict was made about it",
    row.held === false);

  // A second and third attempt, each of which has to land beside the
  // first rather than replacing it.
  makeDue(dataDir, id);
  await delivery.queue.runDue();
  makeDue(dataDir, id);
  await delivery.queue.runDue();

  var later = await delivery.queue.show(id);
  check("every attempt since is on the record too", later.history.length === 3);
  check("in the order they happened",
    later.history[0].at <= later.history[1].at &&
    later.history[1].at <= later.history[2].at);
  check("each one carrying its own attempt number",
    later.history[1].attempt === 2 && later.history[2].attempt === 3);
  check("and the entry counts how many times it has been tried",
    later.attemptsRecorded === 3);
}

// A listing is read for a hundred entries at a time, so it carries the
// last thing that happened rather than everything that ever did.
async function aListingCarriesTheLastAnswerRatherThanAllOfThem(dataDir) {
  var delivery = handleOn(dataDir, withheldResolver(),
    { policy: { mtaSts: "enforce", dane: "off" } });
  await spoolOne(delivery);
  var id = onlyId(dataDir);
  makeDue(dataDir, id);
  await delivery.queue.runDue();

  var listed = await delivery.queue.list();
  check("the listing has the entry", listed.length === 1);
  check("it says how many times the message has been tried",
    listed[0].attemptsRecorded === 2);
  check("and what stopped it the last time",
    listed[0].lastAttempt && /could not be looked up/.test(String(listed[0].lastAttempt.reason)));
  check("without carrying the whole record into every row",
    listed[0].history === undefined);
}

// ---------------------------------------------------------------------------
// What happens if it never succeeds
// ---------------------------------------------------------------------------

async function theEntrySaysHowItEndsIfNothingChanges(dataDir) {
  var delivery = handleOn(dataDir, withheldResolver(), {
    policy: { mtaSts: "enforce", dane: "off" },
    retry:  { maxAttempts: 4, backoffMs: [1000, 2000, 4000, 8000] },
  });
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var entry = await delivery.queue.show(id);
  var ending = entry.projection;
  check("the entry projects how it ends", ending && typeof ending === "object");
  check("it says how much of the budget is gone", ending.attemptsSpent === 1);
  check("and how much there was", ending.attemptsAllowed === 4);
  check("and what is left", ending.attemptsRemaining === 3);
  check("it says when the next attempt is due",
    ending.nextAttemptAt === entry.nextAttemptAt);
  check("nothing is holding it outside the budget", ending.held === false);
  check("and it says in words what happens if nothing changes",
    typeof ending.ifItNeverSucceeds === "string" &&
    /given up on/.test(ending.ifItNeverSucceeds));
  // An operator deciding whether to chase this by hand needs to know
  // who finds out and when. The sender is the one who hears, so the
  // sentence names them.
  check("including that the sender is the one who hears about it",
    /report is sent to/.test(ending.ifItNeverSucceeds) &&
    /alice@example\.com/.test(ending.ifItNeverSucceeds));
}

// A descriptor that arrives with the hold flag set is still readable,
// and reads as what it is: released by the next attempt rather than
// waiting on a receiver. Descriptors outlive the process that wrote
// them, so a restart must not make one unreadable or leave an operator
// with a pile nothing explains.
async function anEntryCarryingAHoldFlagStillReads(dataDir) {
  var delivery = handleOn(dataDir, ANSWERING_MX, {
    retry: { maxAttempts: 4, backoffMs: [1000, 2000, 4000, 8000] },
  });
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  // The shape under test: the flag set, the counter frozen at zero, and
  // a recorded reason that names no receiver.
  var carried = readDescriptor(dataDir, id);
  carried.held = true;
  carried.heldBecause = "outbound mail cannot reach a peer in this build";
  carried.attempt = 0;
  writeDescriptor(dataDir, id, carried);

  var entry = await delivery.queue.show(id);
  check("the entry still reads rather than failing to parse",
    entry !== null && entry.projection.held === true);
  check("and nothing is claimed about how many attempts remain",
    entry.projection.attemptsRemaining === null);
  check("the sentence says no delivery path here sets that flag",
    /hold flag that no delivery path here sets/.test(entry.projection.ifItNeverSucceeds));
  check("and tells the operator how to release it now",
    /queue flush/.test(entry.projection.ifItNeverSucceeds));

  // The release itself: one attempt puts it back on the ordinary budget.
  makeDue(dataDir, id);
  await delivery.queue.runDue();
  var released = readDescriptor(dataDir, id);
  check("the next attempt clears the hold",
    released.held === false && released.heldBecause === "");
  check("and the entry rejoins the retry budget", released.attempt === 1);
  check("so nothing is left held once the spool has turned over",
    (await delivery.queue.held()).messages === 0);
}

// ---------------------------------------------------------------------------
// Bounded in both directions
// ---------------------------------------------------------------------------

async function theRecordCannotGrowWithoutBound(dataDir) {
  var delivery = handleOn(dataDir, LOUD_MX, {
    retry: { maxAttempts: 200, backoffMs: [1000] },
  });
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  for (var i = 0; i < 30; i += 1) {
    makeDue(dataDir, id);
    await delivery.queue.runDue();
  }

  var entry = await delivery.queue.show(id);
  check("the record keeps a bounded number of attempts",
    entry.history.length > 0 && entry.history.length <= 20);
  check("while still counting every attempt that was made",
    entry.attemptsRecorded === 31);
  check("no single answer is stored unbounded",
    entry.history.every(function (r) { return String(r.reason).length <= 512; }));

  var bytes = fs.statSync(descriptorPath(dataDir, id)).size;
  check("and the descriptor stays inside the reader's own ceiling",
    bytes < helpers.b.constants.BYTES.kib(64));

  // The reader has to be able to read it back, which is the assertion
  // a byte count on its own does not make.
  check("the entry is still readable after every one of those attempts",
    (await delivery.queue.list()).length === 1);
}

// The same bound, against an answer that is not ASCII. This is the half
// a run using only ASCII cannot see: with one byte per character the two
// counts agree, so a bound written in bytes and enforced in characters
// looks correct until a peer answers in its own language.
async function aBoundWrittenInBytesHoldsForAnAnswerThatIsNotAscii(dataDir) {
  var delivery = handleOn(dataDir, WIDE_MX, { retry: { maxAttempts: 200, backoffMs: [1000] } });
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var entry  = await delivery.queue.show(id);
  var reason = String(entry.history[0].reason);
  count("the far side keeps its own words", reason.length > 0, reason.slice(0, 40));
  count("and no more of them are handed back than the bound allows, counted in bytes",
    Buffer.byteLength(reason, "utf8") <= REASON_BOUND_BYTES,
    Buffer.byteLength(reason, "utf8") + " bytes");

  var stored = readDescriptor(dataDir, id);
  count("the copy kept on disk is bounded in bytes too",
    Buffer.byteLength(String(stored.history[0].reason), "utf8") <= REASON_BOUND_BYTES,
    Buffer.byteLength(String(stored.history[0].reason), "utf8") + " bytes stored");
}

// And the bound cannot cut a character in half. A record holding an
// unpaired half is one the reader cannot print and the writer cannot
// encode, so the entry an operator opened to diagnose a stall is the
// thing that fails next.
async function theBoundNeverCutsACharacterInHalf(dataDir) {
  var delivery = handleOn(dataDir, ASTRAL_MX, { retry: { maxAttempts: 200, backoffMs: [1000] } });
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  var entry  = await delivery.queue.show(id);
  var reason = String(entry.history[0].reason);
  count("the answer is bounded in bytes here as well",
    Buffer.byteLength(reason, "utf8") <= REASON_BOUND_BYTES,
    Buffer.byteLength(reason, "utf8") + " bytes");
  count("and what is kept is a string that can still be written out",
    reason.isWellFormed(), JSON.stringify(reason.slice(-6)));

  var stored = String(readDescriptor(dataDir, id).history[0].reason);
  count("as is the copy on disk", stored.isWellFormed(), JSON.stringify(stored.slice(-6)));
}

// An id nothing was ever spooled under is not an error, it is an
// answer: nothing by that name is waiting.
async function anIdWithNothingBehindItAnswersRatherThanThrows(dataDir) {
  var delivery = handleOn(dataDir, withheldResolver());
  var absent = await delivery.queue.show("0123456789abcdef01234567");
  check("a well formed id with no entry behind it reads as nothing waiting",
    absent === null);
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
    await helpers.withTestTimeout("delivery history: every attempt is recorded against the entry",
      function () { return everyAttemptIsRecordedAgainstTheEntry(freshDir("dlv-hist-each")); });
    await helpers.withTestTimeout("delivery history: a listing carries the last answer",
      function () { return aListingCarriesTheLastAnswerRatherThanAllOfThem(freshDir("dlv-hist-list")); });
    await helpers.withTestTimeout("delivery history: the entry says how it ends",
      function () { return theEntrySaysHowItEndsIfNothingChanges(freshDir("dlv-hist-end")); });
    await helpers.withTestTimeout("delivery history: an entry carrying a hold flag still reads",
      function () { return anEntryCarryingAHoldFlagStillReads(freshDir("dlv-hist-held")); });
    await helpers.withTestTimeout("delivery history: the record cannot grow without bound",
      function () { return theRecordCannotGrowWithoutBound(freshDir("dlv-hist-cap")); },
      // Thirty sweeps against a real spool on a real disk, so the
      // ceiling is higher than the default for this one case.
      { timeoutMs: 30000 });
    await helpers.withTestTimeout("delivery history: a byte bound holds for an answer that is not ascii",
      function () { return aBoundWrittenInBytesHoldsForAnAnswerThatIsNotAscii(freshDir("dlv-hist-wide")); });
    await helpers.withTestTimeout("delivery history: the bound never cuts a character in half",
      function () { return theBoundNeverCutsACharacterInHalf(freshDir("dlv-hist-astral")); });
    await helpers.withTestTimeout("delivery history: an id with nothing behind it answers",
      function () { return anIdWithNothingBehindItAnswersRatherThanThrows(freshDir("dlv-hist-none")); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "delivery-history", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
