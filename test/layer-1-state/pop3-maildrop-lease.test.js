// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The exclusive maildrop RFC 1939 section 3 gives a POP3 session, and
 * the rule that decides when this server takes it back.
 *
 * POP3's model is unusual in a way that makes the lease load bearing.
 * The maildrop is a snapshot taken at authentication, message numbers
 * are positions in that snapshot rather than identifiers, and section 6
 * applies a DELE only in the UPDATE state on QUIT. So a drop that
 * disappears before the QUIT does not merely end a session: it discards
 * every deletion that session had marked, silently, and the account
 * holder sees the mail they deleted come back.
 *
 * That is one outcome with two ways to reach it. A clock correction is
 * one, and `clock-step-windows.test.js` holds the vectors for it. Time
 * simply passing is the other, and it is the one these cases are about:
 * the sweep has to be able to tell a session that has gone away from a
 * session that has been busy for a while, and the only difference
 * between the two is whether anything has touched the drop lately.
 *
 * A POP3 client downloads a whole mailbox in one session. On a slow
 * link a large maildrop takes longer than any fixed lifetime worth
 * setting, so "has been open a long time" and "has been abandoned" are
 * not the same claim, and a sweep that reads the first as the second
 * reaps the busiest sessions this server has.
 *
 * Both halves are asserted here, because either one alone has a trivial
 * wrong answer: a sweep that never reclaims passes the first, and the
 * shipped predicate passes the second. Only the pair pins the rule.
 *
 * How the duration is moved: `withElapsedStep` replaces
 * `process.hrtime.bigint` for the length of one synchronous call and
 * puts it back in a `finally`. It is the monotonic source the maildrop
 * lease is measured on, so it is the one a case about that lease has to
 * script. Nothing else is replaced, the code under test is the shipped
 * code driven through the shipped verbs, and no reading taken under the
 * step is ever written down: this server keeps elapsed readings in
 * memory and compares them only against each other.
 *
 * Run standalone: node test/layer-1-state/pop3-maildrop-lease.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var config  = require("../../lib/config");
var store   = require("../../lib/store");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// Longer than the maildrop lifetime in lib/mail/mailbox.js, so a step of
// this size crosses it. The point is the crossing, not the number.
var PAST_THE_MAILDROP_TTL_MS = helpers.b.constants.TIME.minutes(31);

// Comfortably inside it, for the case that has to show the sweep is
// reading elapsed time at all rather than reclaiming on any step.
var INSIDE_THE_MAILDROP_TTL_MS = helpers.b.constants.TIME.minutes(5);

var NANOSECONDS_PER_MS = 1000000n;

// ---------------------------------------------------------------------------
// The scripted monotonic clock
// ---------------------------------------------------------------------------

// Kept local to this file rather than shared, on the same reasoning the
// wall clock stepper in clock-step-windows.test.js is kept local to
// that one. It rewrites a global for the length of one call, and what
// makes that safe here is that every call it wraps is one this file
// chose and audited. The moment a second file needs it, it moves to
// test/helpers with that reasoning attached.
var REAL_HRTIME_BIGINT = process.hrtime.bigint;

function withElapsedStep(offsetMs, fn) {
  if (typeof offsetMs !== "number" || !isFinite(offsetMs) || offsetMs < 0) {
    throw new TypeError("withElapsedStep: offsetMs must be a non-negative finite number of " +
      "milliseconds. A monotonic source does not run backwards, so a case that scripted one " +
      "going backwards would be asserting about a machine that does not exist.");
  }
  if (typeof fn !== "function") {
    throw new TypeError("withElapsedStep: fn (function) required");
  }
  var offsetNs = BigInt(Math.round(offsetMs)) * NANOSECONDS_PER_MS;
  process.hrtime.bigint = function () {
    return REAL_HRTIME_BIGINT.call(process.hrtime) + offsetNs;
  };
  var result;
  try { result = fn(); }
  finally { process.hrtime.bigint = REAL_HRTIME_BIGINT; }
  // A synchronous `finally` puts the clock back when the function
  // RETURNS, so wrapping something that resolves later restores it while
  // the call it was stepping for is still in flight and the step never
  // reaches the code it was written for. The case would still pass, on
  // the unstepped clock, while saying the words it was written to say.
  // Every verb stepped here is synchronous; this refuses the edit that
  // makes one of them not.
  if (result !== null && typeof result === "object" && typeof result.then === "function") {
    throw new TypeError("withElapsedStep: fn must be synchronous. The clock is restored when " +
      "fn returns, so a promise would settle after the step was already over.");
  }
  return result;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function actorFor(account) {
  return {
    id:        account.id,
    username:  account.address,
    address:   account.address,
    domain:    account.domain,
    isAdmin:   false,
    mailboxes: [account.address],
    roles:     ["account"],
  };
}

// A store on a temporary volume, opened the way the server opens it.
// Returns the handle plus the teardown, because the store module keeps
// one open database per process and a case that leaves it open takes
// the next one down with it.
async function openStore(prefix) {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-" + prefix + "-"));
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var cfg = config.load({
    env: {
      BLAMEPOST_HOSTNAME:         "mx.example.com",
      BLAMEPOST_DATA_DIR:         nodePath.join(root, "data"),
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    },
    cwd: root,
  });
  var handle = await store.open(cfg);
  await handle.domains.add({ domain: "example.com" });

  return {
    handle: handle,
    close:  function () {
      if (store.isOpen()) store.close();
      if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
      else delete process.env.BLAMEJS_TMPDIR;
      try { nodeFs.rmSync(root, { recursive: true, force: true }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a verdict */ }
    },
  };
}

function refusalCode(fn) {
  try { fn(); return null; }
  catch (e) { return (e && e.code) || "threw without a code"; }
}

// A message whose subject names it, so a case reading octets back can
// say which one it got.
function messageFor(address, subject, body) {
  return Buffer.from([
    "From: sender@example.net",
    "To: " + address,
    "Subject: " + subject,
    "Date: Mon, 24 Aug 2026 09:00:00 +0000",
    "Message-ID: <" + subject.replace(/[^a-z0-9]/gi, "-") + "@example.net>",
    "",
    body,
    "",
  ].join("\r\n"), "utf8");
}

async function accountWith(handle, address, subjects) {
  var actor = actorFor(await handle.accounts.create({
    address: address, password: ACCOUNT_PASSWORD }));
  for (var i = 0; i < subjects.length; i += 1) {
    handle.mailbox.appendMessage("INBOX",
      messageFor(address, subjects[i], "body of " + subjects[i]), { actor: actor });
  }
  return actor;
}

// ---------------------------------------------------------------------------
// The lease measures idleness, not age
// ---------------------------------------------------------------------------

// The half that is about a session which is still there.
//
// A client walking a large maildrop is issuing commands the whole time,
// and every one of them reaches this layer. A sweep that reclaims on
// how long the drop has been OPEN takes the maildrop away from the
// session that is using it hardest, and RFC 1939 section 6 turns that
// into lost deletions rather than an error the client can act on.
async function aBusySessionKeepsItsMaildrop(fixture) {
  var handle = fixture.handle;
  var alice = await accountWith(handle, "alice@example.com", ["first", "second"]);

  var live = handle.mailbox.openPop3Drop(alice, {});
  count("a maildrop opens holding both messages", live.count === 2, String(live.count));

  handle.mailbox.markDelete(alice, live.dropId, 1);
  count("the session marks one for deletion, and nothing is applied yet",
    handle.mailbox.listMessages(alice, live.dropId).length === 1 &&
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 2);

  // The session is busy. Every one of these is a command a client sent,
  // and each of them reaches this layer through the verb the listener
  // calls. Elapsed time is stepped past the lifetime between them,
  // which is the slow link this case is about.
  var readBack = withElapsedStep(PAST_THE_MAILDROP_TTL_MS, function () {
    return handle.mailbox.getMessage(alice, live.dropId, 2, {});
  });
  count("a RETR issued after the maildrop lifetime has elapsed still returns the message, " +
    "because a session issuing commands has not been abandoned",
    readBack !== null && Buffer.isBuffer(readBack.rawBytes) &&
    readBack.rawBytes.toString("utf8").indexOf("Subject: second") !== -1,
    readBack === null ? "no message" : String(readBack.size));

  var stolenBy = withElapsedStep(PAST_THE_MAILDROP_TTL_MS, function () {
    return refusalCode(function () { return handle.mailbox.openPop3Drop(alice, {}); });
  });
  count("and a second session is still refused, because RFC 1939 section 3 gives the drop " +
    "to one session at a time and the first one has not finished with it",
    stolenBy === "mailbox/drop-locked", "second open answered " + String(stolenBy));

  count("the live session still holds its maildrop",
    refusalCode(function () { return handle.mailbox.listMessages(alice, live.dropId); }) === null);

  count("so the delete it marked is still there to apply at QUIT",
    handle.mailbox.listMessages(alice, live.dropId).length === 1);

  var committed = await handle.mailbox.commitPop3Drop(alice, live.dropId);
  count("and QUIT applies it rather than the account holder seeing the message come back",
    committed.deleted === 1, String(committed.deleted));
  count("the mailbox holds what the session left it holding",
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 1);
}

// The other half, and the reason the first one cannot be answered by
// never reclaiming. A client that drops the connection without quitting
// leaves the lock behind, and this server has no signal from the
// listener that the session ended, so time is the only thing left to
// read. An account whose lock is never reclaimed is a mailbox its own
// owner cannot open until the process restarts.
async function anAbandonedSessionLosesItsMaildrop(fixture) {
  var handle = fixture.handle;
  var bob = await accountWith(handle, "bob@example.com", ["only"]);

  var abandoned = handle.mailbox.openPop3Drop(bob, {});
  count("a maildrop opens for a second account", abandoned.dropId.length > 0);

  // Nothing touches it. This is the client that went away.
  var stillHeld = withElapsedStep(INSIDE_THE_MAILDROP_TTL_MS, function () {
    return refusalCode(function () { return handle.mailbox.openPop3Drop(bob, {}); });
  });
  count("inside the lifetime the lock is still honored, so the sweep is reading elapsed " +
    "time rather than reclaiming on any reading at all",
    stillHeld === "mailbox/drop-locked", "second open answered " + String(stillHeld));

  var reopened = withElapsedStep(PAST_THE_MAILDROP_TTL_MS, function () {
    return handle.mailbox.openPop3Drop(bob, {});
  });
  count("past it the account holder gets their maildrop back",
    reopened.dropId !== abandoned.dropId && reopened.count === 1,
    "count " + String(reopened.count));

  count("and the drop the abandoned session was holding is gone rather than left to " +
    "accumulate", refusalCode(function () {
      return handle.mailbox.listMessages(bob, abandoned.dropId);
    }) === "mailbox/no-drop");

  count("the adapter reports one open drop rather than two",
    handle.mailbox.describe().openDrops === 1,
    String(handle.mailbox.describe().openDrops));

  await handle.mailbox.commitPop3Drop(bob, reopened.dropId);
  count("and none once it quits", handle.mailbox.describe().openDrops === 0,
    String(handle.mailbox.describe().openDrops));
}

// ---------------------------------------------------------------------------
// What the maildrop model owes a client between those two rules
// ---------------------------------------------------------------------------

// RFC 1939 section 7 makes the unique id the whole of what a client
// running "leave mail on server" has. It decides what to download by
// comparing the ids it holds against the ids the server lists, so an id
// that changes between sessions redownloads the message and an id that
// two different messages share skips one of them for good.
//
// This server is content addressed: two byte-identical messages are one
// file on disk under one digest. That is exactly the arrangement where
// a unique id taken from the stored content hands both copies the same
// string, so the pair is planted deliberately rather than assumed not
// to happen.
async function uniqueIdsAreUniqueAndStable(fixture) {
  var handle = fixture.handle;
  var carol = actorFor(await handle.accounts.create({
    address: "carol@example.com", password: ACCOUNT_PASSWORD }));

  var identical = messageFor("carol@example.com", "duplicate", "the same octets twice");
  handle.mailbox.appendMessage("INBOX", identical, { actor: carol });
  handle.mailbox.appendMessage("INBOX", identical, { actor: carol });

  var first = handle.mailbox.openPop3Drop(carol, {});
  var listed = handle.mailbox.listMessages(carol, first.dropId);
  count("both copies of a byte-identical message are in the maildrop",
    listed.length === 2, String(listed.length));
  count("and they carry different unique ids, although they are one file on disk",
    listed[0].uid !== listed[1].uid, listed[0].uid + " vs " + listed[1].uid);

  for (var i = 0; i < listed.length; i += 1) {
    count("a unique id is printable ASCII inside the 70 byte ceiling RFC 1939 section 7 " +
      "sets", /^[!-~]{1,70}$/.test(listed[i].uid), listed[i].uid);
  }

  await handle.mailbox.commitPop3Drop(carol, first.dropId);

  var second = handle.mailbox.openPop3Drop(carol, {});
  var again = handle.mailbox.listMessages(carol, second.dropId);
  count("a second session lists the same two messages", again.length === 2, String(again.length));
  count("with the same unique ids, which is the whole of what a client leaving mail on the " +
    "server compares against",
    again[0].uid === listed[0].uid && again[1].uid === listed[1].uid,
    JSON.stringify([listed[0].uid, listed[1].uid]) + " then " +
    JSON.stringify([again[0].uid, again[1].uid]));

  // A third message, so a case can say the ids a client already holds
  // are not handed to something else later.
  handle.mailbox.appendMessage("INBOX",
    messageFor("carol@example.com", "arrived later", "a third message"), { actor: carol });
  await handle.mailbox.commitPop3Drop(carol, second.dropId);

  var third = handle.mailbox.openPop3Drop(carol, {});
  var withNew = handle.mailbox.listMessages(carol, third.dropId);
  var known = [listed[0].uid, listed[1].uid];
  count("a message that arrived later gets an id of its own rather than one already spent",
    withNew.length === 3 && known.indexOf(withNew[2].uid) === -1,
    JSON.stringify(withNew.map(function (m) { return m.uid; })));
  count("and the ids the client already holds still name the messages they named",
    withNew[0].uid === known[0] && withNew[1].uid === known[1]);

  await handle.mailbox.commitPop3Drop(carol, third.dropId);
}

// The count a client allocates on and the octets it is then sent. RFC
// 1939 section 5 makes the LIST size and the STAT total claims about
// the same maildrop RETR serves, and a client that trusts the count and
// reads that many bytes hangs when the server sends fewer and truncates
// when it sends more.
async function listedSizesAreTheOctetsRetrReturns(fixture) {
  var handle = fixture.handle;
  var dave = await accountWith(handle, "dave@example.com", ["short", "a rather longer one"]);

  var drop = handle.mailbox.openPop3Drop(dave, {});
  var listed = handle.mailbox.listMessages(dave, drop.dropId);
  var summed = 0;
  for (var i = 0; i < listed.length; i += 1) {
    var got = handle.mailbox.getMessage(dave, drop.dropId, listed[i].msgNum, {});
    count("message " + listed[i].msgNum + " is listed at the octet count RETR returns",
      got.size === listed[i].size && got.rawBytes.length === listed[i].size,
      "listed " + listed[i].size + ", retrieved " + got.size + ", wrote " + got.rawBytes.length);
    summed += listed[i].size;
  }
  count("and the maildrop total is the sum of them, which is what STAT reports",
    summed === drop.totalBytes, String(summed) + " vs " + String(drop.totalBytes));

  await handle.mailbox.commitPop3Drop(dave, drop.dropId);
}

// RFC 1939 section 5 unmarks every message RSET finds marked, and
// section 6 is the only place a mark becomes a deletion. So a session
// that marks, resets and quits has to leave the mailbox exactly as it
// found it, and one that marks and never quits has to leave it that way
// too.
async function marksBecomeDeletionsOnlyAtQuit(fixture) {
  var handle = fixture.handle;
  var erin = await accountWith(handle, "erin@example.com", ["one", "two", "three"]);

  var resetting = handle.mailbox.openPop3Drop(erin, {});
  handle.mailbox.markDelete(erin, resetting.dropId, 1);
  handle.mailbox.markDelete(erin, resetting.dropId, 3);
  count("a marked message drops out of the listing the session sees (RFC 1939 section 5)",
    handle.mailbox.listMessages(erin, resetting.dropId).length === 1,
    String(handle.mailbox.listMessages(erin, resetting.dropId).length));
  count("and a second DELE for the same number is refused rather than counted twice",
    refusalCode(function () {
      return handle.mailbox.markDelete(erin, resetting.dropId, 1);
    }) === "mailbox/no-message");
  count("a RETR for a marked message is answered as no such message",
    handle.mailbox.getMessage(erin, resetting.dropId, 1, {}) === null);

  handle.mailbox.resetPop3Drop(erin, resetting.dropId);
  count("RSET unmarks them all",
    handle.mailbox.listMessages(erin, resetting.dropId).length === 3,
    String(handle.mailbox.listMessages(erin, resetting.dropId).length));

  var afterReset = await handle.mailbox.commitPop3Drop(erin, resetting.dropId);
  count("so QUIT after a RSET deletes nothing", afterReset.deleted === 0,
    String(afterReset.deleted));
  count("and the mailbox is as the session found it",
    handle.mailbox.selectFolder(erin, "INBOX", {}).exists === 3,
    String(handle.mailbox.selectFolder(erin, "INBOX", {}).exists));

  // The session that never reaches UPDATE state at all. Its drop ages
  // out with the marks still on it, which is the outcome section 6
  // describes for a session that ends any way other than QUIT.
  var abandoned = handle.mailbox.openPop3Drop(erin, {});
  handle.mailbox.markDelete(erin, abandoned.dropId, 1);
  handle.mailbox.markDelete(erin, abandoned.dropId, 2);
  handle.mailbox.markDelete(erin, abandoned.dropId, 3);

  var reopened = withElapsedStep(PAST_THE_MAILDROP_TTL_MS, function () {
    return handle.mailbox.openPop3Drop(erin, {});
  });
  count("a session that never quits deletes nothing, however much it marked",
    reopened.count === 3, String(reopened.count));
  count("and the mailbox still holds every message",
    handle.mailbox.selectFolder(erin, "INBOX", {}).exists === 3,
    String(handle.mailbox.selectFolder(erin, "INBOX", {}).exists));

  await handle.mailbox.commitPop3Drop(erin, reopened.dropId);
}

// ---------------------------------------------------------------------------

async function run() {
  var fixture = await openStore("pop3lease");
  try {
    await helpers.withTestTimeout("pop3 lease: a busy session keeps its maildrop",
      function () { return aBusySessionKeepsItsMaildrop(fixture); });
    await helpers.withTestTimeout("pop3 lease: an abandoned session loses its maildrop",
      function () { return anAbandonedSessionLosesItsMaildrop(fixture); });
    await helpers.withTestTimeout("pop3 lease: unique ids are unique and stable",
      function () { return uniqueIdsAreUniqueAndStable(fixture); });
    await helpers.withTestTimeout("pop3 lease: listed sizes are the octets RETR returns",
      function () { return listedSizesAreTheOctetsRetrReturns(fixture); });
    await helpers.withTestTimeout("pop3 lease: marks become deletions only at QUIT",
      function () { return marksBecomeDeletionsOnlyAtQuit(fixture); });
  } finally {
    fixture.close();
  }
  return helpers.getChecks();
}

module.exports = { name: "pop3-maildrop-lease", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
