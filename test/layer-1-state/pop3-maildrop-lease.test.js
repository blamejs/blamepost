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
 * The window is the backstop rather than the release. The POP3 listener
 * reports a session's activity and its ending, and those reports are
 * what age the lease and hand it back. The report is answered here by
 * `touchPop3Drop` and `releasePop3Drop`, and the cases for them assert
 * the two things a release owes: that it happens on the ending rather
 * than on a timer, and that it names the session which opened the drop
 * rather than the account, so an ending arriving late cannot take a
 * maildrop from the live session that opened the next one.
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

var helpers       = require("../helpers");
var b             = require("../../lib/vendor/blamejs");
var config        = require("../../lib/config");
var store         = require("../../lib/store");
var mailboxModule = require("../../lib/mail/mailbox");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// Longer than the maildrop lifetime in lib/mail/mailbox.js, so a step of
// this size crosses it. The point is the crossing, not the number.
var PAST_THE_MAILDROP_TTL_MS = helpers.b.constants.TIME.minutes(31);

// Comfortably inside it, for the case that has to show the sweep is
// reading elapsed time at all rather than reclaiming on any step.
var INSIDE_THE_MAILDROP_TTL_MS = helpers.b.constants.TIME.minutes(5);

// The lifetime as the operator guide states it, and the sentence it is
// read out of.
//
// The two constants above bracket the window between five minutes and
// thirty-one, which is wide enough for the shipped number to move
// without a case here noticing. The guide tells an account holder that
// a maildrop they cannot open comes back to them after thirty minutes,
// and the support answer it gives is written against that number: an
// operator repeating it to somebody waiting is quoting this server, so
// the window is held to the sentence rather than to the module.
//
// A duration in that sentence is a word rather than a numeral, so the
// words that could reasonably stand in it are mapped. A word outside
// the map reads as no number at all and fails the first check below,
// naming what it found, which is the loud direction: a rewritten
// sentence stops the run rather than quietly widening the bracket.
var SETTINGS_REFERENCE = "docs/operator-guide.md";
var MAILDROP_TTL_RE    = /released after ([a-z-]+|\d+) minutes/;

var MINUTE_WORDS = {
  five: 5, ten: 10, fifteen: 15, twenty: 20, "twenty-five": 25, thirty: 30,
  "thirty-five": 35, forty: 40, "forty-five": 45, fifty: 50, sixty: 60,
};

function documentedMaildropTtlMinutes() {
  var text = nodeFs.readFileSync(
    nodePath.join(helpers.REPO_ROOT, SETTINGS_REFERENCE), "utf8");
  var matched = MAILDROP_TTL_RE.exec(text);
  if (matched === null) return null;
  if (/^\d+$/.test(matched[1])) return parseInt(matched[1], 10);
  var word = MINUTE_WORDS[matched[1]];
  return word === undefined ? null : word;
}

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
    handle:  handle,
    dataDir: cfg.paths.dataDir,
    close:   function () {
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

// How wide that window is, held against the number the guide prints.
//
// The pair above proves the sweep reads idleness rather than age, and
// is satisfied by any window between the two steps it takes. A window
// narrowed to ten minutes keeps both of them green while an account
// holder reading the guide waits out a half hour that ended twenty
// minutes ago, and a widened one leaves them locked out past the answer
// their operator gave them. Both edges are driven, because a window
// asserted from one side alone is satisfied by one that never reclaims
// or by one that reclaims at once.
async function theIdleWindowIsTheWidthTheGuidePrints(fixture) {
  var minutes = documentedMaildropTtlMinutes();
  count("the operator guide names how long an untouched maildrop is held, so this is " +
    "comparing something", minutes !== null && minutes > 1, String(minutes));
  if (minutes === null) return;

  var handle = fixture.handle;
  var heidi = await accountWith(handle, "heidi@example.com", ["only"]);

  var abandoned = handle.mailbox.openPop3Drop(heidi, {});
  count("a maildrop opens and nothing touches it again", abandoned.count === 1,
    String(abandoned.count));

  // Read as either the drop that opened or the code that refused, so a
  // window on the wrong side of the guide's number is a named failure
  // rather than an exception out of the middle of the case.
  function openUnderAStepOf(offsetMs) {
    return withElapsedStep(offsetMs, function () {
      try { return { opened: handle.mailbox.openPop3Drop(heidi, {}) }; }
      catch (e) { return { code: (e && e.code) || "threw without a code" }; }
    });
  }

  // A minute short of the number rather than a millisecond short of it.
  // The reading the sweep takes is the step plus whatever this run spent
  // between the two calls, so a boundary driven to the millisecond would
  // be decided by the runner's load rather than by the window.
  var justBefore = openUnderAStepOf(helpers.b.constants.TIME.minutes(minutes - 1));
  count("a minute short of the time the guide prints, the maildrop is still held, so an " +
    "account holder told half an hour does not get a quarter of one",
    justBefore.code === "mailbox/drop-locked",
    justBefore.code === undefined ? "the maildrop was handed over" : justBefore.code);

  var justAfter = openUnderAStepOf(helpers.b.constants.TIME.minutes(minutes + 1));
  count("and a minute past it the account holder has their maildrop back, so the wait is " +
    "the one the guide prints rather than merely no longer than it",
    justAfter.opened !== undefined && justAfter.opened.dropId !== abandoned.dropId &&
    justAfter.opened.count === 1,
    justAfter.opened === undefined
      ? "second open answered " + justAfter.code
      : "count " + String(justAfter.opened.count));

  if (justAfter.opened !== undefined) {
    await handle.mailbox.commitPop3Drop(heidi, justAfter.opened.dropId);
  }
}

// ---------------------------------------------------------------------------
// The session ending is the release, and it names one session
// ---------------------------------------------------------------------------

// The POP3 listener reports a session's ending however that session
// ended, and this layer hands the maildrop back on that report. The
// window above is what answers when the report never arrives.
//
// Which session the report names is the whole of the risk. An ending
// arriving after the mailbox's next session has already opened a drop
// would, if it named the ACCOUNT, reach past a live client and take the
// maildrop it is holding; RFC 1939 section 6 applies a DELE only at
// QUIT, so the marks go with it and the account holder is offered the
// mail they deleted all over again. Two actor objects for one account
// is what two POP3 connections signing in as the same mailbox produce,
// because the verifier builds one per connection and the listener
// carries it for that connection's life.
async function anEndingReleasesOneSessionsMaildrop(fixture) {
  var handle = fixture.handle;
  var firstSession  = await accountWith(handle, "frank@example.com",
    ["first", "second", "third"]);
  var secondSession = Object.assign({}, firstSession);

  var held = handle.mailbox.openPop3Drop(firstSession, {});
  handle.mailbox.markDelete(firstSession, held.dropId, 1);
  count("a session opens a maildrop and marks a message in it",
    held.count === 3, String(held.count));
  count("and the mailbox is held against everybody else while it does",
    refusalCode(function () {
      return handle.mailbox.openPop3Drop(secondSession, {});
    }) === "mailbox/drop-locked");

  var released = handle.mailbox.releasePop3Drop(firstSession);
  count("the session ending hands the maildrop back there and then, rather than after the " +
    "idle window the reports exist to replace",
    released.released === true && released.dropId === held.dropId, JSON.stringify(released));
  count("and the marks it was holding went with it, because the one place they become " +
    "deletions is QUIT (RFC 1939 section 6)",
    handle.mailbox.selectFolder(firstSession, "INBOX", {}).exists === 3,
    String(handle.mailbox.selectFolder(firstSession, "INBOX", {}).exists));

  var reopened = handle.mailbox.openPop3Drop(secondSession, {});
  count("so the next session opens a maildrop of its own straight away",
    reopened.count === 3 && reopened.dropId !== held.dropId, String(reopened.count));

  var stale = handle.mailbox.releasePop3Drop(firstSession);
  count("an ending reported for the session that has already gone releases nothing",
    stale.released === false, JSON.stringify(stale));
  count("and the live session is still holding the maildrop it opened",
    handle.mailbox.describe().openDrops === 1,
    String(handle.mailbox.describe().openDrops));

  handle.mailbox.markDelete(secondSession, reopened.dropId, 1);
  var committed = await handle.mailbox.commitPop3Drop(secondSession, reopened.dropId);
  count("so its own QUIT applies what it marked rather than failing on a maildrop taken " +
    "from underneath it", committed.deleted === 1, JSON.stringify(committed));
  count("and nothing is held once it has",
    handle.mailbox.describe().openDrops === 0,
    String(handle.mailbox.describe().openDrops));
}

// ---------------------------------------------------------------------------
// The keepalive this layer cannot see on its own
// ---------------------------------------------------------------------------

// RFC 1939 section 5 gives a client NOOP as the way to say it is still
// there, and the listener answers it without asking this layer anything.
// A client sitting on a maildrop it is not reading sends nothing else,
// so the only thing that can move the reading the sweep measures is the
// listener's report that a command arrived.
async function aKeepaliveKeepsTheMaildrop(fixture) {
  var handle = fixture.handle;
  var grace = await accountWith(handle, "grace@example.com", ["only"]);

  var open = handle.mailbox.openPop3Drop(grace, {});
  var opened = handle.mailbox.describe();
  count("an open maildrop reports how long it has been since anything touched it, one " +
    "reading per drop", opened.dropIdleMs.length === opened.openDrops,
    JSON.stringify(opened.dropIdleMs));
  count("and the reading for a drop just opened is a duration rather than a date",
    opened.dropIdleMs[0] >= 0 && opened.dropIdleMs[0] < PAST_THE_MAILDROP_TTL_MS,
    String(opened.dropIdleMs[0]) + "ms");

  var stillHeld = withElapsedStep(PAST_THE_MAILDROP_TTL_MS, function () {
    handle.mailbox.touchPop3Drop(grace);
    return refusalCode(function () { return handle.mailbox.openPop3Drop(grace, {}); });
  });
  count("a keepalive arriving past the idle window keeps the maildrop, so a session doing " +
    "nothing but answering that it is still there is not reaped under a live connection",
    stillHeld === "mailbox/drop-locked", "second open answered " + String(stillHeld));

  var reclaimed = withElapsedStep(PAST_THE_MAILDROP_TTL_MS * 2, function () {
    return handle.mailbox.openPop3Drop(grace, {});
  });
  count("and the window still runs from the last keepalive rather than never expiring",
    reclaimed.dropId !== open.dropId && reclaimed.count === 1, String(reclaimed.count));

  count("a keepalive for a session holding nothing touches nothing",
    handle.mailbox.touchPop3Drop(Object.assign({}, grace)).touched === false);

  count("and the session that opened this one hands it back",
    handle.mailbox.releasePop3Drop(grace).released === true);
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

function _filesUnder(dir) {
  var out = [];
  if (!nodeFs.existsSync(dir)) return out;
  nodeFs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    var full = nodePath.join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(_filesUnder(full));
    else out.push(full);
  });
  return out;
}

// RFC 1939 section 3 sends a message with CRLF line endings, so the size
// LIST reports for a body stored with bare line feeds and no final line
// ending is the count after those are written as CRLF. Login answers it
// from the row written when the body was filed, without reading any
// body: every body file is removed before the drop is opened, and a
// login that read them would fall back to the stored size.
async function theListedSizeIsTakenWhenTheBodyIsFiled(fixture) {
  var handle = fixture.handle;
  var mallory = actorFor(await handle.accounts.create({
    address: "mallory@example.com", password: ACCOUNT_PASSWORD }));
  var bare = Buffer.from("From: sender@example.net\nTo: mallory@example.com\n" +
    "Subject: bare line feeds\n\nfirst line\nlast line with no ending", "utf8");
  var onWire = b.safeSmtp.canonicalizeEol(bare).length + 2;
  handle.mailbox.appendMessage("INBOX", bare, { actor: mallory });

  var bodies = _filesUnder(nodePath.join(fixture.dataDir, "blobs"));
  count("the filed body is on the volume", bodies.length >= 1, String(bodies.length));
  bodies.forEach(function (file) { nodeFs.rmSync(file, { force: true }); });

  var drop = handle.mailbox.openPop3Drop(mallory, {});
  var listed = handle.mailbox.listMessages(mallory, drop.dropId);
  count("LIST reports the octets the message takes with CRLF line endings, read from the row " +
    "written when the body was filed rather than from the body",
    listed.length === 1 && listed[0].size === onWire && drop.totalBytes === onWire,
    JSON.stringify({ listed: listed, totalBytes: drop.totalBytes, onWire: onWire,
      stored: bare.length }));

  var rowsBefore = b.db.from(mailboxModule.WIRE_SIZES).all().length;
  handle.mailbox.markDelete(mallory, drop.dropId, 1);
  await handle.mailbox.commitPop3Drop(mallory, drop.dropId);
  count("and the size row goes when the message is deleted at QUIT",
    b.db.from(mailboxModule.WIRE_SIZES).all().length === rowsBefore - 1,
    rowsBefore + " row(s) before, " + b.db.from(mailboxModule.WIRE_SIZES).all().length +
      " after");

  // A body filed with no size row whose file is gone. Login cannot read
  // the body to count it, so it lists the stored size and opens the
  // maildrop rather than refusing it over one lost message.
  var lost = Buffer.from("From: sender@example.net\r\nTo: mallory@example.com\r\n" +
    "Subject: a body that went missing\r\n\r\ngone\r\n", "utf8");
  handle.mailbox.appendMessage("INBOX", lost, { actor: mallory });
  b.db.from(mailboxModule.WIRE_SIZES).all().forEach(function (row) {
    b.db.from(mailboxModule.WIRE_SIZES).where({ _id: row._id }).deleteOne();
  });
  _filesUnder(nodePath.join(fixture.dataDir, "blobs")).forEach(function (file) {
    nodeFs.rmSync(file, { force: true });
  });
  var opened = null;
  var refused = null;
  try { opened = handle.mailbox.openPop3Drop(mallory, {}); }
  catch (e) { refused = e; }
  count("a maildrop holding a body that cannot be read still opens at login",
    refused === null && opened !== null,
    refused === null ? "" : String(refused.code) + " " + refused.message);
  if (opened === null) return;
  var listedLost = handle.mailbox.listMessages(mallory, opened.dropId);
  count("and lists that message at the size it was stored with",
    listedLost.length === 1 && listedLost[0].size === lost.length,
    JSON.stringify(listedLost));
  await handle.mailbox.commitPop3Drop(mallory, opened.dropId);
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

// The maildrop identifier is a handle, and the question a handle always
// raises is what happens when somebody presents one that is not theirs.
//
// There is no wire form of this: the identifier is minted inside
// `openPop3Drop`, held in the listener's per-connection state and never
// written to the socket, so no POP3 command a client can send carries
// one. That is exactly why the claim is made here rather than over a
// port, and why it is worth making at all: the only thing standing
// between a refactor and a cross-account read is the account comparison
// in `_dropFor`, and nothing above this layer would notice it going.
//
// Three shapes, because they fail differently: another account's live
// identifier, an identifier that names no drop at all, and a shape that
// is not an identifier. All three answer the same refusal, so a session
// learns nothing about what exists from what it is told.
async function aMaildropIdentifierNobodyHandedOutReachesNothing(fixture) {
  var handle = fixture.handle;
  var ivan = await accountWith(handle, "ivan@example.com", ["ivan's own"]);
  var judy = await accountWith(handle, "judy@example.com", ["judy's own", "and another"]);

  var hers = handle.mailbox.openPop3Drop(judy, {});
  count("one account has an open maildrop with mail in it", hers.count === 2,
    String(hers.count));

  var presented = [
    ["another account's live identifier", hers.dropId],
    ["an identifier naming no maildrop",  "drop_0123456789abcdef01234567"],
    ["a shape that is not an identifier", ""],
  ];
  for (var i = 0; i < presented.length; i += 1) {
    var id = presented[i][1];
    count("a session presenting " + presented[i][0] + " is refused a listing",
      refusalCode(function () { return handle.mailbox.listMessages(ivan, id); }) ===
        "mailbox/no-drop");
    count("and refused a message from it", refusalCode(function () {
      return handle.mailbox.getMessage(ivan, id, 1, {});
    }) === "mailbox/no-drop");
    count("and refused a mark on it", refusalCode(function () {
      return handle.mailbox.markDelete(ivan, id, 1);
    }) === "mailbox/no-drop");
    count("and refused a reset of it", refusalCode(function () {
      return handle.mailbox.resetPop3Drop(ivan, id);
    }) === "mailbox/no-drop");
  }

  // The commit is the one that would destroy rather than read, so it is
  // asked separately and its refusal is awaited rather than caught
  // synchronously.
  var committed = null;
  try { await handle.mailbox.commitPop3Drop(ivan, hers.dropId); }
  catch (e) { committed = (e && e.code) || "threw without a code"; }
  count("and a commit aimed at another account's maildrop is refused rather than applying " +
    "that account's marks", committed === "mailbox/no-drop", String(committed));

  count("the other account's maildrop is untouched by any of it",
    handle.mailbox.listMessages(judy, hers.dropId).length === 2,
    String(handle.mailbox.listMessages(judy, hers.dropId).length));

  await handle.mailbox.commitPop3Drop(judy, hers.dropId);
}

// RFC 1939 section 3 gives one session exclusive access to a maildrop,
// and the framework's POP3 listener documents the call it makes for one
// as `openPop3Drop(actor, { exclusive: true })`. There is no other mode:
// the drop is a snapshot, message numbers are positions in it, and
// section 6 applies a DELE at QUIT, so two sessions sharing one would
// each be numbering a mailbox the other is changing.
//
// So an option asking for anything else is refused rather than ignored.
// A call that asks and is answered with a drop has been told its request
// was honored, and nothing anywhere would say otherwise; the shipped
// listener passes no such option today, which is exactly the state in
// which a silently discarded one goes unnoticed.
async function aMaildropCannotBeAskedForOnAnyOtherTerms(fixture) {
  var handle = fixture.handle;
  var karl = await accountWith(handle, "karl@example.com", ["karl's own"]);

  count("asking for the exclusive access RFC 1939 section 3 defines is refused when the " +
    "caller asks for something else instead",
    refusalCode(function () {
      return handle.mailbox.openPop3Drop(karl, { exclusive: false });
    }) === "mailbox/bad-argument");
  count("and nothing is held afterwards, so the refusal cost the account nothing",
    handle.mailbox.describe().openDrops === 0,
    String(handle.mailbox.describe().openDrops));

  // The two shapes the listener actually sends: no options at all, and
  // the exclusive access it documents. Both open.
  var bare = handle.mailbox.openPop3Drop(karl, {});
  count("a call carrying no options opens the drop", bare.count === 1, String(bare.count));
  await handle.mailbox.commitPop3Drop(karl, bare.dropId);

  var asked = handle.mailbox.openPop3Drop(karl, { exclusive: true });
  count("and so does one asking for exactly the access the maildrop gives",
    asked.count === 1, String(asked.count));
  await handle.mailbox.commitPop3Drop(karl, asked.dropId);
}

// ---------------------------------------------------------------------------

async function run() {
  var fixture = await openStore("pop3lease");
  try {
    await helpers.withTestTimeout("pop3 lease: a busy session keeps its maildrop",
      function () { return aBusySessionKeepsItsMaildrop(fixture); });
    await helpers.withTestTimeout("pop3 lease: an abandoned session loses its maildrop",
      function () { return anAbandonedSessionLosesItsMaildrop(fixture); });
    await helpers.withTestTimeout("pop3 lease: the idle window is the width the guide prints",
      function () { return theIdleWindowIsTheWidthTheGuidePrints(fixture); });
    await helpers.withTestTimeout("pop3 lease: an ending releases one session's maildrop",
      function () { return anEndingReleasesOneSessionsMaildrop(fixture); });
    await helpers.withTestTimeout("pop3 lease: a keepalive keeps the maildrop",
      function () { return aKeepaliveKeepsTheMaildrop(fixture); });
    await helpers.withTestTimeout("pop3 lease: unique ids are unique and stable",
      function () { return uniqueIdsAreUniqueAndStable(fixture); });
    await helpers.withTestTimeout("pop3 lease: listed sizes are the octets RETR returns",
      function () { return listedSizesAreTheOctetsRetrReturns(fixture); });
    await helpers.withTestTimeout("pop3 lease: marks become deletions only at QUIT",
      function () { return marksBecomeDeletionsOnlyAtQuit(fixture); });
    await helpers.withTestTimeout("pop3 lease: an identifier nobody handed out reaches nothing",
      function () { return aMaildropIdentifierNobodyHandedOutReachesNothing(fixture); });
    await helpers.withTestTimeout("pop3 lease: a maildrop is not asked for on other terms",
      function () { return aMaildropCannotBeAskedForOnAnyOtherTerms(fixture); });
    // Last, because it removes every body file on the volume.
    await helpers.withTestTimeout("pop3 lease: the listed size is taken when the body is filed",
      function () { return theListedSizeIsTakenWhenTheBodyIsFiled(fixture); });
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
