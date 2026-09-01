// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What happens to this server's windows when the operator's clock moves.
 *
 * A mail server is full of rules that are windows rather than states: a
 * maildrop is held exclusively for half an hour, a report budget is
 * spent over an hour, a signature is valid until an instant its signer
 * chose. Each one is a duration, and a duration is only as trustworthy
 * as the clock it is measured on.
 *
 * `Date.now()` is not that clock. It moves backwards when an operator
 * corrects a wrong time, when NTP steps a drifted host, and when a
 * container starts before it has synchronized and then catches up. None
 * of those is exotic: the last one happens on every cold boot of a
 * machine with no battery-backed clock, which is most of them.
 *
 * So the question each case below asks is the same one, and it is
 * deliberately not "does the window expire on time". It is: **does
 * moving the wall clock change a decision that nothing else changed?**
 * A window that reads a monotonic source answers no, whatever the
 * operator does to the date. A window that reads the wall clock answers
 * yes, and the size of the mistake is the size of the correction.
 *
 * How the clock is moved: `withClockStep` replaces `Date.now` for the
 * duration of one call and puts it back in a `finally`. Nothing else is
 * replaced. The code under test is the shipped code, driven through the
 * shipped verbs, with one scripted reading of the time it asks for. That
 * is the only way to observe a correction without waiting for a real one,
 * and it is narrowly scoped on purpose: a scripted clock left in place
 * across a database write would stamp a row with a time that never
 * happened.
 *
 * The last case scripts nothing at all. Two folder rows minted for the
 * same mailbox inside one second carry the same UIDVALIDITY while the
 * UID space underneath them restarts at 1, which is the collision RFC
 * 9051 section 2.3.1.1 exists to prevent, reachable on an ordinary clock
 * that is behaving perfectly.
 *
 * Run standalone: node test/layer-1-state/clock-step-windows.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");
var zlib     = require("node:zlib");

var helpers   = require("../helpers");
var zone      = require("../helpers/dns-zone");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";

// Longer than the maildrop TTL in lib/mail/mailbox.js, so a step of this
// size crosses it. The point is the crossing, not the number.
var PAST_THE_MAILDROP_TTL_MS = helpers.b.constants.TIME.minutes(31);

// Longer than the report rate window in lib/mail/delivery.js, for the
// same reason.
var PAST_THE_REPORT_WINDOW_MS = helpers.b.constants.TIME.hours(1);

// A correction large enough that a window measured against the wall
// clock cannot elapse until the clock has caught back up to where it
// was. An operator fixing a host that booted a day ahead of itself makes
// exactly this move.
var A_DAY_BACKWARDS_MS = -helpers.b.constants.TIME.days(1);

// ---------------------------------------------------------------------------
// The scripted clock
// ---------------------------------------------------------------------------

// Kept local to this file rather than shared. It is not a fixture the
// other suites want: it rewrites a global for the length of one call,
// and the reason it is safe here is that every call it wraps is one this
// file chose and audited. The moment a second file needs it, it moves to
// test/helpers with that reasoning attached.
var REAL_DATE_NOW = Date.now;

function withClockStep(offsetMs, fn) {
  if (typeof offsetMs !== "number" || !isFinite(offsetMs)) {
    throw new TypeError("withClockStep: offsetMs must be a finite number of milliseconds");
  }
  if (typeof fn !== "function") {
    throw new TypeError("withClockStep: fn (function) required");
  }
  Date.now = function () { return REAL_DATE_NOW.call(Date) + offsetMs; };
  try { return fn(); }
  finally { Date.now = REAL_DATE_NOW; }
}

// The async half. Written out rather than folded into the one above,
// because a `finally` that restores the clock has to run when the
// promise settles and not when the function returns: a synchronous
// restore around an async body puts the real clock back while the call
// it was stepping for is still in flight, and the step is then invisible
// to the code it was meant to reach.
async function withClockStepAsync(offsetMs, fn) {
  if (typeof offsetMs !== "number" || !isFinite(offsetMs)) {
    throw new TypeError("withClockStepAsync: offsetMs must be a finite number of milliseconds");
  }
  if (typeof fn !== "function") {
    throw new TypeError("withClockStepAsync: fn (function) required");
  }
  Date.now = function () { return REAL_DATE_NOW.call(Date) + offsetMs; };
  try { return await fn(); }
  finally { Date.now = REAL_DATE_NOW; }
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
// one open database per process and a case that leaves it open takes the
// next one down with it.
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

// A receiver nothing can reach, so every recipient handed to the
// delivery handle produces the permanent failure that runs the report
// path. The bound on that path is what these cases are about.
var UNREACHABLE_MX = {
  queryMx: function () { return Promise.reject(new Error("no route to any exchanger")); },
};

function deliveryOn(dataDir) {
  return blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: UNREACHABLE_MX,
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
  });
}

function refusalCode(fn) {
  try { fn(); return null; }
  catch (e) { return (e && e.code) || "threw without a code"; }
}

// ---------------------------------------------------------------------------
// The maildrop a clock step can take away
// ---------------------------------------------------------------------------

// RFC 1939 section 3 gives one session exclusive access to a maildrop
// until it quits, and this server backs that with a TTL so a client that
// drops the connection without quitting does not lock its own mailbox
// out forever. Both halves are decisions about how long the session has
// been open, and neither is a decision about what the date is.
//
// A wall clock that jumps forward past the TTL makes the sweep believe
// every open session has been idle for longer than it has. It reaps a
// maildrop somebody is holding, and the deletes that session had marked
// go with it: RFC 1939 applies them at QUIT and at no other point, so a
// drop that disappears before the QUIT discards them without telling
// anyone. The account holder sees the mail they deleted come back.
async function aClockStepDoesNotTakeALiveMaildropAway(fixture) {
  var handle = fixture.handle;
  var alice = actorFor(await handle.accounts.create({
    address: "alice@example.com", password: ALICE_PASSWORD }));

  handle.mailbox.appendMessage("INBOX",
    Buffer.from("From: s@example.net\r\nTo: alice@example.com\r\n" +
      "Subject: keep\r\n\r\nbody\r\n", "utf8"), { actor: alice });

  var live = handle.mailbox.openPop3Drop(alice, {});
  count("a maildrop opens and holds the message", live.count === 1, String(live.count));

  count("a second session is refused while the first holds it (RFC 1939 section 3)",
    refusalCode(function () { return handle.mailbox.openPop3Drop(alice, {}); }) ===
      "mailbox/drop-locked");

  // The session marks a message for deletion. Nothing is applied yet:
  // RFC 1939 holds the marks until QUIT.
  handle.mailbox.markDelete(alice, live.dropId, 1);
  count("the session's delete is marked rather than applied",
    handle.mailbox.listMessages(alice, live.dropId).length === 0 &&
    handle.mailbox.selectFolder(alice, "INBOX", {}).exists === 1);

  // Now the operator corrects a clock, or NTP steps one. The session is
  // still live and no time has passed.
  var stolenBy = withClockStep(PAST_THE_MAILDROP_TTL_MS, function () {
    return refusalCode(function () { return handle.mailbox.openPop3Drop(alice, {}); });
  });
  count("a wall clock stepping forward past the maildrop TTL does not hand the maildrop " +
    "to a second session, because nothing about the first session changed",
    stolenBy === "mailbox/drop-locked", "second open answered " + String(stolenBy));

  count("and the live session still has its maildrop",
    refusalCode(function () { return handle.mailbox.listMessages(alice, live.dropId); }) === null);

  count("so the deletes it had marked are still there to apply at QUIT",
    handle.mailbox.listMessages(alice, live.dropId).length === 0);

  var committed = await handle.mailbox.commitPop3Drop(alice, live.dropId);
  count("and QUIT applies them", committed.deleted === 1, String(committed.deleted));
}

// The same question asked the other way. A clock correction that moves
// backwards must not extend the hold either: an abandoned session would
// otherwise keep the exclusive lock until the wall clock had climbed
// back to where it started, which for a host that booted a day ahead of
// itself is a mailbox its owner cannot open for a day.
//
// What this case can prove without waiting out a real TTL is the half
// that matters: the decision does not move. Half an hour has not
// elapsed, so the hold is correct in both readings, and a hold that
// depended on the date would be answering a different question.
async function aClockStepBackwardsDoesNotExtendTheHold(fixture) {
  var handle = fixture.handle;
  var bob = actorFor(await handle.accounts.create({
    address: "bob@example.com", password: ALICE_PASSWORD }));

  var live = handle.mailbox.openPop3Drop(bob, {});
  count("a second maildrop opens for a second account", live.dropId.length > 0);

  var underStep = withClockStep(A_DAY_BACKWARDS_MS, function () {
    return refusalCode(function () { return handle.mailbox.openPop3Drop(bob, {}); });
  });
  count("a wall clock stepping a day backwards leaves the hold exactly where it was",
    underStep === "mailbox/drop-locked", "second open answered " + String(underStep));

  count("and the reading is the same once the clock is back",
    refusalCode(function () { return handle.mailbox.openPop3Drop(bob, {}); }) ===
      "mailbox/drop-locked");

  await handle.mailbox.commitPop3Drop(bob, live.dropId);
}

// ---------------------------------------------------------------------------
// The report budget a clock step can hand back
// ---------------------------------------------------------------------------

// A delivery report is addressed to the sender of the message it is
// about, and on a run of mail to addresses that do not exist here that
// sender is whoever forged it. The bound on generation is what keeps
// this server from relaying somebody else's run back at them, and it is
// spent over a window.
//
// The window is the whole bound. If it can be rolled over by moving a
// clock rather than by time passing, then a host whose clock is stepped
// hands out a fresh budget on every step, and the ceiling an operator
// reads in the documentation is not the ceiling the server keeps.
async function aClockStepDoesNotHandBackTheReportBudget(dataDir) {
  var delivery = deliveryOn(dataDir);

  // Comfortably past the per sender bound, so the crossing is observed
  // rather than assumed to be at a particular number.
  var refused = 0;
  for (var i = 0; i < 40; i += 1) {
    var outcome = await delivery.bounce({
      to:        "forged@example.net",
      recipient: "nobody" + i + "@example.com",
      reason:    "No mailbox by that name at this server.",
    });
    if (outcome.reportUnsent === true) refused += 1;
  }
  count("a run against one forged sender spends the budget", refused > 0,
    String(refused) + " of 40 recorded rather than sent");

  var beforeStep = await delivery.bounce({
    to: "forged@example.net", recipient: "before@example.com", reason: "y" });
  count("the bound is holding right now", beforeStep.reportUnsent === true);

  // The operator corrects the clock. No reports have been generated in
  // the meantime and no time has passed.
  var afterStep = await withClockStepAsync(PAST_THE_REPORT_WINDOW_MS, function () {
    return delivery.bounce({
      to: "forged@example.net", recipient: "afterstep@example.com", reason: "y" });
  });
  count("a wall clock stepping forward past the report window does not hand back a fresh " +
    "budget, because the bound counts elapsed time rather than the date",
    afterStep.reportUnsent === true,
    afterStep.reportUnsent === true ? "still refused" : "sent on the strength of a clock step");

  var afterBackwards = await withClockStepAsync(A_DAY_BACKWARDS_MS, function () {
    return delivery.bounce({
      to: "forged@example.net", recipient: "backwards@example.com", reason: "y" });
  });
  count("and a clock stepping backwards does not either",
    afterBackwards.reportUnsent === true);

  count("every report the bound refused is still counted where an operator reads it",
    delivery.describe().reportsUnsent >= refused + 3,
    String(delivery.describe().reportsUnsent) + " recorded");
}

// ---------------------------------------------------------------------------
// The period a report claims to cover
// ---------------------------------------------------------------------------

// A receiver that publishes a TLS-RPT endpoint, with an MTA-STS record
// this server cannot settle, so an ordinary send leaves a real RFC 8460
// policy failure to report on.
var WANTS_REPORTS = {
  "example.net":            { mx: ["mx.example.net"] },
  "_mta-sts.example.net":   zone.FAILING,
  "_smtp._tls.example.net": { txt: ["v=TLSRPTv1; rua=https://reports.example.net/tlsrpt"] },
};

// The HTTPS client the submission posts through, recording what a
// receiver would actually have read.
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

function reportIn(post) {
  return JSON.parse(zlib.gunzipSync(post.body).toString("utf8"));
}

// RFC 8460 section 4.3 gives a report a start and an end, and section
// 5.3 puts the same pair in the filename. Both are real instants in a
// receiver's terms, so both are wall clock readings and have to stay
// that way: a monotonic count means nothing to somebody else's calendar.
//
// The accumulation window opens when the first observation lands and
// closes when the report goes out, which puts a persisted timestamp on
// one side and a fresh reading on the other. A clock corrected backwards
// between the two inverts the pair, and a receiver filing thousands of
// these reads a period that ends before it began. The value this server
// can no longer stand behind is the START, because the instant it named
// is one this host now says never happened.
async function aReportNeverClaimsAPeriodThatEndsBeforeItBegan(dataDir) {
  var delivery = blamepost.mail.delivery.create({
    hostname:   "mx.example.com",
    dataDir:    dataDir,
    postmaster: "postmaster@example.com",
    resolver:   zone.resolverOver(WANTS_REPORTS),
    policy:     { mtaSts: "enforce", dane: "off" },
    audit:      false,
  });

  await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from("From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n", "utf8"),
  });

  var recordPath = nodePath.join(dataDir, "tlsrpt", "d.example.net.json");
  count("the attempt opened an accumulation window for the receiver",
    nodeFs.existsSync(recordPath));

  // The host was an hour ahead when the window opened, and the operator
  // has since corrected it. Written onto the record rather than
  // simulated, because that is exactly what the corrected host has on
  // disk: a start instant later than the present.
  var record = JSON.parse(nodeFs.readFileSync(recordPath, "utf8"));
  record.since = Date.now() + helpers.b.constants.TIME.hours(1);
  nodeFs.writeFileSync(recordPath, JSON.stringify(record, null, 2), "utf8");

  var client = recordingClient();
  var run = await delivery.tlsRpt.run({ httpClient: client });
  count("the report still goes out, because the observations are good even though the " +
    "instant the window claimed is not", run.ran === 1 && client.posts.length === 1,
    JSON.stringify(run.results));

  var report = reportIn(client.posts[0]);
  var startsAt = Date.parse(report["date-range"]["start-datetime"]);
  var endsAt   = Date.parse(report["date-range"]["end-datetime"]);
  count("the period a receiver reads is a real one (RFC 8460 section 4.3)",
    isFinite(startsAt) && isFinite(endsAt),
    JSON.stringify(report["date-range"]));
  count("and it does not end before it began, whatever the host's clock did between the " +
    "first observation and the report",
    endsAt >= startsAt, JSON.stringify(report["date-range"]));

  // RFC 8460 section 5.3 builds the report filename out of the same
  // pair, so an inverted period would reach the receiver twice: once in
  // the document and once in the name they file it under. There is no
  // second assertion for it here because there is no second value: the
  // filename is composed from `record.since` and the run's clock, which
  // are the two this case has just read out of the document. A filename
  // that disagreed with the date range would be a different bug, and it
  // is the mail submission path rather than this one that carries a
  // filename at all.
  count("the period the report claims is the one the counts were gathered over, so the " +
    "receiver is not being told to file this under a day it never covered",
    endsAt - startsAt >= 0 && endsAt - startsAt < helpers.b.constants.TIME.hours(25),
    String(endsAt - startsAt) + "ms");
}

// ---------------------------------------------------------------------------
// The identifier a client caches its whole mailbox against
// ---------------------------------------------------------------------------

// RFC 9051 section 2.3.1.1: when a mailbox's unique identifiers do not
// persist into a new session, the server MUST assign a UIDVALIDITY
// larger than the one it used before. That value is the entire contract
// behind an IMAP client's cache. A client that sees the same one keeps
// everything it holds and goes on addressing messages by UID.
//
// Destroying an account and provisioning the same address again is
// exactly that situation: the folder rows are new, so the UID space
// restarts at 1, and every UID the client cached now names a different
// message. The two mailboxes have to be distinguishable, and a value
// taken from a one-second clock reading cannot distinguish them when
// both are minted inside the same second.
//
// No clock is stepped here. Nothing is wrong with the clock. Two
// operations one after the other are simply fast.
async function uidvalidityIsLargerThanTheOneItReplaces(fixture) {
  var handle = fixture.handle;

  var first = actorFor(await handle.accounts.create({
    address: "carol@example.com", password: ALICE_PASSWORD }));
  var before = handle.mailbox.selectFolder(first, "INBOX", {});
  count("the first INBOX reports a UIDVALIDITY", typeof before.uidvalidity === "number" &&
    before.uidvalidity > 0, String(before.uidvalidity));

  await handle.accounts.delete({
    id: first.id, reason: "the account holder left", destroy: true });

  var second = actorFor(await handle.accounts.create({
    address: "carol@example.com", password: ALICE_PASSWORD }));
  var after = handle.mailbox.selectFolder(second, "INBOX", {});

  count("provisioning the same address again mints a fresh UID space",
    after.uidnext === 1, "uidnext " + String(after.uidnext));

  count("so its UIDVALIDITY is larger than the one it replaces, which is what tells a client " +
    "holding a cache of the old mailbox to throw it away (RFC 9051 section 2.3.1.1)",
    after.uidvalidity > before.uidvalidity,
    "before " + String(before.uidvalidity) + ", after " + String(after.uidvalidity));

  // And the same again, so the guarantee is a rule rather than one lucky
  // pair. Three mailboxes minted inside one second still climb.
  await handle.accounts.delete({
    id: second.id, reason: "the account holder left again", destroy: true });
  var third = actorFor(await handle.accounts.create({
    address: "carol@example.com", password: ALICE_PASSWORD }));
  var last = handle.mailbox.selectFolder(third, "INBOX", {});
  count("and it climbs again on the next one", last.uidvalidity > after.uidvalidity,
    "after " + String(after.uidvalidity) + ", last " + String(last.uidvalidity));

  count("a UIDVALIDITY still fits the unsigned 32 bit field RFC 9051 gives it",
    last.uidvalidity > 0 && last.uidvalidity <= 4294967295, String(last.uidvalidity));
}

// ---------------------------------------------------------------------------

async function run() {
  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }

  var fixture = await openStore("clockstep");
  try {
    await helpers.withTestTimeout("clock step: a live maildrop is not taken away",
      function () { return aClockStepDoesNotTakeALiveMaildropAway(fixture); });
    await helpers.withTestTimeout("clock step: a step backwards does not extend the hold",
      function () { return aClockStepBackwardsDoesNotExtendTheHold(fixture); });
    await helpers.withTestTimeout("clock step: UIDVALIDITY is larger than the one it replaces",
      function () { return uidvalidityIsLargerThanTheOneItReplaces(fixture); });
  } finally {
    fixture.close();
  }

  try {
    await helpers.withTestTimeout("clock step: the report budget is not handed back",
      function () { return aClockStepDoesNotHandBackTheReportBudget(freshDir("clock-report")); },
      // Forty bounces against a real spool on a real disk.
      { timeoutMs: 30000 });
    await helpers.withTestTimeout("clock step: a report never claims an inverted period",
      function () {
        return aReportNeverClaimsAPeriodThatEndsBeforeItBegan(freshDir("clock-tlsrpt"));
      });
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }

  return helpers.getChecks();
}

module.exports = { name: "clock-step-windows", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
