// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The spool as a bounded place, and one entry as a thing only one
 * process may attempt at a time.
 *
 * The spool is what stands between a delivery fault and lost mail, and
 * a place that keeps everything has to have a bottom. Without one the
 * ceiling is the volume, and the volume filling takes the database, the
 * message bodies and the audit trail with it, which is a larger outage
 * than the one being avoided.
 *
 * What is asserted here:
 *
 *   - The ceiling is refused at create when it is unusable, so an
 *     operator meets a bad value at boot rather than on the message
 *     that crosses it.
 *   - A ceiling below one whole message is refused, because a spool
 *     that cannot hold a single message the listeners accept is a
 *     ceiling that refuses everything.
 *   - Depth and bytes are both counted, and either one reached is the
 *     spool being full. A count alone lets a few very large messages
 *     take the volume; bytes alone let very many small ones take the
 *     sweep.
 *   - Mail arriving from strangers stops short of the ceiling, so a
 *     flood of forwarding cannot spend the room an account holder needs
 *     to send. Authenticated submission reaches the whole ceiling.
 *   - Nothing is written when an envelope is refused. A message that
 *     spooled some of its recipients and refused the rest is one the
 *     sender retries, and the retry delivers the spooled half twice.
 *   - One entry is claimed before it is attempted, and the claim is a
 *     file the kernel created exclusively rather than a record somebody
 *     wrote down. A second process attempting the same entry finds the
 *     claim and leaves it alone.
 *   - A claim whose holder is gone in this process table is reaped, so
 *     a killed flush does not strand a message forever. A claim
 *     recorded in another process table is left alone, because a PID
 *     probed against the wrong table answers a question nobody asked.
 *
 * No sockets. The wire side of the refusal is
 * `test/layer-2-integration/outbound-spool-refusal.test.js`.
 *
 * Run standalone: node test/layer-1-state/outbound-spool-ceiling.test.js
 */

var nodeProc = require("node:child_process");

var helpers   = require("../helpers");
var cli       = require("../helpers/cli");
var blamepost = require("../../lib");
var b         = require("../../lib/vendor/blamejs");

var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var HOSTNAME  = "mx.example.com";
var ELSEWHERE = "example.net";

// A body with a known size, so a byte ceiling can be expressed in
// messages rather than in a number nobody can place. It is comfortably
// larger than the smallest message the listeners can be configured to
// accept, because that size is the floor under any byte ceiling and a
// fixture below it could not be used to build one.
var BODY_FILLER = "x".repeat(40000);
var MESSAGE = "From: alice@example.com\r\nTo: bob@" + ELSEWHERE + "\r\n" +
  "Subject: ceiling\r\n\r\n" + BODY_FILLER + "\r\n";
var MESSAGE_BYTES = Buffer.byteLength(MESSAGE, "utf8");

// A resolver that answers, which is the only way to reach the part of
// the outbound path this file is about. A failure at MX lookup is a
// verdict somebody made and never reaches the spool.
var ANSWERING_RESOLVER = {
  queryMx: function (name) {
    if (String(name).toLowerCase() === ELSEWHERE) {
      return Promise.resolve([{ priority: 10, exchange: "mx." + ELSEWHERE }]);
    }
    return Promise.reject(new Error("no mail exchanger for " + name));
  },
  queryTxt: function () { return Promise.resolve([]); },
  queryPtr: function () { return Promise.resolve([]); },
  query:    function () { return Promise.resolve([]); },
};

// A budget with room left in it, which is what puts a message in the
// spool at all. On a budget of one the first attempt is also the last,
// so the recipient comes back permanently failed with a report to its
// sender and nothing is ever written for this file to count. That is the
// correct ending for an exhausted budget and the wrong fixture for a
// file about how much the spool will hold.
var RETRY_WITH_ROOM = { maxAttempts: 5 };

function handleFor(dataDir, spool) {
  return blamepost.mail.delivery.create({
    hostname: HOSTNAME,
    dataDir:  dataDir,
    resolver: ANSWERING_RESOLVER,
    policy:   { mtaSts: "off", dane: "off" },
    retry:    RETRY_WITH_ROOM,
    spool:    spool,
  });
}

function spoolFiles(dataDir, ext) {
  var dir = path.join(dataDir, "queue");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(function (n) {
    return ext === undefined || n.slice(-ext.length) === ext;
  }).sort();
}

async function sendOne(handle, n, origin) {
  return await handle.send({
    from:   "alice@example.com",
    to:     ["bob" + n + "@" + ELSEWHERE],
    rfc822: Buffer.from(MESSAGE, "utf8"),
    origin: origin,
  });
}

function refusalFrom(fn) {
  return fn().then(function () { return null; }, function (e) { return e; });
}

// ---- the ceiling is refused at create --------------------------------------

async function anUnusableCeilingIsRefusedAtCreate(dataDir) {
  var bad = [
    { label: "a depth that is not a number",     spool: { maxMessages: "lots" } },
    { label: "a depth of zero",                  spool: { maxMessages: 0 } },
    { label: "a fractional depth",               spool: { maxMessages: 10.5 } },
    { label: "an infinite depth",                spool: { maxMessages: Infinity } },
    { label: "a byte ceiling that is not a number", spool: { maxBytes: "2GB" } },
    { label: "a byte ceiling of zero",           spool: { maxBytes: 0 } },
    { label: "a spool section that is a list",   spool: [] },
  ];
  for (var i = 0; i < bad.length; i += 1) {
    var caught = null;
    try { handleFor(dataDir, bad[i].spool); }
    catch (e) { caught = e; }
    count("create refuses " + bad[i].label,
      caught !== null && caught instanceof TypeError,
      caught === null ? "accepted" : String(caught && caught.message).slice(0, 160));
  }

  // A ceiling below one whole message refuses every message the
  // listeners accept, which is a server that takes nothing rather than
  // a bounded one.
  var tooSmall = null;
  try { handleFor(dataDir, { maxBytes: 1024 }); }
  catch (e) { tooSmall = e; }
  count("create refuses a byte ceiling that cannot hold one message",
    tooSmall !== null, tooSmall === null ? "accepted" : String(tooSmall.message).slice(0, 200));
  count("and the refusal says what the ceiling has to clear",
    tooSmall !== null && /one message/i.test(String(tooSmall.message)),
    tooSmall === null ? "" : String(tooSmall.message).slice(0, 240));

  // And the floor follows what the listeners actually accept when the
  // caller says so, rather than a number this module chose.
  var againstWireCap = null;
  try {
    blamepost.mail.delivery.create({
      hostname:        HOSTNAME,
      dataDir:         dataDir,
      maxMessageBytes: b.constants.BYTES.mib(32),
      spool:           { maxBytes: b.constants.BYTES.mib(8) },
    });
  } catch (e) { againstWireCap = e; }
  count("a ceiling below the message size this server accepts is refused",
    againstWireCap !== null,
    againstWireCap === null ? "accepted" : String(againstWireCap.message).slice(0, 200));

  // The shipped ceiling exists whether or not the operator named one.
  var shipped = handleFor(dataDir, undefined);
  var described = shipped.describe();
  count("a handle built with no ceiling still reports one",
    described.spool && typeof described.spool.maxMessages === "number" &&
    described.spool.maxMessages > 0, JSON.stringify(described.spool));
  count("and it reports a byte ceiling too",
    described.spool && typeof described.spool.maxBytes === "number" &&
    described.spool.maxBytes > 0, JSON.stringify(described.spool));
}

// ---- depth and bytes are both counted --------------------------------------

async function aFullSpoolRefusesRatherThanGrowing(dataDir) {
  var handle = handleFor(dataDir, { maxMessages: 4, maxBytes: b.constants.BYTES.mib(64) });

  for (var i = 0; i < 4; i += 1) {
    var outcome = await sendOne(handle, i, "submission");
    count("message " + i + " is taken while there is room",
      outcome && Array.isArray(outcome.deferred), JSON.stringify(outcome).slice(0, 120));
  }
  count("the spool holds exactly the ceiling", handle.queue.count() === 4,
    String(handle.queue.count()));

  var refused = await refusalFrom(function () { return sendOne(handle, 99, "submission"); });
  count("the message past the ceiling is refused rather than written",
    refused !== null, refused === null ? "accepted" : "");
  count("and the refusal carries the frozen code a listener reads",
    refused !== null && refused.code === "delivery/spool-full",
    String(refused && refused.code));
  count("and it says what an operator would do about it",
    refused !== null && /queue/i.test(String(refused.message)),
    String(refused && refused.message).slice(0, 240));
  count("nothing was written for the refused message",
    handle.queue.count() === 4, String(handle.queue.count()));
  count("and no orphan body was left behind either",
    spoolFiles(dataDir, ".eml").length === 4,
    spoolFiles(dataDir, ".eml").join(" "));

  // Room appears again once an entry leaves, and the next message is
  // taken. A ceiling that latches is an outage rather than a bound.
  var ids = spoolFiles(dataDir, ".json").map(function (n) { return n.slice(0, -5); });
  await handle.queue.remove(ids[0],
    { reason: "making room for the next message", notice: { withheld: "fixture-removal" } });
  var afterRemoval = await refusalFrom(function () { return sendOne(handle, 100, "submission"); });
  count("a message is taken again once an entry has left",
    afterRemoval === null, String(afterRemoval && afterRemoval.message).slice(0, 200));
}

async function aByteCeilingBindsBeforeTheDepthDoes(dataDir) {
  // Room for two messages by bytes and a hundred by count, so the byte
  // ceiling is the one that has to answer.
  var handle = handleFor(dataDir, {
    maxMessages: 100,
    maxBytes:    MESSAGE_BYTES * 2 + b.constants.BYTES.kib(8),
  });
  await sendOne(handle, 0, "submission");
  await sendOne(handle, 1, "submission");
  var refused = await refusalFrom(function () { return sendOne(handle, 2, "submission"); });
  count("the byte ceiling refuses while the depth ceiling still has room",
    refused !== null && refused.code === "delivery/spool-full",
    refused === null ? "accepted at " + handle.queue.count() + " entries" : "");
  count("and the depth was nowhere near its own ceiling",
    handle.queue.count() === 2, String(handle.queue.count()));
  var capacity = handle.queue.capacity();
  count("capacity reports the bytes it counted",
    capacity.bytes >= MESSAGE_BYTES * 2, JSON.stringify(capacity));
  count("capacity reports the depth it counted",
    capacity.messages === 2, JSON.stringify(capacity));
}

// ---- strangers stop short of the ceiling -----------------------------------

async function forwardingForStrangersStopsShortOfTheCeiling(dataDir) {
  var handle = handleFor(dataDir, { maxMessages: 10, maxBytes: b.constants.BYTES.mib(64) });

  // Fill to the point where the reserved share begins.
  var admitted = 0;
  for (var i = 0; i < 10; i += 1) {
    var e = await refusalFrom(function () { return sendOne(handle, i, "inbound"); });
    if (e !== null) break;
    admitted += 1;
  }
  count("inbound forwarding stops before the ceiling rather than at it",
    admitted > 0 && admitted < 10, String(admitted) + " of 10");
  count("and the entries it did write are on disk",
    handle.queue.count() === admitted, String(handle.queue.count()));

  var strangerRefused = await refusalFrom(function () { return sendOne(handle, 50, "inbound"); });
  count("a further forward is refused",
    strangerRefused !== null && strangerRefused.code === "delivery/spool-full", "");

  // The room that is left belongs to the account holders.
  var accountHolder = await refusalFrom(function () { return sendOne(handle, 51, "submission"); });
  count("an authenticated account can still send into the reserved room",
    accountHolder === null, String(accountHolder && accountHolder.message).slice(0, 200));
  count("and that write landed", handle.queue.count() === admitted + 1,
    String(handle.queue.count()));
}

// ---- reports stop shortest of all ------------------------------------------

// A report is this server's own mail, so left alone it would reach the
// whole ceiling. Its volume is not this server's to choose: it is one
// per undeliverable message, and on a run of mail to addresses that do
// not exist here the number is picked by whoever is running it. So it
// stops shortest, and the room it cannot take is room an account holder
// can still send into.
async function reportsStopShortestOfTheCeiling(dataDir) {
  var handle = handleFor(dataDir, { maxMessages: 10, maxBytes: b.constants.BYTES.mib(64) });

  var admitted = 0;
  for (var i = 0; i < 10; i += 1) {
    var e = await refusalFrom(function () { return sendOne(handle, i, "report"); });
    if (e !== null) break;
    admitted += 1;
  }
  count("reports stop well before the ceiling rather than at it",
    admitted > 0 && admitted < 10, String(admitted) + " of 10");

  var refused = await refusalFrom(function () { return sendOne(handle, 50, "report"); });
  count("a further report is refused with the frozen code",
    refused !== null && refused.code === "delivery/spool-full",
    String(refused && refused.code));
  count("and the refusal explains whose room it is protecting",
    refused !== null && /accounts on this server need to send/.test(String(refused.message)),
    String(refused && refused.message).slice(0, 240));

  // The share reports cannot take is smaller than the one mail arriving
  // for forwarding cannot take, which is smaller again than the whole.
  var forwarded = await refusalFrom(function () { return sendOne(handle, 60, "inbound"); });
  count("mail arriving for forwarding still has room a report does not",
    forwarded === null, String(forwarded && forwarded.message).slice(0, 200));
  var accountHolder = await refusalFrom(function () { return sendOne(handle, 61, "submission"); });
  count("and an authenticated account has room neither of them does",
    accountHolder === null, String(accountHolder && accountHolder.message).slice(0, 200));
}

// ---- an envelope crossing the ceiling writes nothing -----------------------

async function anEnvelopeThatCrossesTheCeilingWritesNothing(dataDir) {
  var handle = handleFor(dataDir, { maxMessages: 5, maxBytes: b.constants.BYTES.mib(64) });
  await sendOne(handle, 0, "submission");
  await sendOne(handle, 1, "submission");
  await sendOne(handle, 2, "submission");
  count("three of the five are used", handle.queue.count() === 3,
    String(handle.queue.count()));

  // Four recipients on one envelope with three slots left. The whole
  // envelope has to be refused: spooling three and refusing one leaves
  // the sender to retry a message three of whose recipients already
  // have it waiting.
  var refused = await refusalFrom(function () {
    return handle.send({
      from:   "alice@example.com",
      to:     ["one@" + ELSEWHERE, "two@" + ELSEWHERE,
               "three@" + ELSEWHERE, "four@" + ELSEWHERE],
      rfc822: Buffer.from(MESSAGE, "utf8"),
      origin: "submission",
    });
  });
  count("an envelope that cannot fit whole is refused whole",
    refused !== null && refused.code === "delivery/spool-full",
    refused === null ? "accepted" : "");
  count("and not one of its recipients was written",
    handle.queue.count() === 3, String(handle.queue.count()));
  count("nor was a body left behind for any of them",
    spoolFiles(dataDir, ".eml").length === 3, spoolFiles(dataDir, ".eml").join(" "));
}

// ---- one entry, one attempt ------------------------------------------------

function claimPath(dataDir, id) {
  return path.join(dataDir, "queue", id + ".claim");
}

async function anEntryIsClaimedBeforeItIsAttempted(dataDir) {
  var handle = handleFor(dataDir, { maxMessages: 100 });
  await sendOne(handle, 0, "submission");
  var id = spoolFiles(dataDir, ".json")[0].slice(0, -5);
  var before = await handle.queue.show(id);

  // A second opener of the same spool, which is what an operator
  // running `blamepost queue flush` beside the server is.
  var other = handleFor(dataDir, { maxMessages: 100 });

  var held = handle.queue.claim(id);
  count("the first caller takes the claim", held !== null, String(held));
  count("and the claim is a file on disk rather than a note in memory",
    fs.existsSync(claimPath(dataDir, id)), claimPath(dataDir, id));

  var second = other.queue.claim(id);
  count("a second caller is refused the same entry", second === null, String(second));

  var run = await other.queue.runDue({ force: true });
  var row = run.results.filter(function (r) { return r.id === id; })[0] || null;
  count("a flush that meets a claimed entry reports it rather than attempting it",
    row !== null && row.outcome === "claimed", JSON.stringify(row));

  var during = await handle.queue.show(id);
  count("the claimed entry gained no attempt from the second caller",
    during.attemptsRecorded === before.attemptsRecorded,
    String(before.attemptsRecorded) + " -> " + String(during.attemptsRecorded));

  held.release();
  count("releasing the claim removes the file",
    !fs.existsSync(claimPath(dataDir, id)), claimPath(dataDir, id));

  var after = await other.queue.runDue({ force: true });
  var attempted = after.results.filter(function (r) { return r.id === id; })[0] || null;
  count("and the entry is attempted once the claim is gone",
    attempted !== null && attempted.outcome !== "claimed", JSON.stringify(attempted));
  var settled = await handle.queue.show(id);
  count("the attempt was recorded exactly once",
    settled.attemptsRecorded === before.attemptsRecorded + 1,
    String(before.attemptsRecorded) + " -> " + String(settled.attemptsRecorded));
}

async function aClaimWhoseHolderIsGoneIsReaped(dataDir) {
  var handle = handleFor(dataDir, { maxMessages: 100 });
  await sendOne(handle, 0, "submission");
  var id = spoolFiles(dataDir, ".json")[0].slice(0, -5);
  var before = await handle.queue.show(id);

  // A PID that is not running, in this process table. That is what a
  // flush killed mid-attempt leaves behind, and an entry stranded on it
  // is a message nothing ever tries again.
  var deadPid = 0x7ffffffe;
  fs.writeFileSync(claimPath(dataDir, id), String(deadPid) + "\n" + _ourNamespace() + "\n");

  var run = await handle.queue.runDue({ force: true });
  var row = run.results.filter(function (r) { return r.id === id; })[0] || null;
  count("a claim held by a process that is gone does not strand the message",
    row !== null && row.outcome !== "claimed", JSON.stringify(row));
  var after = await handle.queue.show(id);
  count("and the entry was attempted",
    after.attemptsRecorded === before.attemptsRecorded + 1,
    String(before.attemptsRecorded) + " -> " + String(after.attemptsRecorded));
}

async function aClaimFromAnotherProcessTableIsLeftAlone(dataDir) {
  var handle = handleFor(dataDir, { maxMessages: 100 });
  await sendOne(handle, 0, "submission");
  var id = spoolFiles(dataDir, ".json")[0].slice(0, -5);
  var before = await handle.queue.show(id);

  // The same dead PID, recorded against a process table this process
  // cannot probe. That is the server in a container seen from the host.
  // Probing it here would answer about a completely different process,
  // and reaping on that answer is the double attempt this claim exists
  // to prevent.
  var deadPid = 0x7ffffffe;
  fs.writeFileSync(claimPath(dataDir, id),
    String(deadPid) + "\nsomewhere-else:not-this-process-table\n");

  var run = await handle.queue.runDue({ force: true });
  var row = run.results.filter(function (r) { return r.id === id; })[0] || null;
  count("a claim recorded in another process table is not reaped",
    row !== null && row.outcome === "claimed", JSON.stringify(row));
  var after = await handle.queue.show(id);
  count("and the entry was not attempted",
    after.attemptsRecorded === before.attemptsRecorded,
    String(before.attemptsRecorded) + " -> " + String(after.attemptsRecorded));
  count("and the foreign claim is still on disk",
    fs.existsSync(claimPath(dataDir, id)), claimPath(dataDir, id));
}

function _ourNamespace() {
  try { return String(fs.readlinkSync("/proc/self/ns/pid")); }
  catch (_e) { return "host:" + require("node:os").hostname(); }
}

// ---- two flushes at once ---------------------------------------------------

// The consumer path, driven the way an operator drives it: two
// `blamepost queue flush` runs started together over one spool. The
// invariant is a safety one, so it cannot fail on a run where the two
// happened not to overlap: no entry may gain more than one attempt.
async function twoFlushesNeverAttemptOneEntryTwice(root) {
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });

  var handle = handleFor(dataDir, { maxMessages: 200 });
  var entries = 40;
  for (var i = 0; i < entries; i += 1) await sendOne(handle, i, "submission");
  count("the spool is loaded for the race", handle.queue.count() === entries,
    String(handle.queue.count()));

  var before = {};
  var listed = await handle.queue.list();
  for (var j = 0; j < listed.length; j += 1) before[listed[j].id] = listed[j].attemptsRecorded;

  var env = Object.assign({}, process.env, {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: "a long enough vault passphrase for one test run",
    BLAMEJS_TMPDIR:             workDir,
  });

  function flush(label) {
    return new Promise(function (resolve) {
      var child = nodeProc.spawn(process.execPath,
        [cli.BIN, "queue", "flush", "--force"], { env: env, encoding: "utf8" });
      var out = "";
      child.stdout.on("data", function (d) { out += d; });
      child.stderr.on("data", function (d) { out += d; });
      child.on("close", function (status) {
        resolve({ label: label, status: status, out: cli.withoutBootLines(out) });
      });
    });
  }

  var both = await Promise.all([flush("first"), flush("second")]);
  count("both flushes ran to completion",
    both[0].status === 0 && both[1].status === 0,
    both.map(function (r) { return r.label + "=" + r.status; }).join(" "));

  var after = await handle.queue.list();
  var overAttempted = [];
  for (var k = 0; k < after.length; k += 1) {
    var was = before[after[k].id];
    if (was === undefined) continue;
    if (after[k].attemptsRecorded - was > 1) {
      overAttempted.push(after[k].id + " " + was + "->" + after[k].attemptsRecorded);
    }
  }
  count("no entry was attempted twice by two flushes running together",
    overAttempted.length === 0, overAttempted.slice(0, 8).join(", "));

  var stranded = spoolFiles(dataDir, ".claim");
  count("neither flush left a claim behind", stranded.length === 0, stranded.join(" "));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }
  try {
    await helpers.withTestTimeout("spool ceiling: an unusable ceiling is refused at create",
      function () { return anUnusableCeilingIsRefusedAtCreate(freshDir("spool-create")); });
    await helpers.withTestTimeout("spool ceiling: a full spool refuses rather than growing",
      function () { return aFullSpoolRefusesRatherThanGrowing(freshDir("spool-full")); });
    await helpers.withTestTimeout("spool ceiling: the byte ceiling binds on its own",
      function () { return aByteCeilingBindsBeforeTheDepthDoes(freshDir("spool-bytes")); });
    await helpers.withTestTimeout("spool ceiling: strangers stop short of the ceiling",
      function () { return forwardingForStrangersStopsShortOfTheCeiling(freshDir("spool-reserve")); });
    await helpers.withTestTimeout("spool ceiling: reports stop shortest of the ceiling",
      function () { return reportsStopShortestOfTheCeiling(freshDir("spool-report")); });
    await helpers.withTestTimeout("spool ceiling: an envelope that cannot fit writes nothing",
      function () { return anEnvelopeThatCrossesTheCeilingWritesNothing(freshDir("spool-atomic")); });
    await helpers.withTestTimeout("spool claim: an entry is claimed before it is attempted",
      function () { return anEntryIsClaimedBeforeItIsAttempted(freshDir("spool-claim")); });
    await helpers.withTestTimeout("spool claim: a dead holder's claim is reaped",
      function () { return aClaimWhoseHolderIsGoneIsReaped(freshDir("spool-reap")); });
    await helpers.withTestTimeout("spool claim: a foreign process table is left alone",
      function () { return aClaimFromAnotherProcessTableIsLeftAlone(freshDir("spool-foreign")); });
    await helpers.withTestTimeout("spool claim: two flushes never attempt one entry twice",
      function () { return twoFlushesNeverAttemptOneEntryTwice(freshDir("spool-race")); },
      { timeoutMs: 60000 });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "outbound-spool-ceiling", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
