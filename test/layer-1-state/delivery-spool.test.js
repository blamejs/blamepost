// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The spool as a place on disk, rather than as a retry schedule.
 *
 * Three claims, each of which is about something reaching the spool
 * from outside it.
 *
 * An entry id names two files. It arrives from an operator typing
 * `blamepost queue remove <id>` and from a form field on the admin
 * page, so it is untrusted text that ends up in a path join and then in
 * a removal. Anything that is not the token this server minted is
 * refused before it becomes a path.
 *
 * A descriptor whose body has gone is an entry that can never be sent.
 * Retrying it burns the whole budget against a fault no attempt can
 * clear, and rewriting it after an operator removed the pair puts a
 * cancelled message back in the queue.
 *
 * The reason a message is waiting is written by whoever refused it,
 * which on the outbound path is a stranger's mail server. What the
 * descriptor keeps is what arrived, so an operator diagnosing a refusal
 * reads the peer's own bytes, and it is bounded by what those bytes
 * cost to store so a reply made of control characters cannot grow a
 * file past what the spool's own reader accepts. The screening for the
 * codepoints that forge a terminal row belongs to the read path, and
 * `outbound-queue-render.test.js` is where that side is pinned.
 *
 * Every hostile codepoint below is built with String.fromCharCode
 * rather than typed, so this file stays plain ASCII and an editor or a
 * copy cannot quietly change what the fixture tests.
 *
 * Run standalone: node test/layer-1-state/delivery-spool.test.js
 */

var helpers   = require("../helpers");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;
var fs    = helpers.fs;
var path  = helpers.path;

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

var ESC  = String.fromCharCode(0x1b);
var NUL  = String.fromCharCode(0x00);
var RTLO = String.fromCharCode(0x202e);

// The formatting codepoints that change what a reader sees without
// changing what the bytes say: the bidi embedding and override run
// (U+202A to U+202E), the isolates (U+2066 to U+2069), the two marks
// (U+200E, U+200F) and the Arabic letter mark (U+061C).
var BIDI_RE = new RegExp("[" +
  String.fromCharCode(0x202a) + "-" + String.fromCharCode(0x202e) +
  String.fromCharCode(0x2066) + "-" + String.fromCharCode(0x2069) +
  String.fromCharCode(0x200e) + String.fromCharCode(0x200f) +
  String.fromCharCode(0x061c) + "]");

var UNREACHABLE_MX = {
  queryMx: function () {
    return Promise.reject(new Error("probe resolver: MX lookup unavailable"));
  },
};

// A peer whose refusal carries the bytes that forge a terminal row: an
// escape sequence that repaints the screen, a carriage return that
// overwrites the line, a bidi override that reverses what follows it,
// and a null byte that truncates whatever a C reader does with it.
var HOSTILE_TEXT = "451 4.7.0 try later " +
                   ESC + "[2J" + ESC + "[1;1Hall clear\r\n250 Accepted " +
                   RTLO + "resu ot detrofmoc" + NUL + " done";
var HOSTILE_MX = {
  queryMx: function () { return Promise.reject(new Error(HOSTILE_TEXT)); },
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

function readDescriptor(dataDir, id) {
  return JSON.parse(fs.readFileSync(path.join(dataDir, "queue", id + ".json"), "utf8"));
}

function descriptorOrNull(dataDir, id) {
  try { return readDescriptor(dataDir, id); }
  catch (_e) { return null; }
}

function spoolOne(delivery) {
  return delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
}

// ---------------------------------------------------------------------------
// An id is untrusted text before it is a path
// ---------------------------------------------------------------------------

async function anEntryIdThatDidNotComeFromHereIsRefused(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);

  // A file outside the spool that a traversal would reach. It stands in
  // for the operator's configuration, which lives beside the data
  // directory and ends in the extension the spool appends.
  var bystander = path.join(dataDir, "bystander.json");
  fs.writeFileSync(bystander, "{\"keep\":true}\n", "utf8");

  var escapes = [
    "../bystander",
    "..\\bystander",
    "sub/../../bystander",
    "%2e%2e%2fbystander",
    "abc" + NUL + "/../bystander",
    "ABC123DEF456ABC123DEF456",
  ];

  for (var i = 0; i < escapes.length; i += 1) {
    var threwRemove = null;
    // A reason the removal would accept, so what is being proven is the
    // id check rather than the reason check standing in front of it.
    try {
      await delivery.queue.remove(escapes[i],
        { reason: "clearing a stuck entry", notice: { withheld: "fixture-removal" } });
    }
    catch (e) { threwRemove = e; }
    check("queue.remove refuses an id that is not one this server minted: " +
      JSON.stringify(escapes[i]), threwRemove !== null);

    var threwShow = null;
    try { await delivery.queue.show(escapes[i]); }
    catch (e) { threwShow = e; }
    check("queue.show refuses the same id: " + JSON.stringify(escapes[i]),
      threwShow !== null);
  }

  check("no removal reached a file outside the spool", fs.existsSync(bystander));

  // The ids this server does mint keep working.
  await spoolOne(delivery);
  var id = onlyId(dataDir);
  check("a real entry is still removable",
    (await delivery.queue.remove(id,
      { reason: "the domain is gone", notice: { withheld: "fixture-removal" } })).removed === true);
  check("and removing it clears both files", spoolFiles(dataDir).length === 0);

  var threwEmpty = null;
  try {
    await delivery.queue.remove("",
      { reason: "the domain is gone", notice: { withheld: "fixture-removal" } });
  }
  catch (e) { threwEmpty = e; }
  check("an empty id is refused rather than joined onto the spool path",
    threwEmpty !== null);
}

// ---------------------------------------------------------------------------
// A descriptor whose body has gone
// ---------------------------------------------------------------------------

async function aDescriptorWithNoBodyIsClearedRatherThanRetried(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX, {
    retry: { maxAttempts: 5, backoffMs: [1000, 2000, 4000, 8000, 16000] },
  });
  await spoolOne(delivery);
  var id = onlyId(dataDir);

  // What an interrupted removal leaves behind, and what a sweep
  // overlapping an operator's cancellation produces.
  fs.rmSync(path.join(dataDir, "queue", id + ".eml"), { force: true });
  check("the descriptor is there and the message is not",
    spoolFiles(dataDir).length === 1);

  var run = await delivery.queue.runDue({ force: true });
  check("the sweep gives up on an entry whose message is gone rather than rescheduling it",
    run.results.length === 1 && run.results[0].outcome === "abandoned");
  check("and says the message is what is missing",
    /message body/i.test(String(run.results[0].error || "")));
  check("the orphaned descriptor is cleared off disk",
    spoolFiles(dataDir).length === 0);
  check("so the retry budget is not spent on a fault no attempt can clear",
    descriptorOrNull(dataDir, id) === null);
}

// ---------------------------------------------------------------------------
// A removal that lands while an attempt is running
// ---------------------------------------------------------------------------

// Cancelling a message and sweeping the queue are two things an
// operator can set going at once, from the admin page and from the
// command line, and the sweep timer does the second on its own every
// minute. The attempt reads the message into memory before it asks
// anybody anything, so a removal that lands after that point finds
// nothing to stop, and the attempt then writes its descriptor back:
// the message an operator just cancelled is in the queue again, and
// stays there.
//
// The resolver here is the clock. It reports when the attempt has
// reached it and answers only when the test says so, so the removal
// happens at a known point inside the attempt rather than at a hoped
// for one.
async function aRemovalDuringAnAttemptStaysRemoved(dataDir) {
  var reached = false;
  var release = null;
  var HOLDING_MX = {
    queryMx: function () {
      reached = true;
      return new Promise(function (resolve, reject) {
        release = function () { reject(new Error("probe resolver: MX lookup unavailable")); };
      });
    },
  };

  var spooler = handleOn(dataDir, UNREACHABLE_MX);
  await spoolOne(spooler);
  var id = onlyId(dataDir);
  check("a message is waiting", id !== null);

  var delivery = handleOn(dataDir, HOLDING_MX);
  var sweeping = delivery.queue.runDue({ force: true });

  await helpers.waitUntil(function () { return reached; }, {
    timeoutMs: 5000,
    label:     "delivery spool: the attempt has reached the resolver",
  });

  var removed = await delivery.queue.remove(id,
    { reason: "cancelled during the attempt", notice: { withheld: "fixture-removal" } });
  check("the operator's removal completes while the attempt is in flight",
    removed.removed === true);
  check("and clears both files", spoolFiles(dataDir).length === 0);

  release();
  var run = await sweeping;

  check("the sweep says the entry was taken out from under it",
    run.results.length === 1 && run.results[0].outcome === "removed");
  check("the cancelled message does not come back",
    spoolFiles(dataDir).length === 0);
}

// ---------------------------------------------------------------------------
// A body whose descriptor never arrived
// ---------------------------------------------------------------------------

// The inverse of the case above, and the one nothing was looking for.
//
// A spooled recipient is two files written one after the other: the
// message first, then the descriptor that names it. Every listing this
// module offers enumerates descriptors, so a body whose descriptor never
// arrived is in no listing, has no id an operator can read, and is
// reachable by no verb. The ceiling is the one thing that does see it:
// the room left in the spool is measured off the volume, and it weighs
// every file. So the bytes are spent and the queue reads as empty, and
// enough of them refuses mail for forwarding with nothing on screen to
// explain it.
//
// The body here is planted rather than produced by an interrupted write,
// because what is being pinned is the state, not the way in. The vector
// below produces the same state through the write itself.
var ORPHAN_ID    = "0f1e2d3c4b5a69788796a5b4";
var ORPHAN_BYTES = 60000;

// Older than the settle window by a clear margin, so a filesystem whose
// timestamp resolution is coarse cannot land the file back inside it.
var WELL_SETTLED_MS = blamepost.mail.delivery.SPOOL_SETTLE_MS + 60000;

function plantOrphanBody(dataDir, id, bytes, ageMs) {
  var dir = path.join(dataDir, "queue");
  fs.mkdirSync(dir, { recursive: true });
  var target = path.join(dir, id + ".eml");
  fs.writeFileSync(target, Buffer.alloc(bytes, 0x61), { mode: 0o600 });
  if (ageMs > 0) {
    var when = new Date(Date.now() - ageMs);
    fs.utimesSync(target, when, when);
  }
  return target;
}

async function aBodyWithNoDescriptorIsFoundRatherThanOnlyWeighed(dataDir) {
  // A ceiling one message wide, so the orphan alone is the difference
  // between accepting mail for forwarding and refusing it.
  var delivery = handleOn(dataDir, UNREACHABLE_MX, {
    spool: { maxMessages: 4, maxBytes: 65536 },
  });

  plantOrphanBody(dataDir, ORPHAN_ID, ORPHAN_BYTES, WELL_SETTLED_MS);

  // Nothing that enumerates descriptors can see it.
  check("a spooled body with no descriptor is in no listing",
    (await delivery.queue.list({})).length === 0);
  check("and the waiting count does not count it",
    delivery.queue.count() === 0);
  check("and nothing reads as held on its account",
    (await delivery.queue.held()).messages === 0);

  // The ceiling sees it, because the ceiling is measured off the volume.
  var room = delivery.queue.capacity();
  count("the ceiling weighs its bytes against the spool's own limit",
    room.bytes >= ORPHAN_BYTES, "bytes " + room.bytes);
  count("while counting it as no message at all",
    room.messages === 0, "messages " + room.messages);

  // Which is the whole fault: mail is refused over room that nothing on
  // screen accounts for.
  var refusal = delivery.queue.admits({
    entries: 1, bytes: 4096, origin: "inbound",
  });
  count("so mail arriving for forwarding is refused over the room it spends",
    refusal !== null && /outbound queue is holding/.test(String(refusal && refusal.message)),
    String(refusal && refusal.message).slice(0, 160));

  // What closes it: the same walk that measures the ceiling also holds
  // the bodies against the descriptors, so the room and the reason for
  // it come off one listing rather than two that can disagree.
  count("the capacity answer names how many bodies no descriptor claims",
    room.orphaned && room.orphaned.bodies === 1,
    JSON.stringify(room.orphaned));
  count("and how many bytes they are spending",
    room.orphaned && room.orphaned.bytes >= ORPHAN_BYTES,
    JSON.stringify(room.orphaned));

  var orphans = delivery.queue.orphans();
  count("and the ids are readable, so the operator has something to remove",
    orphans.length === 1 && orphans[0].id === ORPHAN_ID,
    JSON.stringify(orphans));
  count("with the size that says what removing it gets back",
    orphans.length === 1 && orphans[0].sizeBytes === ORPHAN_BYTES,
    JSON.stringify(orphans));

  // And removing it is the verb that already exists. It needs the id
  // and the reason every removal needs, and nothing else: a body with
  // no descriptor names no sender and no recipient, so there is nothing
  // further to say about it.
  await delivery.queue.remove(ORPHAN_ID,
    { reason: "clearing a body no descriptor names", notice: { withheld: "no-sender-recorded" } });
  count("removing it by id clears the file",
    spoolFiles(dataDir).length === 0, JSON.stringify(spoolFiles(dataDir)));
  check("and the room comes back",
    delivery.queue.admits({ entries: 1, bytes: 4096, origin: "inbound" }) === null);
}

// The safety half, and it is not optional. Between the body write and
// the descriptor write there is a moment where the pair is legitimately
// half on disk, and a reconciliation that reported that moment would
// send an operator to delete a message that was arriving normally. So a
// body is only held against the descriptors once it has been there
// longer than any write could still be in flight. Nothing here sleeps:
// the age is set on the file.
async function aBodyStillBeingWrittenIsNotCalledAnOrphan(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);

  plantOrphanBody(dataDir, ORPHAN_ID, 4096, 0);

  var room = delivery.queue.capacity();
  count("a body written moments ago is not yet called an orphan",
    room.orphaned && room.orphaned.bodies === 0, JSON.stringify(room.orphaned));
  check("and it is named by nothing an operator would act on",
    delivery.queue.orphans().length === 0);
  count("while its bytes still count against the ceiling, because they are on the volume",
    room.bytes >= 4096, "bytes " + room.bytes);

  // A real pair is not an orphan at any age, which is what stops the
  // check from reporting the whole queue. The planted body goes first,
  // so the only pair left is the one the spool wrote itself.
  fs.rmSync(path.join(dataDir, "queue", ORPHAN_ID + ".eml"), { force: true });
  await spoolOne(delivery);
  var paired = onlyId(dataDir);
  var when = new Date(Date.now() - WELL_SETTLED_MS);
  fs.utimesSync(path.join(dataDir, "queue", paired + ".eml"), when, when);
  count("a body that has its descriptor is never an orphan, however old",
    delivery.queue.orphans().length === 0,
    JSON.stringify(delivery.queue.orphans()));
}

// ---------------------------------------------------------------------------
// A descriptor write that fails
// ---------------------------------------------------------------------------

// The body is written first on purpose: the other order makes the
// half-written state a descriptor with nothing to send, which the sweep
// clears, and the message is gone. So the write that lands first has to
// be able to take itself back when the second one does not land.
//
// The fault is installed at `b.atomicFile.writeJson`, which is the
// framework surface this module composes for the descriptor and nothing
// else on this path. It refuses for the length of one send and is put
// back afterwards, so what runs is the shipped code path meeting a
// volume that would not take the write, rather than a branch that
// behaves differently because a test is watching. What it stands in for
// is a full disk, a revoked permission, an I/O error.
async function aBodyIsTakenBackWhenItsDescriptorCannotBeWritten(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);
  var b = helpers.b;

  var REFUSAL = "the volume would not take the descriptor";
  var real = b.atomicFile.writeJson;
  var refused = 0;
  b.atomicFile.writeJson = function () {
    refused += 1;
    return Promise.reject(new Error(REFUSAL));
  };

  var thrown = null;
  try {
    await spoolOne(delivery);
  } catch (e) {
    thrown = e;
  } finally {
    b.atomicFile.writeJson = real;
  }

  count("the descriptor write was reached and refused", refused >= 1, "refused " + refused);
  count("and the failure is surfaced rather than swallowed",
    thrown !== null && String(thrown && thrown.message).indexOf(REFUSAL) !== -1,
    String(thrown && thrown.message).slice(0, 160));
  count("the body it had already written is taken back off the volume",
    spoolFiles(dataDir).length === 0, JSON.stringify(spoolFiles(dataDir)));
  count("so nothing is left spending the ceiling that no listing can show",
    delivery.queue.capacity().bytes === 0,
    JSON.stringify(delivery.queue.capacity()));
}

// ---------------------------------------------------------------------------
// What the far side said, before it reaches an operator's screen
// ---------------------------------------------------------------------------

async function aPeersWordsAreKeptAsTheyArrived(dataDir) {
  var delivery = handleOn(dataDir, HOSTILE_MX);

  var outcome = await spoolOne(delivery);
  check("the recipient is deferred with the peer's answer", outcome.deferred.length === 1);

  var id = onlyId(dataDir);
  var stored = String(readDescriptor(dataDir, id).reason);

  check("the stored reason still says what happened",
    /try later/.test(stored));
  check("the escape sequence the peer sent is still there to be read",
    stored.indexOf(ESC) !== -1);
  check("so is the bidi override",
    BIDI_RE.test(stored));
  check("so is the null byte",
    stored.indexOf(NUL) !== -1);
  check("and the peer cannot make the descriptor unbounded",
    JSON.stringify(stored).length <= 1024);

  // The same value on the way out, which is the boundary that protects
  // the terminal. Read once here so this file cannot pass while the
  // screening it stopped doing moved nowhere.
  var listed = String((await delivery.queue.list({}))[0].reason);
  check("what an operator reads carries no escape sequence",
    listed.indexOf(ESC) === -1);
  check("no carriage return or newline to forge a second line",
    listed.indexOf("\r") === -1 && listed.indexOf("\n") === -1);
  check("no bidi override to reverse what they read",
    !BIDI_RE.test(listed));
  check("no null byte to truncate it",
    listed.indexOf(NUL) === -1);
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
    await helpers.withTestTimeout("delivery spool: an id that did not come from here is refused",
      function () { return anEntryIdThatDidNotComeFromHereIsRefused(freshDir("dlv-spool-id")); });
    await helpers.withTestTimeout("delivery spool: a descriptor with no body is cleared",
      function () { return aDescriptorWithNoBodyIsClearedRatherThanRetried(freshDir("dlv-spool-orphan")); });
    await helpers.withTestTimeout("delivery spool: a removal during an attempt stays removed",
      function () { return aRemovalDuringAnAttemptStaysRemoved(freshDir("dlv-spool-race")); });
    await helpers.withTestTimeout("delivery spool: a body with no descriptor is found",
      function () { return aBodyWithNoDescriptorIsFoundRatherThanOnlyWeighed(freshDir("dlv-spool-body")); });
    await helpers.withTestTimeout("delivery spool: a body still being written is not an orphan",
      function () { return aBodyStillBeingWrittenIsNotCalledAnOrphan(freshDir("dlv-spool-settle")); });
    await helpers.withTestTimeout("delivery spool: a body is taken back when its descriptor fails",
      function () { return aBodyIsTakenBackWhenItsDescriptorCannotBeWritten(freshDir("dlv-spool-undo")); });
    await helpers.withTestTimeout("delivery spool: a peer's words are kept as they arrived",
      function () { return aPeersWordsAreKeptAsTheyArrived(freshDir("dlv-spool-text")); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "delivery-spool", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
