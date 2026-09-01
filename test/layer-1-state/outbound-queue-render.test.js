// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The queue as something an operator reads, rather than as something
 * the sweep retries.
 *
 * Two different values reach the same screen from outside this server.
 * A peer's refusal is a stranger's mail server talking. A reverse path
 * and a recipient are addresses somebody else chose. Both are printed
 * by `blamepost queue list` into a terminal and rendered onto the admin
 * queue page, and a terminal is repainted by an escape sequence, has
 * its line overwritten by a carriage return, and has its sentence
 * reversed by a bidi override.
 *
 * Where that screening belongs is the whole point of these cases.
 * Screening on the way IN mutates the record of a refusal an operator
 * may need to read exactly as it arrived, and it does nothing at all
 * for the entries already on disk when it was added. So the descriptor
 * keeps the bytes as they arrived and the read path is what is safe:
 * every value `queue.list`, `queue.show` and `queue.runDue` hand back
 * has been through the framework's text guard, whoever wrote the file
 * and whenever.
 *
 * What the descriptor keeps is still bounded, and bounded by its
 * encoded size rather than by a character count, because a reply made
 * of control characters costs six bytes each once it is written as
 * JSON. A peer that can grow a descriptor past the size its own reader
 * accepts has destroyed the message.
 *
 * Every hostile codepoint below is built with String.fromCharCode
 * rather than typed, so this file stays plain ASCII and an editor or a
 * copy cannot quietly change what the fixture tests.
 *
 * Run standalone: node test/layer-1-state/outbound-queue-render.test.js
 */

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var blamepost = require("../../lib");

var check = helpers.check;
var fs    = helpers.fs;
var path  = helpers.path;

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

var MESSAGE = "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n";

// An address whose local part carries the bytes that forge a terminal
// row. The MX listener hardens the domain of a reverse path and not its
// local part, so this is a shape that reaches the spool.
var HOSTILE_SENDER = "alice" + ESC + "[2J" + RTLO + "eciffo" + NUL + "@example.com";
var HOSTILE_RCPT   = "bob" + ESC + "[1;1H" + RTLO + "ten.elpmaxe" + "@example.net";

// A peer whose refusal carries the same shapes.
var HOSTILE_REPLY = "451 4.7.0 try later " +
                    ESC + "[2J" + ESC + "[1;1Hall clear\r\n250 Accepted " +
                    RTLO + "resu ot detrofmoc" + NUL + " done";

var HOSTILE_MX = {
  queryMx: function () { return Promise.reject(new Error(HOSTILE_REPLY)); },
};

var UNREACHABLE_MX = {
  queryMx: function () {
    return Promise.reject(new Error("probe resolver: MX lookup unavailable"));
  },
};

function handleOn(dataDir, resolver) {
  return blamepost.mail.delivery.create({
    hostname: "mx.example.com",
    dataDir:  dataDir,
    resolver: resolver,
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
  return spoolFiles(dataDir)[0].replace(/\.(json|eml)$/, "");
}

function readDescriptor(dataDir, id) {
  return JSON.parse(fs.readFileSync(path.join(dataDir, "queue", id + ".json"), "utf8"));
}

// Nothing in a value an operator reads may forge a row.
function isSafeToPrint(value) {
  var s = String(value === undefined || value === null ? "" : value);
  if (s.indexOf(ESC) !== -1) return false;
  if (s.indexOf(NUL) !== -1) return false;
  if (s.indexOf("\r") !== -1 || s.indexOf("\n") !== -1) return false;
  return !BIDI_RE.test(s);
}

// ---------------------------------------------------------------------------
// A row written by something else entirely
// ---------------------------------------------------------------------------

// The id shape the spool mints: lowercase hex, long enough that nothing
// an operator mistypes reaches a file.
var PLANTED_ID = "0123456789abcdef0123456789abcdef";

function plantDescriptor(dataDir) {
  var dir = path.join(dataDir, "queue");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, PLANTED_ID + ".eml"), MESSAGE, "utf8");
  fs.writeFileSync(path.join(dir, PLANTED_ID + ".json"), JSON.stringify({
    id:               PLANTED_ID,
    from:             HOSTILE_SENDER,
    recipient:        HOSTILE_RCPT,
    attempt:          1,
    nextAttemptAt:    Date.now() + 60000,
    reason:           HOSTILE_REPLY,
    reasonCode:       "4.7.0" + ESC + "[2J",
    requireTls:       false,
    queuedAt:         Date.now(),
    attemptsRecorded: 1,
    history:          [],
  }, null, 2), "utf8");
}

async function aRowSpooledByAnEarlierBuildIsScreenedOnTheWayOut(dataDir) {
  var delivery = handleOn(dataDir, UNREACHABLE_MX);
  plantDescriptor(dataDir);

  var rows = await delivery.queue.list({});
  check("the planted entry is listed", rows.length === 1);
  var row = rows[0];

  check("the sender it prints cannot repaint a terminal", isSafeToPrint(row.from));
  check("nor can the recipient", isSafeToPrint(row.recipient));
  check("nor can the reason the peer wrote", isSafeToPrint(row.reason));
  check("nor can the enhanced status", isSafeToPrint(row.reasonCode));
  check("and the sender is still recognizable after screening",
    String(row.from).indexOf("@example.com") !== -1);

  var shown = await delivery.queue.show(PLANTED_ID);
  check("queue.show screens the same four values",
    isSafeToPrint(shown.from) && isSafeToPrint(shown.recipient) &&
    isSafeToPrint(shown.reason) && isSafeToPrint(shown.reasonCode));
  check("and the sentence that projects how this entry ends carries no forged row",
    isSafeToPrint(shown.projection.ifItNeverSucceeds));

  var onDisk = readDescriptor(dataDir, PLANTED_ID);
  check("reading the queue changed nothing on disk",
    onDisk.from === HOSTILE_SENDER && onDisk.recipient === HOSTILE_RCPT &&
    onDisk.reason === HOSTILE_REPLY);
}

// ---------------------------------------------------------------------------
// A row this build wrote, from a live attempt
// ---------------------------------------------------------------------------

async function whatThePeerSaidIsKeptAsItArrivedAndScreenedWhenRead(dataDir) {
  var delivery = handleOn(dataDir, HOSTILE_MX);

  var outcome = await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });
  check("the recipient is deferred with the peer's answer", outcome.deferred.length === 1);

  var id = onlyId(dataDir);
  var stored = String(readDescriptor(dataDir, id).reason);
  check("the descriptor keeps the reply exactly as the peer sent it",
    stored.indexOf(ESC) !== -1 && stored.indexOf(RTLO) !== -1);
  check("and it still says what happened", /try later/.test(stored));

  var rows = await delivery.queue.list({});
  check("the listing screens it before an operator reads it",
    isSafeToPrint(rows[0].reason));
  check("and keeps the part that explains the wait",
    /try later/.test(String(rows[0].reason)));

  var shown = await delivery.queue.show(id);
  check("queue.show screens it too", isSafeToPrint(shown.reason));
  check("including every row of the attempt record",
    shown.history.length > 0 && shown.history.every(function (h) {
      return isSafeToPrint(h.reason) && isSafeToPrint(h.reasonCode);
    }));
}

async function aPeerCannotGrowADescriptorPastItsOwnReader(dataDir) {
  var runOfEscapes = "";
  for (var i = 0; i < 4096; i += 1) runOfEscapes += ESC;
  var delivery = handleOn(dataDir, {
    queryMx: function () { return Promise.reject(new Error("451 " + runOfEscapes + " later")); },
  });

  await delivery.send({
    from:   "alice@example.com",
    to:     ["bob@example.net"],
    rfc822: Buffer.from(MESSAGE, "utf8"),
  });

  var id = onlyId(dataDir);
  var stored = String(readDescriptor(dataDir, id).reason);
  check("a reply made of control characters is bounded by what it costs to store",
    JSON.stringify(stored).length <= 1024);
  check("and the entry can still be read back through the spool's own reader",
    (await delivery.queue.show(id)) !== null);
}

// ---------------------------------------------------------------------------
// The sweep reports the same values, to the same screens
// ---------------------------------------------------------------------------

async function theSweepReportsScreenedValues(dataDir) {
  var delivery = handleOn(dataDir, HOSTILE_MX);
  plantDescriptor(dataDir);

  var run = await delivery.queue.runDue({ force: true });
  check("the sweep attempted the planted entry", run.ran === 1);
  var result = run.results[0];
  check("the row it reports cannot forge a terminal line",
    isSafeToPrint(result.recipient) && isSafeToPrint(result.reason) &&
    isSafeToPrint(result.reasonCode));
}

// ---------------------------------------------------------------------------
// The terminal an operator is actually looking at
// ---------------------------------------------------------------------------

// Nothing above proves what reaches a screen, because a caller between
// the queue and the screen could still print the descriptor itself. So
// the last case spawns the real binary and reads its bytes. Newlines
// are what a listing is made of, so they are not counted here; the
// codepoints that forge a row are.
function isSafeTerminalOutput(text) {
  var s = String(text || "");
  if (s.indexOf(ESC) !== -1 || s.indexOf(NUL) !== -1) return false;
  if (s.indexOf("\r") !== -1) return false;
  return !BIDI_RE.test(s);
}

async function theCommandLinePrintsNothingThatCanForgeARow(root) {
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  plantDescriptor(dataDir);

  var cli = cliHelper.create({
    dataDir:  dataDir,
    workDir:  workDir,
    hostname: "mx.example.com",
  });

  var listed = cli(["queue", "list"]);
  cliHelper.count("the queue listing names the waiting message",
    listed.status === 0 && listed.stdout.indexOf(PLANTED_ID) !== -1,
    "exit " + listed.status);
  cliHelper.count("and nothing it writes to the terminal can forge a row",
    isSafeTerminalOutput(listed.both), JSON.stringify(listed.stdout.slice(0, 200)));

  // The machine-readable form goes to the same terminal, and JSON
  // escapes a control character while leaving a bidi override alone.
  var asJson = cli(["queue", "list", "--json"]);
  cliHelper.count("the json form is read in a terminal too, and is safe there",
    asJson.status === 0 && isSafeTerminalOutput(asJson.both),
    JSON.stringify(asJson.stdout.slice(0, 200)));
}

// ---------------------------------------------------------------------------
// Which receiver deferred it
// ---------------------------------------------------------------------------

// A deferral names a schedule and a reason, and until it also names the
// host, an operator reading the queue cannot act on it. A domain with
// several MX hosts is the ordinary case, and "deferred, retry in fifteen
// minutes" for one of them is a different situation from the same
// sentence for all of them: the first is that receiver's problem or this
// server's transport security against that receiver, the second is the
// domain. The reason text rarely says, because it is the peer's words.
//
// The host reaches the descriptor on the attempt row, so this plants one
// and reads it back out through the binary an operator runs.
var DEFERRING_HOST = "mx2.example.net";

function plantDescriptorWithAttempt(dataDir) {
  var dir = path.join(dataDir, "queue");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, PLANTED_ID + ".eml"), MESSAGE, "utf8");
  fs.writeFileSync(path.join(dir, PLANTED_ID + ".json"), JSON.stringify({
    id:               PLANTED_ID,
    from:             "alice@example.com",
    recipient:        "bob@example.net",
    attempt:          1,
    nextAttemptAt:    Date.now() + 60000,
    reason:           "451 4.3.2 try again later",
    reasonCode:       "4.3.2",
    requireTls:       false,
    queuedAt:         Date.now(),
    attemptsRecorded: 1,
    history:          [{
      at:         Date.now(),
      outcome:    "waiting",
      recipient:  "bob@example.net",
      mxHost:     DEFERRING_HOST,
      reason:     "451 4.3.2 try again later",
      reasonCode: "4.3.2",
      requireTls: false,
      held:       false,
    }],
  }, null, 2), "utf8");
}

async function theQueueNamesTheReceiverThatDeferred(root) {
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  plantDescriptorWithAttempt(dataDir);

  var delivery = handleOn(dataDir, UNREACHABLE_MX);
  var rows = await delivery.queue.list({});
  check("the entry carries the host its last attempt reached",
    rows.length === 1 && rows[0].lastAttempt !== null &&
    rows[0].lastAttempt.mxHost === DEFERRING_HOST);

  var cli = cliHelper.create({
    dataDir:  dataDir,
    workDir:  workDir,
    hostname: "mx.example.com",
  });

  var listed = cli(["queue", "list"]);
  cliHelper.count("the listing an operator reads names the receiver that deferred it",
    listed.status === 0 && listed.stdout.indexOf(DEFERRING_HOST) !== -1,
    "exit " + listed.status + " " + JSON.stringify(listed.stdout.slice(0, 300)));

  // The machine-readable form is the same rows, so it carries the host
  // whether or not the human listing prints it. Asserting only on that
  // one would pass over an operator who cannot see it.
  var asJson = cli(["queue", "list", "--json"]);
  cliHelper.count("and the machine-readable form carries it on the attempt row",
    asJson.status === 0 && asJson.stdout.indexOf(DEFERRING_HOST) !== -1,
    "exit " + asJson.status + " " + JSON.stringify(asJson.stdout.slice(0, 300)));

  // A host name arrives from DNS, so it is a value from outside this
  // server and prints under the same rule as the peer's words.
  cliHelper.count("and the host name cannot forge a row either",
    isSafeTerminalOutput(listed.both) && isSafeTerminalOutput(asJson.both),
    JSON.stringify(listed.stdout.slice(0, 200)));
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A message body no descriptor names
// ---------------------------------------------------------------------------

// The screen an operator is on when the queue reads as empty and mail is
// being refused anyway.
//
// A waiting recipient is two files, the message and the descriptor that
// names it, written in that order so an interrupted write leaves a
// message nobody has to send yet rather than a descriptor with nothing
// behind it. What that leaves is a message with no descriptor, and every
// listing here reads descriptors, so it appears in none of them. The
// ceiling is measured off the volume and weighs it regardless.
//
// So the listing says so at the bottom, and names the id, because
// clearing one takes an id and nothing else could supply it.
var STRANDED_ID = "fedcba9876543210fedcba98";

function plantStrandedBody(dataDir) {
  var dir = path.join(dataDir, "queue");
  fs.mkdirSync(dir, { recursive: true });
  var target = path.join(dir, STRANDED_ID + ".eml");
  fs.writeFileSync(target,
    "From: alice@example.com\r\nTo: bob@example.net\r\n\r\nbody\r\n", { mode: 0o600 });
  // Past the window in which the descriptor write could still be in
  // flight, so this is a stranded message rather than an arriving one.
  // The age is set on the file; nothing here sleeps.
  var when = new Date(Date.now() - (blamepost.mail.delivery.SPOOL_SETTLE_MS + 60000));
  fs.utimesSync(target, when, when);
  return target;
}

async function theListingNamesAMessageNoDescriptorClaims(root) {
  var dataDir = path.join(root, "data");
  var workDir = path.join(root, "work");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  plantStrandedBody(dataDir);

  var cli = cliHelper.create({
    dataDir:  dataDir,
    workDir:  workDir,
    hostname: "mx.example.com",
  });

  var listed = cli(["queue", "list"]);
  cliHelper.count("the listing succeeds with nothing waiting",
    listed.status === 0, "exit " + listed.status + " " + listed.both.slice(0, 160));
  cliHelper.count("and says a message body here has no descriptor",
    /no descriptor/.test(listed.stdout), listed.stdout.slice(0, 400));
  cliHelper.count("and names it, because clearing one takes an id",
    listed.stdout.indexOf(STRANDED_ID) !== -1, listed.stdout.slice(0, 400));
  cliHelper.count("and says which verb clears it",
    /queue remove/.test(listed.stdout), listed.stdout.slice(0, 400));

  var removed = cli(["queue", "remove", STRANDED_ID, "--reason", "stranded body, no descriptor"]);
  cliHelper.count("that verb takes it off the volume",
    removed.status === 0, "exit " + removed.status + " " + removed.both.slice(0, 160));
  cliHelper.count("and the listing stops reporting it",
    cli(["queue", "list"]).stdout.indexOf(STRANDED_ID) === -1,
    cli(["queue", "list"]).stdout.slice(0, 300));
}

async function run() {
  var dirs = [];
  function freshDir(prefix) {
    var d = helpers.tempDir(prefix);
    dirs.push(d);
    return d;
  }
  try {
    await helpers.withTestTimeout("outbound queue: an entry spooled earlier is screened on the way out",
      function () { return aRowSpooledByAnEarlierBuildIsScreenedOnTheWayOut(freshDir("out-q-planted")); });
    await helpers.withTestTimeout("outbound queue: a peer's words are kept as sent and screened when read",
      function () { return whatThePeerSaidIsKeptAsItArrivedAndScreenedWhenRead(freshDir("out-q-verbatim")); });
    await helpers.withTestTimeout("outbound queue: a peer cannot grow a descriptor past its own reader",
      function () { return aPeerCannotGrowADescriptorPastItsOwnReader(freshDir("out-q-bound")); });
    await helpers.withTestTimeout("outbound queue: the sweep reports screened values",
      function () { return theSweepReportsScreenedValues(freshDir("out-q-sweep")); });
    await helpers.withTestTimeout("outbound queue: the command line prints nothing that can forge a row",
      function () { return theCommandLinePrintsNothingThatCanForgeARow(freshDir("out-q-cli")); });
    await helpers.withTestTimeout("outbound queue: the listing names the receiver that deferred",
      function () { return theQueueNamesTheReceiverThatDeferred(freshDir("out-q-mxhost")); });
    await helpers.withTestTimeout("outbound queue: the listing names a body no descriptor claims",
      function () { return theListingNamesAMessageNoDescriptorClaims(freshDir("out-q-stranded")); });
    return helpers.getChecks();
  } finally {
    for (var i = 0; i < dirs.length; i += 1) helpers.removeTempDir(dirs[i]);
  }
}

module.exports = { name: "outbound-queue-render", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
