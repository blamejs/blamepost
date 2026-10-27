// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The audit chain's anchor, held against a server that is killed rather
 * than stopped.
 *
 * `audit-chain-tamper.test.js` proves what the record beside the volume
 * catches: a trail rewritten in full, with its checkpoints deleted rather
 * than forged, is refused because the counter and the row hash recorded
 * outside the database no longer agree with the rows inside it. Every one
 * of those cases starts from a volume that was anchored, and the
 * guarantee is worth exactly as much as the anchoring is recent.
 *
 * That is what this file is about. The framework anchors the chain when
 * the volume is opened, so the record names the trail as it stood when
 * the server STARTED, and an ordered shutdown anchors it again on the way
 * out. Between those two moments there is one case left, and it is the
 * way servers actually stop: the process is killed. An out of memory
 * kill, a host reboot, a container killed rather than signaled, a power
 * loss. None of those runs a shutdown phase, so a server up for a month
 * would leave a month of rows past the last anchored counter, and every
 * one of them can be rewritten on the stopped volume with the record
 * beside it still agreeing. That is the same rewrite the tamper cases
 * refuse, reachable without any of the skill they need.
 *
 * So the server has to anchor the trail while it runs, and this file
 * drives it: a real assembled server in a child of its own, real
 * accounts created after the boot so there are rows the boot's anchoring
 * cannot cover, and then a kill with no signal handler in front of it.
 * What is asserted is the counter in the record on disk, read before
 * anything opens the volume again, because opening it anchors the chain
 * afresh and destroys the reading.
 *
 * The interval is an argument rather than a wait. A case that slept for
 * the shipped interval would be a case that passes when the runner is
 * quiet, and the condition here is observable, so it is polled.
 *
 * Two more properties are pinned because getting either wrong is worse
 * than the hole being closed. A killed server must still leave a volume
 * the operator's own verb reads as intact, since an anchor written ahead
 * of the rows it names would refuse every boot after an ordinary crash.
 * And the timer must come down with the server: one that outlived a stop
 * would fire against a store that has already closed, or race the
 * shutdown's own anchoring for the same tip.
 *
 * Run standalone: node test/layer-1-state/audit-anchor-while-running.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeProc = require("node:child_process");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var certs     = require("../helpers/certs");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// The rollback detection record the framework writes beside the database
// every time it anchors the chain. It carries the counter and the row
// hash at that anchoring, in plaintext, outside the encrypted database
// the rows live in, which is what makes it the witness a rewrite has to
// get past.
var ANCHOR_FILE = "audit.tip";

// The interval the server under test anchors on. Small so the condition
// is reached in a poll or two rather than by waiting out a shipped
// interval, and passed to the child rather than read from the shipped
// default, so this file measures the mechanism and the check below
// measures the default.
var TEST_ANCHOR_MS = 300;

// How long the anchor is given to move. Far above the interval above,
// because the failure this file exists to catch is an anchor that never
// moves at all rather than one that moved late on a loaded runner.
var ANCHOR_WAIT_MS = 20000;

// How long a spawned server is given to bind every listener and open its
// volume. A first boot generates a vault keypair, an audit signing
// keypair and a certificate, all of which are slow on purpose.
var CHILD_READY_MS = 90000;

// How long the killed process is given to disappear.
var CHILD_EXIT_MS = 15000;

// The listeners the child binds. POP3 is left off because it is off by
// default and this file is not about the listener set; the ones here are
// enough that the server under test is the assembled one rather than a
// facade with nothing behind it.
var LISTENER_NAMES = ["mx", "submission", "submissions", "imap", "managesieve"];

// The line the child writes once it is serving, carrying the two
// counters the parent has to compare.
var RUNNING_LINE_RE = /^RUNNING (.+)$/m;

// ---- reading the record on disk ---------------------------------------------

// The counter the volume's record currently names, or null when there is
// no readable record there.
//
// Read as a plain file rather than through the store, because opening the
// store is the thing that overwrites it. A partial read reads as absent
// and the next poll re-reads: the framework writes this through an atomic
// rename, so a torn read is a moment rather than a state.
function anchorCounter(dataDir) {
  var raw;
  try { raw = nodeFs.readFileSync(nodePath.join(dataDir, ANCHOR_FILE), "utf8"); }
  catch (_e) { return null; }
  var parsed;
  try { parsed = JSON.parse(String(raw)); }
  catch (_e2) { return null; }
  var counter = Number(parsed && parsed.atMonotonicCounter);
  return isFinite(counter) && counter > 0 ? counter : null;
}

// How far the trail itself has reached, read from the framework's own
// chain table. The parent cannot ask this question, because the volume is
// held by the child, so the child answers it once and reports the number.
function trailCounter() {
  var row = b.db.prepare("SELECT MAX(monotonicCounter) AS c FROM audit_log").get();
  return Number(row && row.c) || 0;
}

// ---- the server, in a child of this file ------------------------------------

// The configuration a child builds, from a certificate written where the
// volume already keeps one.
async function childConfig(dataDir) {
  var certificate = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
  return config.load({
    env: {
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      BLAMEPOST_TLS_CERT:         certificate.certFile,
      BLAMEPOST_TLS_KEY:          certificate.keyFile,
    },
    cwd: dataDir,
  });
}

// A volume as an earlier run leaves it: a hosted domain, a trail with
// rows in it, and a record beside it naming where that trail ended.
//
// It has to be a separate run, because a first boot opens an EMPTY chain
// and there is nothing to anchor, so the record is not written at all. A
// server started on a fresh volume therefore has no counter to advance
// past, which is a starker version of the same hole and not the one this
// file is measuring. The ordered flush, anchor and flush here is the
// shutdown the command line runs, so what this leaves behind is what a
// cleanly stopped server leaves behind.
async function seedChild(dataDir, workDir) {
  process.env.BLAMEJS_TMPDIR = workDir;
  var identity = await store.open(await childConfig(dataDir));
  try {
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });
    await b.audit.flush();
    await b.audit.checkpoint({ skipIfUnchanged: true });
    await b.audit.flush();
  } finally { identity.close(); }
}

// One assembled server, built and started the way the serve verb builds
// and starts it, then left running until somebody kills it.
//
// It has to be a child. The framework holds the vault, the database and
// the audit counter as process state, so one process opens one volume for
// its whole life, and the kill this file is about has to be a real kill
// of a real process rather than a stop called on a handle.
async function serveChild(dataDir, workDir, anchorMs) {
  process.env.BLAMEJS_TMPDIR = workDir;

  var cfg = await childConfig(dataDir);
  var identity = await store.open(cfg);

  var sections = {};
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    sections[LISTENER_NAMES[i]] = {
      enabled: true,
      port:    await wire.reservePort(),
      address: "127.0.0.1",
    };
  }
  var runtimeConfig = Object.assign({}, cfg, {
    httpPort:  0,
    httpsPort: 0,
    listeners: sections,
  });

  var server = blamepost.create({
    config:        runtimeConfig,
    store:         identity,
    mailStore:     identity.mailbox,
    messageStore:  identity.messageStore,
    auditAnchorMs: anchorMs,
  });
  await server.start();

  // What the boot left behind, read before this process writes anything
  // else. Everything after this line is a row the boot's anchoring cannot
  // account for.
  var atBoot = anchorCounter(dataDir);

  // Real work, so the rows are the ones a running server actually writes
  // rather than events invented for the occasion. Creating an account
  // records the act, which is the shape of every row an incident asks
  // about.
  await identity.accounts.create({
    address: "alice@" + DOMAIN, password: ACCOUNT_PASSWORD,
  });
  await identity.accounts.create({
    address: "bob@" + DOMAIN, password: ACCOUNT_PASSWORD,
  });
  await b.audit.flush();

  process.stdout.write("RUNNING " + JSON.stringify({
    atBoot: atBoot,
    trail:  trailCounter(),
  }) + "\n");

  // Nothing else. The listeners hold the event loop open, and the parent
  // ends this process with a kill rather than letting it return.
}

// ---- the harness ------------------------------------------------------------

// A running server and the handful of questions the parent asks about it.
function spawnServer(dataDir, workDir, anchorMs) {
  var child = nodeProc.spawn(process.execPath,
    [__filename, "--serve", dataDir, workDir, String(anchorMs)],
    { stdio: ["ignore", "pipe", "pipe"], env: process.env });

  var captured = "";
  var running  = null;
  var exited   = false;

  function read(chunk) {
    captured += chunk.toString();
    if (running !== null) return;
    var found = RUNNING_LINE_RE.exec(captured);
    if (found === null) return;
    try { running = JSON.parse(found[1]); }
    catch (_e) { running = null; }
  }
  child.stdout.on("data", read);
  child.stderr.on("data", read);
  child.on("exit", function () { exited = true; });
  child.on("error", function (err) {
    exited = true;
    captured += String((err && err.stack) || err);
  });

  return {
    running: function () { return running; },
    exited:  function () { return exited; },
    text:    function () { return cliHelper.withoutBootLines(captured); },
    kill:    function () {
      try { child.kill("SIGKILL"); }
      catch (_e) { /* drop-silent by design: the exit poll below is the verdict */ }
    },
  };
}

// ---- what a killed server leaves behind -------------------------------------

async function aKilledServerLeavesAnAnchoredTrail(root) {
  var dataDir = nodePath.join(root, "killed", "data");
  var workDir = nodePath.join(root, "killed", "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var seeded = nodeProc.spawnSync(process.execPath, [__filename, "--seed", dataDir, workDir],
    { encoding: "utf8" });
  count("a volume an earlier run left behind opens and anchors",
    seeded.status === 0 && anchorCounter(dataDir) !== null,
    "exit " + seeded.status + " " +
    cliHelper.withoutBootLines(String(seeded.stderr || seeded.stdout || ""))
      .replace(/\s+/g, " ").slice(0, 400));
  if (seeded.status !== 0) return;

  var runner = spawnServer(dataDir, workDir, TEST_ANCHOR_MS);
  try {
    await helpers.waitUntil(function () {
      return runner.running() !== null || runner.exited();
    }, {
      timeoutMs: CHILD_READY_MS,
      label:     "audit-anchor-while-running: the child server comes up and reports its counters",
    });
    count("a server is assembled, started and left running",
      runner.running() !== null, runner.text().slice(-500));
    if (runner.running() === null) return;

    var atBoot = runner.running().atBoot;
    var trail  = runner.running().trail;
    count("the boot anchored the trail, so there is a counter to advance past",
      typeof atBoot === "number" && atBoot > 0, "boot anchor " + atBoot);
    count("and work done after the boot carried the trail past it",
      typeof trail === "number" && trail > atBoot,
      "boot anchor " + atBoot + ", trail at " + trail);

    // The claim. Nothing is stopping this server and nothing is
    // signaling it, so an anchor that moves here moved because the
    // server anchored its own trail while it ran. The wait is for the
    // anchor to reach the trail, which is what the second check below
    // reads: an anchor can pass the boot counter on one tick and reach
    // the trail on a later one, and a slow host shows the gap.
    var advanced = null;
    try {
      advanced = await helpers.waitUntil(function () {
        if (runner.exited()) throw new Error("the server exited before the anchor moved");
        var now = anchorCounter(dataDir);
        return (now !== null && now > atBoot && now >= trail) ? now : false;
      }, {
        timeoutMs: ANCHOR_WAIT_MS,
        label:     "audit-anchor-while-running: the anchor reaches the trail the server wrote",
      });
    } catch (_e) { advanced = null; }

    count("the anchor advances while the server runs, with nothing stopping it",
      advanced !== null,
      "boot anchor " + atBoot + ", anchor now " + anchorCounter(dataDir) + "; " +
      runner.text().slice(-300));

    count("and it reaches the rows written after the boot, which is what makes them " +
      "answerable for",
      advanced !== null && advanced >= trail,
      "trail reached " + trail + ", anchor reached " + advanced);

    // The kill. No signal handler runs, no shutdown phase runs, and
    // nothing gets to write a final checkpoint.
    runner.kill();
    await helpers.waitUntil(function () { return runner.exited(); }, {
      timeoutMs: CHILD_EXIT_MS,
      label:     "audit-anchor-while-running: the killed server disappears",
    });

    var afterKill = anchorCounter(dataDir);
    count("the record survives the kill, so the trail the server anchored is still " +
      "held against something outside the database",
      afterKill !== null && advanced !== null && afterKill >= advanced,
      "anchor before the kill " + advanced + ", after " + afterKill);

    // The other direction, and the one that would be worse than the hole:
    // an anchor written ahead of the rows it names refuses every boot
    // after an ordinary crash, which turns a crash into a volume that
    // never opens. This is the first thing to open the volume since the
    // kill, so it is also the first chance for that to show.
    var cli = cliHelper.create({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    });
    var verdict = cli(["audit", "verify-chain"]);
    count("and the volume a killed server left still reads as intact to the operator's " +
      "own verb", verdict.status === 0, "exit " + verdict.status + " " +
      verdict.both.replace(/\s+/g, " ").slice(0, 400));
  } finally {
    runner.kill();
  }
}

// ---- the timer's own lifecycle ----------------------------------------------

// Built and started in this process, because the questions here are about
// the handle rather than about a volume somebody else holds.
async function theTimerComesDownWithTheServer(root) {
  var dataDir = nodePath.join(root, "lifecycle", "data");
  var workDir = nodePath.join(root, "lifecycle", "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;
  try {
    var certificate = await certs.writePair(nodePath.join(dataDir, "tls"), { hostname: HOSTNAME });
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
        BLAMEPOST_TLS_CERT:         certificate.certFile,
        BLAMEPOST_TLS_KEY:          certificate.keyFile,
      },
      cwd: dataDir,
    });
    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.acknowledgeDns({
      domain: DOMAIN, acknowledgedBy: "operator@" + DOMAIN,
    });

    var sections = {};
    for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
      sections[LISTENER_NAMES[i]] = {
        enabled: true,
        port:    await wire.reservePort(),
        address: "127.0.0.1",
      };
    }
    var runtimeConfig = Object.assign({}, cfg, {
      httpPort:  0,
      httpsPort: 0,
      listeners: sections,
    });

    // The shipped interval, on a server nobody told otherwise. It is a
    // measured trade rather than a round number, so a change to it is a
    // change to the window this server leaves and has to be a deliberate
    // one.
    var shipped = blamepost.create({
      config:       runtimeConfig,
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
    });
    count("a server nobody configures anchors its trail once an hour",
      shipped.describe().audit.anchorIntervalMs === b.constants.TIME.hours(1),
      String(shipped.describe().audit.anchorIntervalMs));
    count("and it is not anchoring before anything has started",
      shipped.describe().audit.anchoring === false,
      JSON.stringify(shipped.describe().audit));

    // An interval that is not a usable one is refused where the operator
    // finds out at boot rather than at the moment the window turns out to
    // be the whole uptime.
    var refusals = [0, -1, "hourly", NaN, Infinity, b.constants.TIME.days(2)];
    var refused = refusals.every(function (value) {
      try {
        blamepost.create({
          config:        runtimeConfig,
          store:         identity,
          mailStore:     identity.mailbox,
          messageStore:  identity.messageStore,
          auditAnchorMs: value,
        });
        return false;
      } catch (_e) { return true; }
    });
    count("an anchoring interval outside the usable range is refused at assembly",
      refused, JSON.stringify(refusals));

    server = blamepost.create({
      config:        runtimeConfig,
      store:         identity,
      mailStore:     identity.mailbox,
      messageStore:  identity.messageStore,
      auditAnchorMs: TEST_ANCHOR_MS,
    });
    await server.start();
    running = true;

    count("a started server is anchoring", server.describe().audit.anchoring === true,
      JSON.stringify(server.describe().audit));

    var anchored = null;
    try {
      anchored = await helpers.waitUntil(function () {
        var seen = server.describe().audit.anchoredCounter;
        return typeof seen === "number" && seen > 0 ? seen : false;
      }, {
        timeoutMs: ANCHOR_WAIT_MS,
        label:     "audit-anchor-while-running: the armed timer anchors the trail",
      });
    } catch (_e) { anchored = null; }
    count("and the timer it armed anchors the trail on its own",
      anchored !== null, JSON.stringify(server.describe().audit));

    await server.stop({ timeoutMs: 8000 });
    running = false;
    count("stopping the server disarms it", server.describe().audit.anchoring === false,
      JSON.stringify(server.describe().audit));

    // The absence, over several intervals. A timer that survived a stop
    // fires against a store the command line closes immediately after,
    // and races the shutdown's own anchoring for the same tip. There is
    // no condition to poll for a thing that must not happen.
    var atStop = server.describe().audit.anchoredCounter;
    await helpers.passiveObserve(TEST_ANCHOR_MS * 4,
      "audit-anchor-while-running: nothing anchors after the server stopped");
    count("and nothing anchors after it, so the timer cannot outlive the volume",
      server.describe().audit.anchoredCounter === atStop,
      "anchored at stop " + atStop + ", now " + server.describe().audit.anchoredCounter);
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: 8000 }); }
      catch (_e) { /* drop-silent by design: cleanup must not mask a failure */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
  }
}

// ---- the run ----------------------------------------------------------------

async function run() {
  var root = helpers.tempDir("audit-anchor-while-running");
  try {
    // The killed server first, while this process holds no volume of its
    // own: the child needs the whole of its own data directory and this
    // process must not have opened one when the checks below open theirs.
    await aKilledServerLeavesAnAnchoredTrail(root);
    await theTimerComesDownWithTheServer(root);
    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "audit-anchor-while-running",
  run:       run,
  getChecks: helpers.getChecks,
};

// A child carrying `--seed` is this file leaving a volume as an earlier
// run would, and one carrying `--serve` is this file running the server
// the checks above kill. Anything else is the orchestrator.
function _childFailed(err) {
  console.error(helpers.formatErr(err));
  process.exit(1);
}

if (require.main === module) {
  if (process.argv[2] === "--seed") {
    seedChild(process.argv[3], process.argv[4]).catch(_childFailed);
  } else if (process.argv[2] === "--serve") {
    serveChild(process.argv[3], process.argv[4], Number(process.argv[5])).catch(_childFailed);
  } else {
    // The orchestrator parses `CHECKS <n>` out of this file's stdout.
    run().then(function (total) {
      console.log("CHECKS " + total);
    }).catch(function (e) {
      console.error(helpers.formatErr(e));
      process.exitCode = 1;
    });
  }
}
