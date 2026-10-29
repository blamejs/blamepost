// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * The line ceiling each wire listener enforces, measured on the wire.
 *
 * A command line that never ends is the cheapest thing a peer can send.
 * Every listener bounds it, and until this file existed blamepost passed
 * no bound to any of them, so each one ran on whatever the vendored
 * framework puts there when nobody names a number: 1024 octets for the
 * MX, submission and POP3 listeners, and 8192 for IMAP and ManageSieve.
 *
 * Those numbers were not wrong. They were unchosen, which is a different
 * property and the one that fails quietly. The operator guide publishes
 * the ceilings this server promises, and a number that lives only in the
 * framework is a promise this repository prints without owning: the two
 * agree until a refresh moves one, and nothing then says so. The same
 * reasoning is already written down for the message ceiling in
 * `lib/config/index.js`, where the table exists for exactly this reason.
 *
 * So the cases below ask two different questions, and both have to be
 * asked on a socket rather than of the configuration object:
 *
 *   - A number an operator sets reaches the listener. POP3 is configured
 *     here at 512, which is not the framework's number, so a refusal
 *     naming 512 can only come from the value this repository passed.
 *
 *   - A number nobody sets is the number this repository publishes. The
 *     ManageSieve listener is left unconfigured and the refusal has to
 *     name the value in the defaults table. If the framework moves its
 *     own default and the table does not follow, that is the case that
 *     fails, which is the whole point of writing it down.
 *
 * Run standalone: node test/layer-2-integration/listener-line-ceiling.test.js
 */

"use strict";

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var Wire        = wire.Wire;
var reservePort = wire.reservePort;
var LOOPBACK    = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var PASSWORD         = "quiet lantern bicycle 4291";

var SHUTDOWN_TIMEOUT_MS = 5000;

// Well under the framework's 1024, so a refusal naming it cannot have
// come from anywhere but the configured value.
var POP3_CEILING = 512;

var count = helpers.count;

// `bytes` octets of a command line with NO terminator, which is what
// this ceiling is for.
//
// A line that ends is bounded by its protocol's command grammar long
// before the listener's own number is reached: RFC 2449 section 4 caps a
// POP3 command at 255 octets, and `guardPop3Command.validate` refuses a
// 712 octet line naming that cap, not this one. So a terminated line
// measures the guard and says nothing about the listener. What this
// ceiling answers is the line that never ends, where there is no command
// to validate and the only bound is how many octets the connection may
// hold while it waits for a terminator that is not coming.
function unterminated(verb, bytes) {
  var padding = bytes - (verb.length + 1);
  return Buffer.from(verb + " " + "a".repeat(padding > 0 ? padding : 1), "utf8");
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

// The ceiling an operator sets is the ceiling the POP3 listener applies.
async function theConfiguredCeilingReachesThePop3Listener(port, base) {
  var session = await Wire.pop3(port, Object.assign({}, base, { label: "pop3-over" }));
  try {
    session.sendRaw(unterminated("USER", POP3_CEILING + 200), "an unterminated POP3 line");
    var refusal = await session.read(/^-ERR/m, "an overlong POP3 line is refused");
    count("POP3 refuses a line past the configured ceiling", /^-ERR/m.test(refusal));
    count("and the refusal names the number this repository configured, not the framework's",
      refusal.indexOf(String(POP3_CEILING)) !== -1 && refusal.indexOf("1024") === -1,
      refusal.trim());
  } finally {
    session.close();
  }
}

// An unterminated run that stays inside the ceiling is not refused for
// its length. Terminating it afterwards draws the command grammar's own
// refusal instead, which is a different sentence and proves the ceiling
// is a ceiling rather than a blanket over anything long.
async function aRunInsideTheCeilingIsNotRefusedForLength(port, base) {
  var session = await Wire.pop3(port, Object.assign({}, base, { label: "pop3-under" }));
  try {
    session.sendRaw(unterminated("USER", POP3_CEILING - 64), "a run inside the ceiling");
    session.sendRaw(Buffer.from("\r\n", "utf8"), "its terminator");
    var answer = await session.read(/^(\+OK|-ERR)/m, "a POP3 run inside the ceiling is answered");
    count("a POP3 run inside the ceiling is not refused for its length",
      answer.toLowerCase().indexOf("line too long") === -1, answer.trim());
  } finally {
    session.close();
  }
}

// Nobody configured ManageSieve, so the ceiling it applies is the one
// this repository publishes for it.
async function thePublishedDefaultIsWhatManageSieveEnforces(port, base) {
  var published = config.LISTENER_DEFAULTS.managesieve.maxLineBytes;
  count("the defaults table publishes a ManageSieve line ceiling",
    typeof published === "number" && published > 0, String(published));

  var session = await Wire.managesieve(port, Object.assign({}, base, { label: "sieve-over" }));
  try {
    session.sendRaw(unterminated("HAVESPACE", published + 200), "an unterminated ManageSieve line");
    var refusal = await session.read(/^NO/m, "an overlong ManageSieve line is refused");
    count("ManageSieve refuses a line past the published ceiling", /^NO/m.test(refusal));
    count("and the refusal names the published number",
      refusal.indexOf(String(published)) !== -1, refusal.trim());
  } finally {
    session.close();
  }
}

// Every listener that reads lines off a socket declares its ceiling, so
// none of them is left running on a number this repository does not
// print. The browser surface is absent from the table because it is not
// one of these listeners.
function everyWireListenerDeclaresACeiling() {
  var names = Object.keys(config.LISTENER_DEFAULTS);
  var missing = names.filter(function (name) {
    return typeof config.LISTENER_DEFAULTS[name].maxLineBytes !== "number";
  });
  count("every wire listener in the defaults table declares a line ceiling",
    missing.length === 0, "missing: " + missing.join(", "));
  count("the table still covers all six listeners", names.length === 6, names.join(", "));
}

// Config time refuses a ceiling outside the range, so an operator reads
// the mistake at boot rather than meeting it on a busy socket.
function aCeilingOutsideTheRangeIsRefusedAtLoad(root, dataDir) {
  function load(value) {
    return config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_LISTENERS:        JSON.stringify({ pop3: { maxLineBytes: value } }),
      },
      cwd: root,
    });
  }

  var tooSmall = null;
  try { load(1); } catch (e) { tooSmall = e; }
  count("a line ceiling below the range is refused at load", tooSmall !== null,
    tooSmall === null ? "accepted" : String(tooSmall.message).slice(0, 120));

  var tooLarge = null;
  try { load(b.constants.BYTES.mib(4)); } catch (e) { tooLarge = e; }
  count("a line ceiling above the range is refused at load", tooLarge !== null,
    tooLarge === null ? "accepted" : String(tooLarge.message).slice(0, 120));

  var notANumber = null;
  try { load("eight thousand"); } catch (e) { notANumber = e; }
  count("a line ceiling that is not a number is refused at load", notANumber !== null,
    notANumber === null ? "accepted" : String(notANumber.message).slice(0, 120));
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("linececiling");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var server  = null;
  var running = false;

  try {
    everyWireListenerDeclaresACeiling();
    aCeilingOutsideTheRangeIsRefusedAtLoad(root, dataDir);

    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn:           HOSTNAME,
      usage:        "server",
      sans:         [HOSTNAME, LOOPBACK],
      validityDays: 1,
    });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    await identity.accounts.create({ address: "alice@" + DOMAIN, password: PASSWORD });

    var sections = {
      mx:          { enabled: false, port: await reservePort(), address: LOOPBACK },
      submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
      submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
      imap:        { enabled: false, port: await reservePort(), address: LOOPBACK },
      // Configured well below the framework's own number, so the refusal
      // can only name a value this repository passed.
      pop3:        { enabled: true,  port: await reservePort(), address: LOOPBACK,
                     maxLineBytes: POP3_CEILING },
      // Deliberately unconfigured: this one measures the published default.
      managesieve: { enabled: true,  port: await reservePort(), address: LOOPBACK },
    };

    server = blamepost.create({
      config: Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      tlsContext:   nodeTls.createSecureContext({ cert: leaf.cert, key: leaf.key }),
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var base = { caPem: leaf.ca, servername: HOSTNAME };

    await theConfiguredCeilingReachesThePop3Listener(sections.pop3.port, base);
    await aRunInsideTheCeilingIsNotRefusedForLength(sections.pop3.port, base);
    await thePublishedDefaultIsWhatManageSieveEnforces(sections.managesieve.port, base);

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "listener-line-ceiling", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
