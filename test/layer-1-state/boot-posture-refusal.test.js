// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The boot that refuses, one loosened posture at a time.
 *
 * A server can be configured correctly and still be deployed wrong: the
 * vault left in its unprotected mode, the database written in the clear,
 * the audit signing key on disk unsealed, the clock left unchecked, the
 * transport minimum lowered back to a version with no forward secrecy
 * guarantee, the data directory readable by everyone on the host, or the
 * process started with the runtime environment a developer uses. Every
 * one of those is silent: the server comes up, answers, and delivers
 * mail, and nothing says the guarantees underneath it are not the ones
 * the operator was promised.
 *
 * `blamepost.productionPosture` is the list of those predicates and
 * `start` asserts it before the first listener binds. This file drives
 * each predicate on its own and asserts the BOOT REFUSES, naming the
 * predicate that refused. An advertised guarantee with no test that
 * omitting it fails correctly is a guarantee nobody has checked.
 *
 * Each case runs in its own process, because these indicators are
 * process-wide: the vault mode, the database at-rest mode and the
 * audit-signing mode are decided once per process and cannot be put back
 * afterwards. A child per case is the only way each one starts from a
 * clean posture rather than from the wreckage of the case before it.
 *
 * Two cases carry a note.
 *
 *   - The data directory permission check is POSIX-only in the framework
 *     and skips itself on Windows, so this file skips it there too and
 *     says so rather than reporting a pass it did not earn.
 *   - The Node floor cannot be loosened from inside a running process:
 *     `process.versions` is not writable. What is asserted instead is
 *     that the floor the posture carries is the floor `package.json`
 *     declares, which is the drift that would otherwise be invisible.
 *
 * The DNS acknowledgement gate is this server's own rather than the
 * framework's, and it is asserted here too: composing a production
 * posture assertion must not quietly replace the gate that keeps the MX
 * listener from binding before the records exist.
 *
 * Run standalone: node test/layer-1-state/boot-posture-refusal.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var nodeProc = require("node:child_process");
var nodeTls  = require("node:tls");

var helpers   = require("../helpers");
var cli       = require("../helpers/cli");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");
var pkg       = require("../../package.json");

var skip  = helpers.skip;

var reservePort = wire.reservePort;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var HOSTNAME = "mx.example.com";
var LOOPBACK = "127.0.0.1";

var SHUTDOWN_TIMEOUT_MS = 5000;

// A child that neither started nor refused inside this budget is a
// harness fault rather than a verdict, and the failure should say so.
var CHILD_TIMEOUT_MS = 120000;

// The framework's boot lines are stripped before anything is asserted,
// so a log line cannot satisfy a check about what the boot said. This
// file is the one that most needs it, because what it asserts IS boot
// output. The filter is the shared one rather than a copy.
var withoutBootLines = cli.withoutBootLines;

var count = helpers.count;

// ---- the child -------------------------------------------------------------

// One case, in a process of its own. `loosen` runs before the store is
// opened, which is where a process-wide indicator has to be set for the
// boot to read it.
var CASES = {
  // The control. Nothing is loosened, so the boot has to reach the
  // listeners: a refusal here would mean the assertion refuses a posture
  // this server ships, which is worse than not asserting at all.
  clean: {
    expect: "STARTED",
    loosen: function () { /* the shipped posture, untouched */ },
  },
  ntp: {
    expect: "security/ntp-strict-disabled",
    loosen: function () { process.env.BLAMEJS_NTP_STRICT = "0"; },
  },
  "node-env": {
    expect: "security/node-env-forbidden",
    loosen: function () { process.env.NODE_ENV = "development"; },
  },
  "tls-min": {
    expect: "security/tls-min-version",
    // The framework raises the process-wide floor to TLS 1.3 when it is
    // required. Putting it back is exactly what a dependency or an
    // operator flag can do, and it is invisible from every other angle.
    loosen: function () { nodeTls.DEFAULT_MIN_VERSION = "TLSv1.2"; },
  },
  vault: {
    expect: "security/vault-mismatch",
    // The store opens the vault in its sealed mode only when nothing has
    // opened it yet, so a caller that got there first decides the mode
    // for the whole process.
    loosen: async function (ctx) {
      config.ensureDataDirectories(ctx.cfg);
      await b.vault.init({ dataDir: ctx.cfg.paths.dataDir, mode: "plaintext" });
    },
  },
  "audit-signing": {
    expect: "security/auditSigning-mismatch",
    loosen: async function (ctx) {
      config.ensureDataDirectories(ctx.cfg);
      await b.auditSign.init({ dataDir: ctx.cfg.paths.dataDir, mode: "plaintext" });
    },
  },
  "db-at-rest": {
    expect: "security/dbAtRest-mismatch",
    loosen: async function (ctx) {
      var tables  = require("../../lib/store/tables");
      var mailbox = require("../../lib/mail/mailbox");
      config.ensureDataDirectories(ctx.cfg);
      process.env.BLAMEJS_VAULT_PASSPHRASE = VAULT_PASSPHRASE;
      process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = VAULT_PASSPHRASE;
      await b.vault.init({ dataDir: ctx.cfg.paths.dataDir, mode: "wrapped" });
      await b.db.init({
        dataDir: ctx.cfg.paths.dataDir,
        atRest:  "plain",
        schema:  tables.TABLES.concat(mailbox.TABLES),
      });
    },
  },
  datadir: {
    expect: "security/datadir-permissions",
    // After the store has created the tree, because the mode this check
    // reads is the one on disk at boot rather than the one the creating
    // call asked for. A bind-mounted volume is the case that matters and
    // it arrives with whatever mode the host gave it.
    after: function (ctx) { nodeFs.chmodSync(ctx.cfg.paths.dataDir, 0o777); },
  },
  dns: {
    // This server's own gate rather than the framework's, and it has to
    // survive the production posture assertion landing in front of it.
    expect: "BLAMEPOST_DNS_ACKNOWLEDGED",
    mx:     true,
  },
};

async function runChild(caseName, root) {
  var entry = CASES[caseName];
  if (!entry) throw new Error("boot-posture: no case named " + JSON.stringify(caseName));

  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  process.env.BLAMEJS_TMPDIR = workDir;

  var env = {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
  if (!entry.mx) env.BLAMEPOST_DNS_ACKNOWLEDGED = "1";
  var cfg = config.load({ env: env, cwd: root });

  var ctx = { cfg: cfg, dataDir: dataDir };
  if (entry.loosen) await entry.loosen(ctx);

  var identity = await store.open(cfg);
  if (entry.after) entry.after(ctx);

  var sections = {
    mx:          { enabled: entry.mx === true, port: await reservePort(), address: LOOPBACK },
    submission:  { enabled: false, port: await reservePort(), address: LOOPBACK },
    submissions: { enabled: false, port: await reservePort(), address: LOOPBACK },
    imap:        { enabled: true,  port: await reservePort(), address: LOOPBACK },
    pop3:        { enabled: false, port: await reservePort(), address: LOOPBACK },
    managesieve: { enabled: false, port: await reservePort(), address: LOOPBACK },
  };

  var certPem = nodeFs.readFileSync(nodePath.join(root, "..", "leaf.crt"), "utf8");
  var keyPem  = nodeFs.readFileSync(nodePath.join(root, "..", "leaf.key"), "utf8");

  var server = blamepost.create({
    config:       Object.assign({}, cfg, { httpPort: 0, listeners: sections }),
    store:        identity,
    mailStore:    identity.mailbox,
    messageStore: identity.messageStore,
    tlsContext:   nodeTls.createSecureContext({ cert: certPem, key: keyPem }),
    httpAddress:  LOOPBACK,
  });

  try {
    await server.start();
  } catch (err) {
    process.stdout.write("RESULT REFUSED " +
      String((err && err.message) || err).replace(/[\r\n]+/g, " ") + "\n");
    try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
    catch (_e) { /* drop-silent by design: nothing bound */ }
    if (store.isOpen()) store.close();
    return;
  }
  process.stdout.write("RESULT STARTED\n");
  await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
  if (store.isOpen()) store.close();
}

// ---- the parent ------------------------------------------------------------

function spawnCase(caseName, root) {
  var result = nodeProc.spawnSync(process.execPath,
    [__filename, "--posture-child", caseName, root], {
      encoding: "utf8",
      timeout:  CHILD_TIMEOUT_MS,
      cwd:      helpers.REPO_ROOT,
      env:      Object.assign({}, process.env, {
        // The parent's own working-copy directory must not be inherited:
        // two processes decrypting one database file is not the shape
        // under test.
        BLAMEJS_TMPDIR: nodePath.join(root, "work"),
        NODE_ENV:       "",
      }),
    });
  var stdout = withoutBootLines(result.stdout);
  var stderr = withoutBootLines(result.stderr);
  var line = stdout.split("\n").filter(function (l) { return l.indexOf("RESULT ") === 0; })[0] || "";
  return {
    status: result.status,
    line:   line,
    both:   stdout + "\n" + stderr,
  };
}

async function run() {
  var root = helpers.tempDir("boot-posture");

  try {
    // One certificate for every child, written where each of them can
    // read it. Building a certificate authority per case would cost more
    // than the cases do, and none of these children ever accepts a
    // client: the assertion under test runs before anything binds.
    var ca = b.mtlsCa.create({
      dataDir:         nodePath.join(root, "ca"),
      caKeySealedMode: "disabled",
      generation:      1,
      algorithm:       "ECDSA-P384-SHA384",
    });
    await ca.initCA();
    var leaf = await ca.generateClientCert({
      cn: HOSTNAME, usage: "server", sans: [HOSTNAME, LOOPBACK], validityDays: 1,
    });
    nodeFs.writeFileSync(nodePath.join(root, "leaf.crt"), leaf.cert);
    nodeFs.writeFileSync(nodePath.join(root, "leaf.key"), leaf.key);

    // ---- the posture this server ships ----

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         nodePath.join(root, "posture-data"),
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      },
      cwd: root,
    });
    count("blamepost.productionPosture is composed rather than absent",
      typeof blamepost.productionPosture === "function",
      typeof blamepost.productionPosture);

    var posture = blamepost.productionPosture(cfg);
    count("the vault is required to be sealed", posture.vault === "wrapped", posture.vault);
    count("the database is required to be encrypted at rest",
      posture.dbAtRest === "encrypted", posture.dbAtRest);
    count("the audit signing key is required to be sealed",
      posture.auditSigning === "wrapped", posture.auditSigning);
    count("clock drift is required to be checked", posture.ntpStrict === true, posture.ntpStrict);
    count("the transport minimum is required to be TLS 1.3",
      posture.minTlsVersion === "TLSv1.3", posture.minTlsVersion);
    count("the data directory is named, so its permissions are read at boot",
      posture.dataDir === cfg.paths.dataDir, posture.dataDir);
    count("the runtime environments a developer uses are refused",
      Array.isArray(posture.forbidNodeEnv) && posture.forbidNodeEnv.indexOf("development") !== -1,
      JSON.stringify(posture.forbidNodeEnv));

    // The at-rest resolver is this server's, because the framework's own
    // default reads an accessor the framework does not export, so the
    // shipped default can only ever report an absent mode.
    count("the at-rest mode is read through a resolver that answers",
      posture.resolvers && typeof posture.resolvers.dbAtRest === "function" &&
      posture.resolvers.dbAtRest() === b.db.getMode(),
      posture.resolvers && typeof posture.resolvers.dbAtRest === "function"
        ? String(posture.resolvers.dbAtRest()) : "no resolver");

    // The Node floor cannot be lowered inside a process, so what is
    // pinned here is that the floor the posture carries is the floor the
    // package declares. A posture that kept an older floor while the
    // package moved on would refuse nothing an operator could hit.
    var declared = parseInt(/(\d+)/.exec(String(pkg.engines && pkg.engines.node) || "")[1], 10);
    count("the Node floor is the one package.json declares",
      posture.minNodeMajor === declared,
      posture.minNodeMajor + " against " + declared);

    // ---- each predicate, on its own, against a real boot ----

    var order = ["clean", "ntp", "node-env", "tls-min", "vault", "audit-signing",
      "db-at-rest", "datadir", "dns"];

    for (var i = 0; i < order.length; i += 1) {
      var name = order[i];
      if (name === "datadir" && process.platform === "win32") {
        skip("the data directory permission check is POSIX-only in the framework, " +
          "so it cannot refuse a boot on this platform");
        continue;
      }
      var caseRoot = nodePath.join(root, "case-" + name);
      nodeFs.mkdirSync(caseRoot, { recursive: true });
      var outcome = spawnCase(name, caseRoot);

      if (name === "clean") {
        count("a boot whose posture is the shipped one starts",
          outcome.line === "RESULT STARTED", outcome.both);
        continue;
      }
      count("a boot with " + name + " loosened refuses",
        outcome.line.indexOf("RESULT REFUSED") === 0, outcome.both);
      count("and the refusal names " + CASES[name].expect,
        outcome.line.indexOf(CASES[name].expect) !== -1, outcome.line);
    }
  } finally {
    helpers.removeTempDir(root);
  }

  return helpers.getChecks();
}

module.exports = {
  name:      "boot-posture-refusal",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  if (process.argv[2] === "--posture-child") {
    runChild(process.argv[3], process.argv[4]).catch(function (e) {
      process.stdout.write("RESULT ERROR " +
        String((e && e.stack) || e).replace(/[\r\n]+/g, " ") + "\n");
      process.exitCode = 1;
    });
  } else {
    run().then(function (total) {
      console.log("CHECKS " + total);
    }).catch(function (e) {
      console.error(e && e.stack ? e.stack : String(e));
      // Set the code rather than calling process.exit, which would tear the
      // process down before the stack above is flushed. The orchestrator reads
      // this file's output to diagnose a failure, so losing it costs the run.
      process.exitCode = 1;
    });
  }
}
