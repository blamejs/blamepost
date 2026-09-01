// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * config-listeners: the port surface an operator actually sets, and the
 * ports the server refuses to promise twice.
 *
 * Two failures live here, and both are quiet.
 *
 * The first is a port an operator moves that never moves. Every listener
 * carries an environment variable of its own, which is the only usable
 * form inside a `docker run` line, and a variable the loader does not
 * read is a setting that reads as applied and is not. The container
 * documentation offers those variables as the way to run without binding
 * a privileged port, which is exactly the moment an operator cannot
 * afford them to be inert.
 *
 * The second is two listeners sent to one port. One process cannot bind
 * one port twice, so the second one fails at start with an operating
 * system error naming a number rather than a listener, after the first
 * ones are already accepting connections. The trap is that a listener
 * the configuration never names still binds its documented port: moving
 * IMAP to 25 collides with the MX listener nobody wrote down, and the
 * web interface holds two more ports that no listener section mentions
 * at all.
 *
 * Every case here drives `config.load` the way a boot does, over the
 * environment and over a configuration file, and the ones that matter
 * carry through `mail.listeners.create` so the assertion lands on the
 * table that binds rather than on a property of the loaded object.
 *
 * Run it on its own with
 * `node test/layer-1-state/config-listeners.test.js`.
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers        = require("../helpers");
var certs          = require("../helpers/certs");
var parity         = require("../helpers/parity");
var check          = helpers.check;
var count          = helpers.count;
var config         = require("../../lib/config");
var store          = require("../../lib/store");
var listenerModule = require("../../lib/mail/listeners");

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// Assert a call refuses with one stable error code, and that the message
// carries the fragments an operator needs in order to find the setting.
// Both halves matter: a refusal under the wrong code breaks a caller
// branching on it, and a refusal that names nothing sends the operator
// to read source, which is the failure the loader exists to avoid.
function refusesNaming(label, code, needles, fn) {
  var thrown = null;
  try { fn(); } catch (e) { thrown = e; }
  var message = thrown === null ? "" : String(thrown.message);
  var missing = needles.filter(function (needle) { return message.indexOf(needle) === -1; });
  count(label,
    thrown !== null && thrown.code === code && missing.length === 0,
    thrown === null
      ? "nothing was thrown"
      : thrown.code + " missing " + JSON.stringify(missing) + " in: " + message);
}

function accepts(label, fn) {
  var thrown = null;
  var value  = null;
  try { value = fn(); } catch (e) { thrown = e; }
  count(label, thrown === null,
    thrown === null ? "" : thrown.code + ": " + thrown.message);
  return value;
}

function baseEnv(dataDir, extra) {
  return Object.assign({
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  }, extra || {});
}

// ---------------------------------------------------------------------------
// The per-listener port variables
// ---------------------------------------------------------------------------

// Read off the loader rather than written here, so a variable renamed in
// one place and not the other fails this file rather than passing it.
function portVarFor(name) {
  return config.LISTENER_DEFAULTS[name].portVar;
}

function testEveryListenerHasItsOwnPortVariable(root, dataDir) {
  var names = config.LISTENER_NAMES.slice().sort();
  var seen  = {};
  names.forEach(function (name) {
    var variable = portVarFor(name);
    count("the " + name + " listener carries a port variable of its own",
      typeof variable === "string" && variable.indexOf("BLAMEPOST_") === 0, variable);
    check("and no other listener answers to " + variable, seen[variable] === undefined);
    seen[variable] = name;
  });

  names.forEach(function (name) {
    var variable = portVarFor(name);
    var moved    = config.LISTENER_DEFAULTS[name].port + 10000;
    var env      = baseEnv(dataDir);
    env[variable] = String(moved);
    var cfg = accepts(variable + " is a setting the loader reads", function () {
      return config.load({ env: env, cwd: root });
    });
    count(variable + " moves the " + name + " listener to the port it names",
      cfg !== null && cfg.listeners !== null && cfg.listeners[name] !== undefined &&
      cfg.listeners[name].port === moved,
      cfg === null ? "load refused" : JSON.stringify(cfg.listeners));
  });
}

function testPortVariableRangeIsChecked(root, dataDir) {
  ["0", "70000", "1143x", "-1", ""].forEach(function (bad) {
    var env = baseEnv(dataDir);
    env.BLAMEPOST_IMAP_PORT = bad;
    if (bad === "") {
      // An empty variable is how a container runtime spells "unset", so
      // it must fall through to the default rather than refuse.
      var cfg = accepts("an empty BLAMEPOST_IMAP_PORT leaves the listener alone", function () {
        return config.load({ env: env, cwd: root });
      });
      count("an empty BLAMEPOST_IMAP_PORT declares no port at all",
        cfg !== null && (cfg.listeners === null || cfg.listeners.imap === undefined),
        cfg === null ? "load refused" : JSON.stringify(cfg.listeners));
      return;
    }
    refusesNaming("BLAMEPOST_IMAP_PORT=" + bad + " is refused, naming the variable",
      "config/bad-value", ["BLAMEPOST_IMAP_PORT"], function () {
        config.load({ env: env, cwd: root });
      });
  });
}

function testPortVariableWinsOverTheFile(root, dataDir) {
  var filePath = nodePath.join(root, "listeners-in-the-file.json");
  nodeFs.writeFileSync(filePath,
    JSON.stringify({ listeners: { imap: { port: 1143, address: "127.0.0.1" } } }), "utf8");

  var cfg = accepts("a port variable over a file that names the same listener loads", function () {
    return config.load({
      env: baseEnv(dataDir, { BLAMEPOST_CONFIG: filePath, BLAMEPOST_IMAP_PORT: "2143" }),
      cwd: root,
    });
  });
  count("the environment's port wins over the file's, the way every other setting does",
    cfg !== null && cfg.listeners.imap.port === 2143,
    cfg === null ? "load refused" : JSON.stringify(cfg.listeners));
  count("the rest of the file's listener section survives the override",
    cfg !== null && cfg.listeners.imap.address === "127.0.0.1",
    cfg === null ? "load refused" : JSON.stringify(cfg.listeners));

  // The loaded configuration is shared by every subsystem, so a table
  // rebuilt to take an override has to come back as frozen as the one it
  // replaced. A mutable section is a port one subsystem could rewrite
  // for all the others.
  check("the rebuilt listener table is frozen",
    cfg !== null && Object.isFrozen(cfg.listeners) && Object.isFrozen(cfg.listeners.imap));
}

// The wide form replaces the setting rather than merging into it. That
// is worth pinning, because the narrow port variable does the opposite
// and an operator reading one behavior into the other loses the
// interface a listener was bound to.
function testTheListenerTableReplacesRatherThanMerges(root, dataDir) {
  var filePath = nodePath.join(root, "whole-table.json");
  nodeFs.writeFileSync(filePath, JSON.stringify({
    listeners: { mx: { port: 2525 }, imap: { address: "127.0.0.1" } },
  }), "utf8");

  var cfg = accepts("a listener table in the environment over one in the file loads", function () {
    return config.load({
      env: baseEnv(dataDir, {
        BLAMEPOST_CONFIG:    filePath,
        BLAMEPOST_LISTENERS: '{"managesieve":{"port":14190}}',
      }),
      cwd: root,
    });
  });
  count("the environment's table supersedes the file's rather than merging into it",
    cfg !== null && JSON.stringify(cfg.listeners) === '{"managesieve":{"port":14190}}',
    cfg === null ? "load refused" : JSON.stringify(cfg.listeners));
  count("so the MX listener the file moved is back on its documented port",
    cfg !== null && cfg.listeners.mx === undefined,
    cfg === null ? "load refused" : JSON.stringify(cfg.listeners));
}

function testTwoEnvironmentVariablesForOnePortAreRefused(root, dataDir) {
  refusesNaming("one listener's port set by two environment variables is refused",
    "config/conflicting-settings",
    ["BLAMEPOST_IMAP_PORT", "BLAMEPOST_LISTENERS"], function () {
      config.load({
        env: baseEnv(dataDir, {
          BLAMEPOST_IMAP_PORT: "2143",
          BLAMEPOST_LISTENERS: '{"imap":{"port":1143}}',
        }),
        cwd: root,
      });
    });

  // Agreement is not a rescue. One of the two is dead configuration
  // either way, and the operator who edits the dead one gets nothing.
  refusesNaming("the same refusal when the two agree on the number",
    "config/conflicting-settings",
    ["BLAMEPOST_IMAP_PORT", "BLAMEPOST_LISTENERS"], function () {
      config.load({
        env: baseEnv(dataDir, {
          BLAMEPOST_IMAP_PORT: "1143",
          BLAMEPOST_LISTENERS: '{"imap":{"port":1143}}',
        }),
        cwd: root,
      });
    });

  accepts("a listener table naming a different listener is not a conflict", function () {
    return config.load({
      env: baseEnv(dataDir, {
        BLAMEPOST_IMAP_PORT: "2143",
        BLAMEPOST_LISTENERS: '{"managesieve":{"port":14190}}',
      }),
      cwd: root,
    });
  });

  accepts("a listener table naming the same listener without a port is not a conflict", function () {
    return config.load({
      env: baseEnv(dataDir, {
        BLAMEPOST_IMAP_PORT: "2143",
        BLAMEPOST_LISTENERS: '{"imap":{"address":"127.0.0.1"}}',
      }),
      cwd: root,
    });
  });
}

// ---------------------------------------------------------------------------
// Ports claimed twice
// ---------------------------------------------------------------------------

function testCollisionWithAListenerNobodyNamed(root, dataDir) {
  refusesNaming("IMAP moved onto the MX listener's default port is refused",
    "config/port-collision", ["imap", "mx", "25"], function () {
      config.load({
        env: baseEnv(dataDir, { BLAMEPOST_LISTENERS: '{"imap":{"port":25}}' }),
        cwd: root,
      });
    });

  refusesNaming("ManageSieve moved onto the submission listener's default port is refused",
    "config/port-collision", ["managesieve", "submission", "587"], function () {
      config.load({
        env: baseEnv(dataDir, { BLAMEPOST_MANAGESIEVE_PORT: "587" }),
        cwd: root,
      });
    });

  refusesNaming("the MX port variable moved onto the IMAP default is refused",
    "config/port-collision", ["mx", "imap", "143"], function () {
      config.load({ env: baseEnv(dataDir, { BLAMEPOST_MX_PORT: "143" }), cwd: root });
    });
}

function testCollisionWithTheWebInterface(root, dataDir) {
  refusesNaming("a listener moved onto the HTTP port is refused, naming that variable",
    "config/port-collision", ["imap", "BLAMEPOST_HTTP_PORT", "8080"], function () {
      config.load({
        env: baseEnv(dataDir, { BLAMEPOST_IMAP_PORT: "8080" }),
        cwd: root,
      });
    });

  refusesNaming("a listener moved onto the HTTPS port is refused, naming that variable",
    "config/port-collision", ["imap", "BLAMEPOST_HTTPS_PORT", "8443"], function () {
      config.load({
        env: baseEnv(dataDir, { BLAMEPOST_IMAP_PORT: "8443" }),
        cwd: root,
      });
    });

  refusesNaming("the HTTP port moved onto a listener's default is refused",
    "config/port-collision", ["BLAMEPOST_HTTP_PORT", "imap", "143"], function () {
      config.load({ env: baseEnv(dataDir, { BLAMEPOST_HTTP_PORT: "143" }), cwd: root });
    });

  // The pair check has its own message and has to keep winning, because
  // it explains the one case the sweep would report as an anonymous
  // duplicate.
  refusesNaming("the two web ports set to one another are still refused by their own check",
    "config/port-collision", ["BLAMEPOST_HTTP_PORT", "BLAMEPOST_HTTPS_PORT"], function () {
      config.load({ env: baseEnv(dataDir, { BLAMEPOST_HTTP_PORT: "8443" }), cwd: root });
    });
}

function testADisabledListenerClaimsNothing(root, dataDir) {
  accepts("a listener may take the port of one the operator switched off", function () {
    return config.load({
      env: baseEnv(dataDir, {
        BLAMEPOST_LISTENERS: '{"mx":{"enabled":false},"imap":{"port":25}}',
      }),
      cwd: root,
    });
  });

  // POP3 is off unless the operator turns it on, so its documented port
  // is free until then. This is the case a sweep over the whole default
  // table gets wrong if it ignores what is enabled.
  accepts("a listener may take the POP3 port while POP3 is off", function () {
    return config.load({
      env: baseEnv(dataDir, { BLAMEPOST_IMAP_PORT: "110" }),
      cwd: root,
    });
  });

  refusesNaming("the same configuration is refused once POP3 is turned on",
    "config/port-collision", ["imap", "pop3", "110"], function () {
      config.load({
        env: baseEnv(dataDir, { BLAMEPOST_IMAP_PORT: "110", BLAMEPOST_POP3_ENABLED: "true" }),
        cwd: root,
      });
    });
}

function testTheShippedDefaultsDoNotCollide(root, dataDir) {
  accepts("the configuration an operator gets with nothing set loads", function () {
    return config.load({ env: baseEnv(dataDir), cwd: root });
  });
  accepts("and it still loads with every listener turned on", function () {
    return config.load({ env: baseEnv(dataDir, { BLAMEPOST_POP3_ENABLED: "true" }), cwd: root });
  });
}

// ---------------------------------------------------------------------------
// Two switches for one listener
// ---------------------------------------------------------------------------

function testThePop3SwitchAgainstTheListenerSection(root, dataDir) {
  refusesNaming("POP3 switched off and switched on at once is refused",
    "config/conflicting-settings",
    ["BLAMEPOST_POP3_ENABLED", "listeners.pop3.enabled"], function () {
      config.load({
        env: baseEnv(dataDir, {
          BLAMEPOST_POP3_ENABLED: "false",
          BLAMEPOST_LISTENERS:    '{"pop3":{"enabled":true}}',
        }),
        cwd: root,
      });
    });

  refusesNaming("and refused the other way round",
    "config/conflicting-settings",
    ["BLAMEPOST_POP3_ENABLED", "listeners.pop3.enabled"], function () {
      config.load({
        env: baseEnv(dataDir, {
          BLAMEPOST_POP3_ENABLED: "true",
          BLAMEPOST_LISTENERS:    '{"pop3":{"enabled":false}}',
        }),
        cwd: root,
      });
    });

  accepts("the two agreeing is not a conflict", function () {
    return config.load({
      env: baseEnv(dataDir, {
        BLAMEPOST_POP3_ENABLED: "true",
        BLAMEPOST_LISTENERS:    '{"pop3":{"enabled":true}}',
      }),
      cwd: root,
    });
  });

  accepts("a POP3 section carrying only a port is not a conflict", function () {
    return config.load({
      env: baseEnv(dataDir, {
        BLAMEPOST_POP3_ENABLED: "true",
        BLAMEPOST_LISTENERS:    '{"pop3":{"port":10110}}',
      }),
      cwd: root,
    });
  });
}

// ---------------------------------------------------------------------------
// A certificate path that is not a certificate
// ---------------------------------------------------------------------------

function testCertificatePathsMustNameFiles(root, dataDir) {
  var dir = nodePath.join(root, "a-directory-not-a-certificate");
  nodeFs.mkdirSync(dir, { recursive: true });

  refusesNaming("a certificate path naming a directory is refused at load",
    "config/bad-value", ["BLAMEPOST_TLS_CERT"], function () {
      config.load({
        env: baseEnv(dataDir, { BLAMEPOST_TLS_CERT: dir, BLAMEPOST_TLS_KEY: dir }),
        cwd: root,
      });
    });

  var cert = nodePath.join(root, "cert.pem");
  var key  = nodePath.join(root, "key.pem");
  nodeFs.writeFileSync(cert, "certificate bytes\n", "utf8");
  nodeFs.writeFileSync(key, "key bytes\n", "utf8");
  accepts("a certificate path naming a real file still loads", function () {
    return config.load({
      env: baseEnv(dataDir, { BLAMEPOST_TLS_CERT: cert, BLAMEPOST_TLS_KEY: key }),
      cwd: root,
    });
  });
}

// ---------------------------------------------------------------------------
// The path an operator's port actually travels
// ---------------------------------------------------------------------------

// A port that reaches the loaded object and stops there is a port that
// did not move. The listener composition is the thing that binds, so the
// assertion belongs on the table it describes.
function testAPortVariableReachesTheListenerComposition(root, dataDir, handle) {
  var cfg = config.load({
    env: baseEnv(dataDir, {
      BLAMEPOST_MX_PORT:          "2525",
      BLAMEPOST_MANAGESIEVE_PORT: "14190",
    }),
    cwd: root,
  });

  var composed = listenerModule.create({
    config:     cfg,
    store:      handle,
    mailStore:  { appendMessage: function () { return { objectid: "obj_config_listeners" }; } },
    // The certificate arrives as the loader handle rather than as a
    // context, because the listeners read it per connection so a renewal
    // reaches them. Nothing binds in this case, so the stand-in only has
    // to answer the accessor.
    certificate: certs.handle({}),
    delivery:   helpers.standInDelivery(),
  });
  var described = composed.describe();

  count("the MX port variable reaches the listener that binds",
    described.listeners.mx.port === 2525, JSON.stringify(described.listeners.mx));
  count("the ManageSieve port variable reaches it too",
    described.listeners.managesieve.port === 14190,
    JSON.stringify(described.listeners.managesieve));
  count("a listener no variable named keeps its documented port",
    described.listeners.imap.port === 143, JSON.stringify(described.listeners.imap));
  check("nothing bound while proving it", Object.keys(described.bound).length === 0);
}

// The default port table the loader holds is the one the mail stack
// binds. Two copies of the same numbers drift silently, and the drift
// only shows up as a collision the loader failed to catch or one it
// invented.
function testDefaultPortsMatchTheMailStack() {
  var declared = config.LISTENER_NAMES.slice().sort();

  // The set comparison goes through the shared reader rather than a
  // string equality written here. Two sorted lists joined into one
  // message are a difference the reader has to find by eye; the shared
  // one names the listener that drifted and which side it is on, which
  // are opposite fixes: a listener the mail stack builds and the loader
  // does not know is refused as an unknown field the first time an
  // operator configures it, and one the loader knows and the mail stack
  // does not build is a section that validates and binds nothing.
  parity.report(count, {
    have:      declared,
    want:      Object.keys(listenerModule.DEFAULTS),
    haveLabel: "the loader",
    wantLabel: "the mail stack",
    missingHint: "the mail stack builds this listener and the loader does not know it, so " +
      "configuring it is refused as an unknown field",
    extraHint: "the loader validates a section for this listener and the mail stack builds " +
      "nothing for it, so the section binds nothing",
  });

  declared.forEach(function (name) {
    var built  = listenerModule.DEFAULTS[name];
    var loader = config.LISTENER_DEFAULTS[name];
    count("the loader and the mail stack agree the " + name + " listener defaults to port " +
      loader.port,
      built !== undefined && built.port === loader.port,
      built === undefined ? "the mail stack builds no such listener"
        : built.port + " against " + loader.port);
    count("and that the " + name + " listener is " + (loader.enabled ? "on" : "off") +
      " unless the operator says otherwise",
      built !== undefined && built.enabled === loader.enabled,
      built === undefined ? "the mail stack builds no such listener"
        : built.enabled + " against " + loader.enabled);
  });
}

async function run() {
  var root    = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-config-listeners-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // directory it reads from this variable. Pointing it inside the run's
  // own temporary tree keeps the encrypted-at-rest path exactly as it
  // ships rather than opting the test out of it.
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  try {
    testDefaultPortsMatchTheMailStack();
    testEveryListenerHasItsOwnPortVariable(root, dataDir);
    testPortVariableRangeIsChecked(root, dataDir);
    testPortVariableWinsOverTheFile(root, dataDir);
    testTheListenerTableReplacesRatherThanMerges(root, dataDir);
    testTwoEnvironmentVariablesForOnePortAreRefused(root, dataDir);
    testCollisionWithAListenerNobodyNamed(root, dataDir);
    testCollisionWithTheWebInterface(root, dataDir);
    testADisabledListenerClaimsNothing(root, dataDir);
    testTheShippedDefaultsDoNotCollide(root, dataDir);
    testThePop3SwitchAgainstTheListenerSection(root, dataDir);
    testCertificatePathsMustNameFiles(root, dataDir);

    var handle = await store.open(config.load({ env: baseEnv(dataDir), cwd: root }));
    testAPortVariableReachesTheListenerComposition(root, dataDir, handle);
    store.close();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    // Drop-silent by design: a temporary directory that outlives the run
    // must never mask the assertion that failed inside it.
    try { nodeFs.rmSync(root, { recursive: true, force: true }); } catch (_e) { /* the OS reclaims it */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
