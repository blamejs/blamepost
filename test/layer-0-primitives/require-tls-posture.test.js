// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * require-tls-posture: the REQUIRETLS setting an operator writes is the
 * posture the outbound handle carries.
 *
 * `requireTls` says every outbound envelope asks its receiver for
 * REQUIRETLS (RFC 8689), so a message is withheld from a peer that
 * cannot encrypt rather than delivered to it. The transport appends the
 * keyword to `MAIL FROM` for a peer whose post-STARTTLS EHLO advertises
 * the extension, and RFC 8689 section 4.1 makes a peer that does not
 * advertise it a destination to fail over from rather than deliver to.
 * Those are the wire facts, and `require-tls-wire` measures them against
 * a real peer.
 *
 * What this file measures is the half before the socket: whether the
 * value an operator wrote is the value the handle holds. The setting
 * arrives through three doors and each one has to reach the same
 * posture:
 *
 *   - the environment variable, which is the form the operator guide
 *     shows;
 *   - the configuration file key;
 *   - and a configuration object handed straight to the delivery
 *     composition, which is what `blamepost.create` builds and what the
 *     fixtures in this suite construct. A door that dropped the value
 *     would leave an operator reading their own configuration and
 *     believing confidential mail is held back from peers that cannot
 *     encrypt while it travels to all of them, and nothing would report
 *     the difference.
 *
 * The off spelling is measured beside the on one throughout, and it is
 * the case most easily got wrong. `false` is the shipped default and
 * also the spelling of "I want none of this", so a handle that reported
 * the posture as on whenever the key was present would pass every
 * assertion about the on case and be wrong for every operator who wrote
 * the default down.
 *
 * No sockets and no peer. It loads configurations and builds delivery
 * handles.
 *
 * Run standalone: node test/layer-0-primitives/require-tls-posture.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var config   = require("../../lib/config");
var delivery = require("../../lib/mail/delivery");

var check = helpers.check;
var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var HOSTNAME         = "mx.example.com";

var SETTING_KEY      = "requireTls";
var SETTING_VARIABLE = "BLAMEPOST_REQUIRE_TLS";

function baseEnv(dataDir, extra) {
  return Object.assign({
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  }, extra || {});
}

function loadOrThrow(root, env) {
  var thrown = null;
  var loaded = null;
  try { loaded = config.load({ env: env, cwd: root }); }
  catch (e) { thrown = e; }
  return { loaded: loaded, thrown: thrown };
}

// One origin, measured the same way wherever it came from: the load has
// to succeed, and the posture it produces has to be the one written.
function theOriginCarriesThePosture(label, outcome, wanted) {
  count(label + " loads", outcome.thrown === null,
    outcome.thrown === null ? "loaded" : outcome.thrown.code + ": " + outcome.thrown.message);
  if (outcome.thrown !== null) return;
  count(label + " carries the posture that was written",
    outcome.loaded.requireTls === wanted, String(outcome.loaded.requireTls));
}

// ---- the loader ------------------------------------------------------------

function theEnvironmentVariableIsRead(root, dataDir) {
  theOriginCarriesThePosture("REQUIRETLS asked for through the environment",
    loadOrThrow(root, baseEnv(dataDir, { BLAMEPOST_REQUIRE_TLS: "true" })), true);
  theOriginCarriesThePosture("REQUIRETLS turned off through the environment",
    loadOrThrow(root, baseEnv(dataDir, { BLAMEPOST_REQUIRE_TLS: "false" })), false);
}

function theConfigurationFileKeyIsRead(root, dataDir) {
  function fileWith(value, name) {
    var filePath = nodePath.join(root, name);
    nodeFs.writeFileSync(filePath, JSON.stringify({ requireTls: value }, null, 2), "utf8");
    return loadOrThrow(root, baseEnv(dataDir, { BLAMEPOST_CONFIG: filePath }));
  }
  theOriginCarriesThePosture("REQUIRETLS asked for in the configuration file",
    fileWith(true, "require-tls-on.config.json"), true);
  theOriginCarriesThePosture("REQUIRETLS turned off in the configuration file",
    fileWith(false, "require-tls-off.config.json"), false);
}

// The variable has to stay a name the loader knows. The environment is a
// namespace this server shares with everything else on the host, so a
// name it stops recognizing is a name it stops reading, and the operator
// who set it is told nothing at all.
function theSettingIsStillDeclared() {
  var row = null;
  config.SETTINGS.forEach(function (setting) {
    if (setting.key === SETTING_KEY) row = setting;
  });
  check("the loader declares the REQUIRETLS setting", row !== null);
  count("and reads it from the variable the documents name",
    row !== null && row.env === SETTING_VARIABLE, row === null ? "absent" : row.env);
  // The row carried a `refused` string for as long as the parameter
  // could not reach the wire. A refusal left in place after the wire
  // half landed is a protection an operator can no longer ask for, and
  // it fails in the direction nobody investigates: the boot stops and
  // the setting looks unsupported.
  count("and does not refuse it, because the keyword reaches the wire",
    row !== null && row.refused === undefined, row === null ? "absent" : String(row.refused));
}

function aConfigurationWithoutTheSettingIsOff(root, dataDir) {
  var outcome = loadOrThrow(root, baseEnv(dataDir));
  count("a configuration that never mentions REQUIRETLS loads",
    outcome.thrown === null,
    outcome.thrown === null ? "loaded" : outcome.thrown.code + ": " + outcome.thrown.message);
  count("and leaves the posture off, which is the shipped default",
    outcome.thrown === null && outcome.loaded.requireTls === false,
    outcome.thrown === null ? String(outcome.loaded.requireTls) : "not loaded");
}

// ---- the delivery composition ----------------------------------------------

function _composeDelivery(dataDir, extra) {
  var thrown = null;
  var described = null;
  var handle = null;
  try {
    handle = delivery.create(Object.assign({
      hostname: HOSTNAME,
      dataDir:  dataDir,
    }, extra || {}));
    described = handle.describe();
  } catch (e) { thrown = e; }
  if (handle && typeof handle.stop === "function") handle.stop();
  return { thrown: thrown, described: described };
}

// The loader is one of two doors. `blamepost.create` takes a
// configuration OBJECT, so a value the loader read correctly and the
// composition dropped would still leave the posture unapplied.
function theDeliveryCompositionCarriesIt(dataDir) {
  var on = _composeDelivery(dataDir, { requireTls: true });
  count("a delivery composition asked for REQUIRETLS is built",
    on.thrown === null, on.thrown === null ? "built" : String(on.thrown.message));
  count("and reports the posture as on",
    on.thrown === null && on.described.requireTls === true,
    on.thrown === null ? String(on.described.requireTls) : "not built");

  // The control. Without it the case above would pass on a composition
  // that reported every handle as asking for REQUIRETLS, which is the
  // shape that turns the default into a delivery failure for every peer
  // that does not implement the extension.
  var off = _composeDelivery(dataDir);
  count("a delivery composition that does not ask for it reports the posture as off",
    off.thrown === null && off.described.requireTls === false,
    off.thrown === null ? String(off.described.requireTls) : String(off.thrown));
}

// A value that is neither true nor false leaves undecided the question
// that decides whether mail is delivered or bounced, so it is refused at
// composition rather than coerced.
function aNonBooleanIsRefused(dataDir) {
  var outcome = _composeDelivery(dataDir, { requireTls: "yes" });
  count("a REQUIRETLS posture that is not a boolean is refused at composition",
    outcome.thrown !== null,
    outcome.thrown === null ? "accepted" : String(outcome.thrown.message).slice(0, 120));
  count("and the refusal names the setting an operator would search for",
    outcome.thrown !== null && String(outcome.thrown.message).indexOf(SETTING_KEY) !== -1,
    outcome.thrown === null ? "accepted" : String(outcome.thrown.message));
}

// ---- runner ----------------------------------------------------------------

function run() {
  var root    = helpers.tempDir("require-tls-posture");
  var dataDir = nodePath.join(root, "data");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  try {
    theSettingIsStillDeclared();
    theEnvironmentVariableIsRead(root, dataDir);
    theConfigurationFileKeyIsRead(root, dataDir);
    aConfigurationWithoutTheSettingIsOff(root, dataDir);
    theDeliveryCompositionCarriesIt(dataDir);
    aNonBooleanIsRefused(dataDir);
  } finally {
    helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "require-tls-posture", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
