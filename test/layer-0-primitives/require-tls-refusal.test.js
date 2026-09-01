// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * require-tls-refusal: a protective setting that never reaches the wire
 * refuses at boot rather than reporting a protection it does not apply.
 *
 * `requireTls` says every outbound envelope asks for REQUIRETLS (RFC
 * 8689), so a message bounces rather than being delivered to a peer that
 * cannot encrypt. The value is accepted, coerced, and threaded through
 * the delivery composer into the transport, and the transport has no
 * reader for it: the option arrives and is discarded. The MAIL FROM line
 * leaves with no REQUIRETLS parameter, and a receiver that would have
 * honored one is never asked. Reported upstream as blamejs#660.
 *
 * This is the more dangerous half of the class `relayAllowedFor` belongs
 * to, and the two are worth reading together. A grant that cannot work
 * fails safe: the operator believes a device can send and it cannot, so
 * somebody complains on the first attempt. A protection that cannot work
 * fails silent and in the operator's favor. Mail keeps flowing, nothing
 * bounces, no delivery report says anything is wrong, and the operator
 * reads their own configuration and believes confidential mail is being
 * held back from peers that cannot encrypt. The evidence that it is
 * working is indistinguishable from the evidence that it was never asked
 * for, which is why this has to refuse rather than warn.
 *
 * The refusal has to fire from every origin the value arrives through:
 *
 *   - the environment variable, which is the form the operator guide
 *     shows;
 *   - the configuration file key;
 *   - and a configuration object handed straight to the delivery
 *     composition, which is what `blamepost.create` builds and what the
 *     fixtures in this suite construct. A refusal living only in the
 *     loader is one an in-process composition walks past.
 *
 * The off spelling is the case most easily got wrong here, and it is the
 * reason this test exists as much as the refusal is. A refused setting
 * still has a spelling that means "I want none of this", and refusing
 * that spelling hands an operator a boot failure for agreeing with the
 * server. For a list that spelling is the empty list. For a boolean it
 * is `false`, which is also the shipped default, so an operator who
 * writes the default down explicitly must still boot.
 *
 * No sockets and no peer. It loads configurations and builds a delivery
 * handle that is expected never to be built.
 *
 * Run standalone: node test/layer-0-primitives/require-tls-refusal.test.js
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

// The words an operator has to find in the refusal. The setting name is
// what they search their own configuration for. Naming a protection that
// does apply is the rest of it: an operator who turned this on wanted
// mail withheld from a peer that cannot encrypt, and that want is
// legitimate, so a refusal that only says no leaves them with nothing.
var NAMES_THE_SETTING  = "requireTls";
var NAMES_THE_VARIABLE = "BLAMEPOST_REQUIRE_TLS";
var NAMES_WHAT_APPLIES = /MTA-STS|DANE/;

function baseEnv(dataDir, extra) {
  return Object.assign({
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  }, extra || {});
}

function loadRefusal(root, env) {
  var thrown = null;
  try {
    config.load({ env: env, cwd: root });
  } catch (e) { thrown = e; }
  return thrown;
}

// One refusal, measured the same way wherever it came from.
function aRefusalThatNamesWhatDoesApply(label, thrown) {
  count(label + " is refused", thrown !== null,
    thrown === null ? "nothing was thrown" : String(thrown.code));
  if (thrown === null) return;
  var message = String(thrown.message || "");
  count(label + " names the setting an operator would search for",
    message.indexOf(NAMES_THE_SETTING) !== -1 || message.indexOf(NAMES_THE_VARIABLE) !== -1,
    message);
  count(label + " names a transport protection that does apply",
    NAMES_WHAT_APPLIES.test(message), message);
}

// ---- the loader ------------------------------------------------------------

function theEnvironmentVariableIsRefused(root, dataDir) {
  aRefusalThatNamesWhatDoesApply("REQUIRETLS asked for through the environment",
    loadRefusal(root, baseEnv(dataDir, { BLAMEPOST_REQUIRE_TLS: "true" })));
}

function theConfigurationFileKeyIsRefused(root, dataDir) {
  var filePath = nodePath.join(root, "require-tls.config.json");
  nodeFs.writeFileSync(filePath,
    JSON.stringify({ requireTls: true }, null, 2), "utf8");
  aRefusalThatNamesWhatDoesApply("REQUIRETLS asked for in the configuration file",
    loadRefusal(root, baseEnv(dataDir, { BLAMEPOST_CONFIG: filePath })));
}

// The variable has to stay a name the loader knows. The environment is a
// namespace this server shares with everything else on the host, so a
// name it stops recognizing is a name it stops reading, and the operator
// who set it is told nothing at all.
function theSettingIsStillDeclared() {
  var row = null;
  config.SETTINGS.forEach(function (setting) {
    if (setting.key === NAMES_THE_SETTING) row = setting;
  });
  check("the loader still declares the REQUIRETLS setting rather than dropping it", row !== null);
  count("and still reads it from the variable the documents name",
    row !== null && row.env === NAMES_THE_VARIABLE, row === null ? "absent" : row.env);
}

// `false` is the boolean spelling of "I want none of this", and it is
// also the shipped default. An operator who writes the default down
// explicitly, or who turns the setting off after reading this refusal,
// has agreed with the server and must still boot. A refusal keyed on
// the presence of the value rather than on what it asks for fails here
// and nowhere else, because every other refused setting so far has been
// a list whose empty spelling is structurally distinguishable.
function turningItOffIsNotARequest(root, dataDir) {
  var thrown = loadRefusal(root, baseEnv(dataDir, { BLAMEPOST_REQUIRE_TLS: "false" }));
  count("REQUIRETLS explicitly turned off loads, because it asks for nothing",
    thrown === null, thrown === null ? "loaded" : thrown.code + ": " + thrown.message);
}

function aConfigurationWithoutTheSettingLoads(root, dataDir) {
  var thrown = loadRefusal(root, baseEnv(dataDir));
  count("a configuration that never mentions REQUIRETLS loads",
    thrown === null, thrown === null ? "loaded" : thrown.code + ": " + thrown.message);
}

// ---- the delivery composition ----------------------------------------------

function _composeDelivery(dataDir, extra) {
  var thrown = null;
  var handle = null;
  try {
    handle = delivery.create(Object.assign({
      hostname: HOSTNAME,
      dataDir:  dataDir,
    }, extra || {}));
  } catch (e) { thrown = e; }
  if (handle && typeof handle.stop === "function") handle.stop();
  return thrown;
}

// The loader is one of two doors. `blamepost.create` takes a
// configuration OBJECT, so a refusal that lived only in the loader would
// be one an in-process composition never meets.
function theDeliveryCompositionRefusesIt(dataDir) {
  aRefusalThatNamesWhatDoesApply("REQUIRETLS handed straight to the delivery composition",
    _composeDelivery(dataDir, { requireTls: true }));
}

// And the same composition without it builds. Without this the case
// above would pass on a composition that refuses everything, which
// proves nothing about the REQUIRETLS check.
function theDeliveryCompositionBuildsWithoutIt(dataDir) {
  var thrown = _composeDelivery(dataDir);
  count("a delivery composition that does not ask for REQUIRETLS is built",
    thrown === null, thrown === null ? "built" : String(thrown.message));
}

// ---- runner ----------------------------------------------------------------

function run() {
  var root    = helpers.tempDir("require-tls-refusal");
  var dataDir = nodePath.join(root, "data");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  try {
    theSettingIsStillDeclared();
    theEnvironmentVariableIsRefused(root, dataDir);
    theConfigurationFileKeyIsRefused(root, dataDir);
    turningItOffIsNotARequest(root, dataDir);
    aConfigurationWithoutTheSettingLoads(root, dataDir);
    theDeliveryCompositionRefusesIt(dataDir);
    theDeliveryCompositionBuildsWithoutIt(dataDir);
  } finally {
    helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "require-tls-refusal", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
