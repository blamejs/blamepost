// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * relay-grant-refusal: a setting that cannot work refuses at boot, and
 * says what to do instead.
 *
 * `relayAllowedFor` names source ranges the MX listener would accept a
 * recipient outside the hosted domains for. The framework's listener
 * carries the range arithmetic, so the ranges reach it and a peer inside
 * one is admitted at RCPT. Nothing after that point can deliver the
 * message: every recipient is resolved against the hosted domains, an
 * address elsewhere resolves to nothing, and the peer is answered `451`
 * for a condition that will never clear. A setting that validates,
 * documents itself, and cannot do the thing it names is worse than one
 * that is not offered, because the operator reads their own
 * configuration and believes the printer in the branch office can send.
 *
 * This server refuses it instead, and the refusal is the whole feature:
 * it names the setting, says why the range cannot be honored, and points
 * at authenticated submission, which serves the same device and binds an
 * identity to it.
 *
 * The refusal has to fire from every origin the value can arrive
 * through, and there are three:
 *
 *   - the environment variable, which is the form the operator guide
 *     shows;
 *   - the configuration file key, which is the form the README shows;
 *   - and a configuration object handed straight to the listener
 *     composition, which is what `blamepost.create` receives and what
 *     every test fixture builds. A refusal that lives only in the loader
 *     is one an in-process composition walks past.
 *
 * The row stays in the setting table on purpose, and that is the case
 * most easily got wrong. Deleting it would make the file key an unknown
 * key, which is refused, and would make the environment variable
 * silently ignored, because the environment is a shared namespace and
 * the loader reads only names it recognizes. An operator who had set the
 * variable would get a server that relays for nobody and never says so.
 *
 * An empty allowlist is not a grant and is left alone: it says relay for
 * nobody, which is what this server does.
 *
 * No sockets and no database. It loads configurations and constructs a
 * listener handle that is expected never to be built.
 *
 * Run standalone: node test/layer-0-primitives/relay-grant-refusal.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var config    = require("../../lib/config");
var listeners = require("../../lib/mail/listeners");

var check = helpers.check;
var count = helpers.count;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var HOSTNAME         = "mx.example.com";

var GRANT      = '[{"cidr":"192.0.2.0/24","scope":"branch office"}]';
var GRANT_JSON = [{ cidr: "192.0.2.0/24", scope: "branch office" }];

// The words an operator has to find in the refusal. The setting name is
// what they search their own configuration for, and the alternative is
// the reason the refusal is a refusal rather than a removal: a message
// that only says no sends them looking for a bug.
var NAMES_THE_SETTING    = "relayAllowedFor";
var NAMES_THE_VARIABLE   = "BLAMEPOST_RELAY_ALLOWED_FOR";
var NAMES_THE_ALTERNATIVE = /submission/i;

function baseEnv(dataDir, extra) {
  return Object.assign({
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  }, extra || {});
}

// The file origin is selected by BLAMEPOST_CONFIG rather than by an
// argument, so both origins are driven through the same call and the
// only difference is which variable the caller set.
function loadRefusal(root, env) {
  var thrown = null;
  try {
    config.load({ env: env, cwd: root });
  } catch (e) { thrown = e; }
  return thrown;
}

// One refusal, measured the same way wherever it came from.
function aRefusalThatNamesTheWayOut(label, thrown) {
  count(label + " is refused", thrown !== null,
    thrown === null ? "nothing was thrown" : String(thrown.code));
  if (thrown === null) return;
  var message = String(thrown.message || "");
  count(label + " names the setting an operator would search for",
    message.indexOf(NAMES_THE_SETTING) !== -1 || message.indexOf(NAMES_THE_VARIABLE) !== -1,
    message);
  count(label + " points at authenticated submission instead of just saying no",
    NAMES_THE_ALTERNATIVE.test(message), message);
}

// ---- the loader ------------------------------------------------------------

function theEnvironmentVariableIsRefused(root, dataDir) {
  aRefusalThatNamesTheWayOut("a relay range set through the environment",
    loadRefusal(root, baseEnv(dataDir, { BLAMEPOST_RELAY_ALLOWED_FOR: GRANT })));
}

function theConfigurationFileKeyIsRefused(root, dataDir) {
  var filePath = nodePath.join(root, "relay.config.json");
  nodeFs.writeFileSync(filePath,
    JSON.stringify({ relayAllowedFor: GRANT_JSON }, null, 2), "utf8");
  aRefusalThatNamesTheWayOut("a relay range written into the configuration file",
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
  check("the loader still declares the relay setting rather than dropping it", row !== null);
  count("and still reads it from the variable the documents name",
    row !== null && row.env === NAMES_THE_VARIABLE, row === null ? "absent" : row.env);
}

// An operator who writes an empty list has said relay for nobody, which
// is what this server does. Refusing that would be a boot failure for
// agreeing with the default.
function anEmptyAllowlistIsNotAGrant(root, dataDir) {
  var thrown = loadRefusal(root, baseEnv(dataDir, { BLAMEPOST_RELAY_ALLOWED_FOR: "[]" }));
  count("an empty relay allowlist loads, because it grants nothing",
    thrown === null, thrown === null ? "loaded" : thrown.code + ": " + thrown.message);
}

function aConfigurationWithoutTheSettingLoads(root, dataDir) {
  var thrown = loadRefusal(root, baseEnv(dataDir));
  count("a configuration that never mentions relay loads",
    thrown === null, thrown === null ? "loaded" : thrown.code + ": " + thrown.message);
}

// ---- the listener composition ---------------------------------------------

// The loader is one of two doors. `blamepost.create` takes a
// configuration OBJECT, and every fixture in this suite builds one
// directly, so a refusal that lived only in the loader would be one an
// in-process composition never meets. The listener refuses on its own
// account, against the object it was handed.
function theListenerCompositionRefusesAGrant() {
  var thrown = null;
  try {
    listeners.create({
      config: {
        hostname:        HOSTNAME,
        relayAllowedFor: GRANT_JSON,
      },
    });
  } catch (e) { thrown = e; }
  aRefusalThatNamesTheWayOut("a relay range handed straight to the listener composition", thrown);
}

// And the same composition with no grant gets past the relay check to
// the ordinary construction refusals. Without this the case above would
// pass on a composition that refuses everything, which proves nothing
// about the relay check.
function theListenerCompositionRefusesAGrantForTheRelayReasonAlone() {
  var thrown = null;
  try {
    listeners.create({ config: { hostname: HOSTNAME } });
  } catch (e) { thrown = e; }
  count("a composition with no relay range is refused for something else entirely",
    thrown !== null && String(thrown.message || "").indexOf(NAMES_THE_SETTING) === -1,
    thrown === null ? "nothing was thrown" : String(thrown.message));
}

// ---- runner ----------------------------------------------------------------

function run() {
  var root    = helpers.tempDir("relay-grant-refusal");
  var dataDir = nodePath.join(root, "data");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  try {
    theSettingIsStillDeclared();
    theEnvironmentVariableIsRefused(root, dataDir);
    theConfigurationFileKeyIsRefused(root, dataDir);
    anEmptyAllowlistIsNotAGrant(root, dataDir);
    aConfigurationWithoutTheSettingLoads(root, dataDir);
    theListenerCompositionRefusesAGrant();
    theListenerCompositionRefusesAGrantForTheRelayReasonAlone();
  } finally {
    helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = { name: "relay-grant-refusal", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
