// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * outbound-describe-reach: an option the outbound handle accepts is an
 * option its describe() reports.
 *
 * `blamepost.mail.delivery.describe()` is the one reading of the
 * outbound handle anything outside it has. `blamepost doctor` renders
 * it, the admin surface renders it, and a test asking whether a setting
 * took effect has nowhere else to look. An option the handle accepts and
 * describe() leaves out is a value an operator writes that nothing
 * downstream can see: no test can hold the handle to it, and the value
 * only has to survive as far as the line that forwards it to look
 * correct from every side.
 *
 * `outboundTimeouts` is the worked example. The loader declares
 * `BLAMEPOST_OUTBOUND_TIMEOUTS`, bounds both of its leaves and returns
 * the object, `lib/index.js` hands it to `blamepost.mail.delivery.create`
 * as `timeouts`, and the vendored composer reads `mxLookupMs` and
 * `perHostMs` off it. No module between the loader and that read names
 * either leaf, and the only test that named the setting asserted that
 * the loader returned what was written, which is the declaring call
 * rather than the enforcing one.
 *
 * Two questions are asked here, and they fail independently.
 *
 * THE CLASS. Every option the create block declares is either reported
 * by describe() at a named path, or listed below against a written
 * reason. The reason is refuted rather than trusted: an excluded option
 * is measured against the set `lib/index.js` actually hands over, so an
 * option excluded because nothing configures it is reported the day the
 * composition starts configuring it. The option list is read from the
 * `@opts` block of the primitive, which is the contract a reader of it
 * sees and the one `scripts/validate-source-comment-blocks.js` already
 * holds to a schema and an ordering.
 *
 * THE WORKED EXAMPLE. The timeout pair arrives through three doors and
 * each has to reach the same handle: the environment variable the
 * operator guide shows, the configuration file key, and a configuration
 * object handed straight to the delivery composition, which is what
 * `blamepost.create` builds. The loaded configuration is then handed to
 * the composition in the same run, because a door that reads the value
 * correctly and a composition that drops it are two halves that pass
 * their own measurements separately.
 *
 * The unset spelling is measured beside the written one. A handle that
 * reported a number whenever the key was absent would pass every
 * assertion about a configured pair while telling an operator who set
 * nothing that this server runs a wait it never chose, and the wait it
 * would be naming belongs to the vendored composer, which is free to
 * change it on a refresh.
 *
 * No sockets and no peer. It reads source text, loads configurations and
 * builds delivery handles under a temporary directory.
 *
 * Run standalone: node test/layer-0-primitives/outbound-describe-reach.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var blocks   = require("../../lib/web/wiki/blocks.js");
var config   = require("../../lib/config");
var delivery = require("../../lib/mail/delivery");

var check = helpers.check;
var count = helpers.count;

var REPO_ROOT     = helpers.REPO_ROOT;
var DELIVERY_FILE = nodePath.join(REPO_ROOT, "lib", "mail", "delivery.js");
var FACADE_FILE   = nodePath.join(REPO_ROOT, "lib", "index.js");
var CREATE_TOKEN  = "blamepost.mail.delivery.create";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var HOSTNAME         = "mx.example.com";

var SETTING_KEY      = "outboundTimeouts";
var SETTING_VARIABLE = "BLAMEPOST_OUTBOUND_TIMEOUTS";
// Inside the bounds the loader declares for both leaves, and different
// from the composer's own waits, so an assertion that passes cannot be
// satisfied by a handle reporting a default.
var WRITTEN          = { mxLookupMs: 5000, perHostMs: 30000 };

// Where describe() reports each option an operator can configure. A path
// is dotted from the root of the returned object.
var REPORTED_AT = {
  hostname:         ["hostname"],
  dataDir:          ["spoolDir"],
  postmaster:       ["postmaster"],
  policy:           ["policy.mtaSts", "policy.dane", "policy.dnssecValidated"],
  retry:            ["policy.maxAttempts", "policy.backoffMs"],
  timeouts:         ["timeouts.mxLookupMs", "timeouts.perHostMs"],
  spool:            ["spool.maxMessages", "spool.maxBytes"],
  requireTls:       ["requireTls"],
  sweepIntervalMs:  ["sweepIntervalMs"],
  tlsRptIntervalMs: ["tlsRpt.reportingIntervalMs"],
};

// The options describe() does not report, each against the reason and
// against whether `lib/index.js` hands it over. The second field is what
// refutes the first: an option left unreported because no configuration
// reaches it is reported here the moment a configuration does.
var NOT_REPORTED = [
  {
    key:      "port",
    composed: false,
    reason:   "the peer port a smarthost relay connects to. No setting reaches it and the " +
              "composition names it nowhere, so every handle this server builds delivers " +
              "to the port RFC 5321 assigns and a reported value could only ever restate it",
  },
  {
    key:      "resolver",
    composed: true,
    reason:   "a live DNS handle rather than a value an operator writes. What it changes is " +
              "where the MTA-STS record question is asked, and the posture that question " +
              "serves is reported as policy.mtaSts",
  },
  {
    key:      "maxMessageBytes",
    composed: true,
    reason:   "the ceiling the listeners accept a message at, handed here for one comparison " +
              "against spool.maxBytes at create and applied to no message by this handle. " +
              "listeners.describe() reports it beside the other ceilings the listeners run",
  },
  {
    key:      "tlsRptSubmit",
    composed: false,
    reason:   "the HTTPS client a report is submitted through. It is a handle rather than a " +
              "value, the composition names it nowhere, and what an operator asks about " +
              "reporting is reported under tlsRpt",
  },
  {
    key:      "audit",
    composed: false,
    reason:   "whether the framework emits audit rows for this handle. No setting reaches " +
              "it and the composition names it nowhere, so every handle this server builds " +
              "emits them",
  },
];

// ---- the option list, read from the contract --------------------------------

// Every key the create block declares, in the order it declares them.
function declaredOptions() {
  var records = blocks.collectPrimitives([DELIVERY_FILE]).filter(function (record) {
    return record.token === CREATE_TOKEN;
  });
  if (records.length !== 1 || typeof records[0].opts !== "string") return [];
  var keys = [];
  records[0].opts.split("\n").forEach(function (line) {
    var named = /^([A-Za-z_$][\w$]*)\s*:/.exec(line.trim());
    if (named !== null && keys.indexOf(named[1]) === -1) keys.push(named[1]);
  });
  return keys;
}

// Every key `lib/index.js` names in the object it builds the outbound
// handle from. The walk runs from the call to the line that closes it,
// and the two required options below are what says it reached the call
// rather than an empty stretch of the file.
function composedOptions() {
  var lines = nodeFs.readFileSync(FACADE_FILE, "utf8").split("\n");
  var keys  = [];
  var open  = -1;
  for (var i = 0; i < lines.length; i += 1) {
    if (lines[i].indexOf("delivery.create({") !== -1) { open = i; break; }
  }
  if (open === -1) return keys;
  for (var j = open + 1; j < lines.length; j += 1) {
    if (lines[j].trim() === "});") break;
    var named = /^ {4}([A-Za-z_$][\w$]*)\s*:/.exec(lines[j]);
    if (named !== null && keys.indexOf(named[1]) === -1) keys.push(named[1]);
  }
  return keys;
}

function reportsPath(described, path) {
  var here = described;
  var parts = path.split(".");
  for (var i = 0; i < parts.length; i += 1) {
    if (here === null || typeof here !== "object") return false;
    if (!Object.prototype.hasOwnProperty.call(here, parts[i])) return false;
    here = here[parts[i]];
  }
  return here !== undefined;
}

// ---- building a handle ------------------------------------------------------

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

// One option of every kind an operator can configure, each written to a
// value the shipped default is not, so a reported value that matches is
// the value that was written rather than one the handle would have
// reported anyway.
function _everyOptionWritten(dataDir) {
  return {
    postmaster:       "MAILER-DAEMON@" + HOSTNAME,
    policy:           { mtaSts: "testing", dane: "off" },
    retry:            { maxAttempts: 3, backoffMs: [60000, 120000] },
    timeouts:         WRITTEN,
    spool:            { maxMessages: 10, maxBytes: helpers.b.constants.BYTES.mib(64) },
    requireTls:       true,
    sweepIntervalMs:  5000,
    tlsRptIntervalMs: helpers.b.constants.TIME.hours(1),
    dataDir:          dataDir,
  };
}

// ---- the class --------------------------------------------------------------

function everyDeclaredOptionIsClassified(declared) {
  count("the create block still declares options, so this is comparing something",
    declared.length > 0, declared.length);

  var unclassified = declared.filter(function (key) {
    if (REPORTED_AT[key] !== undefined) return false;
    return !NOT_REPORTED.some(function (entry) { return entry.key === key; });
  });
  count("every option the outbound handle accepts is either reported by describe() or " +
    "written down here against the reason it is not. An option named here is accepted, " +
    "acted on and invisible from outside, so nothing can hold the handle to the value an " +
    "operator wrote: report it, or write down why it is not worth reporting",
    unclassified.length === 0, unclassified.join(", "), { limit: 2000 });

  var reportedNames = Object.keys(REPORTED_AT);
  var stale = reportedNames.concat(NOT_REPORTED.map(function (entry) { return entry.key; }))
    .filter(function (key) { return declared.indexOf(key) === -1; });
  count("and neither list names an option the block no longer declares, so a removed " +
    "option leaves with its row rather than standing over nothing",
    stale.length === 0, stale.join(", "));
}

function anExclusionIsMeasuredAgainstTheComposition(composed) {
  count("the composition still names options, so the refutation below is comparing " +
    "something rather than answering clean over an empty read",
    composed.length > 0, composed.join(", "));
  count("and the walk reached the call that builds the outbound handle, which names both " +
    "options it cannot be built without",
    composed.indexOf("hostname") !== -1 && composed.indexOf("dataDir") !== -1,
    composed.join(", "));

  NOT_REPORTED.forEach(function (entry) {
    count("the reason " + entry.key + " is not reported is a sentence somebody arriving " +
      "at this gate can act on",
      typeof entry.reason === "string" && entry.reason.length > 40, entry.reason);
    count("and it still describes the composition, which " +
      (entry.composed ? "does name " : "names no ") + entry.key,
      (composed.indexOf(entry.key) !== -1) === entry.composed,
      composed.indexOf(entry.key) !== -1 ? "composed" : "not composed");
  });
}

function everyReportedPathIsThere(dataDir) {
  var outcome = _composeDelivery(dataDir, _everyOptionWritten(dataDir));
  count("a handle naming every option an operator can configure is built",
    outcome.thrown === null,
    outcome.thrown === null ? "built" : String(outcome.thrown.message).slice(0, 200));
  if (outcome.thrown !== null) return;

  var missing = [];
  Object.keys(REPORTED_AT).forEach(function (key) {
    REPORTED_AT[key].forEach(function (path) {
      if (!reportsPath(outcome.described, path)) missing.push(key + " at " + path);
    });
  });
  count("and describe() reports every path this file says it reports, so the table above " +
    "is a reading of the handle rather than a description of one",
    missing.length === 0, missing.join(", "), { limit: 2000 });

  // The values, for the options whose reported path holds the written
  // value rather than a count taken off the volume.
  count("the posture describe() reports is the one that was written rather than the " +
    "shipped default",
    outcome.described.policy.mtaSts === "testing" && outcome.described.policy.dane === "off",
    outcome.described.policy.mtaSts + "/" + outcome.described.policy.dane);
  count("and so is the retry budget",
    outcome.described.policy.maxAttempts === 3 &&
    outcome.described.policy.backoffMs.length === 2,
    outcome.described.policy.maxAttempts + " attempt(s) over " +
    outcome.described.policy.backoffMs.length + " wait(s)");
}

// ---- the worked example: the doors a timeout pair arrives through -----------

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
// to succeed, and the pair it produces has to be the pair that was
// written.
function theOriginCarriesThePair(label, outcome) {
  count(label + " loads", outcome.thrown === null,
    outcome.thrown === null ? "loaded"
      : outcome.thrown.code + ": " + outcome.thrown.message);
  if (outcome.thrown !== null) return;
  var pair = outcome.loaded[SETTING_KEY];
  count(label + " carries both waits that were written",
    pair !== null && pair !== undefined &&
    pair.mxLookupMs === WRITTEN.mxLookupMs && pair.perHostMs === WRITTEN.perHostMs,
    JSON.stringify(pair));
}

function theSettingIsStillDeclared() {
  var row = null;
  config.SETTINGS.forEach(function (setting) {
    if (setting.key === SETTING_KEY) row = setting;
  });
  check("the loader declares the outbound timeout setting", row !== null);
  count("and reads it from the variable the documents name",
    row !== null && row.env === SETTING_VARIABLE, row === null ? "absent" : row.env);
  count("and bounds both waits, so a value written in seconds is refused at boot rather " +
    "than failing every delivery",
    row !== null && row.fields !== undefined &&
    row.fields.mxLookupMs !== undefined && row.fields.perHostMs !== undefined,
    row === null ? "absent" : Object.keys(row.fields || {}).join(", "));
}

function theEnvironmentVariableIsRead(root, dataDir) {
  theOriginCarriesThePair("the waits asked for through the environment",
    loadOrThrow(root, baseEnv(dataDir, {
      BLAMEPOST_OUTBOUND_TIMEOUTS: JSON.stringify(WRITTEN),
    })));
}

function theConfigurationFileKeyIsRead(root, dataDir) {
  var filePath = nodePath.join(root, "outbound-timeouts.config.json");
  var body = {};
  body[SETTING_KEY] = WRITTEN;
  nodeFs.writeFileSync(filePath, JSON.stringify(body, null, 2), "utf8");
  theOriginCarriesThePair("the waits written in the configuration file",
    loadOrThrow(root, baseEnv(dataDir, { BLAMEPOST_CONFIG: filePath })));
}

function aConfigurationWithoutTheSettingLeavesItToTheComposer(root, dataDir) {
  var outcome = loadOrThrow(root, baseEnv(dataDir));
  count("a configuration that never mentions the outbound waits loads",
    outcome.thrown === null,
    outcome.thrown === null ? "loaded"
      : outcome.thrown.code + ": " + outcome.thrown.message);
  count("and names no pair, which is what leaves both waits to the composer",
    outcome.thrown === null && outcome.loaded[SETTING_KEY] === null,
    outcome.thrown === null ? JSON.stringify(outcome.loaded[SETTING_KEY]) : "not loaded");
}

// The loader is one door of three. `blamepost.create` takes a
// configuration OBJECT, so a pair the loader read correctly and the
// composition dropped would still leave the handle running waits nobody
// wrote.
function theDeliveryCompositionCarriesThePair(dataDir) {
  var written = _composeDelivery(dataDir, { timeouts: WRITTEN });
  count("a delivery composition handed a pair of waits is built",
    written.thrown === null,
    written.thrown === null ? "built" : String(written.thrown.message).slice(0, 200));
  count("and reports both waits that were written",
    written.thrown === null && written.described.timeouts !== undefined &&
    written.described.timeouts.mxLookupMs === WRITTEN.mxLookupMs &&
    written.described.timeouts.perHostMs === WRITTEN.perHostMs,
    written.thrown === null ? JSON.stringify(written.described.timeouts) : "not built");

  // The control. Without it the case above would pass on a composition
  // that reported a fixed pair, which is the shape that tells an
  // operator who wrote nothing that this server runs waits it never
  // chose.
  var silent = _composeDelivery(dataDir);
  count("a delivery composition handed no waits names neither, because both are the " +
    "composer's to apply and a number reported here would be a second copy of one this " +
    "file never reads",
    silent.thrown === null && silent.described.timeouts !== undefined &&
    silent.described.timeouts.mxLookupMs === null &&
    silent.described.timeouts.perHostMs === null,
    silent.thrown === null ? JSON.stringify(silent.described.timeouts) : String(silent.thrown));

  // One leaf written and the other left alone, which is the ordinary
  // shape of a configuration: the two waits are independent settings and
  // a handle that read them as a pair would apply neither unless both
  // were named.
  var one = _composeDelivery(dataDir, { timeouts: { perHostMs: WRITTEN.perHostMs } });
  count("a composition naming one wait reports that one and leaves the other unnamed",
    one.thrown === null && one.described.timeouts !== undefined &&
    one.described.timeouts.perHostMs === WRITTEN.perHostMs &&
    one.described.timeouts.mxLookupMs === null,
    one.thrown === null ? JSON.stringify(one.described.timeouts) : String(one.thrown));
}

// The two halves joined: what the loader read is what the composition
// reports. Each half passes its own measurement while the value is
// dropped between them, which is the state this setting was in.
function theLoadedConfigurationReachesTheHandle(root, dataDir) {
  var outcome = loadOrThrow(root, baseEnv(dataDir, {
    BLAMEPOST_OUTBOUND_TIMEOUTS: JSON.stringify(WRITTEN),
  }));
  count("the configuration the composition is built from loads",
    outcome.thrown === null,
    outcome.thrown === null ? "loaded"
      : outcome.thrown.code + ": " + outcome.thrown.message);
  if (outcome.thrown !== null) return;

  var built = _composeDelivery(dataDir, { timeouts: outcome.loaded[SETTING_KEY] });
  count("and a handle built from it reports the waits the environment asked for, which is " +
    "the whole route from the variable an operator sets to the handle that delivers",
    built.thrown === null && built.described.timeouts !== undefined &&
    built.described.timeouts.mxLookupMs === WRITTEN.mxLookupMs &&
    built.described.timeouts.perHostMs === WRITTEN.perHostMs,
    built.thrown === null ? JSON.stringify(built.described.timeouts)
      : String(built.thrown.message).slice(0, 200));
}

// A wait that is not a number leaves undecided how long an attempt waits
// before it is abandoned, so it is refused at composition rather than
// coerced, and the refusal names the leaf an operator wrote.
function aWaitThatIsNotANumberIsRefused(dataDir) {
  var outcome = _composeDelivery(dataDir, { timeouts: { mxLookupMs: "soon" } });
  count("a wait that is not a number is refused at composition",
    outcome.thrown !== null,
    outcome.thrown === null ? "accepted" : String(outcome.thrown.message).slice(0, 160));
  count("and the refusal names the leaf an operator would search for",
    outcome.thrown !== null &&
    String(outcome.thrown.message).indexOf("mxLookupMs") !== -1,
    outcome.thrown === null ? "accepted" : String(outcome.thrown.message).slice(0, 160));
}

// ---- runner ----------------------------------------------------------------

function run() {
  var root    = helpers.tempDir("outbound-describe-reach");
  var dataDir = helpers.dataDir(root);
  try {
    var declared = declaredOptions();
    var composed = composedOptions();

    everyDeclaredOptionIsClassified(declared);
    anExclusionIsMeasuredAgainstTheComposition(composed);
    everyReportedPathIsThere(dataDir);

    theSettingIsStillDeclared();
    theEnvironmentVariableIsRead(root, dataDir);
    theConfigurationFileKeyIsRead(root, dataDir);
    aConfigurationWithoutTheSettingLeavesItToTheComposer(root, dataDir);
    theDeliveryCompositionCarriesThePair(dataDir);
    theLoadedConfigurationReachesTheHandle(root, dataDir);
    aWaitThatIsNotANumberIsRefused(dataDir);
  } finally {
    helpers.removeTempDir(root);
  }
  return helpers.getChecks();
}

module.exports = {
  name:      "outbound-describe-reach",
  run:       run,
  getChecks: helpers.getChecks,
};

if (require.main === module) {
  Promise.resolve().then(run).then(
    function (n) { console.log("CHECKS " + n); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
