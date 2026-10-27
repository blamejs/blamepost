// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * config-schema: the setting table checked against itself, and against
 * the document that promises it.
 *
 * A configuration option fails in two directions, and neither one is
 * loud. An option the loader declares but no origin can reach is a knob
 * connected to nothing: the operator sets it, the boot succeeds, and the
 * value is discarded. An option a document names that the loader never
 * declares is worse, because the environment is a shared namespace where
 * an unrecognized variable is simply ignored, so the operator gets
 * silence and a server running the default they were trying to change.
 *
 * Both directions are swept here rather than reasoned about. Every
 * declared setting is supplied through the environment and through a
 * configuration file and has to come back changed; every `BLAMEPOST_`
 * variable the configuration documents name has to be one the loader
 * reads; and every variable the loader reads has to appear in one of
 * them. That is the rule the setting table states in its own header,
 * mechanized: a row, a default, and a line an operator can find, or it
 * does not ship.
 *
 * The table is also checked against itself. A default that its own shape
 * would refuse is a boot that fails only for the operator who never
 * touched the setting, and a bounded number written with no bounds is a
 * refusal message reading "between undefined and undefined".
 *
 * Nothing here opens a socket or a database. It writes configuration
 * files into a temporary directory, because a file is one of the two
 * origins under test and a loader checked against one origin has been
 * checked against half of itself.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/config-schema.test.js`.
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;
var count   = helpers.count;
var b       = helpers.b;
var config  = require("../../lib/config");

var REPO_ROOT        = helpers.REPO_ROOT;
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The two documents an operator configures this server from: the
// README's settings table and the operator guide's prose around DNS,
// ports and day-2 work. Every variable the loader reads is named in at
// least one of them, and neither names one the loader ignores.
var CONFIGURATION_DOCS = [
  nodePath.join(REPO_ROOT, "README.md"),
  nodePath.join(REPO_ROOT, "docs", "operator-guide.md"),
];

// The variable that names the configuration file is the one setting the
// file itself cannot carry, so it is declared apart from the table and
// belongs in every sweep over the loader's surface.
var CONFIG_PATH_VAR = "BLAMEPOST_CONFIG";

// The settings nothing reads while `zoneProvider` names no provider. The
// loader refuses each of them on its own in that state, so a sweep that
// drove one without naming a provider would be measuring the refusal
// instead of the setting.
var ZONE_NEEDS_PROVIDER = [
  "zoneApiToken", "zoneAllowMxWrites", "zoneEndpoint", "zoneAllowInternalEndpoint",
];

// A value of the right shape for each kind, distinct from every default
// so that reading it back proves the origin was read rather than that
// the default happened to match.
var SAMPLES = {
  hostname:  { env: "mx.test.example",             file: "mx.test.example" },
  path:      { env: "/srv/blamepost-sample",       file: "/srv/blamepost-sample" },
  port:      { env: "9101",                        file: 9101 },
  secret:    { env: "a different long passphrase for the sample",
               file: "a different long passphrase for the sample" },
  // A credential the vault has sealed under authenticated data, the way
  // the provider token is. The loader reads the prefix and nothing else,
  // because that is all that separates a sealed value from whatever
  // somebody typed, so the sample carries the framework's own prefix
  // rather than a string that merely looks like one. Taking the prefix
  // from the framework is what keeps this sample valid the day the
  // framework changes it.
  sealed:    { env: b.vault.aad.AAD_PREFIX + "c2FtcGxlZC1jcmVkZW50aWFs",
               file: b.vault.aad.AAD_PREFIX + "c2FtcGxlZC1jcmVkZW50aWFs" },
  email:     { env: "sample@test.example",         file: "sample@test.example" },
  url:       { env: "https://sample.test.example/client/v4",
               file: "https://sample.test.example/client/v4" },
  boolean:   { env: "true",                        file: true },
  integer:   { env: null,                          file: null },
  enum:      { env: null,                          file: null },
  timestamp: { env: "2099-01-01T00:00:00Z",        file: "2099-01-01T00:00:00Z" },
  object:    { env: null,                          file: null },
  array:     { env: null,                          file: null },
  file:      { env: null,                          file: null },
};

// The composite and bounded kinds cannot be filled from a table, because
// a valid value depends on the row: an array of URIs is not an array of
// MX hosts, and a bounded integer has to land inside its own bounds.
// Each is derived from the row it belongs to instead.
function sampleFor(setting) {
  if (setting.kind === "integer") {
    var mid = Math.floor((setting.min + setting.max) / 2);
    return { env: String(mid), file: mid };
  }
  if (setting.kind === "enum") {
    // The value that is NOT the default, so reading it back proves the
    // origin was read. A single-value enum has nothing to prove with.
    var other = setting.values.filter(function (v) { return v !== setting.fallback; });
    if (other.length === 0) return null;
    return { env: other[0], file: other[0] };
  }
  if (setting.kind === "array")  return arraySample(setting);
  if (setting.kind === "object") return objectSample(setting);
  if (setting.kind === "file")   return null;   // needs a real path; covered below
  var s = SAMPLES[setting.kind];
  return s && s.env !== null ? s : null;
}

function arraySample(setting) {
  var element = setting.element;
  var value;
  if (element.kind === "uri")     value = ["mailto:sample@test.example"];
  else if (element.kind === "url")     value = ["https://test.example/policy"];
  else if (element.kind === "mxHost")  value = ["mx1.test.example"];
  // RFC 5737 documentation space, network aligned so the loader's
  // alignment audit stays quiet, and carrying a mask because the CIDR
  // options refuse a bare address.
  else if (element.kind === "cidr")    value = ["192.0.2.0/24"];
  else if (element.kind === "object")  value = [objectSample(element).file];
  else if (element.kind === "integer") value = [element.min, Math.floor((element.min + element.max) / 2)];
  else return null;
  return { env: JSON.stringify(value), file: value };
}

// Ports handed out for a sample are drawn in sequence, because the
// loader refuses one port claimed twice and a table of listeners all
// sharing one number would be refused for that rather than read.
var _nextSamplePort = 9101;

function objectSample(shape) {
  var out = {};
  var names = shape.fields ? Object.keys(shape.fields) : shape.keys;
  for (var i = 0; i < names.length; i += 1) {
    var child = shape.fields ? shape.fields[names[i]] : shape.value;
    var value = null;
    if (child.kind === "enum")    value = child.values[child.values.length - 1];
    else if (child.kind === "integer") value = Math.floor((child.min + child.max) / 2);
    else if (child.kind === "boolean") value = true;
    else if (child.kind === "port")    { value = _nextSamplePort; _nextSamplePort += 1; }
    else if (child.kind === "address") value = "127.0.0.1";
    else if (child.kind === "cidr")    value = "192.0.2.0/24";
    else if (child.kind === "text")    value = "a sample scope";
    else if (child.kind === "array")   value = arraySample(child).file;
    else if (child.kind === "object")  value = objectSample(child).file;
    if (value !== null) out[names[i]] = value;
  }
  return { env: JSON.stringify(out), file: out };
}

// ---------------------------------------------------------------------------
// The table against itself
// ---------------------------------------------------------------------------

function walkShapes(shape, where, visit) {
  visit(shape, where);
  if (shape.fields) {
    Object.keys(shape.fields).forEach(function (name) {
      walkShapes(shape.fields[name], where + "." + name, visit);
    });
  }
  if (shape.value)   walkShapes(shape.value, where + ".<listener>", visit);
  if (shape.element) walkShapes(shape.element, where + "[]", visit);
}

function testEveryRowIsWellFormed() {
  var seenKeys = {};
  var seenVars = {};
  config.SETTINGS.forEach(function (s) {
    count("the " + s.key + " row names an environment variable",
      typeof s.env === "string" && s.env.indexOf("BLAMEPOST_") === 0, s.env);
    count("the " + s.key + " row describes what it sets",
      typeof s.describe === "string" && s.describe.length > 20, s.describe);
    check("the " + s.key + " row is the only one with that key",
      seenKeys[s.key] === undefined);
    check("the " + s.env + " variable is the only one with that name",
      seenVars[s.env] === undefined);
    seenKeys[s.key] = true;
    seenVars[s.env] = true;
    count("the " + s.key + " row is either required or carries a default",
      s.required === true || s.fallback !== undefined,
      "required=" + s.required + " fallback=" + s.fallback);
  });
}

function testEveryBoundedNumberDeclaresItsBounds() {
  config.SETTINGS.forEach(function (s) {
    walkShapes(s, s.key, function (shape, where) {
      if (shape.kind !== "integer") return;
      count("the bounded number at " + where + " declares a floor and a ceiling",
        Number.isInteger(shape.min) && Number.isInteger(shape.max) && shape.min <= shape.max,
        "min=" + shape.min + " max=" + shape.max);
    });
    walkShapes(s, s.key, function (shape, where) {
      if (shape.kind !== "array") return;
      count("the list at " + where + " declares how long it may be",
        Number.isInteger(shape.maxLength) && shape.maxLength > 0, shape.maxLength);
    });
  });
}

// A default that its own shape would refuse is a boot failure reserved
// for the operator who left the setting alone, which is the operator
// least equipped to recognize it.
function testEveryDefaultSurvivesItsOwnShape(root, dataDir) {
  var bare = config.load({ env: baseEnv(dataDir), cwd: root });

  config.SETTINGS.forEach(function (s) {
    var value = bare[s.key];
    if (value === null || value === undefined) return;
    if (s.required === true) return;              // no default to check
    var env = baseEnv(dataDir);
    env[s.env] = typeof value === "object" ? JSON.stringify(value) : String(value);
    var round = null;
    var thrown = null;
    try { round = config.load({ env: env, cwd: root })[s.key]; }
    catch (e) { thrown = e; }
    count("the default for " + s.key + " is a value the loader itself accepts",
      thrown === null, thrown === null ? "" : thrown.code + ": " + thrown.message);
    count("and supplying that default explicitly reads back unchanged",
      thrown !== null || JSON.stringify(round) === JSON.stringify(value),
      JSON.stringify(value) + " reads back as " + JSON.stringify(round));
  });
}

// ---------------------------------------------------------------------------
// Every declared setting can actually be set, from both origins
// ---------------------------------------------------------------------------

function baseEnv(dataDir, extra) {
  return Object.assign({
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  }, extra || {});
}

// A setting the server declares and does not honor. The row carries the
// sentence an operator reads when they set it, and this sweep drives it
// the same way it drives every other row: supply a value, and check what
// comes back. What comes back is a refusal rather than the value, so the
// two reachability sweeps below branch here rather than skipping.
//
// Branching on a declared property rather than on the setting's name is
// the whole point. A name would make this an exception somebody wrote
// into a test; the property makes it a category the table declares, and
// the next setting to land in it is covered without touching this file.
function isRefused(setting) {
  return typeof setting.refused === "string" && setting.refused.length > 0;
}

// A refused row is still driven from the origin, because the failure it
// guards against is the same one this whole file exists for: a variable
// the loader has stopped reading is a variable the operator sets to no
// effect and no message. Refusing is how it says so, so the refusal is
// what gets asserted.
function checkRefusedFromOrigin(setting, where, load) {
  var thrown = null;
  try { load(); } catch (e) { thrown = e; }
  count(setting.env + " is refused from " + where + " rather than ignored",
    thrown !== null && thrown.code === "config/setting-refused",
    thrown === null ? "the value was accepted" : thrown.code + ": " + thrown.message);
  if (thrown === null) return;
  count("and the refusal from " + where + " tells the operator what to do instead",
    String(thrown.message).indexOf(setting.refused) !== -1,
    String(thrown.message));
}

function testEverySettingIsReachableFromTheEnvironment(root, dataDir, certPath) {
  config.SETTINGS.forEach(function (s) {
    var sample = s.kind === "file" ? { env: certPath, file: certPath } : sampleFor(s);
    if (sample !== null && isRefused(s)) {
      var refusedEnv = baseEnv(dataDir);
      refusedEnv[s.env] = sample.env;
      checkRefusedFromOrigin(s, "the environment", function () {
        config.load({ env: refusedEnv, cwd: root });
      });
      return;
    }
    if (sample === null) {
      helpers.skip("no sample value is defined for the " + s.kind + " kind, so " +
        s.key + " was not driven from the environment");
      return;
    }
    var env = baseEnv(dataDir);
    env[s.env] = sample.env;
    // The two settings that are refused one without the other.
    if (s.key === "tlsCert") env.BLAMEPOST_TLS_KEY = certPath;
    if (s.key === "tlsKey")  env.BLAMEPOST_TLS_CERT = certPath;
    if (s.key === "adminEmail")    env.BLAMEPOST_ADMIN_PASSWORD = "a distinct administrator password";
    if (s.key === "adminPassword") env.BLAMEPOST_ADMIN_EMAIL = "admin@test.example";
    // The zone-writer group. Every setting under it is read only once a
    // provider client exists, so the loader refuses the group while the
    // provider names none: driving one of them alone would be driving
    // the refusal rather than the setting.
    if (ZONE_NEEDS_PROVIDER.indexOf(s.key) !== -1) env.BLAMEPOST_ZONE_PROVIDER = "cloudflare";
    if (s.key === "zoneAllowInternalEndpoint") {
      env.BLAMEPOST_ZONE_ENDPOINT = "https://zone-proxy.test.example/client/v4";
    }

    var loaded = null;
    var thrown = null;
    try { loaded = config.load({ env: env, cwd: root }); }
    catch (e) { thrown = e; }
    count(s.env + " is a variable the loader reads",
      thrown === null, thrown === null ? "" : thrown.code + ": " + thrown.message);
    if (thrown !== null) return;
    count(s.env + " changes the setting it names",
      JSON.stringify(loaded[s.key]) !== JSON.stringify(config.load({ env: baseEnv(dataDir), cwd: root })[s.key]),
      s.key + " read back as " + JSON.stringify(loaded[s.key]));
  });
}

// The file is driven as the ONLY origin here. Overlaying it under the
// environment would leave the three settings the environment supplies
// reading their environment value, so the check would pass without the
// file having been read at all.
function testEverySettingIsReachableFromTheFile(root, dataDir, certPath) {
  var filePath = nodePath.join(root, "one-setting.config.json");
  var required = {
    hostname:        "mx.example.com",
    dataDir:         dataDir,
    vaultPassphrase: VAULT_PASSPHRASE,
  };

  function loadFile(body) {
    nodeFs.writeFileSync(filePath, JSON.stringify(body), "utf8");
    return config.load({ env: { BLAMEPOST_CONFIG: filePath }, cwd: root });
  }

  var baseline = loadFile(required);

  config.SETTINGS.forEach(function (s) {
    var sample = s.kind === "file" ? { env: certPath, file: certPath } : sampleFor(s);
    if (sample !== null && isRefused(s)) {
      var refusedBody = Object.assign({}, required);
      refusedBody[s.key] = sample.file;
      checkRefusedFromOrigin(s, "the configuration file", function () { loadFile(refusedBody); });
      return;
    }
    if (sample === null) {
      helpers.skip("no sample value is defined for the " + s.kind + " kind, so " +
        s.key + " was not driven from a file");
      return;
    }
    var body = Object.assign({}, required);
    body[s.key] = sample.file;
    if (s.key === "tlsCert") body.tlsKey  = certPath;
    if (s.key === "tlsKey")  body.tlsCert = certPath;
    if (s.key === "adminEmail")    body.adminPassword = "a distinct administrator password";
    if (s.key === "adminPassword") body.adminEmail    = "admin@test.example";
    if (ZONE_NEEDS_PROVIDER.indexOf(s.key) !== -1) body.zoneProvider = "cloudflare";
    if (s.key === "zoneAllowInternalEndpoint") {
      body.zoneEndpoint = "https://zone-proxy.test.example/client/v4";
    }

    var loaded = null;
    var thrown = null;
    try { loaded = loadFile(body); } catch (e) { thrown = e; }
    count('the configuration file accepts a "' + s.key + '" key',
      thrown === null, thrown === null ? "" : thrown.code + ": " + thrown.message);
    if (thrown !== null) return;
    count('and a "' + s.key + '" key in the file changes the setting it names',
      JSON.stringify(loaded[s.key]) !== JSON.stringify(baseline[s.key]),
      s.key + " read back as " + JSON.stringify(loaded[s.key]));
  });
}

// ---------------------------------------------------------------------------
// Constraints the schema states, and has to enforce
// ---------------------------------------------------------------------------

// A shape whose description promises an ordering and does not check it
// hands the consumer a list it will read the wrong way round. The
// delivery path reads the last wait as the longest one it may hold a
// message for, so a falling list gives it the shortest under that name.
function testAnOrderedListIsRefusedOutOfOrder(root, dataDir) {
  var found = 0;
  config.SETTINGS.forEach(function (s) {
    walkShapes(s, s.key, function (shape, where) {
      if (shape.kind !== "array" || shape.ascending !== true) return;
      if (shape.element.kind !== "integer") return;
      found += 1;

      var rising  = [shape.element.min, shape.element.min * 2];
      var falling = [shape.element.min * 2, shape.element.min];
      var route   = where.split(".");            // "outboundRetry.backoffMs"
      var setting = config.SETTINGS.filter(function (row) { return row.key === route[0]; })[0];

      function loadWith(list) {
        var body = {};
        var cursor = body;
        for (var i = 1; i < route.length - 1; i += 1) {
          cursor[route[i]] = {};
          cursor = cursor[route[i]];
        }
        cursor[route[route.length - 1]] = list;
        var env = baseEnv(dataDir);
        env[setting.env] = JSON.stringify(body);
        return config.load({ env: env, cwd: root });
      }

      var refusedRising = null;
      try { loadWith(rising); } catch (e) { refusedRising = e; }
      count(where + " accepts a list that rises",
        refusedRising === null,
        refusedRising === null ? "" : refusedRising.code + ": " + refusedRising.message);

      var thrown = null;
      try { loadWith(falling); } catch (e) { thrown = e; }
      count(where + " refuses a list that falls, naming the entry that broke the order",
        thrown !== null && thrown.code === "config/bad-value" &&
        thrown.message.indexOf(where + "[1]") !== -1,
        thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);
    });
  });
  count("the ordered-list rule was driven against at least one shape", found > 0, found);
}

// ---------------------------------------------------------------------------
// Which origin wins
// ---------------------------------------------------------------------------

// The stated rule is that the environment wins over the file. The rule
// it does not state is what an empty variable means, and that one is
// load-bearing: a container runtime spells an unset value as an empty
// string, so reading one as "set to nothing" would turn every
// unsupplied optional into a refusal at boot.
function testAnEmptyVariableMeansUnset(root, dataDir) {
  var filePath = nodePath.join(root, "origins.config.json");
  nodeFs.writeFileSync(filePath, JSON.stringify({ logLevel: "debug", httpPort: 9090 }), "utf8");

  function loadWith(extra) {
    return config.load({
      env: baseEnv(dataDir, Object.assign({ BLAMEPOST_CONFIG: filePath }, extra)),
      cwd: root,
    });
  }

  check("a variable that carries a value wins over the file",
    loadWith({ BLAMEPOST_LOG_LEVEL: "warn" }).logLevel === "warn");
  check("an empty variable leaves the file's value alone",
    loadWith({ BLAMEPOST_LOG_LEVEL: "" }).logLevel === "debug");
  check("a variable holding only spaces does the same",
    loadWith({ BLAMEPOST_LOG_LEVEL: "   " }).logLevel === "debug");
  check("and with no file behind it, an empty variable takes the default",
    config.load({ env: baseEnv(dataDir, { BLAMEPOST_LOG_LEVEL: "" }), cwd: root }).logLevel === "info");

  // The file is this server's own document rather than a shared
  // namespace, so an empty value there is a typo and is refused. The two
  // origins differ on purpose, and the difference is worth pinning.
  var emptyInFile = nodePath.join(root, "empty-in-file.config.json");
  nodeFs.writeFileSync(emptyInFile, JSON.stringify({ logLevel: "" }), "utf8");
  var thrown = null;
  try {
    config.load({
      env: baseEnv(dataDir, { BLAMEPOST_CONFIG: emptyInFile }),
      cwd: root,
    });
  } catch (e) { thrown = e; }
  count("an empty value written in the file is refused rather than ignored",
    thrown !== null && thrown.code === "config/bad-value",
    thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);
}

// ---------------------------------------------------------------------------
// The bound on address enumeration
// ---------------------------------------------------------------------------

// The MX listener answers an address it does not host with a permanent
// refusal at RCPT, which is the right answer for a legitimate sender and
// is also an oracle: a stranger can walk a word list against it and
// learn which mailboxes exist here. `limits.rcptFailuresPerIpPerMinute`
// is how many guesses a minute one source gets before it is answered
// temporarily instead, so it is the setting that stands between this
// server and a directory harvest.
//
// It is refused at boot rather than clamped, and both ends of the range
// matter. Too high and the bound stops bounding. Too low and a
// legitimate sender with several recipients on one connection, or a
// mailing list expanding to addresses that have since closed, starts
// drawing temporary failures for ordinary mail.
function testTheRcptEnumerationBoundIsRefusedAtItsEdges(root, dataDir) {
  function loadLimits(value) {
    var thrown = null;
    var loaded = null;
    try {
      loaded = config.load({
        env: baseEnv(dataDir, { BLAMEPOST_LIMITS: JSON.stringify(value) }),
        cwd: root,
      });
    } catch (e) { thrown = e; }
    return { thrown: thrown, loaded: loaded };
  }

  var accepted = loadLimits({ rcptFailuresPerIpPerMinute: 20 });
  count("an operator may tighten the guess budget",
    accepted.thrown === null &&
    accepted.loaded.limits.rcptFailuresPerIpPerMinute === 20,
    accepted.thrown ? accepted.thrown.message : JSON.stringify(accepted.loaded.limits));

  var tooLow = loadLimits({ rcptFailuresPerIpPerMinute: 1 });
  count("a budget too low to pass ordinary multi recipient mail is refused",
    tooLow.thrown !== null && tooLow.thrown.code === "config/bad-value",
    tooLow.thrown === null ? "accepted" : tooLow.thrown.code);
  count("and the refusal names the field rather than the object it sits in",
    tooLow.thrown !== null && /rcptFailuresPerIpPerMinute/.test(tooLow.thrown.message),
    tooLow.thrown && tooLow.thrown.message.slice(0, 160));

  var tooHigh = loadLimits({ rcptFailuresPerIpPerMinute: 100000 });
  count("a budget so high it bounds nothing is refused too",
    tooHigh.thrown !== null && tooHigh.thrown.code === "config/bad-value",
    tooHigh.thrown === null ? "accepted" : tooHigh.thrown.code);

  // Left unset it keeps the shipped ceiling rather than becoming
  // unbounded, which is the direction that would matter.
  var unset = loadLimits({ maxMessageBytes: 1048576 });
  count("a limits object that does not name it leaves the shipped ceiling in place",
    unset.thrown === null &&
    unset.loaded.limits.rcptFailuresPerIpPerMinute === undefined,
    unset.thrown ? unset.thrown.message : JSON.stringify(unset.loaded.limits));
}

// ---------------------------------------------------------------------------
// The two report windows, held against each other
// ---------------------------------------------------------------------------

// A forensic DMARC report carries the envelope of a message belonging to
// somebody with no account on this server. An aggregate report carries
// counts. So a forensic window longer than the aggregate one keeps a
// stranger's addresses after the counting they belong to has been
// destroyed, which is the one ordering these two settings may not be
// written in.
//
// The store refuses it at construction. Refusing it at load is what puts
// the refusal in front of the operator at boot rather than at the first
// sweep, and both edges are driven because a rule asserted from one side
// alone is satisfied by a loader that refuses every pair.
function testTheForensicWindowCannotOutlastTheAggregateOne(root, dataDir) {
  function loadDays(aggregate, forensic, extra) {
    var supplied = Object.assign({
      BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS: String(aggregate),
      BLAMEPOST_DMARC_FORENSIC_RETENTION_DAYS:  String(forensic),
    }, extra || {});
    var thrown = null;
    var loaded = null;
    try { loaded = config.load({ env: baseEnv(dataDir, supplied), cwd: root }); }
    catch (e) { thrown = e; }
    return { thrown: thrown, loaded: loaded };
  }

  var shorter = loadDays(30, 7);
  count("a forensic window shorter than the aggregate one loads, and both settings read " +
    "back as the operator wrote them",
    shorter.thrown === null &&
    shorter.loaded.dmarcAggregateRetentionDays === 30 &&
    shorter.loaded.dmarcForensicRetentionDays === 7,
    shorter.thrown === null
      ? JSON.stringify([shorter.loaded.dmarcAggregateRetentionDays,
        shorter.loaded.dmarcForensicRetentionDays])
      : shorter.thrown.code + ": " + shorter.thrown.message);

  var equal = loadDays(14, 14);
  count("and one equal to it loads, because the rule is that it may not be the longer of " +
    "the two rather than that it has to be shorter",
    equal.thrown === null,
    equal.thrown === null ? "loaded" : equal.thrown.code + ": " + equal.thrown.message);

  var longer = loadDays(7, 14);
  count("a forensic window longer than the aggregate one stops the boot",
    longer.thrown !== null && longer.thrown.code === "config/retention-window-order",
    longer.thrown === null
      ? "14 forensic days were accepted against 7 aggregate ones"
      : longer.thrown.code + ": " + longer.thrown.message);
  count("and the refusal names both settings, so the operator knows which of the two to move",
    longer.thrown !== null &&
    String(longer.thrown.message).indexOf("BLAMEPOST_DMARC_FORENSIC_RETENTION_DAYS") !== -1 &&
    String(longer.thrown.message).indexOf("BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS") !== -1,
    longer.thrown === null ? "accepted" : String(longer.thrown.message).slice(0, 240));

  // The ordering is refused whatever the switch says. Waiting for the
  // setting that turns forensic reports on would leave the wrong pair on
  // disk until the moment somebody turns them on, which is the moment
  // they are least able to read a boot failure about retention.
  var switchedOff = loadDays(7, 14, { BLAMEPOST_DMARC_FORENSIC_ENABLED: "false" });
  count("the ordering is refused with forensic reports turned off as well, rather than " +
    "waiting for the setting that turns them on",
    switchedOff.thrown !== null && switchedOff.thrown.code === "config/retention-window-order",
    switchedOff.thrown === null ? "accepted" : switchedOff.thrown.code);
}

// The one setting in the table whose default is a privacy posture rather
// than a convenience. Turning it on stores the envelope of mail belonging
// to people who have no account on this server, so the shipped answer is
// off, and the sentence an operator reads before changing it has to say
// whose data it stores rather than only which feature it enables.
function testForensicStorageIsOffUntilAnOperatorAsksForIt(root, dataDir) {
  var bare = config.load({ env: baseEnv(dataDir), cwd: root });
  count("a server nobody configures does not store forensic DMARC reports",
    bare.dmarcForensicEnabled === false, String(bare.dmarcForensicEnabled));

  var row = config.SETTINGS.filter(function (s) {
    return s.key === "dmarcForensicEnabled";
  })[0];
  count("the switch has a row of its own in the setting table", row !== undefined);
  if (row === undefined) return;
  count("and the sentence beside it names whose data turning it on stores, rather than " +
    "only which feature it enables",
    /personal data/.test(row.describe) && /no account/.test(row.describe),
    row.describe);
}

// ---------------------------------------------------------------------------
// The file the loader opens
// ---------------------------------------------------------------------------

// The size limit exists so a runaway or hostile file is never parsed at
// all, and it only means that if the READ stops at the limit. A limit
// enforced against a size measured earlier holds nothing: the size and
// the bytes are two separate lookups of one path, and the second can
// resolve to something the first never described.
//
// The bound is driven at its exact edge from both sides, because an
// off-by-one either refuses a legal file or reads one byte past the cap
// on every boot.
function testTheConfigFileReadStopsAtTheLimit(root, dataDir) {
  var limit = 256 * 1024;                     // MAX_CONFIG_FILE_BYTES
  var filePath = nodePath.join(root, "sized.config.json");

  function padTo(bytes) {
    // A valid document whose only variable part is a comment-free filler
    // value, so size is the one thing under test.
    var head = '{"logLevel":"debug","adminEmail":"';
    var tail = '@test.example","adminPassword":"a distinct administrator password"}';
    var room = bytes - head.length - tail.length;
    return head + "a".repeat(Math.max(1, room)) + tail;
  }

  function loadSized(bytes) {
    nodeFs.writeFileSync(filePath, padTo(bytes), "utf8");
    return config.load({
      env: baseEnv(dataDir, { BLAMEPOST_CONFIG: filePath }),
      cwd: root,
    });
  }

  // At the cap the document is well-formed but its address is absurd, so
  // the refusal that matters is the one about the address rather than the
  // one about the size. Reaching that refusal is the proof the bytes were
  // read rather than rejected on length.
  var atLimit = null;
  try { loadSized(limit); } catch (e) { atLimit = e; }
  count("a file exactly at the limit is read rather than refused for its size",
    atLimit !== null && atLimit.code !== "config/file-too-large",
    atLimit === null ? "nothing was thrown" : atLimit.code + ": " + atLimit.message);

  var overLimit = null;
  try { loadSized(limit + 1); } catch (e) { overLimit = e; }
  count("one byte past the limit is refused, naming the limit",
    overLimit !== null && overLimit.code === "config/file-too-large" &&
    overLimit.message.indexOf(String(limit)) !== -1,
    overLimit === null ? "nothing was thrown" : overLimit.code + ": " + overLimit.message);
}

function testWhatTheLoaderDoesAboutAFileItCannotRead(root, dataDir) {
  var absent = nodePath.join(root, "no-such.config.json");
  var thrown = null;
  try {
    config.load({ env: baseEnv(dataDir, { BLAMEPOST_CONFIG: absent }), cwd: root });
  } catch (e) { thrown = e; }
  count("a named configuration file that does not exist is refused",
    thrown !== null && thrown.code === "config/file-missing",
    thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);

  var asDirectory = nodePath.join(root, "a-directory.config.json");
  nodeFs.mkdirSync(asDirectory, { recursive: true });
  var onDirectory = null;
  try {
    config.load({ env: baseEnv(dataDir, { BLAMEPOST_CONFIG: asDirectory }), cwd: root });
  } catch (e) { onDirectory = e; }
  count("a directory in place of the configuration file is refused",
    onDirectory !== null &&
    (onDirectory.code === "config/file-not-a-file" || onDirectory.code === "config/file-unreadable"),
    onDirectory === null ? "nothing was thrown" : onDirectory.code + ": " + onDirectory.message);

  // The default path is allowed to be absent, because the environment
  // alone is a complete configuration. Only a path the operator named
  // has to be there.
  var noFile;
  var refusedDefault = null;
  try {
    noFile = config.load({
      env: { BLAMEPOST_HOSTNAME: "mx.example.com", BLAMEPOST_DATA_DIR: dataDir,
             BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE },
      cwd: root,
    });
  } catch (e) { refusedDefault = e; }
  count("no configuration file at the default path is not a failure",
    refusedDefault === null && noFile.logLevel === "info",
    refusedDefault === null ? "" : refusedDefault.code + ": " + refusedDefault.message);
}

// ---------------------------------------------------------------------------
// The loader against the document that promises it
// ---------------------------------------------------------------------------

// Every variable the loader reads, including the narrow per-listener
// ports and the one that names the file.
function loaderVariables() {
  var names = [CONFIG_PATH_VAR];
  config.SETTINGS.forEach(function (s) { names.push(s.env); });
  config.LISTENER_NAMES.forEach(function (name) {
    names.push(config.LISTENER_DEFAULTS[name].portVar);
  });
  return names.sort();
}

// Every `BLAMEPOST_` variable named anywhere in the configuration
// documents, with the file each one came from, so a finding says which
// document to open.
function documentedVariables() {
  var found = {};
  CONFIGURATION_DOCS.forEach(function (file) {
    var text = nodeFs.readFileSync(file, "utf8");
    (text.match(/BLAMEPOST_[A-Z0-9_]+/g) || []).forEach(function (name) {
      if (found[name] === undefined) found[name] = [];
      if (found[name].indexOf(file) === -1) found[name].push(file);
    });
  });
  return found;
}

// The direction that has cost this project the most: a setting written
// down that no code reads. The environment is a shared namespace, so an
// unrecognized variable is not an error. The operator sets it, the boot
// succeeds, and the server runs the default they were trying to change.
function testTheDocumentsNameNothingTheLoaderIgnores() {
  var known = loaderVariables();
  var documented = documentedVariables();
  Object.keys(documented).sort().forEach(function (name) {
    var where = documented[name].map(function (file) { return nodePath.basename(file); });
    count(name + ", named in " + where.join(" and ") + ", is a variable the loader reads",
      known.indexOf(name) !== -1,
      "the loader reads: " + known.join(", "));
  });
}

// The default a document states, against the one the loader holds.
//
// A variable that exists and is documented can still lie, and this is the
// quiet way it does it: the table says one number, the loader falls back
// to another, and the operator who reads the table and leaves the setting
// alone gets the second one. Nothing fails, and the disagreement surfaces
// as behavior nobody can account for.
//
// A row is checked only where the loader has a concrete default to
// disagree with. Settings whose effective default is derived at use time,
// such as the postmaster address built from this server's own hostname,
// carry a null fallback and are described in prose rather than pinned to
// a value.
function expectedDefaults() {
  var wanted = {};
  config.SETTINGS.forEach(function (s) {
    if (s.fallback === undefined || s.fallback === null) return;
    wanted[s.env] = [String(s.fallback)];
  });
  config.LISTENER_NAMES.forEach(function (name) {
    var row = config.LISTENER_DEFAULTS[name];
    // The listener a port variable moves is as much a claim as the
    // number, and naming the wrong one sends the operator to open the
    // wrong port on the firewall.
    wanted[row.portVar] = [String(row.port), name];
  });
  wanted[CONFIG_PATH_VAR] = [config.DEFAULT_CONFIG_PATH];
  return wanted;
}

// A table row whose first cell is a backticked variable name. Only the
// cells that are a single backticked literal end to end count as values:
// those are the ones an operator copies. A cell of prose that happens to
// quote something, such as "Must be `1` before the MX listener binds", is
// a sentence rather than a stated default, and a row whose default cell
// is prose ("unset", "*see below*") states no value to disagree with.
var TABLE_ROW_RE = /^\|\s*`(BLAMEPOST_[A-Z0-9_]+)`\s*\|(.*\|)\s*$/;
var VALUE_CELL_RE = /^`([^`]+)`$/;

function valueCells(rest) {
  var cells = rest.split("|");
  var out = [];
  for (var i = 0; i < cells.length; i += 1) {
    var hit = VALUE_CELL_RE.exec(cells[i].trim());
    if (hit !== null) out.push(hit[1]);
  }
  return out;
}

function testADocumentedDefaultMatchesTheLoader() {
  var wanted = expectedDefaults();
  var rows = 0;
  CONFIGURATION_DOCS.forEach(function (file) {
    var where = nodePath.basename(file);
    nodeFs.readFileSync(file, "utf8").split(/\r?\n/).forEach(function (line, index) {
      var row = TABLE_ROW_RE.exec(line);
      if (row === null) return;
      var expect = wanted[row[1]];
      if (expect === undefined) return;
      var stated = valueCells(row[2]);
      if (stated.length === 0) return;
      rows += 1;
      expect.forEach(function (value) {
        count(where + ":" + (index + 1) + " states " + row[1] + " as the loader holds it, " + value,
          stated.indexOf(value) !== -1,
          "the row states " + JSON.stringify(stated));
      });
    });
  });
  count("at least one documented default was reconciled against the loader", rows > 0, rows);
}

// And the other direction. A setting with no line anywhere an operator
// reads is a setting only its author knows about.
function testEveryVariableTheLoaderReadsIsDocumented() {
  var documented = documentedVariables();
  loaderVariables().forEach(function (name) {
    count(name + " is documented where an operator configuring this server would find it",
      documented[name] !== undefined,
      "documented: " + Object.keys(documented).sort().join(", "));
  });
}

// The two calls that turn a loaded value into something that acts. A
// setting reaching the object the loader returns is half of what the
// header above calls a knob connected to something; these are the other
// half, and they are unit-checked here because both are pure enough to
// answer without a server.
//
// `blamepost.config.applyLogLevel` publishes the level to the variable
// the framework's boot logger reads, and
// `blamepost.config.logLevelInEffect` reads it back, so a caller that
// has to report a failure before any configuration was loaded still
// answers from the environment.
function testTheLogLevelIsPublishedAndReadBack() {
  var priorBoot = process.env.BLAMEJS_BOOT_LOG_LEVEL;
  var priorOwn  = process.env.BLAMEPOST_LOG_LEVEL;
  try {
    delete process.env.BLAMEJS_BOOT_LOG_LEVEL;
    delete process.env.BLAMEPOST_LOG_LEVEL;
    count("logLevelInEffect answers the shipped default when nothing has been set",
      config.logLevelInEffect() === "info", config.logLevelInEffect());
    count("and it reads the variable an operator set before any configuration was loaded",
      config.logLevelInEffect({ BLAMEPOST_LOG_LEVEL: "debug" }) === "debug");
    count("a value neither variable recognizes reads as the default rather than " +
      "stopping the caller that is already reporting a failure",
      config.logLevelInEffect({ BLAMEPOST_LOG_LEVEL: "loud" }) === "info");

    count("applyLogLevel returns the level it published",
      config.applyLogLevel({ logLevel: "debug" }) === "debug");
    count("and publishes it where the framework's boot logger reads it",
      process.env.BLAMEJS_BOOT_LOG_LEVEL === "debug",
      String(process.env.BLAMEJS_BOOT_LOG_LEVEL));
    count("so what it published is what logLevelInEffect answers next",
      config.logLevelInEffect() === "debug", config.logLevelInEffect());

    var refused = null;
    try { config.applyLogLevel({ logLevel: "loud" }); }
    catch (e) { refused = (e && e.code) || null; }
    count("a level the schema would refuse is refused here too, rather than published " +
      "and silently ignored by the logger",
      refused === "config/bad-config", String(refused));
  } finally {
    if (priorBoot === undefined) delete process.env.BLAMEJS_BOOT_LOG_LEVEL;
    else process.env.BLAMEJS_BOOT_LOG_LEVEL = priorBoot;
    if (priorOwn === undefined) delete process.env.BLAMEPOST_LOG_LEVEL;
    else process.env.BLAMEPOST_LOG_LEVEL = priorOwn;
  }
}

// `blamepost.config.assertAbsoluteDataDir` is what the subsystems that
// keep files call before they join a name onto the directory they were
// handed. The behavior it guards is measured against the running
// primitives in test/layer-1-state/data-dir-absolute.test.js; what is
// checked here is the guard itself, at both edges.
function testTheDataDirectoryGuardTakesAnAbsolutePathAndNothingElse() {
  var absolute = nodePath.resolve(nodePath.sep, "var", "lib", "blamepost");
  count("assertAbsoluteDataDir passes an absolute path back to its caller",
    config.assertAbsoluteDataDir("probe", absolute) === absolute, absolute);

  var refused = null;
  try { config.assertAbsoluteDataDir("probe: opts.dataDir", "data"); }
  catch (e) { refused = (e && e.message) || String(e); }
  count("and refuses a relative one, naming the caller that was handed it",
    refused !== null && refused.indexOf("probe: opts.dataDir") === 0 &&
      refused.indexOf("must be an absolute path") !== -1,
    String(refused).slice(0, 200));

  // The absent case belongs to each caller, which has its own sentence
  // about what it keeps under the directory. A guard that also refused
  // here would replace those sentences with one that says less.
  count("an absent value is left to the caller that has a better sentence for it",
    config.assertAbsoluteDataDir("probe", undefined) === undefined);
}

// ---------------------------------------------------------------------------
// A data directory that cannot be a directory
// ---------------------------------------------------------------------------

// The volume is one setting and six entries derived from it, and every
// one of them is created and written to. A path that already holds
// something of the wrong kind is therefore a configuration this server
// cannot honor, and it is answered the way the certificate paths beside
// it are answered: refuse it where the operator can still change it,
// naming the setting and the resolved path.
//
// What made it worth driving is what it did instead. A data directory
// naming a regular file loaded clean, and the failure arrived later out
// of `node:fs` as `EEXIST: file already exists, mkdir '<path>'`, which
// names neither `BLAMEPOST_DATA_DIR` nor the entry under it. An operator
// reading that line learns a path and has to work back to which of the
// settings produced it. The same hole covered a data directory under a
// regular file (`ENOTDIR`), a `blobs/` entry occupied by a file
// (`EEXIST`), and a `db.enc` that is a directory, which was accepted
// silently because the creation loop skips that entry.
//
// The refusals are asserted to carry BOTH the entry and the path, because
// a message with only the path is the one this replaces, and the two
// checks fail independently.
function testADataDirectoryThatCannotBeOneIsRefusedByName(root) {
  var here = nodePath.join(root, "volume-kinds");
  nodeFs.mkdirSync(here, { recursive: true });

  function loadDir(dir) {
    var thrown = null;
    var loaded = null;
    try { loaded = config.load({ env: baseEnv(dir), cwd: root }); }
    catch (e) { thrown = e; }
    return { thrown: thrown, loaded: loaded };
  }

  function ensure(loaded) {
    var thrown = null;
    try { config.ensureDataDirectories(loaded); }
    catch (e) { thrown = e; }
    return thrown;
  }

  // 1. The setting itself names a regular file. `load` reads the path the
  //    same way it reads a certificate path, so this is the one the
  //    operator can be told about without anything being created.
  var asFile = nodePath.join(here, "not-a-directory");
  nodeFs.writeFileSync(asFile, "occupied\n", "utf8");
  var onFile = loadDir(asFile);
  count("a data directory naming a regular file is refused while loading, rather than " +
    "accepted and failed later inside node:fs",
    onFile.thrown !== null && onFile.thrown.code === "config/bad-value",
    onFile.thrown === null ? "the value was accepted" : onFile.thrown.code);
  count("and that refusal names the variable the operator has to move",
    onFile.thrown !== null &&
    String(onFile.thrown.message).indexOf("BLAMEPOST_DATA_DIR") !== -1,
    onFile.thrown === null ? "accepted" : String(onFile.thrown.message).slice(0, 240));
  count("and it names the resolved path, so the operator can look at what is there",
    onFile.thrown !== null && String(onFile.thrown.message).indexOf(asFile) !== -1,
    onFile.thrown === null ? "accepted" : String(onFile.thrown.message).slice(0, 240));

  // 2. Under a regular file. Loading cannot see this one, because there is
  //    nothing at the path to read, so the refusal belongs to the call that
  //    creates the directories.
  var underFile = nodePath.join(asFile, "inside");
  var beneath = loadDir(underFile);
  count("a data directory under a regular file loads, because nothing is at the path to read",
    beneath.thrown === null,
    beneath.thrown === null ? "loaded" : beneath.thrown.code + ": " + beneath.thrown.message);
  if (beneath.thrown === null) {
    var beneathRefusal = ensure(beneath.loaded);
    count("and creating the volume refuses it with this server's own error class rather " +
      "than raising node's",
      beneathRefusal !== null && beneathRefusal.code === "config/data-directory-unusable",
      beneathRefusal === null ? "the directories were created"
        : beneathRefusal.code + ": " + beneathRefusal.message);
    count("and that refusal names the entry and the path",
      beneathRefusal !== null &&
      String(beneathRefusal.message).indexOf("dataDir") !== -1 &&
      String(beneathRefusal.message).indexOf(underFile) !== -1,
      beneathRefusal === null ? "created" : String(beneathRefusal.message).slice(0, 240));
  }

  // 3. The setting is fine and one entry under it is occupied. The entries
  //    are derived rather than written by the operator, so the refusal has
  //    to name which one, and nothing may be created before it.
  var clash = nodePath.join(here, "blobs-occupied");
  nodeFs.mkdirSync(clash, { recursive: true });
  nodeFs.writeFileSync(nodePath.join(clash, "blobs"), "occupied\n", "utf8");
  var occupied = loadDir(clash);
  count("a data directory whose blobs entry is occupied by a file still loads",
    occupied.thrown === null,
    occupied.thrown === null ? "loaded" : occupied.thrown.code);
  if (occupied.thrown === null) {
    var clashRefusal = ensure(occupied.loaded);
    count("and creating the volume refuses it, naming the entry that cannot be a directory",
      clashRefusal !== null && clashRefusal.code === "config/data-directory-unusable" &&
      String(clashRefusal.message).indexOf("blobs") !== -1,
      clashRefusal === null ? "the directories were created"
        : clashRefusal.code + ": " + clashRefusal.message);
    // Every entry is checked before any of them is created, which is the
    // rule the absolute-path check in the same call already states. A
    // refusal that left the entries ahead of the bad one already made
    // would answer the message and not the rule.
    count("and nothing was created before the refusal, so a half-made volume is not left " +
      "behind",
      !nodeFs.existsSync(nodePath.join(clash, "queue")) &&
      !nodeFs.existsSync(nodePath.join(clash, "keys")) &&
      !nodeFs.existsSync(nodePath.join(clash, "tls")),
      nodeFs.readdirSync(clash).join(", "));
  }

  // 4. The one entry the creation loop skips. It is a file rather than a
  //    directory, so a directory sitting on it is invisible to a loop that
  //    passes over it, and the first thing to notice is the store failing
  //    to open the database.
  var dbClash = nodePath.join(here, "database-occupied");
  nodeFs.mkdirSync(nodePath.join(dbClash, "db.enc"), { recursive: true });
  var onDb = loadDir(dbClash);
  if (onDb.thrown === null) {
    var dbRefusal = ensure(onDb.loaded);
    count("a directory sitting where the database file goes is refused rather than passed " +
      "over by the loop that skips that entry",
      dbRefusal !== null && dbRefusal.code === "config/data-directory-unusable" &&
      String(dbRefusal.message).indexOf("database") !== -1,
      dbRefusal === null ? "the volume was accepted"
        : dbRefusal.code + ": " + dbRefusal.message);
  }

  // The other edge. A refusal asserted on its own is satisfied by a call
  // that refuses every volume, so the two shapes an operator actually has
  // are driven too: a directory that is not there yet, and one that is.
  var fresh = nodePath.join(here, "fresh", "deeper");
  var freshLoad = loadDir(fresh);
  count("a data directory that does not exist yet is created, which is the ordinary first " +
    "boot",
    freshLoad.thrown === null && ensure(freshLoad.loaded) === null &&
    nodeFs.statSync(nodePath.join(fresh, "queue")).isDirectory(),
    freshLoad.thrown === null ? "loaded" : freshLoad.thrown.code);

  var again = loadDir(fresh);
  count("and a volume that is already there is accepted a second time, so a restart is not " +
    "a refusal",
    again.thrown === null && ensure(again.loaded) === null,
    again.thrown === null ? "loaded" : again.thrown.code);
}

// ---------------------------------------------------------------------------
// The zone writer, which is a group of settings rather than one
// ---------------------------------------------------------------------------

// Four settings that nothing reads until a provider is named, and one
// that names it. Set on their own they are the shape an operator cannot
// tell apart from a zone writer that is running: a sealed credential and
// an MX switch that reach nothing, and a server that says nothing about
// either. So the loader refuses the group, and each half of that is
// driven here.
//
// Both edges, because a rule asserted from one side alone is satisfied
// by a loader that refuses everything as much as by one that refuses
// nothing. The setting is refused without a provider AND accepted with
// one, and the value it reads back is the value that was supplied.
function testTheZoneWriterGroupIsRefusedWithoutAProvider(root, dataDir) {
  var SEALED = b.vault.aad.AAD_PREFIX + "c2VhbGVkLWZvci1vbmUtdGVzdA";
  var ENDPOINT = "https://zone-proxy.test.example/client/v4";

  var cases = [
    { label: "a sealed provider token",
      env:   { BLAMEPOST_ZONE_API_TOKEN: SEALED },
      key:   "zoneApiToken", expect: SEALED },
    { label: "the MX write switch",
      env:   { BLAMEPOST_ZONE_ALLOW_MX_WRITES: "true" },
      key:   "zoneAllowMxWrites", expect: true },
    { label: "a provider endpoint",
      env:   { BLAMEPOST_ZONE_ENDPOINT: ENDPOINT },
      key:   "zoneEndpoint", expect: ENDPOINT },
    { label: "permission to reach a private endpoint",
      env:   { BLAMEPOST_ZONE_ENDPOINT: ENDPOINT,
               BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "true" },
      key:   "zoneAllowInternalEndpoint", expect: true },
  ];

  cases.forEach(function (entry) {
    var refused = null;
    try { config.load({ env: baseEnv(dataDir, entry.env), cwd: root }); }
    catch (e) { refused = e; }
    count(entry.label + " is refused while BLAMEPOST_ZONE_PROVIDER names none, rather than " +
      "read by nothing",
      refused !== null && refused.code === "config/conflicting-settings",
      refused === null ? "the value was accepted" : refused.code + ": " + refused.message);

    var named = Object.assign({ BLAMEPOST_ZONE_PROVIDER: "cloudflare" }, entry.env);
    var loaded = null;
    var thrown = null;
    try { loaded = config.load({ env: baseEnv(dataDir, named), cwd: root }); }
    catch (e) { thrown = e; }
    count("and the same value loads once a provider is named, reading back what was set",
      thrown === null && loaded !== null &&
      JSON.stringify(loaded[entry.key]) === JSON.stringify(entry.expect),
      thrown === null ? entry.key + " read back as " +
        JSON.stringify(loaded && loaded[entry.key]) : thrown.code + ": " + thrown.message);
  });

  // Nothing at all under the group is the default, and it has to load:
  // an operator who never touched any of this gets a server with no zone
  // writer rather than a boot failure.
  var bare = null;
  var bareThrown = null;
  try { bare = config.load({ env: baseEnv(dataDir), cwd: root }); }
  catch (e) { bareThrown = e; }
  count("a configuration that names none of the group loads, and reads back as no provider",
    bareThrown === null && bare.zoneProvider === config.ZONE_PROVIDER_NONE &&
    bare.zoneApiToken === null && bare.zoneAllowMxWrites === false,
    bareThrown === null
      ? bare.zoneProvider + " / " + bare.zoneApiToken + " / " + bare.zoneAllowMxWrites
      : bareThrown.code + ": " + bareThrown.message);

  // The MX switch again, from the other direction. Its default is the
  // whole of the posture, so a change that flipped it would pass every
  // check above and be caught by nothing.
  count("and the MX write switch is off in that configuration, which is the posture rather " +
    "than an incidental value",
    bareThrown === null && bare.zoneAllowMxWrites === false,
    bareThrown === null ? String(bare.zoneAllowMxWrites) : bareThrown.code);

  // Permission to reach a private address without an address to reach.
  // The provider's public API is not a private address, so the
  // permission would grant nothing while an operator who set it believes
  // a proxy is in the path.
  var lonely = null;
  try {
    config.load({ env: baseEnv(dataDir, {
      BLAMEPOST_ZONE_PROVIDER: "cloudflare",
      BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "true",
    }), cwd: root });
  } catch (e) { lonely = e; }
  count("permission to reach a private endpoint is refused when no endpoint names one",
    lonely !== null && lonely.code === "config/conflicting-settings",
    lonely === null ? "the value was accepted" : lonely.code + ": " + lonely.message);
}

// The credential is a sealed value or it is refused, and the refusal
// happens at boot rather than at the moment a zone is being edited.
//
// Opening a seal passes a value that is not sealed straight through, so
// a raw token written into the configuration authenticates exactly as
// well as a sealed one while being readable to everyone who can read the
// file. The prefix is the only thing separating the two, which is why it
// is checked where the operator can still act on the answer.
function testARawProviderTokenIsRefused(root, dataDir) {
  var thrown = null;
  try {
    config.load({ env: baseEnv(dataDir, {
      BLAMEPOST_ZONE_PROVIDER:  "cloudflare",
      BLAMEPOST_ZONE_API_TOKEN: "fixtureDnsTokenZ8bC3dF6gH1jL5nS0aE2uT9iO",
    }), cwd: root });
  } catch (e) { thrown = e; }
  count("a provider token written into the configuration in the clear is refused at boot",
    thrown !== null && thrown.code === "config/bad-value",
    thrown === null ? "the value was accepted" : thrown.code);

  count("and the refusal names the command that produces the sealed form",
    thrown !== null && String(thrown.message).indexOf("blamepost zone token set") !== -1,
    thrown === null ? "accepted" : String(thrown.message).slice(0, 220));

  // The credential itself is never quoted back. A refusal that printed
  // the value would put the token in the terminal, in the shell's
  // scrollback and in whatever collects the boot output, which is the
  // failure this refusal exists to report.
  count("and the refusal does not echo the token it refused",
    thrown !== null && String(thrown.message).indexOf("Z8bC3dF6gH1jL5nS") === -1,
    thrown === null ? "accepted" : String(thrown.message).slice(0, 220));

  // And the same value in a file, because the file is the origin an
  // operator is most likely to paste a credential into.
  var filePath = nodePath.join(root, "raw-token.config.json");
  nodeFs.writeFileSync(filePath, JSON.stringify({
    hostname:        "mx.example.com",
    dataDir:         dataDir,
    vaultPassphrase: VAULT_PASSPHRASE,
    zoneProvider:    "cloudflare",
    zoneApiToken:    "fixtureDnsTokenZ8bC3dF6gH1jL5nS0aE2uT9iO",
  }), "utf8");
  var fromFile = null;
  try { config.load({ env: { BLAMEPOST_CONFIG: filePath }, cwd: root }); }
  catch (e) { fromFile = e; }
  count("a raw provider token in the configuration file is refused the same way",
    fromFile !== null && fromFile.code === "config/bad-value",
    fromFile === null ? "the value was accepted" : fromFile.code);

  // A value carrying the vault's plain seal. It is sealed, so it is not
  // exposed, and it is some other value a volume sealed, such as a signing
  // key, rather than the provider token.
  var plainSeal = null;
  try {
    config.load({ env: baseEnv(dataDir, {
      BLAMEPOST_ZONE_PROVIDER:  "cloudflare",
      BLAMEPOST_ZONE_API_TOKEN: b.constants.VAULT_PREFIX + "c2VhbGVkLWZvci1vbmUtdGVzdA",
    }), cwd: root });
  } catch (e) { plainSeal = e; }
  count("a value carrying the vault's plain seal is refused as sealed for another purpose " +
    "rather than as exposed",
    plainSeal !== null && plainSeal.code === "config/bad-value" &&
    String(plainSeal.message).indexOf("exposed") === -1 &&
    String(plainSeal.message).indexOf("blamepost zone token set") !== -1,
    plainSeal === null ? "the value was accepted" : String(plainSeal.message).slice(0, 260));

  // The redaction is a property of the row rather than of one call site,
  // so the value a support bundle would carry is checked here too.
  var sealed = b.vault.aad.AAD_PREFIX + "c2VhbGVkLWZvci1vbmUtdGVzdA";
  var loaded = config.load({ env: baseEnv(dataDir, {
    BLAMEPOST_ZONE_PROVIDER:  "cloudflare",
    BLAMEPOST_ZONE_API_TOKEN: sealed,
  }), cwd: root });
  count("a sealed token loads, and config.redacted masks it the way it masks the vault " +
    "passphrase",
    loaded.zoneApiToken === sealed &&
    config.redacted(loaded).zoneApiToken === "[redacted]",
    String(config.redacted(loaded).zoneApiToken));
}

// ---------------------------------------------------------------------------
// The one setting with a length floor
// ---------------------------------------------------------------------------

// The vault passphrase seals the DKIM private keys and every sealed
// column in the database, so a short one is an offline-guessing target
// against material that never rotates on its own. The settings
// reference prints a floor for it, and the floor is the whole of the
// promise: a passphrase one character short has to be refused at boot,
// where the operator can still choose another one.
//
// The number is read out of the document rather than out of the loader.
// A case comparing the loader against itself passes at any floor,
// including one low enough to accept a dictionary word, while the
// sentence an operator acted on went on printing sixteen. Both edges
// are driven, because a floor asserted from one side alone is satisfied
// by a loader that refuses everything or by one that refuses nothing.
var PASSPHRASE_FLOOR_RE = /At least (\d+) characters/;

function documentedPassphraseFloor() {
  var text = nodeFs.readFileSync(
    nodePath.join(REPO_ROOT, "docs", "operator-guide.md"), "utf8");
  var matched = PASSPHRASE_FLOOR_RE.exec(text);
  return matched === null ? null : parseInt(matched[1], 10);
}

function testTheVaultPassphraseFloorIsTheOneTheGuidePrints(root, dataDir) {
  var floor = documentedPassphraseFloor();
  count("the operator guide names a length floor for the vault passphrase, so this is " +
    "comparing something", floor !== null && floor > 0, String(floor));
  if (floor === null) return;

  function loadWith(chars) {
    var thrown = null;
    var loaded = null;
    try {
      loaded = config.load({
        env: baseEnv(dataDir, { BLAMEPOST_VAULT_PASSPHRASE: "p".repeat(chars) }),
        cwd: root,
      });
    } catch (e) { thrown = e; }
    return { thrown: thrown, loaded: loaded };
  }

  var short = loadWith(floor - 1);
  count("a passphrase one character under the floor the guide prints is refused at boot",
    short.thrown !== null && short.thrown.code === "config/bad-value",
    short.thrown === null ? "accepted " + (floor - 1) + " characters" : short.thrown.code);
  count("and the refusal names the number an operator has to reach rather than saying only " +
    "that it is short",
    short.thrown !== null && String(short.thrown.message).indexOf(String(floor)) !== -1,
    short.thrown === null ? "accepted" : String(short.thrown.message).slice(0, 200));

  var exact = loadWith(floor);
  count("a passphrase of exactly that length loads, so the floor is the number the guide " +
    "prints rather than merely at least it",
    exact.thrown === null &&
    exact.loaded.vaultPassphrase === "p".repeat(floor),
    exact.thrown === null ? "loaded" : exact.thrown.message);
}

// ---------------------------------------------------------------------------

function run() {
  var root    = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-config-schema-"));
  var dataDir = nodePath.join(root, "data");
  var cert    = nodePath.join(root, "cert.pem");
  nodeFs.writeFileSync(cert, "certificate bytes\n", "utf8");

  try {
    testEveryRowIsWellFormed();
    testEveryBoundedNumberDeclaresItsBounds();
    testEveryDefaultSurvivesItsOwnShape(root, dataDir);
    testEverySettingIsReachableFromTheEnvironment(root, dataDir, cert);
    testEverySettingIsReachableFromTheFile(root, dataDir, cert);
    testAnOrderedListIsRefusedOutOfOrder(root, dataDir);
    testAnEmptyVariableMeansUnset(root, dataDir);
    testTheRcptEnumerationBoundIsRefusedAtItsEdges(root, dataDir);
    testTheForensicWindowCannotOutlastTheAggregateOne(root, dataDir);
    testForensicStorageIsOffUntilAnOperatorAsksForIt(root, dataDir);
    testTheZoneWriterGroupIsRefusedWithoutAProvider(root, dataDir);
    testARawProviderTokenIsRefused(root, dataDir);
    testTheVaultPassphraseFloorIsTheOneTheGuidePrints(root, dataDir);
    testTheConfigFileReadStopsAtTheLimit(root, dataDir);
    testWhatTheLoaderDoesAboutAFileItCannotRead(root, dataDir);
    testTheDocumentsNameNothingTheLoaderIgnores();
    testADocumentedDefaultMatchesTheLoader();
    testEveryVariableTheLoaderReadsIsDocumented();
    testTheLogLevelIsPublishedAndReadBack();
    testTheDataDirectoryGuardTakesAnAbsolutePathAndNothingElse();
    testADataDirectoryThatCannotBeOneIsRefusedByName(root);
  } finally {
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
