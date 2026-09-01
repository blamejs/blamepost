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

// A value of the right shape for each kind, distinct from every default
// so that reading it back proves the origin was read rather than that
// the default happened to match.
var SAMPLES = {
  hostname:  { env: "mx.test.example",             file: "mx.test.example" },
  path:      { env: "/srv/blamepost-sample",       file: "/srv/blamepost-sample" },
  port:      { env: "9101",                        file: 9101 },
  secret:    { env: "a different long passphrase for the sample",
               file: "a different long passphrase for the sample" },
  email:     { env: "sample@test.example",         file: "sample@test.example" },
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
    testTheConfigFileReadStopsAtTheLimit(root, dataDir);
    testWhatTheLoaderDoesAboutAFileItCannotRead(root, dataDir);
    testTheDocumentsNameNothingTheLoaderIgnores();
    testADocumentedDefaultMatchesTheLoader();
    testEveryVariableTheLoaderReadsIsDocumented();
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
