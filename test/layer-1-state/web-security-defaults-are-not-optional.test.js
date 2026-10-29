// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The second half of the browser surface's security claim: not that the
 * eight controls are composed, but that no setting takes one away.
 *
 * test/layer-1-state/web-security-posture.test.js measures the first
 * half. Every assertion there is a request that has to be refused and
 * is, on the one configuration the file builds. A control can satisfy
 * all of it and still be reachable by a setting, because the file never
 * changes a setting: a surface whose bot guard reads a flag would refuse
 * the automation agent on the default and serve it on the other value,
 * and nothing in that file would ever see the other value.
 *
 * So the question here is the one the posture file structurally cannot
 * ask. It is asked three ways, because each of the three can be true
 * while the others are false.
 *
 * FROM SOURCE, THE CHAIN IS NOT WRITTEN AGAINST THE LOADER. Each of the
 * six middleware that carry these controls is located by the framework's
 * own published name, and the options each is handed are read. An option
 * list naming `config.` or `process.env` is a control whose posture a
 * setting decides, which is what the rule forbids, and it is reported
 * with the primitive and the text that reached it.
 *
 * FROM SOURCE, NOTHING IS TURNED OFF AT THE LIFECYCLE. The framework
 * mounts these same layers on its own request lifecycle and takes
 * `false` per layer to leave one out. Which layers are on by default
 * there is read out of the vendored tree rather than copied into this
 * file, so a framework that adds a default-on security layer is covered
 * the day it is vendored rather than when somebody remembers this list.
 * Every one of them has to be absent from the application's own
 * lifecycle options or present with something other than `false`.
 *
 * ON THE WIRE, UNDER A CONFIGURATION DRIVEN OFF ITS DEFAULTS. The
 * settings this browser surface reads are derived from its source, every
 * one of them is moved to a legal value it does not hold by default, the
 * server is booted on that, and each of the eight controls is measured
 * by a request that has to be refused. The derivation is the part that
 * keeps this honest: a setting that reaches the surface tomorrow and is
 * not in the swept set fails here rather than passing unmeasured.
 *
 * `trustedProxies` is the one setting that reaches these controls at
 * all, and it gets a vector of its own. It names the ranges whose
 * `X-Forwarded-Proto` this server believes, and that reading decides the
 * cookie prefix, the scheme the origin cross-check builds its baseline
 * from, whether the strict transport header is sent and whether a
 * credential is accepted. So the sweep names the range the reader
 * connects from, which is the most an operator can concede, and then
 * sends the header that reading was conceded for. A state change under
 * it still has to be refused.
 *
 * Run standalone:
 * node test/layer-1-state/web-security-defaults-are-not-optional.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var browser = require("../helpers/browser");
var certs   = require("../helpers/certs");
var wire    = require("../helpers/wire");

var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;
var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var READER_PASSWORD  = "quiet lantern bicycle 4291";

// Spelled unusually on purpose, for the reason the posture file gives:
// a common word would be absent from the volume for reasons that have
// nothing to do with sealing.
var READER_LOCAL   = "thornwhistle";
var READER_ADDRESS = READER_LOCAL + "@" + DOMAIN;
var READER_NAME    = "Thorn Whistle Ashgrove";
var SUBJECT        = "Quarterly ledger of the marchpane";
var BODY           = "cerulean4471 is the only copy of this sentence";

// The one file under the data directory that is cleartext by design.
// Finding it proves the scan reached the tree and can match a string.
var CLEARTEXT_CANARY = "BEGIN CERTIFICATE";

var FOREIGN_ORIGIN   = "https://attacker.example.net";
var AUTOMATION_AGENT = "curl/8.4.0";
var WRONG_TOKEN      = "0".repeat(64);

var TRUSTED_TYPES = "require-trusted-types-for 'script'";

var CROSS_SITE = Object.freeze({
  "Sec-Fetch-Site": "cross-site",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
});

var SHUTDOWN_TIMEOUT_MS = 5000;

var WEB_SOURCE = nodePath.join(helpers.REPO_ROOT, "lib", "web", "index.js");
var APP_SOURCE = nodePath.join(helpers.REPO_ROOT, "lib", "vendor", "blamejs",
  "lib", "app.js");

// ---- the eight, and where each one is composed -------------------------------

// The framework primitive each control is composed from. These are the
// published names on the surface `b` exports, so they survive every
// rename inside this repository and disappear only when the control
// itself is taken out, which is the shape a detector wants.
//
// Two of the eight are not middleware and are named beside the six that
// are: the session token is sealed by the primitive that mints it, and
// the volume is sealed by the database the store opens.
var MIDDLEWARE_CONTROLS = Object.freeze([
  { control: "CSRF",            primitive: "csrfProtect",      lifecycleKey: "csrf" },
  { control: "origin check",    primitive: "csrfProtect",      lifecycleKey: "csrf" },
  { control: "bot guard",       primitive: "botGuard",         lifecycleKey: "botGuard" },
  { control: "fetch metadata",  primitive: "fetchMetadata",    lifecycleKey: "fetchMetadata" },
  { control: "cookie prefixes", primitive: "cookies",          lifecycleKey: "cookies" },
  { control: "Trusted Types",   primitive: "securityHeaders",  lifecycleKey: "securityHeaders" },
]);

// A setting decides a control the moment one of these reaches the option
// list the control is built from.
var LOADER_REACH_RE = /\bconfig\s*\.|\bcfg\s*\.|process\s*\.\s*env/;

// Which line an offset sits on, so a finding names somewhere to look.
function lineOf(source, index) {
  return source.slice(0, index).split("\n").length;
}

// Each `b.middleware.<name>(` call in a source file, as the text from
// the opening parenthesis to the one that closes it, with the line it
// starts on.
//
// Balanced rather than bounded by a line budget: a call grows an option
// and a character count stops covering the end of it silently, which is
// the failure a dead matcher has. Balancing reaches the real end however
// long the option list becomes.
function callTextsFor(source, primitive) {
  var out    = [];
  var needle = "b.middleware." + primitive + "(";
  var at     = source.indexOf(needle);
  while (at !== -1) {
    var open  = at + needle.length - 1;
    var depth = 0;
    var i     = open;
    for (; i < source.length; i += 1) {
      if (source[i] === "(") depth += 1;
      else if (source[i] === ")") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    out.push({ text: source.slice(open, i + 1), line: lineOf(source, at) });
    at = source.indexOf(needle, i === source.length ? at + needle.length : i);
  }
  return out;
}

function testTheChainIsNotWrittenAgainstTheLoader(webSource) {
  var located = 0;
  for (var i = 0; i < MIDDLEWARE_CONTROLS.length; i += 1) {
    var entry = MIDDLEWARE_CONTROLS[i];
    var calls = callTextsFor(webSource, entry.primitive);
    count("the " + entry.control + " control is composed from b.middleware." +
      entry.primitive, calls.length > 0, calls.length + " call sites");
    if (calls.length === 0) continue;
    located += 1;

    var reached = calls.filter(function (call) { return LOADER_REACH_RE.test(call.text); });
    count("and no setting decides it: nothing in the options b.middleware." +
      entry.primitive + " is built from reads the loaded configuration",
      reached.length === 0,
      reached.length === 0
        ? "none"
        : "lib/web/index.js:" + reached[0].line + " " +
          JSON.stringify(reached[0].text.slice(0, 180)));
  }
  count("every control in the table was located in the browser surface, so the " +
    "assertions above answer for all of them",
    located === MIDDLEWARE_CONTROLS.length,
    located + " of " + MIDDLEWARE_CONTROLS.length);
  return located;
}

// ---- the framework's own lifecycle -------------------------------------------

// Which layers the framework mounts on its own request lifecycle unless
// told otherwise, read out of the vendored tree. `_resolveMiddlewareOpt`
// takes the layer's configuration, whether it is on by default, and its
// name, so the third argument of every call whose second is `true` is
// the list this file needs and nothing here has to hold a copy of it.
var DEFAULT_ON_RE =
  /_resolveMiddlewareOpt\(\s*mwConfig\.[A-Za-z0-9_]+\s*,\s*true\s*,\s*"([A-Za-z0-9_]+)"\s*\)/g;

function defaultOnLayers(appSource) {
  var names = [];
  var m;
  DEFAULT_ON_RE.lastIndex = 0;
  while ((m = DEFAULT_ON_RE.exec(appSource)) !== null) names.push(m[1]);
  return names;
}

// The object the application hands `b.createApp` as its `middleware`,
// from the brace that opens it to the one that closes it.
function lifecycleOptionsText(webSource) {
  var at = webSource.indexOf("b.createApp(");
  if (at === -1) return null;
  var key = webSource.indexOf("middleware:", at);
  if (key === -1) return null;
  var open = webSource.indexOf("{", key);
  if (open === -1) return null;
  var depth = 0;
  for (var i = open; i < webSource.length; i += 1) {
    if (webSource[i] === "{") depth += 1;
    else if (webSource[i] === "}") {
      depth -= 1;
      if (depth === 0) return webSource.slice(open, i + 1);
    }
  }
  return null;
}

function testNothingIsTurnedOffAtTheLifecycle(webSource, appSource) {
  var onByDefault = defaultOnLayers(appSource);
  count("the framework's default-on layers were read out of the vendored tree, so " +
    "this section answers for something", onByDefault.length > 0,
    JSON.stringify(onByDefault));

  var options = lifecycleOptionsText(webSource);
  count("the application's own lifecycle options were located",
    options !== null, options === null ? "none" : options.slice(0, 120));
  if (options === null) return 0;

  // A layer left out entirely keeps the framework's default, which is
  // on. A layer named with `false` is the one shape that removes it, and
  // it is the shape this looks for.
  var switchedOff = onByDefault.filter(function (name) {
    return new RegExp("\\b" + name + "\\s*:\\s*false\\b").test(options);
  });
  count("no layer the framework turns on by default is turned off where this " +
    "application builds its request lifecycle",
    switchedOff.length === 0,
    switchedOff.length === 0 ? "none" : JSON.stringify(switchedOff));

  // And the same question of the loader, because a layer switched off by
  // a setting reads as present here while an operator decides it.
  count("and no setting decides which of them are mounted",
    !LOADER_REACH_RE.test(options.replace(/protocolResolver:[^,\n]*/g, "")),
    options.slice(0, 200));

  // Each control's own key, so a framework that stops defaulting one of
  // them on is a finding rather than a silent change of posture.
  var unknown = MIDDLEWARE_CONTROLS.filter(function (entry) {
    return onByDefault.indexOf(entry.lifecycleKey) === -1;
  }).map(function (entry) { return entry.control + " (" + entry.lifecycleKey + ")"; });
  count("every control in the table is one the framework mounts by default, so " +
    "leaving it unnamed is what keeps it on",
    unknown.length === 0, unknown.length === 0 ? "none" : JSON.stringify(unknown));

  return onByDefault.length;
}

// ---- which settings reach the browser surface at all -------------------------

// Every setting the browser surface reads, derived from its source
// rather than listed here. `config.<key>` and `cfg.<key>` are the two
// names a consumer binds the loaded object to, which is the same reading
// test/layer-0-primitives/config-knob-reach.test.js takes of the tree.
//
// Comment text is not code, so a full-line comment is dropped and a
// trailing one is cut off the end of a code line. A key named in the
// sentence above a function is not that function reading it.
function settingsReadBy(source, declared) {
  var read  = [];
  var lines = String(source).split("\n");
  for (var i = 0; i < lines.length; i += 1) {
    var text = lines[i];
    if (/^\s*(\/\/|\*|\/\*)/.test(text)) continue;
    var slash = text.indexOf("//");
    while (slash > 0 && text[slash - 1] === ":") slash = text.indexOf("//", slash + 2);
    if (slash !== -1) text = text.slice(0, slash);
    for (var k = 0; k < declared.length; k += 1) {
      var key = declared[k];
      if (read.indexOf(key) !== -1) continue;
      if (new RegExp("\\b(?:config|cfg)\\s*\\.\\s*" + key + "\\b").test(text)) read.push(key);
    }
  }
  return read.sort();
}

// ---- the configuration the vectors are driven under --------------------------

// Every setting the browser surface reads, moved to a legal value it
// does not hold by default. `dataDir` and the ports are decided by the
// run rather than written here, and `paths` is derived from `dataDir`
// inside the loader, so neither is a value this table can carry.
function sweptEnv(dataDir, material) {
  return {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DNS_ACKNOWLEDGED: "1",
    BLAMEPOST_TLS_CERT:         material.certFile,
    BLAMEPOST_TLS_KEY:          material.keyFile,

    // The one setting that reaches these controls, named as wide as an
    // operator can name it: the range the reader below connects from.
    BLAMEPOST_TRUSTED_PROXIES:     JSON.stringify([LOOPBACK + "/32"]),
    // The front page on, which is the only other setting that changes
    // what this surface serves a reader with no session.
    BLAMEPOST_PUBLIC_SITE_ENABLED: "true",
    BLAMEPOST_MTA_STS_MODE:        "testing",
    BLAMEPOST_MTA_STS_MAX_AGE:     "86400",
    BLAMEPOST_MTA_STS_MX:          JSON.stringify([HOSTNAME]),
    BLAMEPOST_SECURITY_CONTACT:    JSON.stringify(["mailto:security@example.com"]),
    BLAMEPOST_SECURITY_POLICY_URL: JSON.stringify(["https://example.com/security"]),
    BLAMEPOST_SECURITY_TXT_EXPIRES: "2027-01-01T00:00:00Z",
    // Off the defaults everywhere else the loader reaches, so a control
    // reading one of these would be reading the other value here.
    BLAMEPOST_PROFILE:             "balanced",
    BLAMEPOST_COMPLIANCE_POSTURE:  "soc2",
    BLAMEPOST_LOG_LEVEL:           "error",
    BLAMEPOST_REQUIRE_TLS:         "true",
    BLAMEPOST_DMARC_FORENSIC_ENABLED: "true",
  };
}

// The names above that are settings rather than the run's own values.
function sweptKeys(env, declared) {
  var byVar = {};
  config.SETTINGS.forEach(function (row) { byVar[row.env] = row.key; });
  var keys = [];
  Object.keys(env).forEach(function (name) {
    var key = byVar[name];
    if (key !== undefined && declared.indexOf(key) !== -1) keys.push(key);
  });
  return keys.sort();
}

// Every mail listener off. The browser surface is what this file is
// about, and a port taken is a port another file in the same run cannot
// have.
async function listenerSections() {
  var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
  var sections = {};
  for (var i = 0; i < names.length; i += 1) {
    sections[names[i]] = {
      enabled: false,
      port:    await wire.reservePort(),
      address: LOOPBACK,
    };
  }
  return sections;
}

function messageFor(recipient) {
  return Buffer.from(
    "Message-ID: <swept@example.net>\r\n" +
    "From: Sender <sender@example.net>\r\n" +
    "To: <" + recipient + ">\r\n" +
    "Subject: " + SUBJECT + "\r\n" +
    "Date: Sat, 22 Aug 2026 09:00:00 +0000\r\n" +
    "\r\n" + BODY + "\r\n", "utf8");
}

// ---- the eight, measured on the wire under that configuration ----------------

// One state-changing route is enough here, because the posture file
// already sweeps each refusal across every route on the surface. What
// this adds is the configuration, not a second copy of that sweep.
var ROUTE = "/mail/actions?folder=INBOX";

async function testCsrfStillRefusesUnderTheSweptConfiguration(reader) {
  var untokened = await reader.post(ROUTE, "application/x-www-form-urlencoded",
    "action=flag", { "X-CSRF-Token": "" });
  count("a state change carrying no token is refused under the swept configuration",
    untokened.status === 403, untokened.status + " " + untokened.body.slice(0, 160));
  count("and the refusal is the token compare rather than another gate on the chain",
    untokened.body.indexOf("CSRF token mismatch") !== -1, untokened.body.slice(0, 160));

  var wrong = await reader.post(ROUTE, "application/x-www-form-urlencoded",
    "action=flag", { "X-CSRF-Token": WRONG_TOKEN });
  count("a state change carrying a wrong token is refused under it too",
    wrong.status === 403, wrong.status + " " + wrong.body.slice(0, 160));
}

async function testTheOriginCrossCheckStillRefusesUnderIt(reader) {
  var foreign = await reader.form(ROUTE, { action: "flag" }, { Origin: FOREIGN_ORIGIN });
  count("a state change from another origin is refused under the swept configuration, " +
    "carrying a valid token", foreign.status === 403,
    foreign.status + " " + foreign.body.slice(0, 160));
  count("and the refusal is the origin cross check",
    foreign.body.indexOf("cross-origin request refused") !== -1,
    foreign.body.slice(0, 160));
}

async function testFetchMetadataStillRefusesUnderIt(reader, origin) {
  var crossSite = await reader.form(ROUTE, { action: "flag" },
    Object.assign({ Origin: origin }, CROSS_SITE));
  count("a state change a browser reports as cross site is refused under the swept " +
    "configuration", crossSite.status === 403,
    crossSite.status + " " + crossSite.body.slice(0, 160));
  count("and the refusal is the fetch metadata gate rather than either CSRF check",
    crossSite.body.indexOf("Cross-site request refused") !== -1,
    crossSite.body.slice(0, 160));
}

async function testTheBotGuardStillRefusesUnderIt(origin, caPem) {
  var robot  = browser.browserAt(origin, { ca: caPem, userAgent: AUTOMATION_AGENT });
  var turned = await robot.get("/sign-in");
  count("an automation agent is refused under the swept configuration",
    turned.status === 403, turned.status + " " + turned.body.slice(0, 80));

  // The differential, and the one that decides whether the sweep proved
  // a guard or a surface that stopped answering. The front page is on
  // under this configuration, so a browser agent reaches a page here
  // that the default configuration does not serve at all.
  var human  = browser.browserAt(origin, { ca: caPem });
  var served = await human.get("/sign-in");
  count("while a browser agent is still served the sign in page",
    served.status === 200 && served.body.indexOf("_csrf") !== -1,
    served.status + " " + served.body.slice(0, 80));
}

function testTheCookiePrefixStillHoldsUnderIt(page) {
  var written = page.setCookie.filter(function (line) {
    return String(line).indexOf("__Host-csrf=") === 0;
  });
  count("the double submit cookie still carries the host prefix under the swept " +
    "configuration", written.length === 1,
    JSON.stringify(page.setCookie.map(function (l) { return String(l).split(";")[0]; })));
  if (written.length !== 1) return;

  var attributes = String(written[0]);
  count("it is still Secure, which the prefix requires",
    /;\s*Secure/i.test(attributes), attributes.slice(-120));
  count("it is still scoped to the whole origin, which the prefix requires",
    /;\s*Path=\/(?:;|$)/i.test(attributes), attributes.slice(-120));
  count("it still carries no Domain attribute, which the prefix also requires",
    !/;\s*Domain=/i.test(attributes), attributes.slice(-120));
}

async function testTrustedTypesStillHoldUnderIt(reader) {
  var pages = [
    { what: "a rendered page",       answer: await reader.get("/sign-in") },
    { what: "an authenticated page", answer: await reader.get("/mail?folder=INBOX") },
    { what: "the front page the sweep turned on", answer: await reader.get("/") },
    { what: "a refusal body",        answer: await reader.post(ROUTE,
      "application/x-www-form-urlencoded", "action=flag", { "X-CSRF-Token": "" }) },
  ];
  for (var i = 0; i < pages.length; i += 1) {
    var policy = String(pages[i].answer.headers["content-security-policy"] || "");
    count("the policy on " + pages[i].what + " still requires typed values at every " +
      "DOM sink under the swept configuration",
      policy.indexOf(TRUSTED_TYPES) !== -1,
      pages[i].answer.status + " " +
      (policy.length === 0 ? "<no policy>" : policy.slice(-140)));
  }
}

function testTheSessionTokenIsStillSealedUnderIt(landing) {
  var written = landing.setCookie.filter(function (line) {
    return String(line).indexOf("__Host-bp_session=") === 0;
  });
  count("signing in under the swept configuration writes one session cookie under the " +
    "host prefixed name", written.length === 1,
    JSON.stringify(landing.setCookie.map(function (l) { return String(l).split(";")[0]; })));
  if (written.length !== 1) return;

  var value = decodeURIComponent(
    String(written[0]).split(";")[0].split("=").slice(1).join("="));
  count("and the value the browser carries is still sealed rather than the identifier " +
    "itself", value.indexOf("vault:") === 0, value.slice(0, 48));
  count("with nothing about the account legible in it",
    value.indexOf(READER_LOCAL) === -1 && value.indexOf(DOMAIN) === -1,
    value.slice(0, 96));
}

// ---- the setting that does reach the chain ----------------------------------

// `trustedProxies` names the ranges whose `X-Forwarded-Proto` this
// server believes, and the sweep above named the range this reader
// connects from. So this reader can now state the browser's half of the
// transport, which is the most a setting on this surface can concede.
//
// What it must not buy is a state change. The transport reading decides
// the cookie prefix and the scheme the origin baseline is built from,
// and a request that drives it backwards is still a cross-site write
// with no token behind it.
async function testTheTransportSettingBuysNoStateChange(reader, origin) {
  var downgraded = await reader.form(ROUTE, { action: "flag" },
    { "X-Forwarded-Proto": "http" });
  count("a request stating the browser reached this server in the clear, under a " +
    "setting that makes this server believe it, does not perform a state change",
    downgraded.status !== 302, downgraded.status + " " + downgraded.body.slice(0, 160));

  var foreign = await reader.form(ROUTE, { action: "flag" },
    { "X-Forwarded-Proto": "http", Origin: FOREIGN_ORIGIN });
  count("and neither does the same request from another origin",
    foreign.status === 403, foreign.status + " " + foreign.body.slice(0, 160));

  // The differential. A surface that refused every request carrying the
  // header would satisfy both of those and would also be one no operator
  // can put a terminator in front of.
  var ordinary = await reader.form("/prefs/theme", { theme: "dark" },
    { "X-Forwarded-Proto": "https", Origin: origin });
  count("while the same reader's ordinary form submit is still performed",
    ordinary.status === 302, ordinary.status + " " + ordinary.body.slice(0, 160));
}

// ---- sealed storage ----------------------------------------------------------

// Read after the store closes, so what is measured is the volume an
// operator backs up rather than a process still holding the key. The
// counts are the point: a search that finds nothing because it opened
// nothing is the failure a clean verdict cannot be told apart from.
function scanTree(dir, needles, found) {
  var entries;
  try { entries = nodeFs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return found; }
  for (var i = 0; i < entries.length; i += 1) {
    var full = nodePath.join(dir, entries[i].name);
    if (entries[i].isDirectory()) { scanTree(full, needles, found); continue; }
    var bytes;
    try { bytes = nodeFs.readFileSync(full); }
    catch (_e) { continue; }
    found.files += 1;
    found.bytes += bytes.length;
    for (var n = 0; n < needles.length; n += 1) {
      if (bytes.indexOf(Buffer.from(needles[n], "utf8")) !== -1) {
        found.hits.push(needles[n].slice(0, 48) + " in " + nodePath.basename(full));
      }
    }
  }
  return found;
}

function testTheVolumeIsStillSealedUnderIt(dataDir) {
  var sealed = [READER_ADDRESS, READER_NAME, SUBJECT, BODY];
  var found  = scanTree(dataDir, sealed.concat([CLEARTEXT_CANARY]),
    { files: 0, bytes: 0, hits: [] });

  count("the scan read the whole volume rather than an empty directory",
    found.files >= 5 && found.bytes > 100000,
    found.files + " files, " + found.bytes + " bytes");
  count("it can see cleartext, proven on the certificate the operator supplied",
    found.hits.filter(function (h) { return h.indexOf(CLEARTEXT_CANARY) === 0; })
      .length === 1, JSON.stringify(found.hits));

  var leaked = found.hits.filter(function (h) { return h.indexOf(CLEARTEXT_CANARY) !== 0; });
  count("and no address, name, subject or body survives in any byte of a volume " +
    "written under the swept configuration", leaked.length === 0, JSON.stringify(leaked));
}

// ---- the drive ---------------------------------------------------------------

async function run() {
  var webSource = nodeFs.readFileSync(WEB_SOURCE, "utf8");
  var appSource = nodeFs.readFileSync(APP_SOURCE, "utf8");

  var located    = testTheChainIsNotWrittenAgainstTheLoader(webSource);
  var defaultOn  = testNothingIsTurnedOffAtTheLifecycle(webSource, appSource);

  var declared = config.SETTINGS.map(function (row) { return row.key; });
  count("the loader published its settings, so the sweep below answers for a table " +
    "rather than for an empty list", declared.length > 0, declared.length + " settings");

  var reachable = settingsReadBy(webSource, declared);
  count("the settings the browser surface reads were derived from its source",
    reachable.length > 0, JSON.stringify(reachable));

  var root    = helpers.tempDir("web-defaults-swept");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  var server   = null;
  var running  = false;
  try {
    var material = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });
    var env = sweptEnv(dataDir, material);

    // The assertion that keeps this file honest as the surface grows. A
    // setting that starts reaching the browser surface and is not moved
    // off its default here is measured by nothing, and this is where
    // that is reported rather than where it is discovered.
    var swept   = sweptKeys(env, declared);
    var unswept = reachable.filter(function (key) {
      // Decided by the run rather than by the table above: the data
      // directory is a temporary one and the ports are ephemeral, and
      // `paths` is derived from the data directory inside the loader.
      if (key === "dataDir" || key === "httpPort" || key === "httpsPort") return false;
      return swept.indexOf(key) === -1;
    });
    count("every setting the browser surface reads is driven off its default by the " +
      "sweep below, so a control reading one would be reading the other value",
      unswept.length === 0, JSON.stringify(unswept));

    var cfg = config.load({ env: env, cwd: root });
    count("the swept configuration loads, so the refusals below are measured under it " +
      "rather than under a configuration that was rejected",
      cfg.trustedProxies !== null && cfg.publicSiteEnabled === true,
      JSON.stringify([cfg.trustedProxies, cfg.publicSiteEnabled, cfg.profile]));

    identity = await store.open(cfg);
    await identity.domains.add({ domain: DOMAIN });
    var reader = await identity.accounts.create({
      address:     READER_ADDRESS,
      password:    READER_PASSWORD,
      displayName: READER_NAME,
    });
    identity.mailbox.appendMessage("INBOX", messageFor(READER_ADDRESS),
      { actor: { id: reader.id } });

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: await listenerSections(),
      }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
    });
    await server.start();
    running = true;

    var bound = server.web.bound();
    count("the browser surface took a TLS port under the swept configuration",
      typeof bound.https === "number" && bound.https > 0, JSON.stringify(bound));

    var origin  = "https://" + LOOPBACK + ":" + bound.https;
    var session = browser.browserAt(origin, { ca: material.caPem });

    var form = await session.readCsrf("/sign-in");
    count("the sign in form carries a token for the reader to send back",
      form.token.length === 64, form.page.status + " " + JSON.stringify(form.token));
    testTheCookiePrefixStillHoldsUnderIt(form.page);

    var landing = await session.signIn(READER_ADDRESS, READER_PASSWORD);
    count("the reader is signed in under the swept configuration", landing.status === 302,
      landing.status + " " + landing.body.slice(0, 160));
    testTheSessionTokenIsStillSealedUnderIt(landing);

    await testCsrfStillRefusesUnderTheSweptConfiguration(session);
    await testTheOriginCrossCheckStillRefusesUnderIt(session);
    await testFetchMetadataStillRefusesUnderIt(session, origin);
    await testTrustedTypesStillHoldUnderIt(session);
    await testTheTransportSettingBuysNoStateChange(session, origin);
    await testTheBotGuardStillRefusesUnderIt(origin, material.caPem);

    count("the reader still holds their session after every refusal above, so those " +
      "were refusals rather than a sign out",
      (await session.get("/mail?folder=INBOX")).status === 200, "checked");

    await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS });
    running = false;
    identity.close();
    identity = null;

    testTheVolumeIsStillSealedUnderIt(dataDir);

    // What this file examined, published for the reason every gate in
    // the release battery publishes one: a clean verdict over an empty
    // set answers for no part of the surface.
    console.log("EXAMINED " + located + " composed controls");
    console.log("EXAMINED " + defaultOn + " framework default-on layers");
    console.log("EXAMINED " + declared.length + " declared settings");
    console.log("EXAMINED " + reachable.length + " settings the browser surface reads");

    return helpers.getChecks();
  } finally {
    if (running && server) {
      try { await server.stop({ timeoutMs: SHUTDOWN_TIMEOUT_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "web-security-defaults-are-not-optional",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    process.exitCode = 1;
  });
}
