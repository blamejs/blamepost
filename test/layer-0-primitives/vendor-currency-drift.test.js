// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * vendor-currency-drift: an upstream that did not answer is UNKNOWN, and
 * UNKNOWN is not current.
 *
 * Two tools measure the vendored pin against the registry:
 * `scripts/vendor-update.sh --check` and
 * `scripts/check-vendor-currency.js`. Both are wired into CI, both
 * document the same promise, and the promise is the interesting half of
 * what they do. A gate that reports a stale pin is useful. A gate that
 * reports "up to date" because the registry refused the connection is
 * worse than no gate at all: the pin stops being measured, and the line
 * in the log says the opposite.
 *
 * That claim was written in three shipped documents and in the CI job's
 * own comment, and nothing tested it. This file drives both tools as CI
 * runs them, against a registry standing on loopback that can be made to
 * answer correctly, answer wrongly, or not answer at all.
 *
 * Every case is offline. `NPM_REGISTRY` points both tools at the
 * stand-in, so no case depends on the public registry being reachable,
 * and none of them writes: both tools only read
 * `lib/vendor/MANIFEST.json`.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/vendor-currency-drift.test.js`.
 */

var fs   = require("node:fs");
var path = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;

// The stand-in registry, the loopback port finder and the async runner
// are shared with the refresh cases rather than written twice. Two mocks
// of one registry are two sets of assumptions about what a registry
// answers, and they drift.
var shared = require("./vendor-refresh-atomicity.test.js");

var currency = require("../../scripts/check-vendor-currency.js");

var REPO_ROOT     = helpers.REPO_ROOT;
var CHECK_SCRIPT  = path.join(REPO_ROOT, "scripts", "vendor-update.sh");
var CURRENCY_JS   = path.join(REPO_ROOT, "scripts", "check-vendor-currency.js");
var MANIFEST_PATH = path.join(REPO_ROOT, "lib", "vendor", "MANIFEST.json");

// The abbreviated document the shell tool asks for, and the version
// document the Node tool asks for. The scope separator is percent-encoded
// because the registry addresses a scoped package as one path segment.
var ABBREVIATED_PATH = "/@blamejs%2Fcore";
var LATEST_PATH      = "/@blamejs%2Fcore/latest";

function _vendoredVersion() {
  var m = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  return m.packages.blamejs.version;
}

function _routesFor(version) {
  var versions = {};
  versions[version] = {
    dist: {
      tarball:   "https://example.invalid/core-" + version + ".tgz",
      integrity: "sha512-" + "C".repeat(86) + "==",
    },
  };
  var routes = {};
  routes[ABBREVIATED_PATH] = { body: { "dist-tags": { latest: version }, versions: versions } };
  routes[LATEST_PATH]      = { body: { name: "@blamejs/core", version: version } };
  return routes;
}

function _bumped(version) {
  var parts = String(version).split(".");
  parts[2] = String(parseInt(parts[2], 10) + 1);
  return parts.join(".");
}

function _transcript(result) {
  return "exit=" + String(result.status) +
    " stdout: " + String(result.stdout || "").replace(/\s+/g, " ").slice(-600) +
    " stderr: " + String(result.stderr || "").replace(/\s+/g, " ").slice(-400);
}

// ---------------------------------------------------------------------------
// Driving the two tools
// ---------------------------------------------------------------------------

function _runShellCheck(registryBase) {
  return shared.runCommand("bash", [shared.bashPath(CHECK_SCRIPT), "--check"], {
    cwd: REPO_ROOT,
    env: { NPM_REGISTRY: registryBase },
  });
}

function _runCurrency(registryBase, args) {
  return shared.runCommand(process.execPath, [CURRENCY_JS].concat(args || []), {
    cwd: REPO_ROOT,
    env: { NPM_REGISTRY: registryBase },
  });
}

/**
 * _withRegistry(routes, fn) serves `routes` on loopback for the duration
 * of `fn` and closes the listener afterwards, whichever way `fn` settles.
 */
async function _withRegistry(routes, fn) {
  var server = await shared.startRegistry({ routes: routes });
  try { return await fn(server.base); }
  finally { await server.close(); }
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

async function _shellCheckCases() {
  var vendored = _vendoredVersion();

  // ---- The pin matches what the registry publishes ----
  await _withRegistry(_routesFor(vendored), async function (base) {
    var r = await _runShellCheck(base);
    check("--check exits 0 when the pin matches the published release. " + _transcript(r),
      r.status === 0);
    check("--check says the pin is up to date",
      /up to date/.test(r.stdout));
  });

  // ---- The registry publishes something newer ----
  await _withRegistry(_routesFor(_bumped(vendored)), async function (base) {
    var r = await _runShellCheck(base);
    check("--check exits non-zero when a newer release exists",
      r.status !== 0);
    check("--check names the drift rather than calling it unknown",
      /UPDATE AVAILABLE/.test(r.stdout));
  });

  // ---- Nothing is listening ----
  var deadPort = await shared.closedPort();
  var deadBase = "http://127.0.0.1:" + deadPort;
  var refused  = await _runShellCheck(deadBase);
  check("--check exits non-zero when the registry refuses the connection. " + _transcript(refused),
    refused.status !== 0);
  check("--check reports a refused connection as UNKNOWN",
    /UNKNOWN/.test(refused.stdout));
  check("--check never reports a refused connection as up to date",
    !/up to date/.test(refused.stdout));
  check("--check leaves the latest column unfilled rather than guessing",
    /\?/.test(refused.stdout));
  check("--check tells the operator the currency is unknown rather than telling them to refresh alone",
    /currency is UNKNOWN/i.test(refused.stdout));

  // ---- The registry answers, badly ----
  var badAnswers = [
    {
      label:  "a 500 from the registry",
      routes: (function () {
        var r = {};
        r[ABBREVIATED_PATH] = { status: 500, body: "upstream is unwell", contentType: "text/plain" };
        return r;
      }()),
    },
    {
      label:  "a body that is not JSON",
      routes: (function () {
        var r = {};
        r[ABBREVIATED_PATH] = { body: "<html>a proxy sign-in page</html>", contentType: "text/html" };
        return r;
      }()),
    },
    {
      label:  "a document with no latest dist-tag",
      routes: (function () {
        var r = {};
        r[ABBREVIATED_PATH] = { body: { "dist-tags": {}, versions: {} } };
        return r;
      }()),
    },
    {
      label:  "a path the registry does not serve at all",
      routes: {},
    },
  ];

  // Sequential on purpose: each case binds a port, and every assertion is
  // about one tool run rather than about concurrency.
  for (var i = 0; i < badAnswers.length; i += 1) {
    await _oneBadAnswer(badAnswers[i]);
  }
}

async function _oneBadAnswer(spec) {
  var label = spec.label;
  await _withRegistry(spec.routes, async function (base) {
    var r = await _runShellCheck(base);
    check("--check exits non-zero on " + label + ". " + _transcript(r),
      r.status !== 0);
    check("--check reports " + label + " as UNKNOWN",
      /UNKNOWN/.test(r.stdout));
    check("--check never reports " + label + " as up to date",
      !/up to date/.test(r.stdout));
  });
}

async function _currencyScriptCases() {
  var vendored = _vendoredVersion();
  var CLAIM = /matches its latest upstream release/;

  // ---- The pin matches what the registry publishes ----
  await _withRegistry(_routesFor(vendored), async function (base) {
    var r = await _runCurrency(base);
    check("the currency gate exits 0 when the pin matches. " + _transcript(r),
      r.status === 0);
    check("the currency gate says so, and that is the only place the claim belongs",
      CLAIM.test(r.stdout));
  });

  // ---- The registry publishes something newer ----
  await _withRegistry(_routesFor(_bumped(vendored)), async function (base) {
    var r = await _runCurrency(base);
    check("the currency gate exits non-zero on a stale pin",
      r.status !== 0);
    check("the currency gate reports the stale pin as stale",
      /FAIL/.test(r.stdout) && /behind the latest upstream release/.test(r.stdout));
    check("the currency gate does not claim currency on a stale pin",
      !CLAIM.test(r.stdout));
  });

  // ---- Nothing is listening ----
  var deadPort = await shared.closedPort();
  var deadBase = "http://127.0.0.1:" + deadPort;

  var refused = await _runCurrency(deadBase);
  check("the currency gate exits non-zero when the registry refuses the connection. " +
    _transcript(refused),
  refused.status !== 0);
  check("the currency gate reports a refused connection as UNKNOWN",
    /UNKNOWN/.test(refused.stdout));
  check("the currency gate never claims the pin matches upstream when it could not ask",
    !CLAIM.test(refused.stdout));
  check("the currency gate says currency is unknown rather than current",
    /unknown, not current/.test(refused.stdout));

  // ---- The registry answers with something that is not a version ----
  //
  // Reaching upstream is not the same as measuring the pin. A value the
  // comparison cannot read leaves exactly the hole an unreachable registry
  // leaves, and the numeric comparison used to answer "equal" for it, which
  // is the same forbidden answer arrived at one layer down.
  var unreadable = {};
  unreadable[ABBREVIATED_PATH] = {
    body: { "dist-tags": { latest: "2026.01" }, versions: { "2026.01": { dist: {} } } },
  };
  unreadable[LATEST_PATH] = { body: { name: "@blamejs/core", version: "2026.01" } };
  await _withRegistry(unreadable, async function (base) {
    var r = await _runCurrency(base);
    check("the currency gate exits non-zero when the published version cannot be compared. " +
      _transcript(r),
    r.status !== 0);
    check("the currency gate reports an uncomparable version as UNKNOWN",
      /UNKNOWN/.test(r.stdout));
    check("the currency gate never claims currency it could not measure",
      !CLAIM.test(r.stdout));
    check("the currency gate names the value it could not read",
      /2026\.01/.test(r.stdout));
  });

  // ---- The advisory local run ----
  var warned = await _runCurrency(deadBase, ["--warn"]);
  check("--warn exits 0, which is what it is for. " + _transcript(warned),
    warned.status === 0);
  check("--warn still reports the unmeasured package as UNKNOWN",
    /UNKNOWN/.test(warned.stdout));
  check("--warn changes the exit code and never the claim",
    !CLAIM.test(warned.stdout));

  // ---- Structured output carries the same verdict ----
  await _withRegistry({}, async function (base) {
    var r = await _runCurrency(base, ["--json"]);
    check("--json exits non-zero when a package could not be measured",
      r.status !== 0);
    // The document comes first and the verdict lines follow it, so the
    // split is on the prefix every verdict line carries.
    var parsed;
    try { parsed = JSON.parse(String(r.stdout).split("\n[vendor-currency]")[0]); }
    catch (_e) { parsed = null; /* the check below reports the transcript */ }
    check("--json emits a parseable document. " + _transcript(r),
      parsed !== null && Array.isArray(parsed.results));
    check("--json marks the unmeasured package as an upstream error rather than as current",
      parsed !== null && parsed.results.every(function (x) { return x.status !== "current"; }));
  });
}

async function _registryOverrideCases() {
  // A mirror reached in the clear is a mirror anyone on the path can
  // answer for, and what it answers decides whether this repository ships
  // a stale framework. Loopback is the exception, because there is no path.
  var overrides = [
    { value: "http://registry.example.com/", why: "plaintext to a host that is not loopback" },
    { value: "ftp://registry.example.com/",  why: "a scheme that is not http or https" },
    { value: "not a url at all",             why: "a value that is not a URL" },
  ];
  for (var i = 0; i < overrides.length; i += 1) {
    var r = await shared.runCommand(process.execPath, [CURRENCY_JS], {
      cwd: REPO_ROOT,
      env: { NPM_REGISTRY: overrides[i].value },
    });
    check("the currency gate refuses " + overrides[i].why + ". " + _transcript(r),
      r.status !== 0);
    check("the refusal of " + overrides[i].why + " names the variable rather than failing as a network error",
      /NPM_REGISTRY/.test(String(r.stderr)));
  }

  check("loopback by name is recognized", currency._isLoopback("localhost"));
  check("loopback by address is recognized", currency._isLoopback("127.0.0.1"));
  check("the whole loopback block is recognized, not just the first address",
    currency._isLoopback("127.13.9.4"));
  check("the bracketed IPv6 loopback form Node reports is recognized",
    currency._isLoopback("[::1]"));
  check("a routable address is not loopback", !currency._isLoopback("93.184.216.34"));
  check("a host that merely starts with the loopback digits is not loopback",
    !currency._isLoopback("127.0.0.1.evil.example"));
}

function _verdictCases() {
  var CLAIM = /matches its latest upstream release/;

  var allCurrent = currency._verdict([{ status: "current" }, { status: "skipped" }]);
  check("a run where everything was measured and matched passes",
    allCurrent.code === 0);
  check("only that run claims currency", CLAIM.test(allCurrent.summary));

  var oneUnknown = currency._verdict([{ status: "upstream-error" }]);
  check("a run that could not measure a package does not pass",
    oneUnknown.code !== 0);
  check("that run reports UNKNOWN", /UNKNOWN/.test(oneUnknown.summary));
  check("that run never claims currency", !CLAIM.test(oneUnknown.summary));

  var mixed = currency._verdict([{ status: "stale" }, { status: "upstream-error" }]);
  check("a run with a stale package fails", mixed.code !== 0);
  check("a stale verdict still counts the packages it could not measure",
    /could not be checked/.test(mixed.summary));
  check("a stale verdict never claims currency", !CLAIM.test(mixed.summary));

  var aheadOnly = currency._verdict([{ status: "ahead" }]);
  check("a pin ahead of the published release is not a failure",
    aheadOnly.code === 0);

  var unreadable = currency._verdict([{ status: "unreadable-version" }]);
  check("a version that could not be compared does not pass either",
    unreadable.code !== 0);
  check("it lands under the same UNKNOWN verdict as an upstream that never answered",
    /UNKNOWN/.test(unreadable.summary) && !CLAIM.test(unreadable.summary));

  check("both unmeasured statuses are counted as unmeasured",
    currency._isUnmeasured({ status: "upstream-error" }) &&
    currency._isUnmeasured({ status: "unreadable-version" }));
  check("a measured status is not counted as unmeasured",
    !currency._isUnmeasured({ status: "current" }) &&
    !currency._isUnmeasured({ status: "stale" }));

  // The comparison itself, at the root. Answering 0 for a pair it could not
  // read is what let an unreadable version reach the gate as current.
  check("comparing an unreadable version against a readable one is not equality",
    currency._semverCompare(currency._semverParse("2026.01"),
      currency._semverParse("1.2.3")) === null);
  check("comparing two readable versions still works",
    currency._semverCompare(currency._semverParse("1.2.3"),
      currency._semverParse("1.2.4")) === -1);
  check("two identical readable versions still compare equal",
    currency._semverCompare(currency._semverParse("0.18.51"),
      currency._semverParse("0.18.51")) === 0);
}

async function run() {
  await helpers.withTestTimeout("vendor currency drift", async function () {
    _verdictCases();
    await _registryOverrideCases();
    await _shellCheckCases();
    await _currencyScriptCases();
  }, { timeoutMs: 180000 });
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
