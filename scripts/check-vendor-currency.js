// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Vendor-currency gate.
 *
 * Reads lib/vendor/MANIFEST.json and asserts that every vendored package is
 * pinned at its latest upstream release. A vendored tree that fell behind is
 * a security-relevant pin nobody moved, so the drift becomes a release
 * blocker here rather than an after-the-fact advisory.
 *
 * Two upstream kinds are understood, chosen per entry:
 *
 *   npm     applies when the entry names an `npm` package. The registry's
 *             `latest` dist-tag is authoritative, because that is the artifact
 *             scripts/vendor-update.sh fetches and integrity-verifies. This is
 *             the path every entry takes today.
 *   github  applies when the entry names no npm package and its `source` is a
 *             github.com URL. The latest published RELEASE tag is authoritative;
 *             pre-releases and un-released tags are ignored by the GitHub
 *             `releases/latest` endpoint, which is the behavior this gate
 *             wants, because a tag nobody released is not a version to vendor.
 *
 * Run locally:
 *   node scripts/check-vendor-currency.js
 *   node scripts/check-vendor-currency.js --json     // structured output
 *   node scripts/check-vendor-currency.js --warn     // exit 0, print only
 *
 * Run in CI: pass GITHUB_TOKEN so the GitHub API gives the authenticated
 * 5000/hour budget instead of the 60/hour unauthenticated per-IP limit.
 *
 * NPM_REGISTRY overrides the registry, and is the same variable
 * scripts/vendor-update.sh reads, so an operator running a mirror gets one
 * answer from both tools instead of two that disagree about what "latest"
 * is. A non-https override is refused unless it addresses loopback, so a
 * mirror on the network cannot be reached in the clear.
 *
 * Failure policy, in one sentence: a package this gate could not measure is
 * reported as UNKNOWN and never as current. A stale package fails. So does
 * an unmeasured one, under its own summary line, because a check that did
 * not happen reading as up to date is the one answer a currency gate must
 * never give: the pin stops being measured and nothing says so. Three things
 * count as unmeasured. Two are the same hole from two directions: an
 * upstream that did not answer, and an upstream whose answer could not be
 * compared against the pin. The third is the whole RUN measuring nothing,
 * which is the first two generalised and is the one that reads as a pass
 * rather than as a failure. `--warn` is the advisory local run, and it
 * still prints the UNKNOWN verdict before exiting 0.
 *
 * Packages with no single upstream version to track are declared in
 * SPECIAL_MAP as `{ type: "skip", reason }`; skipped packages do NOT trip
 * the gate by design, because the gate is for version drift on packages that
 * COULD have shipped fresh. A manifest whose packages are ALL skipped is a
 * different statement and it does trip the gate: nothing was compared, so
 * there is no currency to report either way.
 *
 * WHAT THE RUN EXAMINED is published as the last lines of every run, whatever
 * the verdict and whatever the output mode, in the form the release battery
 * reads:
 *
 *   EXAMINED <n> manifest-packages
 *   EXAMINED <n> measured-packages
 *
 * This gate is the closest of the battery to self-proving already: it names
 * every package it looked at, one line each, with the pin and the published
 * version beside it. Three things that naming does not give, and each of them
 * is why the lines above exist anyway.
 *
 * The number it already prints is the COUNT OF ENTRIES IN THE MANIFEST, not the
 * count it measured, and those come apart in the one direction that matters. A
 * manifest whose every entry resolves to `{ type: "skip" }` prints its package
 * count, prints a `skip` line for each, and then exits 0 under the summary that
 * every checked package matches its latest upstream release. Nothing was
 * checked. That is the same shape as a walk pointed at an empty directory, so
 * `measured-packages` counts only the entries that got a real comparison against
 * a published version, and never a skip and never one that could not be read.
 *
 * `--json` prints no package lines at all, so a machine reading the structured
 * output has nothing to tell an empty run from a measured one. The count lines
 * are written in that mode too, behind the document, and the empty-set refusal
 * does not depend on either: it is part of the VERDICT, so it reaches the exit
 * code whichever output mode was asked for. A refusal that lived only in a
 * printed line would be one `--json` silently switched off.
 *
 * And a line a person has to count is not a line CI counts. The two units are
 * published in the shape every other gate in the battery publishes, so one
 * reader in scripts/release.js refuses a zero from any of them.
 *
 * That reader is not enough on its own, and the refusal does not rest
 * entirely on it. Only the release battery captures this
 * gate's stdout. The pull-request workflow runs it bare and reads the exit code;
 * so does the plain invocation in the release flow that precedes the counted
 * one. Both of those are the everyday path, and for both of them a count nobody
 * reads is a count that does not exist. So `_verdict` refuses an empty
 * measurement itself, and the published counts are what a caller that DOES
 * capture the output can hold it to as well. The two say the same thing from
 * two sides rather than one of them deferring to the other.
 */

var fs    = require("node:fs");
var http  = require("node:http");
var path  = require("node:path");
var https = require("node:https");

var MANIFEST_PATH    = path.join(__dirname, "..", "lib", "vendor", "MANIFEST.json");
var DEFAULT_REGISTRY = "https://registry.npmjs.org/";
var GITHUB_API       = "https://api.github.com";
var USER_AGENT       = "blamepost-vendor-currency/1";

// Loopback literals, the only hosts a plaintext registry override may
// address. A mirror on the network carries the same integrity decision the
// public registry does, so reaching it in the clear would let anyone on the
// path decide what "latest" is.
var LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]", "::1"];

function _isLoopback(hostname) {
  if (LOOPBACK_HOSTS.indexOf(hostname) !== -1) return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

/**
 * _registryBase() resolves the registry this run measures against. This is
 * an entry point rather than a request, so bad input throws: an operator
 * who mistyped a mirror URL finds out here, instead of watching every
 * package report as unreachable and reading it as a network problem.
 */
function _registryBase() {
  var raw = process.env.NPM_REGISTRY;
  if (typeof raw !== "string" || raw.length === 0) return DEFAULT_REGISTRY;
  var parsed;
  try { parsed = new URL(raw); }
  catch (_e) { throw new TypeError("NPM_REGISTRY is not a URL: " + raw); }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new TypeError("NPM_REGISTRY must be http or https, got " + parsed.protocol);
  }
  if (parsed.protocol === "http:" && !_isLoopback(parsed.hostname)) {
    throw new TypeError("NPM_REGISTRY may only use http for a loopback address, got " + raw);
  }
  return parsed.href.endsWith("/") ? parsed.href : parsed.href + "/";
}

// Resolved once, on first use rather than on load, so requiring this file
// for its pure helpers cannot throw on an environment variable it will
// never read.
var _registryBaseMemo = null;
function registryBase() {
  if (_registryBaseMemo === null) _registryBaseMemo = _registryBase();
  return _registryBaseMemo;
}

var WARN_ONLY  = process.argv.indexOf("--warn") !== -1;
var JSON_OUT   = process.argv.indexOf("--json") !== -1;
var TIMEOUT_MS = 10000;

// Per-package overrides keyed by MANIFEST.json package key. Missing entries
// are resolved from the entry's own fields. See _upstreamFor.
//
// shape:
//   { type: "github", repo: "<owner>/<name>" }  tracks the latest release tag
//   { type: "npm", name: "<npm-package>" }      tracks the registry `latest`
//   { type: "skip", reason: "..." }             skips, with a stated reason
var SPECIAL_MAP = {};

// Decide where a manifest entry's upstream version comes from. An explicit
// SPECIAL_MAP entry wins; otherwise the entry's own `npm` field names the
// package, a github.com `source` selects the release path, and the manifest key
// is the last resort.
//
// Reading `npm` FIRST is what keeps this gate measuring the same thing
// scripts/vendor-update.sh fetched. The manifest key names the vendored
// DIRECTORY and the `npm` field names the package the registry knows; where a
// directory is named for the project rather than its scoped package, falling
// back to the key would query a package nobody publishes and report the entry
// as an upstream error forever.
function _upstreamFor(key, entry) {
  var special = SPECIAL_MAP[key];
  if (special) return special;
  if (entry && typeof entry.npm === "string" && entry.npm.length > 0) {
    return { type: "npm", name: entry.npm };
  }
  var source = (entry && typeof entry.source === "string") ? entry.source : "";
  var m = /^https?:\/\/github\.com\/([^/]+)\/([^/#?]+)/.exec(source);
  if (m) return { type: "github", repo: m[1] + "/" + m[2].replace(/\.git$/, "") };
  return { type: "npm", name: key };
}

function _get(url, headers) {
  // Direct node:https for portability, because the gate runs from scripts/ before
  // any application state exists. node:https with TLS 1.3 is sufficient for
  // a public GET. node:http is reachable only for the loopback mirror
  // _registryBase already validated.
  var transport = url.indexOf("http://") === 0 ? http : https;
  return new Promise(function (resolve, reject) {
    var req = transport.get(url, { timeout: TIMEOUT_MS, headers: headers }, function (res) {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(url + " status " + res.statusCode));
      }
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error(url + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

async function _registryFetch(name) {
  var url = registryBase() + encodeURIComponent(name).replace("%40", "@") + "/latest";
  var doc = await _get(url, { "User-Agent": USER_AGENT, "Accept": "application/json" });
  if (!doc || typeof doc.version !== "string") {
    throw new Error("registry " + name + " returned no .version");
  }
  return doc.version;
}

async function _githubLatestRelease(repo) {
  var headers = { "User-Agent": USER_AGENT, "Accept": "application/vnd.github+json" };
  var token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (token) headers.Authorization = "Bearer " + token;
  var doc = await _get(GITHUB_API + "/repos/" + repo + "/releases/latest", headers);
  if (!doc || typeof doc.tag_name !== "string" || doc.tag_name.length === 0) {
    throw new Error("github " + repo + " returned no .tag_name");
  }
  // The manifest records a bare version; the tag carries the `v` prefix the
  // release convention uses. Compare like with like.
  return doc.tag_name.replace(/^v/, "");
}

function _semverParse(v) {
  // Strip leading "v" + any pre-release tail. Returns [maj, min, pat] as
  // numbers, or null if not parseable.
  var m = String(v).match(/^v?(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

// Returns null when either side did not parse, and never 0.
//
// Returning 0 for an unreadable version is the same defect as reporting an
// unreachable registry as current, one layer down: 0 means "the pin matches
// the published release", and a comparison that could not be made has not
// established that. The caller has to see the difference, so the answer for
// "cannot tell" is its own value.
function _semverCompare(a, b) {
  if (!a || !b) return null;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

async function _checkOne(key, manifestEntry) {
  var upstream = _upstreamFor(key, manifestEntry);
  if (upstream.type === "skip") {
    return { key: key, status: "skipped", reason: upstream.reason };
  }
  var origin = upstream.type === "github"
    ? "github:" + upstream.repo
    : "npm:" + (upstream.name || key);
  var current = manifestEntry.version;
  try {
    var latest = upstream.type === "github"
      ? await _githubLatestRelease(upstream.repo)
      : await _registryFetch(upstream.name || key);
    var cmp = _semverCompare(_semverParse(current), _semverParse(latest));
    if (cmp === null) {
      // Reached upstream, could not compare what it said. That is still a
      // pin nobody measured, so it lands in the same bucket as an upstream
      // that never answered, and the message names the value to look at.
      return {
        key:      key,
        upstream: origin,
        current:  current,
        latest:   latest,
        status:   "unreadable-version",
        error:    "cannot compare " + JSON.stringify(current) + " against " +
                  JSON.stringify(latest) + ": at least one is not a semantic version",
      };
    }
    return {
      key:      key,
      upstream: origin,
      current:  current,
      latest:   latest,
      status:   cmp === 0 ? "current" : (cmp < 0 ? "stale" : "ahead"),
    };
  } catch (e) {
    return {
      key:      key,
      upstream: origin,
      current:  current,
      status:   "upstream-error",
      error:    (e && e.message) || String(e),
    };
  }
}

/**
 * _verdict(results) turns the per-package results into the one line this
 * gate answers with, and the exit code that goes with it.
 *
 * The rule it encodes: a package that could not be measured is UNKNOWN,
 * and UNKNOWN is not a pass. The shape this replaces printed "every
 * checked package matches its latest upstream release" whenever nothing
 * was stale, which was true of a run where the registry answered nothing
 * at all. A CI job reading that line, or its exit code, learns that the
 * pin is current at the exact moment the check stopped happening.
 *
 * Pure, and exported, so the failure paths are provable without a network.
 */
// Every status that means "this pin was not measured". Both belong in one
// bucket: an upstream that did not answer and an answer that could not be
// read leave the same hole, and the gate must treat them the same way.
var UNMEASURED_STATUSES = ["upstream-error", "unreadable-version"];

function _isUnmeasured(result) {
  return UNMEASURED_STATUSES.indexOf(result && result.status) !== -1;
}

// Every status that means "this pin WAS measured": upstream answered, the answer
// parsed, and the comparison against the pin returned an ordering. A skip is not
// one of them, which is the whole point of counting these separately from the
// manifest's entries.
var MEASURED_STATUSES = ["current", "stale", "ahead"];

function _isMeasured(result) {
  return MEASURED_STATUSES.indexOf(result && result.status) !== -1;
}

function _verdict(results) {
  results = results || [];
  var stale = results.filter(function (r) { return r.status === "stale"; });
  var unknown = results.filter(_isUnmeasured);
  var measured = results.filter(_isMeasured);
  if (stale.length > 0) {
    return {
      code: 1,
      summary: "FAIL: " + stale.length + " package(s) behind the latest upstream release" +
        (unknown.length > 0 ? ", and " + unknown.length + " that could not be checked" : ""),
      advice: "Refresh with: bash scripts/vendor-update.sh <package> latest",
    };
  }
  if (unknown.length > 0) {
    return {
      code: 1,
      summary: "UNKNOWN: " + unknown.length + " package(s) could not be measured against " +
        "upstream. Currency is unknown, not current.",
      advice: "Re-run once the upstream named beside each package answers.",
    };
  }

  // Nothing measured at all. "Every checked package matches its latest
  // upstream release" is TRUE of a run that checked no package, and true in the
  // same words it uses when it checked all of them. A manifest whose entries
  // all resolve to `{ type: "skip" }`, a manifest that lost its `packages` map,
  // a walk pointed at a file that moved: each lands here, prints the passing
  // line, and exits zero having compared nothing against upstream.
  //
  // The refusal belongs in the gate rather than only in the caller that spawns
  // it. Two of the three places this runs read nothing but the exit code, a
  // workflow step and the release flow's plain invocation, so a count published
  // for a reader that is not there protects neither of them. `--warn` still
  // exits 0, which is what the advisory local run is for, and it still prints
  // this verdict rather than a passing one.
  if (measured.length === 0) {
    return {
      code: 1,
      summary: "UNKNOWN: no vendored package was measured against upstream. Currency is " +
        "unknown, not current.",
      advice: "Check that lib/vendor/MANIFEST.json still declares its packages, and that each " +
        "one names an `npm` package or a github.com `source` this gate can resolve a published " +
        "version from.",
    };
  }

  return {
    code: 0,
    summary: "OK, every checked package matches its latest upstream release",
    advice: "",
  };
}

async function main() {
  // Resolve the registry before any work, so a mistyped mirror reads as a
  // configuration refusal rather than as every package being unreachable.
  try {
    registryBase();
  } catch (e) {
    process.stderr.write("[vendor-currency] " + ((e && e.message) || String(e)) + "\n");
    process.exit(2);
  }
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  var manifest = JSON.parse(raw);
  var pkgs = manifest.packages || {};
  var keys = Object.keys(pkgs);
  var results = [];
  // Sequential, because both upstreams are fine with polite serial traffic and the
  // total package count is small. Parallel would burn sockets for no
  // measurable gain.
  for (var i = 0; i < keys.length; i++) {
    results.push(await _checkOne(keys[i], pkgs[keys[i]]));
  }

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ results: results }, null, 2) + "\n");
  } else {
    process.stdout.write("[vendor-currency] " + keys.length + " vendored package(s) inspected:\n");
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var label = r.status === "current"            ? "OK"
                : r.status === "stale"              ? "STALE"
                : r.status === "ahead"              ? "AHEAD"
                : r.status === "upstream-error"     ? "UNKNOWN"
                : r.status === "unreadable-version" ? "UNKNOWN"
                : r.status === "skipped"            ? "skip"
                :                                     r.status;
      var line = "  [" + label + "] " + r.key;
      if (r.upstream)            line += "  (" + r.upstream + ")";
      if (r.current && r.latest) line += "  " + r.current + " -> " + r.latest;
      else if (r.current)        line += "  " + r.current;
      if (r.reason) line += "  (" + r.reason + ")";
      if (r.error)  line += "  (upstream: " + r.error + ")";
      process.stdout.write(line + "\n");
    }
  }

  var verdict = _verdict(results);
  process.stdout.write("[vendor-currency] " + verdict.summary + "\n");
  if (verdict.advice) process.stdout.write("[vendor-currency] " + verdict.advice + "\n");

  if (WARN_ONLY && verdict.code !== 0) {
    // The advisory local run still prints the verdict above. What --warn
    // changes is the exit code, never the claim.
    process.stdout.write("[vendor-currency] --warn: exiting 0 anyway\n");
  }

  // Last, on every path and in both output modes. `--json` writes its document
  // before any of the verdict lines, so a reader splitting on the verdict prefix
  // still gets the document, and these sit behind them all.
  process.stdout.write("EXAMINED " + keys.length + " manifest-packages\n");
  process.stdout.write("EXAMINED " + results.filter(_isMeasured).length + " measured-packages\n");

  process.exit(WARN_ONLY ? 0 : verdict.code);
}

// Exported for hermetic unit tests (the semver comparison and the upstream
// routing are pure, touch no network, and are the load-bearing logic).
module.exports = {
  _semverParse:   _semverParse,
  _semverCompare: _semverCompare,
  _upstreamFor:   _upstreamFor,
  _verdict:       _verdict,
  _isUnmeasured:  _isUnmeasured,
  _isMeasured:    _isMeasured,
  _isLoopback:    _isLoopback,
  SPECIAL_MAP:    SPECIAL_MAP,
};

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[vendor-currency] script crashed: " + ((e && e.stack) || e) + "\n");
    process.exit(2);
  });
}
