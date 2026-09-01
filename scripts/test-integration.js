// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/test-integration.js
 *
 * Live-listener integration runner. Confirms every endpoint the suite talks
 * to is up (scripts/check-services.js), then spawns each file in
 * test/integration/ as its own node process and aggregates the per-file
 * "CHECKS <n>" counts.
 *
 * Each integration file speaks a wire protocol over a real socket: an SMTP
 * conversation, an IMAP session, a JMAP request, a delivery attempt against
 * a receiving MTA. That is the layer where a listener's own idea of what it
 * emitted stops being evidence. Only a client on the other end of the socket
 * is. A fresh process per file contains a crash or a leaked handle to one file
 * and keeps the check counter isolated.
 *
 * This is distinct from test/smoke.js, and the distinction is the point. The
 * layered suites that test/smoke.js runs build the server inside the test
 * process and bind ephemeral loopback ports, so they need no external stack
 * and prove nothing about what another implementation makes of the bytes.
 * Pointing this runner at those directories would make this command pass
 * while asserting no interop property at all, and would run them twice. The
 * smoke gate must also stay pure (it runs in CI, and on a laptop with no
 * service stack) and must never "skip silently when a service is down," which
 * would make its pass count misleading.
 *
 * An EMPTY suite is its own state, and it is neither a pass nor a broken
 * tree. test/integration/ is tracked with the contract a file has to meet,
 * so the directory being there and holding no test file means no interop file
 * has been written yet. That exits 4, which says nothing was proven; the
 * release flow prints it as a gate that did not run rather than as a green
 * one. A MISSING directory is still a broken tree and exits 3.
 *
 * Exit codes:
 *   0  every integration file passed
 *   1  a required endpoint is unreachable (bring the stack up, or start the
 *      server); re-run with --skip-service-check to bypass
 *   2  at least one file threw / returned non-zero
 *   3  script-level error (missing dir, a named file that does not exist)
 *   4  the suite is empty, so nothing was proven
 *
 * Usage:
 *   node scripts/test-integration.js
 *   node scripts/test-integration.js smtp-submission          one file
 *   node scripts/test-integration.js --skip-service-check     assume ready
 */

var fs   = require("node:fs");
var path = require("node:path");
var spawn = require("node:child_process").spawn;

var INTEGRATION_DIR = path.join(__dirname, "..", "test", "integration");
var CHECK_SERVICES  = path.join(__dirname, "check-services.js");

function _padRight(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function _spawn(cmd, args, opts) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, Object.assign({ stdio: "inherit" }, opts || {}));
    child.once("exit", function (code, signal) { resolve({ code: code, signal: signal }); });
    child.once("error", reject);
  });
}

function _spawnCapturing(cmd, args, env) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, { env: env, stdio: ["ignore", "pipe", "pipe"] });
    var stdout = "";
    var stderr = "";
    child.stdout.on("data", function (b) { stdout += b.toString(); });
    child.stderr.on("data", function (b) { stderr += b.toString(); });
    child.once("exit", function (code, signal) {
      resolve({ code: code, signal: signal, stdout: stdout, stderr: stderr });
    });
    child.once("error", reject);
  });
}

(async function main() {
  var args = process.argv.slice(2);
  var skipCheck = args.indexOf("--skip-service-check") !== -1;
  var named = args.filter(function (a) { return a.charAt(0) !== "-"; });

  if (!fs.existsSync(INTEGRATION_DIR)) {
    console.error("[test-integration] missing dir: " + INTEGRATION_DIR);
    console.error("[test-integration] the interop suite lives there and is tracked even " +
      "while it holds no test file; a missing directory is a broken tree, not an empty suite.");
    process.exit(3);
  }

  var present = fs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .sort();

  // The suite holds nothing yet. That is a real and visible state rather than
  // an error: the directory is tracked, the runner is wired to it, and no
  // interop file has been written. It is reported as nothing proven, with its
  // own exit code, so a caller can tell it apart both from a green run and
  // from a failure. Reporting "OK, 0 checks passed" here would be the exact
  // shape this runner refuses one file for: an empty answer read as a pass.
  if (present.length === 0) {
    console.log("");
    console.log("[test-integration] SUITE EMPTY: test/integration/ holds no *.test.js file.");
    console.log("[test-integration] Nothing was proven. This is NOT a pass.");
    console.log("[test-integration] An interop file drives a running server from the outside " +
      "with a client that is not this codebase; see test/integration/README.md.");
    process.exit(4);
  }

  var files = present.filter(function (f) {
    if (named.length === 0) return true;
    return named.some(function (n) { return f === n || f === n + ".test.js"; });
  });

  if (files.length === 0) {
    console.error("[test-integration] no test file matched " + named.join(", "));
    console.error("[test-integration] present: " + present.join(", "));
    process.exit(3);
  }

  if (!skipCheck) {
    console.log("[test-integration] running scripts/check-services.js gate...");
    var checkExit = await _spawn(process.execPath, [CHECK_SERVICES]);
    if (checkExit.code !== 0) {
      console.error("[test-integration] service-check gate failed (exit " + checkExit.code + ")");
      console.error("[test-integration] bring the stack up first:");
      console.error("[test-integration]   docker compose up -d --wait");
      console.error("[test-integration] OR re-run with --skip-service-check to bypass");
      process.exit(1);
    }
  }

  console.log("");
  console.log("[test-integration] running " + files.length + " integration file" +
    (files.length === 1 ? "" : "s") + " (each in a fresh node process)...");
  var suiteStart = Date.now();
  var failed = 0;
  var totalChecks = 0;
  var totalSkips = 0;
  for (var i = 0; i < files.length; i++) {
    var fullPath = path.join(INTEGRATION_DIR, files[i]);
    var fileStart = Date.now();
    var rv;
    try {
      rv = await _spawnCapturing(process.execPath, [fullPath], process.env);
    } catch (err) {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " SPAWN FAILED");
      console.error("    " + (err.message || String(err)));
      continue;
    }
    var ms = Date.now() - fileStart;
    var m = /CHECKS\s+(\d+)/.exec(rv.stdout || "");
    var checks = m ? parseInt(m[1], 10) : 0;
    // A check an optional endpoint can't answer is reported as a SKIP, never
    // folded into the pass count, so "N checks passed" is not inflated by skips.
    var sm = /SKIPS\s+(\d+)/.exec(rv.stdout || "");
    var skips = sm ? parseInt(sm[1], 10) : 0;
    if (rv.code === 0 && checks === 0 && skips === 0) {
      // A file that exits clean having asserted nothing is a test that is not running, and it is
      // indistinguishable from a passing one in the totals: a missing self-invocation, a loop whose
      // fixture generation failed into `continue`, or a guard that returned early all land here. The
      // endpoint-absent case has its own signal (SKIPS), so silence is never the honest answer.
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " FAILED (exited 0 having asserted nothing --" +
        " no CHECKS and no SKIPS; the file ran but exercised nothing)");
    } else if (rv.code === 0) {
      totalChecks += checks;
      totalSkips += skips;
      console.log("  " + _padRight(files[i], 40) + " (" + ms + "ms, " + checks + " checks" +
        (skips > 0 ? ", " + skips + " skipped" : "") + ")");
    } else {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " FAILED (exit " + rv.code + ")");
      var lines = (rv.stderr || rv.stdout || "").split(/\r?\n/).filter(Boolean).slice(-12);
      lines.forEach(function (l) { console.error("    " + l); });
    }
  }
  console.log("");
  if (failed === 0) {
    console.log("[test-integration] OK, " + totalChecks + " checks passed" +
      (totalSkips > 0 ? " (" + totalSkips + " check(s) skipped for an absent optional endpoint)" : "") +
      " across " + files.length + " file(s) in " + (Date.now() - suiteStart) + "ms");
    process.exit(0);
  }
  console.error("[test-integration] " + failed + " of " + files.length + " file(s) failed");
  process.exit(2);
})().catch(function (err) {
  console.error("[test-integration] runner error: " + ((err && err.stack) || err));
  process.exit(3);
});
