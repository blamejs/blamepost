// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/test-integration.js
 *
 * Live-listener integration runner. Confirms every endpoint the suite talks
 * to is up (scripts/check-services.js), locates the foreign clients the
 * selected files need, then spawns each file in test/integration/ as its own
 * node process and aggregates the per-file "CHECKS <n>" counts.
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
 * ## A run that located no client proved no interop property
 *
 * The clients are LOCATED at run time and never installed, because hard rule
 * one is zero runtime dependencies. So the ordinary state of a machine that
 * has none of them is a run where every case needing a foreign parser records
 * a skip and every case that does not still passes. Measured: that run
 * printed "OK, 3 checks passed" and exited 0. Wired into a pipeline as-is it
 * is a green badge over a run that put no foreign parser on any socket, which
 * is worse than nobody running it: the badge is read as the interop property
 * holding.
 *
 * test/smoke.js already answers this for the container engine and this file
 * follows it. The clients are probed ONCE, up front, through the same helper
 * and the same table the interop files use, so the runner and the files
 * cannot disagree about what "absent" means. Every client that could not be
 * located is NAMED and counted as skipped, never folded into a total. Set
 * `INTEGRATION_REQUIRE_CLIENTS=1` and an absent client refuses the whole run
 * before anything is spawned, which is what a release or a pipeline wants:
 * the client being missing is the finding rather than something to route
 * around.
 *
 * ## What this run examined
 *
 * The counts are published as `EXAMINED <n> <unit>` on the last lines of
 * stdout, on a passing run and a failing one alike, and a unit that came back
 * zero refuses the run by name. Three units, because they empty for three
 * different reasons and each is a way for this command to answer for nothing:
 *
 *   - `interop-files` empties when discovery found no file to run, which is a
 *     glob or a directory that moved out from under this runner.
 *   - `located-clients` empties when no foreign parser was found on the
 *     machine, which is a run that spoke to the server only in its own code.
 *   - `driven-checks` empties when the files ran and asserted nothing.
 *
 * An EMPTY suite is its own state, and it is neither a pass nor a broken
 * tree. test/integration/ is tracked with the contract a file has to meet,
 * so the directory being there and holding no test file means no interop file
 * has been written yet. That exits 4, which says nothing was proven; the
 * release flow prints it as a gate that did not run rather than as a green
 * one. A MISSING directory is still a broken tree and exits 3.
 *
 * Environment:
 *   INTEGRATION_REQUIRE_CLIENTS  1 to make an absent foreign client refuse
 *                                the run rather than skip the cases needing
 *                                one.
 *   BLAMEPOST_INTEGRATION_DIR    directory to discover interop files under.
 *                                Default test/integration/. It exists so
 *                                this runner's own behavior can be driven
 *                                over fixture files. It moves the FILES
 *                                only; the client table stays the suite's,
 *                                so a fixture claiming an id is looked for
 *                                with the same specification the shipped
 *                                files are.
 *   BLAMEPOST_PYTHON_BIN         an explicit path for one of the clients,
 *   BLAMEPOST_CURL_BIN           read by test/helpers/foreign-client.js.
 *
 * ## Skipping the service pre-flight
 *
 * The pre-flight probes the listeners this suite is about to drive and refuses
 * a partial-up stack once, here, instead of as a dozen connection errors spread
 * across the files. Skipping it is therefore skipping the answer to "is the
 * thing under test actually running", so the skip costs a written reason:
 *
 *   --skip-service-check --service-check-skip-reason="<why>"
 *
 * The reason is printed as a banner, so the transcript carries it and a
 * pipeline log records what was not checked. The flag alone is refused. This is
 * the same posture the release flow's interop override already has, and it is
 * here for the same reason: a bypass nobody has to justify becomes the shape
 * every run is typed in, and the run it silently skips is the one that would
 * have failed.
 *
 * Exit codes:
 *   0  every integration file passed
 *   1  a required endpoint is unreachable (bring the stack up, or start the
 *      server); re-run with --skip-service-check and its reason to bypass
 *   2  at least one file threw / returned non-zero
 *   3  script-level error (missing dir, a named file that does not exist)
 *   4  the suite is empty, so nothing was proven
 *   5  INTEGRATION_REQUIRE_CLIENTS=1 and a client the selected files need is
 *      not on this machine
 *   6  the run examined nothing: a unit came back empty, so a clean verdict
 *      from it answers for no part of the suite
 *   7  --skip-service-check was passed without --service-check-skip-reason
 *
 * Usage:
 *   node scripts/test-integration.js
 *   node scripts/test-integration.js smtp-submission          one file
 *   node scripts/test-integration.js --skip-service-check \
 *     --service-check-skip-reason="the stack is up under a different runner"
 *   INTEGRATION_REQUIRE_CLIENTS=1 node scripts/test-integration.js
 */

var fs   = require("node:fs");
var path = require("node:path");
var spawn = require("node:child_process").spawn;

var examinedCounts = require("./examined-counts.js");

// The two halves of the client contract, read from where the interop files
// read them. A second table here would answer about a different set of
// programs than the one the files went on to drive.
var clients = require("../test/integration/clients.js");
var foreign = require("../test/helpers/foreign-client.js");

var DEFAULT_INTEGRATION_DIR = path.join(__dirname, "..", "test", "integration");
var INTEGRATION_DIR = process.env.BLAMEPOST_INTEGRATION_DIR
  ? path.resolve(process.env.BLAMEPOST_INTEGRATION_DIR)
  : DEFAULT_INTEGRATION_DIR;
var CHECK_SERVICES  = path.join(__dirname, "check-services.js");

var REQUIRE_CLIENTS = process.env.INTEGRATION_REQUIRE_CLIENTS === "1";

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

// Every count this run answers for, printed last and on every path that got
// far enough to have one. `verdict` wins when it is already non-zero: a file
// that failed and a stack that is down ask different things of the reader,
// and collapsing either into the empty-set code because a unit came back
// zero would lose the distinction the codes exist to carry.
function _finish(verdict, units) {
  var published = examinedCounts.publish(units, { tag: "[test-integration]" });
  if (verdict !== 0) process.exit(verdict);
  process.exit(published === 0 ? 0 : 6);
}

// Which clients the selected files need, and whether each is on this machine.
//
// The ids come out of the files themselves rather than from a list kept here,
// so a file added to the suite is looked for with what it claims and a runner
// invoked on one named file does not refuse over a client only its neighbors
// drive.
async function _preflightClients(dir, files) {
  var needed = [];
  files.forEach(function (name) {
    var source = "";
    try { source = fs.readFileSync(path.join(dir, name), "utf8"); }
    catch (_e) { /* an unreadable file fails when it is spawned, and says why */ }
    clients.claimedBy(source).forEach(function (id) {
      if (needed.indexOf(id) === -1) needed.push(id);
    });
  });

  var located = [];
  var absent  = [];
  for (var i = 0; i < needed.length; i += 1) {
    var spec = clients.spec(needed[i]);
    var rv   = await foreign.locate(spec);
    if (rv.found) located.push({ id: needed[i], bin: rv.bin, detail: rv.detail });
    else absent.push({ id: needed[i], name: spec.name, reason: rv.reason });
  }
  return { needed: needed, located: located, absent: absent };
}

// The exit code for a bypass nobody wrote a reason for. Its own code rather
// than folded into the script-level one, because a caller that mistyped the
// override and a caller with a broken tree have different next moves.
var UNJUSTIFIED_SKIP_EXIT = 7;

// The written half of the service-check bypass. Read from `--service-check-skip-reason=<why>`,
// which is how the release flow's interop override spells its own, so an
// operator who has typed one has typed both.
function _skipReason(args) {
  var flag = "--service-check-skip-reason=";
  for (var i = 0; i < args.length; i += 1) {
    if (args[i].indexOf(flag) === 0) return args[i].slice(flag.length).trim();
  }
  return "";
}

(async function main() {
  var args = process.argv.slice(2);
  var skipCheck = args.indexOf("--skip-service-check") !== -1;
  var skipReason = _skipReason(args);
  var named = args.filter(function (a) { return a.charAt(0) !== "-"; });

  // Refused before anything is discovered or spawned, so a bypass without a
  // reason costs nothing to find and cannot be half-applied. The pre-flight is
  // the answer to whether the thing under test is running at all, and a skip
  // that costs one flag is one that ends up in every invocation, at which point
  // the suite drives whatever happens to be listening and reports it green.
  if (skipCheck && skipReason.length === 0) {
    console.error("[test-integration] --skip-service-check requires " +
      "--service-check-skip-reason=\"<why>\".");
    console.error("[test-integration] The pre-flight probes the listeners this suite is about " +
      "to drive, so skipping it skips the answer to whether the server is up at all. That is " +
      "an audited exception, not a convenience: the reason is printed as a banner and stays in " +
      "the transcript.");
    process.exit(UNJUSTIFIED_SKIP_EXIT);
    return;
  }

  if (!fs.existsSync(INTEGRATION_DIR)) {
    console.error("[test-integration] missing dir: " + INTEGRATION_DIR);
    console.error("[test-integration] the interop suite lives there and is tracked even " +
      "while it holds no test file; a missing directory is a broken tree, not an empty suite.");
    _finish(3, [
      { unit: "interop-files",   n: 0 },
      { unit: "located-clients", n: 0 },
      { unit: "driven-checks",   n: 0 },
    ]);
    return;
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
    console.log("[test-integration] SUITE EMPTY: " + INTEGRATION_DIR + " holds no *.test.js file.");
    console.log("[test-integration] Nothing was proven. This is NOT a pass.");
    console.log("[test-integration] An interop file drives a running server from the outside " +
      "with a client that is not this codebase; see test/integration/README.md.");
    _finish(4, [
      { unit: "interop-files",   n: 0 },
      { unit: "located-clients", n: 0 },
      { unit: "driven-checks",   n: 0 },
    ]);
    return;
  }

  var files = present.filter(function (f) {
    if (named.length === 0) return true;
    return named.some(function (n) { return f === n || f === n + ".test.js"; });
  });

  if (files.length === 0) {
    console.error("[test-integration] no test file matched " + named.join(", "));
    console.error("[test-integration] present: " + present.join(", "));
    _finish(3, [
      { unit: "interop-files",   n: 0 },
      { unit: "located-clients", n: 0 },
      { unit: "driven-checks",   n: 0 },
    ]);
    return;
  }

  // Before the stack is asked about, because a machine with no client cannot
  // prove an interop property however healthy the listeners are, and finding
  // that out costs one probe per client rather than a whole suite run.
  var probe = await _preflightClients(INTEGRATION_DIR, files);
  console.log("");
  console.log("[test-integration] " + probe.located.length + " of " + probe.needed.length +
    " foreign client(s) the selected file(s) need are on this machine:");
  probe.located.forEach(function (c) {
    console.log("  " + _padRight(c.id, 18) + "located  " + c.bin + " -- " + c.detail);
  });
  probe.absent.forEach(function (c) {
    console.log("  " + _padRight(c.id, 18) + "ABSENT   " + c.reason);
  });

  if (probe.absent.length > 0 && REQUIRE_CLIENTS) {
    console.error("");
    console.error("[test-integration] REFUSED: INTEGRATION_REQUIRE_CLIENTS=1 and " +
      probe.absent.length + " client(s) the selected file(s) need are not on this machine:");
    probe.absent.forEach(function (c) {
      console.error("  " + c.id + " (" + c.name + "): " + c.reason);
    });
    console.error("[test-integration] Install them, name them with the variable in the " +
      "reason above, or unset INTEGRATION_REQUIRE_CLIENTS to have the cases needing them " +
      "reported as skipped instead.");
    _finish(5, [
      { unit: "interop-files",   n: files.length },
      { unit: "located-clients", n: probe.located.length },
      { unit: "driven-checks",   n: 0 },
    ]);
    return;
  }

  if (probe.absent.length > 0) {
    console.log("[test-integration] A skipped client is not a located one. The cases behind " +
      "each name above will not run, and this run does not answer for what they assert. " +
      "Set INTEGRATION_REQUIRE_CLIENTS=1 to make an absent client fail the run instead.");
  }

  if (skipCheck) {
    console.log("");
    console.log("[test-integration] !! SERVICE PRE-FLIGHT SKIPPED BY OPERATOR OVERRIDE");
    console.log("[test-integration] !! reason: " + skipReason);
    console.log("[test-integration] !! The listeners this suite drives were not probed, so a " +
      "failure below may be a stack that is down rather than a defect.");
    console.log("");
  } else {
    console.log("[test-integration] running scripts/check-services.js gate...");
    var checkExit = await _spawn(process.execPath, [CHECK_SERVICES]);
    if (checkExit.code !== 0) {
      console.error("[test-integration] service-check gate failed (exit " + checkExit.code + ")");
      console.error("[test-integration] bring the stack up first:");
      console.error("[test-integration]   docker compose up -d --wait");
      console.error("[test-integration] OR re-run with --skip-service-check " +
        "--service-check-skip-reason=\"<why>\" to bypass");
      _finish(1, [
        { unit: "interop-files",   n: files.length },
        { unit: "located-clients", n: probe.located.length },
        { unit: "driven-checks",   n: 0 },
      ]);
      return;
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

  var units = [
    { unit: "interop-files",   n: files.length },
    { unit: "located-clients", n: probe.located.length },
    { unit: "driven-checks",   n: totalChecks },
  ];

  console.log("");
  if (failed === 0) {
    console.log("[test-integration] OK, " + totalChecks + " checks passed" +
      (totalSkips > 0 ? " (" + totalSkips + " check(s) skipped for an absent optional endpoint)" : "") +
      " across " + files.length + " file(s) in " + (Date.now() - suiteStart) + "ms" +
      (probe.absent.length > 0
        ? ", with " + probe.absent.length + " foreign client(s) absent: " +
          probe.absent.map(function (c) { return c.id; }).join(", ")
        : ""));
    _finish(0, units);
    return;
  }
  console.error("[test-integration] " + failed + " of " + files.length + " file(s) failed");
  _finish(2, units);
})().catch(function (err) {
  console.error("[test-integration] runner error: " + ((err && err.stack) || err));
  process.exit(3);
});
