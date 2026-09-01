// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/run-gates.js
 *
 * Runs the declared static-gate list and reports a verdict for every gate
 * in it.
 *
 * WHY THIS EXISTS. An `&&`-joined shell chain stops at its first failing
 * link. Everything after that link does not run, and nothing in the output
 * says so: the transcript ends where the failure happened and the remaining
 * gates leave no trace at all. One red gate therefore converts every gate
 * behind it into an unknown, and an unknown printed as nothing reads as a
 * red. Measured on this tree, a single failing first link hid seven gates
 * behind it, and the only way to learn they were green was to run each of
 * them by hand.
 *
 * That is the same defect the `EXAMINED <n> <unit>` contract exists to
 * refuse, arriving from the other side. A gate that examined an empty set
 * answers for no part of the tree; a gate that never ran answers for no
 * part of the tree either, and it does so more quietly, because it
 * publishes nothing to notice. So the rule is the same in both
 * directions: a verdict has to be published, and an absent verdict is
 * never a pass.
 *
 * WHAT IT GUARANTEES.
 *
 *   - Every declared gate is attempted, whatever the ones before it did.
 *   - Every gate ends the run with one of four named verdicts: passed,
 *     FAILED, NOT RUN, or UNANSWERED. There is no fifth state and no
 *     silence.
 *   - A gate that could not be started at all is NOT RUN and fails the
 *     run. A missing file is the way past a gate that tolerates absence,
 *     so absence is a finding rather than a skip.
 *   - A gate that ran, exited clean, and published no count, or published
 *     a zero in any unit, is UNANSWERED and fails the run. That is the
 *     same hole as NOT RUN reached from the other side, and it is the
 *     quieter of the two, because the gate does print something.
 *   - The exit code is non-zero when any gate failed, did not run, or did
 *     not answer, so a caller keys on the same signal the chain gave it.
 *   - Declared order is preserved, so the cheapest gates still answer
 *     first. Cheapest-first is about how quickly a failure is SEEN; it
 *     was never a reason for the expensive gates to go unmeasured when a
 *     cheap one fails.
 *
 * THE COUNT, AND WHY THE RUNNER READS IT. The project's contract says a
 * gate exiting clean over an empty set stops the cut, and that refusal
 * lived in `scripts/release.js` alone. So a gate publishing `EXAMINED 0`
 * passed `npm run gates`, passed CI, and was caught only if somebody
 * happened to run a release, which is exactly the tree this repository
 * has already paid for: the spelling gate resolved its reads against a
 * wrong base, the tree went unread, its canary still passed, and four real
 * findings vanished behind a clean exit code. A canary proves a checker
 * still FIRES; only a count proves it REACHED anything. The count belongs
 * where the gates are actually run, which is here.
 *
 * THE POLICY ON A GATE THAT PUBLISHES NOTHING, written down rather than
 * decided per gate: every gate in the declared chain publishes at least one
 * count, and a gate that publishes none is UNANSWERED. There is no
 * exemption list, because an exemption list is a second hand-maintained
 * list of gates in a repository that has been bitten by exactly that, and
 * because every gate in this chain does sweep a set whose emptiness would
 * be a fault: a manifest with no packages, a lockfile comparison that
 * matched no specs, a floor sweep that found no references. A gate with
 * genuinely nothing to count does not belong in a chain whose whole subject
 * is what was examined.
 *
 * WHY THE OUTPUT IS CAPTURED. Reading what a gate published means holding
 * its stdout, so a gate's transcript now arrives when it finishes rather
 * than line by line. That costs the live progress of a long gate and buys
 * the only evidence that it looked at anything; every gate persists its own
 * detail to `.test-output/` regardless, and `scripts/release.js` made the
 * same trade for the same reason.
 *
 * WHERE THE LIST LIVES. In `scripts.gates` in package.json, passed here
 * as one argument per gate. That file stays the single authority: the
 * runner holds no list of its own, cannot drift from one, and a gate
 * added there starts running everywhere with no second edit. A copy kept
 * here would be a third hand-maintained list of gates in a repository
 * that has been bitten by exactly that.
 *
 * WHAT IT PUBLISHES, in the form the release battery reads:
 *
 *   EXAMINED <n> declared-gates
 *   EXAMINED <n> gates-run
 *   EXAMINED <n> published-counts
 *
 * Three, because they fail independently and each one alone can be
 * satisfied over nothing. `declared-gates` is the list as it arrived: an
 * empty one runs nothing and would otherwise exit clean, which is a
 * perfect score over no gates. `gates-run` is how many were actually
 * started, which comes apart from the first number the moment a gate
 * script is missing or unspawnable. `published-counts` is how many count
 * lines this runner actually READ back off the gates, which is the
 * runner's answer to the question it now asks of everything else: a reader
 * that stopped reaching the lines would take that number to zero while
 * both of the others stayed healthy.
 *
 * Usage:
 *   node scripts/run-gates.js "node scripts/check-one.js" "node scripts/check-two.js --check"
 */

var fs        = require("node:fs");
var path      = require("node:path");
var spawnSync = require("node:child_process").spawnSync;

var counts = require("./examined-counts.js");

var REPO_ROOT  = path.resolve(__dirname, "..");
var OUTPUT_DIR = path.join(REPO_ROOT, ".test-output");

// Where the verdict summary is persisted, so a run that exits non-zero
// leaves its findings on disk rather than in a scrollback the next command
// overwrites. The override exists for one caller: the layer-0 cases that
// drive this runner against stand-in gates. Without it those runs land on
// the same path as the real chain, so running the test suite replaces the
// summary of the last real `npm run gates` with a list of fixture gates,
// and the log the failure discipline says to read first describes a tree
// nobody was asking about.
var LOG_FILE = process.env.BLAMEPOST_GATES_LOG ||
  path.join(OUTPUT_DIR, "gates.log");

// The four verdicts a gate can end with. Frozen words rather than
// booleans: "did not run", "ran and failed" and "ran and answered for
// nothing" call for different fixes, and a reader that cannot tell them
// apart goes looking in the wrong place. NOT_RUN and UNANSWERED are the
// two a boolean cannot spell.
var PASSED     = "passed";
var FAILED     = "FAILED";
var NOT_RUN    = "NOT RUN";
var UNANSWERED = "UNANSWERED";

// The count words a gate may answer in. `CHECKS <n>` is the detector
// suite's, frozen in that spelling because test/smoke.js reads it too; every
// other gate answers in `EXAMINED <n> <unit>`. Both are accepted here rather
// than demanded per gate, because which word a gate uses is a property of
// the gate and the runner's question is only whether it answered at all.
var ACCEPTED_TOKENS = ["EXAMINED", "CHECKS"];

// ---------------------------------------------------------------------------
// Reading the declared list
// ---------------------------------------------------------------------------

/**
 * _parseGate(commandText) turns one declared gate into something
 * spawnable.
 *
 * A gate is written the way it would be typed: `node <script> [args]`.
 * The tokens are split on whitespace, which is all this list has ever
 * needed, and a token carrying a quote is refused rather than guessed at
 * so a gate that grows a quoted argument is a loud parse failure here
 * instead of a silently mis-split command line.
 *
 * Returns { text, script, args } or throws with the reason.
 */
function _parseGate(commandText) {
  var text = String(commandText).trim();
  if (text.length === 0) throw new Error("empty gate command");
  if (/["']/.test(text)) {
    throw new Error("gate command carries a quote, which this runner does not " +
      "split: " + text);
  }
  var tokens = text.split(/\s+/);
  if (tokens[0] !== "node") {
    throw new Error("gate command must start with `node`: " + text);
  }
  if (tokens.length < 2) throw new Error("gate command names no script: " + text);
  return { text: text, script: tokens[1], args: tokens.slice(1) };
}

// ---------------------------------------------------------------------------
// Running one gate
// ---------------------------------------------------------------------------

/**
 * _runOne(gate) runs one gate and returns its verdict record.
 *
 * The child's stdout is CAPTURED and written through rather than
 * inherited. Inheriting is what a reader wants, since the gate's output
 * then arrives live and in order, and it is incompatible with reading the
 * count the gate published: a stream handed straight to the terminal passes
 * through nothing this process can inspect. Reading the count is the point,
 * so the trade goes the other way: the transcript arrives when the gate
 * finishes, and every gate persists its own detail to `.test-output/`
 * meanwhile. `scripts/release.js` made the identical trade for the
 * identical reason.
 *
 * `spawnSync` is deliberate: the exit code arrives as a value on the
 * result rather than through a pipe. A gate whose verdict is read off the
 * end of a pipeline reports the pipeline's status instead of its own,
 * which is how a failing gate has already been recorded as a pass in this
 * project once.
 */
function _runOne(gate) {
  // Resolved rather than joined, so a gate named by an absolute path is
  // run where it actually is. The declared list uses repository-relative
  // paths and always will; what this buys is a runner that can be driven
  // against a fixture tree without a gate stand-in having to be written
  // into the working tree to be reachable.
  var absolute = path.resolve(REPO_ROOT, gate.script);
  if (!fs.existsSync(absolute)) {
    return {
      text:    gate.text,
      script:  gate.script,
      verdict: NOT_RUN,
      code:    null,
      counts:  [],
      reason:  "the script is not on disk at " + gate.script,
    };
  }

  var result = spawnSync(process.execPath, gate.args, {
    cwd:      REPO_ROOT,
    stdio:    ["ignore", "pipe", "pipe"],
    shell:    false,
    encoding: "utf8",
    // A gate's transcript is the detector suite's worst case here and it
    // runs to a few hundred kilobytes. The cap is a backstop well above
    // that: a gate that produced more than this has a fault of its own,
    // and truncating its middle is better than the runner dying on it.
    maxBuffer: 64 * 1024 * 1024,
  });

  var stdout = result.stdout || "";
  var stderr = result.stderr || "";
  if (stdout) process.stdout.write(stdout.endsWith("\n") ? stdout : stdout + "\n");
  if (stderr) process.stderr.write(stderr.endsWith("\n") ? stderr : stderr + "\n");

  if (result.error) {
    return {
      text:    gate.text,
      script:  gate.script,
      verdict: NOT_RUN,
      code:    null,
      counts:  [],
      reason:  "the gate could not be started: " +
               ((result.error && result.error.message) || String(result.error)),
    };
  }

  // A gate killed by a signal produced no verdict of its own. Reporting
  // the null exit code as anything other than a failure would let a gate
  // that was cut short read as one that answered.
  if (result.signal) {
    return {
      text:    gate.text,
      script:  gate.script,
      verdict: NOT_RUN,
      code:    null,
      counts:  [],
      reason:  "the gate was killed by " + result.signal + " before it reached a verdict",
    };
  }

  if (result.status !== 0) {
    return {
      text:    gate.text,
      script:  gate.script,
      verdict: FAILED,
      code:    result.status,
      counts:  counts.publishedCounts(stdout, ACCEPTED_TOKENS),
      reason:  "exit " + result.status,
    };
  }

  // The gate exited clean, so the only question left is whether the clean
  // verdict answers for anything. Applied to a passing run alone on
  // purpose: a gate that already failed has a finding to act on, and
  // replacing it with a complaint about its counts would bury the finding
  // under the accounting.
  var published = counts.publishedCounts(stdout, ACCEPTED_TOKENS);
  if (published.length === 0) {
    return {
      text:    gate.text,
      script:  gate.script,
      verdict: UNANSWERED,
      code:    result.status,
      counts:  published,
      reason:  "it exited clean and published no " + ACCEPTED_TOKENS.join(" or ") +
               " count, so it will not say what it looked at",
    };
  }
  var empty = counts.emptyUnits(published);
  if (empty.length > 0) {
    return {
      text:    gate.text,
      script:  gate.script,
      verdict: UNANSWERED,
      code:    result.status,
      counts:  published,
      reason:  "it exited clean having examined nothing: it published 0 " +
               empty.join(" and 0 ") + ", so its discovery matched an empty set",
    };
  }

  return {
    text:    gate.text,
    script:  gate.script,
    verdict: PASSED,
    code:    result.status,
    counts:  published,
    reason:  counts.format(published),
  };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

function _report(lines) {
  lines.forEach(function (l) { console.log(l); });
  // The summary is persisted for the same reason every other gate here
  // persists: a run that exits non-zero must leave its findings on disk,
  // rather than in a terminal scrollback that the next command overwrites.
  // Drop-silent by design: the verdict is already decided and a
  // filesystem fault must not replace it with a different failure.
  try {
    fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
    var fd = fs.openSync(LOG_FILE, "w");
    try { fs.writeSync(fd, lines.join("\n") + "\n"); }
    finally { fs.closeSync(fd); }
  } catch (_e) { /* drop-silent by design: the summary above is the result */ }
}

function _summaryLines(results, declared) {
  var width = results.reduce(function (w, r) {
    return Math.max(w, r.script.length);
  }, 0);

  var lines = ["", "gate verdicts:"];
  results.forEach(function (r) {
    var pad  = new Array(Math.max(1, width - r.script.length + 2)).join(" ") + " ";
    var note = r.reason ? "  (" + r.reason + ")" : "";
    lines.push("  " + r.script + pad + r.verdict + note);
  });

  var failed     = results.filter(function (r) { return r.verdict === FAILED; });
  var notRun     = results.filter(function (r) { return r.verdict === NOT_RUN; });
  var unanswered = results.filter(function (r) { return r.verdict === UNANSWERED; });

  lines.push("");
  if (failed.length > 0) {
    lines.push("FAILED (" + failed.length + "): " +
      failed.map(function (r) { return r.script; }).join(", "));
  }
  if (notRun.length > 0) {
    lines.push("NOT RUN (" + notRun.length + "): " +
      notRun.map(function (r) { return r.script; }).join(", ") +
      " — a gate that did not run answered for no part of the tree, which is not a pass");
  }
  // Named one per line with the reason it gave, because the two ways of
  // not answering call for different fixes: a gate that published nothing
  // has to be taught the contract, and a gate that published a zero has a
  // discovery that stopped matching, which is a live defect in whatever it
  // was supposed to be reading.
  if (unanswered.length > 0) {
    lines.push("UNANSWERED (" + unanswered.length + "): a gate that exited clean over an " +
      "empty set answers for no part of the tree, which is not a pass");
    unanswered.forEach(function (r) {
      lines.push("  " + r.script + ": " + r.reason);
    });
  }
  if (failed.length === 0 && notRun.length === 0 && unanswered.length === 0) {
    lines.push("all " + results.length + " declared gates ran, answered, and passed");
  }

  // The counts, last, in the form the release battery reads. Three units
  // because each can be satisfied over nothing on its own: a list that
  // arrived empty, a list that arrived full of gates none of which started,
  // and a run whose gates all started while this runner read nothing back
  // off any of them.
  lines.push("EXAMINED " + declared + " declared-gates");
  lines.push("EXAMINED " + results.filter(function (r) {
    return r.verdict !== NOT_RUN;
  }).length + " gates-run");
  lines.push("EXAMINED " + results.reduce(function (n, r) {
    return n + ((r.counts && r.counts.length) || 0);
  }, 0) + " published-counts");

  return lines;
}

// ---------------------------------------------------------------------------

function main(argv) {
  // An empty list is refused rather than run. Running no gates and
  // exiting clean is a perfect score over nothing, which is precisely the
  // verdict this runner exists to stop anyone from being handed.
  if (argv.length === 0) {
    console.error("[run-gates] no gates were declared. The list lives in " +
      "`scripts.gates` in package.json, one quoted command per gate; an empty " +
      "list would exit clean having measured no part of the tree.");
    console.log("EXAMINED 0 declared-gates");
    console.log("EXAMINED 0 gates-run");
    console.log("EXAMINED 0 published-counts");
    process.exit(1);
  }

  var gates = [];
  var parseFailures = [];
  argv.forEach(function (text) {
    try { gates.push(_parseGate(text)); }
    catch (e) { parseFailures.push((e && e.message) || String(e)); }
  });

  // A gate the runner cannot even read is not something to route around:
  // it would silently shrink the list, which is the same defect as the
  // short-circuit, reached by a different door.
  if (parseFailures.length > 0) {
    console.error("[run-gates] the declared gate list does not parse:");
    parseFailures.forEach(function (m) { console.error("  - " + m); });
    console.log("EXAMINED " + argv.length + " declared-gates");
    console.log("EXAMINED 0 gates-run");
    console.log("EXAMINED 0 published-counts");
    process.exit(1);
  }

  console.log("[run-gates] " + gates.length + " declared gate(s); every one is run, every " +
    "one reports a verdict whatever the ones before it did, and every one says what it " +
    "examined or does not pass.");

  var results = [];
  gates.forEach(function (gate, i) {
    console.log("");
    console.log("--- gate " + (i + 1) + "/" + gates.length + ": " + gate.text + " ---");
    results.push(_runOne(gate));
  });

  var lines = _summaryLines(results, gates.length);
  _report(lines);

  var bad = results.filter(function (r) { return r.verdict !== PASSED; });
  process.exit(bad.length === 0 ? 0 : 1);
}

module.exports = {
  PASSED:          PASSED,
  FAILED:          FAILED,
  NOT_RUN:         NOT_RUN,
  UNANSWERED:      UNANSWERED,
  ACCEPTED_TOKENS: ACCEPTED_TOKENS,
};

if (require.main === module) {
  main(process.argv.slice(2));
}
