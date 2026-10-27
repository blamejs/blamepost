#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * release.js orchestrates the full release flow as a sequence of
 * idempotent subcommands. Each subcommand performs ONE phase, prints
 * what it did, and exits with a code that's safe to script against in a
 * CI runner or an operator's terminal.
 *
 * Usage:
 *   node scripts/release.js prepare    # bump + regen CHANGELOG/api-snapshot + static gates
 *   node scripts/release.js regen      # re-regen artifacts (after release-notes edits)
 *   node scripts/release.js smoke       # smoke + interop
 *   node scripts/release.js commit      # release branch + signed commit
 *   node scripts/release.js interop     # cross-implementation interop tests
 *   node scripts/release.js push        # interop + gitleaks + push + open PR
 *   node scripts/release.js watch       # gh pr checks --watch + flag review threads
 *   node scripts/release.js merge       # squash-merge if CLEAN + zero unresolved threads
 *   node scripts/release.js tag         # signed tag + push tag + verify
 *   node scripts/release.js publish     # watch both publish workflows, then read the
 *                                       #   npm version and the image digest back
 *   node scripts/release.js all         # prepare -> ... -> publish
 *
 *   node scripts/release.js help        # this banner
 *   node scripts/release.js status      # what phase the current branch is in
 *
 * Pre-conditions:
 *   - The release-notes JSON `release-notes/v<next>.json` MUST already
 *     exist before `prepare` runs. The script refuses and prints a
 *     template to stdout otherwise: the headline, the summary and the
 *     sections require human judgment and don't auto-generate from a diff.
 *     `regen` folds that hand-written file into the minor series file
 *     `release-notes/v<X>.<Y>.x.json` and removes it, so every phase
 *     after the fold reads the release back out of the series.
 *   - Git signing config (SSH + allowed_signers + commit/tag.gpgsign)
 *     must be in place before the first signed commit/tag.
 *
 * PUBLISHES-NO-COUNT: this file invokes gates rather than being one, so it
 * has no set of its own whose emptiness would be a fault. It reads the
 * `EXAMINED <n> <unit>` lines the gates it spawns publish, and refuses a
 * cut when one of them comes back empty; a count of its own would be a
 * number about how many subcommands ran, which nothing is deciding
 * anything from. It matches the gate shape only because it passes
 * `--check` along to the gates it drives.
 *
 * The judgment-requiring parts stay manual:
 *   - Writing `release-notes/v<next>.json` content.
 *   - Reviewing review-bot P1/P2 findings (watch flags them + stops; the
 *     operator writes the fix + re-runs watch).
 *   - Choosing minor vs patch bump (default: patch;
 *     override via `--minor` on prepare).
 */

var fs           = require("node:fs");
var path         = require("node:path");
var childProcess = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");

// ---- Repo coordinates (owner/name) ---------------------------------------
//
// Parsed from package.json `repository.url` so the gh + GraphQL calls point
// at the right slug without a hardcode drifting from the manifest.
function _repoSlug() {
  var owner = "blamejs";
  var name = "blamepost";
  try {
    var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    var url = (pkg.repository && pkg.repository.url) || "";
    var m = url.match(/github\.com[/:]([^/]+)\/([^/.]+(?:\.[^/.]+)*?)(?:\.git)?$/);
    if (m) { owner = m[1]; name = m[2]; }
  } catch (_e) { /* fall back to defaults */ }
  return { owner: owner, name: name };
}

// The published container image for a version, in the form
// `.github/workflows/release-container.yml` pushes: the repository owner,
// the repository name, and the version as the tag. The tag carries no `v`,
// because the git tag is `vX.Y.Z` and the image published from it is
// `X.Y.Z`, which is the form compose.yml and the quick start both use.
function _containerImageRef(version) {
  var slug = _repoSlug();
  return "ghcr.io/" + slug.owner + "/" + slug.name + ":" + version;
}

// ---- Helpers -------------------------------------------------------------

// The last line a command printed, with blank trailing lines dropped. A
// tool that prints a warning before its answer would otherwise be read as
// having answered the warning.
function _lastLine(text) {
  var lines = String(text || "").split(/\r?\n/)
    .map(function (l) { return l.trim(); })
    .filter(function (l) { return l !== ""; });
  return lines.length === 0 ? "" : lines[lines.length - 1];
}

// Windows resolves `npm` / `npx` as `npm.cmd` / `npx.cmd` shims, which
// child_process.spawn can only invoke through a shell. Everything else in
// the release-flow toolchain (`gh`, `git`, `docker`, `node`) is a native
// exe that spawns directly without a shell. Keeping shell off avoids the
// DEP0190 deprecation + the implicit arg-quoting risk.
function _needsShell(cmd) {
  if (process.platform !== "win32") return false;
  return cmd === "npm" || cmd === "npx";
}

function _readPackageVersion() {
  var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  return pkg.version;
}

function _writePackageVersion(next) {
  var pkgPath = path.join(ROOT, "package.json");
  var content = fs.readFileSync(pkgPath, "utf8");
  var updated = content.replace(/"version":\s*"[^"]+"/, '"version": "' + next + '"');
  if (updated === content) {
    throw new Error("release: failed to rewrite package.json version line");
  }
  fs.writeFileSync(pkgPath, updated);
}

function _bumpPatch(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + parts[1] + "." + (parts[2] + 1);
}

function _bumpMinor(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + (parts[1] + 1) + ".0";
}

// Quote a single argument for a Windows cmd.exe command line. Tokens made
// only of safe characters pass through unquoted; anything else is
// double-quoted with embedded quotes doubled.
function _quoteWinArg(a) {
  a = String(a);
  if (/^[A-Za-z0-9_@.\-/:=]+$/.test(a)) return a;
  return '"' + a.replace(/"/g, '""') + '"';
}

// Windows resolves npm / npx through .cmd shims that can only be launched
// via a shell (the CVE-2024-27980 mitigation refuses to spawn .cmd files
// without one). Node 26's DEP0190 deprecates pairing an args ARRAY with
// shell:true because the args would be concatenated onto the command line
// without escaping, which is a quoting / injection hazard. Build a single,
// explicitly-quoted command string and pass NO args array. Every spawn in
// this file (run and capture alike) routes through this one form.
function _shellForm(cmd, args) {
  if (!_needsShell(cmd)) return { cmd: cmd, args: args, shell: false };
  return {
    cmd: [cmd].concat(args.map(_quoteWinArg)).join(" "),
    args: undefined,
    shell: true,
  };
}

function _run(cmd, args, opts) {
  opts = opts || {};
  args = args || [];
  var form = _shellForm(cmd, args);
  var rv = childProcess.spawnSync(form.cmd, form.args, {
    cwd:   opts.cwd   || ROOT,
    stdio: opts.stdio || "inherit",
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: form.shell,
  });
  if (rv.status !== 0 && !opts.allowFail) {
    throw new Error("release: " + cmd + " " + args.join(" ") +
                    " failed with status " + rv.status);
  }
  return rv;
}

// ABSENCE FAILS. Every gate routed through here is a file this repository
// tracks, so a missing one is a broken checkout and not an environment that
// has yet to configure the gate. Tolerating a missing script here buys a way
// past any gate in the battery that costs a single `git rm`. A gate that
// silently skips when its script is missing stops gating at exactly the
// moment nobody is told, which is the rule
// scripts/check-operator-prose.js states at its own probe, and the reason the
// interop gate below refuses the same tolerance.
//
// There is no override, and that asymmetry with --skip-interop is deliberate.
// An interop run needs sockets and a listening server, so a machine can
// genuinely be unable to perform it, and an audited, written-down bypass is
// the honest answer for a gate in that position. These are node scripts that
// run wherever the release flow itself runs, so no such environment exists,
// and a bypass with no legitimate use is only ever used illegitimately.
function _requireGateScript(relScriptPath) {
  var abs = path.join(ROOT, relScriptPath);
  if (fs.existsSync(abs)) return abs;
  throw new Error(
    "release: " + relScriptPath + " is missing, and a missing gate script is not a pass. " +
    "Nothing was checked, so there is nothing to report clean. Restore the file, or take the " +
    "gate out of the battery as a deliberate edit rather than by deleting what it runs.");
}

// The structural-detector suite, named as a path because the battery has to
// know which gate publishes a liveness signal. Its last line is `CHECKS <n>`,
// the same contract test/smoke.js reads to refuse a test file that exited
// clean having asserted nothing.
var DETECTOR_GATE = "test/layer-0-primitives/codebase-patterns.test.js";

// THE EXAMINED-COUNT CONTRACT, and the one reader of it.
//
// A gate whose script is absent checked nothing, and _requireGateScript above
// refuses that. A gate that runs, exits clean and examined nothing is the same
// hole reached by a different route, and it is the harder of the two to see:
// "OK, no findings" is byte-identical whether the gate read every file in the
// tree or none of them. A glob that stopped matching, a walk pointed at a
// directory that moved, a filter that widened until it covered everything, all
// land there, and all of them read as a clean bill of health for every rule the
// gate carries.
//
// So each gate in the battery publishes what it examined, as trailing lines of
// the form
//
//   EXAMINED <n> <unit>
//
// one line per unit it wants to answer for, and the detector suite publishes
// the `CHECKS <n>` line it already froze for test/smoke.js. The unit is the
// gate's own choice and is load-bearing: a validator that opened 200 files and
// extracted 0 documentation blocks proved as little as one that opened none, so
// the number that has to move is the one the rules are actually applied to.
//
// The lines are read from the END of stdout, stopping at the first line that is
// not one of them. That keeps the contract cheap for the gate, which prints its
// ordinary human report and then its counts, and it holds on a FAILING run too:
// a gate is expected to publish its counts whatever its verdict, so the number
// is in the log beside the findings rather than only beside a pass.
// The reader itself lives in scripts/examined-counts.js, because three
// callers read these lines: this battery, the runner that executes the
// declared chain, and the layer-0 cases holding both to the contract. Three
// copies of "read the last lines, refuse a zero" is three places for the
// refusal to quietly differ, and the copy that drifts is the one nobody
// watches run. A count read only from this battery lets a gate publishing a
// zero pass `npm run gates` and CI, caught only by somebody happening to cut
// a release.
var examinedCounts = require("./examined-counts.js");

// The runner that executes the declared chain, required here for the two things
// it owns: the count words a gate may answer in, and the reader of
// `scripts.gates` in package.json. Both are read rather than restated, because
// a second copy of either is a second thing to keep in step and the copy that
// drifts is the one nobody watches run. That has already happened in this
// file: its battery was a hand-written list and three gates in the chain were
// missing from it.
var runGates = require("./run-gates.js");

// Run one gate for its verdict AND for the count behind it. Every gate in the
// battery that publishes a count comes through here, so the rule is written
// once: five copies of "read the last line, refuse a zero" is five places for
// the refusal to quietly differ.
//
// The output is captured and written through rather than inherited, which costs
// the live progress of the gate and buys the ability to read what it published.
//
// Both count words are accepted from every gate, exactly as the chain runner
// accepts them: `CHECKS <n>` is the detector suite's, frozen in that spelling
// because test/smoke.js reads it, and which word a gate answers in is a
// property of the gate rather than something a caller should have to know. What
// IS chosen per gate is `verb`, the word the refusal uses, because a suite that
// asserted nothing and a walk that examined nothing are the same defect
// described in the vocabulary of two different jobs, and the operator reading
// the refusal is looking at one of them.
function _runCountedGate(relScriptPath, opts) {
  opts = opts || {};
  var verb = opts.verb || "examined";
  _requireGateScript(relScriptPath);
  var rv = _capture("node", [relScriptPath].concat(opts.args || []));
  if (rv.stdout) console.log(rv.stdout);
  if (rv.stderr) console.error(rv.stderr);
  if (rv.status !== 0) {
    throw new Error("release: " + relScriptPath + " failed with status " + rv.status);
  }
  var counts = examinedCounts.publishedCounts(rv.stdout, runGates.ACCEPTED_TOKENS);
  if (counts.length === 0) {
    throw new Error(
      "release: " + relScriptPath + " exited clean having " + verb + " nothing: its output " +
      "carries no " + runGates.ACCEPTED_TOKENS.join(" or ") + " count. A gate that will not say " +
      "what it looked at reports nothing about any rule it carries, and that is not a pass.");
  }
  var empty = examinedCounts.emptyUnits(counts);
  if (empty.length > 0) {
    throw new Error(
      "release: " + relScriptPath + " exited clean having " + verb + " nothing: it published 0 " +
      empty.join(" and 0 ") + ". Its discovery matched an " +
      "empty set, so its clean verdict answers for no part of this tree, and that is not a pass.");
  }
  _ok(relScriptPath + ": " + examinedCounts.format(counts));
}

function _capture(cmd, args, opts) {
  opts = opts || {};
  var form = _shellForm(cmd, args || []);
  var rv = childProcess.spawnSync(form.cmd, form.args, {
    cwd:   opts.cwd || ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: form.shell,
  });
  return {
    status: rv.status,
    stdout: (rv.stdout || "").toString().trim(),
    stderr: (rv.stderr || "").toString().trim(),
  };
}

function _gitClean() {
  return _capture("git", ["status", "--porcelain"]).stdout === "";
}

function _gitBranch() {
  return _capture("git", ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
}

function _gitOnMain() {
  return _gitBranch() === "main";
}

function _gitOnRelease() {
  return /^release\/v\d+\.\d+\.\d+$/.test(_gitBranch());
}

function _releaseBranchFor(version) {
  return "release/v" + version;
}

function _releaseNotesPath(version) {
  return path.join(ROOT, "release-notes", "v" + version + ".json");
}

function _seriesNotesPath(version) {
  return path.join(ROOT, "release-notes", "v" + version.replace(/\.\d+$/, "") + ".x.json");
}

// The release's notes, wherever they currently live. An operator writes
// the hand-written file; `regen` folds it into the minor series file and
// removes it. Every phase after that fold has to read the release back
// out of the series, or the flow would refuse its own artifact.
function _loadReleaseNotes(version) {
  try {
    return JSON.parse(fs.readFileSync(_releaseNotesPath(version), "utf8"));
  } catch (e) {
    if (!e || e.code !== "ENOENT") throw e;
  }
  var series;
  try {
    series = JSON.parse(fs.readFileSync(_seriesNotesPath(version), "utf8"));
  } catch (e2) {
    if (!e2 || e2.code !== "ENOENT") throw e2;
    return null;
  }
  var releases = Array.isArray(series.releases) ? series.releases : [];
  for (var i = 0; i < releases.length; i += 1) {
    if (releases[i] && releases[i].version === version) return releases[i];
  }
  return null;
}

function _ensureReleaseNotes(version) {
  if (_loadReleaseNotes(version) !== null) return;
  var template = {
    "$schema": "../scripts/release-notes-schema.json",
    version:   version,
    date:      new Date().toISOString().slice(0, 10),
    headline:  "<one-line operator-facing summary, no trailing full stop>",
    summary:   "<one paragraph on why it matters, ending in a full stop.>",
    sections: [
      {
        heading: "Added",
        items: [
          {
            title: "<short title, no trailing full stop>",
            body:  "<what changed and what an operator does about it.>",
          },
        ],
      },
    ],
  };
  console.error("");
  console.error("release: no notes for v" + version + ". Looked at " +
                _releaseNotesPath(version) + " and " + _seriesNotesPath(version) + ".");
  console.error("");
  console.error("Create the hand-written file before re-running. Template:");
  console.error("");
  console.error(JSON.stringify(template, null, 2));
  console.error("");
  process.exit(2);
}

function _section(title) {
  console.log("\n=== " + title + " ===");
}

function _ok(msg) {
  console.log("ok: " + msg);
}

// Normalize the release-notes `sections` (object keyed by heading, or an
// array of { heading, items }) into an ordered list of { heading, items }
// so the commit body + PR body render either shape.
function _sectionsList(sections) {
  var pairs = [];
  if (Array.isArray(sections)) {
    sections.forEach(function (s) {
      if (!s || !s.heading) return;
      var items = (s.items || []).map(function (it) {
        return typeof it === "string" ? it : (it && it.title ? it.title : String(it));
      });
      pairs.push({ heading: s.heading, items: items });
    });
  } else if (sections && typeof sections === "object") {
    Object.keys(sections).forEach(function (h) {
      if (Array.isArray(sections[h])) pairs.push({ heading: h, items: sections[h].slice() });
    });
  }
  return pairs.filter(function (p) { return p.items.length > 0; });
}

// Shared artifact-regeneration helper. Called by `prepare` after the
// version bump, and standalone via `regen` when the operator edits
// release-notes mid-flow. It is idempotent, so running it twice with no
// edits in between is a no-op.
function _regenArtifacts() {
  // Regenerate the committed lockfile to the just-bumped version FIRST, so the
  // pin-all --check static gate can never ship a lockfile that records the
  // previous release.
  _run("node", ["scripts/pin-all.js", "--lockfiles"]);
  // Fold the hand-written release file into its minor series file and
  // remove it, so the line carries one JSON however many patches it
  // grows. The CHANGELOG is rebuilt from the folded result, never from
  // the file that has just gone.
  _run("node", ["scripts/consolidate-release-notes.js", "--prune"]);
  _run("node", ["scripts/generate-changelog-entry.js", "--rebuild"]);
  _run("node", ["scripts/gen-migrating.js"]);
  _run("node", ["scripts/refresh-api-snapshot.js"]);
  _run("node", ["scripts/check-api-snapshot.js"]);
  _run("node", ["scripts/consolidate-release-notes.js", "--check"]);
  _run("node", ["scripts/generate-changelog-entry.js", "--check"]);
  _run("node", ["scripts/check-changelog-extract.js"]);
  _ok("lockfile + release notes + CHANGELOG + MIGRATING + api-snapshot regenerated");
}

// Verify HEAD's commit signature via two independent paths:
//   1. `git verify-commit HEAD` exits 0 on a Good signature (the same
//      truth signal GitHub's required_signatures ruleset checks).
//   2. `git log -1 --pretty=%h %G? %GS` prints the sha, the signature
//      letter and the signer as a human-readable line.
function _verifyCommitSignature(label) {
  var verifyRv = _capture("git", ["verify-commit", "HEAD"]);
  if (verifyRv.status !== 0) {
    var hint = "release: " + label + " commit signature is not Good. " +
               "Check SSH signing setup (commit.gpgsign=true + gpg.format=ssh + " +
               "~/.ssh/allowed_signers populated).";
    if (verifyRv.stderr) hint += "\n" + verifyRv.stderr;
    throw new Error(hint);
  }
  var sig = _capture("git", ["log", "-1", "--pretty=%h %G? %GS"]);
  console.log("signature: " + (sig.stdout || "(captured empty, verify-commit reports Good)"));
  _ok(label + " commit signature verified");
}

// Digest-pinned gitleaks image. The scan runs immediately before the branch
// push, so a floating tag would let a tag-swapped upstream image execute
// arbitrary code with the repo mounted at the most sensitive point in the
// flow. That is the same reason every GitHub Action is SHA-pinned and every
// Dockerfile FROM is digest-synced. Refresh by updating BOTH the version tag
// (informational) and the digest (the actual pin) together.
var GITLEAKS_IMAGE = "zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f";

// Docker gitleaks scan over full history, the same gate CI runs. Shared by
// `push` (before the PR opens) and `push-fix` (before a fix reaches the remote),
// so no secret is pushed even briefly. Windows host paths (`C:\Users\...`) must
// be rewritten to Docker Desktop's `//c/Users/...` form, because the colon in
// `C:` confuses the `-v src:dst` splitter. The mount is read-only: gitleaks only
// reads the work tree + .git history, and a scanner must not be able to write
// into the tree it is about to certify.
function _gitleaks() {
  _section("gitleaks");
  var mount;
  if (process.platform === "win32") {
    var posixified = ROOT.replace(/\\/g, "/");
    mount = "//" + posixified.charAt(0).toLowerCase() + posixified.slice(2);   // C:/x -> //c/x
  } else {
    mount = ROOT;
  }
  _run("docker", [
    "run", "--rm",
    "-v", mount + ":/repo:ro",
    "-w", "//repo",
    GITLEAKS_IMAGE,
    "git", "--config=.gitleaks.toml", "--redact", "--exit-code=1",
  ]);
  _ok("gitleaks clean");
}

// The open PR number for a release branch. This is the branch -> PR lookup
// shared by watch / merge / push-fix. Throws if the branch has no open PR.
function _openPrNumber(branch) {
  var prNum = _capture("gh", ["pr", "list", "--head", branch, "--state", "open",
                              "--json", "number", "--jq", ".[0].number"]).stdout;
  if (!prNum) {
    throw new Error("release: no open PR for branch " + branch);
  }
  return prNum;
}

// ---- Interop gate --------------------------------------------------------
//
// A mail server proves itself against real clients on real sockets: an MUA
// that pipelines IMAP commands, a receiving MTA that enforces MTA-STS, a
// submission client that gets its envelope refused. That live surface lives
// in scripts/test-integration.js. A change that only passed the in-process
// smoke can still mis-frame a response the moment something other than this
// codebase is reading it.
//
// Non-skippable except via an explicit, audited override
// (--skip-interop --interop-skip-reason="<why>"), printed loudly so a
// bypass is never silent.
//
// Returns { ran, reason }. `ran` is true only when interop files existed and
// all of them passed. It is false when the audited override skipped the gate,
// and false when the suite is EMPTY, which is a third state the runner reports
// with its own exit code: the directory is tracked and wired up, and no
// interop file has been written yet. That state proceeds without a flag,
// because an override that has to be typed on every single release stops
// being an audited exception and becomes a habit, and a habit skips the run
// that would have failed. It never reports as a pass: `reason` carries the
// state, and callers that publish gate results (the PR body) print it.
var INTEROP_EMPTY_EXIT = 4;

function cmdInterop(opts) {
  opts = opts || {};
  _section("interop");

  if (opts.skip) {
    if (!opts.skipReason) {
      throw new Error(
        "release: --skip-interop requires --interop-skip-reason=\"<why>\".\n" +
        "The interop gate proves the listeners against real clients on real " +
        "sockets; skipping it needs an explicit, audited reason printed to the " +
        "operator, not a silent bypass.");
    }
    console.log("");
    console.log("!! INTEROP SKIPPED BY OPERATOR OVERRIDE");
    console.log("!! reason: " + opts.skipReason);
    console.log("!! This override is recorded in the release-flow output above.");
    return { ran: false, reason: "SKIPPED by operator override: " + opts.skipReason };
  }

  // The interop gate IS configured for this repo: scripts/test-integration.js
  // is a required release input, so its absence is a broken tree, not an
  // unconfigured gate. Tolerating absence here would convert the one
  // non-skippable gate into a silent bypass (delete the script, skip the
  // gate). The audited --skip-interop override is the ONLY bypass.
  if (!fs.existsSync(path.join(ROOT, "scripts", "test-integration.js"))) {
    throw new Error(
      "release: scripts/test-integration.js is missing. The interop gate is " +
      "required and a missing gate script is not a pass. Restore the script, or " +
      "use --skip-interop --interop-skip-reason=\"<why>\" for an audited override.");
  }
  var rv = _run("node", ["scripts/test-integration.js"], { allowFail: true });
  if (rv.status === 0) {
    _ok("interop green");
    return { ran: true, reason: null };
  }
  if (rv.status === INTEROP_EMPTY_EXIT) {
    console.log("");
    console.log("!! INTEROP DID NOT RUN: the suite is empty, so nothing was proven.");
    console.log("!! This is not a pass and is published as an open box on the PR.");
    return {
      ran:    false,
      reason: "NOT RUN: test/integration/ holds no interop file, so nothing was proven",
    };
  }
  throw new Error("release: scripts/test-integration.js failed with status " + rv.status +
                  ". A failing interop run is a hard stop.");
}

// ---- Subcommands ---------------------------------------------------------

// The static gate battery. Every gate in it reads the WORKING TREE, so a run
// answers only for the bytes present at the moment it runs: a cut that edits
// the release notes or regenerates the CHANGELOG after an earlier hand-run
// leaves that run answering for a tree the commit no longer contains. Running
// it wherever a commit is about to be created is what makes the LAST edit the
// gated one, and it covers the cut shape that skips `prepare`. A feature
// already in the working tree cannot satisfy prepare's clean-main requirement,
// so prepare-only gating leaves that shape resting on the operator's memory.
//
// WHICH GATES IT RUNS IS NOT DECIDED HERE. The list is `scripts.gates` in
// package.json, read through scripts/run-gates.js, which is the same authority
// `npm run gates` and the pull-request workflow execute. This file used to
// spell the battery out by hand and the copy had drifted: three gates the chain
// runs were missing from it, so a release cut ran a WEAKER battery than a
// developer typing `npm run gates`, which is backwards. A gate added to the
// chain now runs here with no second edit, and there is no second list to fall
// behind.
//
// The commands BESIDE the chain are the ones the chain deliberately does not
// carry, and they are listed here because this is the caller that wants them:
// a linter that takes its own file arguments, and the two release-artifact
// round-trips, which compare a generated document against the notes it derives
// from rather than sweeping a set of the tree.
function _staticGates() {
  _section("static gates");
  _run("npx", ["--yes", "eslint@10.8.1", "--max-warnings", "0", "."]);

  // A chain that cannot be read, or that reads as empty, throws out of here
  // rather than running the gates that happened to parse. Shrinking the battery
  // silently is the one outcome none of this may produce.
  var declared = runGates.declaredGates(path.join(ROOT, "package.json"));
  console.log("declared gate chain: " + declared.length + " gate(s) from package.json " +
    "scripts." + runGates.CHAIN_KEY);
  declared.forEach(function (gate) {
    // The detector suite answers in `CHECKS <n>`, frozen in that spelling
    // because test/smoke.js reads it, and a suite that asserted nothing and a
    // walk that examined nothing are the same defect in two vocabularies. Both
    // words are accepted from every gate, as run-gates.js accepts them, because
    // which one a gate uses is a property of the gate; only the refusal's
    // wording is chosen per gate, and that is what an operator reads.
    _runCountedGate(gate.script, {
      args: gate.args.slice(1),
      verb: gate.script === DETECTOR_GATE ? "asserted" : "examined",
    });
  });

  // The notes gate publishes what it verified, so the battery reads it here
  // rather than taking the exit code alone. The gate refuses its own empty set
  // too, which is what covers the workflow steps and the npm hook that run it
  // bare; this is the other side of the same contract, and it is what notices a
  // gate that stopped publishing rather than one that published a zero.
  _runCountedGate("scripts/consolidate-release-notes.js", { args: ["--check"], verb: "verified" });
  // The CHANGELOG round-trip publishes too, in both of its units, and its count
  // was being discarded here. A gate that says what it looked at and a caller
  // that throws the number away is the same hole as a gate that says nothing.
  _runCountedGate("scripts/generate-changelog-entry.js", { args: ["--check"], verb: "rendered" });
  _ok("eslint + the declared gate chain (" + declared.length + " gate(s)) + release notes + " +
      "CHANGELOG round-trip clean");
}

function cmdPrepare(opts) {
  _section("prepare");
  if (!_gitOnMain()) {
    throw new Error("release: prepare must run on main (currently on " + _gitBranch() + ")");
  }
  if (!_gitClean()) {
    throw new Error("release: prepare requires a clean working tree");
  }

  var current = _readPackageVersion();
  var next = opts.minor ? _bumpMinor(current) : _bumpPatch(current);
  console.log("current version: " + current);
  console.log("next version:    " + next + " (" + (opts.minor ? "minor" : "patch") + ")");

  _ensureReleaseNotes(next);

  _writePackageVersion(next);
  _ok("bumped package.json -> " + next);

  _section("regen artifacts");
  _regenArtifacts();

  _staticGates();

  _section("supply-chain currency");
  // A stale vendored bundle becomes a release blocker HERE instead of an
  // after-the-fact advisory. The currency check treats only an actually-
  // newer upstream version as a failure; transient registry errors stay
  // advisory so a flaky network response doesn't block the cut.
  _runCountedGate("scripts/check-vendor-currency.js");
  _ok("vendored bundles current");

  console.log("\nnext: node scripts/release.js smoke");
}

function cmdRegen() {
  _section("regen");
  // Operators edit release-notes/v<next>.json mid-flow (e.g. addressing a
  // review-bot finding that belongs in the operator-facing notes). This
  // subcommand re-runs the artifact pipeline without re-bumping the
  // version. Safe to run from any branch.
  var next = _readPackageVersion();
  _ensureReleaseNotes(next);
  _regenArtifacts();
  console.log("\nnext: re-run the phase you were on (commit / push / watch / ...)");
}

function cmdSmoke() {
  _section("smoke");
  // A release ships the container image, and the files that drive it are
  // the only ones a machine with no container engine cannot run. On a
  // cut, an engine that is not there has to refuse rather than have
  // those files reported as skipped: a release whose image checks did
  // not run must not read as the same green as one whose did. Start the
  // engine, or run `node test/smoke.js` directly, which reports them by
  // name instead.
  _run("node", ["test/smoke.js"], {
    env: { SMOKE_PARALLEL: "64", SMOKE_REQUIRE_CONTAINER: "1" },
  });
  _ok("smoke clean");

  // Interop runs alongside smoke so a cut catches a wire regression before
  // the branch is even pushed.
  cmdInterop({});

  console.log("\nnext: node scripts/release.js commit");
}

function cmdCommit() {
  _section("commit");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var current = _gitBranch();

  // Resumable: if a previous `commit` failed AFTER the `git checkout -b`
  // (signature verification, hook failure), the branch already exists.
  // Switch to it instead of refusing; the remaining steps are idempotent.
  if (current === branch) {
    _ok("already on " + branch + " (resume mode)");
  } else if (current === "main") {
    var branchExists = _capture("git", ["rev-parse", "--verify", "--quiet", branch]).status === 0;
    if (branchExists) {
      _run("git", ["checkout", branch]);
      _ok("checked out existing " + branch + " (resume mode)");
    } else {
      _run("git", ["checkout", "-b", branch]);
      _ok("created " + branch);
    }
  } else {
    throw new Error("release: commit must run on main or " + branch +
                    " (currently on " + current + ")");
  }

  // AFTER the branch is selected, never before: every gate reads the working
  // tree, and the checkout above can replace it. Running from `main` with the
  // release branch already present would otherwise validate main's bytes and
  // then commit the branch's, which is the same "answered for a tree the commit
  // does not contain" fault the battery exists to close. A failing gate here leaves
  // the branch checked out, which is idempotent and costs nothing; committing
  // ungated bytes is not.
  _staticGates();

  // If HEAD already carries a commit for this release, skip the second
  // commit and verify the existing signature instead.
  var headSubject = _capture("git", ["log", "-1", "--pretty=%s"]).stdout;
  if (headSubject.indexOf(next + " — ") === 0) {
    _ok("HEAD already carries a " + next + " release commit (resume mode)");
    _verifyCommitSignature("existing");
    console.log("\nnext: node scripts/release.js push");
    return;
  }

  // Compose the commit body from the release-notes JSON. Operators can
  // amend post-commit; the auto-generated body mirrors the CHANGELOG shape.
  var rn = _loadReleaseNotes(next);
  if (rn === null) throw new Error("release: no notes for v" + next + " to compose a commit body from");
  var lines = [next + " — " + rn.headline, "", rn.summary];
  _sectionsList(rn.sections).forEach(function (s) {
    lines.push("", s.heading + ":");
    s.items.forEach(function (it) { lines.push("  - " + it); });
  });
  var msgPath = path.join(ROOT, ".scratch", "release-commit-msg.txt");
  try { fs.mkdirSync(path.dirname(msgPath), { recursive: true }); } catch (_e) { /* ignore */ }
  fs.writeFileSync(msgPath, lines.join("\n") + "\n");

  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-s", "-F", msgPath]);   // -s: DCO Signed-off-by
  _ok("signed commit");

  _verifyCommitSignature("new");

  console.log("\nnext: node scripts/release.js push");
}

function cmdPush(opts) {
  opts = opts || {};
  _section("push");
  if (!_gitOnRelease()) {
    throw new Error("release: push must run on a release/vX.Y.Z branch");
  }
  var next = _readPackageVersion();

  // Interop runs BEFORE gitleaks + the PR opens. A change that only passed
  // the in-process smoke must prove itself against real-world encodings
  // here; a failure is a hard stop that refuses the push. Non-skippable
  // except via an explicit, audited override (see cmdInterop).
  var interop = cmdInterop({ skip: opts.skipInterop, skipReason: opts.interopSkipReason });

  _gitleaks();

  // Cheap static gate re-run so the PR body claims only what this command
  // verified against the exact tree being pushed. Counted, for the reason
  // every gate in the battery is: this is the last reading before the branch
  // leaves the machine, so a clean verdict over an empty set here is the one
  // that reaches the pull request wearing a pass.
  _section("api-snapshot");
  _runCountedGate("scripts/check-api-snapshot.js");
  _ok("api surface tracked");

  _section("push branch");
  _run("git", ["push", "-u", "origin", _releaseBranchFor(next)]);
  _ok("pushed " + _releaseBranchFor(next));

  _section("open PR");
  var rn = _loadReleaseNotes(next);
  if (rn === null) throw new Error("release: no notes for v" + next + " to compose a PR body from");
  var title = next + " — " + rn.headline;
  // Each checkbox states what THIS command verified: interop / api-snapshot /
  // gitleaks ran above; smoke runs in its own phase and CI re-verifies, so
  // its box (and CI's) stay open for the reviewer. An interop gate that did
  // not run is published with the reason it did not, never as a pass.
  var summaryLines = ["## Summary", "", rn.summary, "", "## Verification", ""];
  summaryLines.push("- [ ] `node test/smoke.js`: runs in the smoke phase; CI re-verifies");
  if (interop.ran) {
    summaryLines.push("- [x] `node scripts/test-integration.js`: interop clean");
  } else {
    summaryLines.push("- [ ] `node scripts/test-integration.js` " + interop.reason);
  }
  summaryLines.push("- [x] `node scripts/check-api-snapshot.js`: surface tracked");
  summaryLines.push("- [x] `gitleaks`: no leaks");
  summaryLines.push("- [ ] `gh pr checks`: required checks read in the watch phase");
  _run("gh", ["pr", "create",
              "--base", "main",
              "--head", _releaseBranchFor(next),
              "--title", title,
              "--body",  summaryLines.join("\n")]);
  _ok("PR opened");

  console.log("\nnext: node scripts/release.js watch");
}

// Land a review/CI fix on the ALREADY-OPEN release PR. Encapsulates the
// multi-step flow that a Codex/Codex-P1/CI finding otherwise makes by hand:
// gitleaks -> a NEW signed commit -> push -> re-request a Codex review.
//
// Two non-obvious invariants it enforces:
//   - The fix is a NEW commit, never `--amend`. The pushed head must MOVE so
//     the review-thread + Codex gates re-check the new revision
//     (feedback_fix_codex_flags: fix in a new commit, never dismiss).
//   - Codex reviews a PR ONCE on open and does NOT auto-review a pushed fix,
//     so `watch`/`merge` would wait out their 10m budget on a review that
//     never comes. A `@codex review` comment re-triggers it on the current
//     head; the verdict (clean issue comment / finding thread) lands ~5-6m
//     later and the gate then sees it. This is NOT RELEASE_SKIP_CODEX_WAIT.
//     The gate still runs, we just make Codex actually review.
function cmdPushFix(opts) {
  opts = opts || {};
  _section("push-fix");
  if (!_gitOnRelease()) {
    throw new Error("release: push-fix must run on a release/vX.Y.Z branch (it lands a fix on the open PR)");
  }
  if (!opts.message) {
    throw new Error("release: push-fix needs a commit message. " +
      "node scripts/release.js push-fix -m \"<what the fix changes>\"");
  }
  if (_gitClean()) {
    throw new Error("release: nothing to commit. Stage the fix first " +
      "(push-fix captures the whole working tree with git add -A)");
  }
  var branch = _releaseBranchFor(_readPackageVersion());

  // Resolve the open PR FIRST and fail closed if there is none. push-fix is only
  // valid for an already-open release PR, so this must precede any commit/push.
  // Otherwise a stale branch whose PR already merged/closed would get a new
  // commit and a recreated remote branch before the lookup failed.
  var prNum = _openPrNumber(branch);

  // A fix commit reaches the same CI as the release commit, so it answers to the
  // same battery. Running it after the PR lookup and before the commit keeps a
  // failing gate from creating a commit that has to be rolled back.
  _staticGates();

  _section("commit");
  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-s", "-m", opts.message]);   // -s DCO; NOT --amend (head must move)
  _ok("signed fix commit");

  // Every post-commit / pre-push gate rolls the fix commit back on failure, so a
  // failed gate never dead-ends at the clean-tree guard. The operator fixes the
  // cause (a leaked secret, a broken SSH-signing setup) and re-runs push-fix
  // cleanly. gitleaks runs here, AFTER the commit, so the fix itself is scanned
  // (scanning before would miss a secret in it); the signature verify catches an
  // unsigned/badly-signed commit before it reaches the remote. On either failure
  // a soft reset keeps the fix staged, and nothing reached the remote (the push
  // is still ahead).
  try {
    _gitleaks();
    _verifyCommitSignature("new");
  } catch (gate) {
    _run("git", ["reset", "--soft", "HEAD~1"]);
    throw new Error("release: a pre-push gate failed. The fix commit was rolled back " +
      "(your changes are kept staged). Fix the cause, then re-run push-fix.\n" + (gate.message || String(gate)));
  }

  _section("push");
  _run("git", ["push"]);   // branch already tracks origin from the initial push
  _ok("pushed fix to " + branch);

  // The push is the critical, already-completed work; re-requesting the review is
  // a best-effort follow-up. If the comment fails (transient API / rate-limit),
  // do NOT throw. Throwing would leave the fix pushed but the review un-requested,
  // and a rerun would stop at the clean-tree guard. Print the exact manual
  // re-trigger instead so the operator can post it without another commit.
  _section("re-request Codex review");
  var commentRv = _run("gh", ["pr", "comment", prNum, "--body", "@codex review"], { allowFail: true });
  if (commentRv.status === 0) {
    _ok("posted @codex review on PR #" + prNum + ", Codex will review the new head (~5-6m)");
  } else {
    console.log("\nwarn: the fix IS pushed, but posting `@codex review` failed (transient?).");
    console.log("      Re-trigger it manually (push-fix would refuse to rerun now that the tree is clean):");
    console.log("        gh pr comment " + prNum + " --body \"@codex review\"");
  }

  console.log("\nNext:");
  console.log("  - Resolve any Codex thread THIS fix addresses (fix it, never dismiss):");
  console.log("      gh api graphql -f query='mutation { resolveReviewThread(" +
              "input:{threadId:\"<PRRT_...>\"}){ thread { isResolved } } }'");
  console.log("  - Then: node scripts/release.js watch   (awaits the re-review + flags remaining threads)");
}

// Fetch every UNRESOLVED review thread on the PR with enough context to act
// on it: the file:line, the reviewer, the first line of the finding, the
// thread id, and the resolve mutation. Bot reviews post ASYNCHRONOUSLY, often
// a minute or two AFTER the status checks finish, so this is the
// authoritative check at merge time, not just at watch.
// The async-review race: Codex (chatgpt-codex-connector) reviews a PR a
// minute or two AFTER the status checks go green. required_review_thread_
// resolution can only block threads that EXIST at merge time, so a merge
// fired the instant CI is green outruns Codex and ships its findings.
// Closing it: before the thread gate runs, WAIT until Codex has actually
// reviewed the CURRENT head, so that the thread-resolution gate sees its
// findings.
var CODEX_LOGIN = "chatgpt-codex-connector";

// GitHub renders a GitHub App / bot author's login as the bare handle in
// GraphQL but suffixed with "[bot]" in some REST surfaces. Tolerate both so
// the gate recognizes Codex regardless of which shape the login arrives in.
function _isCodexLogin(login) {
  return String(login || "").replace(/\[bot\]$/, "") === CODEX_LOGIN;
}

// Synchronous sleep with no busy-spin (release.js is a synchronous CLI).
function _sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Parse a captured gh JSON payload, failing closed: a non-zero exit or an
// unparseable payload throws instead of degrading to the gate-passing empty
// value. An unreadable review/thread state is not an empty one (a transient
// gh failure must never merge past a live finding).
function _ghJson(rv, what) {
  if (rv.status !== 0) {
    throw new Error("release: " + what + " lookup failed (gh exit " + rv.status + "). " +
                    "An unreadable result is not an empty one.\n" +
                    (rv.stderr || rv.stdout || "(no output)"));
  }
  try {
    return JSON.parse(rv.stdout || "");
  } catch (e) {
    throw new Error("release: " + what + " payload did not parse (" + ((e && e.message) || e) +
                    "). An unreadable result is not an empty one.");
  }
}

// True once Codex has reviewed the PR's current head, meaning it reviewed THIS
// revision (a push after the review moves the head and this goes false until
// Codex re-reviews the new head). Codex signals a review in TWO forms and both
// must count, or the gate times out on the common case:
//   (1) when it HAS findings, a formal review node whose commit is the head;
//   (2) when it is CLEAN, an issue comment that cites "Reviewed commit:
//       `<sha>`" and reports no major issues, with NO formal review node and
//       NO commit.oid.
// Recognizing only (1) means every clean review times out. The gate would
// only ever pass when Codex complains, which is backwards.
function _codexReviewedHead(prNum) {
  var slug = _repoSlug();
  var head = (_capture("gh", ["pr", "view", prNum, "--json", "headRefOid",
                              "--jq", ".headRefOid"]).stdout || "").trim();
  if (!head) return false;

  // (1) Formal review node whose commit is the current head.
  var rv = _capture("gh", ["api", "graphql",
    "-f", "query=query { repository(owner:\"" + slug.owner + "\",name:\"" + slug.name +
      "\") { pullRequest(number:" + prNum +
      ") { reviews(last:100) { nodes { author{login} commit{oid} } } } } }",
    "--jq", ".data.repository.pullRequest.reviews.nodes"]);
  var nodes = _ghJson(rv, "PR #" + prNum + " review list");
  if ((nodes || []).some(function (r) {
    return r && r.author && _isCodexLogin(r.author.login) &&
           r.commit && r.commit.oid === head;
  })) return true;

  // (2) Clean-verdict issue comment citing the current head's commit sha.
  var cv = _capture("gh", ["pr", "view", prNum, "--json", "comments", "--jq", ".comments"]);
  var comments = _ghJson(cv, "PR #" + prNum + " comment list");
  var headPrefix = head.slice(0, 10);
  return (comments || []).some(function (c) {
    return c && c.author && _isCodexLogin(c.author.login) &&
           typeof c.body === "string" && c.body.indexOf(headPrefix) !== -1;
  });
}

// Block until Codex has reviewed the current head (fail-closed on timeout).
// RELEASE_SKIP_CODEX_WAIT=1 is the documented escape hatch for a confirmed
// Codex outage/disablement only, not a routine bypass.
function _waitForCodexReview(prNum) {
  if (process.env.RELEASE_SKIP_CODEX_WAIT === "1") {
    _ok("Codex-review wait skipped (RELEASE_SKIP_CODEX_WAIT=1)");
    return;
  }
  var stepMs = 20 * 1000, budgetMs = 10 * 60 * 1000, waitedMs = 0;
  console.log("waiting for Codex (" + CODEX_LOGIN + ") to review PR #" + prNum +
              " head before the thread gate (up to 10m; it reviews a bit after CI)...");
  while (waitedMs <= budgetMs) {
    if (_codexReviewedHead(prNum)) {
      _ok("Codex has reviewed the current PR head, thread gate now sees its findings");
      return;
    }
    _sleepSync(stepMs);
    waitedMs += stepMs;
  }
  throw new Error("release: Codex has not reviewed PR #" + prNum + " head after 10m. " +
    "It reviews asynchronously; a late finding must not be outrun by the merge. Re-run " +
    "`node scripts/release.js merge` once it posts, or set RELEASE_SKIP_CODEX_WAIT=1 " +
    "ONLY if Codex is confirmed disabled/down.");
}

function _unresolvedThreads(prNum) {
  var slug = _repoSlug();
  // PAGINATE every review thread. GitHub caps a GraphQL connection's `first` at 100,
  // so a single first:100 page silently drops thread 101+, and a long-lived release
  // PR accrues far more than 100 threads over a deep review loop, so the gate reported
  // "no unresolved threads" while later-page findings still blocked the merge. Walk the
  // cursor to completion; a bounded page cap backstops a runaway rather than truncating
  // real work (the loop stops at hasNextPage=false well before it).
  var nodes = [];
  var after = null;
  for (var page = 0; page < 100; page += 1) {
    var afterClause = after ? (", after: \"" + after + "\"") : "";
    var rv = _capture("gh", ["api", "graphql",
      "-f", "query=query { repository(owner:\"" + slug.owner + "\",name:\"" + slug.name +
        "\") { pullRequest(number:" + prNum +
        ") { reviewThreads(first:100" + afterClause + ") { pageInfo { hasNextPage endCursor } nodes { " +
        "id isResolved path line comments(first:1) { nodes { author{login} body } } } } } } }"]);
    // Fail closed: [] is this gate's PASS value, so a failed lookup must throw rather
    // than report the thread list as empty (an unreadable state is not an empty one,
    // because a transient gh failure must never merge past a live finding).
    var data = _ghJson(rv, "PR #" + prNum + " review-thread page " + page);
    var conn = data && data.data && data.data.repository && data.data.repository.pullRequest &&
               data.data.repository.pullRequest.reviewThreads;
    if (!conn || !conn.pageInfo) {
      throw new Error("release: PR #" + prNum + " review-thread page " + page +
                      " had no reviewThreads connection. An unreadable result is not an empty one.");
    }
    nodes = nodes.concat(conn.nodes || []);
    if (!conn.pageInfo.hasNextPage) { after = null; break; }
    after = conn.pageInfo.endCursor;
  }
  // Fail closed: if the page cap was hit while more pages remained (hasNextPage still true, so `after` is still set),
  // the thread list is TRUNCATED. Returning it would let the gate see [] / a partial set and merge past unresolved
  // findings on later pages. A PR with 10,000+ threads is a runaway, not a mergeable state, so throw and never truncate.
  if (after !== null) {
    throw new Error("release: PR #" + prNum + " has more review threads than the " +
      "pagination cap can read. Refusing to treat a truncated thread list as authoritative (resolve threads or split the PR).");
  }
  return nodes.filter(function (t) { return t && t.isResolved === false; })
    .map(function (t) {
      var c = t.comments && t.comments.nodes && t.comments.nodes[0];
      return {
        id:     t.id,
        path:   t.path || "(pr-level)",
        line:   t.line,
        author: (c && c.author && c.author.login) || "(unknown)",
        body:   (c && c.body) || "",
      };
    });
}

// Surface each unresolved thread with the exact finding it raises + how to
// clear it, so a BLOCKED merge names its cause instead of "state=BLOCKED".
function _printUnresolvedThreads(unresolved) {
  console.log("\n" + unresolved.length + " unresolved review thread(s) block the merge " +
              "(main-protection requires every thread resolved):\n");
  unresolved.forEach(function (t, i) {
    var lines = (t.body || "").split("\n");
    var firstLine = "(no text)";
    for (var li = 0; li < lines.length; li++) {
      if (lines[li].trim().length > 0) { firstLine = lines[li]; break; }
    }
    firstLine = firstLine.replace(/!\[[^\]]*\]\([^)]*\)/g, "").replace(/[*_`#>]/g, "").trim();
    console.log("  " + (i + 1) + ". [" + t.author + "] " + t.path +
                (t.line != null ? ":" + t.line : ""));
    console.log("     " + firstLine.slice(0, 160));
    console.log("     resolve: gh api graphql -f query='mutation { resolveReviewThread(" +
                "input:{threadId:\"" + t.id + "\"}){ thread { isResolved } } }'");
  });
  console.log("\nFix each finding in a NEW commit on the branch (never dismiss), then run the");
  console.log("resolve command above for its thread. Re-run: node scripts/release.js merge");
}

// What `watch` reports when it refuses to advance. Three states rather than
// one, because the operator's next move differs for each: re-run a build that
// failed on its own, go write a fix for a finding, or do both before either
// is worth re-running. A single non-zero code makes a caller guess, and the
// guess is wrong half the time.
//
// A bitmask would read better and is not available. 3 is the code this
// command has always exited with for unresolved threads, so a `checks |
// threads` composition would have to land on 3 as well and would silently
// retype an answer callers already key on. The published code therefore stays
// where it is, and the two new states take the next numbers this file has not
// already spoken for: 4 is INTEROP_EMPTY_EXIT.
var WATCH_EXIT_THREADS = 3;
var WATCH_EXIT_CHECKS  = 5;
var WATCH_EXIT_BOTH    = 6;

function cmdWatch() {
  _section("watch");
  var prNum = _openPrNumber(_releaseBranchFor(_readPackageVersion()));
  console.log("PR #" + prNum);

  // The watch is allowed to fail and the run is allowed to continue past it,
  // so ONE pass reports the failing build together with the findings that
  // landed beside it rather than stopping at whichever arrived first. What is
  // not allowed is forgetting: the status is bound here and decides the exit
  // code at the bottom. A command that watches a red build and then hands the
  // operator on to `merge` is worse than one that never watched, because it
  // reports having checked.
  var checks = _run("gh", ["pr", "checks", prNum, "--watch"], { allowFail: true });
  var checksFailed = checks.status !== 0;
  if (checksFailed) {
    // Said here as well as at the bottom. The Codex wait below fails closed
    // on a timeout, and a run that ends there still has to carry the verdict
    // it already holds.
    console.log("checks: FAILED (gh pr checks exited " + checks.status + ")");
  } else {
    _ok("required checks passed");
  }

  // Wait for Codex to review THIS head before reading threads, so a late
  // finding is caught here instead of being outrun by the merge.
  _waitForCodexReview(prNum);

  var unresolved = _unresolvedThreads(prNum);
  if (unresolved.length > 0) {
    _printUnresolvedThreads(unresolved);
  } else {
    _ok("Codex has reviewed the head and zero unresolved threads remain (merge re-checks)");
  }

  if (checksFailed || unresolved.length > 0) {
    console.log("\nwatch: refusing to advance.");
    if (checksFailed) {
      console.log("  checks: FAILED for PR #" + prNum +
                  ". Read them with: gh pr checks " + prNum);
    }
    if (unresolved.length > 0) {
      console.log("  threads: " + unresolved.length + " unresolved, listed above.");
    }
    console.log("Fix the cause, land it with `node scripts/release.js push-fix`, " +
                "then re-run watch.");
    process.exit(checksFailed
      ? (unresolved.length > 0 ? WATCH_EXIT_BOTH : WATCH_EXIT_CHECKS)
      : WATCH_EXIT_THREADS);
  }

  console.log("\nnext: node scripts/release.js merge");
}

function cmdMerge() {
  _section("merge");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var prNum = _openPrNumber(branch);
  // Authoritative gate: do not read merge state / threads until Codex has
  // reviewed the current head, so its asynchronously-posted findings are in
  // the thread set the checks below enforce.
  _waitForCodexReview(prNum);
  var state = JSON.parse(_capture("gh", ["pr", "view", prNum,
    "--json", "mergeStateStatus,mergeable"]).stdout || "{}");
  // Pull unresolved review threads FIRST. A BLOCKED state is most often
  // unresolved threads. The bot reviews post asynchronously, AFTER the
  // status checks finish, so `watch` can have seen zero while they were
  // still landing. Surface exactly which findings block the merge.
  var unresolved = _unresolvedThreads(prNum);
  if (state.mergeStateStatus !== "CLEAN" || state.mergeable !== "MERGEABLE") {
    if (unresolved.length > 0) _printUnresolvedThreads(unresolved);
    throw new Error("release: PR #" + prNum + " not mergeable (state=" +
                    state.mergeStateStatus + " mergeable=" + state.mergeable + ")" +
                    (unresolved.length > 0
                      ? ": " + unresolved.length + " unresolved review thread(s); see above"
                      : ": no unresolved threads; check required status checks / signatures"));
  }
  // Belt-and-suspenders: even if the API reports CLEAN, refuse on any open
  // thread (a thread can open in the window between the state read and merge).
  if (unresolved.length > 0) {
    _printUnresolvedThreads(unresolved);
    throw new Error("release: refusing to merge PR #" + prNum + " with " +
                    unresolved.length + " unresolved review thread(s)");
  }
  _run("gh", ["pr", "merge", prNum, "--squash", "--delete-branch"]);
  _ok("PR #" + prNum + " squash-merged");

  _run("git", ["checkout", "main"]);
  _run("git", ["pull", "origin", "main"]);

  console.log("\nnext: node scripts/release.js tag");
}

function cmdTag() {
  _section("tag");
  if (!_gitOnMain()) {
    throw new Error("release: tag must run on main (post-merge)");
  }
  var next = _readPackageVersion();
  var tag = "v" + next;

  // Refuse if the tag already exists. The release-tags ruleset refuses tag
  // overwrites server-side; a clearer client-side error is friendlier.
  var existing = _capture("git", ["tag", "-l", tag]).stdout;
  if (existing === tag) {
    throw new Error("release: tag " + tag + " already exists locally");
  }
  _run("git", ["tag", "-s", tag, "-m", tag]);

  // Verify the signature BEFORE the tag leaves the machine: the npm-publish
  // workflow triggers on the tag push, so a bad signature must stop the flow
  // while the tag is still local. Like _verifyCommitSignature, this throws and
  // never warns-and-continues; the just-created tag is deleted so a re-run
  // after fixing the signing setup starts clean.
  var verify = _capture("git", ["tag", "-v", tag]);
  if (verify.stderr.indexOf("Good") === -1 && verify.stdout.indexOf("Good") === -1) {
    // The cleanup is allowed to fail; its status is still part of what the
    // refusal says. An operator told the tag was removed, who then hits
    // "already exists locally" on the re-run, has been sent looking for a
    // fault that is not there.
    var removal = _run("git", ["tag", "-d", tag], { allowFail: true });
    var removalNote = removal.status === 0
      ? "The local tag was removed; fix the setup and re-run tag."
      : "The local tag could NOT be removed (git tag -d exited " + removal.status +
        "); delete it by hand before re-running tag.";
    throw new Error("release: `git tag -v " + tag + "` did not report a Good signature. " +
      "Check SSH signing setup (tag.gpgsign=true + gpg.format=ssh + " +
      "~/.ssh/allowed_signers populated). " + removalNote + "\n" +
      (verify.stderr || verify.stdout));
  }
  _ok("tag signature: Good");

  _run("git", ["push", "origin", tag]);
  _ok("tagged + pushed " + tag);

  console.log("\nnext: node scripts/release.js publish");
}

function cmdPublish() {
  _section("publish");
  var next = _readPackageVersion();
  var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

  _section("npm-publish workflow");
  var npmRunId = _capture("gh", ["run", "list",
                                  "--workflow=npm-publish.yml",
                                  "--limit", "1",
                                  "--json", "databaseId",
                                  "--jq",   ".[0].databaseId"]).stdout;
  if (npmRunId) {
    // The watch's exit status IS the publish verdict. A failed npm-publish
    // run means nothing reached the registry, and `all` must not exit 0 on
    // an unpublished release.
    var npmWatch = _run("gh", ["run", "watch", npmRunId, "--exit-status"], { allowFail: true });
    if (npmWatch.status !== 0) {
      throw new Error("release: the npm-publish workflow run concluded FAILED. " +
        "Nothing was published. Inspect it (gh run view " + npmRunId + "), fix the " +
        "cause, and re-run the workflow or re-push the tag.");
    }
  } else {
    console.log("no npm-publish run found (workflow may not be configured)");
  }

  _section("release-container workflow");
  var containerRunId = _capture("gh", ["run", "list",
                                  "--workflow=release-container.yml",
                                  "--limit", "1",
                                  "--json", "databaseId",
                                  "--jq",   ".[0].databaseId"]).stdout;
  if (containerRunId) {
    var containerWatch = _run("gh", ["run", "watch", containerRunId, "--exit-status"], { allowFail: true });
    if (containerWatch.status !== 0) {
      throw new Error("release: the release-container workflow run concluded FAILED. " +
        "ghcr.io/blamejs/blamepost did not publish for this tag, so operators who pull the " +
        "image get the previous release while npm reports the new one. Inspect it " +
        "(gh run view " + containerRunId + ").");
    }
  } else {
    console.log("no release-container run found; the registry check below is what " +
                "answers for the image");
  }

  // Verify path: the exit code is the verdict. A registry answer that
  // mismatches, or no answer at all, is a failed verification, never a
  // warning that exits 0 (publish is the last step of `all`, so its exit
  // code is the whole flow's verdict).
  //
  // Both artifacts are read back from the registry that serves them, and
  // neither reading is conditional on having found a workflow run. An empty
  // `gh run list` is what a renamed workflow, a token without the scope to
  // list runs and an API timeout all produce, so treating it as evidence
  // about the artifact answers a question nobody asked. The watch above says
  // a workflow concluded; only the registry says the bytes are there.
  //
  // Both are read before either refusal, so one pass says what is wrong with
  // the release rather than two rounds.
  _section("verify");
  var failures = [];

  var npmVersion = _capture("npm", ["view", pkg.name, "version"]).stdout;
  console.log("npm " + pkg.name + ": " + (npmVersion || "(unable to query)") +
              "  (expected: " + next + ")");
  if (npmVersion !== next) {
    failures.push("npm reports " + (npmVersion || "(unable to query)") +
      " but this release expected " + next + ". The registry may still be " +
      "propagating; re-run `node scripts/release.js publish` to re-verify.");
  } else {
    _ok("npm matches " + next);
  }

  var imageRef = _containerImageRef(next);
  var inspected = _capture("docker", ["buildx", "imagetools", "inspect", imageRef,
                                      "--format", "{{.Manifest.Digest}}"]);
  var imageDigest = _lastLine(inspected.stdout);
  console.log("ghcr " + imageRef + ": " + (imageDigest || "(unable to query)"));
  if (!/^sha256:[0-9a-f]{64}$/.test(imageDigest)) {
    failures.push(imageRef + " did not answer with an image digest. " +
      "`docker buildx imagetools inspect` exited " + inspected.status + " and gave " +
      JSON.stringify(imageDigest || inspected.stderr.split("\n").pop() || "") + ". " +
      "Operators who pull the image get the previous release while npm reports this one. " +
      "A container engine is required here: this reading is the only thing that says the " +
      "image is served, so it cannot be skipped on a machine that has none.");
  } else {
    _ok("container image published at " + imageRef + " (" + imageDigest + ")");
  }

  if (failures.length > 0) {
    throw new Error("release: " + failures.join("\n\nrelease: "));
  }
}

function cmdAll(opts) {
  cmdPrepare(opts);
  cmdSmoke();
  cmdCommit();
  cmdPush(opts);
  cmdWatch();
  cmdMerge();
  cmdTag();
  cmdPublish();
}

function cmdStatus() {
  _section("status");
  console.log("branch:           " + _gitBranch());
  console.log("clean:            " + _gitClean());
  console.log("package version:  " + _readPackageVersion());
  var statusVersion = _readPackageVersion();
  console.log("release-notes:    " +
    (fs.existsSync(_releaseNotesPath(statusVersion))
      ? "hand-written, not yet folded"
      : (_loadReleaseNotes(statusVersion) !== null
        ? "folded into " + path.basename(_seriesNotesPath(statusVersion))
        : "missing")));
  var prNum = _capture("gh", ["pr", "list",
                              "--author", "@me",
                              "--head",   _releaseBranchFor(_readPackageVersion()),
                              "--state",  "open",
                              "--json",   "number,mergeStateStatus,mergeable",
                              "--jq",     ".[0]"]).stdout;
  console.log("open PR:          " + (prNum || "(none)"));
}

function cmdHelp() {
  console.log("release.js orchestrates the release flow");
  console.log("");
  console.log("Usage:");
  console.log("  node scripts/release.js prepare [--minor]   # bump + regen + static gates");
  console.log("  node scripts/release.js regen               # re-regen artifacts after release-notes edits");
  console.log("  node scripts/release.js smoke               # smoke + interop");
  console.log("  node scripts/release.js commit              # release branch + signed commit");
  console.log("  node scripts/release.js interop             # live-listener integration tests");
  console.log("  node scripts/release.js push                # interop + gitleaks + push + open PR");
  console.log("  node scripts/release.js push-fix -m \"...\"    # land a review/CI fix on the open PR:");
  console.log("                                              #   gitleaks + signed commit + push + re-request Codex");
  console.log("  node scripts/release.js watch               # CI watch + flag review threads");
  console.log("                                              #   exits " + WATCH_EXIT_CHECKS +
              " on failing checks, " + WATCH_EXIT_THREADS + " on open threads, " +
              WATCH_EXIT_BOTH + " on both");
  console.log("  node scripts/release.js merge               # squash-merge if CLEAN");
  console.log("  node scripts/release.js tag                 # signed tag + push tag");
  console.log("  node scripts/release.js publish             # watch both publish workflows, then");
  console.log("                                              #   read the npm version and the");
  console.log("                                              #   image digest back off the registries");
  console.log("  node scripts/release.js all [--minor]       # prepare -> ... -> publish");
  console.log("  node scripts/release.js status              # current branch + version state");
  console.log("  node scripts/release.js help                # this banner");
  console.log("");
  console.log("Interop gate (runs inside push and smoke):");
  console.log("  Runs scripts/test-integration.js, which drives a running server from");
  console.log("  the outside with clients that are not this codebase. A failing interop");
  console.log("  run is a HARD STOP. An EMPTY suite proceeds and is published on the PR");
  console.log("  as a gate that did not run, never as a pass.");
  console.log("  To override a suite that does have files (audited, never silent):");
  console.log("  --skip-interop --interop-skip-reason=\"<why>\".");
}

// ---- Dispatch ------------------------------------------------------------

var sub = process.argv[2] || "help";
var args = process.argv.slice(3);

// Parse a `--flag=value` form into its value; returns undefined if absent
// or if the flag was passed bare (no `=value`).
function _flagValue(name) {
  var prefix = name + "=";
  for (var i = 0; i < args.length; i++) {
    if (args[i].indexOf(prefix) === 0) return args[i].slice(prefix.length);
  }
  return undefined;
}

// The push-fix commit message: `-F <path>` / `--message-file <path>` reads it from a file, or
// `-m "…"` / `--message "…"` / `--message="…"` gives it inline. Returns undefined if absent.
//
// Prefer the file form for anything with punctuation in it. An inline message is typed on a command
// line, where the shell expands a backtick or a `$` before the argument ever reaches this script,
// and the damage is silent: the commit lands with a mangled body that reads as a successful commit.
// A file is read here, after the shell is out of the way.
function _messageValue() {
  var fileAttached = _flagValue("--message-file");
  var filePath = fileAttached;
  if (filePath === undefined) {
    for (var f = 0; f < args.length; f++) {
      if (args[f] === "-F" || args[f] === "--message-file") { filePath = args[f + 1]; break; }
    }
  }
  if (filePath !== undefined) {
    if (!filePath) throw new Error("release: --message-file needs a path");
    return fs.readFileSync(filePath, "utf8").replace(/\s+$/, "");
  }
  var attached = _flagValue("--message");
  if (attached !== undefined) return attached;
  for (var i = 0; i < args.length; i++) {
    if (args[i] === "-m" || args[i] === "--message") return args[i + 1];
  }
  return undefined;
}

var opts = {
  minor: args.indexOf("--minor") !== -1,
  // The interop gate is on by default. `--skip-interop` opts out, but ONLY
  // together with `--interop-skip-reason="<why>"`; the reason is printed
  // loudly and recorded in the release-flow transcript.
  skipInterop:       args.indexOf("--skip-interop") !== -1,
  interopSkipReason: _flagValue("--interop-skip-reason"),
  message:           _messageValue(),
};

try {
  switch (sub) {
    case "prepare": cmdPrepare(opts); break;
    case "regen":   cmdRegen();       break;
    case "smoke":   cmdSmoke();       break;
    case "commit":  cmdCommit();      break;
    case "interop": cmdInterop({
                      skip:       opts.skipInterop,
                      skipReason: opts.interopSkipReason,
                    });            break;
    case "push":    cmdPush(opts);    break;
    case "push-fix": cmdPushFix(opts); break;
    case "watch":   cmdWatch();       break;
    case "merge":   cmdMerge();       break;
    case "tag":     cmdTag();         break;
    case "publish": cmdPublish();     break;
    case "all":     cmdAll(opts);     break;
    case "status":  cmdStatus();      break;
    case "help":
    case "--help":
    case "-h":      cmdHelp();        break;
    default:
      console.error("release: unknown subcommand '" + sub + "'");
      cmdHelp();
      process.exit(1);
  }
} catch (e) {
  console.error("\nrelease FAILED: " + (e.message || e));
  process.exit(1);
}
