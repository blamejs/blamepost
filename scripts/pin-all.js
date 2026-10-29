#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// pin-all.js aggregates every supply-chain PIN in one pass so a fix run
// keeps all segments in sync instead of hand-editing each. Segments:
//
//   1. Committed lockfiles, the manifests whose committed package-lock.json
//      lets CI's `npm ci` pin exact reviewed versions with integrity hashes.
//      OpenSSF Scorecard keys "pinned" on the `npm ci` verb, so the committed
//      lockfile IS the pin.
//   2. GitHub Action SHAs, delegated to check-actions-currency.js (its --fix
//      resolves each `uses:` tag to the upstream commit SHA and pins it,
//      honoring the .pinact.yaml exceptions).
//   3. Docker base-image digests, mirroring a Dependabot-tracked reference
//      Dockerfile's `@sha256:` digest into a sibling that Scorecard scans but
//      that the tracked pipeline never builds. The shipped Dockerfile is the
//      one Dependabot tracks and the one the release builds, so there is
//      nothing to mirror: the segment is empty and runs as a clean no-op.
//
//   --check (default): verify segments 1 + 3 are in sync (fast, no network)
//     and exit non-zero on drift. Segment 2 currency has its own CI gate;
//     --check does not re-run it to avoid duplicate rate-limited API calls.
//   --fix: regenerate all lockfiles, pin/bump the Action SHAs, and sync the
//     Docker digests. One command re-pins the repo.
//   --lockfiles: regenerate ONLY the committed lockfiles (no Action/digest
//     work, no token). release.js regen runs this after the version bump.
//
// Wire `--check` into CI + release.js so no pin can silently drift; run
// `--fix` (with GH_TOKEN for the Action step) whenever a pin needs refreshing.

var fs = require("node:fs");
var path = require("node:path");
var cp = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");
var FIX = process.argv.indexOf("--fix") !== -1;
var LOCKFILES_ONLY = process.argv.indexOf("--lockfiles") !== -1;

function readJson(p) { return JSON.parse(fs.readFileSync(p, "utf8")); }

// Every directory whose committed package-lock.json backs an `npm ci`.
//
// Read from the tree rather than listed. A listed set answers for the
// directories somebody remembered to add to it, and a workflow running
// `npm ci` in a directory absent from the list installs from a lockfile
// nothing compared against its package.json. The published count is the
// same shape of miss: over a list it reports the list's length, so it holds
// steady at the old number while a new manifest goes unread.
//
// The walk skips `node_modules` and the vendored tree. Neither holds a
// manifest this repository pins: the runtime declares no dependencies, and
// the vendored framework is extracted from an integrity-verified registry
// tarball rather than installed as a resolved dependency.
function _skipDir(rel) {
  var base = path.basename(rel);
  if (base === "node_modules" || base === ".git") return true;
  return rel.split(path.sep).join("/") === "lib/vendor";
}

function discoverLockfileDirs() {
  var found = [];

  function walk(relDir) {
    var abs = path.join(ROOT, relDir);
    if (fs.existsSync(path.join(abs, "package.json"))) {
      found.push(relDir === "" ? "." : relDir.split(path.sep).join("/"));
    }
    var entries;
    try { entries = fs.readdirSync(abs, { withFileTypes: true }); }
    catch (_e) { return; } // drop-silent by design: an unreadable directory holds no manifest to pin
    entries.forEach(function (ent) {
      if (!ent.isDirectory()) return;
      var rel = relDir === "" ? ent.name : path.join(relDir, ent.name);
      if (_skipDir(rel)) return;
      walk(rel);
    });
  }

  walk("");

  return found.sort().map(function (dir) {
    // `--fix` spawns npm with this path on the command line, so a directory
    // carrying a shell metacharacter is refused rather than run.
    if (!/^[A-Za-z0-9._/-]+$/.test(dir)) {
      throw new Error("pin-all: refusing manifest directory " + JSON.stringify(dir) +
        ": it must carry no shell metacharacter, because --fix passes it to npm.");
    }
    return {
      dir:   dir,
      args:  [],
      label: dir === "." ? "root dev-tools" : dir + " toolchain",
    };
  });
}

var LOCKFILE_DIRS = discoverLockfileDirs();

// Docker base images pinned by MIRRORING a Dependabot-maintained reference.
// Empty here, because the shipped Dockerfile is both the Dependabot-tracked file and
// the one the release builds, so no second copy can drift from it. The forEach
// over an empty list is a clean no-op.
var DIGEST_SYNCS = [];

var problems = [];
var fixed = [];

// WHAT THE RUN EXAMINED. `--check` is a gate in the declared chain, so it
// publishes what it looked at as the last lines of stdout:
//
//   EXAMINED <n> lockfile-manifests
//   EXAMINED <n> pinned-specs
//
// Both, because they fail independently and the second is the one a healthy
// first number hides. `lockfile-manifests` is how many directories the walk
// found a package.json in and measured, so a manifest added anywhere in the
// tree moves it. `pinned-specs` is how many top-level
// dependency specs were actually COMPARED against the committed lockfile,
// and it goes to zero on its own: `checkLockfile` returns early for a
// manifest with no declared dependencies, so a package.json whose
// devDependencies vanished takes every comparison with it while the
// directory still counts. "OK, in sync" over nothing compared is the same
// clean-verdict-over-an-empty-set this whole contract refuses.
//
// The Docker digest segment publishes no unit of its own: DIGEST_SYNCS is
// deliberately empty, because the shipped Dockerfile is both the tracked
// file and the built one, so there is no second copy that could drift. A
// unit that is legitimately zero would refuse every run, and a count that is
// always zero teaches a reader to ignore it.
var examined = { lockfileManifests: 0, pinnedSpecs: 0 };

function publishExamined() {
  console.log("EXAMINED " + examined.lockfileManifests + " lockfile-manifests");
  console.log("EXAMINED " + examined.pinnedSpecs + " pinned-specs");
}

// ---- Segment 1: lockfiles ----

function topSpecs(node) {
  var out = {};
  ["dependencies", "devDependencies", "optionalDependencies"].forEach(function (k) {
    var d = (node && node[k]) || {};
    Object.keys(d).forEach(function (n) { out[n] = d[n]; });
  });
  return out;
}

function checkLockfile(entry) {
  var dirAbs = path.join(ROOT, entry.dir);
  var pkgPath = path.join(dirAbs, "package.json");
  if (!fs.existsSync(pkgPath)) return; // nothing to lock
  examined.lockfileManifests += 1;
  // A package.json with zero deps needs no lockfile.
  var pkgForSpecs;
  try { pkgForSpecs = readJson(pkgPath); }
  catch (e) { problems.push(entry.dir + ": unreadable package.json: " + (e && e.message)); return; }
  if (Object.keys(topSpecs(pkgForSpecs)).length === 0) return;

  var lockPath = path.join(dirAbs, "package-lock.json");
  if (!fs.existsSync(lockPath)) {
    problems.push(entry.dir + "/package-lock.json is missing (" + entry.label + "). Run `node scripts/pin-all.js --fix`");
    return;
  }
  var pkg, lock;
  try { pkg = readJson(pkgPath); lock = readJson(lockPath); }
  catch (e) { problems.push(entry.dir + ": unreadable package.json/lockfile: " + (e && e.message)); return; }
  // The lockfile's root package node must carry the exact package.json specs;
  // `npm ci` refuses to run when they disagree, so drift here breaks CI.
  var want = topSpecs(pkg);
  var have = topSpecs((lock.packages && lock.packages[""]) || {});
  Object.keys(want).forEach(function (name) {
    examined.pinnedSpecs += 1;
    if (have[name] !== want[name]) {
      problems.push(entry.dir + "/package-lock.json spec for " + name + " is " +
        (have[name] === undefined ? "<absent>" : have[name]) + " but package.json wants " + want[name] +
        ". Regenerate with `node scripts/pin-all.js --fix`");
    }
  });

  // Version drift: a version-only release bumps package.json but a spec-only
  // comparison still passes, leaving the lockfile's own recorded version
  // pointing at the prior release. npm ci tolerates it until something
  // linked breaks, so catch the drift here.
  var pkgs = lock.packages || {};
  var selfVer = pkgs[""] && pkgs[""].version;
  if (entry.dir === "." && selfVer !== undefined && selfVer !== pkg.version) {
    problems.push(entry.dir + "/package-lock.json records root version " + selfVer +
      " but package.json is " + pkg.version + ". Regenerate with `node scripts/pin-all.js --lockfiles`");
  }
}

function fixLockfile(entry) {
  var dirAbs = path.join(ROOT, entry.dir);
  var pkgPath = path.join(dirAbs, "package.json");
  if (!fs.existsSync(pkgPath)) return;
  // Skip a zero-dependency manifest, which needs no lockfile.
  try { if (Object.keys(topSpecs(readJson(pkgPath))).length === 0) return; }
  catch (e) { problems.push(entry.dir + ": unreadable package.json: " + (e && e.message)); return; }
  // One command STRING rather than an args array plus shell, because Windows needs a shell
  // for the npm .cmd shim, and a shell concatenates an args array without
  // escaping (Node's DEP0190). Every token must stay shell-safe, so
  // `discoverLockfileDirs` above refuses a manifest directory carrying a
  // space or a metacharacter instead of passing it through to npm.
  var cmd = ["npm", "install", "--package-lock-only", "--no-audit", "--no-fund"]
    .concat(entry.args).join(" ");
  var r = cp.spawnSync(cmd, {
    cwd: dirAbs, encoding: "utf8", shell: true,
  });
  if (r.status !== 0) {
    problems.push(entry.dir + ": `npm install --package-lock-only` failed: " + ((r.stderr || r.stdout || "").trim().slice(-300)));
    return;
  }
  fixed.push(entry.dir + "/package-lock.json regenerated (" + entry.label + ")");
}

// ---- Segment 3: Docker digest mirror ----

function reEscape(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function readFrom(file, image) {
  var abs = path.join(ROOT, file);
  var src;
  try { src = fs.readFileSync(abs, "utf8"); }
  catch (e) { return { err: file + " unreadable: " + (e && e.message) }; }
  var re = new RegExp("FROM\\s+" + reEscape(image) + "(@sha256:[0-9a-f]{64})?", "m");
  var m = re.exec(src);
  if (!m) return { err: file + " has no `FROM " + image + "` line" };
  return { digest: m[1] ? m[1].slice(1) : null, src: src, matched: m[0] };
}

function checkDigestSync(entry) {
  var ref = readFrom(entry.reference, entry.image);
  var tgt = readFrom(entry.target, entry.image);
  if (ref.err) { problems.push(ref.err); return; }
  if (tgt.err) { problems.push(tgt.err); return; }
  if (!ref.digest) {
    problems.push(entry.reference + " `FROM " + entry.image + "` is not @sha256-pinned. The reference must be pinned for the mirror to have a source of truth");
    return;
  }
  if (tgt.digest !== ref.digest) {
    problems.push(entry.target + " `FROM " + entry.image + "` digest " + (tgt.digest || "<unpinned>") +
      " != reference " + entry.reference + " " + ref.digest + ". Sync with `node scripts/pin-all.js --fix`");
  }
}

function fixDigestSync(entry) {
  var ref = readFrom(entry.reference, entry.image);
  var tgt = readFrom(entry.target, entry.image);
  if (ref.err) { problems.push(ref.err); return; }
  if (tgt.err) { problems.push(tgt.err); return; }
  if (!ref.digest) { problems.push(entry.reference + " reference is not @sha256-pinned"); return; }
  if (tgt.digest === ref.digest) return;
  var newSrc = tgt.src.replace(tgt.matched, "FROM " + entry.image + "@" + ref.digest);
  fs.writeFileSync(path.join(ROOT, entry.target), newSrc);
  fixed.push(entry.target + " base digest synced to " + ref.digest.slice(0, 19) + "... (" + entry.label + ")");
}

// ---- Segment 2: GitHub Action SHAs (delegate) ----

function fixActions() {
  var script = path.join(__dirname, "check-actions-currency.js");
  if (!fs.existsSync(script)) {
    problems.push("Action-SHA --fix skipped: scripts/check-actions-currency.js not present");
    return;
  }
  var r = cp.spawnSync(process.execPath, [script, "--fix"], { cwd: ROOT, encoding: "utf8" });
  if (r.status !== 0) {
    problems.push("Action-SHA --fix (check-actions-currency.js) failed:\n" + ((r.stdout || "") + (r.stderr || "")).trim().slice(-600));
    return;
  }
  fixed.push("GitHub Action SHAs pinned/updated (check-actions-currency.js --fix)");
}

// ---- Run ----

if (LOCKFILES_ONLY) {
  LOCKFILE_DIRS.forEach(fixLockfile);
} else if (FIX) {
  LOCKFILE_DIRS.forEach(fixLockfile);
  DIGEST_SYNCS.forEach(fixDigestSync);
  fixActions();
} else {
  LOCKFILE_DIRS.forEach(checkLockfile);
  DIGEST_SYNCS.forEach(checkDigestSync);
}

fixed.forEach(function (f) { console.log("[pin-all] fixed: " + f); });
if (problems.length) {
  problems.forEach(function (p) { console.error("[pin-all] " + ((FIX || LOCKFILES_ONLY) ? "ERROR" : "DRIFT") + ": " + p); });
  // Published on the failing path too, so the number sits beside the
  // findings rather than only beside a pass.
  if (!FIX && !LOCKFILES_ONLY) publishExamined();
  process.exit(1);
}
console.log("[pin-all] OK, " + (LOCKFILES_ONLY
  ? "committed lockfiles regenerated to the current versions."
  : FIX
    ? "lockfiles regenerated, Action SHAs pinned, Docker digests synced."
    : "committed lockfiles (specs + versions) in sync with package.json (Action-SHA currency has its own gate)."));
// The counts belong to the CHECK. A --fix run rewrites the lockfiles rather
// than comparing them, so it examined nothing in the sense this contract
// means, and publishing a number there would answer a question nobody asked.
if (!FIX && !LOCKFILES_ONLY) publishExamined();
