// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/refresh-vendor-manifest.js
 *
 * Recomputes SHA-256 over every vendored file declared in
 * lib/vendor/MANIFEST.json and writes the hashes back to the manifest.
 * The operator runs this after a vendored bundle is re-built.
 *
 * Verification (catching drift between the manifest's recorded hashes and
 * the on-disk content) is done by the vendor-manifest smoke check. This
 * script is the refresh-tool side only.
 *
 *   node scripts/refresh-vendor-manifest.js
 *   node scripts/refresh-vendor-manifest.js --hash <path>
 *
 * The second form prints one hash for one path and writes nothing. It is
 * how scripts/vendor-update.sh measures a staged tree before it publishes
 * it and the published tree afterwards: both measurements come from this
 * implementation, so the value the refresh compares is the same value the
 * manifest ends up recording rather than a second algorithm that agrees
 * until the day it does not.
 *
 * Two properties of this file are load-bearing and easy to undo.
 *
 * It composes nothing from lib/vendor/blamejs/. That looks like a missed
 * primitive and is not: this script runs from inside a vendor refresh, at
 * the moment the vendored tree is being replaced, and an operator runs it
 * by hand to repair a manifest after a refresh went wrong. Tooling whose
 * job is to recover the framework cannot require the framework, because
 * the state it exists for is the state where the framework will not load.
 * b.atomicFile.writeJson is the primitive this would otherwise compose;
 * the write below is that primitive's sequence written out locally for
 * that reason alone.
 *
 * And the manifest write is replace-in-place rather than truncate-and-fill.
 * The manifest is the only record of which framework version is on disk and
 * what its bytes hash to. A write that opens it for truncation destroys
 * that record before the replacement exists, so a process that dies in
 * between leaves a tree nothing describes.
 */

var fs     = require("node:fs");
var crypto = require("node:crypto");
var path   = require("node:path");

// The one reader and writer of the published-count contract, so the definition
// of a refusable zero here is the one every caller applies.
var examinedCounts = require("./examined-counts.js");

var MANIFEST_PATH = path.join(__dirname, "..", "lib", "vendor", "MANIFEST.json");

function hashFile(p) {
  return "sha256:" + crypto.createHash("sha256")
    .update(fs.readFileSync(p)).digest("hex");
}

function hashTree(dir) {
  var entries = fs.readdirSync(dir, { withFileTypes: true })
    .sort(function (a, b) { return a.name.localeCompare(b.name); });
  var h = crypto.createHash("sha256");
  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    var p = path.join(dir, e.name);
    h.update(e.name);
    if (e.isDirectory()) h.update(hashTree(p));
    else h.update(fs.readFileSync(p));
  }
  return "sha256-tree:" + h.digest("hex");
}

// File paths in MANIFEST.json are repo-relative (e.g.
// "lib/vendor/noble-ciphers.cjs"); resolve them against the repo root.
function _resolve(fp) {
  return path.join(__dirname, "..", fp);
}

function computeHashes(pkgEntry) {
  if (!pkgEntry.files) return {};
  var out = {};
  var keys = Object.keys(pkgEntry.files);
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    var fp = pkgEntry.files[k];
    if (typeof fp !== "string") continue;
    var abs = _resolve(fp);
    if (fp.endsWith("/")) {
      if (fs.existsSync(abs)) out[k] = hashTree(abs);
      else out[k] = "MISSING";
    } else if (fs.existsSync(abs)) {
      out[k] = hashFile(abs);
    } else {
      out[k] = "MISSING";
    }
  }
  return out;
}

// Encoding gate. Reject manifests that carry Latin-1-of-UTF-8 mojibake
// (typographic punctuation re-encoded through a mis-set editor codepage)
// or a U+FFFD replacement character (a lossy encoding round-trip).
// Operator-facing artifacts MUST be clean UTF-8.
function _refuseMojibake(raw) {
  if (/â/.test(raw)) {
    process.stderr.write("[refresh-vendor-manifest] FAIL: MANIFEST.json contains UTF-8-as-Latin-1 mojibake.\n");
    process.stderr.write("[refresh-vendor-manifest] Re-author affected prose fields in clean UTF-8 before refreshing.\n");
    process.exit(1);
  }
  if (raw.indexOf("�") !== -1) {
    process.stderr.write("[refresh-vendor-manifest] FAIL: MANIFEST.json contains U+FFFD replacement character (encoding loss).\n");
    process.exit(1);
  }
}

// RFC 3339 timestamp. Date-only strings boundary-flip across midnight-UTC
// under Date.parse comparisons; emit the full seconds-precision form so a
// currency check comparing bundledAt against an upstream commit time is
// boundary-safe.
function _rfc3339Now() {
  return new Date().toISOString();
}

/**
 * hashPath(p) picks the tree walk for a directory and the file digest for
 * a file, so a caller that has a path but not its kind gets the value the
 * manifest would record for it.
 */
function hashPath(p) {
  var st = fs.statSync(p);
  return st.isDirectory() ? hashTree(p) : hashFile(p);
}

/**
 * writeReplace(target, contents) puts `contents` at `target` without ever
 * leaving `target` shorter than it was. The bytes go to a sibling
 * temporary file, that file is flushed, and only then does a rename put it
 * over the destination. A rename within one directory replaces the entry
 * in a single step, so a reader sees either the whole old file or the
 * whole new one.
 *
 * The temporary file is removed on any failure, so a refusal does not
 * leave scratch beside a manifest an operator is about to read.
 */
function writeReplace(target, contents) {
  var dir  = path.dirname(target);
  var temp = path.join(dir, "." + path.basename(target) + ".tmp-" +
    crypto.randomBytes(8).toString("hex"));
  var fd;
  try {
    fd = fs.openSync(temp, "wx");
    fs.writeFileSync(fd, contents);
    // fsync is best effort. Some filesystems reject it and the rename is
    // still the atomic step; a refusal here must not fail the write.
    try { fs.fsyncSync(fd); }
    catch (_e) { /* drop-silent by design: the rename below is the guarantee */ }
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temp, target);
  } catch (e) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); }
      catch (_e2) { /* drop-silent by design: the throw below is the verdict */ }
    }
    try { fs.rmSync(temp, { force: true }); }
    catch (_e3) { /* drop-silent by design: the throw below is the verdict */ }
    throw e;
  }
}

function main() {
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  _refuseMojibake(raw);
  var manifest = JSON.parse(raw);
  var pkgs = Object.keys(manifest.packages || {});
  var totalHashes = 0;
  var refreshedAt = _rfc3339Now();
  for (var i = 0; i < pkgs.length; i += 1) {
    var pkg = manifest.packages[pkgs[i]];
    pkg.hashes = computeHashes(pkg);
    totalHashes += Object.keys(pkg.hashes).length;
    // Promote date-only bundledAt fields to RFC 3339 UTC so a
    // Date.parse-based currency comparison is boundary-safe.
    if (typeof pkg.bundledAt === "string" && /^\d{4}-\d{2}-\d{2}$/.test(pkg.bundledAt)) {
      pkg.bundledAt = pkg.bundledAt + "T00:00:00Z";
    }
    // Stamp the refresh timestamp so operators can diff "when did this
    // bundle last get re-hashed" without trawling git log.
    pkg.refreshedAt = refreshedAt;
  }
  var out = JSON.stringify(manifest, null, 2) + "\n";
  _refuseMojibake(out);
  writeReplace(MANIFEST_PATH, out);
  process.stdout.write("[refresh-vendor-manifest] wrote " +
    pkgs.length + " packages / " + totalHashes + " hashes to " +
    MANIFEST_PATH + " (refreshedAt=" + refreshedAt + ")\n");

  // WHAT THE REFRESH REACHED, published as the last lines of stdout.
  //
  // This file is not a gate, and it writes the record two of them read:
  // check-vendor-integrity.js verifies the tree against these hashes and
  // check-vendor-currency.js compares these versions against upstream. A
  // manifest whose `packages` map arrived absent or empty walks no package,
  // hashes nothing, writes itself back, and exits 0. Both gates then answer
  // over an empty record and report clean, and each of them refuses its own
  // zero only because this file did not hand them one to begin with.
  //
  // Two units, because they fail apart. `manifest-packages` is the map that
  // was read. `hashed-slots` is what the walk actually computed inside it: a
  // package whose file list emptied leaves the package count healthy and the
  // hashes it was refreshed to produce gone.
  return examinedCounts.publish([
    { unit: "manifest-packages", n: pkgs.length },
    { unit: "hashed-slots",      n: totalHashes },
  ], { tag: "[refresh-vendor-manifest]" });
}

// `--hash <path>` prints one hash and writes nothing. Bad input throws
// here rather than degrading to a default, because the caller is a script
// about to decide whether a vendored tree may be published.
function hashOnly(target) {
  if (typeof target !== "string" || target.length === 0) {
    process.stderr.write("[refresh-vendor-manifest] --hash needs a path\n");
    process.exit(1);
  }
  var value;
  try {
    value = hashPath(target);
  } catch (e) {
    process.stderr.write("[refresh-vendor-manifest] cannot hash " + target +
      ": " + ((e && e.message) || String(e)) + "\n");
    process.exit(1);
    return;
  }
  process.stdout.write(value + "\n");
}

// Exported so the vendored-tree gate and the refresh tooling measure a
// tree with one implementation rather than three that agree by habit.
// Requiring this file runs nothing.
module.exports = {
  MANIFEST_PATH: MANIFEST_PATH,
  hashFile:      hashFile,
  hashTree:      hashTree,
  hashPath:      hashPath,
  writeReplace:  writeReplace,
};

if (require.main === module) {
  var flagAt = process.argv.indexOf("--hash");
  // `--hash` writes one digest and nothing else, because a caller reads that
  // stdout to decide whether a vendored tree may be published; a count line
  // after it would arrive inside the value. The refresh mode's stdout is a
  // human report, so its counts go there and its exit code carries the
  // refusal.
  if (flagAt !== -1) hashOnly(process.argv[flagAt + 1]);
  else process.exit(main());
}
