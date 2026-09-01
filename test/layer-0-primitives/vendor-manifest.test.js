// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * vendor-manifest: the gate that catches a hand-edited vendored tree.
 *
 * `lib/vendor/MANIFEST.json` is the record of what the vendor refresh
 * put on disk: which package, which version, the integrity value the
 * registry published for the tarball, and a hash over the extracted
 * tree. The refresh script writes it; nothing else may.
 *
 * The failure this gate exists for is quiet. A patch applied directly
 * to `lib/vendor/blamejs/` works, passes every behavioral test, and
 * survives until the next refresh replaces the tree and takes the patch
 * with it. Nothing announces the loss. Comparing the recorded hash
 * against the bytes on disk turns that into a failing check on the
 * commit that introduced it.
 *
 * What is asserted:
 *
 *   - the manifest parses, and declares the framework package
 *   - the recorded version matches the vendored package.json
 *   - the recorded npm coordinates and source URL agree with that
 *     version, so the manifest names a tarball that can be re-fetched
 *   - the integrity value is present and is a well-formed SHA-512
 *     subresource-integrity string
 *   - the tree hash still matches the bytes on disk
 *   - the vendored entry point loads and reports the same version
 *
 * The tree hash is computed the way `scripts/refresh-vendor-manifest.js`
 * computes it: a depth-first walk in name order, feeding each entry
 * name and then either the nested directory digest or the file bytes
 * into one SHA-256. The two implementations have to agree, and this
 * gate is what proves they do: a change to either that the other does
 * not follow fails here on the next run.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/vendor-manifest.test.js`.
 */

var fs      = require("node:fs");
var path    = require("node:path");
var crypto  = require("node:crypto");
var helpers = require("../helpers");
var check   = helpers.check;

var REPO_ROOT     = helpers.REPO_ROOT;
var VENDOR_DIR    = path.join(REPO_ROOT, "lib", "vendor");
var MANIFEST_PATH = path.join(VENDOR_DIR, "MANIFEST.json");
var PACKAGE_KEY   = "blamejs";
var NPM_NAME      = "@blamejs/core";

// A subresource-integrity value for SHA-512: 64 raw bytes, base64, so
// 86 characters plus two padding characters.
var INTEGRITY_RE = /^sha512-[A-Za-z0-9+/]{86}==$/;

// Mirrors scripts/refresh-vendor-manifest.js. Kept here rather than
// required from there, because that script runs its main() on load and
// rewrites the manifest, which is the one thing a verification gate
// must never do.
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

function hashFile(p) {
  return "sha256:" + crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

function run() {
  // ---- The manifest itself ----

  check("MANIFEST.json exists", fs.existsSync(MANIFEST_PATH));
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");

  var manifest = null;
  var parseErr = null;
  try { manifest = JSON.parse(raw); }
  catch (e) { parseErr = e; }
  check("MANIFEST.json parses as JSON" + (parseErr ? ": " + parseErr.message : ""), manifest !== null);

  check("MANIFEST.json declares a packages map",
    manifest.packages && typeof manifest.packages === "object");

  var pkg = manifest.packages[PACKAGE_KEY];
  check("MANIFEST.json declares the " + PACKAGE_KEY + " package", !!pkg);

  // ---- Version agreement ----

  check("recorded version is a string", typeof pkg.version === "string" && pkg.version.length > 0);
  check("recorded version is a release version",
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(pkg.version));

  var treePath = pkg.files && pkg.files.server;
  check("the package records a vendored tree path",
    typeof treePath === "string" && /\/$/.test(treePath));

  var treeAbs = path.join(REPO_ROOT, treePath);
  check("the vendored tree is on disk at " + treePath, fs.existsSync(treeAbs));

  var vendoredPkgPath = path.join(treeAbs, "package.json");
  check("the vendored tree carries a package.json", fs.existsSync(vendoredPkgPath));
  var vendoredPkg = JSON.parse(fs.readFileSync(vendoredPkgPath, "utf8"));

  check("recorded version matches the vendored package.json (" +
    pkg.version + " against " + vendoredPkg.version + ")",
  pkg.version === vendoredPkg.version);

  check("recorded npm name matches the vendored package.json (" +
    String(pkg.npm) + " against " + String(vendoredPkg.name) + ")",
  pkg.npm === NPM_NAME && vendoredPkg.name === NPM_NAME);

  check("recorded license matches the vendored package.json",
    !pkg.license || !vendoredPkg.license || pkg.license === vendoredPkg.license);

  // ---- Provenance of the bytes ----

  check("the package records a registry source URL",
    typeof pkg.source === "string" && /^https:\/\//.test(pkg.source));
  check("the source URL names the recorded version",
    typeof pkg.source === "string" && pkg.source.indexOf(pkg.version) !== -1);

  check("integrity is present", typeof pkg.integrity === "string" && pkg.integrity.length > 0);
  check("integrity is a well-formed sha512 subresource-integrity value: " +
    String(pkg.integrity).slice(0, 16) + "...",
  INTEGRITY_RE.test(String(pkg.integrity)));

  check("bundledAt is a parseable timestamp",
    typeof pkg.bundledAt === "string" && !isNaN(Date.parse(pkg.bundledAt)));

  // ---- The tree hash ----

  check("the package records hashes", pkg.hashes && typeof pkg.hashes === "object");

  var slots = Object.keys(pkg.files || {});
  check("every declared file slot has a recorded hash",
    slots.length > 0 && slots.every(function (s) {
      return typeof pkg.hashes[s] === "string" && pkg.hashes[s].length > 0;
    }));
  check("no recorded hash is the missing-file marker",
    slots.every(function (s) { return pkg.hashes[s] !== "MISSING"; }));

  slots.forEach(function (slot) {
    var declared = pkg.files[slot];
    var abs      = path.join(REPO_ROOT, declared);
    var recorded = pkg.hashes[slot];
    var computed = /\/$/.test(declared) ? hashTree(abs) : hashFile(abs);
    check("slot '" + slot + "' hash prefix agrees with the recorded algorithm",
      recorded.split(":")[0] === computed.split(":")[0]);
    check("slot '" + slot + "' matches the bytes on disk. " +
      "A mismatch means the vendored tree was changed outside the vendor refresh, " +
      "and the next refresh will discard the change: " +
      "recorded " + recorded.slice(0, 24) + "..., computed " + computed.slice(0, 24) + "...",
    recorded === computed);
  });

  // ---- The tree loads ----

  // The framework handle comes from the helper, which requires the
  // vendored entry point. A tree that parses but does not load is a
  // broken vendor refresh, and this is the cheapest place to find out.
  var b = helpers.b;
  check("the vendored entry point loads", b && typeof b === "object");
  check("the loaded framework reports the recorded version (" +
    String(b.version) + ")",
  b.version === pkg.version);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
