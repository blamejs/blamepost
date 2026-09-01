#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/generate-release-signing-key.js
 *
 * One-time setup: generate the ML-DSA-65 release-signing keypair that the
 * npm-publish workflow uses to sign every release tarball. The keypair is
 * produced with Node's built-in node:crypto (OpenSSL 3.5, FIPS 204); no
 * vendored crypto is involved.
 *
 * Run this ONCE locally before the first signed release. The script:
 *   - Writes the PUBLIC key to `keys/release-pqc-pub.json` (commit this
 *     file, because operators verify against the in-tree pubkey).
 *   - Prints the PRIVATE key (base64url PKCS#8 DER) to stdout. Store it as
 *     the `RELEASE_PQC_SIGNING_KEY` secret in the npm-publish GitHub Actions
 *     environment (same scope as NPM_TOKEN).
 *   - Prints the public-key fingerprint (SHA3-512 of the raw public-key
 *     bytes). Add it to SECURITY.md so operators can verify the in-tree
 *     pubkey out of band against the commit-signed SECURITY.md.
 *
 *   node scripts/generate-release-signing-key.js
 *   node scripts/generate-release-signing-key.js --rotate
 *   node scripts/generate-release-signing-key.js --out <path>
 *
 * A key that is already on disk is a REFUSAL, not something to overwrite.
 * Every sidecar signature already published was made with the private half
 * of the key in that file, so replacing it retires all of them at once. An
 * operator verifying an older release against the in-tree public key then
 * gets a failed signature, and nothing in that failure distinguishes a
 * rotated key from a tampered artifact. `--rotate` is how the operator says
 * they mean it, and the outgoing key's fingerprint is recorded in the
 * replacement so there is a written answer to "which releases does the old
 * key cover".
 *
 * Rotating:
 *   1. `node scripts/generate-release-signing-key.js --rotate`
 *   2. Update the `RELEASE_PQC_SIGNING_KEY` secret.
 *   3. Update SECURITY.md with the new fingerprint.
 *   4. Commit and ship a release.
 *   Releases signed before the rotation verify only against the OLD public
 *   key. `git log keys/release-pqc-pub.json` walks the history, and the
 *   `replaces` block in the new file names the fingerprint it succeeded.
 *
 * `--out` writes the public key somewhere other than the default path. It
 * exists so the refusal above can be exercised without addressing the
 * operator's real key, and so a rotation can be staged before it is moved
 * into place.
 *
 * Algorithm: ML-DSA-65 (FIPS 204), at NIST PQC security level 3
 * (~192-bit classical, ~128-bit post-quantum collision margin on the
 * SHA3-512 fingerprint).
 *
 * Exit codes:
 *   0  a keypair was generated and the public half written
 *   1  refused: a key is already there, or the outgoing key could not be
 *      identified, or there was nothing to replace
 *   2  the invocation itself was wrong
 */

var fs     = require("node:fs");
var path   = require("node:path");
var crypto = require("node:crypto");

// FIPS 204 ML-DSA-65 raw public-key length. The pubkey is stored raw
// (base64url) so it is engine-portable and small.
var ML_DSA_65_PUBKEY_BYTES = 1952;

var ALGORITHM = "ml-dsa-65";

var DEFAULT_PUB_PATH = path.resolve(__dirname, "..", "keys", "release-pqc-pub.json");

var ROTATION_NOTE =
  "Replacing this key retires every sidecar signature published under it. " +
  "Run scripts/generate-release-signing-key.js --rotate, update the " +
  "RELEASE_PQC_SIGNING_KEY secret and the SECURITY.md fingerprint in the same commit.";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function sha3_512_hex(buf) {
  return crypto.createHash("sha3-512").update(buf).digest("hex");
}

// Raw public-key bytes come out of the JWK export (`pub` is base64url of
// the FIPS 204 encoded public key); this keeps the stored pubkey to the
// spec's 1952 bytes rather than the SPKI-wrapped form.
function _rawPublicKey(publicKey) {
  var jwk = publicKey.export({ format: "jwk" });
  if (!jwk || typeof jwk.pub !== "string") {
    throw new Error("could not extract raw ML-DSA public key from JWK export");
  }
  return Buffer.from(jwk.pub, "base64url");
}

/**
 * _pubPathFrom(argv) reads the `--out` override. This is an entry point
 * rather than a request, so a flag with no path throws: quietly falling
 * back to the default would write release key material into the tree when
 * the caller asked for somewhere else.
 */
function _pubPathFrom(argv) {
  var at = argv.indexOf("--out");
  if (at === -1) return DEFAULT_PUB_PATH;
  var value = argv[at + 1];
  if (typeof value !== "string" || value.length === 0 || value.charAt(0) === "-") {
    throw new TypeError("--out needs a path");
  }
  return path.resolve(value);
}

/**
 * _identify(doc) returns the fingerprint and creation date of a key
 * document already on disk, or null when neither can be established.
 *
 * The recorded fingerprint wins, and the public key it carries is the
 * fallback, because an operator who trimmed the file by hand still has the
 * bytes the fingerprint is taken over. When neither is readable the answer
 * is null rather than a guess: the record of what is being retired is the
 * whole reason the rotation is allowed to proceed.
 */
function _identify(doc) {
  if (!doc || typeof doc !== "object") return null;
  var createdAt = typeof doc.createdAt === "string" ? doc.createdAt : null;
  if (typeof doc.fingerprint_sha3_512 === "string" && doc.fingerprint_sha3_512.length > 0) {
    return { fingerprint: doc.fingerprint_sha3_512, createdAt: createdAt };
  }
  if (typeof doc.publicKey === "string" && doc.publicKey.length > 0) {
    var raw = Buffer.from(doc.publicKey, "base64url");
    if (raw.length === 0) return null;
    return { fingerprint: sha3_512_hex(raw), createdAt: createdAt };
  }
  return null;
}

/**
 * _rotationPlan(pubPath, argv) decides what this run may do, BEFORE any
 * key material exists. Settling it first is the point: a run that mints a
 * keypair and then declines to write it has still produced private bytes
 * and put them in a process that was never supposed to hold any.
 *
 * Returns one of:
 *   { action: "create", replacing: null }
 *   { action: "rotate", replacing: { fingerprint, createdAt } }
 *   { action: "refuse", reason: "<what to do instead>" }
 *
 * Pure apart from reading the path, and exported, so the refusals are
 * provable against a temporary directory without generating anything.
 */
function _rotationPlan(pubPath, argv) {
  var wantsRotate = (argv || []).indexOf("--rotate") !== -1;

  if (!fs.existsSync(pubPath)) {
    if (wantsRotate) {
      return {
        action: "refuse",
        reason: "--rotate replaces an existing release signing key and there is nothing at " +
          pubPath + " to replace. Run without --rotate to mint the first key, or point " +
          "--out at the key you meant.",
      };
    }
    return { action: "create", replacing: null };
  }

  var doc;
  try {
    doc = JSON.parse(fs.readFileSync(pubPath, "utf8"));
  } catch (e) {
    return {
      action: "refuse",
      reason: "a release signing key is already at " + pubPath + " and it could not be read (" +
        ((e && e.message) || String(e)) + "), so the key this run would retire cannot be " +
        "identified. Repair or move that file deliberately before minting a replacement.",
    };
  }

  var outgoing = _identify(doc);
  if (outgoing === null) {
    return {
      action: "refuse",
      reason: "a release signing key is already at " + pubPath + " and it carries neither a " +
        "fingerprint nor a public key, so the key this run would retire could not be " +
        "identified. Repair or move that file deliberately before minting a replacement.",
    };
  }

  if (!wantsRotate) {
    return {
      action: "refuse",
      reason: "a release signing key is already at " + pubPath + " (fingerprint " +
        outgoing.fingerprint + "). Every sidecar signature already published was made with " +
        "its private half, and overwriting it retires all of them at once: an operator " +
        "verifying an earlier release against the in-tree public key gets a failed " +
        "signature that looks exactly like a tampered artifact. Pass --rotate to replace it " +
        "on purpose, and update the RELEASE_PQC_SIGNING_KEY secret and the SECURITY.md " +
        "fingerprint in the same commit.",
    };
  }

  return { action: "rotate", replacing: outgoing };
}

/**
 * _publicKeyDocument(opts) builds the file that ships in the tree. A
 * replacement carries a `replaces` block naming the fingerprint it
 * succeeded, so the answer to "which key verifies release X" is in the
 * file rather than only in the commit history.
 *
 * @opts
 *   publicKey:   string,  // base64url raw public key
 *   fingerprint: string,  // SHA3-512 over the raw public key
 *   plan:        object,  // the decision from _rotationPlan
 */
function _publicKeyDocument(opts) {
  opts = opts || {};
  var doc = {
    algorithm:            ALGORITHM,
    publicKey:            opts.publicKey,
    fingerprint_sha3_512: opts.fingerprint,
    createdAt:            new Date().toISOString().slice(0, 10),
    rotation_note:        ROTATION_NOTE,
  };
  var plan = opts.plan || {};
  if (plan.action === "rotate" && plan.replacing) {
    doc.replaces = {
      fingerprint_sha3_512: plan.replacing.fingerprint,
      createdAt:            plan.replacing.createdAt,
      note: "Releases signed before this rotation verify only against the retired key. " +
        "Recover it with: git log -p keys/release-pqc-pub.json",
    };
  }
  return doc;
}

function main() {
  var pubPath;
  try {
    pubPath = _pubPathFrom(process.argv);
  } catch (e) {
    process.stderr.write("[generate-release-signing-key] " + ((e && e.message) || String(e)) + "\n");
    process.exit(2);
    return;
  }

  // Settled before anything is generated. Nothing below this point runs on
  // a refusal, so a refused run leaves no key material anywhere.
  var plan = _rotationPlan(pubPath, process.argv);
  if (plan.action === "refuse") {
    process.stderr.write("[generate-release-signing-key] refused: " + plan.reason + "\n");
    process.exit(1);
    return;
  }

  var pair;
  try {
    pair = crypto.generateKeyPairSync(ALGORITHM);
  } catch (e) {
    process.stderr.write("[generate-release-signing-key] node:crypto ML-DSA-65 keygen failed: " +
      ((e && e.message) || e) + "\n");
    process.stderr.write("[generate-release-signing-key] ML-DSA requires the engine floor (Node >=24.19.0, OpenSSL 3.5).\n");
    process.exit(1);
    return;
  }

  var pubBytes = _rawPublicKey(pair.publicKey);
  if (pubBytes.length !== ML_DSA_65_PUBKEY_BYTES) {
    process.stderr.write("[generate-release-signing-key] unexpected public-key length " +
      pubBytes.length + " (expected " + ML_DSA_65_PUBKEY_BYTES + " for ML-DSA-65)\n");
    process.exit(1);
    return;
  }
  // The private key is exported as PKCS#8 DER (seed form), which is
  // self-contained, standard, and reconstructable by
  // scripts/sign-release-artifact.js with a single createPrivateKey call.
  var pkcs8 = pair.privateKey.export({ type: "pkcs8", format: "der" });
  var fingerprint = sha3_512_hex(pubBytes);

  var pubJson = _publicKeyDocument({
    publicKey:   b64url(pubBytes),
    fingerprint: fingerprint,
    plan:        plan,
  });

  fs.mkdirSync(path.dirname(pubPath), { recursive: true });
  fs.writeFileSync(pubPath, JSON.stringify(pubJson, null, 2) + "\n");

  process.stderr.write("\n=== ML-DSA-65 release-signing keypair (node:crypto, FIPS 204) ===\n\n");
  process.stderr.write("Public key written to: " + pubPath + "\n");
  process.stderr.write("Fingerprint (SHA3-512): " + fingerprint + "\n");
  if (plan.action === "rotate") {
    process.stderr.write("Retired fingerprint:    " + plan.replacing.fingerprint + "\n");
    process.stderr.write("Retired key created:    " +
      (plan.replacing.createdAt || "not recorded") + "\n");
    process.stderr.write("\nEvery release signed before now verifies only against the retired\n");
    process.stderr.write("key. Recover it with: git log -p keys/release-pqc-pub.json\n");
  }
  process.stderr.write("\nPrivate key (base64url PKCS#8 DER). Paste it into the RELEASE_PQC_SIGNING_KEY secret:\n");
  process.stderr.write("------------------------\n");
  process.stdout.write(b64url(pkcs8) + "\n");
  process.stderr.write("------------------------\n\n");
  process.stderr.write("Next steps:\n");
  process.stderr.write("  1. Verify the public-key write:\n");
  process.stderr.write("       cat " + pubPath + "\n");
  process.stderr.write("  2. Set the secret in the npm-publish environment:\n");
  process.stderr.write("       gh secret set RELEASE_PQC_SIGNING_KEY --env npm-publish --body \"<paste from above>\"\n");
  process.stderr.write("  3. Update SECURITY.md with the fingerprint above.\n");
  process.stderr.write("  4. Commit keys/release-pqc-pub.json + SECURITY.md, ship a release.\n");
}

// Exported so the guard is provable without generating a keypair.
// Requiring this file runs NOTHING: the previous shape called main() on
// load, so anything that required it minted release key material and
// printed the private half to stdout.
module.exports = {
  DEFAULT_PUB_PATH:   DEFAULT_PUB_PATH,
  _identify:          _identify,
  _publicKeyDocument: _publicKeyDocument,
  _pubPathFrom:       _pubPathFrom,
  _rotationPlan:      _rotationPlan,
};

if (require.main === module) {
  main();
}
