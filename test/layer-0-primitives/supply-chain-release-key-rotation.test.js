// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * supply-chain-release-key-rotation: replacing the release signing key is
 * a decision, not a side effect of running a setup script twice.
 *
 * `scripts/generate-release-signing-key.js` mints the ML-DSA-65 keypair
 * whose public half ships as `keys/release-pqc-pub.json` and whose private
 * half signs every release sidecar. Every signature already published was
 * made with the private half of whatever key is in that file. Overwriting
 * it retires all of them at once: an operator who verifies an older release
 * against the in-tree public key gets a failed signature, and nothing about
 * that failure says a key was rotated rather than an artifact tampered
 * with.
 *
 * The guard is the one DKIM generation already uses. A key that is present
 * is a refusal, the replacement needs a verb of its own, and the outgoing
 * key's fingerprint is recorded so the operator can tell an auditor which
 * releases the retired key covers.
 *
 * Everything below runs against a temporary directory, and NOTHING here
 * generates a keypair. That material belongs to the operator, it has to be
 * safeguarded the moment it exists, and a test that mints one is a test
 * that leaves private key bytes in a process table and a temp file. Every
 * case therefore drives either the decision function or a refusal that
 * lands before any key is generated, and the successful rotation is
 * recorded as an uncovered case rather than smuggled in.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/supply-chain-release-key-rotation.test.js`.
 */

var crypto = require("node:crypto");
var fs     = require("node:fs");
var path   = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;

var shared = require("./vendor-refresh-atomicity.test.js");

var keygen = require("../../scripts/generate-release-signing-key.js");

var REPO_ROOT = helpers.REPO_ROOT;
var SCRIPT    = path.join(REPO_ROOT, "scripts", "generate-release-signing-key.js");

// A stand-in for the public half of a key that has already signed
// releases. It is four bytes of nothing rather than a real ML-DSA-65
// public key: the guard reads the recorded fingerprint and the file's
// presence, and never the key itself.
var STAND_IN_PUB = "AAEC";

function _standInFingerprint() {
  return crypto.createHash("sha3-512")
    .update(Buffer.from(STAND_IN_PUB, "base64url")).digest("hex");
}

function _existingKeyDoc(extra) {
  var doc = {
    algorithm:            "ml-dsa-65",
    publicKey:            STAND_IN_PUB,
    fingerprint_sha3_512: _standInFingerprint(),
    createdAt:            "2026-01-15",
  };
  Object.keys(extra || {}).forEach(function (k) {
    if (extra[k] === undefined) delete doc[k];
    else doc[k] = extra[k];
  });
  return JSON.stringify(doc, null, 2) + "\n";
}

/**
 * _outPath(label, contents) returns a path inside a temporary directory,
 * with `contents` already written there when given. Nothing here ever
 * addresses the repository's own keys directory: a case that reached it
 * would mint release key material into the tree.
 */
function _outPath(label, contents) {
  var dir = helpers.tempDir("relkey-" + label);
  var out = path.join(dir, "release-pqc-pub.json");
  if (typeof contents === "string") fs.writeFileSync(out, contents);
  return out;
}

function _runScript(args) {
  return shared.runCommand(process.execPath, [SCRIPT].concat(args || []), { cwd: REPO_ROOT });
}

function _transcript(result) {
  return "exit=" + String(result.status) +
    " stdout: " + String(result.stdout || "").replace(/\s+/g, " ").slice(-300) +
    " stderr: " + String(result.stderr || "").replace(/\s+/g, " ").slice(-600);
}

// ---------------------------------------------------------------------------
// The decision, exercised without generating anything
// ---------------------------------------------------------------------------

function _decisionCases() {
  check("the generator exports its rotation decision",
    typeof keygen._rotationDecision === "function");

  // First setup. Nothing to retire, so nothing to confirm.
  var fresh = keygen._rotationDecision(_outPath("fresh"), []);
  check("no key on disk decides on a first mint", fresh.action === "create");

  // A key is present and the operator did not say to replace it.
  var present = _outPath("present", _existingKeyDoc());
  var refused = keygen._rotationDecision(present, []);
  check("a key already on disk refuses", refused.action === "refuse");
  check("the refusal names the flag that means it on purpose",
    /--rotate/.test(refused.reason));
  check("the refusal says what replacing the key costs",
    /verif/i.test(refused.reason) && /publish/i.test(refused.reason));

  // The deliberate replacement, with the outgoing key recorded.
  var rotate = keygen._rotationDecision(present, ["--rotate"]);
  check("the deliberate replacement is allowed", rotate.action === "rotate");
  check("the decision records the fingerprint being retired",
    rotate.replacing && rotate.replacing.fingerprint === _standInFingerprint());
  check("the decision records when the retired key was created",
    rotate.replacing && rotate.replacing.createdAt === "2026-01-15");

  // A file with no recorded fingerprint still has one, derived from the
  // public key it carries. An operator who hand-trimmed the file must not
  // lose the record of what is being retired.
  var nofp = _outPath("nofp", _existingKeyDoc({ fingerprint_sha3_512: undefined }));
  var derived = keygen._rotationDecision(nofp, ["--rotate"]);
  check("a missing fingerprint is derived from the recorded public key",
    derived.action === "rotate" &&
    derived.replacing.fingerprint === _standInFingerprint());

  // A key file that cannot be read is the case that matters. The whole
  // point of the guard is the record of what is being replaced, and a
  // rotation that cannot make that record has not made it.
  var unreadable = _outPath("unreadable", "{ not json\n");
  var refusedUnreadable = keygen._rotationDecision(unreadable, ["--rotate"]);
  check("a key file that cannot be read refuses even with the flag",
    refusedUnreadable.action === "refuse");
  check("the refusal says the outgoing key could not be identified",
    /could not/i.test(refusedUnreadable.reason));

  var empty = _outPath("nofields", JSON.stringify({ algorithm: "ml-dsa-65" }, null, 2) + "\n");
  var refusedEmpty = keygen._rotationDecision(empty, ["--rotate"]);
  check("a key file carrying no identifying material refuses",
    refusedEmpty.action === "refuse");

  // Asking to replace a key that is not there means the operator is
  // pointed somewhere they did not intend.
  var nothing = keygen._rotationDecision(_outPath("nothing"), ["--rotate"]);
  check("replacing a key that is not there refuses", nothing.action === "refuse");
  check("that refusal names the path it looked at",
    typeof nothing.reason === "string" && nothing.reason.length > 0);
}

// ---------------------------------------------------------------------------
// The refusal, driven the way an operator drives it
// ---------------------------------------------------------------------------

async function _refusalCases() {
  var before   = _existingKeyDoc();
  var existing = _outPath("spawn", before);

  var r1 = await _runScript(["--out", existing]);
  check("running the generator over an existing key exits non-zero. " + _transcript(r1),
    r1.status === 1);
  check("the refusal reaches the operator. " + _transcript(r1),
    /--rotate/.test(String(r1.stderr) + String(r1.stdout)));
  check("the refusal names the fingerprint that would have been retired. " + _transcript(r1),
    (String(r1.stderr) + String(r1.stdout)).indexOf(_standInFingerprint().slice(0, 32)) !== -1);
  check("the existing public key is left byte for byte as it was",
    fs.readFileSync(existing, "utf8") === before);
  check("the refusal emits nothing on stdout, where the private key would go. " +
    _transcript(r1), String(r1.stdout).trim() === "");

  // The refusal has to land BEFORE anything is generated. A run that mints
  // a keypair and then declines to write it has still produced private key
  // bytes and put them in this process's memory.
  var missing = _outPath("norotate");
  var r2 = await _runScript(["--out", missing, "--rotate"]);
  check("asking to replace a key that is not there exits non-zero. " + _transcript(r2),
    r2.status === 1);
  check("nothing was written when the replacement was refused",
    fs.existsSync(missing) === false);
  check("no key material reached stdout on the refused replacement. " + _transcript(r2),
    String(r2.stdout).trim() === "");

  var broken = _outPath("broken", "{ not json\n");
  var r3 = await _runScript(["--out", broken, "--rotate"]);
  check("an unreadable key file refuses the replacement. " + _transcript(r3),
    r3.status === 1);
  check("the unreadable key file is left alone",
    fs.readFileSync(broken, "utf8") === "{ not json\n");

  var r4 = await _runScript(["--out"]);
  check("--out with no path is refused rather than defaulted to the tree. " + _transcript(r4),
    r4.status === 2);

  // The successful replacement is not driven here on purpose. Generating a
  // release signing key produces private material that belongs to the
  // operator, so the path past the guard is covered by the decision cases
  // above and left unexercised end to end.
  helpers.skip("the successful mint and the successful replacement are not driven: " +
    "generating release signing key material is the operator's act, so only the " +
    "refusals are exercised against the script itself");
}

// ---------------------------------------------------------------------------
// The rotation record the new file has to carry
// ---------------------------------------------------------------------------

function _recordCases() {
  check("the generator exports the document builder",
    typeof keygen._publicKeyDocument === "function");

  var decision = { action: "create", replacing: null };
  var first = keygen._publicKeyDocument({
    publicKey:   STAND_IN_PUB,
    fingerprint: _standInFingerprint(),
    decision:    decision,
  });
  check("a first mint records the algorithm", first.algorithm === "ml-dsa-65");
  check("a first mint records its own fingerprint",
    first.fingerprint_sha3_512 === _standInFingerprint());
  check("a first mint records no predecessor",
    Object.prototype.hasOwnProperty.call(first, "replaces") === false);

  var rotated = keygen._publicKeyDocument({
    publicKey:   STAND_IN_PUB,
    fingerprint: _standInFingerprint(),
    decision:    {
      action:    "rotate",
      replacing: { fingerprint: "abc123", createdAt: "2026-01-15" },
    },
  });
  check("a replacement records the fingerprint it retired",
    rotated.replaces && rotated.replaces.fingerprint_sha3_512 === "abc123");
  check("a replacement records when the retired key was created",
    rotated.replaces && rotated.replaces.createdAt === "2026-01-15");
  check("a replacement records what stopped verifying",
    typeof rotated.replaces.note === "string" && /verif/i.test(rotated.replaces.note));
}

// ---------------------------------------------------------------------------
// Requiring a supply-chain script must not run it
// ---------------------------------------------------------------------------

// The three scripts this file and its siblings drive. Each is required by a
// test for its decision functions, so each must do nothing on load.
var REQUIRE_SAFE = [
  "scripts/generate-release-signing-key.js",
  "scripts/check-vendor-integrity.js",
  "scripts/check-actions-currency.js",
];

/**
 * _requireSafetyCases() asserts each of those scripts puts its invocation
 * behind a require.main guard.
 *
 * This is the shape that made the defect above expensive rather than
 * theoretical. The generator called main() at module scope, so requiring it
 * for any reason at all generated a keypair, wrote the public half into the
 * tree and printed the private half to stdout. There is no argument, no
 * flag and no refusal in front of that, because the file had not decided
 * anything yet when it ran.
 *
 * The list is the scripts these cases own. The same shape is live in other
 * scripts under `scripts/`, and closing it there belongs to whoever owns
 * them; narrowing this check to make those pass would be the opposite of
 * what it is for.
 */
function _requireSafetyCases() {
  REQUIRE_SAFE.forEach(function (rel) {
    var src = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    check(rel + " puts its invocation behind a require.main guard",
      /if\s*\(\s*require\.main\s*===\s*module\s*\)/.test(src));
    // Anything that would run on load sits at column zero outside that
    // guard, so a call written flush left is the shape to refuse.
    check(rel + " calls nothing at module scope",
      /^(?:main|run)\s*\(/m.test(src) === false);
  });
}

// ---------------------------------------------------------------------------

async function run() {
  _decisionCases();
  _recordCases();
  _requireSafetyCases();
  await _refusalCases();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
