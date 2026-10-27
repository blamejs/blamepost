// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Whether the key a domain signs with is the key its published record
 * carries.
 *
 * A selector is two halves kept in two places. The public half is a
 * column on a selector row, and it is what `blamepost dkim records`
 * prints, what the admin interface renders, and what `blamepost doctor`
 * resolves out of the live zone and compares. The private half is a
 * sealed file under the keys folder, named by the `keyRef` on that same
 * row, and it is what the signer opens and signs with. Nothing had ever
 * asked whether the two belong together.
 *
 * A pair that has come apart is silent from every direction. The row is
 * intact, so `dkim list` and `dkim records` answer exactly as before.
 * The zone still carries what the row says, so `doctor` compares the two
 * and reports the domain correct. The signer opens a sealed file that
 * unseals and parses, so it builds and signs without a word. What leaves
 * is a signature a receiver cannot verify, under a selector the receiver
 * resolved successfully, and the only place that shows up is the
 * domain's own DMARC failure reports days later.
 *
 * It is reached by ordinary operator work rather than by an attack. The
 * keys folder is where this server sends an operator by hand: a key that
 * would not erase is named and left for them to delete, a mint refused
 * over a file already under its name tells them which file to remove,
 * and the refusal for a damaged key tells them to restore the volume
 * from a backup. A restore that brings back a key file older than the
 * row beside it is exactly this state, and the instruction to perform
 * one is in the refusal this server prints.
 *
 * The cost is not symmetric across the pair. A domain signs with both
 * algorithms and a receiver needs one aligned pass, so a single half
 * that has come apart still leaves DMARC passing everywhere, which is
 * why it can stand for months. Retiring the pair that still worked then
 * takes the domain to mail that fails DKIM at every receiver, with every
 * shipped report saying the zone is correct.
 *
 * What is pinned here, over the real signing path:
 *
 *   - A sealed key that does not match its row's published half refuses
 *     rather than signing, on the Ed25519 half and on the RSA half.
 *   - The refusal carries a stable code a surface can branch on, and it
 *     names the selector, the domain and the way back.
 *   - The code is a member of the module's exported set, which is what
 *     an operator-facing surface reads to decide a refusal may be shown.
 *   - A domain whose halves do agree signs, and the signature verifies
 *     against the record this server publishes, so a refusal reported
 *     here reads as the disagreement being caught rather than as signing
 *     being broken.
 *
 * Every key in this file is minted at run time into a temporary data
 * directory by the shipped verb. Real vault, real encrypted database,
 * real sealed key files. No sockets.
 *
 * Run standalone: node test/layer-1-state/dkim-record-key-agreement.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var dnsZone = require("../helpers/dns-zone");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var dkimMod = require("../../lib/mail/dkim");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The two halves a domain signs with. A disagreement on either one is
// the same defect and costs the same signature, so both are driven and
// the count below says two rather than one.
var HALVES_EXAMINED = 2;

// The frozen contract. A surface reads this to decide what to show and
// what to do next, so it survives every rename of the function that
// raises it and disappears only if the refusal itself is deleted.
var KEY_RECORD_MISMATCH = "dkim/key-record-mismatch";

// ---------------------------------------------------------------------------
// Readings
// ---------------------------------------------------------------------------

function refusalOf(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

function codeOf(e) {
  return e === null ? "(no refusal)" : ((e && e.code) || "(no code)");
}

function messageOf(e) {
  return e === null ? "(no refusal)" : String((e && e.message) || e).slice(0, 400);
}

// A handle that has never signed for this domain. The signer for a
// domain is built once and kept, so a handle that has already signed
// answers out of what it built rather than off the file a probe has just
// replaced, and every vector below would pass over an intact key.
function freshHandle(cfg, identity) {
  return dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
}

// The sealed private key a selector row points at, read straight off the
// volume. Copied rather than re-minted, because the whole claim is about
// a file that unseals and parses and belongs to a different row.
function sealedKeyOf(keyDir, identity, domain, algorithm) {
  var row = identity.domains.listSelectors({ domain: domain, status: "active" })
    .filter(function (s) { return s.algorithm === algorithm; })[0];
  return {
    keyRef:   row.keyRef,
    selector: row.selector,
    path:     nodePath.join(keyDir, row.keyRef),
  };
}

// The context a signing key is sealed under, spelled out here rather
// than imported for the reason the code above is: it is the contract
// deciding whether a key already on a volume opens, and a test that
// imports it cannot tell a changed tuple from a working one.
function sealContext(domain, selector, algorithm) {
  return {
    purpose:   "blamepost.mail.dkim.signing-key",
    domain:    domain,
    selector:  selector,
    algorithm: algorithm,
  };
}

// One half of a domain's pair replaced with another domain's private key
// of the same algorithm, sealed to the selector it is put under.
//
// The seal has to be redone rather than the file copied, and that is the
// whole shape of what this file still covers. A key is sealed to the
// selector it belongs to, so a file copied from another domain does not
// open here at all and is refused at the seal. What this leaves instead
// is a key that opens correctly for this selector and is not the key the
// selector's record publishes, which is what a database restored from
// before a selector was minted again under the same name leaves on the
// volume: the row carries the older public half, the file carries the
// newer private one, and every reading on this server but the derivation
// below answers off the row.
function putTheWrongKeyUnder(keyDir, identity, domain, donor, algorithm) {
  var target = sealedKeyOf(keyDir, identity, domain, algorithm);
  var source = sealedKeyOf(keyDir, identity, donor, algorithm);
  var donorPem = helpers.b.vault.aad.unseal(
    nodeFs.readFileSync(source.path, "utf8"),
    sealContext(donor, source.selector, algorithm));
  nodeFs.writeFileSync(target.path,
    helpers.b.vault.aad.seal(donorPem, sealContext(domain, target.selector, algorithm)),
    { mode: 0o600 });
  return target.keyRef;
}

// ---------------------------------------------------------------------------
// One half that has come apart
// ---------------------------------------------------------------------------

// The Ed25519 half. A receiver that resolves the selector gets the
// record the row publishes, checks the signature against it, and fails.
// Nothing on this server reports anything, because every shipped reading
// answers off the row.
async function anEd25519KeyThatIsNotTheRecordsRefuses(identity, cfg, keyDir, donor) {
  var domain = "eddsa-apart.example.com";
  await identity.domains.add({ domain: domain });
  var minted = freshHandle(cfg, identity);
  await minted.generate({ domain: domain, selector: "bpeddsa" });

  var published = minted.dnsRecords(domain).map(function (r) { return r.dnsTxtValue; }).sort();
  var swapped = putTheWrongKeyUnder(keyDir, identity, domain, donor, "ed25519");

  var dkim = freshHandle(cfg, identity);
  var refused = refusalOf(function () { return dkim.signerFor(domain); });

  count("a sealed Ed25519 key that is not the one its record publishes refuses to sign",
    refused !== null,
    refused === null
      ? "signed with a key the published record does not carry, under " + swapped
      : "refused");
  count("and the refusal carries the code a surface branches on",
    codeOf(refused) === KEY_RECORD_MISMATCH,
    codeOf(refused) + ": " + messageOf(refused));
  count("the refusal names the selector, so the operator knows which record to compare",
    refused !== null && messageOf(refused).indexOf("bpeddsa") !== -1,
    messageOf(refused));
  count("and names the domain that has stopped signing",
    refused !== null && messageOf(refused).indexOf(domain) !== -1,
    messageOf(refused));
  count("no key material reaches the refusal an operator reads",
    refused !== null && messageOf(refused).indexOf("PRIVATE KEY") === -1 &&
      messageOf(refused).indexOf("BEGIN") === -1,
    messageOf(refused));

  count("the record the row publishes is unchanged, which is why nothing else could see this",
    minted.dnsRecords(domain).map(function (r) { return r.dnsTxtValue; }).sort()
      .join("|") === published.join("|"),
    minted.dnsRecords(domain).length + " record(s)");

  // The relay path treats a coded refusal as an unsigned send and files a
  // row for it, so the code has to be one the module publishes rather
  // than one only this file knows about.
  count("the code is a member of the set a surface reads to decide a refusal may be shown",
    Object.keys(dkimMod.CODES).some(function (k) {
      return dkimMod.CODES[k] === KEY_RECORD_MISMATCH;
    }),
    Object.keys(dkimMod.CODES).join(", "));
}

// The RSA half, because the two are read through the same call and a
// claim proved on one says nothing about the other until the other is
// driven. This is the half a receiver that cannot check Ed25519 falls
// back to, so a domain that has come apart here fails at exactly the
// receivers the second signature exists for.
async function anRsaKeyThatIsNotTheRecordsRefuses(identity, cfg, keyDir, donor) {
  var domain = "rsa-apart.example.com";
  await identity.domains.add({ domain: domain });
  var minted = freshHandle(cfg, identity);
  await minted.generate({ domain: domain, selector: "bprsa" });

  var swapped = putTheWrongKeyUnder(keyDir, identity, domain, donor, "rsa-sha256");

  var dkim = freshHandle(cfg, identity);
  var refused = refusalOf(function () { return dkim.signerFor(domain); });

  count("a sealed RSA key that is not the one its record publishes refuses to sign",
    refused !== null,
    refused === null
      ? "signed with a key the published record does not carry, under " + swapped
      : "refused");
  count("under the same code as the other half, so one branch answers for the pair",
    codeOf(refused) === KEY_RECORD_MISMATCH,
    codeOf(refused) + ": " + messageOf(refused));
  count("and the refusal names the RSA selector rather than only the pair",
    refused !== null && messageOf(refused).indexOf("bprsa-rsa") !== -1,
    messageOf(refused));

  // `sign` is what the relay and the compose form call, and a refusal
  // that only `signerFor` made would never reach either of them.
  var signRefusal = null;
  try {
    await freshHandle(cfg, identity).sign(domain,
      "From: a@" + domain + "\r\nSubject: t\r\n\r\nbody\r\n");
  } catch (e) { signRefusal = e; }
  count("signing one message refuses too, which is the call the relay path makes",
    codeOf(signRefusal) === KEY_RECORD_MISMATCH,
    codeOf(signRefusal) + ": " + messageOf(signRefusal));
}

// The uncontested form of the same call. Without it a refusal reported
// above reads as signing being broken rather than as the disagreement
// being caught.
async function apairThatAgreesStillSignsAndVerifies(identity, cfg) {
  var domain = "agrees.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = freshHandle(cfg, identity);
  await dkim.generate({ domain: domain, selector: "bpagree" });

  var message =
    "From: alice@" + domain + "\r\nTo: bob@example.net\r\nSubject: t\r\n" +
    "Date: Mon, 1 Jan 2026 00:00:00 +0000\r\nMessage-ID: <a@" + domain + ">\r\n\r\nbody\r\n";
  var signed = await dkim.sign(domain, message);

  count("a pair whose halves agree signs once with each algorithm",
    (String(signed).match(/DKIM-Signature:/g) || []).length === 2,
    String((String(signed).match(/DKIM-Signature:/g) || []).length) + " signature(s)");

  var verdicts = await dnsZone.verifyAgainst(signed, dkim.dnsRecords(domain));
  count("and every signature verifies against the record this server publishes",
    dnsZone.allPass(verdicts), dnsZone.summarize(verdicts));
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-record-key-agreement");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var identity = null;
  try {
    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    });
    identity = await store.open(cfg);
    var keyDir = freshHandle(cfg, identity).describe().keyDir;

    // The keys every vector below moves onto another domain's name. They
    // are minted here by the shipped verb, so nothing in this repository
    // ever carries private key material.
    var donor = "donor.example.com";
    await identity.domains.add({ domain: donor });
    await freshHandle(cfg, identity).generate({ domain: donor, selector: "bpdonor" });

    await anEd25519KeyThatIsNotTheRecordsRefuses(identity, cfg, keyDir, donor);
    await anRsaKeyThatIsNotTheRecordsRefuses(identity, cfg, keyDir, donor);
    await apairThatAgreesStillSignsAndVerifies(identity, cfg);

    return helpers.getChecks();
  } finally {
    if (identity) {
      try { identity.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "dkim-record-key-agreement",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// half and a run that drove both otherwise report the same total and
// neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + HALVES_EXAMINED + " signing-half");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
