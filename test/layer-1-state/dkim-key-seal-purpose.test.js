// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a sealed DKIM private key is bound to, and what a volume whose
 * keys were sealed before that binding existed does next.
 *
 * The vault's plain seal produces a value that opens wherever it is
 * found. Every sealed value on one volume is therefore interchangeable
 * with every other, so a file dropped into the keys folder opens as a
 * signing key whatever it was sealed as. The authenticated-data seal
 * binds a value to a context, and the context here names the purpose and
 * the selector the key belongs to, so a value sealed as anything else,
 * or as another selector's key, does not open here at all.
 *
 * The derivation check that compares an opened key against the public
 * half its own selector row publishes is a different guard and stays: it
 * catches a key file and a row that disagree. It cannot catch a key file
 * and a row that were copied TOGETHER out of another domain, because the
 * two agree, and that vector is driven below.
 *
 * Nothing here is faked. A real vault seals, a real encrypted database
 * holds the selector rows, and the private keys are minted at run time
 * in a temporary directory, because a key committed to a repository is a
 * key anyone who clones it holds.
 *
 * Run standalone: node test/layer-1-state/dkim-key-seal-purpose.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers    = require("../helpers");
var cliHelper  = require("../helpers/cli");
var b          = require("../../lib/vendor/blamejs");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var auditActor = require("../../lib/store/actor");
var blamepost  = require("../../lib");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var DOMAIN   = "example.com";
var SELECTOR = "bp202601";
var ED       = "ed25519";
var RSA      = "rsa-sha256";

// The domain whose pair is lifted, and the domain it is lifted onto.
var SOURCE_DOMAIN = "example.net";
var SOURCE_SELECTOR = "bp202609";
var LIFTED_DOMAIN = "lifted.example.com";

// The context a signing key is sealed under, written out here rather
// than imported from the module that seals with it.
//
// It is the contract that decides whether a key sealed by the server
// running today opens in the server running tomorrow, and there is no
// second copy of the key to fall back on. Importing the constant would
// let a changed tuple pass this file while every key already on every
// volume became unopenable, which is the one failure that cannot be
// repaired from here.
var KEY_SEAL_PURPOSE = "blamepost.mail.dkim.signing-key";

function sealContext(domain, selector, algorithm) {
  return {
    purpose:   KEY_SEAL_PURPOSE,
    domain:    domain,
    selector:  selector,
    algorithm: algorithm,
  };
}

// The other purpose this server seals a secret under. A value carrying
// it is sealed, is this volume's, and is not a signing key, which is
// exactly the value the binding exists to keep out of the keys folder.
var TOKEN_SEAL_CONTEXT = { purpose: "blamepost.dns.provider-token" };

function keyPathOf(dataDir, domain, selector, algorithm) {
  return nodePath.join(dataDir, "keys",
    domain + "." + selector + "." + algorithm + ".sealed");
}

// A private key opened from a file in whichever of the two forms it
// holds, so this file runs to the end against a tree that seals either
// way and reports each claim separately rather than stopping at the
// first one.
function openedKeyAt(path, context) {
  var text = nodeFs.readFileSync(path, "utf8");
  if (b.vault.aad.isAadSealed(text)) return b.vault.aad.unseal(text, context);
  return b.vault.unseal(text);
}

// A signer built through a handle that has never signed for this domain.
// A handle that has already signed answers from what it built rather
// than from the file a probe has just replaced.
function freshSignerFor(dataDir, identity, domain) {
  return blamepost.mail.dkim.create({ dataDir: dataDir, store: identity })
    .signerFor(domain);
}

function refusalOf(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

async function refusalOfAsync(fn) {
  try { await fn(); return null; }
  catch (e) { return e; }
}

// A private key of the right kind that this server never minted. Made
// here, in the run's own temporary directory, and never written into the
// repository.
function foreignKeyPem() {
  return nodeCrypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  }).privateKey;
}

// Temporary files an atomic write leaves behind when it is cut off. The
// write names them by appending to the file it is writing, so a run that
// stopped between the write and the rename shows up as one of these.
function partialFilesIn(keyDir) {
  return nodeFs.readdirSync(keyDir).filter(function (name) {
    return name.indexOf(".tmp-") !== -1;
  });
}

// ---- new keys carry their purpose ------------------------------------------

function aMintedKeyIsBoundToItsSelector(dataDir, identity) {
  var path = keyPathOf(dataDir, DOMAIN, SELECTOR, ED);
  var onDisk = nodeFs.readFileSync(path, "utf8");

  count("a newly minted private key is sealed under a purpose rather than to the volume " +
    "at large", b.vault.aad.isAadSealed(onDisk), onDisk.slice(0, 32));
  count("and it does not carry the plain volume seal, which every other sealed value on " +
    "this volume also carries",
    onDisk.indexOf(b.constants.VAULT_PREFIX) !== 0, onDisk.slice(0, 32));
  count("no plaintext private key reaches the volume",
    onDisk.indexOf("PRIVATE KEY") === -1, onDisk.slice(0, 32));
  count("and the domain signs with the key it just wrote",
    freshSignerFor(dataDir, identity, DOMAIN).pairs === 1,
    "pairs=" + String(freshSignerFor(dataDir, identity, DOMAIN).pairs));
}

// ---- a value sealed for something else is not a key ------------------------

function aValueSealedElsewhereDoesNotOpenAsAKey(dataDir, identity) {
  var path = keyPathOf(dataDir, DOMAIN, SELECTOR, ED);
  var whole = nodeFs.readFileSync(path, "utf8");
  try {
    nodeFs.writeFileSync(path, b.vault.aad.seal(foreignKeyPem(), TOKEN_SEAL_CONTEXT),
      { mode: 0o600 });
    var planted = refusalOf(function () {
      return freshSignerFor(dataDir, identity, DOMAIN);
    });

    count("a value this volume sealed for something other than this key is refused rather " +
      "than signed with",
      planted !== null && planted.code === "dkim/key-seal-foreign",
      planted ? String(planted.code) : "the domain signed with it");
    count("and the refusal names the domain and the selector, which is what an operator acts on",
      planted !== null && planted.message.indexOf(DOMAIN) !== -1 &&
      planted.message.indexOf(SELECTOR) !== -1,
      planted ? planted.message : "(no refusal)");
    count("and carries no part of the volume's layout, because a coded refusal is shown to " +
      "whoever asked",
      planted !== null && planted.message.indexOf(dataDir) === -1 &&
      planted.message.indexOf(".sealed") === -1,
      planted ? planted.message : "(no refusal)");
    count("and it is not the code a key that will not open under this volume's vault key " +
      "refuses under, because that one is repaired by restoring the volume and this one is not",
      planted !== null && planted.code !== "dkim/key-seal-unopened",
      planted ? String(planted.code) : "(no refusal)");
    // The domain's own key, sealed under the purpose and nothing else.
    // This is what the seal would carry if the three fields naming the
    // key were dropped from the context, and it is the reading that says
    // those fields are load-bearing rather than decoration: every key
    // this server mints carries the same purpose, so a purpose on its
    // own puts every selector's key back in reach of every other.
    var ownPem = b.vault.aad.unseal(whole, sealContext(DOMAIN, SELECTOR, ED));
    nodeFs.writeFileSync(path, b.vault.aad.seal(ownPem, { purpose: KEY_SEAL_PURPOSE }),
      { mode: 0o600 });
    var purposeOnly = refusalOf(function () {
      return freshSignerFor(dataDir, identity, DOMAIN);
    });
    count("the right key sealed under the purpose alone does not open either, so the seal " +
      "names the selector rather than only the kind of secret",
      purposeOnly !== null && purposeOnly.code === "dkim/key-seal-foreign",
      purposeOnly ? String(purposeOnly.code) : "a purpose-only seal signed");
  } finally {
    nodeFs.writeFileSync(path, whole, { mode: 0o600 });
  }
  count("and the whole file signs again, so the refusal was about the value rather than " +
    "about the domain",
    freshSignerFor(dataDir, identity, DOMAIN).pairs === 1, "the domain stopped signing");
}

// ---- a pair lifted from another domain, record and all ---------------------

async function aPairLiftedWithItsRecordDoesNotSign(dataDir, identity) {
  await identity.domains.add({ domain: LIFTED_DOMAIN });
  var source = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity })
    .list(SOURCE_DOMAIN);

  for (var i = 0; i < source.length; i += 1) {
    var sel = source[i];
    var keyRef = LIFTED_DOMAIN + "." + sel.selector + "." + sel.algorithm + ".sealed";
    nodeFs.copyFileSync(
      keyPathOf(dataDir, SOURCE_DOMAIN, sel.selector, sel.algorithm),
      nodePath.join(dataDir, "keys", keyRef));
    // The public half comes across with the private one, so the record
    // and the key agree and the derivation check has nothing to report.
    await identity.domains.addSelector({
      domain:    LIFTED_DOMAIN,
      selector:  sel.selector,
      algorithm: sel.algorithm,
      publicKey: sel.publicKey,
      keyRef:    keyRef,
    });
  }

  var lifted = refusalOf(function () {
    return freshSignerFor(dataDir, identity, LIFTED_DOMAIN);
  });
  count("a key pair copied out of another domain together with the records that name it is " +
    "refused, which the derivation check cannot do because the copied record and the copied " +
    "key agree with each other",
    lifted !== null && lifted.code === "dkim/key-seal-foreign",
    lifted ? String(lifted.code) : LIFTED_DOMAIN + " signed with " + SOURCE_DOMAIN + "'s key");
  count("and the refusal names the domain that cannot sign rather than the one the key came " +
    "from, because the operator is standing at the first",
    lifted !== null && lifted.message.indexOf(LIFTED_DOMAIN) !== -1,
    lifted ? lifted.message : "(no refusal)");
  count("and the domain the pair was lifted from still signs, so nothing was done to it",
    freshSignerFor(dataDir, identity, SOURCE_DOMAIN).pairs === 1,
    SOURCE_DOMAIN + " stopped signing");
}

// ---- a volume sealed before the binding existed -----------------------------

function aVolumeSealedTheOldWayKeepsSigning(dataDir, identity) {
  var path = keyPathOf(dataDir, DOMAIN, SELECTOR, ED);
  var pem = openedKeyAt(path, sealContext(DOMAIN, SELECTOR, ED));
  nodeFs.writeFileSync(path, b.vault.seal(pem), { mode: 0o600 });

  count("a key sealed the way this volume sealed them before still opens, so an upgrade " +
    "does not take a hosted domain off the air until an operator has run the migration",
    freshSignerFor(dataDir, identity, DOMAIN).pairs === 1,
    "the domain stopped signing on a key sealed the old way");

  // The guard the old form still has. It is the derivation check, and it
  // is why signing with the old form mid-migration is a key this server
  // can still prove is the record's.
  nodeFs.writeFileSync(path, b.vault.seal(foreignKeyPem()), { mode: 0o600 });
  var stranger = refusalOf(function () {
    return freshSignerFor(dataDir, identity, DOMAIN);
  });
  count("and a value sealed the old way that is not the key its record publishes is still " +
    "refused, so a volume part way through the migration signs with nothing it cannot place",
    stranger !== null && stranger.code === "dkim/key-record-mismatch",
    stranger ? String(stranger.code) : "the domain signed with a stranger's key");

  nodeFs.writeFileSync(path, b.vault.seal(pem), { mode: 0o600 });
  return pem;
}

// ---- the migration ----------------------------------------------------------

async function resealBindsWhatTheOldFormLeft(dataDir, identity, expectedPem) {
  var path = keyPathOf(dataDir, DOMAIN, SELECTOR, ED);
  var dkim = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity });

  var migrated = await dkim.reseal({ domain: DOMAIN });
  count("reseal binds the one key that was sealed the old way",
    migrated.resealed.length === 1, JSON.stringify(migrated.resealed));
  count("and reports the key that was already bound rather than writing it again",
    migrated.alreadyBound.length === 1, JSON.stringify(migrated.alreadyBound));
  count("and names each key it rewrote by the selector it belongs to",
    migrated.resealed[0].selector === SELECTOR &&
    migrated.resealed[0].algorithm === ED, JSON.stringify(migrated.resealed));

  var afterwards = nodeFs.readFileSync(path, "utf8");
  count("the file carries the purpose afterwards",
    b.vault.aad.isAadSealed(afterwards), afterwards.slice(0, 32));
  count("and the key inside it is the key that was there, so every signature already made " +
    "under this selector still verifies",
    openedKeyAt(path, sealContext(DOMAIN, SELECTOR, ED)) === expectedPem,
    "the migration changed the key material");
  count("and the domain signs afterwards",
    freshSignerFor(dataDir, identity, DOMAIN).pairs === 1, "the domain stopped signing");

  var again = await refusalOfAsync(function () { return dkim.reseal({ domain: DOMAIN }); });
  count("running the migration again writes nothing and refuses nothing, so an operator who " +
    "is not sure whether it has run can run it",
    again === null, again ? String(again.message) : "(no refusal)");
  var repeated = await dkim.reseal({ domain: DOMAIN });
  count("and reports both halves as already sealed to their selectors",
    repeated.resealed.length === 0 && repeated.alreadyBound.length === 2,
    JSON.stringify(repeated));
}

// A foreign value must not come out of the migration bound to a selector
// it was never sealed for. Binding one would take the only value this
// server can still refuse it by and turn it into a value it cannot.
async function resealRefusesToBindAValueItCannotPlace(dataDir, identity, realPem) {
  var path = keyPathOf(dataDir, DOMAIN, SELECTOR, ED);
  var dkim = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity });

  nodeFs.writeFileSync(path, b.vault.seal(foreignKeyPem()), { mode: 0o600 });
  var planted = nodeFs.readFileSync(path, "utf8");

  var refused = await refusalOfAsync(function () { return dkim.reseal({ domain: DOMAIN }); });
  count("the migration refuses a sealed value that is not the key its record publishes",
    refused !== null && refused.code === "dkim/keys-not-resealed",
    refused ? String(refused.code) : "the migration bound it");
  count("and names the selector it would not bind",
    refused !== null && refused.message.indexOf(SELECTOR) !== -1,
    refused ? refused.message : "(no refusal)");
  count("and leaves the file exactly as it found it, so nothing turns a value sealed for " +
    "something else into one bound to this selector",
    nodeFs.readFileSync(path, "utf8") === planted, "the file was rewritten");

  nodeFs.writeFileSync(path, b.vault.aad.seal(realPem, sealContext(DOMAIN, SELECTOR, ED)),
    { mode: 0o600 });
}

// ---- a migration that is cut off --------------------------------------------
//
// A signing key has one copy and nothing anywhere holds a second, so the
// write that replaces it must leave either the value that was there or
// the value that replaces it, and never part of one. The fault is
// installed on the rename, which is the step that makes a written
// temporary file the file, so the run below is a volume that stops
// taking writes half way through the migration.

async function anInterruptedMigrationLosesNoKey(dataDir, identity) {
  var dkim = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity });
  var keyDir = nodePath.join(dataDir, "keys");
  var edPath  = keyPathOf(dataDir, DOMAIN, SELECTOR, ED);
  var rsaPath = keyPathOf(dataDir, DOMAIN, SELECTOR + "-rsa", RSA);

  var edPem  = openedKeyAt(edPath,  sealContext(DOMAIN, SELECTOR, ED));
  var rsaPem = openedKeyAt(rsaPath, sealContext(DOMAIN, SELECTOR + "-rsa", RSA));
  nodeFs.writeFileSync(edPath,  b.vault.seal(edPem),  { mode: 0o600 });
  nodeFs.writeFileSync(rsaPath, b.vault.seal(rsaPem), { mode: 0o600 });
  var rsaBefore = nodeFs.readFileSync(rsaPath, "utf8");

  var fault = helpers.installWriteFault(SELECTOR + "-rsa." + RSA + ".sealed");
  var stopped;
  try {
    stopped = await refusalOfAsync(function () { return dkim.reseal({ domain: DOMAIN }); });
  } finally {
    fault.remove();
  }

  // What the fault actually refused. Without this the vector passes on a
  // run that never reached the write at all, and a refusal for some other
  // reason reads exactly like the one being driven.
  count("the run reached the write the fault was installed on",
    fault.attempts.length === 1 &&
    fault.attempts[0].indexOf(SELECTOR + "-rsa." + RSA + ".sealed") !== -1,
    JSON.stringify(fault.attempts));
  count("a migration that meets a volume which will not take a write stops and says so",
    stopped !== null && stopped.code === "dkim/keys-not-resealed",
    stopped ? String(stopped.code) : "the run reported success");
  count("and names the key it could not write",
    stopped !== null && stopped.message.indexOf(SELECTOR + "-rsa") !== -1,
    stopped ? stopped.message : "(no refusal)");
  count("the key the write refused is byte for byte the key that was there, because the " +
    "rename that would have replaced it never happened",
    nodeFs.readFileSync(rsaPath, "utf8") === rsaBefore,
    "the file under the refused write changed");
  count("and it still opens as the key its record publishes",
    openedKeyAt(rsaPath, sealContext(DOMAIN, SELECTOR + "-rsa", RSA)) === rsaPem,
    "the key material under the refused write changed");
  count("the key the run reached first is bound",
    b.vault.aad.isAadSealed(nodeFs.readFileSync(edPath, "utf8")),
    nodeFs.readFileSync(edPath, "utf8").slice(0, 32));
  count("and no half-written file is left in the keys folder for the next run to find",
    partialFilesIn(keyDir).length === 0, partialFilesIn(keyDir).join(", "));
  count("and the domain signs while the volume is part way through, on one key bound and " +
    "one not",
    freshSignerFor(dataDir, identity, DOMAIN).pairs === 1, "the domain stopped signing");

  var finished = await dkim.reseal({ domain: DOMAIN });
  count("running the migration again once the volume takes writes finishes it",
    finished.resealed.length === 1 && finished.alreadyBound.length === 1,
    JSON.stringify(finished));
  count("and both halves are bound afterwards",
    b.vault.aad.isAadSealed(nodeFs.readFileSync(edPath, "utf8")) &&
    b.vault.aad.isAadSealed(nodeFs.readFileSync(rsaPath, "utf8")),
    nodeFs.readFileSync(rsaPath, "utf8").slice(0, 32));
  count("and the domain signs on both of them",
    freshSignerFor(dataDir, identity, DOMAIN).pairs === 1, "the domain stopped signing");
}

// ---- the row the migration leaves -------------------------------------------

async function theMigrationLeavesARow(dataDir, identity) {
  var dkim = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity });
  var edPath = keyPathOf(dataDir, DOMAIN, SELECTOR, ED);
  var edPem = openedKeyAt(edPath, sealContext(DOMAIN, SELECTOR, ED));
  nodeFs.writeFileSync(edPath, b.vault.seal(edPem), { mode: 0o600 });

  b.audit.registerNamespace("blamepost");
  var capture = helpers.auditCapture();
  var rows;
  try {
    await b.audit.flush();
    // The identity the command line establishes, entered the way the
    // command line enters it, because the row has to name the operator
    // who ran the migration and an emit reached outside a scope records
    // that nobody did.
    await auditActor.runAs(auditActor.forCommandLine(), function () {
      return dkim.reseal({ domain: DOMAIN });
    });
    await b.audit.flush();
    rows = capture.forAction("blamepost.mail.dkim.keys_resealed");
  } finally {
    capture.release();
  }

  count("the migration is recorded, because it is a change to key material at rest",
    rows.length === 1, String(rows.length) + " row(s)");
  if (rows.length === 0) return;
  var row = rows[0];
  count("and the row names who performed it",
    typeof row.actorUserId === "string" && row.actorUserId.length > 0,
    JSON.stringify(row.actorUserId));
  count("and marks them as an operator at a terminal rather than an account, which is what " +
    "one column holding both kinds of principal has to be filtered by",
    typeof row.actorUserId === "string" && row.actorUserId.indexOf("cli:") === 0,
    JSON.stringify(row.actorUserId));
  count("and records that it succeeded", row.outcome === "success", String(row.outcome));

  var metadata = helpers.metadataOf(row);
  count("and names the domain", metadata.domain === DOMAIN, JSON.stringify(metadata.domain));
  count("and names each selector whose key it rewrote, which is what an incident reading " +
    "the trail places a signature by",
    JSON.stringify(metadata.resealed).indexOf(SELECTOR) !== -1,
    JSON.stringify(metadata.resealed));
  count("and carries no key material, because the chain is append-only and a value written " +
    "into it once cannot be taken back out",
    JSON.stringify(metadata).indexOf("PRIVATE KEY") === -1 &&
    JSON.stringify(metadata).indexOf("BEGIN ") === -1,
    JSON.stringify(metadata).slice(0, 240));
}

// ---- the command line -------------------------------------------------------

function theCommandLineCarriesTheVerb() {
  var cliDir  = helpers.tempDir("dkim-reseal-cli");
  var workDir = nodePath.join(cliDir, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });
  var cli = cliHelper.create({
    dataDir: cliDir, workDir: workDir, hostname: HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
  });
  try {
    var usage = cli(["dkim"]);
    count("`blamepost dkim` names the migration among its verbs, so an operator finds it " +
      "where they look for the other key verbs",
      usage.both.indexOf("reseal") !== -1, usage.both.slice(0, 400));

    var unhosted = cli(["dkim", "reseal", "--domain", "nothosted.example"]);
    count("and the verb takes --domain rather than answering that it does not know the flag",
      unhosted.both.indexOf("does not take") === -1 &&
      unhosted.both.indexOf("unknown") === -1,
      "exit " + unhosted.status + " " + unhosted.both.slice(0, 300));
    count("and refuses a domain this server does not host",
      unhosted.status !== 0 && unhosted.both.indexOf("nothosted.example") !== -1,
      "exit " + unhosted.status + " " + unhosted.both.slice(0, 300));
  } finally {
    helpers.removeTempDir(cliDir);
  }
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var dataDir = helpers.tempDir("dkim-seal-purpose");
  var workDir = nodePath.join(dataDir, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var cfg = config.load({ env: {
    BLAMEPOST_HOSTNAME:         HOSTNAME,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    BLAMEPOST_DATA_DIR:         dataDir,
  } });

  var identity = await store.open(cfg);
  try {
    await identity.domains.add({ domain: DOMAIN });
    await identity.domains.add({ domain: SOURCE_DOMAIN });
    var dkim = blamepost.mail.dkim.create({ dataDir: dataDir, store: identity });
    await dkim.generate({ domain: DOMAIN, selector: SELECTOR });
    await dkim.generate({ domain: SOURCE_DOMAIN, selector: SOURCE_SELECTOR });

    aMintedKeyIsBoundToItsSelector(dataDir, identity);
    aValueSealedElsewhereDoesNotOpenAsAKey(dataDir, identity);
    await aPairLiftedWithItsRecordDoesNotSign(dataDir, identity);

    var pem = aVolumeSealedTheOldWayKeepsSigning(dataDir, identity);
    await resealBindsWhatTheOldFormLeft(dataDir, identity, pem);
    await resealRefusesToBindAValueItCannotPlace(dataDir, identity, pem);
    await anInterruptedMigrationLosesNoKey(dataDir, identity);
    await theMigrationLeavesARow(dataDir, identity);

    theCommandLineCarriesTheVerb();

    return helpers.getChecks();
  } finally {
    identity.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(dataDir);
  }
}

module.exports = { name: "dkim-key-seal-purpose", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (checks) {
    console.log("CHECKS " + checks);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
