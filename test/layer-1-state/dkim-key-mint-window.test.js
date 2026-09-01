// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a mint may write over, and what it must refuse.
 *
 * `blamepost.mail.dkim.generate` and `blamepost.mail.dkim.rotate` both
 * mint a pair the same way: the name of each half is worked out, the
 * material is generated, the sealed private key is written to a file
 * under the keys folder, and the selector row naming that file is
 * written afterwards. The row is the only handle this server has on the
 * file, so the file has to land first: a row published for a key that is
 * not there is a domain whose mail leaves unsigned.
 *
 * That ordering leaves one question, and it is the question here: what
 * happens when the file name a mint is about to write is already taken.
 * A key file is derived from the domain, the selector and the algorithm,
 * so two mints asked for the same selector derive the SAME name, and
 * neither can see the other's selector row until it lands. Writing over
 * a name that is already there destroys the only copy of whatever was
 * under it, and what is under it is signing material: either the pair
 * another mint is halfway through writing, or the remains of a run that
 * stopped between the file and the row.
 *
 * The claim every vector below settles is one sentence: no mint writes
 * over a sealed private key that is already on this volume. What falls
 * out of it is that a domain never ends up publishing a selector whose
 * key is gone or is the wrong half of somebody else's pair, which is a
 * domain that signs nothing and fails DMARC alignment wherever the
 * policy sends failures.
 *
 * The interleaving is arranged rather than raced. A run that started two
 * mints and hoped they overlapped would reproduce the failure only
 * sometimes, which is worse than no test at all. Instead the selector
 * row writer is wrapped so that one call parks until this file releases
 * it, matched on the domain and algorithm the vector names, and every
 * other call runs the real primitive untouched. Nothing about the code
 * path changes: the same store, the same verbs, the same keys folder, in
 * the same order. Only the moment that one row lands is this file's to
 * choose.
 *
 * The reading that decides it is not "is the file there". It is whether
 * the sealed key a published row names opens, and whether the public
 * half it carries is the one that row publishes, because a mint that
 * wrote over another's key leaves both halves present and disagreeing.
 *
 * Run standalone: node test/layer-1-state/dkim-key-mint-window.test.js
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var dkimMod = require("../../lib/mail/dkim");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// How long a parked row write may wait for the mint that is supposed to
// land inside its window. Generous, because the work landing there
// generates an RSA modulus and seals two keys, and a fixed budget is
// what a loaded runner gets wrong.
var PARK_TIMEOUT_MS = 30000;

// The selector both mints in the interleaving ask for, so both derive
// the same key file name. Named rather than defaulted, because the
// default carries the current month and a vector that reads differently
// on the first of a month is a vector nobody can act on.
var SELECTOR = "bpmint";

// The two verbs that mint, printed at the end as the unit examined. A
// run that drove one of them and a run that drove both otherwise report
// the same check total and neither says which happened.
var MINTING_VERBS_EXAMINED = 2;

// The refusal a mint raises rather than writing over a sealed private
// key that is already on the volume. A frozen contract: a surface reads
// it to decide whether the message may be shown, and it survives every
// rename of the function that raises it.
var KEY_FILE_HELD = "dkim/key-file-held";

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

// One method on one handle, wrapped so a single call parks. Every call
// the vector did not ask for runs the real primitive and answers with
// exactly what it answered before, so the mint that lands inside the
// window does its own work exactly as it would in production.
//
// The wrapper stands on the store handle the mint was built with, which
// is the same object the identity layer published, so the verb under
// test reaches it without knowing anything happened.
function installCallGate(holder, name, wanted) {
  var real  = holder[name];
  var state = { parked: null, calls: [] };
  holder[name] = function () {
    var args = Array.prototype.slice.call(arguments);
    state.calls.push(args);
    if (state.parked !== null || !wanted(args)) return real.apply(holder, args);
    return new Promise(function (resolve, reject) {
      state.parked = { args: args, resolve: resolve, reject: reject };
    });
  };
  state.release = function () {
    var held = state.parked;
    if (held === null) throw new Error("installCallGate: nothing is parked to release");
    return Promise.resolve(real.apply(holder, held.args)).then(held.resolve, held.reject);
  };
  state.remove = function () { holder[name] = real; };
  return state;
}

// Park until the mint under test has actually reached the seam, rather
// than after a budget somebody guessed at.
function parked(gate, label) {
  return helpers.waitUntil(function () { return gate.parked !== null; }, {
    timeoutMs: PARK_TIMEOUT_MS,
    label:     "dkim-key-mint-window: " + label,
  });
}

// ---------------------------------------------------------------------------
// Readings
// ---------------------------------------------------------------------------

async function refused(fn) {
  try { await fn(); }
  catch (e) { return e; }
  return null;
}

function codeOf(e) {
  return e === null ? "(no refusal)" : ((e && e.code) || "(no code)");
}

function messageOf(e) {
  return e === null ? "(no refusal)" : String((e && e.message) || e).slice(0, 240);
}

function keyPath(keyDir, keyRef) { return nodePath.join(keyDir, keyRef); }

function keysFor(keyDir, domain) {
  var all;
  try { all = nodeFs.readdirSync(keyDir); }
  catch (_e) { return []; }
  return all.filter(function (f) { return f.indexOf(domain + ".") === 0; }).sort();
}

// The public half of a sealed private key, spelled the way the record's
// p= tag spells it: the raw key bytes for Ed25519 per RFC 8463, and the
// whole SubjectPublicKeyInfo for RSA. Read off the file rather than off
// the row, so the two can be held against each other.
//
// Answers null for a key that is not there or will not open, which is
// itself one of the answers a vector asserts on.
function publishedHalfOnDisk(keyDir, keyRef, algorithm) {
  var sealed;
  try { sealed = nodeFs.readFileSync(keyPath(keyDir, keyRef), "utf8"); }
  catch (_e) { return null; }
  var pem;
  try { pem = b.vault.unseal(sealed); }
  catch (_e) { return null; }
  var der;
  try {
    der = nodeCrypto.createPublicKey(pem).export({ type: "spki", format: "der" });
  } catch (_e) { return null; }
  if (algorithm === "ed25519") return der.subarray(der.length - 32).toString("base64");
  return der.toString("base64");
}

// The claim, as a reading. Every selector row the domain publishes whose
// sealed private key is missing, will not open, or opens to a public
// half other than the one that row publishes. A row in this list is a
// record for a signature this server cannot make.
function rowsTheKeysDisagreeWith(identity, keyDir, domain) {
  return identity.domains.listSelectors({ domain: domain })
    .filter(function (row) {
      return publishedHalfOnDisk(keyDir, row.keyRef, row.algorithm) !== row.publicKey;
    })
    .map(function (row) { return row.selector + ":" + row.algorithm; });
}

function activeSelectors(identity, domain) {
  return identity.domains.listSelectors({ domain: domain, status: "active" })
    .map(function (row) { return row.selector + ":" + row.algorithm; }).sort();
}

// Whether the domain can still sign, asked the way the submission path
// asks it. A domain publishing a record for a key that is gone refuses
// here, which is what every message it sends meets.
function canSign(dkim, domain) {
  try { dkim.signerFor(domain); return null; }
  catch (e) { return e; }
}

// A file left in the keys folder under the name a row would point at.
// Written here rather than kept as a fixture: nothing that looks like
// key material belongs in the tree, and what matters about it is only
// that the bytes are recognizable when they are read back.
function plantKeyFile(keyDir, keyRef) {
  var bytes = "a stand-in for the sealed private key a stopped run left behind: " + keyRef;
  nodeFs.mkdirSync(keyDir, { recursive: true });
  nodeFs.writeFileSync(keyPath(keyDir, keyRef), bytes, { mode: 0o600 });
  return bytes;
}

function keyFileBytes(keyDir, keyRef) {
  try { return nodeFs.readFileSync(keyPath(keyDir, keyRef), "utf8"); }
  catch (_e) { return null; }
}

// The Ed25519 half's file name, which is the one both halves of an
// interleaving reach first and so the one a claim has to be taken on.
function eddsaKeyRef(domain, selector) {
  return domain + "." + selector + ".ed25519.sealed";
}

// ---------------------------------------------------------------------------
// Two mints deriving one file name
// ---------------------------------------------------------------------------

// Two mints asked for the same selector at once. Each works out the same
// key file name, and neither can see the other's selector row until it
// lands, so a mint that simply writes its file puts its own private half
// under the name the other's row is about to name. Then, when its own
// row is refused for a selector that is now taken, it takes that file
// back out as it unwinds. The domain is left publishing a record for a
// key nobody holds.
//
// One of the two has to win and one has to be told no. Which one is not
// the claim; the claim is that whichever mint's row is published, the
// key under it is that mint's own key and is still on the volume.
async function twoMintsCannotWriteOverEachOthersKey(identity, cfg, keyDir) {
  var domain = "two-mints.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  // The first selector row this domain writes, held so the second mint
  // runs its whole plan against a domain that still publishes nothing.
  var gate = installCallGate(identity.domains, "addSelector", function (args) {
    return !!args[0] && args[0].domain === domain && args[0].algorithm === "ed25519";
  });

  var firstStopped  = null;
  var firstMinted   = null;
  var secondStopped = null;
  var secondMinted  = null;
  try {
    var first = dkim.generate({ domain: domain, selector: SELECTOR });
    var firstSettled = first.then(
      function (value) { firstMinted = value; },
      function (e) { firstStopped = e; });
    await parked(gate, "the first mint reaching the row for its Ed25519 half");

    try { secondMinted = await dkim.generate({ domain: domain, selector: SELECTOR }); }
    catch (e) { secondStopped = e; }

    await gate.release();
    await firstSettled;
  } finally {
    gate.remove();
  }

  var minted = (firstMinted === null ? 0 : 1) + (secondMinted === null ? 0 : 1);
  count("exactly one of two mints for the same selector reports a pair",
    minted === 1,
    "first: " + (firstMinted === null ? codeOf(firstStopped) : "minted") +
      "; second: " + (secondMinted === null ? codeOf(secondStopped) : "minted"));

  count("and the one that was refused says the key file is already held rather than " +
    "reporting a selector it never got as far as naming",
    codeOf(firstStopped === null ? secondStopped : firstStopped) === KEY_FILE_HELD,
    codeOf(firstStopped === null ? secondStopped : firstStopped) + ": " +
      messageOf(firstStopped === null ? secondStopped : firstStopped));

  count("the domain publishes the whole pair the mint that won wrote",
    activeSelectors(identity, domain).length === 2,
    activeSelectors(identity, domain).join(", ") || "(none)");

  var disagreeing = rowsTheKeysDisagreeWith(identity, keyDir, domain);
  count("and every record it publishes is for a sealed private key that is on this volume " +
    "and holds the public half that record carries",
    disagreeing.length === 0,
    "records the keys disagree with: " + (disagreeing.join(", ") || "(none)") +
      "; keys on the volume: " + (keysFor(keyDir, domain).join(", ") || "(none)"));

  count("so the domain can still sign",
    canSign(dkim, domain) === null, messageOf(canSign(dkim, domain)));
}

// ---------------------------------------------------------------------------
// A key file a stopped run left behind
// ---------------------------------------------------------------------------

// The same claim reached without a second caller. A key file and the row
// naming it are two writes and nothing spans them, so a run that stops
// between them leaves a file under a name no record points at. Nothing
// signs with it and nothing here removes it, and a later mint asked for
// that selector derives the same name.
//
// Writing over it destroys the one copy. Whoever holds a copy signs mail
// as the domain, so the file is refused and named instead, and the ways
// past it are a different selector name or deleting the file.
async function aMintRefusesRatherThanWritingOverALeftoverKey(identity, cfg, keyDir) {
  var domain = "leftover.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  var keyRef  = eddsaKeyRef(domain, SELECTOR);
  var planted = plantKeyFile(keyDir, keyRef);

  var stopped = await refused(function () {
    return dkim.generate({ domain: domain, selector: SELECTOR });
  });

  count("a mint refuses rather than writing over a sealed private key already on the volume",
    codeOf(stopped) === KEY_FILE_HELD, codeOf(stopped) + ": " + messageOf(stopped));
  count("and names the file, because clearing it takes a name",
    stopped !== null && String(stopped.message).indexOf(keyRef) !== -1, messageOf(stopped));
  count("and what was sitting there is exactly as it was",
    keyFileBytes(keyDir, keyRef) === planted,
    JSON.stringify(String(keyFileBytes(keyDir, keyRef)).slice(0, 80)));
  count("and the domain publishes no record, so nothing was half minted",
    identity.domains.listSelectors({ domain: domain }).length === 0,
    activeSelectors(identity, domain).join(", ") || "(none)");

  // The way past it that costs nothing. A name of the operator's own is
  // what the refusal offers first, because it needs no decision about a
  // file whose contents nobody can read.
  var elsewhere = await dkim.generate({ domain: domain, selector: "bpelsewhere" });
  count("and minting under a name of its own still works",
    elsewhere.publish.length === 2 && activeSelectors(identity, domain).length === 2,
    activeSelectors(identity, domain).join(", "));
  count("with the leftover still where it was, named by no record",
    keyFileBytes(keyDir, keyRef) === planted &&
      identity.domains.listSelectors({ domain: domain }).every(function (row) {
        return row.keyRef !== keyRef;
      }),
    keysFor(keyDir, domain).join(", "));
  count("and the domain signs with the pair it did mint",
    canSign(dkim, domain) === null, messageOf(canSign(dkim, domain)));
}

// ---------------------------------------------------------------------------
// The same claim through the other minting verb
// ---------------------------------------------------------------------------

// Rotation mints exactly the way first setup does, so it meets the same
// file name and owes the same refusal. It is the verb where writing over
// a key costs the most: the domain is signing while this runs, and the
// pair it is signing with is what a receiver is checking against right
// now.
async function rotationRefusesOverALeftoverKeyToo(identity, cfg, keyDir) {
  var domain = "rotating.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpcurrent" });

  var signing = activeSelectors(identity, domain);
  count("the domain is signing with the pair it holds", signing.length === 2, signing.join(", "));

  var keyRef  = eddsaKeyRef(domain, "bpnext");
  var planted = plantKeyFile(keyDir, keyRef);

  var stopped = await refused(function () {
    return dkim.rotate({ domain: domain, selector: "bpnext" });
  });
  count("a rotation refuses over a key file that is already there",
    codeOf(stopped) === KEY_FILE_HELD, codeOf(stopped) + ": " + messageOf(stopped));
  count("and the leftover is exactly as it was",
    keyFileBytes(keyDir, keyRef) === planted,
    JSON.stringify(String(keyFileBytes(keyDir, keyRef)).slice(0, 80)));
  count("and the domain is still signing with the pair it was signing with",
    activeSelectors(identity, domain).join(", ") === signing.join(", ") &&
      canSign(dkim, domain) === null,
    activeSelectors(identity, domain).join(", "));
  count("and every record it publishes still holds its own key",
    rowsTheKeysDisagreeWith(identity, keyDir, domain).length === 0,
    rowsTheKeysDisagreeWith(identity, keyDir, domain).join(", ") || "(none)");
}

// ---------------------------------------------------------------------------
// The ordinary path
// ---------------------------------------------------------------------------

// So the refusals above read as a name being held rather than as the
// minting verbs refusing everything they are shown. A domain with an
// empty keys folder mints, and a rotation alongside it mints again.
async function anUncontestedMintStillWritesBothHalves(identity, cfg, keyDir) {
  var domain = "uncontested.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  var minted = await dkim.generate({ domain: domain, selector: "bpalpha" });
  count("an uncontested mint publishes both halves",
    minted.publish.length === 2 && activeSelectors(identity, domain).length === 2,
    activeSelectors(identity, domain).join(", "));
  count("and each of them holds the sealed private key its record names",
    rowsTheKeysDisagreeWith(identity, keyDir, domain).length === 0,
    rowsTheKeysDisagreeWith(identity, keyDir, domain).join(", ") || "(none)");

  var rotated = await dkim.rotate({ domain: domain, selector: "bpbeta" });
  count("and a rotation alongside it mints a second pair, both signing meanwhile",
    rotated.minted.length === 2 && activeSelectors(identity, domain).length === 4,
    activeSelectors(identity, domain).join(", "));
  count("with every one of the four still holding its own key",
    rowsTheKeysDisagreeWith(identity, keyDir, domain).length === 0,
    rowsTheKeysDisagreeWith(identity, keyDir, domain).join(", ") || "(none)");
  count("and the domain signing with them",
    canSign(dkim, domain) === null, messageOf(canSign(dkim, domain)));
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-key-mint-window");
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

    var keyDir = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir })
      .describe().keyDir;

    await twoMintsCannotWriteOverEachOthersKey(identity, cfg, keyDir);
    await aMintRefusesRatherThanWritingOverALeftoverKey(identity, cfg, keyDir);
    await rotationRefusesOverALeftoverKeyToo(identity, cfg, keyDir);
    await anUncontestedMintStillWritesBothHalves(identity, cfg, keyDir);

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
  name:      "dkim-key-mint-window",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// minting verb and a run that drove both otherwise report the same total
// and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + MINTING_VERBS_EXAMINED + " minting-verb");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
