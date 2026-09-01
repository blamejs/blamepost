// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The two refusals that stand between an operator and a domain holding
 * half a DKIM pair.
 *
 * Every domain this server signs for holds two selectors, one Ed25519
 * and one RSA, and it signs with both or with neither. A domain that
 * ends up holding one of them signs nothing at all: the signer refuses
 * rather than sending under a single algorithm, and the way back out
 * costs a signing gap, because minting refuses while a selector is
 * still active and rotating refuses with no whole pair to rotate away
 * from. So the verbs that mint and the verb that retires each carry a
 * refusal whose whole job is to keep that state from being reached, and
 * neither of them had a vector.
 *
 * They sit at opposite ends of the same change and the difference is
 * what an operator has to do next.
 *
 * The first refuses BEFORE anything is written. Both halves of a pair
 * are named before either is minted, and the two names go into one
 * zone: `<selector>._domainkey.<domain>` is a name, not a row, so two
 * keys published under one name are two records at one name and a
 * receiver checking a signature gets whichever of the two it happens to
 * pick. Half the mail signed by that domain then fails to verify, at a
 * receiver whose DMARC policy decides what that costs. Nothing has been
 * changed when this refuses, and the operator picks another name.
 *
 * The names are compared as the store will record them, which is the
 * part a test that passed one string twice would not reach. A selector
 * is folded before it is stored, because a name in the zone is
 * case-insensitive, so two spellings of one name are one selector and
 * the collision is the same collision. The vector below therefore hands
 * in two spellings rather than one string.
 *
 * The second refuses AFTER the rows have moved, and it cannot do
 * anything else. Retirement stops the pair signing first, on purpose, so
 * a retiring selector keeps its record published while mail signed under
 * it is still being retried, and only then are the private keys erased
 * because nothing will ever sign with them again. A key the volume will
 * not give up at that point is key material for a domain, still on disk
 * and in every backup taken afterwards, that no row will ever name
 * again: nothing walks the keys folder in normal operation, so if this
 * refusal did not name the file, nothing else would ever mention it.
 * Whoever holds that key can sign mail as the domain, which is the whole
 * of what a DKIM signature asserts, and it stays true after the domain
 * is hosted somewhere else.
 *
 * Both vectors are paired with the uncontested form of the same call, so
 * a refusal reported here reads as this server refusing the thing it
 * refuses rather than as the verb being broken.
 *
 * Real vault, real encrypted database, real sealed key files in a
 * temporary data directory. No sockets.
 *
 * Run standalone: node test/layer-1-state/dkim-pair-refusal.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var dkimMod = require("../../lib/mail/dkim");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// The two refusals this file examines, printed at the end as the unit
// examined. A run that drove one of them and a run that drove both
// otherwise report the same check total and neither says which happened.
var PAIR_REFUSALS_EXAMINED = 2;

// Frozen contracts. A surface reads each of these to decide what to show
// and what to do next, so they survive every rename of the function that
// raises them and disappear only if the refusal itself is deleted.
var SELECTOR_NAME_COLLISION = "dkim/selector-name-collision";
var KEYS_STRANDED           = "dkim/keys-stranded";
var NO_ACTIVE_SELECTOR      = "dkim/no-active-selector";

// The row a retirement files. Its outcome is the reading that separates
// a retirement which refused with the domain as it was from one that
// moved the rows and could not finish, and only the second needs
// somebody to go and look.
var KEYS_RETIRED = "blamepost.mail.dkim.keys_retired";

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
  return e === null ? "(no refusal)" : String((e && e.message) || e).slice(0, 300);
}

// The sealed private key file a selector row points at, named the way
// the module names it: the domain, the selector and the algorithm.
// Derived here rather than read off a row, because half of what these
// vectors assert is what is on the volume when there is no row left to
// ask.
function keyRefFor(domain, selector, algorithm) {
  return domain + "." + selector + "." + algorithm + ".sealed";
}

function keysFor(keyDir, domain) {
  var all;
  try { all = nodeFs.readdirSync(keyDir); }
  catch (_e) { return []; }
  return all.filter(function (f) { return f.indexOf(domain + ".") === 0; }).sort();
}

function selectorsOf(identity, domain, status) {
  var criteria = { domain: domain };
  if (status) criteria.status = status;
  return identity.domains.listSelectors(criteria)
    .map(function (row) { return row.selector + ":" + row.algorithm; }).sort();
}

// Whether the domain can still sign, asked the way the submission path
// asks it. A domain left holding one algorithm refuses here, which is
// what every message it sends would meet.
function signingRefusal(dkim, domain) {
  try { dkim.signerFor(domain); return null; }
  catch (e) { return e; }
}

function _asRows(value) { return Array.isArray(value) ? value : []; }

// The rows one action filed about one domain. A row names its resource
// by the store's own identifier rather than by the domain name, so the
// name is resolved to that identifier here: filtering on the name would
// match nothing and read as a trail that was never written.
async function rowsFor(identity, action, domain) {
  await b.audit.flush();
  var row = identity.domains.get(domain);
  var id = row === null ? null : String(row.id);
  var rows = _asRows(await b.audit.query({ action: action, order: "desc", limit: 100 }));
  return rows.filter(function (r) { return id !== null && String(r.resourceId) === id; });
}

// ---------------------------------------------------------------------------
// Two names that are one name
// ---------------------------------------------------------------------------

// A first mint asked for the same selector for both halves, in two
// spellings. The store folds a selector before it records it, because a
// name in the zone is case-insensitive, so these are one name and
// publishing both keys under it puts two records where a receiver
// expects one.
//
// Nothing has been written when this refuses, and that is the half of
// the claim worth asserting: the plan settles both names before the
// first key file is sealed, so the domain is exactly as it was.
async function aMintNamingOneSelectorTwiceIsRefusedWithNothingWritten(identity, cfg, keyDir) {
  var domain = "one-name.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  var collided = await refused(function () {
    return dkim.generate({ domain: domain, selector: "BPONE", rsaSelector: "bpone" });
  });

  count("a mint naming one selector for both halves is refused",
    collided !== null, collided === null ? "minted a pair under one name" : "refused");
  count("and the refusal carries the code a surface branches on",
    codeOf(collided) === SELECTOR_NAME_COLLISION,
    codeOf(collided) + ": " + messageOf(collided));
  count("even though the two spellings differ, because a selector is folded before it is " +
    "recorded and a zone name is not case-sensitive either",
  collided !== null && /both '?bpone/i.test(messageOf(collided)),
  messageOf(collided));
  count("the refusal names the zone entry that would carry two records, which is where the " +
    "receiver picking one of them is looking",
  collided !== null && messageOf(collided).indexOf("bpone._domainkey." + domain) !== -1,
  messageOf(collided));

  count("nothing was written: the domain publishes no selector",
    selectorsOf(identity, domain).length === 0,
    selectorsOf(identity, domain).join(", ") || "(none)");
  count("and no sealed private key was left on the volume under either name",
    keysFor(keyDir, domain).length === 0,
    keysFor(keyDir, domain).join(", ") || "(none)");
}

// The same plan on the other verb that mints. `generate` and `rotate`
// settle their names through one path, so a refusal proved on one of
// them says nothing about the other unless the other is driven too: a
// rotation is the mint that runs against a domain already signing, and
// it is the one where a collision would land on live records.
async function aRotationNamingOneSelectorTwiceIsRefusedToo(identity, cfg, keyDir) {
  var domain = "one-name-rotation.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  await dkim.generate({ domain: domain, selector: "bpfirst" });
  var before = selectorsOf(identity, domain, "active");
  var keysBefore = keysFor(keyDir, domain);
  count("the domain signs with a whole pair before the rotation is asked for",
    before.length === 2, before.join(", ") || "(none)");

  var collided = await refused(function () {
    return dkim.rotate({ domain: domain, selector: "bpnext", rsaSelector: "BPNEXT" });
  });

  count("a rotation naming one selector for both halves is refused as well",
    codeOf(collided) === SELECTOR_NAME_COLLISION,
    codeOf(collided) + ": " + messageOf(collided));
  count("the live pair is untouched, so the domain is still signing with what it had",
    selectorsOf(identity, domain, "active").join(", ") === before.join(", "),
    selectorsOf(identity, domain, "active").join(", ") || "(none)");
  count("and no third key file was sealed beside the two it already holds",
    keysFor(keyDir, domain).join(", ") === keysBefore.join(", "),
    keysFor(keyDir, domain).join(", ") || "(none)");
  count("so the domain can still sign", signingRefusal(dkim, domain) === null,
    messageOf(signingRefusal(dkim, domain)));
}

// The uncontested form of the same call, so the two refusals above read
// as this server refusing one name for two keys rather than as minting
// being broken.
async function twoNamesStillMintAPair(identity, cfg, keyDir) {
  var domain = "two-names.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  var minted = await refused(function () {
    return dkim.generate({ domain: domain, selector: "bpalpha", rsaSelector: "bpbeta" });
  });
  count("two names of their own mint the pair", minted === null, messageOf(minted));
  count("and both halves are published", selectorsOf(identity, domain, "active").length === 2,
    selectorsOf(identity, domain, "active").join(", ") || "(none)");
  count("with a sealed private key on the volume for each",
    keysFor(keyDir, domain).length === 2,
    keysFor(keyDir, domain).join(", ") || "(none)");
}

// ---------------------------------------------------------------------------
// A key the volume will not give up, after the rows have moved
// ---------------------------------------------------------------------------

// Retirement moves the rows out of signing first and erases the private
// keys second. This is the volume refusing to erase one of them once
// that is already done.
//
// It cannot be undone and must not be reported as ordinary. The pair has
// stopped signing, one sealed private key is still on the volume, and
// no row will ever name it again, so this refusal is the only thing that
// will ever mention the file. The claim is that it says which file, and
// that the trail records the run as a failure rather than as a refusal:
// the two leave the volume in different states and only this one needs
// somebody to go and look.
async function aKeyTheVolumeKeepsIsNamedAfterThePairStopsSigning(identity, cfg, keyDir) {
  var domain = "stranded-key.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  await dkim.generate({ domain: domain, selector: "bpgoing", rsaSelector: "bpgoingrsa" });
  var held = keyRefFor(domain, "bpgoing", "ed25519");
  var partner = keyRefFor(domain, "bpgoingrsa", "rsa-sha256");
  count("the domain holds a whole pair, one sealed key per half",
    keysFor(keyDir, domain).join(", ") === [held, partner].sort().join(", "),
    keysFor(keyDir, domain).join(", ") || "(none)");

  // One file the volume will not give up, and only that one. The other
  // half erases normally, which is what makes the answer "one key is
  // stranded" rather than "the erasure did not run".
  var fault = helpers.installRemovalFault(held);
  var stranded;
  try {
    stranded = await refused(function () {
      return dkim.retire({ domain: domain, selector: "bpgoing", rsaSelector: "bpgoingrsa" });
    });
  } finally {
    fault.remove();
  }

  count("the retirement refuses rather than reporting a retirement that finished",
    stranded !== null, stranded === null ? "reported success" : "refused");
  count("and the refusal carries the code a surface branches on",
    codeOf(stranded) === KEYS_STRANDED, codeOf(stranded) + ": " + messageOf(stranded));
  count("it names the sealed private key that is still on the volume, because no row will " +
    "ever name it again",
  stranded !== null && messageOf(stranded).indexOf(held) !== -1, messageOf(stranded));
  count("and it names the selectors the domain has stopped signing with, so the refusal " +
    "describes the state the volume is actually in",
  stranded !== null && messageOf(stranded).indexOf("bpgoing") !== -1, messageOf(stranded));

  count("the volume did keep that key, which is what the refusal said",
    nodeFs.existsSync(nodePath.join(keyDir, held)),
    keysFor(keyDir, domain).join(", ") || "(none)");
  count("while the half the volume did give up is gone, so this is one key stranded rather " +
    "than an erasure that never ran",
  !nodeFs.existsSync(nodePath.join(keyDir, partner)),
  keysFor(keyDir, domain).join(", ") || "(none)");

  count("the pair has stopped signing, which is what happens before the erasure and is not " +
    "put back by the refusal",
  selectorsOf(identity, domain, "active").length === 0,
  selectorsOf(identity, domain, "active").join(", ") || "(none)");
  count("so the domain signs nothing, and the signer says so rather than signing under one " +
    "algorithm",
  codeOf(signingRefusal(dkim, domain)) === NO_ACTIVE_SELECTOR,
  codeOf(signingRefusal(dkim, domain)) + ": " + messageOf(signingRefusal(dkim, domain)));

  var rows = await rowsFor(identity, KEYS_RETIRED, domain);
  count("the trail carries the attempt", rows.length >= 1,
    JSON.stringify(rows.map(function (r) { return r.outcome; })));
  count("recorded as a failure rather than as a refusal, because the rows moved and a key " +
    "was left behind",
  rows.length >= 1 && rows[0].outcome === "failure",
  JSON.stringify(rows.map(function (r) { return r.outcome; })));
}

// The uncontested form, so the vector above reads as the volume refusing
// rather than as retirement never erasing anything.
async function anUncontestedRetirementErasesBothKeys(identity, cfg, keyDir) {
  var domain = "clean-retire.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });

  await dkim.generate({ domain: domain, selector: "bpclean", rsaSelector: "bpcleanrsa" });
  count("the domain holds a whole pair before it is retired",
    keysFor(keyDir, domain).length === 2, keysFor(keyDir, domain).join(", ") || "(none)");

  var stopped = await refused(function () {
    return dkim.retire({ domain: domain, selector: "bpclean", rsaSelector: "bpcleanrsa" });
  });
  count("an uncontested retirement raises nothing", stopped === null, messageOf(stopped));
  count("and both sealed private keys are off the volume, because nothing signs with them " +
    "again",
  keysFor(keyDir, domain).length === 0, keysFor(keyDir, domain).join(", ") || "(none)");
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-pair-refusal");
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

    await aMintNamingOneSelectorTwiceIsRefusedWithNothingWritten(identity, cfg, keyDir);
    await aRotationNamingOneSelectorTwiceIsRefusedToo(identity, cfg, keyDir);
    await twoNamesStillMintAPair(identity, cfg, keyDir);

    await aKeyTheVolumeKeepsIsNamedAfterThePairStopsSigning(identity, cfg, keyDir);
    await anUncontestedRetirementErasesBothKeys(identity, cfg, keyDir);

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
  name:      "dkim-pair-refusal",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// refusal and a run that drove both otherwise report the same total and
// neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + PAIR_REFUSALS_EXAMINED + " pair-refusal");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
