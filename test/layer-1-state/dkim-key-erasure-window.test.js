// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What the two verbs that destroy signing material decide, and when.
 *
 * `blamepost.store.domains.remove` and
 * `blamepost.store.domains.removeSelector` both erase a sealed private
 * key and delete the selector row that named it. The row is the only
 * handle this server has on that file: nothing walks the keys folder,
 * and the code that erases a key reaches it through a row. So the two
 * halves have to leave together, and the order between them is what
 * decides which half survives a stop.
 *
 * The claim every vector here settles is one sentence: no call to either
 * verb ends with a selector row still published whose sealed private key
 * that same call destroyed. A domain in that state signs nothing, every
 * message it sends fails DMARC alignment wherever the policy sends
 * failures, and the record it is still publishing points at a key
 * nobody holds.
 *
 * The way that used to happen is a decision taken before the erasure and
 * acted on after it. Erasing a key is the only suspension either verb
 * has, and a refusal raised on the far side of it is a refusal about a
 * volume that has already changed: the keys are gone, the rows are not,
 * and running the verb again reaches the same refusal for as long as
 * whatever changed stays changed.
 *
 * The last-active-selector refusal is the same fault seen from the other
 * side. It is a statement about the SET of selectors a domain still
 * signs with, not about the one row being withdrawn, so re-reading that
 * row across the window answers a different question: the row is
 * unchanged in both of two concurrent withdrawals, and both proceed.
 *
 * The interleaving is arranged rather than raced. A test that started
 * two withdrawals and hoped they overlapped would reproduce the failure
 * only sometimes, which is the nondeterministic coverage gap and is
 * worse than no test at all. Instead the key eraser is wrapped for the
 * length of each interleaving so that one call parks until this file
 * releases it, and every other call runs the real primitive untouched.
 * Nothing about the code path under test changes: the same store, the
 * same verb, the same key files, in the same order. Only the moment the
 * erasure runs is this file's to choose, which is what makes the
 * ordering a fact rather than a hope.
 *
 * Run standalone: node test/layer-1-state/dkim-key-erasure-window.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var b        = require("../../lib/vendor/blamejs");
var config   = require("../../lib/config");
var store    = require("../../lib/store");
var dkimMod  = require("../../lib/mail/dkim");

var count = helpers.count;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ACCOUNT_PASSWORD = "quiet lantern bicycle 4291";

// How long a parked erasure may wait for the call that is supposed to
// land inside it. Generous, because the work landing there opens the
// vault and writes rows, and a fixed budget is what a loaded runner
// gets wrong.
var PARK_TIMEOUT_MS = 30000;

// The two verbs this file answers for, printed at the end as the unit
// examined. A run that drove one of them and a run that drove both
// otherwise report the same check total and neither says which happened.
var VERBS_EXAMINED = 2;

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

// The key eraser, wrapped so one call parks. Every call whose key set
// this file did not ask for runs the real primitive, so the withdrawal
// that lands inside the window does its own erasure exactly as it would
// in production.
//
// The wrapper stands on the module's exported object, which is the same
// object the identity layer bound at require time, so the verb under
// test reaches it without knowing anything happened.
function installErasureGate(wanted) {
  var real  = dkimMod.eraseKeyFiles;
  var state = { parked: null, calls: 0 };
  dkimMod.eraseKeyFiles = function (dataDir, keyRefs, decide) {
    state.calls += 1;
    var mine = Array.isArray(keyRefs) && keyRefs.some(function (ref) {
      return wanted.indexOf(ref) !== -1;
    });
    if (state.parked !== null || !mine) return real(dataDir, keyRefs, decide);
    return new Promise(function (resolve, reject) {
      state.parked = { args: [dataDir, keyRefs, decide], resolve: resolve, reject: reject };
    });
  };
  state.release = function () {
    var held = state.parked;
    if (held === null) throw new Error("installErasureGate: nothing is parked to release");
    return real.apply(null, held.args).then(held.resolve, held.reject);
  };
  state.remove = function () { dkimMod.eraseKeyFiles = real; };
  return state;
}

// One file the volume will not give up, for the length of one call.
// Matched on the substring rather than on the whole path, because a key
// on its way out may be reached under a name the caller set it aside
// under, and both are the same file refusing to go.
//
// The key erasure reaches for the asynchronous removal, so this is the
// helper that patches that one. Its synchronous sibling exists for the
// blob release and the two are not interchangeable.
var installRemovalFault = helpers.installRemovalFault;

// ---------------------------------------------------------------------------
// Readings
// ---------------------------------------------------------------------------

function keysFor(keyDir, domain) {
  var all;
  try { all = nodeFs.readdirSync(keyDir); }
  catch (_e) { return []; }
  return all.filter(function (f) { return f.indexOf(domain + ".") === 0; }).sort();
}

// The claim, as a reading. Every selector row the domain still publishes,
// held against the sealed private key its keyRef names. A row in this
// list is a published record for a signature this server can no longer
// make.
function rowsNamingAMissingKey(identity, keyDir, domain) {
  return identity.domains.listSelectors({ domain: domain })
    .filter(function (row) {
      return !nodeFs.existsSync(nodePath.join(keyDir, row.keyRef));
    })
    .map(function (row) { return row.selector + ":" + row.algorithm; });
}

function activeSelectors(identity, domain) {
  return identity.domains.listSelectors({ domain: domain, status: "active" })
    .map(function (row) { return row.selector + ":" + row.algorithm; });
}

function keyBytes(keyDir, keyRef) {
  try { return nodeFs.readFileSync(nodePath.join(keyDir, keyRef), "utf8"); }
  catch (_e) { return null; }
}

async function refused(fn) {
  try { await fn(); }
  catch (e) { return e; }
  return null;
}

function codeOf(e) {
  return e === null ? "(no refusal)" : ((e && e.code) || "(no code)");
}

// The two halves a generated pair puts on the volume, in the order the
// removal reads them, so a vector can name one of them without knowing
// which algorithm sorted first.
function pairRefs(identity, domain) {
  return identity.domains.listSelectors({ domain: domain })
    .map(function (row) { return row.keyRef; }).sort();
}

// ---------------------------------------------------------------------------
// domains.remove
// ---------------------------------------------------------------------------

// A volume that gives up one key and holds on to the other. Whatever the
// verb does about the one it could not erase, it may not leave the row
// that names the one it DID erase still published: that row is a record
// for a signature the domain can no longer make, and `dkim generate`
// refuses to mint a replacement while a selector row for the domain is
// still there.
async function aHeldKeyLeavesNoRowNamingAnErasedOne(identity, cfg, keyDir) {
  var domain = "held-key.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpheld" });

  var refs = pairRefs(identity, domain);
  count("the domain publishes two selectors, each naming a sealed private key",
    refs.length === 2 && keysFor(keyDir, domain).length === 2, refs.join(","));

  // The second of the two, so the first is already destroyed by the time
  // the volume refuses. A fault on the first alone would leave nothing
  // erased and the fault would cost nothing, which is not this case.
  var fault = installRemovalFault(refs[1]);
  var removed = null;
  var stopped = null;
  try {
    removed = await identity.domains.remove({
      domain: domain, reason: "moved to another host" });
  } catch (e) {
    stopped = e;
  } finally {
    fault.remove();
  }

  var orphaned = rowsNamingAMissingKey(identity, keyDir, domain);
  count("no selector row is left publishing a record for a key the removal destroyed",
    orphaned.length === 0,
    "left publishing: " + (orphaned.join(", ") || "(none)") +
      "; refusal: " + codeOf(stopped) +
      "; keys on the volume: " + (keysFor(keyDir, domain).join(", ") || "(none)"));

  // The key that would not go is out of the place its row pointed at, so
  // nothing signs with it, and the removal names where it is sitting.
  // Reported rather than raised: the rows have already gone, and a throw
  // would leave the caller unable to tell that the removal it asked for
  // had happened.
  count("the removal reports the key the volume would not give up rather than raising over " +
    "a removal that has already happened",
    stopped === null && removed !== null &&
      removed.keysLeftAside.length === 1 &&
      removed.keysLeftAside[0].indexOf(refs[1]) === 0,
    stopped === null ? JSON.stringify(removed) : codeOf(stopped));

  count("and it is sitting under a name no selector row points at, so nothing signs with it",
    keysFor(keyDir, domain).length === 1 &&
      keysFor(keyDir, domain)[0] !== refs[1] &&
      keysFor(keyDir, domain)[0].indexOf(refs[1]) === 0,
    keysFor(keyDir, domain).join(", ") || "(none)");

  // And a re-run cannot rename another key over it. Whatever is sitting
  // there is signing material, and a rename that overwrote it would
  // destroy the one copy nobody can replace.
  var leftover = keysFor(keyDir, domain)[0];
  await identity.domains.add({ domain: domain });
  await identity.domains.addSelector({
    domain:    domain,
    selector:  "bpheld",
    algorithm: "rsa-sha256",
    publicKey: Buffer.from("a key minted after the domain was re-hosted").toString("base64"),
    keyRef:    refs[1],
  });
  nodeFs.writeFileSync(nodePath.join(keyDir, refs[1]), "sealed stand-in for a fresh mint");
  var blocked = await refused(function () {
    return identity.domains.remove({ domain: domain, reason: "removing it again" });
  });
  count("a removal that would have to rename a key over the one left behind refuses instead",
    codeOf(blocked) === "store/domain-keys-stranded",
    codeOf(blocked) + ": " + (blocked ? String(blocked.message).slice(0, 160) : ""));
  count("so the key left behind is still there, and so is the one that would have gone over it",
    nodeFs.existsSync(nodePath.join(keyDir, leftover)) &&
      nodeFs.existsSync(nodePath.join(keyDir, refs[1])),
    keysFor(keyDir, domain).join(", "));

  // What the operator is told to do about it, which is the part a rerun
  // cannot supply.
  //
  // Every other reason a key will not move is a property of the volume.
  // The file is open, the mode is wrong, the disk is gone: those clear on
  // their own, so "run it again" is the right instruction and the rerun
  // really does reach the key. This reason is not one of
  // those. Two files carry the name, this server cannot tell which one
  // the rows mean, and it refuses rather than renaming one over the
  // other. Nothing about that changes between runs, so a rerun meets the
  // identical guard and answers identically, forever.
  //
  // Telling the operator to rerun is therefore the one instruction that
  // cannot work, and it is the instruction they are given at the moment
  // they most need a real one: a domain that will not come off the
  // volume with signing material on it that nobody can account for.
  count("the refusal does not send the operator back for a rerun that meets the same " +
    "guard, because two files carry the name and no run can choose between them",
    blocked !== null && /again reaches them/.test(String(blocked.message)) === false,
    blocked ? String(blocked.message).slice(0, 500) : "(no refusal)");

  count("and it says what the state actually is, so the operator knows a second file is " +
    "sitting beside the one the rows name",
    blocked !== null && /set aside/i.test(String(blocked.message)),
    blocked ? String(blocked.message).slice(0, 500) : "(no refusal)");

  count("and it still names the key it stopped on, which is the file the operator has to " +
    "go and look at",
    blocked !== null && String(blocked.message).indexOf(refs[1]) !== -1,
    blocked ? String(blocked.message).slice(0, 500) : "(no refusal)");
}

// The same two-file state, reached through the verb that withdraws ONE
// selector rather than the whole domain.
//
// It is a separate refusal in a separate function, and it had no test at
// all. The domain verb prints the key it stopped on; this one printed
// only the reason, so an operator holding it was told a key could not be
// moved and not which file to go and look at. Both then closed by
// promising a rerun that this reason can never satisfy.
async function aStrandedSelectorKeyNamesTheFileAndTheRepair(identity, cfg, keyDir) {
  var domain = "selector-stranded.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpsel" });

  var refs = pairRefs(identity, domain);
  var rows = identity.domains.listSelectors({ domain: domain });
  var target = rows.filter(function (r) { return r.keyRef === refs[0]; })[0];
  var before = activeSelectors(identity, domain).length;

  // Put a file under the staged name by hand, leaving the key itself in
  // place. That is the state an earlier run stopped half way through,
  // and it is the one the eraser refuses to rename over.
  nodeFs.writeFileSync(nodePath.join(keyDir, refs[0] + ".erasing"),
    "a sealed key an earlier run set aside and could not finish moving");

  var blocked = await refused(function () {
    return identity.domains.removeSelector({
      domain:    domain,
      selector:  target.selector,
      algorithm: target.algorithm,
      reason:    "withdrawing an exposed selector",
      immediate: true,
    });
  });

  count("withdrawing a selector whose key is already set aside refuses rather than " +
    "renaming one file over the other",
    codeOf(blocked) === "store/selector-key-stranded",
    codeOf(blocked) + ": " + (blocked ? String(blocked.message).slice(0, 200) : ""));

  count("and the refusal names the key file, which its sibling on the domain verb prints " +
    "and this one did not",
    blocked !== null && String(blocked.message).indexOf(refs[0]) !== -1,
    blocked ? String(blocked.message).slice(0, 500) : "(no refusal)");

  count("and it does not promise a rerun, because the two files are still two files on " +
    "the next run and the guard answers the same",
    blocked !== null && /again reaches it/.test(String(blocked.message)) === false,
    blocked ? String(blocked.message).slice(0, 500) : "(no refusal)");

  count("and nothing was destroyed reaching that refusal: both files are still here and " +
    "the row still names the one it always named",
    nodeFs.existsSync(nodePath.join(keyDir, refs[0])) &&
      nodeFs.existsSync(nodePath.join(keyDir, refs[0] + ".erasing")) &&
      activeSelectors(identity, domain).length === before,
    keysFor(keyDir, domain).join(", ") || "(none)");
}

// The restore that could not be made. A refusal puts the key material
// back where it was, and a volume that will not take it back leaves the
// row published and its key sitting beside the name the row points at.
// Nothing on this server finds it there, so the refusal has to name it.
async function aRestoreTheVolumeRefusesIsNamedInTheRefusal(identity, cfg, keyDir) {
  var domain = "restore-refused.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpstuck" });

  var refs = pairRefs(identity, domain);

  // The rename refused in one direction only: back. Setting the material
  // aside still works, so the decision is reached with it already aside,
  // and the refusal it makes is the one that cannot put it back. The
  // account arrives inside the window rather than before it, because a
  // domain that plainly holds one is refused before a key is touched at
  // all, which is a different path and not this one.
  var realRename = b.atomicFile.renameWithRetry;
  var gate = installErasureGate(refs);
  var stopped;
  try {
    var removal = identity.domains.remove({ domain: domain, reason: "moved to another host" });
    var caught = removal.then(function () { return null; }, function (e) { return e; });
    await helpers.waitUntil(function () { return gate.parked !== null; }, {
      timeoutMs: PARK_TIMEOUT_MS,
      label:     "dkim-key-erasure-window: the removal reaching its key erasure",
    });

    await identity.accounts.create({
      address: "resident@" + domain, password: ACCOUNT_PASSWORD });
    b.atomicFile.renameWithRetry = function (from, to) {
      if (String(to).indexOf(".erasing") === -1 && String(from).indexOf(".erasing") !== -1) {
        var e = new Error("the volume refused to move " + from + " back");
        e.code = "EPERM";
        throw e;
      }
      return realRename.apply(b.atomicFile, arguments);
    };

    await gate.release();
    stopped = await caught;
  } finally {
    b.atomicFile.renameWithRetry = realRename;
    gate.remove();
  }

  count("the removal still refuses for the account on the domain",
    codeOf(stopped) === "store/domain-in-use",
    codeOf(stopped) + ": " + (stopped ? String(stopped.message).slice(0, 120) : ""));

  count("and the refusal names every key it could not put back, so the operator is not left " +
    "to find them",
    stopped !== null && refs.every(function (ref) {
      return String(stopped.message).indexOf(ref + ".erasing") !== -1;
    }),
    stopped ? String(stopped.message).slice(-300) : "(no refusal)");

  count("the material is still on the volume rather than destroyed by a restore that failed",
    keysFor(keyDir, domain).length === 2,
    keysFor(keyDir, domain).join(", ") || "(none)");

  // Put it back the way the refusal tells the operator to, and the
  // domain signs again. A state nobody can finish is the one thing this
  // path may not leave.
  for (var i = 0; i < refs.length; i += 1) {
    nodeFs.renameSync(nodePath.join(keyDir, refs[i] + ".erasing"),
      nodePath.join(keyDir, refs[i]));
  }
  count("and renaming them back by hand, as the refusal says to, leaves the domain signing " +
    "with every selector it publishes",
    rowsNamingAMissingKey(identity, keyDir, domain).length === 0 &&
      activeSelectors(identity, domain).length === 2,
    keysFor(keyDir, domain).join(", "));
}

// An account created on the domain while its keys are being erased. The
// removal refuses for it, correctly, and that refusal has to cost
// nothing: the domain is still hosted, so the keys its records name have
// to still be here or the domain has stopped signing on the strength of
// a change that was refused.
async function anAccountArrivingMidErasureRefusesWithNothingDestroyed(identity, cfg, keyDir) {
  var domain = "late-account.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bplate" });

  var refs   = pairRefs(identity, domain);
  var before = refs.map(function (ref) { return keyBytes(keyDir, ref); });

  var gate = installErasureGate(refs);
  var stopped;
  try {
    var removal = identity.domains.remove({ domain: domain, reason: "moved to another host" });
    var caught = removal.then(function () { return null; }, function (e) { return e; });
    await helpers.waitUntil(function () { return gate.parked !== null; }, {
      timeoutMs: PARK_TIMEOUT_MS,
      label:     "dkim-key-erasure-window: the removal reaching its key erasure",
    });

    await identity.accounts.create({
      address: "arrived@" + domain, password: ACCOUNT_PASSWORD });
    count("an account is created on the domain while its keys are being erased",
      identity.accounts.list({ domain: domain }).length === 1,
      JSON.stringify(activeSelectors(identity, domain)));

    await gate.release();
    stopped = await caught;
  } finally {
    gate.remove();
  }

  count("the removal refuses for the account that arrived", codeOf(stopped) === "store/domain-in-use",
    codeOf(stopped) + ": " + (stopped ? String(stopped.message).slice(0, 160) : ""));

  var orphaned = rowsNamingAMissingKey(identity, keyDir, domain);
  count("and the refusal costs nothing: the domain is still hosted and still holds every " +
    "sealed private key its records name",
    orphaned.length === 0 && identity.domains.get(domain) !== null,
    "left publishing: " + (orphaned.join(", ") || "(none)") +
      "; keys on the volume: " + (keysFor(keyDir, domain).join(", ") || "(none)"));

  var after = refs.map(function (ref) { return keyBytes(keyDir, ref); });
  count("the key material is the same bytes it was, rather than a file put back empty",
    after[0] !== null && after[0] === before[0] && after[1] !== null && after[1] === before[1],
    "before " + before.map(function (v) { return v === null ? 0 : v.length; }).join("/") +
      " bytes, after " + after.map(function (v) { return v === null ? 0 : v.length; }).join("/"));

  // And the domain is removable once the thing in the way has gone,
  // which is what makes the refusal a refusal rather than a state the
  // operator is stuck in.
  await identity.accounts.delete({
    id: identity.accounts.list({ domain: domain })[0].id,
    reason: "clearing the way for the removal that was refused",
    destroy: true,
  });
  var removed = await identity.domains.remove({
    domain: domain, reason: "moved to another host" });
  count("and the removal that was refused completes once the account is gone",
    removed.outcome === "removed" && keysFor(keyDir, domain).length === 0,
    JSON.stringify(removed));
}

// A selector published on the domain while its existing keys are being
// erased. The removal refuses, because deleting every row for the domain
// would drop one whose key is still on the volume, and the refusal has
// to leave the domain exactly as it was.
async function aSelectorArrivingMidErasureRefusesWithNothingDestroyed(identity, cfg, keyDir) {
  var domain = "late-selector.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpearly" });

  var refs   = pairRefs(identity, domain);
  var before = refs.map(function (ref) { return keyBytes(keyDir, ref); });
  var lateRef = domain + ".bplater.ed25519.sealed";

  var gate = installErasureGate(refs);
  var stopped;
  try {
    var removal = identity.domains.remove({ domain: domain, reason: "moved to another host" });
    var caught = removal.then(function () { return null; }, function (e) { return e; });
    await helpers.waitUntil(function () { return gate.parked !== null; }, {
      timeoutMs: PARK_TIMEOUT_MS,
      label:     "dkim-key-erasure-window: the removal reaching its key erasure",
    });

    // The row and the file together, which is what a mint leaves. A row
    // on its own would make the reading below unable to tell a key this
    // removal destroyed from one that was never written.
    nodeFs.writeFileSync(nodePath.join(keyDir, lateRef), "sealed stand-in for a late mint");
    await identity.domains.addSelector({
      domain:    domain,
      selector:  "bplater",
      algorithm: "ed25519",
      publicKey: Buffer.from("a key minted while the removal was running").toString("base64"),
      keyRef:    lateRef,
    });
    count("a selector is published on the domain while its keys are being erased",
      identity.domains.listSelectors({ domain: domain }).length === 3,
      activeSelectors(identity, domain).join(","));

    await gate.release();
    stopped = await caught;
  } finally {
    gate.remove();
  }

  count("the removal refuses for the selector that arrived",
    codeOf(stopped) === "store/domain-selectors-changed",
    codeOf(stopped) + ": " + (stopped ? String(stopped.message).slice(0, 160) : ""));

  var orphaned = rowsNamingAMissingKey(identity, keyDir, domain);
  count("and every selector the domain publishes still has the sealed private key it names",
    orphaned.length === 0,
    "left publishing: " + (orphaned.join(", ") || "(none)") +
      "; keys on the volume: " + (keysFor(keyDir, domain).join(", ") || "(none)"));

  var after = refs.map(function (ref) { return keyBytes(keyDir, ref); });
  count("including the two that were part way through being erased",
    after[0] !== null && after[0] === before[0] && after[1] !== null && after[1] === before[1],
    "before " + before.map(function (v) { return v === null ? 0 : v.length; }).join("/") +
      " bytes, after " + after.map(function (v) { return v === null ? 0 : v.length; }).join("/"));
}

// ---------------------------------------------------------------------------
// domains.removeSelector
// ---------------------------------------------------------------------------

// Two withdrawals, each of one half of the only pair a domain has. Each
// one reads two active selectors and concludes it is not taking the
// last. Both cannot be right, and the domain they would leave signs
// nothing.
async function twoWithdrawalsCannotBothTakeTheLastActiveSelector(identity, cfg, keyDir) {
  var domain = "both-halves.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpboth" });

  var rows = identity.domains.listSelectors({ domain: domain });
  var parkedRow = rows[0];
  var otherRow  = rows[1];
  count("the domain signs with exactly two active selectors, which is one pair",
    activeSelectors(identity, domain).length === 2, activeSelectors(identity, domain).join(","));

  var before = keyBytes(keyDir, parkedRow.keyRef);
  var gate = installErasureGate([parkedRow.keyRef]);
  var stopped;
  try {
    var first = identity.domains.removeSelector({
      domain: domain, selector: parkedRow.selector, algorithm: parkedRow.algorithm,
      reason: "withdrawn by one operator", immediate: true,
    });
    var caught = first.then(function () { return null; }, function (e) { return e; });
    await helpers.waitUntil(function () { return gate.parked !== null; }, {
      timeoutMs: PARK_TIMEOUT_MS,
      label:     "dkim-key-erasure-window: the first withdrawal reaching its key erasure",
    });

    // The second withdrawal runs to completion inside the first one's
    // window. It reads two active selectors, exactly as the first one
    // did, and takes the other half.
    var second = await identity.domains.removeSelector({
      domain: domain, selector: otherRow.selector, algorithm: otherRow.algorithm,
      reason: "withdrawn by another operator", immediate: true,
    });
    count("the second withdrawal completes while the first is still erasing its key",
      second.outcome === "removed", JSON.stringify(second));

    await gate.release();
    stopped = await caught;
  } finally {
    gate.remove();
  }

  count("the first withdrawal is refused rather than taking the domain's last active selector",
    codeOf(stopped) === "store/last-selector",
    codeOf(stopped) + ": " + (stopped ? String(stopped.message).slice(0, 160) : ""));

  count("so the domain still signs with one active selector",
    activeSelectors(identity, domain).length === 1, activeSelectors(identity, domain).join(",") ||
      "(none)");

  var orphaned = rowsNamingAMissingKey(identity, keyDir, domain);
  count("and the selector it still publishes still has the sealed private key it names",
    orphaned.length === 0 && keyBytes(keyDir, parkedRow.keyRef) === before,
    "left publishing: " + (orphaned.join(", ") || "(none)") +
      "; keys on the volume: " + (keysFor(keyDir, domain).join(", ") || "(none)"));
}

// The same rule reached the other way. Nothing is withdrawn alongside;
// the sibling is simply moved out of signing while this key is being
// erased, which takes the active count down by one without any row this
// call is looking at changing at all.
async function aSiblingRetiredMidErasureStillLeavesTheDomainSigning(identity, cfg, keyDir) {
  var domain = "sibling-retired.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpsibling" });

  var rows = identity.domains.listSelectors({ domain: domain });
  var parkedRow = rows[0];
  var otherRow  = rows[1];
  var before = keyBytes(keyDir, parkedRow.keyRef);

  var gate = installErasureGate([parkedRow.keyRef]);
  var stopped;
  try {
    var withdrawal = identity.domains.removeSelector({
      domain: domain, selector: parkedRow.selector, algorithm: parkedRow.algorithm,
      reason: "withdrawn while the pair was still signing", immediate: true,
    });
    var caught = withdrawal.then(function () { return null; }, function (e) { return e; });
    await helpers.waitUntil(function () { return gate.parked !== null; }, {
      timeoutMs: PARK_TIMEOUT_MS,
      label:     "dkim-key-erasure-window: the withdrawal reaching its key erasure",
    });

    await identity.domains.retireSelector({
      domain: domain, selector: otherRow.selector, algorithm: otherRow.algorithm });
    count("the other half is moved out of signing while this key is being erased",
      activeSelectors(identity, domain).length === 1, activeSelectors(identity, domain).join(","));

    await gate.release();
    stopped = await caught;
  } finally {
    gate.remove();
  }

  count("the withdrawal is refused, because the selector it was taking is now the last one " +
    "the domain signs with",
    codeOf(stopped) === "store/last-selector",
    codeOf(stopped) + ": " + (stopped ? String(stopped.message).slice(0, 160) : ""));

  count("the domain still signs with the selector that was left",
    activeSelectors(identity, domain).length === 1, activeSelectors(identity, domain).join(",") ||
      "(none)");

  var orphaned = rowsNamingAMissingKey(identity, keyDir, domain);
  count("and its sealed private key is the one it always had",
    orphaned.length === 0 && keyBytes(keyDir, parkedRow.keyRef) === before,
    "left publishing: " + (orphaned.join(", ") || "(none)") +
      "; keys on the volume: " + (keysFor(keyDir, domain).join(", ") || "(none)"));
}

// The row itself withdrawn by another caller across the window. This one
// already refused before the window was closed, and it stays refused:
// the checks this call made were against a row that is no longer there,
// and no row was deleted here.
async function aRowWithdrawnUnderneathRefusesWithoutDeletingAnything(identity, cfg, keyDir) {
  var domain = "row-withdrawn.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpfirst" });
  await dkim.rotate({ domain: domain, selector: "bpsecond" });
  count("the domain is part way through a rotation, with four active selectors",
    activeSelectors(identity, domain).length === 4, activeSelectors(identity, domain).join(","));

  var target = identity.domains.listSelectors({ domain: domain })[0];
  var gate = installErasureGate([target.keyRef]);
  var stopped;
  try {
    var first = identity.domains.removeSelector({
      domain: domain, selector: target.selector, algorithm: target.algorithm,
      reason: "withdrawn by one operator", immediate: true,
    });
    var caught = first.then(function () { return null; }, function (e) { return e; });
    await helpers.waitUntil(function () { return gate.parked !== null; }, {
      timeoutMs: PARK_TIMEOUT_MS,
      label:     "dkim-key-erasure-window: the withdrawal reaching its key erasure",
    });

    var second = await identity.domains.removeSelector({
      domain: domain, selector: target.selector, algorithm: target.algorithm,
      reason: "withdrawn by another operator", immediate: true,
    });
    count("another caller withdraws the same selector inside the window",
      second.outcome === "removed", JSON.stringify(second));

    await gate.release();
    stopped = await caught;
  } finally {
    gate.remove();
  }

  count("the first withdrawal reports that the row moved rather than reporting a deletion " +
    "it did not make",
    codeOf(stopped) === "store/selector-moved",
    codeOf(stopped) + ": " + (stopped ? String(stopped.message).slice(0, 160) : ""));

  count("the domain is left with the three selectors the second withdrawal did not take",
    activeSelectors(identity, domain).length === 3, activeSelectors(identity, domain).join(","));

  var orphaned = rowsNamingAMissingKey(identity, keyDir, domain);
  count("and every one of them still has the sealed private key it names",
    orphaned.length === 0, orphaned.join(", ") || "(none)");
}

// The ordinary path, so the vectors above are read as the window closing
// rather than as the verb refusing everything. A domain part way through
// a rotation has four active selectors, so withdrawing one is not
// refused, and the key goes with the row.
async function anUncontestedWithdrawalStillTakesTheKeyWithTheRow(identity, cfg, keyDir) {
  var domain = "uncontested.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpalpha" });
  await dkim.rotate({ domain: domain, selector: "bpbeta" });

  var target = identity.domains.listSelectors({ domain: domain })[0];
  var withdrawn = await identity.domains.removeSelector({
    domain: domain, selector: target.selector, algorithm: target.algorithm,
    reason: "the replacement pair is already signing", immediate: true,
  });

  count("an uncontested withdrawal takes the row", withdrawn.outcome === "removed" &&
    activeSelectors(identity, domain).length === 3, JSON.stringify(withdrawn));
  count("and the sealed private key it named goes with it",
    keysFor(keyDir, domain).indexOf(target.keyRef) === -1,
    keysFor(keyDir, domain).join(","));
  count("and nothing that is left publishes a record for a key that is gone",
    rowsNamingAMissingKey(identity, keyDir, domain).length === 0,
    rowsNamingAMissingKey(identity, keyDir, domain).join(", ") || "(none)");
}

// ---------------------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-key-erasure-window");
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

    await aHeldKeyLeavesNoRowNamingAnErasedOne(identity, cfg, keyDir);
    await aStrandedSelectorKeyNamesTheFileAndTheRepair(identity, cfg, keyDir);
    await aRestoreTheVolumeRefusesIsNamedInTheRefusal(identity, cfg, keyDir);
    await anAccountArrivingMidErasureRefusesWithNothingDestroyed(identity, cfg, keyDir);
    await aSelectorArrivingMidErasureRefusesWithNothingDestroyed(identity, cfg, keyDir);
    await twoWithdrawalsCannotBothTakeTheLastActiveSelector(identity, cfg, keyDir);
    await aSiblingRetiredMidErasureStillLeavesTheDomainSigning(identity, cfg, keyDir);
    await aRowWithdrawnUnderneathRefusesWithoutDeletingAnything(identity, cfg, keyDir);
    await anUncontestedWithdrawalStillTakesTheKeyWithTheRow(identity, cfg, keyDir);

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
  name:      "dkim-key-erasure-window",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout. The
// line beside it names what was examined, because a run that drove one
// destructive verb and a run that drove both otherwise report the same
// total and neither says which happened.
if (require.main === module) {
  run().then(function (total) {
    console.log("EXAMINED " + VERBS_EXAMINED + " destructive-selector-verb");
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
