// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * What a refused DKIM operation leaves behind.
 *
 * Minting a key pair touches two places: a sealed private key file
 * under the data directory's keys folder, and a selector row in the
 * store. Neither is any use without the other. A key file nothing
 * points at is private key material that is never signed with, never
 * rotated, never erased when the selector is retired, and still there
 * after the domain is removed. A selector row whose key file is gone
 * is a published record for a signature the server can no longer make.
 *
 * Both halves are settled here the only way a DKIM claim can be
 * settled: by signing a message and verifying it against the records
 * this server tells the operator to publish. A record that has drifted
 * from its key is invisible from the sending side, so comparing the
 * two strings is not the same as checking that mail still verifies.
 *
 * Run standalone: node test/layer-1-state/dkim-key-lifecycle.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers  = require("../helpers");
var zone     = require("../helpers/dns-zone");
var config   = require("../../lib/config");
var store    = require("../../lib/store");
var dkimMod  = require("../../lib/mail/dkim");

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// A domain and a selector that are each perfectly legal on their own.
// The selector is one DNS label inside the 63 octets RFC 1035 §2.3.1
// allows and inside the 64 the framework's minting shape allows; the
// domain is an ordinary hosted name. Together they name a key file
// longer than the store records, which is the only thing wrong with
// the pair and the reason it belongs here.
var LONG_DOMAIN   = "newsletters.marketing.department.example-company.example.com";
var LONG_SELECTOR = "bp-quarterly-newsletter-signing-key-rotation-2026-selector";

// The assertion that quotes the value that produced the verdict. It is
// the shared one rather than a copy, because a private wrapper that
// formats a failure differently is a failure line nobody can grep for.
var count = helpers.count;

function keysFor(keyDir, domain) {
  var all;
  try { all = nodeFs.readdirSync(keyDir); }
  catch (_e) { return []; }
  return all.filter(function (f) { return f.indexOf(domain + ".") === 0; }).sort();
}

async function refused(fn) {
  try { await fn(); }
  catch (e) { return e; }
  return null;
}

// ---- a refusal writes nothing -----------------------------------------------

// The selector and the domain are both inside their own limits and the
// name built from them is not. Whatever refuses it has to refuse before
// a private key exists on disk, because nothing afterwards will ever
// look at that file again.
async function aRefusedMintLeavesNoKeyMaterial(dkim, identity, keyDir) {
  await identity.domains.add({ domain: LONG_DOMAIN });

  var keyRef = LONG_DOMAIN + "." + LONG_SELECTOR + ".ed25519.sealed";
  count("the key file name this pair would need is over the 128 characters the store records",
    keyRef.length > 128, keyRef.length + " characters");

  var before = keysFor(keyDir, LONG_DOMAIN);
  var err = await refused(function () {
    return dkim.generate({ domain: LONG_DOMAIN, selector: LONG_SELECTOR });
  });

  count("minting a pair whose key file name is too long is refused",
    err !== null, err ? "refused" : "accepted");
  count("and the refusal says which flag shortens it",
    err !== null && /--selector/.test(err.message),
    err ? err.message.slice(0, 200) : "");
  count("no sealed private key is left behind by the refusal",
    keysFor(keyDir, LONG_DOMAIN).join(",") === before.join(","),
    keysFor(keyDir, LONG_DOMAIN).join(",") || "(none)");
  count("and no selector row was recorded either",
    identity.domains.listSelectors({ domain: LONG_DOMAIN }).length === 0,
    String(identity.domains.listSelectors({ domain: LONG_DOMAIN }).length));
}

// ---- what is undone when the second half fails anyway -----------------------

// Everything a mint can work out in advance is settled before a key
// exists, so recording the second half should not be able to fail.
// Should not is not the same as cannot: a full disk or a database fault
// lands in the same place, and the pair has to come apart cleanly or the
// domain is left in a state no command can get it out of.
//
// The store is wrapped rather than faked, so every check below the
// injected fault is the real one: the real vault seals the key, the real
// database records the first row, and the real refusal has to take both
// back out. Undoing the first row is the part worth driving, because
// dropping a selector is refused while it is the domain's last active
// one, which a half-finished first mint always leaves it as.
async function aFaultRecordingTheSecondHalfTakesTheFirstBackOut(identity, cfg, keyDir) {
  var domain = "half-mint.example.com";
  await identity.domains.add({ domain: domain });

  var calls = 0;
  var wrapped = Object.create(identity);
  wrapped.domains = Object.create(identity.domains);
  wrapped.domains.addSelector = function (addOpts) {
    calls += 1;
    if (calls === 2) return Promise.reject(new Error("the database is unavailable"));
    return identity.domains.addSelector(addOpts);
  };

  var faulty = dkimMod.create({ store: wrapped, dataDir: cfg.paths.dataDir });
  var err = await refused(function () {
    return faulty.generate({ domain: domain, selector: "bphalf" });
  });

  count("a fault recording the second half fails the whole mint",
    err !== null, err ? "refused" : "accepted");
  count("and the failure that caused it is the one reported",
    err !== null && /database is unavailable/.test(err.message), err ? err.message.slice(0, 200) : "");
  count("the first half's sealed key is erased rather than left pointing at nothing",
    keysFor(keyDir, domain).length === 0, keysFor(keyDir, domain).join(",") || "(none)");
  count("and its selector row goes with it, even though it was the only active one",
    identity.domains.listSelectors({ domain: domain }).length === 0,
    identity.domains.listSelectors({ domain: domain })
      .map(function (s) { return s.selector + ":" + s.status; }).join(",") || "(none)");

  // The domain is back where it started, so the operator's next attempt
  // is an ordinary first mint rather than a state with no way out.
  var again = await refused(function () {
    return dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir })
      .generate({ domain: domain, selector: "bphalf" });
  });
  count("so minting again onto the same name works",
    again === null, again ? again.message.slice(0, 160) : "minted");
}

// ---- a refusal says which name is in the way --------------------------------

// Rotation mints a second pair alongside the one already signing, so
// both selector names have to be free. When the RSA half is the one
// that collides, a refusal naming the Ed25519 half sends the operator
// to change the flag that was never the problem, and the next attempt
// stops at the same place.
async function aRefusedRotationNamesTheSelectorInTheWay(dkim, identity, keyDir) {
  var domain = "partner-clash.example.com";
  await identity.domains.add({ domain: domain });
  await dkim.generate({ domain: domain, selector: "bpspring", rsaSelector: "bpspringrsa" });

  var published = dkim.dnsRecords(domain);
  var before = keysFor(keyDir, domain);
  var rowsBefore = dkim.list(domain).map(function (s) { return s.selector + ":" + s.state; }).sort().join(",");

  var err = await refused(function () {
    return dkim.rotate({ domain: domain, selector: "bpsummer", rsaSelector: "bpspringrsa" });
  });
  count("rotating onto an RSA selector already in use is refused",
    err !== null, err ? "refused" : "accepted");
  count("and the refusal names the selector that is actually taken",
    err !== null && /bpspringrsa/.test(err.message), err ? err.message.slice(0, 200) : "");
  count("rather than the one that was free",
    err !== null && !/bpsummer'/.test(err.message), err ? err.message.slice(0, 200) : "");

  count("the refusal leaves the key files exactly as they were",
    keysFor(keyDir, domain).join(",") === before.join(","),
    keysFor(keyDir, domain).join(","));
  count("and leaves the selector rows exactly as they were",
    dkim.list(domain).map(function (s) { return s.selector + ":" + s.state; }).sort().join(",") === rowsBefore,
    dkim.list(domain).map(function (s) { return s.selector + ":" + s.state; }).sort().join(","));

  // The assertion that matters to a receiver: the private keys still on
  // disk are still the ones the published records name.
  var signed = dkim.signerFor(domain).sign(zone.messageFrom(domain, "after-refused-rotation"));
  var results = await zone.verifyAgainst(signed, published);
  count("mail signed after the refusal still verifies against the records already published",
    zone.allPass(results), zone.summarize(results));
}

// First keys for a domain checks that nothing is signing yet, which is
// a different question from whether the name is free. A domain whose
// only pair is retiring has no active selector and still publishes the
// retiring records, so minting onto one of those names collides in the
// store, after the key file has been written.
async function mintingOntoARetiringSelectorNameIsRefusedFirst(dkim, identity, keyDir) {
  var domain = "retiring-name.example.com";
  await identity.domains.add({ domain: domain });
  await dkim.generate({ domain: domain, selector: "bpolder" });
  await dkim.rotate({ domain: domain, selector: "bpnewer" });
  await dkim.retire({ domain: domain, selector: "bpolder" });
  await dkim.retire({ domain: domain, selector: "bpnewer" });

  count("the domain now has no active selector and still publishes its retiring ones",
    dkim.list(domain).every(function (s) { return s.state !== "active"; }) &&
      dkim.dnsRecords(domain).length === 4,
    dkim.list(domain).map(function (s) { return s.selector + ":" + s.state; }).join(","));

  var before = keysFor(keyDir, domain);
  var err = await refused(function () {
    return dkim.generate({ domain: domain, selector: "bpolder" });
  });
  count("minting onto a selector name still published is refused",
    err !== null, err ? "refused" : "accepted");
  count("and the refusal names it",
    err !== null && /bpolder/.test(err.message), err ? err.message.slice(0, 200) : "");
  count("no sealed key is written under a name the store will not record",
    keysFor(keyDir, domain).join(",") === before.join(","),
    keysFor(keyDir, domain).join(",") || "(none)");
}

// A selector name differing only in case is the same selector: the
// store folds it, and on a filesystem that folds names it is the same
// key file too. Deciding that after the key is written means the write
// has already landed on top of the live one.
async function aCaseFoldedSelectorIsRefusedBeforeAnythingIsWritten(dkim, identity, keyDir) {
  var domain = "case-fold.example.com";
  await identity.domains.add({ domain: domain });
  await dkim.generate({ domain: domain, selector: "bpautumn" });

  var published = dkim.dnsRecords(domain);
  var before = keysFor(keyDir, domain);

  var err = await refused(function () {
    return dkim.rotate({ domain: domain, selector: "BPAUTUMN" });
  });
  count("a selector differing from a published one only in case is refused",
    err !== null, err ? "refused" : "accepted");
  count("no extra key file appears under the unfolded name",
    keysFor(keyDir, domain).join(",") === before.join(","),
    keysFor(keyDir, domain).join(","));

  var signed = dkim.signerFor(domain).sign(zone.messageFrom(domain, "after-case-clash"));
  var results = await zone.verifyAgainst(signed, published);
  count("and the live key still matches the record published under the folded name",
    zone.allPass(results), zone.summarize(results));
}

// ---- retiring names both halves, or does nothing ----------------------------

// A domain part way through a rotation has two pairs and the store
// records no link between the two halves of one, so retiring works from
// the names the operator gives it. When the RSA name is not the default
// and the operator does not supply it, the answer has to be a refusal
// that changed nothing: the alternative erases one private key, leaves
// the other pair half published, and takes the domain out of signing
// altogether with no way back through the command line.
async function retiringWithoutTheRsaPartnerChangesNothing(dkim, identity, keyDir) {
  var domain = "retire-partner.example.com";
  await identity.domains.add({ domain: domain });
  await dkim.generate({ domain: domain, selector: "bpwinter", rsaSelector: "bpwinterrsa" });

  var published = dkim.dnsRecords(domain);
  var before = keysFor(keyDir, domain);
  var rowsBefore = dkim.list(domain).map(function (s) { return s.selector + ":" + s.state; }).sort().join(",");

  var err = await refused(function () {
    return dkim.retire({ domain: domain, selector: "bpwinter" });
  });
  count("retiring a pair whose RSA half is not named is refused",
    err !== null, err ? "refused" : "accepted");
  count("and the refusal names the option that supplies it",
    err !== null && /rsaSelector/.test(err.message), err ? err.message.slice(0, 220) : "");
  count("and it lists the RSA selectors the domain actually has",
    err !== null && /bpwinterrsa/.test(err.message), err ? err.message.slice(0, 220) : "");
  count("and it says nothing was retired",
    err !== null && /nothing has been retired/i.test(err.message),
    err ? err.message.slice(0, 220) : "");

  count("no private key was erased by the refusal",
    keysFor(keyDir, domain).join(",") === before.join(","),
    keysFor(keyDir, domain).join(","));
  count("and no selector was moved out of signing",
    dkim.list(domain).map(function (s) { return s.selector + ":" + s.state; }).sort().join(",") === rowsBefore,
    dkim.list(domain).map(function (s) { return s.selector + ":" + s.state; }).sort().join(","));

  var signed = dkim.signerFor(domain).sign(zone.messageFrom(domain, "after-refused-retire"));
  var results = await zone.verifyAgainst(signed, published);
  count("the domain still signs, and what it signs still verifies",
    zone.allPass(results), zone.summarize(results));

  // A name that matches nothing at all is a different mistake from a
  // name that matches half a pair, and it is still a refusal.
  var neither = await refused(function () {
    return dkim.retire({ domain: domain, selector: "bpnothing" });
  });
  count("a selector name matching nothing under either algorithm is refused",
    neither !== null && /nothing has been retired/i.test(neither.message),
    neither ? neither.message.slice(0, 200) : "accepted");

  // Named in full, the same retirement goes through.
  var ok = await refused(function () {
    return dkim.retire({ domain: domain, selector: "bpwinter", rsaSelector: "bpwinterrsa" });
  });
  count("naming both halves retires the pair",
    ok === null, ok ? ok.message.slice(0, 160) : "retired");
  count("and both private keys are erased, because nothing signs with them again",
    keysFor(keyDir, domain).length === 0, keysFor(keyDir, domain).join(",") || "(none)");
  count("while both records stay published through the overlap",
    dkim.dnsRecords(domain).length === 2,
    dkim.dnsRecords(domain).map(function (r) { return r.selector + ":" + r.state; }).join(","));
}

// A refusal that cannot be got past is its own trap. A domain whose pair
// is already half gone has to be recoverable, and refusing every
// retirement because the missing half is missing would leave it signing
// with a selector nothing can retire and nothing can rotate away from.
// The rule is about mismatch, not absence: name a selector the domain
// does not have while it has others of that algorithm and the answer is
// no; the same name where it has none of that algorithm at all is the
// repair.
async function retiringWhatIsLeftOfABrokenPairIsAllowed(identity, cfg, keyDir) {
  var domain = "half-pair.example.com";
  await identity.domains.add({ domain: domain });

  // Stand the broken state up by dropping one row out from under the
  // pair, which is what a mint that never completed used to leave.
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bplone" });
  await identity.domains.removeSelector({
    domain: domain, selector: "bplone-rsa", algorithm: "rsa-sha256",
    reason: "standing in for a pair that never completed",
  });
  count("the domain is left with an Ed25519 selector and no RSA partner",
    dkim.list(domain).length === 1 && dkim.list(domain)[0].algorithm === "ed25519",
    dkim.list(domain).map(function (s) { return s.selector + ":" + s.algorithm; }).join(","));

  var err = await refused(function () {
    return dkim.retire({ domain: domain, selector: "bplone" });
  });
  count("retiring the half that is left is allowed rather than refused",
    err === null, err ? err.message.slice(0, 200) : "retired");
  count("the private key of the selector it retired is erased",
    keysFor(keyDir, domain).indexOf(domain + ".bplone.ed25519.sealed") === -1,
    keysFor(keyDir, domain).join(",") || "(none)");
  count("and its record stays published through the overlap",
    dkim.dnsRecords(domain).length === 1,
    dkim.dnsRecords(domain).map(function (r) { return r.selector + ":" + r.state; }).join(","));
}

// ---- a row that goes takes its key with it -----------------------------------

// Withdrawing a hosted domain deletes every selector row it published.
// Each of those rows carried the name of a sealed private key file, and
// the row was the only thing that could ever find that file again:
// nothing walks the keys folder, and the one code path that erases a key
// reaches it through a selector row. So a removal that takes the rows
// and leaves the files leaves signing material for the domain on the
// volume permanently, in every backup taken afterwards, with no verb
// that can name it and no report that can see it.
async function removingADomainErasesTheKeysItsSelectorsNamed(identity, cfg, keyDir) {
  var domain = "withdrawn.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpleaving" });

  count("the domain holds one sealed private key per algorithm before it is withdrawn",
    keysFor(keyDir, domain).length === 2, keysFor(keyDir, domain).join(",") || "(none)");

  var removed = await identity.domains.remove({
    domain: domain, reason: "moved to another host",
  });

  count("withdrawing the domain takes its selector rows",
    removed.selectorsRemoved === 2 &&
      identity.domains.listSelectors({ domain: domain }).length === 0,
    JSON.stringify(removed));
  count("and the sealed private keys those rows named go with them, because the row was " +
    "the only thing that could ever find the file again",
    keysFor(keyDir, domain).length === 0, keysFor(keyDir, domain).join(",") || "(none)");
  count("and the removal says how much signing material it destroyed rather than " +
    "reporting only the rows",
    removed.keysErased === 2, JSON.stringify(removed));
}

// The same rule one selector at a time. A domain part way through a
// rotation holds four active selectors, so withdrawing one of them is
// not refused for leaving the domain unable to sign, and the row that
// goes is the only handle on the sealed key it named.
async function withdrawingOneSelectorErasesTheKeyItNamed(identity, cfg, keyDir) {
  var domain = "mid-rotation.example.com";
  await identity.domains.add({ domain: domain });
  var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
  await dkim.generate({ domain: domain, selector: "bpone" });
  await dkim.rotate({ domain: domain, selector: "bptwo" });

  var outgoing = domain + ".bpone.ed25519.sealed";
  count("the domain is part way through a rotation, with four active selectors and a " +
    "sealed key for each",
    dkim.list(domain).length === 4 && keysFor(keyDir, domain).length === 4,
    keysFor(keyDir, domain).join(","));

  await identity.domains.removeSelector({
    domain: domain, selector: "bpone", algorithm: "ed25519",
    reason: "withdrawn while the replacement pair is already signing",
  });

  count("the selector row is withdrawn",
    dkim.list(domain).length === 3,
    dkim.list(domain).map(function (s) { return s.selector + ":" + s.algorithm; }).join(","));
  count("and the sealed private key it named is erased with it, rather than left on the " +
    "volume with no row that can reach it",
    keysFor(keyDir, domain).indexOf(outgoing) === -1,
    keysFor(keyDir, domain).join(","));

  // The half that says the erasure was aimed at the right file: what is
  // left still signs, and what it signs still verifies against the
  // records this server is asking the operator to publish.
  var signed = dkim.signerFor(domain).sign(zone.messageFrom(domain, "after-withdrawal"));
  var results = await zone.verifyAgainst(signed, dkim.dnsRecords(domain));
  count("and the pair that is left still signs mail that verifies",
    zone.allPass(results), zone.summarize(results));
}

// ---- the ordinary path still works ------------------------------------------

// The refusals above are only worth anything if the path they guard is
// still open. A domain minted, rotated and retired end to end has to
// keep producing mail that verifies at every step.
async function theLifecycleStillProducesVerifiableMail(dkim, identity) {
  var domain = "lifecycle.example.com";
  await identity.domains.add({ domain: domain });

  await dkim.generate({ domain: domain, selector: "bpfirst" });
  var afterGenerate = await zone.verifyAgainst(
    dkim.signerFor(domain).sign(zone.messageFrom(domain, "generated")),
    dkim.dnsRecords(domain));
  count("a freshly minted domain signs mail that verifies",
    zone.allPass(afterGenerate) && afterGenerate.length === 2, zone.summarize(afterGenerate));

  await dkim.rotate({ domain: domain, selector: "bpsecond" });
  var afterRotate = await zone.verifyAgainst(
    dkim.signerFor(domain).sign(zone.messageFrom(domain, "rotated")),
    dkim.dnsRecords(domain));
  count("a domain mid rotation signs with both pairs and all four verify",
    zone.allPass(afterRotate) && afterRotate.length === 4, zone.summarize(afterRotate));

  await dkim.retire({ domain: domain, selector: "bpfirst" });
  var afterRetire = await zone.verifyAgainst(
    dkim.signerFor(domain).sign(zone.messageFrom(domain, "retired")),
    dkim.dnsRecords(domain));
  count("after the retirement the incoming pair signs on its own and verifies",
    zone.allPass(afterRetire) && afterRetire.length === 2, zone.summarize(afterRetire));
  count("and the retired selector no longer signs",
    zone.selectorsOn(dkim.signerFor(domain).sign(zone.messageFrom(domain, "check")))
      .indexOf("bpfirst") === -1,
    zone.selectorsOn(dkim.signerFor(domain).sign(zone.messageFrom(domain, "check"))).join(","));
}

// ---- runner -----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-key-lifecycle");
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

    var dkim = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir });
    var keyDir = dkim.describe().keyDir;

    await aRefusedMintLeavesNoKeyMaterial(dkim, identity, keyDir);
    await aFaultRecordingTheSecondHalfTakesTheFirstBackOut(identity, cfg, keyDir);
    await aRefusedRotationNamesTheSelectorInTheWay(dkim, identity, keyDir);
    await mintingOntoARetiringSelectorNameIsRefusedFirst(dkim, identity, keyDir);
    await aCaseFoldedSelectorIsRefusedBeforeAnythingIsWritten(dkim, identity, keyDir);
    await retiringWithoutTheRsaPartnerChangesNothing(dkim, identity, keyDir);
    await retiringWhatIsLeftOfABrokenPairIsAllowed(identity, cfg, keyDir);
    await removingADomainErasesTheKeysItsSelectorsNamed(identity, cfg, keyDir);
    await withdrawingOneSelectorErasesTheKeyItNamed(identity, cfg, keyDir);
    await theLifecycleStillProducesVerifiableMail(dkim, identity);

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

module.exports = { name: "dkim-key-lifecycle", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
