// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Key rotation, checked by verifying a real signature against the
 * records this server tells the operator to publish.
 *
 * DKIM fails in the worst direction available: silently, at the far end,
 * days later. A record that has drifted from the key signing with it
 * looks perfect from here, and the only symptom is other people's
 * servers quietly trusting your mail less. Nothing about that reaches
 * this side, so the check has to be done here and it has to be done
 * against the bytes rather than against a description of them.
 *
 * So every claim in this file is settled by `b.mail.dkim.verify`, with
 * its DNS lookup fed from what `dkim records` publishes. If a message
 * this server signed verifies against the zone this server asks for,
 * the two agree. If it does not, they have drifted, and that is exactly
 * the condition that is invisible in production.
 *
 * The overlap is the other half. A message signed an hour ago may still
 * be sitting in a receiver's queue, so a rotation that stops signing
 * with the outgoing key immediately breaks mail that has already left.
 * Both pairs sign until the old one is retired, and the retired
 * selector stays published while its overlap runs.
 *
 * Run standalone: node test/layer-1-state/mail-dkim-rotation.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");
var dnsZone = require("../helpers/dns-zone");
var b       = require("../../lib/vendor/blamejs");
var config  = require("../../lib/config");
var store   = require("../../lib/store");
var dkimMod = require("../../lib/mail/dkim");
var tables  = require("../../lib/store/tables");

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

var MESSAGE = [
  "From: alice@" + DOMAIN,
  "To: bob@example.net",
  "Subject: A message worth signing",
  "Date: Sat, 23 Aug 2026 12:00:00 +0000",
  "Message-ID: <rotation-probe@" + DOMAIN + ">",
  "",
  "Body under signature.",
  "",
].join("\r\n");

// The assertion that quotes the value that produced the verdict. It is
// the shared one rather than a copy, because a private wrapper that
// formats a failure differently is a failure line nobody can grep for.
var count = helpers.count;

// A DNS resolver built from what the operator has been told to publish.
// Verification against this is the whole point: it answers whether the
// zone this server asks for actually validates the mail this server
// sends.
function zoneFrom(records) {
  var byName = Object.create(null);
  records.forEach(function (r) { byName[r.dnsName.toLowerCase()] = r.dnsTxtValue; });
  return async function dnsLookup(qname) {
    var value = byName[String(qname).toLowerCase().replace(/\.$/, "")];
    if (!value) return [];
    // node:dns returns TXT as an array of chunk arrays, and the verifier
    // reassembles them the way a resolver would.
    return [[value]];
  };
}

// Every `s=` selector on the message, in order. The shared reader, so
// this file and the zone fixtures cannot come to disagree about what a
// signature header looks like: two parsers of one header is one of them
// quietly matching nothing while the file it is in reports green.
var selectorsOn = dnsZone.selectorsOn;

async function verifyAgainst(signed, records) {
  return await b.mail.dkim.verify(signed, { dnsLookup: zoneFrom(records) });
}

// ---- cases -----------------------------------------------------------------

async function afreshDomainSignsWithBothAlgorithms(dkim) {
  await dkim.generate({ domain: DOMAIN });

  var records = dkim.dnsRecords(DOMAIN);
  count("a fresh domain publishes two records, one per algorithm",
    records.length === 2, records.map(function (r) { return r.algorithm; }).join(", "));

  // The stored `algorithm` is an internal discriminator and its two
  // values are named asymmetrically, `ed25519` beside `rsa-sha256`. What
  // an operator publishes is the k= tag, and RFC 6376 §3.6.1 with RFC
  // 8463 §3 allow exactly `rsa` and `ed25519` there, so that is the
  // string worth asserting.
  var kTags = records.map(function (r) {
    var m = /k=([^;\s]+)/.exec(r.dnsTxtValue);
    return m ? m[1] : "(none)";
  }).sort().join(", ");
  // Hard rule: the default is a dual signer over Ed25519 and RSA. The
  // ML-DSA claim this project carried for a while was wrong, and the
  // correction is worth pinning against the bytes rather than a doc.
  count("the published k= tags are the two the RFCs define",
    kTags === "ed25519, rsa", kTags);
  count("and neither is anything post-quantum, which DKIM has no tag for",
    !/dilithium|ml-dsa/i.test(records.map(function (r) {
      return r.dnsTxtValue; }).join(" ")), kTags);

  var signed = dkim.signerFor(DOMAIN).sign(MESSAGE);
  var results = await verifyAgainst(signed, records);
  count("a signed message carries two signatures",
    results.length === 2, results.length + " signature(s)");
  count("and both verify against the records the operator publishes",
    results.length === 2 && results.every(function (r) { return r.result === "pass"; }),
    results.map(function (r) { return r.s + "=" + r.result; }).join(", "));

  var algs = results.map(function (r) { return r.alg; }).sort().join(", ");
  count("the a= tags on the wire are the two RFC 8463 and RFC 6376 forms",
    /ed25519-sha256/.test(algs) && /rsa-sha256/.test(algs), algs);
}

async function rotationKeepsSigningWithBothPairs(dkim) {
  var before = dkim.dnsRecords(DOMAIN).map(function (r) { return r.selector; }).sort();

  // The default selector is derived from the month, so rotating in the
  // same month the keys were generated collides with the name already
  // published. An operator meets this the first time they rotate twice
  // in thirty days, and the refusal has to send them somewhere rather
  // than just failing.
  var collided = null;
  try { await dkim.rotate({ domain: DOMAIN }); }
  catch (e) { collided = e; }
  count("rotating onto a selector name already in use is refused",
    collided !== null, collided ? "refused" : "accepted a duplicate selector");
  count("and the refusal names the flag that resolves it",
    collided !== null && /--selector/.test(collided.message),
    collided ? collided.message.slice(0, 120) : "");

  await dkim.rotate({ domain: DOMAIN, selector: "bprotated" });

  var records = dkim.dnsRecords(DOMAIN);
  count("rotation publishes four records, two pairs",
    records.length === 4, records.map(function (r) { return r.selector; }).join(", "));

  var after = records.map(function (r) { return r.selector; }).sort();
  count("and the outgoing selectors are still published",
    before.every(function (s) { return after.indexOf(s) !== -1; }),
    "before " + before.join(",") + " after " + after.join(","));

  // The property that protects mail already in flight: a message signed
  // an hour ago is still verifiable, and a message signed now carries
  // the new pair too.
  var signed = dkim.signerFor(DOMAIN).sign(MESSAGE);
  var results = await verifyAgainst(signed, records);
  count("a message signed mid rotation carries four signatures",
    results.length === 4, results.length + " signature(s)");
  count("and every one of them verifies",
    results.length === 4 && results.every(function (r) { return r.result === "pass"; }),
    results.map(function (r) { return r.s + "=" + r.result; }).join(", "));

  var onMessage = selectorsOn(signed).sort();
  count("both the outgoing and the incoming selector sign",
    before.every(function (s) { return onMessage.indexOf(s) !== -1; }),
    "signed by " + onMessage.join(","));

  return before;
}

async function retiringStopsSigningAndKeepsPublishing(dkim, outgoing) {
  // Retire one algorithm's outgoing selector. The other stays, so the
  // count moves by one rather than by a pair.
  var target = dkim.list(DOMAIN).filter(function (s) {
    return outgoing.indexOf(s.selector) !== -1 && s.state === "active";
  })[0];
  count("an outgoing selector is still active before it is retired",
    !!target, JSON.stringify(outgoing));

  await dkim.retire({ domain: DOMAIN, selector: target.selector });

  // The operator names one selector and its RSA partner goes with it.
  // The guide says so and an operator relies on it, because retiring
  // half a pair would leave a domain signing with one algorithm while
  // publishing two.
  var partner = dkim.list(DOMAIN).filter(function (s) {
    return s.selector === target.selector + "-rsa"; })[0];
  count("the RSA partner is named with an -rsa suffix",
    !!partner, dkim.list(DOMAIN).map(function (s) { return s.selector; }).join(", "));
  count("and retiring the Ed25519 selector retires the partner with it",
    partner && partner.state !== "active", partner && partner.state);

  var records = dkim.dnsRecords(DOMAIN);
  var stillPublished = records.some(function (r) { return r.selector === target.selector; });
  // RFC 6376 does not say how long to keep a retired record, and the
  // reason to keep it is entirely practical: a receiver holding a
  // message signed before the retirement still has to resolve the key.
  count("a retired selector stays published through its overlap",
    stillPublished, records.map(function (r) {
      return r.selector + ":" + r.state; }).join(", "));

  var retiredRow = dkim.list(DOMAIN).filter(function (s) {
    return s.selector === target.selector; })[0];
  count("and it is marked retiring rather than active",
    retiredRow && retiredRow.state !== "active", retiredRow && retiredRow.state);

  var signed = dkim.signerFor(DOMAIN).sign(MESSAGE);
  var onMessage = selectorsOn(signed);
  count("a message signed after the retirement no longer uses that selector",
    onMessage.indexOf(target.selector) === -1, onMessage.join(","));

  var results = await verifyAgainst(signed, records);
  count("and what it does sign with still verifies",
    results.length > 0 && results.every(function (r) { return r.result === "pass"; }),
    results.map(function (r) { return r.s + "=" + r.result; }).join(", "));

  return target.selector;
}

async function sweepWaitsForTheOverlap(dkim, retiredSelector) {
  // The overlap is read from the code rather than from the guide,
  // because the guide is where this project's drift has consistently
  // been.
  count("the overlap the store applies is seven days",
    tables.SELECTOR_OVERLAP_MS === b.constants.TIME.days(7),
    String(tables.SELECTOR_OVERLAP_MS));

  var swept = await dkim.sweep({ domain: DOMAIN });
  var named = (swept.withdrawn || []).map(function (r) { return r.selector; });
  count("a sweep inside the overlap withdraws nothing",
    named.indexOf(retiredSelector) === -1, named.join(",") || "(none)");

  var stillThere = dkim.dnsRecords(DOMAIN).some(function (r) {
    return r.selector === retiredSelector; });
  count("so the record an in-flight message needs is still published",
    stillThere, retiredSelector);

  // The operator override, for the case the overlap exists to serve
  // being the wrong trade: a key that leaked has to leave the zone now,
  // and the in-flight mail signed with it is the acceptable loss.
  var forced = await dkim.sweep({ domain: DOMAIN, immediate: true });
  var forcedNames = (forced.withdrawn || []).map(function (r) { return r.selector; });
  count("--immediate withdraws it before the overlap has elapsed",
    forcedNames.indexOf(retiredSelector) !== -1, forcedNames.join(",") || "(none)");

  var gone = dkim.dnsRecords(DOMAIN).every(function (r) {
    return r.selector !== retiredSelector; });
  count("and the record leaves the published set",
    gone, dkim.dnsRecords(DOMAIN).map(function (r) { return r.selector; }).join(","));
}

// A domain left holding one algorithm, which is the state the guide
// used to describe as a per-domain choice. Nothing an operator can type
// produces it: `dkim retire` names a pair and takes both halves, so the
// only way in is a mint that stopped after writing one row. It is built
// here through the store row, and read through a handle built fresh
// afterwards, because that is the shape the failed mint leaves behind.
// Its own cache is dropped on the way out, so the next signer is built
// from the rows rather than from memory.
//
// What makes this worth a case of its own is that everything RFC 6376
// asks for is present. The remaining key is active, sealed and
// published, and a receiver could check a signature made with it. The
// refusal is still correct, because a domain that publishes two records
// and signs with one is a domain whose mail fails at every receiver
// that reads the other. What the refusal owes the operator is which
// half is gone and a way out that works from here.
async function oneAlgorithmAloneRefusesAndSaysWhy(identity, cfg) {
  var live = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir, vault: b.vault });

  var eddsa = live.list(DOMAIN).filter(function (s) {
    return s.algorithm === "ed25519" && s.state === "active"; })[0];
  var rsa = live.list(DOMAIN).filter(function (s) {
    return s.algorithm === "rsa-sha256" && s.state === "active"; })[0];
  count("the domain holds one active selector per algorithm to begin with",
    !!eddsa && !!rsa, live.list(DOMAIN).map(function (s) {
      return s.selector + ":" + s.algorithm + ":" + s.state; }).join(", "));

  await identity.domains.retireSelector({
    domain: DOMAIN, selector: eddsa.selector, algorithm: "ed25519",
  });
  var stranded = dkimMod.create({ store: identity, dataDir: cfg.paths.dataDir, vault: b.vault });

  var stillActive = stranded.list(DOMAIN).filter(function (s) { return s.state === "active"; });
  count("one algorithm is left active and it is the RSA half",
    stillActive.length === 1 && stillActive[0].algorithm === "rsa-sha256",
    stillActive.map(function (s) { return s.selector + ":" + s.algorithm; }).join(", ") || "(none)");
  count("its record is still published and still names its key family",
    stranded.dnsRecords(DOMAIN).some(function (r) {
      return r.selector === rsa.selector && /k=rsa/.test(r.dnsTxtValue); }),
    rsa.selector);

  var refusal = null;
  try { stranded.signerFor(DOMAIN); }
  catch (e) { refusal = e; }
  count("signing refuses rather than sending under one algorithm",
    refusal !== null, refusal ? "refused" : "signed with half a pair");
  count("and the refusal carries the code the relay path branches on",
    refusal !== null && refusal.code === dkimMod.CODES.noActiveSelector,
    refusal ? String(refusal.code) : "(no refusal)");

  // The operator reading this has an active key and a published record,
  // so "no active DKIM key pair" reads as though the domain has nothing
  // at all. Naming the half that is missing is the difference between a
  // state they can act on and one they have to go and reconstruct.
  count("the refusal names the algorithm that is missing",
    refusal !== null && /ed25519/i.test(refusal.message),
    refusal ? refusal.message : "(no refusal)");

  // Every verb the two refusals name is tried from this exact state, so
  // an instruction that cannot be followed from here fails the check
  // rather than reading plausibly.
  var generated = null;
  try { await stranded.generate({ domain: DOMAIN }); }
  catch (e) { generated = e; }
  count("generate refuses while a selector is still active",
    generated !== null, generated ? "refused" : "minted a third selector");

  var rotated = null;
  try { await stranded.rotate({ domain: DOMAIN, selector: "bprecover" }); }
  catch (e) { rotated = e; }
  count("rotate refuses from the same state, having no pair to rotate away from",
    rotated !== null && rotated.code === dkimMod.CODES.noActiveSelector,
    rotated ? String(rotated.code) : "rotated off half a pair");

  // Both verbs work from here, but only in one order, and a refusal
  // that named the mint on its own would be naming the verb that just
  // refused. What is checked is the order rather than the words: strip
  // the withdrawal step later and leave "run generate" behind, and this
  // is the check that notices.
  count("so the signing refusal puts the withdrawal ahead of the mint",
    refusal !== null && /retire/.test(refusal.message) &&
      refusal.message.indexOf("retire") < refusal.message.indexOf("dkim generate"),
    refusal ? refusal.message : "(no refusal)");
  count("and generate's own refusal does not send them on to rotate",
    generated !== null && !/dkim rotate/.test(generated.message),
    generated ? generated.message : "(no refusal)");
  count("naming the withdrawal instead, which is the step that works from here",
    generated !== null && /dkim retire/.test(generated.message),
    generated ? generated.message : "(no refusal)");

  // A refusal that only says no leaves the operator to guess. Both of
  // these end at the same place, and it costs a signing gap, so both
  // have to say so rather than one of them implying a repair in place.
  count("the signing refusal says signing stops until a fresh pair is published",
    refusal !== null && /signs? nothing|unsigned|no signature/i.test(refusal.message),
    refusal ? refusal.message : "(no refusal)");
  count("and generate's refusal says the same when the pair is already broken",
    generated !== null && /ed25519/i.test(generated.message),
    generated ? generated.message : "(no refusal)");
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("dkim-rotation");
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
    await identity.domains.add({ domain: DOMAIN });

    var dkim = dkimMod.create({
      store:   identity,
      dataDir: cfg.paths.dataDir,
      vault:   b.vault,
    });

    await afreshDomainSignsWithBothAlgorithms(dkim);
    var outgoing = await rotationKeepsSigningWithBothPairs(dkim);
    var retired  = await retiringStopsSigningAndKeepsPublishing(dkim, outgoing);
    await sweepWaitsForTheOverlap(dkim, retired);
    await oneAlgorithmAloneRefusesAndSaysWhy(identity, cfg);

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

module.exports = { name: "mail-dkim-rotation", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
