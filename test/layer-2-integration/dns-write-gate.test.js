// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * dns-write-gate: what the hosted-DNS write path will and will not do
 * with a credential that can edit a zone.
 *
 * The operator has chosen a token that can write, so the question this
 * file asks is never whether a write works. It is what stands between a
 * caller and the zone: the allowlist, the switch over MX, the preview
 * that has to come first and still be true when it is applied, the
 * reason on every write, and the two independent reads afterwards.
 *
 * The provider is a stand-in bound on loopback for the run, and it
 * speaks TLS because the client has no cleartext mode and is not given
 * one for a test. It implements the envelope, the paging block and the
 * error numbers the real one documents, so a refusal measured here is
 * the refusal a real response produces rather than one a mock was told
 * to produce. It records every request it receives, which is what lets
 * the preview assertions measure that nothing was written rather than
 * assume it.
 *
 * The credential is sealed through the running vault, not a stand-in
 * pair, so the prefix check and the opened value are the real ones.
 *
 * Run standalone: node test/layer-2-integration/dns-write-gate.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var dnsZone = require("../helpers/dns-zone");
var standIn = require("../helpers/dns-provider");
var b       = require("../../lib/vendor/blamejs");
var dns     = require("../../lib/dns");
var provider = require("../../lib/dns/cloudflare");
var configModule = require("../../lib/config");

var check = helpers.check;
var count = helpers.count;

// The stand-in provider itself lives in test/helpers/dns-provider.js,
// because the command-line run in zone-cli-wire.test.js drives the same
// one. Two copies would be two answers to what the provider's envelope
// looks like, and whichever one somebody corrected the other would keep
// passing on the old shape.
var startProvider = standIn.start;
// The failure envelope, for the one case that hands the stand-in a
// forced reply of its own. The success envelope is not needed here: no
// case builds one, because every successful answer comes from the
// stand-in's own routes.
var fail = standIn.fail;

var DOMAIN = standIn.DOMAIN;
var ZONE   = standIn.ZONE_ID;

// A credential shaped like the provider's: forty characters of the
// alphabet a real token draws from. It is a fixture and never leaves
// this process, and every assertion about leaking is made against this
// exact string.
var TOKEN = "fixtureDnsTokenZ8bC3dF6gH1jL5nS0aE2uT9iO";

// Every refusal code this run actually observed. The last case compares
// it against what the two modules publish, so a code that exists and is
// unreachable is a finding rather than something nobody noticed.
var observedCodes = Object.create(null);

function note(code) {
  if (typeof code === "string" && code.length > 0) observedCodes[code] = true;
}

// Run `fn` and return the error it threw. A case that expects a refusal
// and gets a return value has found the safeguard missing, which is the
// failure this reports rather than a later assertion reading undefined.
async function refusalFrom(label, fn) {
  var thrown = null;
  try {
    await fn();
  } catch (e) {
    thrown = e;
  }
  if (thrown === null) {
    throw new Error("FAIL: " + label + ": expected a refusal and the call returned");
  }
  note(thrown.code);
  return thrown;
}

// ---- fixtures --------------------------------------------------------------

var vaultReady = false;
var sealedToken = null;

async function ensureVault() {
  if (vaultReady) return;
  var dataDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-dns-"));
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  sealedToken = dns.sealToken(TOKEN, b.vault);
  vaultReady = true;
}

// The context a provider token is sealed under. It is spelled here rather
// than read from the module because it is the stored format: a change to
// it leaves every token already on a volume unable to open, and this file
// is what fails when that happens.
var TOKEN_SEAL_CONTEXT = { purpose: "blamepost.dns.provider-token" };

// The sealed fixture token, opened the way the gate opens it.
function openToken() {
  return b.vault.aad.unseal(sealedToken, TOKEN_SEAL_CONTEXT);
}

// A gate wired to one stand-in provider. Each case builds its own, so a
// breaker tripped or a budget spent in one does not reach the next.
function gateOver(fake, extra) {
  var opts = {
    domain:      DOMAIN,
    sealedToken: sealedToken,
    vault:       b.vault,
    resolver:    (extra && extra.resolver) || dnsZone.pinnedResolverOver({}),
    clientOptions: {
      baseUrl:               fake.baseUrl,
      agent:                 fake.agent,
      allowInternalEndpoint: true,
      maxAttempts:           (extra && extra.maxAttempts) || 2,
    },
  };
  Object.keys(extra || {}).forEach(function (k) {
    if (k !== "resolver" && k !== "maxAttempts") opts[k] = extra[k];
  });
  return dns.create(opts);
}

function dmarcRecord(content) {
  return { type: "TXT", name: "_dmarc." + DOMAIN, content: content || "v=DMARC1; p=reject" };
}

// ---- the cases -------------------------------------------------------------

async function theGateRefusesWhatIsOutsideItsAllowlist() {
  var fake = await startProvider();
  var gate = gateOver(fake);
  try {
    var byType = await refusalFrom("a record type outside the allowlist", function () {
      return gate.preview({
        desired: [{ type: "A", name: DOMAIN, content: "203.0.113.10" }],
        reason:  "attempt an address record",
      });
    });
    count("blamepost.dns.preview refuses a type outside the allowlist",
      byType.code === dns.CODES.writeNotAllowed, byType.code);

    var byName = await refusalFrom("an address outside the allowlist", function () {
      return gate.preview({
        desired: [{ type: "TXT", name: "www." + DOMAIN, content: "anything" }],
        reason:  "attempt an ordinary name",
      });
    });
    count("blamepost.dns.preview refuses an address outside the allowlist",
      byName.code === dns.CODES.writeNotAllowed, byName.code);

    var otherZone = await refusalFrom("an address in another zone", function () {
      return gate.preview({
        desired: [{ type: "TXT", name: "_dmarc.other-domain.test", content: "v=DMARC1" }],
        reason:  "attempt another zone",
      });
    });
    count("blamepost.dns.preview refuses an address in another zone",
      otherZone.code === dns.CODES.writeNotAllowed, otherZone.code);

    var wildcard = await refusalFrom("a wildcard address", function () {
      return gate.preview({
        desired: [{ type: "TXT", name: "*." + DOMAIN, content: "v=spf1 -all" }],
        reason:  "attempt a wildcard",
      });
    });
    count("blamepost.dns.preview refuses a wildcard address",
      wildcard.code === dns.CODES.badRecord, wildcard.code);

    check("nothing reached the provider while the allowlist was refusing",
      fake.writes().length === 0);
  } finally {
    gate.close();
    fake.close();
  }
}

async function theMxSwitchIsOffUntilAnOperatorTurnsItOn() {
  var fake = await startProvider();
  var closedGate = gateOver(fake);
  try {
    var refused = await refusalFrom("MX with the switch at its default", function () {
      return closedGate.preview({
        desired: [{ type: "MX", name: DOMAIN, content: "mx.example.com", priority: 10 }],
        reason:  "attempt to repoint the mail exchanger",
      });
    });
    count("the MX switch is off by default",
      refused.code === dns.CODES.mxWriteDisabled, refused.code);
    check("the default allowlist reports MX as off",
      closedGate.allowlist().allowMxWrites === false);
    check("no MX address is listed while the switch is off",
      closedGate.allowlist().addresses.every(function (a) { return a.type !== "MX"; }));
  } finally {
    closedGate.close();
  }

  var openGate = gateOver(fake, { allowMxWrites: true });
  try {
    var preview = await openGate.preview({
      desired: [{ type: "MX", name: DOMAIN, content: "mx.example.com", priority: 10 }],
      reason:  "point the mail exchanger at this server",
    });
    count("the MX switch admits the write when an operator turns it on",
      preview.changes.length === 1 && preview.changes[0].type === "MX",
      JSON.stringify(preview.changes.map(function (c) { return c.type + " " + c.action; })));
    check("the opened allowlist reports MX as on", openGate.allowlist().allowMxWrites === true);

    // An MX record with no preference cannot be ordered against another,
    // so it is refused rather than written with one invented for it.
    var noPref = await refusalFrom("MX with no preference", function () {
      return openGate.preview({
        desired: [{ type: "MX", name: DOMAIN, content: "mx.example.com" }],
        reason:  "attempt an unordered exchanger",
      });
    });
    count("an MX record with no preference is refused",
      noPref.code === dns.CODES.badRecord, noPref.code);
  } finally {
    openGate.close();
    fake.close();
  }
}

// Two desired records of one type at one name, against a zone holding
// one record there. Each existing record is the target of at most one
// update, an exact match is kept rather than overwritten, and whatever
// the zone cannot supply is created. The preview this produces is one
// apply accepts.
async function severalRecordsAtOneNameEachTakeTheirOwnTarget() {
  var fake = await startProvider({
    records: [{ id: "mxold000000000000000000000000000", type: "MX", name: DOMAIN,
      content: "old-mx.example.com", priority: 10, ttl: 300 }],
  });
  var gate = gateOver(fake, { allowMxWrites: true });
  try {
    var preview = await gate.preview({
      desired: [
        { type: "MX", name: DOMAIN, content: "mx1.example.com", priority: 10 },
        { type: "MX", name: DOMAIN, content: "mx2.example.com", priority: 20 },
      ],
      reason: "replace one exchanger with two",
    });
    var actions = preview.changes.map(function (c) { return c.action; }).sort();
    count("replacing one record with two previews one update and one create",
      actions.join(",") === "create,update", JSON.stringify(preview.changes.map(function (c) {
        return { action: c.action, recordId: c.recordId, content: c.after && c.after.content };
      })));
    var targeted = preview.changes.filter(function (c) { return c.recordId !== null; })
      .map(function (c) { return c.recordId; });
    count("no existing record is the target of two changes",
      targeted.length === new Set(targeted).size, JSON.stringify(targeted));

    var applied = await gate.apply(preview,
      { reason: "replace one exchanger with two", confirm: true });
    count("apply accepts the preview it was handed and writes both changes",
      applied.written.length === 2, JSON.stringify(applied.written));
    var held = fake.state.records.filter(function (r) { return r.type === "MX"; })
      .map(function (r) { return r.content; }).sort();
    count("the zone then holds exactly the two exchangers asked for",
      held.join(",") === "mx1.example.com,mx2.example.com", JSON.stringify(held));

    // An exact match keeps its record even when it is listed after a
    // record that needs a target. The first desired record must not take
    // the matching record as its update target.
    var settled = await gate.preview({
      desired: [
        { type: "MX", name: DOMAIN, content: "mx3.example.com", priority: 30 },
        { type: "MX", name: DOMAIN, content: "mx2.example.com", priority: 20 },
      ],
      reason: "swap one exchanger and keep the other",
    });
    var updates = settled.changes.filter(function (c) { return c.action === "update"; });
    var kept = fake.state.records.filter(function (r) {
      return r.type === "MX" && r.content === "mx2.example.com";
    })[0];
    count("a record that already matches is not chosen as another record's update target",
      settled.changes.length === 1 && updates.length === 1 &&
      updates[0].recordId !== kept.id && updates[0].after.content === "mx3.example.com",
      JSON.stringify(settled.changes.map(function (c) {
        return { action: c.action, recordId: c.recordId, content: c.after && c.after.content };
      })));
  } finally {
    gate.close();
    fake.close();
  }
}

async function previewWritesNothingAndApplyWritesWhatItShowed() {
  var fake = await startProvider();
  var gate = gateOver(fake);
  try {
    var preview = await gate.preview({
      desired: [dmarcRecord()],
      reason:  "publish the DMARC policy",
    });
    count("blamepost.dns.preview computed one create",
      preview.changes.length === 1 && preview.changes[0].action === "create",
      preview.diff);
    check("blamepost.dns.preview wrote nothing to the provider",
      fake.writes().length === 0);
    check("the preview rendered a diff a reader can act on",
      preview.diff.indexOf("+ TXT _dmarc." + DOMAIN) !== -1);
    check("the preview carries what the zone held, for apply to compare",
      typeof preview.fingerprint === "string" && preview.fingerprint.length > 0);

    var applied = await gate.apply(preview, { reason: "publish the DMARC policy" });
    count("blamepost.dns.apply performed exactly the one change previewed",
      applied.written.length === 1 && applied.written[0].action === "create",
      JSON.stringify(applied.written.map(function (w) { return w.action; })));

    var writes = fake.writes();
    count("the provider received exactly one write", writes.length === 1,
      JSON.stringify(writes.map(function (w) { return w.method + " " + w.path; })));

    var sent = JSON.parse(writes[0].body);
    check("the write carried the record the preview showed",
      sent.type === "TXT" && sent.name === "_dmarc." + DOMAIN &&
      sent.content === "v=DMARC1; p=reject");
    check("the zone now holds the record",
      fake.state.records.some(function (r) { return r.name === "_dmarc." + DOMAIN; }));

    // Running the same desire again is a no-op rather than a second
    // write, which is what makes the gate safe to drive from a loop.
    var again = await gate.preview({ desired: [dmarcRecord()], reason: "confirm settled" });
    count("a settled record previews as no change", again.changes.length === 0, again.diff);
    var reapplied = await gate.apply(again, { reason: "confirm settled" });
    check("applying an empty change set writes nothing more",
      reapplied.written.length === 0 && fake.writes().length === 1);
  } finally {
    gate.close();
    fake.close();
  }
}

async function applyRefusesAZoneThatMovedUnderneathThePreview() {
  var fake = await startProvider();
  var gate = gateOver(fake);
  try {
    var preview = await gate.preview({
      desired: [dmarcRecord("v=DMARC1; p=reject")],
      reason:  "publish the DMARC policy",
    });

    // Something else edits the zone between the two calls. This is the
    // case the fingerprint exists for.
    fake.state.records.push({
      id: "outside01", type: "TXT", name: "_dmarc." + DOMAIN,
      content: "v=DMARC1; p=none", ttl: 300,
    });

    var drift = await refusalFrom("apply after the zone moved", function () {
      return gate.apply(preview, { reason: "publish the DMARC policy", confirm: true });
    });
    count("blamepost.dns.apply refuses a preview the zone has outgrown",
      drift.code === dns.CODES.recordDrift, drift.code);
    check("nothing was written when the zone had drifted", fake.writes().length === 0);

    // A fresh preview sees the new state and is applicable again.
    var fresh = await gate.preview({
      desired: [dmarcRecord("v=DMARC1; p=reject")],
      reason:  "publish the DMARC policy after reading the zone again",
    });
    var applied = await gate.apply(fresh,
      { reason: "publish the DMARC policy after reading the zone again", confirm: true });
    check("a preview taken after the drift applies", applied.written.length === 1);
  } finally {
    gate.close();
    fake.close();
  }
}

async function applyRefusesAnythingThatIsNotItsOwnPreview() {
  var fake = await startProvider();
  var gate = gateOver(fake);
  try {
    var notAPreview = await refusalFrom("apply given a bare object", function () {
      return gate.apply({ changes: [] }, { reason: "attempt without a preview" });
    });
    count("blamepost.dns.apply refuses something that is not a preview",
      notAPreview.code === dns.CODES.previewRequired, notAPreview.code);

    var real = await gate.preview({ desired: [dmarcRecord()], reason: "compute a change" });
    var foreign = Object.assign({}, real, { domain: "other-domain.test" });
    var refusedForeign = await refusalFrom("apply given another domain's preview", function () {
      return gate.apply(foreign, { reason: "attempt another domain's preview" });
    });
    count("blamepost.dns.apply refuses a preview computed for another domain",
      refusedForeign.code === dns.CODES.previewForeign, refusedForeign.code);

    // A caller that edits the change set to smuggle a record past the
    // allowlist meets the same refusal the preview would have given.
    var tampered = Object.assign({}, real, {
      changes: [{ action: "create", type: "A", name: "www." + DOMAIN,
        before: null, after: { type: "A", name: "www." + DOMAIN, content: "203.0.113.9" },
        recordId: null }],
    });
    var refusedTamper = await refusalFrom("apply given an edited change set", function () {
      return gate.apply(tampered, { reason: "attempt an edited change set", confirm: true });
    });
    count("blamepost.dns.apply re-checks the allowlist rather than trusting the preview",
      refusedTamper.code === dns.CODES.writeNotAllowed, refusedTamper.code);
    check("nothing was written for any refused preview", fake.writes().length === 0);
  } finally {
    gate.close();
    fake.close();
  }
}

async function everyWriteCarriesAReasonAndBulkTakesConfirmation() {
  var fake = await startProvider();
  var gate = gateOver(fake);
  try {
    var noReason = await refusalFrom("preview with no reason", function () {
      return gate.preview({ desired: [dmarcRecord()] });
    });
    count("blamepost.dns.preview needs a recorded reason",
      noReason.code === dns.CODES.reasonRequired, noReason.code);

    var blank = await refusalFrom("preview with a blank reason", function () {
      return gate.preview({ desired: [dmarcRecord()], reason: "   " });
    });
    check("a reason of only spaces is not a reason",
      blank.code === dns.CODES.reasonRequired);

    var preview = await gate.preview({
      desired: [dmarcRecord(), { type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
      reason:  "publish the posture records",
    });
    check("the change set has two changes", preview.changes.length === 2);

    var noConfirm = await refusalFrom("a two-change apply without confirmation", function () {
      return gate.apply(preview, { reason: "publish the posture records" });
    });
    count("a change set of more than one takes confirmation",
      noConfirm.code === dns.CODES.confirmRequired, noConfirm.code);
    check("nothing was written while confirmation was missing", fake.writes().length === 0);

    var applyNoReason = await refusalFrom("apply with no reason", function () {
      return gate.apply(preview, { confirm: true });
    });
    check("blamepost.dns.apply needs a recorded reason",
      applyNoReason.code === dns.CODES.reasonRequired);

    var applied = await gate.apply(preview,
      { reason: "publish the posture records", confirm: true });
    check("the confirmed set was written", applied.written.length === 2);

    var verifyNoReason = await refusalFrom("verify with no reason", function () {
      return gate.verify(applied, {});
    });
    check("blamepost.dns.verify needs a recorded reason",
      verifyNoReason.code === dns.CODES.reasonRequired);
  } finally {
    gate.close();
    fake.close();
  }
}

async function verifyReportsWhenTheProviderAndTheResolverDisagree() {
  var fake = await startProvider();

  // The resolver answers with a policy nobody here wrote. The provider
  // will report the record as stored, so only asking both finds this.
  var conflicting = dnsZone.pinnedResolverOver({});
  var agreeing    = dnsZone.pinnedResolverOver({});
  var silent      = dnsZone.pinnedResolverOver({});

  var gate = gateOver(fake, { resolver: conflicting });
  try {
    var preview = await gate.preview({ desired: [dmarcRecord()], reason: "publish DMARC" });
    var applied = await gate.apply(preview, { reason: "publish DMARC" });

    // A resolver that has nothing yet is a write still propagating.
    var pendingGate = gateOver(fake, { resolver: silent });
    var pendingReport = await pendingGate.verify(applied, { reason: "check propagation" });
    count("blamepost.dns.verify reports a silent resolver as pending",
      pendingReport.pending === 1 && pendingReport.conflicts === 0 && !pendingReport.ok,
      JSON.stringify(pendingReport.checks.map(function (c) { return c.verdict; })));
    pendingGate.close();

    // A resolver answering with a different value is the alarming case.
    var conflictZone = {};
    conflictZone["_dmarc." + DOMAIN + "|TXT"] = [
      { type: 16, decoded: ["v=DMARC1; p=none"], ttl: 60 },
    ];
    var conflictGate = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(conflictZone) });
    var conflictReport = await conflictGate.verify(applied, { reason: "check propagation" });
    count("blamepost.dns.verify reports a disagreeing resolver as a conflict",
      conflictReport.conflicts === 1 && !conflictReport.ok,
      JSON.stringify(conflictReport.checks.map(function (c) { return c.verdict; })));
    check("the conflicting report quotes what the resolver actually answered",
      conflictReport.checks[0].resolverValues.indexOf("v=DMARC1; p=none") !== -1);
    check("the conflicting report quotes what the provider holds",
      conflictReport.checks[0].providerValues.indexOf("v=DMARC1; p=reject") !== -1);
    conflictGate.close();

    // Both agreeing is the only shape that reports ok.
    var agreeZone = {};
    agreeZone["_dmarc." + DOMAIN + "|TXT"] = [
      { type: 16, decoded: ["v=DMARC1; p=reject"], ttl: 60 },
    ];
    var agreeResolver = dnsZone.pinnedResolverOver(agreeZone);
    var agreeGate = gateOver(fake, { resolver: agreeResolver });
    var agreeReport = await agreeGate.verify(applied, { reason: "check propagation" });
    count("blamepost.dns.verify reports agreement when both reads match",
      agreeReport.ok === true && agreeReport.conflicts === 0,
      JSON.stringify(agreeReport.checks.map(function (c) { return c.verdict; })));
    check("the resolver was actually asked rather than assumed",
      agreeResolver.wasAsked("_dmarc." + DOMAIN, "TXT"));
    agreeGate.close();

    check("agreeing and conflicting resolvers were separate handles",
      agreeing !== conflicting);

    // A resolver answering a longer record that contains the value
    // written is a different record, and is reported as one.
    var longerZone = {};
    longerZone["_dmarc." + DOMAIN + "|TXT"] = [
      { type: 16, decoded: ["v=DMARC1; p=reject; pct=1"], ttl: 60 },
    ];
    var longerGate = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(longerZone) });
    var longerReport = await longerGate.verify(applied, { reason: "check propagation" });
    count("a resolver answer that only contains the written value is a conflict",
      longerReport.conflicts === 1 && !longerReport.ok,
      JSON.stringify(longerReport.checks.map(function (c) { return c.verdict; })));
    longerGate.close();
  } finally {
    gate.close();
    fake.close();
  }
}

// The resolver decodes MX and TLSA answers into objects rather than
// text. Verification compares their fields against the record written,
// for a write and for a removal.
async function verifyReadsMxAndTlsaAnswersByTheirFields() {
  var STALE = "mxstale0000000000000000000000000";
  var fake = await startProvider({
    records: [
      { id: "mxkeep00000000000000000000000000", type: "MX", name: DOMAIN,
        content: "mx.example.com", priority: 10, ttl: 300 },
      { id: STALE, type: "MX", name: DOMAIN,
        content: "old-mx.example.com", priority: 20, ttl: 300 },
    ],
  });
  var TLSA_NAME = "_25._tcp.mx." + DOMAIN;
  var DIGEST = "aa".repeat(32);
  var gate = gateOver(fake, { allowMxWrites: true });
  try {
    var tlsaPreview = await gate.preview({
      desired: [{ type: "TLSA", name: TLSA_NAME, content: "3 1 1 " + DIGEST }],
      reason:  "publish the DANE association",
    });
    var tlsaApplied = await gate.apply(tlsaPreview, { reason: "publish the DANE association" });

    function tlsaZone(certHex) {
      var zone = {};
      zone[TLSA_NAME + "|TLSA"] = [{ type: 52, ttl: 60, decoded: {
        usage: 3, selector: 1, matchingType: 1, certData: Buffer.from(certHex, "hex") } }];
      return zone;
    }
    var tlsaAgree = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(tlsaZone(DIGEST)) });
    var tlsaAgreeReport = await tlsaAgree.verify(tlsaApplied, { reason: "check propagation" });
    count("a TLSA answer carrying the written association is agreement",
      tlsaAgreeReport.ok === true,
      JSON.stringify(tlsaAgreeReport.checks.map(function (c) {
        return { verdict: c.verdict, resolver: c.resolverValues };
      })));
    tlsaAgree.close();
    var tlsaOther = gateOver(fake,
      { resolver: dnsZone.pinnedResolverOver(tlsaZone("bb".repeat(32))) });
    var tlsaOtherReport = await tlsaOther.verify(tlsaApplied, { reason: "check propagation" });
    count("a TLSA answer carrying another association is a conflict",
      tlsaOtherReport.conflicts === 1,
      JSON.stringify(tlsaOtherReport.checks.map(function (c) { return c.verdict; })));
    tlsaOther.close();

    // Pruning removes the stale exchanger and keeps the one asked for.
    var mxPreview = await gate.preview({
      desired: [{ type: "MX", name: DOMAIN, content: "mx.example.com", priority: 10 }],
      prune:   true,
      reason:  "remove the stale exchanger",
    });
    var mxApplied = await gate.apply(mxPreview,
      { reason: "remove the stale exchanger", confirm: true });
    count("the prune removes only the stale exchanger",
      mxApplied.written.length === 1 && mxApplied.written[0].action === "delete" &&
      mxApplied.written[0].record.id === STALE, JSON.stringify(mxApplied.written));

    function mxZone(hosts) {
      var zone = {};
      zone[DOMAIN + "|MX"] = hosts.map(function (h) {
        return { type: 15, ttl: 60, decoded: { preference: h[0], exchange: h[1] } };
      });
      return zone;
    }
    var cached = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(
      mxZone([[10, "mx.example.com"], [20, "old-mx.example.com"]])) });
    var cachedReport = await cached.verify(mxApplied, { reason: "check propagation" });
    count("a removal is not agreement while the resolver still answers the removed exchanger",
      cachedReport.ok === false && cachedReport.checks[0].verdict !== "agrees",
      JSON.stringify(cachedReport.checks.map(function (c) {
        return { verdict: c.verdict, resolver: c.resolverValues };
      })));
    cached.close();
    var cleared = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(
      mxZone([[10, "mx.example.com."]])) });
    var clearedReport = await cleared.verify(mxApplied, { reason: "check propagation" });
    count("the removal is agreement once the resolver no longer answers it",
      clearedReport.ok === true,
      JSON.stringify(clearedReport.checks.map(function (c) { return c.verdict; })));
    cleared.close();

    // A removed record whose exchanger a kept record also names, at a
    // different priority. The provider still lists that exchanger, and
    // the removal is confirmed by the removed record being gone rather
    // than by the exchanger disappearing.
    fake.state.records.push({ id: "mxdup000000000000000000000000000", type: "MX",
      name: DOMAIN, content: "mx.example.com", priority: 40, ttl: 300 });
    var dupPreview = await gate.preview({
      desired: [{ type: "MX", name: DOMAIN, content: "mx.example.com", priority: 10 }],
      prune:   true,
      reason:  "remove the duplicate exchanger",
    });
    var dupApplied = await gate.apply(dupPreview,
      { reason: "remove the duplicate exchanger", confirm: true });
    var dupVerifier = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(
      mxZone([[10, "mx.example.com"]])) });
    var dupReport = await dupVerifier.verify(dupApplied, { reason: "check propagation" });
    count("removing one of two records naming the same exchanger is agreement once it is gone",
      dupReport.ok === true,
      JSON.stringify(dupReport.checks.map(function (c) {
        return { verdict: c.verdict, provider: c.providerValues };
      })));
    dupVerifier.close();

    // A written MX record the provider holds at another priority is not
    // the record written, even while a resolver cache still answers the
    // priority that was asked for.
    var newPreview = await gate.preview({
      desired: [
        { type: "MX", name: DOMAIN, content: "mx.example.com", priority: 10 },
        { type: "MX", name: DOMAIN, content: "mx-new.example.com", priority: 15 },
      ],
      reason:  "add a second exchanger",
    });
    var newApplied = await gate.apply(newPreview, { reason: "add a second exchanger" });
    fake.state.records.forEach(function (r) {
      if (r.type === "MX" && r.content === "mx-new.example.com") r.priority = 25;
    });
    var movedVerifier = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(
      mxZone([[10, "mx.example.com"], [15, "mx-new.example.com"]])) });
    var movedReport = await movedVerifier.verify(newApplied, { reason: "check propagation" });
    count("a written MX record the provider holds at another priority is not agreement",
      newApplied.written.length === 1 && movedReport.ok === false &&
        movedReport.checks[0].verdict === "provider-missing",
      JSON.stringify({ written: newApplied.written.length,
        checks: movedReport.checks.map(function (c) {
          return { verdict: c.verdict, provider: c.providerValues };
        }) }));
    movedVerifier.close();
  } finally {
    gate.close();
    fake.close();
  }
}

async function theTokenNeverReachesAnEmittedString() {
  var fake = await startProvider();
  var events = [];

  // Built by hand so the event hook can be attached to the client.
  var client = provider.create({
    readToken:             openToken,
    baseUrl:               fake.baseUrl,
    agent:                 fake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           2,
    onEvent:               function (e) { events.push(JSON.stringify(e)); },
  });
  var live = dns.create({
    domain:      DOMAIN,
    sealedToken: sealedToken,
    vault:       b.vault,
    client:      client,
    resolver:    dnsZone.pinnedResolverOver({}),
  });

  var emitted = [];
  function collect(value) {
    if (value === undefined || value === null) return;
    emitted.push(typeof value === "string" ? value : JSON.stringify(value));
  }

  try {
    var preview = await live.preview({ desired: [dmarcRecord()], reason: "publish DMARC" });
    collect(preview);
    collect(preview.diff);
    var applied = await live.apply(preview, { reason: "publish DMARC" });
    collect(applied);
    var report = await live.verify(applied, { reason: "confirm" });
    collect(report);
    collect(live.allowlist());
    collect(client.state());

    // Every refusal path this run can reach, for their messages.
    var refusals = [
      function () { return live.preview({ desired: [{ type: "A", name: DOMAIN,
        content: "203.0.113.1" }], reason: "refused type" }); },
      function () { return live.apply({ changes: [] }, { reason: "refused preview" }); },
      function () { return live.preview({ desired: [dmarcRecord()] }); },
    ];
    for (var i = 0; i < refusals.length; i += 1) {
      try { await refusals[i](); } catch (e) {
        collect(e.message);
        collect(e.stack);
        collect(String(e));
      }
    }

    // A forced provider failure, whose message quotes the provider.
    fake.state.mode = "unauthorized";
    try {
      await live.preview({ desired: [dmarcRecord("v=DMARC1; p=quarantine")],
        reason: "provoke a provider refusal" });
    } catch (e2) {
      collect(e2.message);
      collect(e2.stack);
      note(e2.code);
    }
    fake.state.mode = "malformed";
    try { await live.preview({ desired: [dmarcRecord()], reason: "provoke a bad envelope" }); }
    catch (e3) { collect(e3.message); collect(e3.stack); note(e3.code); }
    fake.state.mode = "ok";

    // The transport-failure path. It is reached separately because it
    // is the one refusal built while the opened token is still in
    // scope, so it is the one a careless edit can interpolate it into.
    var unreachable = provider.create({
      readToken:             openToken,
      baseUrl:               "https://127.0.0.1:1/client/v4",
      allowInternalEndpoint: true,
      maxAttempts:           1,
      timeoutMs:             2000,
    });
    try { await unreachable.zoneId(DOMAIN); }
    catch (e4) { collect(e4.message); collect(e4.stack); collect(String(e4)); note(e4.code); }
    unreachable.close();

    // And the guarded-endpoint refusal. A loopback address written into
    // the endpoint is refused while the client is built.
    try {
      provider.create({
        readToken:   openToken,
        baseUrl:     fake.baseUrl,
        agent:       fake.agent,
        maxAttempts: 1,
      }).close();
    } catch (e5) { collect(e5.message); collect(e5.stack); note(e5.code); }

    events.forEach(collect);

    // Everything the provider received, minus the one header the token
    // is supposed to travel in.
    fake.state.requests.forEach(function (req) {
      collect(req.body);
      collect(req.path);
      collect(JSON.stringify(req.query));
      var headers = Object.assign({}, req.headers);
      delete headers.authorization;
      collect(JSON.stringify(headers));
    });

    var leaked = emitted.filter(function (text) { return text.indexOf(TOKEN) !== -1; });
    count("the provider token appears in nothing this layer emits",
      leaked.length === 0,
      leaked.length === 0 ? String(emitted.length) + " strings checked"
        : leaked.slice(0, 2).join(" | "));

    // The positive control. Without it this case would also pass if the
    // token were never sent at all, which would prove nothing.
    var authorized = fake.state.requests.filter(function (req) {
      return String(req.headers.authorization || "").indexOf(TOKEN) !== -1;
    });
    count("the token did travel, in the authorization header and only there",
      authorized.length > 0, String(authorized.length) + " authorized requests");

    check("more than a handful of emitted strings were examined", emitted.length > 20);
  } finally {
    live.close();
    client.close();
    fake.close();
  }
}

async function theOutboundScannerRefusesTheTokenInAPayload() {
  var fake = await startProvider();
  var client = provider.create({
    readToken:             openToken,
    baseUrl:               fake.baseUrl,
    agent:                 fake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           1,
  });
  try {
    // The credential in a record value is the shape a leak takes: the
    // request is well formed and the provider would store it.
    await client.zoneId(DOMAIN);
    var refused = await refusalFrom("a record body carrying the token", function () {
      return client.createRecord(ZONE, {
        type: "TXT", name: "_dmarc." + DOMAIN, content: TOKEN,
      });
    });
    count("the outbound scanner refuses the credential inside a payload",
      refused.code === provider.CODES.credentialEgress, refused.code);
    check("no record carrying the token reached the provider",
      !fake.state.records.some(function (r) { return r.content === TOKEN; }));
    check("no request body carrying the token reached the provider",
      !fake.state.requests.some(function (r) { return r.body.indexOf(TOKEN) !== -1; }));
  } finally {
    client.close();
    fake.close();
  }
}

async function anUnsealedCredentialIsRefused() {
  var fake = await startProvider();
  try {
    var refused = await refusalFrom("a token that is not sealed", function () {
      return dns.create({ domain: DOMAIN, sealedToken: TOKEN, vault: b.vault });
    });
    count("a credential that is not sealed is refused rather than used",
      refused.code === dns.CODES.tokenNotSealed, refused.code);

    check("the sealed form carries the framework's authenticated-data seal prefix",
      sealedToken.indexOf(b.vault.aad.AAD_PREFIX) === 0);
    check("the sealed form is not the token", sealedToken.indexOf(TOKEN) === -1);
    check("blamepost.dns.sealToken round-trips through the vault under the token's context",
      openToken() === TOKEN);
    var elsewhere = null;
    try { b.vault.aad.unseal(sealedToken, { purpose: "some-other-purpose" }); }
    catch (e) { elsewhere = e; }
    check("and the token's seal does not open under any other context", elsewhere !== null);

    var doubleSeal = null;
    try { dns.sealToken(sealedToken, b.vault); } catch (e) { doubleSeal = e; }
    check("blamepost.dns.sealToken refuses a value that is already sealed",
      doubleSeal !== null);

    // A vault whose unseal fails is a volume mismatch, and it is
    // reported as itself rather than as a provider problem.
    var brokenVault = {
      aad: {
        seal:   function (v, context) { return b.vault.aad.seal(v, context); },
        unseal: function () { throw new Error("wrong key"); },
      },
    };
    var brokenGate = dns.create({
      domain: DOMAIN, sealedToken: sealedToken, vault: brokenVault,
      resolver: dnsZone.pinnedResolverOver({}),
      clientOptions: { baseUrl: fake.baseUrl, agent: fake.agent,
        allowInternalEndpoint: true, maxAttempts: 1 },
    });
    var unopened = await refusalFrom("a seal that will not open", function () {
      return brokenGate.preview({ desired: [dmarcRecord()], reason: "provoke the seal" });
    });
    count("a seal that will not open is reported as itself",
      unopened.code === dns.CODES.tokenSealUnopened, unopened.code);
    brokenGate.close();
  } finally {
    fake.close();
  }
}

async function theClientFollowsPagingAndRefusesABrokenPager() {
  var many = [];
  for (var i = 0; i < 250; i += 1) {
    many.push({ id: "page" + i + "0000000000000000000000", type: "TXT",
      name: "s" + i + "._domainkey." + DOMAIN, content: "v=DKIM1; p=key" + i, ttl: 300 });
  }
  var fake = await startProvider({ records: many });
  var client = provider.create({
    readToken:             openToken,
    baseUrl:               fake.baseUrl,
    agent:                 fake.agent,
    allowInternalEndpoint: true,
    perPage:               100,
  });
  try {
    var all = await client.listRecords(ZONE, { type: "TXT" });
    count("blamepost.dns.cloudflare.listRecords follows paging to the end",
      all.length === 250, String(all.length) + " records over "
        + String(fake.state.requests.length) + " requests");
    check("paging took more than one request", fake.state.requests.length >= 3);

    // A provider that returns the same page forever would otherwise
    // produce a listing that looks complete and is not.
    fake.state.duplicatePages = true;
    var refused = await refusalFrom("a provider repeating a page", function () {
      return client.listRecords(ZONE, { type: "TXT" });
    });
    count("a repeated record across pages refuses the listing",
      refused.code === provider.CODES.malformedResponse, refused.code);
  } finally {
    client.close();
    fake.close();
  }
}

async function theProviderEnvelopeBecomesANamedRefusal() {
  async function clientOver(fake, opts) {
    return provider.create(Object.assign({
      readToken:             openToken,
      baseUrl:               fake.baseUrl,
      agent:                 fake.agent,
      allowInternalEndpoint: true,
      maxAttempts:           1,
    }, opts || {}));
  }

  var cases = [
    { mode: "unauthorized", expect: provider.CODES.tokenUnverified,
      label: "an invalid token" },
    { mode: "malformed", expect: provider.CODES.malformedResponse,
      label: "an envelope with no success field" },
    { mode: "not-json", expect: provider.CODES.malformedResponse,
      label: "a response that is not JSON" },
    { mode: "empty-body", expect: provider.CODES.malformedResponse,
      label: "an empty body" },
    { mode: "bad-request", expect: provider.CODES.badRequest,
      label: "an unmapped provider refusal" },
  ];

  for (var i = 0; i < cases.length; i += 1) {
    var fake = await startProvider();
    fake.state.mode = cases[i].mode;
    var client = await clientOver(fake);
    var refused = await refusalFrom(cases[i].label, function () {
      return client.zoneId(DOMAIN);
    });
    count("the provider envelope for " + cases[i].label + " becomes a named refusal",
      refused.code === cases[i].expect, refused.code);
    client.close();
    fake.close();
  }

  // A token that reads but cannot write reports on the first write, and
  // it is a different refusal from a token that is not valid at all.
  var scopeFake = await startProvider();
  scopeFake.state.mode = "no-scope";
  var scopeClient = await clientOver(scopeFake);
  var scoped = await refusalFrom("a token without the edit scope", function () {
    return scopeClient.createRecord(ZONE, { type: "TXT", name: "_dmarc." + DOMAIN,
      content: "v=DMARC1" });
  });
  count("a token that cannot write reports the missing scope",
    scoped.code === provider.CODES.tokenScopeMissing, scoped.code);
  scopeClient.close();
  scopeFake.close();

  // A zone the account does not hold, and a name it holds twice.
  var emptyFake = await startProvider({ zones: [] });
  var emptyClient = await clientOver(emptyFake);
  var missing = await refusalFrom("a zone the account does not hold", function () {
    return emptyClient.zoneId(DOMAIN);
  });
  count("a zone the account does not hold is a named refusal",
    missing.code === provider.CODES.zoneNotFound, missing.code);
  emptyClient.close();
  emptyFake.close();

  var twinFake = await startProvider({
    zones: [{ id: ZONE, name: DOMAIN }, { id: "second0000000000000000000000000", name: DOMAIN }],
  });
  var twinClient = await clientOver(twinFake);
  var ambiguous = await refusalFrom("a name held by two zones", function () {
    return twinClient.zoneId(DOMAIN);
  });
  count("a domain matching two zones is refused rather than guessed",
    ambiguous.code === provider.CODES.zoneAmbiguous, ambiguous.code);
  twinClient.close();
  twinFake.close();

  // A delete the provider answers about a different record.
  var wrongFake = await startProvider({
    records: [{ id: "target00000000000000000000000000", type: "TXT",
      name: "_dmarc." + DOMAIN, content: "v=DMARC1", ttl: 300 }],
  });
  wrongFake.state.mode = "wrong-delete-id";
  var wrongClient = await clientOver(wrongFake);
  var wrongDelete = await refusalFrom("a delete answered about another record", function () {
    return wrongClient.deleteRecord(ZONE, "target00000000000000000000000000");
  });
  count("a delete the provider answers about another record is refused",
    wrongDelete.code === provider.CODES.malformedResponse, wrongDelete.code);
  wrongClient.close();
  wrongFake.close();
}

async function transientFailuresAreRetriedAndPermanentOnesAreNot() {
  // A throttled request names an interval, and it is waited out.
  var throttleFake = await startProvider();
  throttleFake.state.throttleLeft = 1;
  var throttleClient = provider.create({
    readToken:             openToken,
    baseUrl:               throttleFake.baseUrl,
    agent:                 throttleFake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           3,
  });
  var startedAt = Date.now();
  var zone = await throttleClient.zoneId(DOMAIN);
  var elapsed = Date.now() - startedAt;
  count("a throttled request is retried and succeeds", zone === ZONE, zone);
  count("the interval the provider named was waited out", elapsed >= 1000,
    String(elapsed) + "ms");
  throttleClient.close();
  throttleFake.close();

  // A throttle that never clears exhausts the attempts and refuses.
  var stuckFake = await startProvider();
  stuckFake.state.throttleLeft = 99;
  var stuckClient = provider.create({
    readToken:             openToken,
    baseUrl:               stuckFake.baseUrl,
    agent:                 stuckFake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           2,
  });
  var throttled = await refusalFrom("a throttle that never clears", function () {
    return stuckClient.zoneId(DOMAIN);
  });
  count("a throttle that never clears refuses after the attempts are spent",
    throttled.code === provider.CODES.rateLimited, throttled.code);
  stuckClient.close();
  stuckFake.close();

  // A failing provider is transient and retried; the refusal names it.
  var downFake = await startProvider();
  downFake.state.serverErrorLeft = 99;
  var downClient = provider.create({
    readToken:             openToken,
    baseUrl:               downFake.baseUrl,
    agent:                 downFake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           2,
  });
  var down = await refusalFrom("a provider that is failing", function () {
    return downClient.zoneId(DOMAIN);
  });
  count("a failing provider is a named, transient refusal",
    down.code === provider.CODES.providerUnavailable, down.code);
  check("a failing provider was retried rather than refused once",
    downFake.state.requests.length >= 2);
  downClient.close();
  downFake.close();

  // A permanent refusal is not retried, which is what keeps a wrong
  // credential from spending the provider's whole request ceiling.
  var authFake = await startProvider();
  authFake.state.mode = "unauthorized";
  var authClient = provider.create({
    readToken:             openToken,
    baseUrl:               authFake.baseUrl,
    agent:                 authFake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           4,
  });
  await refusalFrom("an invalid credential", function () { return authClient.zoneId(DOMAIN); });
  count("a permanent refusal is not retried",
    authFake.state.requests.length === 1, String(authFake.state.requests.length) + " requests");
  authClient.close();
  authFake.close();
}

async function theEndpointItselfIsGuarded() {
  var fake = await startProvider();
  try {
    // The loopback endpoint without the deliberate opt-in is what the
    // outbound guard exists to refuse. Written as an address, it is
    // refused while the client is built, under the code the guard's own
    // refusal on a request carries.
    var refused = await refusalFrom("a private endpoint without the opt-in", function () {
      provider.create({
        readToken: openToken,
        baseUrl:   fake.baseUrl,
        agent:     fake.agent,
        maxAttempts: 1,
      }).close();
    });
    count("a private endpoint is refused unless it is deliberate",
      refused.code === provider.CODES.endpointNotAllowed, refused.code);
    check("and it is refused before a request is sent", fake.state.requests.length === 0);

    // A cleartext endpoint has no opt-in at all, because the credential
    // travels on every request.
    var cleartext = null;
    try {
      provider.create({ readToken: function () { return TOKEN; },
        baseUrl: "http://127.0.0.1:1/client/v4" });
    } catch (e) { cleartext = e; }
    check("a cleartext endpoint is refused at construction",
      cleartext !== null && cleartext instanceof TypeError);

    // Credentials written into the endpoint would reach request logs.
    var userinfo = null;
    try {
      provider.create({ readToken: function () { return TOKEN; },
        baseUrl: "https://user:secret@api.example.com/client/v4" });
    } catch (e2) { userinfo = e2; }
    check("an endpoint carrying credentials is refused at construction",
      userinfo !== null && userinfo instanceof TypeError);

    // A closed port is a request that did not complete.
    var deadClient = provider.create({
      readToken:             openToken,
      baseUrl:               "https://127.0.0.1:1/client/v4",
      allowInternalEndpoint: true,
      maxAttempts:           1,
      timeoutMs:             2000,
    });
    var dead = await refusalFrom("a provider that is not listening", function () {
      return deadClient.zoneId(DOMAIN);
    });
    count("a provider that cannot be reached is a named refusal",
      dead.code === provider.CODES.requestFailed, dead.code);
    deadClient.close();
  } finally {
    fake.close();
  }
}

async function aPartlyWrittenChangeSetIsReportedAsItself() {
  var fake = await startProvider();
  var gate = gateOver(fake);
  try {
    var preview = await gate.preview({
      desired: [dmarcRecord(), { type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
      reason:  "publish the posture records",
    });
    check("the set has two changes to fail between", preview.changes.length === 2);

    var originalRecords = fake.state.records.length;

    // The first write lands and the second refuses permanently, which
    // is the shape that leaves a zone holding half a change. A
    // transient failure would not: the client retries it and the set
    // completes, which is the whole point of telling the two apart.
    fake.state.onWrite = function (n) {
      return n === 1 ? null
        : { status: 403, body: fail(9109, "Unauthorized to access requested resource") };
    };

    var incomplete = await refusalFrom("a change set that fails partway", function () {
      return gate.apply(preview, { reason: "publish the posture records", confirm: true });
    });
    count("a partly written change set is reported as itself",
      incomplete.code === dns.CODES.writeIncomplete, incomplete.code);
    check("the refusal says what was written and what was not",
      incomplete.message.indexOf(" of ") !== -1);
    check("the zone did change, which is why the refusal has to say so",
      fake.state.records.length > originalRecords);
  } finally {
    gate.close();
    fake.close();
  }
}

async function badShapesAndOversizedSetsAreRefused() {
  var fake = await startProvider();
  var gate = gateOver(fake, { maxChanges: 2 });
  try {
    var tooMany = await refusalFrom("a change set past the ceiling", function () {
      return gate.preview({
        desired: [
          dmarcRecord(),
          { type: "TXT", name: DOMAIN, content: "v=spf1 -all" },
          { type: "TXT", name: "_mta-sts." + DOMAIN, content: "v=STSv1; id=1" },
        ],
        reason: "attempt an oversized set",
      });
    });
    count("a change set past the ceiling is refused",
      tooMany.code === dns.CODES.tooManyChanges, tooMany.code);

    var shapes = [
      { desired: [{ type: "TXT", name: "_dmarc." + DOMAIN }], label: "no value" },
      { desired: [{ type: "TXT", content: "v=DMARC1" }], label: "no address" },
      { desired: [{ name: "_dmarc." + DOMAIN, content: "v=DMARC1" }], label: "no type" },
      { desired: [{ type: "TXT", name: "_dmarc." + DOMAIN, content: "v=DMARC1", ttl: 5 }],
        label: "a lifetime below the floor" },
      { desired: [{ type: "TXT", name: "_dmarc." + DOMAIN, content: "v=DMARC1", ttl: 1e9 }],
        label: "a lifetime past the ceiling" },
      { desired: [{ type: "TXT", name: "_dmarc." + DOMAIN,
        content: new Array(5000).join("x") }], label: "an oversized value" },
      { desired: ["not a record"], label: "something that is not a record" },
    ];
    for (var i = 0; i < shapes.length; i += 1) {
      var refused = await refusalFrom(shapes[i].label, (function (spec) {
        return function () {
          return gate.preview({ desired: spec.desired, reason: "attempt " + spec.label });
        };
      })(shapes[i]));
      check("a record with " + shapes[i].label + " is refused",
        refused.code === dns.CODES.badRecord);
    }
    check("no bad shape reached the provider as a write", fake.writes().length === 0);
  } finally {
    gate.close();
    fake.close();
  }
}

// The ceiling is stated as a bound on the change SET, and a change set
// is what gets written. Counting the records a caller asked for answers
// for one half of it: pruning turns a single desired record into one
// write plus a removal for every extra the address is holding, so a set
// naming one record can carry any number of changes and pass a check
// that only ever read the one.
//
// The same reading is what `apply` needs, and for a second reason. A
// preview is an ordinary object a caller can build, so a bound checked
// only where the set is computed is a bound the write path never applies
// at all.
async function theCeilingCountsTheChangesRatherThanTheRecordsAskedFor() {
  var CEILING = 5;
  var HELD    = 9;
  var seeded  = [];
  for (var i = 0; i < HELD; i += 1) {
    seeded.push({
      id:      "extra" + String(i) + new Array(32 - 6 - String(i).length).join("0"),
      type:    "TXT",
      name:    "_dmarc." + DOMAIN,
      content: "v=DMARC1; p=none; rf=" + i,
      ttl:     300,
    });
  }
  var fake = await startProvider({ records: seeded });
  var gate = gateOver(fake, { maxChanges: CEILING });
  try {
    var refused = await refusalFrom("a prune past the ceiling", function () {
      return gate.preview({
        desired: [dmarcRecord("v=DMARC1; p=reject")],
        reason:  "reduce a crowded DMARC address to one record",
        prune:   true,
      });
    });
    count("a change set carrying more changes than the ceiling is refused, even when it " +
      "names one record", refused.code === dns.CODES.tooManyChanges, refused.code);
    check("the refusal names how many changes the set carried",
      refused.message.indexOf(String(HELD)) !== -1);
    check("nothing was written while the ceiling was refusing", fake.writes().length === 0);

    // The other end of the same bound. A preview is an ordinary object,
    // so a set handed straight to `apply` has to meet the ceiling there
    // as well: a check that lives only where the set is computed is one
    // the write path never runs.
    var underCeiling = await gate.preview({
      desired: [dmarcRecord("v=DMARC1; p=reject")],
      reason:  "settle the DMARC record without pruning",
    });
    var oversized = Object.assign({}, underCeiling, {
      changes: seeded.map(function (row) {
        return { action: "delete", type: "TXT", name: row.name,
          before: row, after: null, recordId: row.id };
      }),
    });
    var atApply = await refusalFrom("an oversized set handed to apply", function () {
      return gate.apply(oversized,
        { reason: "attempt an oversized set at the write", confirm: true });
    });
    count("apply refuses a change set past the ceiling rather than performing it",
      atApply.code === dns.CODES.tooManyChanges, atApply.code);
    check("and nothing reached the provider as a write",
      fake.writes().length === 0);
  } finally {
    gate.close();
    fake.close();
  }
}

async function theAllowlistIsReadableAndPruningRemovesWhatIsNotWanted() {
  var fake = await startProvider({
    records: [
      { id: "stale000000000000000000000000000", type: "TXT", name: DOMAIN,
        content: "v=spf1 include:old.example -all", ttl: 300 },
    ],
  });
  var gate = gateOver(fake);
  try {
    var list = gate.allowlist();
    check("blamepost.dns.allowlist names the domain it governs", list.domain === DOMAIN);
    check("blamepost.dns.allowlist reports the types it writes",
      list.types.indexOf("TXT") !== -1 && list.types.indexOf("A") === -1);
    check("blamepost.dns.allowlist describes each address in words",
      list.addresses.length > 0 && list.addresses.every(function (a) {
        return typeof a.describes === "string" && a.describes.length > 0;
      }));

    var preview = await gate.preview({
      desired: [{ type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
      reason:  "replace the sender policy",
    });
    count("replacing a record in place is an update rather than a create",
      preview.changes.length === 1 && preview.changes[0].action === "update",
      preview.diff);
    check("the diff shows what the address is holding now",
      preview.diff.indexOf("holding") !== -1);

    var applied = await gate.apply(preview, { reason: "replace the sender policy" });
    check("the replacement was written", applied.written.length === 1);
    check("the zone holds one policy record, not two",
      fake.state.records.filter(function (r) {
        return r.name === DOMAIN && r.type === "TXT";
      }).length === 1);
  } finally {
    gate.close();
    fake.close();
  }
}

async function pruningRemovesTheExtrasAndNothingElse() {
  // An apex holding two sender policies is a permanent error to every
  // receiver that reads it, so reducing it to one is the case pruning
  // exists for. The apex is also where a domain verification record
  // put there by somebody else lives, and that one has to survive, so
  // both are in the zone at once and the run measures which went.
  var fake = await startProvider({
    records: [
      { id: "spfold00000000000000000000000000", type: "TXT", name: DOMAIN,
        content: "v=spf1 include:old.example -all", ttl: 300 },
      { id: "spfnew00000000000000000000000000", type: "TXT", name: DOMAIN,
        content: "v=spf1 -all", ttl: 300 },
      { id: "verify00000000000000000000000000", type: "TXT", name: DOMAIN,
        content: "some-vendor-site-verification=abc123", ttl: 300 },
      { id: "dmarcnow000000000000000000000000", type: "TXT", name: "_dmarc." + DOMAIN,
        content: "v=DMARC1; p=none", ttl: 300 },
    ],
  });
  var gate = gateOver(fake);
  try {
    var withoutPrune = await gate.preview({
      desired: [{ type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
      reason:  "settle the sender policy without pruning",
    });
    count("without pruning an address holding extras is left as it is",
      withoutPrune.changes.length === 0, withoutPrune.diff);

    var preview = await gate.preview({
      desired: [{ type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
      reason:  "reduce the apex to one sender policy",
      prune:   true,
    });
    var deletes = preview.changes.filter(function (c) { return c.action === "delete"; });
    count("pruning removes the extra sender policy at the address it was given, and not the " +
      "verification record beside it",
      deletes.length === 1 && deletes[0].recordId === "spfold00000000000000000000000000",
      preview.diff);

    var applied = await gate.apply(preview,
      { reason: "reduce the apex to one sender policy", confirm: true });
    check("the removal was written", applied.written.length === 1);

    var apexNow = fake.state.records.filter(function (r) {
      return r.name === DOMAIN && r.type === "TXT";
    });
    var policies = apexNow.filter(function (r) { return r.content.indexOf("v=spf1") === 0; });
    count("the apex is left holding exactly the policy that was asked for",
      policies.length === 1 && policies[0].content === "v=spf1 -all",
      JSON.stringify(apexNow.map(function (r) { return r.content; })));
    count("and the verification record somebody else put there is still beside it",
      apexNow.some(function (r) { return r.id === "verify00000000000000000000000000"; }),
      JSON.stringify(apexNow.map(function (r) { return r.content; })));

    // The address the change set never named has to survive, and the
    // mechanism that saves it is that pruning never READS it: the
    // addresses a preview looks at come from the change set alone.
    // Asserting the record is still there would pass whether or not
    // that holds, because a preview that read it and spared it looks
    // identical from the zone. So the question asked is whether the
    // provider was ever asked about that address at all.
    check("an address the change set is silent about keeps its records",
      fake.state.records.some(function (r) {
        return r.name === "_dmarc." + DOMAIN && r.content === "v=DMARC1; p=none";
      }));
    var askedAbout = fake.state.requests.filter(function (req) {
      return req.query && req.query.name === "_dmarc." + DOMAIN;
    });
    count("pruning never read the address the change set was silent about",
      askedAbout.length === 0, String(askedAbout.length) + " reads of that address");

    // A second policy record appears at an address the change set does
    // name, so pruning it is a single removal. One removal is still a
    // removal, which is what the confirmation is asked for.
    fake.state.records.push({ id: "dmarcdupe00000000000000000000000", type: "TXT",
      name: "_dmarc." + DOMAIN, content: "v=DMARC1; p=quarantine", ttl: 300 });

    var single = await gate.preview({
      desired: [{ type: "TXT", name: "_dmarc." + DOMAIN, content: "v=DMARC1; p=none" }],
      reason:  "reduce the DMARC record to one",
      prune:   true,
    });
    var singleDeletes = single.changes.filter(function (c) { return c.action === "delete"; });
    count("pruning one extra record is one removal",
      single.changes.length === 1 && singleDeletes.length === 1, single.diff);

    var bulk = await refusalFrom("a removal without confirmation", function () {
      return gate.apply(single, { reason: "reduce the DMARC record to one" });
    });
    check("a change set that removes a record takes confirmation, even at one",
      bulk.code === dns.CODES.confirmRequired);
    check("nothing was removed while confirmation was missing",
      fake.state.records.some(function (r) { return r.id === "dmarcdupe00000000000000000000000"; }));
  } finally {
    gate.close();
    fake.close();
  }
}

async function theCredentialAnswersForItselfBeforeAWrite() {
  // blamepost.dns.cloudflare.verifyToken exists so a revoked or
  // mistyped credential is reported as itself, rather than as whatever
  // the first record call happens to fail with. A token that verifies
  // is still not a token that may write, which is a separate refusal
  // and a separate message.
  var fake = await startProvider();
  var client = provider.create({
    readToken:             openToken,
    baseUrl:               fake.baseUrl,
    agent:                 fake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           1,
  });
  try {
    var live = await client.verifyToken();
    count("blamepost.dns.cloudflare.verifyToken reports a live credential",
      live.active === true, JSON.stringify(live));

    fake.state.mode = "inactive";
    var dead = await refusalFrom("a credential the provider has disabled", function () {
      return client.verifyToken();
    });
    count("blamepost.dns.cloudflare.verifyToken refuses a credential that is not active",
      dead.code === provider.CODES.tokenUnverified, dead.code);
    check("the refusal tells the operator to issue a replacement",
      dead.message.indexOf("replacement") !== -1);

    fake.state.mode = "malformed";
    var shapeless = await refusalFrom("a verification with no result", function () {
      return client.verifyToken();
    });
    check("a verification response with no result object is refused",
      shapeless.code === provider.CODES.malformedResponse);
  } finally {
    client.close();
    fake.close();
  }
}

// The provider can answer a TXT record in its zone-file form: quoted,
// and split into character-strings of at most 255 octets. The gate reads
// the text those strings carry, so a published record matches the same
// record asked for again, and verification compares like with like.
async function quotedTxtContentReadsAsTheTextItCarries() {
  var fake = await startProvider({
    records: [
      { id: "dmarcquoted000000000000000000000", type: "TXT", name: "_dmarc." + DOMAIN,
        content: "\"v=DMARC1; \" \"p=reject\"", ttl: 300 },
    ],
  });
  var agreeZone = {};
  agreeZone["_dmarc." + DOMAIN + "|TXT"] = [
    { type: 16, decoded: ["v=DMARC1; p=reject"], ttl: 60 },
  ];
  var gate = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(agreeZone) });
  try {
    var preview = await gate.preview({ desired: [dmarcRecord()], reason: "confirm DMARC" });
    count("a quoted, split TXT record holding the asked-for text previews as no change",
      preview.changes.length === 0, preview.diff);

    var changed = await gate.preview({
      desired: [dmarcRecord("v=DMARC1; p=quarantine")], reason: "change DMARC" });
    count("and a different policy updates that record rather than adding a second one",
      changed.changes.length === 1 && changed.changes[0].action === "update" &&
      changed.changes[0].before.content === "v=DMARC1; p=reject",
      JSON.stringify(changed.changes));
    var applied = await gate.apply(changed, { reason: "change DMARC", confirm: true });
    fake.state.records.forEach(function (r) {
      if (r.type === "TXT") r.content = "\"" + r.content + "\"";
    });
    var updatedZone = {};
    updatedZone["_dmarc." + DOMAIN + "|TXT"] = [
      { type: 16, decoded: ["v=DMARC1; p=quarantine"], ttl: 60 },
    ];
    var verifier = gateOver(fake, { resolver: dnsZone.pinnedResolverOver(updatedZone) });
    var report = await verifier.verify(applied, { reason: "check propagation" });
    count("verification reads the quoted provider value as the text the resolver answers",
      report.ok === true, JSON.stringify(report.checks.map(function (c) {
        return { verdict: c.verdict, provider: c.providerValues, resolver: c.resolverValues };
      })));
    verifier.close();
  } finally {
    gate.close();
    fake.close();
  }
}

async function aRecordThatMovedUnderTheProviderIsNamed() {
  // The two answers a provider gives about a record that is not where
  // the change set expected it. Both mean the same thing to an
  // operator, which is that the preview is stale, and both have to say
  // so rather than arriving as an unclassified refusal.
  var fake = await startProvider();
  var client = provider.create({
    readToken:             openToken,
    baseUrl:               fake.baseUrl,
    agent:                 fake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           1,
  });
  try {
    var missing = await refusalFrom("a record the provider no longer holds", function () {
      return client.deleteRecord(ZONE, "vanished000000000000000000000000");
    });
    count("a record the provider no longer holds is a named refusal",
      missing.code === provider.CODES.recordNotFound, missing.code);

    var updateMissing = await refusalFrom("an update of a vanished record", function () {
      return client.updateRecord(ZONE, "vanished000000000000000000000000",
        { type: "TXT", name: "_dmarc." + DOMAIN, content: "v=DMARC1" });
    });
    check("an update of a vanished record reports the same way",
      updateMissing.code === provider.CODES.recordNotFound);

    fake.state.mode = "record-conflict";
    var conflict = await refusalFrom("a create the provider already holds", function () {
      return client.createRecord(ZONE, { type: "TXT", name: "_dmarc." + DOMAIN,
        content: "v=DMARC1" });
    });
    count("a record the provider already holds is a named refusal",
      conflict.code === provider.CODES.recordConflict, conflict.code);
    check("the refusal tells the operator to preview again",
      conflict.message.indexOf("preview again") !== -1);
  } finally {
    client.close();
    fake.close();
  }
}

// ---- the configuration that decides whether any of this exists -------------

// One loaded configuration, built the way a server's is rather than by
// hand, so what the wiring reads is the shape `config.load` produces. A
// case that assembled the object itself would prove the reader agrees
// with the test's idea of a configuration and nothing about the loader.
function loadedConfig(root, dataDir, extra) {
  return configModule.load({
    env: Object.assign({
      BLAMEPOST_HOSTNAME:         "mx." + DOMAIN,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: "a long enough vault passphrase for one test run",
    }, extra || {}),
    cwd: root,
  });
}

// Whether a zone writer exists at all is the configuration's answer, and
// the two answers are a handle and nothing.
//
// The absent one is the shipped default and the one worth measuring: an
// operator who set nothing gets no credential opened, no provider client
// built and no request sent. A stand-in provider is running for the
// whole case, so "nothing was sent" is read off what it received rather
// than assumed from a null.
async function theConfigurationDecidesWhetherAWriterExistsAtAll() {
  var fake = await startProvider();
  var root    = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-zone-cfg-"));
  var dataDir = nodePath.join(root, "data");
  try {
    // ---- the default: no writer, and nothing on the wire ----
    var quiet = loadedConfig(root, dataDir);
    var absent = dns.fromConfig(quiet);
    count("a configuration naming no provider builds no zone writer at all",
      absent === null, String(absent));
    count("and nothing reached a provider while it was being decided",
      fake.state.requests.length === 0, fake.state.requests.length + " request(s)");

    // ---- a provider named with no credential anywhere ----
    var starved = loadedConfig(root, dataDir, { BLAMEPOST_ZONE_PROVIDER: "cloudflare" });
    var noToken = await refusalFrom("a provider named with no token", function () {
      return dns.fromConfig(starved);
    });
    count("naming a provider with no credential refuses at assembly rather than starting a " +
      "writer that cannot write", noToken.code === dns.CODES.noToken, noToken.code);
    count("and the refusal names the command that installs one",
      String(noToken.message).indexOf("blamepost zone token set") !== -1,
      String(noToken.message).slice(0, 200));

    // ---- a provider this server does not speak to ----
    //
    // The setting table refuses an unrecognized value on its own, so
    // this drives a configuration assembled by hand, which is the only
    // way one reaches the reader. A reader that trusted the loader would
    // be a reader with no answer for its other caller.
    var invented = await refusalFrom("a provider nothing here speaks to", function () {
      return dns.fromConfig({ zoneProvider: "route53", dataDir: dataDir,
        paths: { keys: nodePath.join(dataDir, "keys") } });
    });
    count("a provider this server does not speak to is refused by name",
      invented.code === dns.CODES.noProvider, invented.code);

    // ---- the credential on the volume ----
    var path = dns.tokenPath(starved);
    count("the sealed token is kept in the keys folder, beside the sealed DKIM private keys",
      path === nodePath.join(dataDir, "keys", "zone-token.sealed"), path);

    var emptyClear = dns.clearToken(starved);
    count("clearing a volume that holds no token says so rather than reporting a removal",
      emptyClear.removed === false && emptyClear.path === path, JSON.stringify(emptyClear));

    await dns.storeToken(starved, TOKEN, { vault: b.vault });
    var onDisk = nodeFs.readFileSync(path, "utf8");
    count("what reaches disk is the sealed form and not the token",
      onDisk.indexOf(TOKEN) === -1 && onDisk.indexOf(b.vault.aad.AAD_PREFIX) === 0,
      onDisk.slice(0, 24));
    count("and it opens back to the credential that was handed in",
      b.vault.aad.unseal(onDisk.trim(), TOKEN_SEAL_CONTEXT) === TOKEN);

    // ---- the writer the volume's credential builds ----
    var wired = dns.fromConfig(starved, { vault: b.vault });
    count("a provider and a sealed token on the volume build a writer",
      wired !== null && wired.provider === "cloudflare",
      wired === null ? "null" : wired.provider);
    var shape = wired.describe();
    count("and it reports where the credential came from without reporting the credential",
      shape.tokenSource === "volume" && shape.tokenPath === path &&
      JSON.stringify(shape).indexOf(TOKEN) === -1, JSON.stringify(shape));
    count("and the endpoint it will send to is the provider's public API when none is named",
      shape.endpoint === provider.DEFAULT_BASE_URL, shape.endpoint);

    // The same reading with a client the caller built. `doctor` and the
    // operator interface render what `describe` answers, so a value here
    // is read as the value in force. A supplied client is taken as it
    // stands and the endpoint options this handle holds shape nothing, so
    // reporting them would name an endpoint no request goes to and a
    // policy this handle never applied. The case above cannot catch that:
    // it names no client, which is the one arrangement where the option
    // and the client agree.
    var ownFake = await startProvider();
    try {
      var ownClient = provider.create({
        baseUrl:               ownFake.baseUrl,
        agent:                 ownFake.agent,
        allowInternalEndpoint: true,
        readToken:             function () { return TOKEN; },
      });
      var supplied = dns.fromConfig(starved, { vault: b.vault, client: ownClient });
      var told     = supplied.describe();
      var inForce  = ownClient.state().endpoint;
      count("a handle given a client reports the endpoint that client sends to",
        told.endpoint === inForce, told.endpoint + " against " + inForce);
      count("and it does not claim an endpoint policy it never applied",
        told.allowInternalEndpoint === null, String(told.allowInternalEndpoint));
      supplied.close();
      ownClient.close();
    } finally {
      ownFake.close();
    }

    // The MX switch, read off the WIRED gate rather than off a gate this
    // case built for itself. The module's own default is covered
    // elsewhere; what is asked here is whether the wiring carries it,
    // which is the half that goes wrong when a configuration key is
    // added and never passed on.
    var mxGate = wired.forDomain(DOMAIN);
    count("the MX switch is off on a gate the configuration built, not only on one built by " +
      "hand", mxGate.allowlist().allowMxWrites === false,
      JSON.stringify(mxGate.allowlist()));
    var mxRefused = await refusalFrom("an MX write through the wired gate", function () {
      return mxGate.preview({
        desired: [{ type: "MX", name: DOMAIN, content: "mx." + DOMAIN, priority: 10 }],
        reason:  "attempt to repoint delivery through the wired gate",
      });
    });
    count("and a wired gate refuses an MX write with the switch off",
      mxRefused.code === dns.CODES.mxWriteDisabled, mxRefused.code);
    wired.close();

    // And the other edge, so the check above is measuring the switch
    // rather than a gate that refuses everything.
    var permitted = dns.fromConfig(
      loadedConfig(root, dataDir, {
        BLAMEPOST_ZONE_PROVIDER:        "cloudflare",
        BLAMEPOST_ZONE_ALLOW_MX_WRITES: "true",
      }), { vault: b.vault });
    count("and it is on when the operator turns it on, through the same wiring",
      permitted.forDomain(DOMAIN).allowlist().allowMxWrites === true);
    permitted.close();

    // ---- one credential per run ----
    var sealedInConfig = loadedConfig(root, dataDir, {
      BLAMEPOST_ZONE_PROVIDER:  "cloudflare",
      BLAMEPOST_ZONE_API_TOKEN: sealedToken,
    });
    var doubled = await refusalFrom("a credential supplied twice", function () {
      return dns.fromConfig(sealedInConfig, { vault: b.vault });
    });
    count("a credential in the configuration and on the volume at once is refused rather " +
      "than resolved by precedence",
      doubled.code === dns.CODES.tokenTwoSources, doubled.code);
    count("and the refusal names the file, so the operator knows which of the two to erase",
      String(doubled.message).indexOf(path) !== -1, String(doubled.message).slice(0, 220));

    // ---- an unsealed credential on the volume ----
    nodeFs.writeFileSync(path, TOKEN, "utf8");
    var raw = await refusalFrom("an unsealed token on the volume", function () {
      return dns.fromConfig(starved, { vault: b.vault });
    });
    count("a token sitting unsealed on the volume is refused at assembly, not at the first " +
      "write", raw.code === dns.CODES.tokenNotSealed, raw.code);
    count("and the operator is told to treat it as exposed rather than to reseal it",
      String(raw.message).indexOf("exposed") !== -1, String(raw.message).slice(0, 220));

    var cleared = dns.clearToken(starved);
    count("clearing erases the file and says it did", cleared.removed === true &&
      !b.atomicFile.exists(path), JSON.stringify(cleared));

    // ---- the configuration's credential, used over the wire ----
    //
    // The sealed value in the configuration is the other supported
    // source, and a source that is validated and never used is the
    // defect this whole file is about. So it builds a gate and that gate
    // performs a real preview against the stand-in provider.
    var fromSetting = dns.fromConfig(sealedInConfig, {
      vault:    b.vault,
      resolver: dnsZone.pinnedResolverOver({}),
      client:   provider.create({
        readToken:             openToken,
        baseUrl:               fake.baseUrl,
        agent:                 fake.agent,
        allowInternalEndpoint: true,
        maxAttempts:           2,
      }),
    });
    count("the sealed value in the configuration is the other source, and it is read",
      fromSetting.describe().tokenSource === "configuration" &&
      fromSetting.describe().tokenPath === null,
      JSON.stringify(fromSetting.describe()));
    var previewed = await fromSetting.forDomain(DOMAIN).preview({
      desired: [dmarcRecord()],
      reason:  "prove the wired credential reaches the provider",
    });
    count("and a gate the configuration built reaches the provider and computes a change",
      previewed.changes.length === 1 && fake.writes().length === 0,
      previewed.diff + " / " + fake.writes().length + " write(s)");
    fromSetting.close();
  } finally {
    fake.close();
    // Drop-silent by design: a temporary directory that outlives the run
    // must never mask the assertion that failed inside it.
    try { nodeFs.rmSync(root, { recursive: true, force: true }); }
    catch (_e) { /* the OS reclaims it */ }
  }
}

async function everyPublishedRefusalCodeWasReached() {
  var published = [];
  Object.keys(dns.CODES).forEach(function (k) { published.push(dns.CODES[k]); });
  Object.keys(provider.CODES).forEach(function (k) { published.push(provider.CODES[k]); });

  var unreached = published.filter(function (code) { return observedCodes[code] !== true; });
  count("every refusal code the two modules publish was reached by this run",
    unreached.length === 0,
    unreached.length === 0 ? String(published.length) + " codes"
      : "never reached: " + unreached.join(", "));

  // The set is published so a caller can branch on it, which is only
  // worth anything if it is complete in the other direction too.
  var stray = Object.keys(observedCodes).filter(function (code) {
    return code.indexOf("zone/") === 0 && published.indexOf(code) === -1;
  });
  count("no refusal was raised under a code the published set does not hold",
    stray.length === 0, stray.length === 0 ? "none" : stray.join(", "));
}

// ---- runner ----------------------------------------------------------------

var CASES = [
  theGateRefusesWhatIsOutsideItsAllowlist,
  theMxSwitchIsOffUntilAnOperatorTurnsItOn,
  severalRecordsAtOneNameEachTakeTheirOwnTarget,
  previewWritesNothingAndApplyWritesWhatItShowed,
  applyRefusesAZoneThatMovedUnderneathThePreview,
  applyRefusesAnythingThatIsNotItsOwnPreview,
  everyWriteCarriesAReasonAndBulkTakesConfirmation,
  verifyReportsWhenTheProviderAndTheResolverDisagree,
  verifyReadsMxAndTlsaAnswersByTheirFields,
  theTokenNeverReachesAnEmittedString,
  theOutboundScannerRefusesTheTokenInAPayload,
  anUnsealedCredentialIsRefused,
  theClientFollowsPagingAndRefusesABrokenPager,
  theProviderEnvelopeBecomesANamedRefusal,
  transientFailuresAreRetriedAndPermanentOnesAreNot,
  theEndpointItselfIsGuarded,
  aPartlyWrittenChangeSetIsReportedAsItself,
  badShapesAndOversizedSetsAreRefused,
  theCeilingCountsTheChangesRatherThanTheRecordsAskedFor,
  theAllowlistIsReadableAndPruningRemovesWhatIsNotWanted,
  pruningRemovesTheExtrasAndNothingElse,
  theCredentialAnswersForItselfBeforeAWrite,
  quotedTxtContentReadsAsTheTextItCarries,
  aRecordThatMovedUnderTheProviderIsNamed,
  theConfigurationDecidesWhetherAWriterExistsAtAll,
  everyPublishedRefusalCodeWasReached,
];

async function run() {
  await ensureVault();
  for (var i = 0; i < CASES.length; i += 1) {
    if (process.env.DNS_GATE_TRACE === "1") {
      console.log("  case " + CASES[i].name);
    }
    await CASES[i]();
  }
  return helpers.getChecks();
}

module.exports = { name: "dns-write-gate", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
