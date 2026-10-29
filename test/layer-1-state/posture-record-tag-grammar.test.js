// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The posture report and the verifier read one published record the
 * same way.
 *
 * RFC 6376 §3.2 lets folding whitespace sit around the `=` of a tag,
 * and §3.6.1 says whitespace inside the base64 of `p=` is ignored. A
 * DNS provider that wraps a long value, and an operator who pastes the
 * key across two lines, both publish a record every receiver accepts.
 *
 * This server reads that record in two places. `b.mail.dkim.verify`
 * takes it apart with the framework's tag-list parser, so a signature
 * against it passes. `blamepost doctor` compares the `p=` tag of the
 * published record against the `p=` tag of the record it tells the
 * operator to publish, and a reader that keeps the whitespace makes
 * those two strings differ. The report then says the published key does
 * not match the private key this server signs with, and points the
 * operator at a truncated paste, for a record that is signing mail
 * correctly.
 *
 * Both readings are settled here against one zone: the verifier accepts
 * the record, so the report has to as well.
 *
 * Run standalone: node test/layer-1-state/posture-record-tag-grammar.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers    = require("../helpers");
var zone       = require("../helpers/dns-zone");
var config     = require("../../lib/config");
var store      = require("../../lib/store");
var dkimMod    = require("../../lib/mail/dkim");
var postureMod = require("../../lib/mail/posture");

var b = helpers.b;

var HOSTNAME = "mx.example.com";
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var DOMAIN = "folded-record.example.com";

var count = helpers.count;

// Put folding whitespace inside the base64 of the p= tag, the way a
// provider that wraps a long value does. The key itself is untouched:
// every octet of it is still there and still in order.
function foldPublicKey(record) {
  var at = record.indexOf("p=");
  if (at === -1) return record;
  var head = record.slice(0, at + 2);
  var key  = record.slice(at + 2);
  var cut  = Math.min(20, key.length);
  return head + key.slice(0, cut) + " " + key.slice(cut);
}

// The same record with the whitespace around the `=` of a tag rather
// than inside the value, which RFC 6376 §3.2 also allows.
function spaceAroundEquals(record) {
  var at = record.indexOf("; p=");
  if (at === -1) return record;
  return record.slice(0, at) + "; p = " + record.slice(at + 4);
}

async function theVerifierAcceptsAFoldedRecord(dkim, identity) {
  var published = dkim.dnsRecords(DOMAIN);
  count("the domain publishes a selector pair to check", published.length === 2,
    "records " + published.length);

  var folded = published.map(function (rec) {
    return { name: rec.dnsName, txt: [foldPublicKey(rec.dnsTxtValue)] };
  });
  count("and the folded record really does differ from the canonical one",
    folded[0].txt[0] !== published[0].dnsTxtValue, folded[0].txt[0].slice(0, 90));

  var signer = await dkim.signerFor(DOMAIN);
  var message = "From: a@" + DOMAIN + "\r\n" +
    "To: b@example.net\r\n" +
    "Subject: folded record\r\n" +
    "Date: Tue, 1 Sep 2026 07:05:09 +0000\r\n" +
    "Message-ID: <folded@" + DOMAIN + ">\r\n" +
    "\r\n" +
    "body\r\n";
  var signed = await signer.sign(Buffer.from(message, "utf8"));

  var records = {};
  folded.forEach(function (entry) { records[entry.name] = { txt: entry.txt }; });
  var results = await b.mail.dkim.verify(signed, { dnsLookup: zone.lookupOver(records) });
  var passed = results.filter(function (r) { return r.result === "pass"; });
  count("the framework verifier passes every signature against the folded record",
    passed.length === results.length && results.length > 0,
    zone.summarize(results));

  return { published: published, folded: folded, identity: identity };
}

async function theReportAcceptsTheSameFoldedRecord(dkim, published, folded) {
  var records = {};
  records[DOMAIN] = {
    txt: ["v=spf1 -all"],
    mx:  [HOSTNAME],
  };
  records["_dmarc." + DOMAIN] = { txt: ["v=DMARC1; p=reject"] };
  folded.forEach(function (entry) { records[entry.name] = { txt: entry.txt }; });

  var posture = postureMod.create({
    hostname: HOSTNAME,
    resolver: zone.resolverOver(records),
    dkim:     dkim,
  });
  var report = await posture.check({ domains: [DOMAIN] });
  var domainReport = report.domains.filter(function (d) { return d.domain === DOMAIN; })[0];
  var dkimFindings = (domainReport ? domainReport.findings : []).filter(function (f) {
    return f.record === "DKIM";
  });

  count("the report checks both selector records", dkimFindings.length === 2,
    "findings " + dkimFindings.length);
  var failed = dkimFindings.filter(function (f) { return !f.ok; });
  count("and reports the folded record as matching the key it signs with",
    failed.length === 0,
    failed.length > 0 ? String(failed[0].detail).slice(0, 160) : "all matched");
}

async function theReportAcceptsWhitespaceAroundTheEquals(dkim, published) {
  var records = {};
  records[DOMAIN] = { txt: ["v=spf1 -all"], mx: [HOSTNAME] };
  records["_dmarc." + DOMAIN] = { txt: ["v=DMARC1; p=reject"] };
  published.forEach(function (rec) {
    records[rec.dnsName] = { txt: [spaceAroundEquals(rec.dnsTxtValue)] };
  });

  var posture = postureMod.create({
    hostname: HOSTNAME,
    resolver: zone.resolverOver(records),
    dkim:     dkim,
  });
  var report = await posture.check({ domains: [DOMAIN] });
  var domainReport = report.domains.filter(function (d) { return d.domain === DOMAIN; })[0];
  var failed = (domainReport ? domainReport.findings : []).filter(function (f) {
    return f.record === "DKIM" && !f.ok;
  });
  count("a record with whitespace around the tag's equals also reads as matching",
    failed.length === 0,
    failed.length > 0 ? String(failed[0].detail).slice(0, 160) : "all matched");
}

// The verifier accepts an uppercase tag name, so the report has to as
// well. Which of the two readings is the stricter one is not the
// question this settles: an operator reads the report to find out
// whether the mail this server signs verifies, and a report that
// disagrees with the verifier answers a different question from the one
// being asked.
async function theReportAgreesWithTheVerifierOnTagNameCase(dkim, published) {
  var records = {};
  records[DOMAIN] = { txt: ["v=spf1 -all"], mx: [HOSTNAME] };
  records["_dmarc." + DOMAIN] = { txt: ["v=DMARC1; p=reject"] };
  var upper = published.map(function (rec) {
    return { name: rec.dnsName, txt: [rec.dnsTxtValue.replace("; p=", "; P=")] };
  });
  upper.forEach(function (entry) { records[entry.name] = { txt: entry.txt }; });

  var signer = await dkim.signerFor(DOMAIN);
  var signed = await signer.sign(Buffer.from(
    "From: a@" + DOMAIN + "\r\nTo: b@example.net\r\nSubject: case\r\n" +
    "Date: Tue, 1 Sep 2026 07:05:09 +0000\r\nMessage-ID: <case@" + DOMAIN + ">\r\n\r\nbody\r\n",
    "utf8"));
  var verifyRecords = {};
  upper.forEach(function (entry) { verifyRecords[entry.name] = { txt: entry.txt }; });
  var results = await b.mail.dkim.verify(signed, {
    dnsLookup: zone.lookupOver(verifyRecords),
  });
  var verifierPassed = results.length > 0 && results.every(function (r) {
    return r.result === "pass";
  });

  var posture = postureMod.create({
    hostname: HOSTNAME,
    resolver: zone.resolverOver(records),
    dkim:     dkim,
  });
  var report = await posture.check({ domains: [DOMAIN] });
  var domainReport = report.domains.filter(function (d) { return d.domain === DOMAIN; })[0];
  var reportPassed = (domainReport ? domainReport.findings : []).filter(function (f) {
    return f.record === "DKIM" && !f.ok;
  }).length === 0;

  count("the report and the verifier agree about an uppercase tag name",
    verifierPassed === reportPassed,
    "verifier " + (verifierPassed ? "pass" : "fail") +
    ", report " + (reportPassed ? "pass" : "fail"));
}

// The reader must not become so forgiving that it stops noticing a key
// that really is different. A record carrying somebody else's key is
// still a finding, and it is the finding the whole check exists for.
async function aGenuinelyDifferentKeyIsStillReported(dkim, published) {
  var records = {};
  records[DOMAIN] = { txt: ["v=spf1 -all"], mx: [HOSTNAME] };
  records["_dmarc." + DOMAIN] = { txt: ["v=DMARC1; p=reject"] };
  published.forEach(function (rec) {
    records[rec.dnsName] = {
      txt: [rec.dnsTxtValue.replace(/p=.*$/, "p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")],
    };
  });

  var posture = postureMod.create({
    hostname: HOSTNAME,
    resolver: zone.resolverOver(records),
    dkim:     dkim,
  });
  var report = await posture.check({ domains: [DOMAIN] });
  var domainReport = report.domains.filter(function (d) { return d.domain === DOMAIN; })[0];
  var failed = (domainReport ? domainReport.findings : []).filter(function (f) {
    return f.record === "DKIM" && !f.ok;
  });
  count("a record publishing a different key is still reported as a mismatch",
    failed.length === 2, "mismatches " + failed.length);
}

// RFC 6376 §3.6.1 gives an empty p= its own meaning: the selector is
// revoked. Stripping whitespace out of a value must not turn a record
// that is only whitespace into one that looks like a key.
async function aRevokedSelectorIsStillReportedAsRevoked(dkim, published) {
  var records = {};
  records[DOMAIN] = { txt: ["v=spf1 -all"], mx: [HOSTNAME] };
  records["_dmarc." + DOMAIN] = { txt: ["v=DMARC1; p=reject"] };
  published.forEach(function (rec) {
    records[rec.dnsName] = { txt: [rec.dnsTxtValue.replace(/p=.*$/, "p=   ")] };
  });

  var posture = postureMod.create({
    hostname: HOSTNAME,
    resolver: zone.resolverOver(records),
    dkim:     dkim,
  });
  var report = await posture.check({ domains: [DOMAIN] });
  var domainReport = report.domains.filter(function (d) { return d.domain === DOMAIN; })[0];
  var revoked = (domainReport ? domainReport.findings : []).filter(function (f) {
    return f.record === "DKIM" && !f.ok && /revokes the selector/.test(String(f.detail));
  });
  count("a p= tag holding only whitespace still reads as a revoked selector",
    revoked.length === 2, "revocations " + revoked.length);
}

async function run() {
  var root    = helpers.tempDir("posture-record-tag-grammar");
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
    await identity.domains.add({ domain: DOMAIN });
    await dkim.generate({ domain: DOMAIN, selector: "bpfold", rsaSelector: "bpfoldrsa" });

    var first = await theVerifierAcceptsAFoldedRecord(dkim, identity);
    await theReportAcceptsTheSameFoldedRecord(dkim, first.published, first.folded);
    await theReportAcceptsWhitespaceAroundTheEquals(dkim, first.published);
    await theReportAgreesWithTheVerifierOnTagNameCase(dkim, first.published);
    await aGenuinelyDifferentKeyIsStillReported(dkim, first.published);
    await aRevokedSelectorIsStillReportedAsRevoked(dkim, first.published);

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
  name: "posture-record-tag-grammar", run: run, getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
