// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * certificate-report: what is actually in the certificate an operator
 * supplied, rather than whether the file is there.
 *
 * blamepost issues nothing. `tlsCert` and `tlsKey` name two files an
 * operator's certificate client writes, and until this primitive existed
 * the only thing anything asked about them was whether they were present
 * and readable. Every way a present, readable certificate can be the
 * wrong one is silent, and each of them ends at the same place:
 *
 *   - It expired. The files are still there and still readable, so the
 *     server starts, binds every port and refuses every handshake.
 *   - The key beside it is from the previous issuance, because a renewal
 *     wrote one file and not the other.
 *   - It is the leaf without its issuer. Browsers fetch the missing
 *     intermediate themselves and sending mail servers do not, so the
 *     operator's own check of the web port passes while the mail ports
 *     fail.
 *   - It is issued to a name this server does not answer to.
 *   - The two paths point at each other, so the chain file holds a key.
 *
 * Each of those is built here and the reading is checked. The cases are
 * built rather than committed: a certificate fixture on disk is a
 * private key on disk, and one with a real expiry would start passing
 * or failing on a date nobody chose.
 *
 * Nothing here opens a socket or a database. It writes PEM into a
 * temporary directory, because the primitive reads paths and one handed
 * a string instead would be a different function.
 *
 * Run it on its own with
 * `node test/layer-0-primitives/certificate-report.test.js`.
 */

var nodeFs     = require("node:fs");
var nodeOs     = require("node:os");
var nodePath   = require("node:path");
var nodeCrypto = require("node:crypto");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var blamepost = require("../../lib");

var check = helpers.check;

var HOSTNAME = "mx.example.com";

// Every case mints its own material, so a pair written for the
// mismatched-key case cannot be the pair another case reads.
function writeInto(dir, name, bytes) {
  nodeFs.mkdirSync(dir, { recursive: true });
  var target = nodePath.join(dir, name);
  nodeFs.writeFileSync(target, bytes, "utf8");
  return target;
}

function findingFor(report, name) {
  var matched = report.findings.filter(function (f) { return f.check === name; });
  return matched.length === 0 ? null : matched[matched.length - 1];
}

// ---- a pair that is correct in every respect --------------------------------

function testAGoodPairReadsAsGood(root, material) {
  var dir = nodePath.join(root, "good");
  var certFile = writeInto(dir, "fullchain.pem", material.chain);
  var keyFile  = writeInto(dir, "privkey.pem", material.key);

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME,
  });

  check("a complete, current, matching pair reads as usable", report.ok === true);
  check("the reading names the subject", /mx\.example\.com/.test(String(report.subject)));
  check("the reading carries the expiry date", typeof report.validTo === "string" &&
    report.validTo.length > 0);
  check("the reading counts the days left rather than leaving the operator to subtract",
    typeof report.expiresInDays === "number" && report.expiresInDays > 0);
  check("a chain of leaf plus issuer is counted as two", report.chainLength === 2);
  check("the private key is reported as matching",
    findingFor(report, "private key").ok === true);
  check("the name this server answers to is reported as covered",
    findingFor(report, "certificate name").ok === true);

  // The private key is read to compare it and must never come back out.
  var serialized = JSON.stringify(report);
  check("no part of the private key appears anywhere in the reading",
    serialized.indexOf("PRIVATE KEY") === -1);
}

// ---- expiry -----------------------------------------------------------------

function testAnExpiredCertificateIsRefused(root, material) {
  var dir = nodePath.join(root, "expired");
  var certFile = writeInto(dir, "fullchain.pem", material.chain);
  var keyFile  = writeInto(dir, "privkey.pem", material.key);

  // Measured from a moment after the certificate's own expiry rather
  // than by minting a certificate that has already expired, which no
  // issuer will do and which would put a fixed date in this file.
  var afterItExpires = Date.parse(
    new nodeCrypto.X509Certificate(material.cert).validTo) + 1000;

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME, now: afterItExpires,
  });
  var validity = findingFor(report, "certificate validity");

  check("a certificate read after its expiry is not usable", report.ok === false);
  check("the expiry is what makes it unusable", validity.ok === false);
  check("the refusal names the date it expired rather than saying only that it is old",
    validity.detail.indexOf(String(report.validTo)) !== -1);
  check("the refusal says every connection is refused until it is replaced",
    /refuses every connection/.test(validity.detail));
  check("days remaining goes negative rather than clamping to zero",
    report.expiresInDays < 0);
}

// The width of the notice window, held against the number the operator
// guide prints for it.
//
// The case below reads three days of life left and is satisfied by any
// window at least that wide, so on its own it holds the reader to a
// floor of three while two shipped documents promise a fortnight. A
// window narrowed to a few days would keep that case green and leave
// `blamepost doctor` and both health probes silent through most of the
// period the guide tells an operator they will be warned in, which is
// the whole of the notice an unattended renewal failure produces.
//
// So the number is taken from the guide rather than written here or
// read out of the module. The sentence an operator acts on is the
// authority, and a change to either side without the other fails here.
var SETTINGS_REFERENCE = "docs/operator-guide.md";
var NOTICE_WINDOW_RE   = /inside (\d+) days of expiring/;

function noticeWindowDaysFromTheGuide() {
  var text    = nodeFs.readFileSync(
    nodePath.join(helpers.REPO_ROOT, SETTINGS_REFERENCE), "utf8");
  var matched = NOTICE_WINDOW_RE.exec(text);
  return matched === null ? null : parseInt(matched[1], 10);
}

// Read at an exact number of days before the expiry the leaf carries, so
// the floor the reader divides by lands on a whole number rather than on
// whichever side of it the run happened to start.
function readingDaysBeforeExpiry(certFile, keyFile, leafPem, days) {
  var notAfter = Date.parse(new nodeCrypto.X509Certificate(leafPem).validTo);
  return blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME,
    now: notAfter - (days * 24 * 60 * 60 * 1000),
  });
}

async function testTheNoticeWindowIsTheWidthTheGuidePrints(root) {
  var days = noticeWindowDaysFromTheGuide();
  check("the operator guide names the width of the certificate notice window, so this is " +
    "comparing something", days !== null && days > 0);
  if (days === null) return;

  // Minted with a life comfortably past the window, because both edges
  // are read against the leaf's own validity and a leaf shorter than the
  // window would put the outer reading before it was valid at all.
  var material = await certs.pair({
    hostname: HOSTNAME, authorityName: "a longer lived authority", validityDays: days * 4 });
  var dir = nodePath.join(root, "notice-window");
  var certFile = writeInto(dir, "fullchain.pem", material.chain);
  var keyFile  = writeInto(dir, "privkey.pem", material.key);

  var inside = readingDaysBeforeExpiry(certFile, keyFile, material.cert, days);
  var insideValidity = findingFor(inside, "certificate validity");
  check("a certificate with exactly the days the guide names left is inside the window, so " +
    "the notice an operator was promised is the notice they get",
    inside.expiresInDays === days && insideValidity.severity === "advised");

  var outside = readingDaysBeforeExpiry(certFile, keyFile, material.cert, days + 1);
  var outsideValidity = findingFor(outside, "certificate validity");
  check("and one day further out is outside it, so the window is the width the guide prints " +
    "rather than merely at least that wide",
    outside.expiresInDays === days + 1 &&
    outsideValidity.ok === true && outsideValidity.severity === undefined);
}

function testAnExpiryComingUpIsSaidOutLoudWithoutFailing(root, material) {
  var dir = nodePath.join(root, "soon");
  var certFile = writeInto(dir, "fullchain.pem", material.chain);
  var keyFile  = writeInto(dir, "privkey.pem", material.key);

  // Three days before it expires: inside the window where a renewal
  // client should already have replaced it several times over.
  var threeDaysBefore = Date.parse(
    new nodeCrypto.X509Certificate(material.cert).validTo) - (3 * 24 * 60 * 60 * 1000);

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME, now: threeDaysBefore,
  });
  var validity = findingFor(report, "certificate validity");

  check("a certificate close to expiry still reads as usable, because it still works",
    validity.ok === true);
  check("and it is marked as something to say rather than passed over in silence",
    validity.severity === "advised");
  check("the notice points at the renewal rather than at the certificate",
    /renewal/i.test(validity.detail));
}

// ---- the key beside it ------------------------------------------------------

async function testAKeyFromADifferentIssuanceIsRefused(root, material) {
  var other = await certs.pair({ hostname: HOSTNAME, authorityName: "a different authority" });
  var dir = nodePath.join(root, "mismatch");
  var certFile = writeInto(dir, "fullchain.pem", material.chain);
  var keyFile  = writeInto(dir, "privkey.pem", other.key);

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME,
  });
  var key = findingFor(report, "private key");

  check("a key that does not belong to the certificate is refused", report.ok === false);
  check("the refusal is reported against the key rather than as a parse failure",
    key.ok === false);
  check("the refusal names both files, so the operator knows which two disagree",
    key.detail.indexOf(certFile) !== -1 && key.detail.indexOf(keyFile) !== -1);
  check("and it names the cause an operator can act on: a half written renewal",
    /renewal wrote one file and not the other/.test(key.detail));
}

function testTheTwoPathsPointingAtEachOtherIsRefused(root, material) {
  var dir = nodePath.join(root, "swapped");
  // The key bytes where the chain belongs, and the chain where the key
  // belongs. A single transposed pair of variable names in a deployment
  // template produces exactly this.
  var certFile = writeInto(dir, "fullchain.pem", material.key);
  var keyFile  = writeInto(dir, "privkey.pem", material.chain);

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME,
  });
  var certFinding = findingFor(report, "certificate file");

  check("a key written where the chain belongs is refused", report.ok === false);
  check("the refusal is reported against the certificate file", certFinding.ok === false);
  check("the refusal names the file rather than only the parser's complaint",
    certFinding.detail.indexOf(certFile) !== -1);
  check("and it names the transposition, which is what actually happened",
    /key written where the chain belongs/.test(certFinding.detail));
}

// ---- the chain --------------------------------------------------------------

function testALeafWithNoIssuerIsRefused(root, material) {
  var dir = nodePath.join(root, "leafonly");
  // cert.pem rather than fullchain.pem, which is the mistake: both files
  // sit in the same directory and only one of them is complete.
  var certFile = writeInto(dir, "cert.pem", material.cert);
  var keyFile  = writeInto(dir, "privkey.pem", material.key);

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME,
  });
  var chain = findingFor(report, "certificate chain");

  check("a leaf with no issuer beside it is refused", report.ok === false);
  check("the chain is what makes it unusable", chain.ok === false);
  check("one certificate is counted as one", report.chainLength === 1);
  check("the refusal explains why a browser accepts this and a mail server does not",
    /browser fetches that issuer/.test(chain.detail));
  check("and it names the file to point at instead",
    chain.detail.indexOf("fullchain.pem") !== -1);
}

async function testASelfSignedCertificateIsAWholeChain(root) {
  // A private authority signing for itself: one certificate in the file
  // and nothing missing from it. Counting blocks alone would call this
  // the same mistake as the case above, and it is not one.
  var authority = await certs.pair({ hostname: HOSTNAME });
  var dir = nodePath.join(root, "selfsigned");
  var certFile = writeInto(dir, "ca.pem", authority.caPem);

  var report = blamepost.certificateReport({
    certFile: certFile,
    keyFile:  writeInto(dir, "privkey.pem", authority.key),
    // No hostname: the authority is not issued to one, and asking would
    // be checking this fixture rather than the chain rule under test.
  });
  var chain = findingFor(report, "certificate chain");

  check("a self-signed certificate is recognized as signing for itself",
    report.selfSigned === true);
  check("and one certificate that is its own issuer is a complete chain",
    chain.ok === true);
}

// ---- the name ---------------------------------------------------------------

async function testACertificateForAnotherNameIsRefused(root) {
  var elsewhere = await certs.pair({ hostname: "mail.example.net" });
  var dir = nodePath.join(root, "wrongname");
  var certFile = writeInto(dir, "fullchain.pem", elsewhere.chain);
  var keyFile  = writeInto(dir, "privkey.pem", elsewhere.key);

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME,
  });
  var name = findingFor(report, "certificate name");

  check("a certificate issued to another name is refused", report.ok === false);
  check("the name is what makes it unusable", name.ok === false);
  check("the refusal names both the name it carries and the name this server answers to",
    name.detail.indexOf(HOSTNAME) !== -1 && /mail\.example\.net/.test(name.detail));
}

// ---- files that are not there -----------------------------------------------

function testAnUnreadableFileIsReportedAtTheFileRatherThanAsACrash(root, material) {
  var dir = nodePath.join(root, "absent");
  var keyFile  = writeInto(dir, "privkey.pem", material.key);
  var certFile = nodePath.join(dir, "nothing-here.pem");

  var report = blamepost.certificateReport({
    certFile: certFile, keyFile: keyFile, hostname: HOSTNAME,
  });
  var certFinding = findingFor(report, "certificate file");

  check("a certificate path with no file behind it is refused", report.ok === false);
  check("the refusal is reported rather than thrown", certFinding.ok === false);
  check("and it names the path that could not be read",
    certFinding.detail.indexOf(certFile) !== -1);
  check("and it names the permission case, which is what a container that drops " +
    "privileges hits on a root-owned key",
    /readable only by root/.test(certFinding.detail));
}

// ---- a sealed key that does not open ----------------------------------------

// An operator may seal the private key on the volume, and then there are
// exactly two ways it does not open again: the bytes were written under
// a different volume's vault key, or they have been damaged where they
// lie. A seal authenticates what it carries end to end, so those two are
// indistinguishable from the outside and the reading names both.
//
// The passphrase is not a third way, and saying it might be sends an
// operator to check the one thing already proven correct. It opens
// vault.key.sealed while the vault itself is being opened, which happens
// before any of this runs, and a passphrase that does not fit refuses
// the boot there under its own name. So a reading that runs at all is
// running under a passphrase that fitted.
//
// The vault is a stand-in here on purpose. What is being read is the
// sentence this layer composes when a seal does not open, and a real
// vault refusing for a real reason would test the vault instead.
function testASealedKeyThatDoesNotOpenNamesTheTwoCausesThereAre(root, material) {
  var dir = nodePath.join(root, "sealed");
  var certFile = writeInto(dir, "fullchain.pem", material.chain);
  var keyFile  = writeInto(dir, "privkey.pem", "vault:not-openable-here\n");

  var report = blamepost.certificateReport({
    certFile: certFile,
    keyFile:  keyFile,
    hostname: HOSTNAME,
    vault:    {
      seal:   function (value) { return "vault:" + value; },
      unseal: function () { throw new Error("authentication tag mismatch"); },
    },
  });
  var keyFinding = findingFor(report, "private key");

  check("a sealed key that does not open makes the pair unusable", report.ok === false);
  check("and it is the key rather than the certificate that says so",
    keyFinding !== null && keyFinding.ok === false);
  check("the reading names the key that was written under another volume's vault key",
    keyFinding !== null && /different volume's vault key/.test(keyFinding.detail));
  check("and names damage in place, which is the other of the two and has the same remedy",
    keyFinding !== null && /damaged where they lie/.test(keyFinding.detail));
  check("and does not send the operator after the passphrase, which opens the vault at " +
    "start and stops the boot when it does not fit, so it cannot be the cause of a read " +
    "that ran",
    keyFinding !== null && keyFinding.detail.indexOf("passphrase") === -1);
  check("and says what to do about it rather than only what happened",
    keyFinding !== null && /Restore the file from a backup/.test(keyFinding.detail));
}

// ---- and the boot refuses on the same reading -------------------------------

// The reading is only worth having if something acts on it. `create`
// reads the pair before anything binds, so a certificate that cannot be
// used stops the boot instead of producing a server that takes every
// port and refuses every handshake on all of them. Driven here rather
// than described, because the reader answering correctly into a boot
// that ignored the answer is exactly the failure this covers.
//
// `create` reaches the certificate before it reaches the store, so these
// cases need no database: a store that is never consulted cannot change
// the verdict, and building one would only make the case slower.
function bootWith(certFile, keyFile, atEpochMs) {
  // The boot reads the wall clock, so a case about an expiry moves the
  // clock rather than minting a certificate that has already expired,
  // which no issuer will do and which would put a fixed date in this
  // file. Restored in a finally, because everything after this in the
  // process reads the same clock.
  var realNow = Date.now;
  if (atEpochMs !== undefined) Date.now = function () { return atEpochMs; };
  try {
    blamepost.create({
      config: {
        hostname: HOSTNAME,
        dataDir:  nodePath.dirname(certFile),
        tlsCert:  certFile,
        tlsKey:   keyFile,
      },
      store:     {},
      mailStore: {},
    });
    return null;
  } catch (err) {
    return err;
  } finally {
    Date.now = realNow;
  }
}

function testTheBootRefusesACertificateItCannotUse(root, material) {
  var dir = nodePath.join(root, "boot-expired");
  var certFile = writeInto(dir, "fullchain.pem", material.chain);
  var keyFile  = writeInto(dir, "privkey.pem", material.key);
  var refusal = bootWith(certFile, keyFile, Date.parse(
    new nodeCrypto.X509Certificate(material.cert).validTo) + 1000);

  check("a boot over a certificate whose validity has closed is refused", refusal !== null);
  check("and the refusal is the certificate, not a later failure about a store",
    /certificate this server would present/.test(refusal.message));
  check("the refusal names the date it expired", refusal.message.indexOf(
    new nodeCrypto.X509Certificate(material.cert).validTo) !== -1);
  check("the refusal names both variables an operator has to correct",
    refusal.message.indexOf("BLAMEPOST_TLS_CERT") !== -1 &&
    refusal.message.indexOf("BLAMEPOST_TLS_KEY") !== -1);
  check("and points at the command that reports the same reading without starting anything",
    /blamepost doctor/.test(refusal.message));
}

// A certificate that is WRONG but still works must not stop a boot.
//
// A chain with no issuer and a certificate issued to another name are
// both faults an operator should fix, and both serve every peer that
// does not check the thing they got wrong, which is most of them. A
// version upgrade that took a running server down over either would cost
// an operator more than it saved, and it would do it at the moment they
// were least expecting a certificate to be the reason. `doctor` reports
// both as failures, which is where a fault belongs.
function testTheBootAcceptsACertificateThatIsWrongButUsable(root, material) {
  var leafOnly = nodePath.join(root, "boot-leafonly");
  var stoppedByChain = bootWith(
    writeInto(leafOnly, "cert.pem", material.cert),
    writeInto(leafOnly, "privkey.pem", material.key));
  check("a leaf with no issuer does not stop the boot, because it still serves",
    stoppedByChain !== null &&
    !/certificate this server would present/.test(stoppedByChain.message));

  // And the same reading still calls it a failure, so nothing has been
  // quietly downgraded to a pass.
  var report = blamepost.certificateReport({
    certFile: nodePath.join(leafOnly, "cert.pem"),
    keyFile:  nodePath.join(leafOnly, "privkey.pem"),
  });
  check("and the reading still reports the missing issuer as a failure",
    findingFor(report, "certificate chain").ok === false);
  check("marked as something that does not stop a server",
    findingFor(report, "certificate chain").fatal === false);
}

function testTheBootRefusesAKeyThatDoesNotMatch(root, material) {
  var dir = nodePath.join(root, "boot-mismatch");
  // Cert and key transposed, which is the shape that used to arrive as a
  // bare OpenSSL string naming neither file.
  var refusal = bootWith(
    writeInto(dir, "fullchain.pem", material.key),
    writeInto(dir, "privkey.pem", material.chain));

  check("a boot over two paths pointing at each other is refused", refusal !== null);
  check("the refusal names the certificate file rather than only the parser's complaint",
    refusal.message.indexOf(nodePath.join(dir, "fullchain.pem")) !== -1);
  check("and it names the key file too, so the operator can see the transposition",
    refusal.message.indexOf(nodePath.join(dir, "privkey.pem")) !== -1);
}

function testTheBootAcceptsAPairItCanUse(root, material) {
  var dir = nodePath.join(root, "boot-good");
  var refusal = bootWith(
    writeInto(dir, "fullchain.pem", material.chain),
    writeInto(dir, "privkey.pem", material.key));

  // It gets past the certificate and fails on the store it was handed,
  // which is the assertion: the certificate is not what stopped it.
  check("a usable certificate does not stop the boot", refusal !== null &&
    !/certificate this server would present/.test(refusal.message));
}

// ---- the entry point refuses what it cannot answer for ----------------------

function testTheEntryPointRefusesBadInput() {
  var refused = 0;
  [
    undefined,
    {},
    { certFile: "/tmp/cert.pem" },
    { certFile: "/tmp/cert.pem", keyFile: "/tmp/key.pem", now: "yesterday" },
  ].forEach(function (opts) {
    try { blamepost.certificateReport(opts); }
    catch (e) { if (e instanceof TypeError) refused += 1; }
  });
  check("every incomplete call is refused at the entry point rather than reported as a " +
    "certificate problem", refused === 4);
}

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-certreport-"));
  try {
    // One good pair, reused by the cases that vary one thing about it.
    // Minting a fresh authority per case would say nothing extra and
    // costs a keypair each time.
    var material = await certs.pair({ hostname: HOSTNAME });

    testAGoodPairReadsAsGood(root, material);
    testAnExpiredCertificateIsRefused(root, material);
    testAnExpiryComingUpIsSaidOutLoudWithoutFailing(root, material);
    await testTheNoticeWindowIsTheWidthTheGuidePrints(root);
    await testAKeyFromADifferentIssuanceIsRefused(root, material);
    testTheTwoPathsPointingAtEachOtherIsRefused(root, material);
    testALeafWithNoIssuerIsRefused(root, material);
    await testASelfSignedCertificateIsAWholeChain(root);
    await testACertificateForAnotherNameIsRefused(root);
    testAnUnreadableFileIsReportedAtTheFileRatherThanAsACrash(root, material);
    testASealedKeyThatDoesNotOpenNamesTheTwoCausesThereAre(root, material);
    testTheBootRefusesACertificateItCannotUse(root, material);
    testTheBootRefusesAKeyThatDoesNotMatch(root, material);
    testTheBootAcceptsACertificateThatIsWrongButUsable(root, material);
    testTheBootAcceptsAPairItCanUse(root, material);
    testTheEntryPointRefusesBadInput();
  } finally {
    // Drop-silent by design: a temporary directory that outlives the run
    // must never mask the assertion that failed inside it.
    try { nodeFs.rmSync(root, { recursive: true, force: true }); } catch (_e) { /* the OS reclaims it */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
